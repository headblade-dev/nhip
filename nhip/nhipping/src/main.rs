use std::os::unix::net::UnixStream;
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use std::io::stdout;

use anyhow::{Context, Result};
use clap::{Parser};
use nhip_cfg::*;


// COMMANDS
#[derive(Parser, Debug)]
#[command(name = "nhipping")]
#[command(about = "NHIP ping-pong test utility (with command abbreviation support)")]
#[command(infer_long_args = true)]
struct Cli {
    dest: String,
    #[arg(short, long, visible_alias = "src")]
    source: Option<String>,
    #[arg(short, long, visible_alias = "iface")]
    dev: Option<String>,
    #[arg(short, long, visible_alias = "number")]
    count: Option<u16>,
    #[arg(short, long, visible_alias = "bytes")]
    bytesize: Option<usize>,
}

fn resolve_src(dev: Option<&str>, src: Option<&str>, config: &Vec<AddressEntry>) -> anyhow::Result<(u32, String)> {
    
    match dev {
        Some(dev) => {
            let dev_entry = config.iter().find(|e| e.ifname == dev);
            if let Some(dev_entry) = dev_entry {
                let addrs = dev_entry.addresses.clone();
                if addrs.len() > 1 && src == None {
                    println!("Interface {} has more than one address. Please specify a source address",
                        colorize(dev, ansi_color::BOLD)
                    );
                } else {
                    let src_addr = addrs.first();
                    if let Some(src_addr) = src_addr {
                        let expanded_src_addr = expand_tilde(&src_addr, dev, &config)?;
                        return Ok((ifname_to_index(&dev_entry.ifname)?, expanded_src_addr));
                    } else {
                        println!("Interface {} has no addresses configured", colorize(dev, ansi_color::BOLD));
                    }
                }
            } else {
                println!("Interface {} has no addresses configured", colorize(dev, ansi_color::BOLD));
            }
        }
        None => {
            if config.len() > 1 {
                println!("Has more than one inteface configured. Please specify an interface or a source address");
            } else {
                if let Some(entry) = config.first() {
                    let addrs = entry.addresses.clone();
                    if addrs.len() > 1 {
                        println!("Interface {} has more than one address configured. Please specify a source address",
                            colorize(&entry.ifname, ansi_color::BOLD)
                        )
                    } else {
                        if let Some(addr) = addrs.first() {
                            let expanded_addr = expand_tilde(addr, &entry.ifname, &config)?;
                            return Ok((ifname_to_index(&entry.ifname)?, expanded_addr));
                        } else {
                            println!("The only interface {} has no address assigned",
                                colorize(&entry.ifname, ansi_color::BOLD)
                            )
                        }
                    }
                } else {
                    println!("Has no interface configured");
                }
            }
        }
    }

    anyhow::bail!("Cannot find source address");
}

fn fill_payload(size: usize, buf: &mut [u8]){
    let mut curr_bytes: usize = 0;
    if size == 0 {
        return;
    }
    loop {
        buf[curr_bytes] = (curr_bytes as u8).wrapping_add(0x01);
        curr_bytes += 1;
        if curr_bytes == size {
            return
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_addrs()?;

    // Process addresses
    
    let expanded_dst = expand_tilde(&cli.dest, &cli.dev.as_deref().unwrap_or_default(), &config)
        .context(format!("Failed to expand tilde for destination address: {}", &cli.dest))?;

    let (ifindex, expanded_src) = resolve_src(
        cli.dev.clone().as_deref(), 
        cli.source.as_deref(), &config
    )
        .context("Failed to get source address from input data")?;

    // Payload pattern

    let payload_size = cli.bytesize.unwrap_or(64);
    let mut payload = vec![0u8; payload_size];
    fill_payload(payload_size, &mut payload);
    let payload = &payload[..];

    let cmd = format!("PING {} {} {} {}\n",
        expanded_dst,
        expanded_src,
        ifindex,
        hex::encode(&payload)
    );

    let mut stream = UnixStream::connect("/var/run/nhipd.sock")?;
    

    let count = cli.count.unwrap_or(5) as u32;
    let mut attempt: u32 = 0;
    let mut success_count: u32 = 0;
    
    let socket_path = "/var/run/nhipd-ping.sock";
    let _ = std::fs::remove_file(socket_path);


    loop {
        if count != 0 && attempt >= count || attempt >= u32::MAX { break; }
        let start = Instant::now();
        

        let mut response = String::new();
        let mut buf = [0u8; 4096];
        stream.set_read_timeout(Some(Duration::from_millis(100)))?;

        if let Err(e) = stream.write_all(&cmd.as_bytes()) {
            eprintln!("Error: Failed to write UnixStream {}", e);
            return Ok(());
        }

        'attempt: loop {
            
            match stream.read(&mut buf) {
                Ok(n) => {
                    response.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if response.starts_with("PONG") {
                        let parts: Vec<&str> = response.trim().split_whitespace().collect();
                        let pong_src_addr_str = parts[1];
                        let pong_dst_addr_str = parts[2];
                        if pong_src_addr_str == &expanded_dst && pong_dst_addr_str == &expanded_src {
                            print!("!");
                            stdout().flush()?;
                            success_count += 1;
                            break 'attempt; 
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    if start.elapsed() >= Duration::from_secs(2) {
                        print!(".");
                        stdout().flush()?;
                        break 'attempt;
                    }
                }
                Err(e) => {
                    anyhow::bail!("UnixStream read error: {}", e);
                }
            }
        }

        attempt += 1;
    }

    let failed_count = attempt - success_count;
    let loss = if attempt > 0 { (failed_count * 100) / attempt } else { 100 };
    println!("\nSuccess: {}, Failed {}, Loss: {}%, Total: {}", success_count, failed_count, loss, attempt);


    return Ok(())
}
