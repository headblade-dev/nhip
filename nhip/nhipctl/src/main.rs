use anyhow::{Context, Result};
use aya::{include_bytes_aligned, maps::HashMap, Ebpf};
use bytemuck::{Pod, Zeroable};
use clap::{Parser, Subcommand};
use nhip_cfg::*;
use serde::{de, Deserialize, Serialize};
use std::{collections::HashMap as StdHashMap, default};

mod ansi_color {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const CYAN: &str = "\x1b[36m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const RED: &str = "\x1b[31m";
}

#[derive(Parser)]
#[command(name = "nhipctl")]
#[command(about = "NHIP control manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(visible_alias = "a")]
    Addr {
        #[command(subcommand)]
        action: AddrAction,
    },

    #[command(visible_alias = "r")]
    Route {
        #[command(subcommand)]
        action: RouteAction,
    },
}

#[derive(Subcommand)]
enum AddrAction {
    #[command(visible_alias = "add")]
    Add {
        address: String,
        #[arg(short, long)]
        dev: String,
        #[arg(short, long)]
        prefix: Option<String>,
    },

    #[command(visible_alias = "del")]
    Delete {
        address: String,
        #[arg(short, long)]
        dev: String,
    },

    #[command(visible_alias = "show")]
    Show {
        #[arg(short, long)]
        dev: Option<String>,
    },
}

#[derive(Subcommand)]
enum RouteAction {
    #[command(visible_alias = "add")]
    Add {
        destination: String,
        #[arg(short, long)]
        via: String,
        #[arg(short, long)]
        dev: String,
        #[arg(short, long)]
        priority: u8,
    },

    #[command(visible_alias = "del")]
    Delete {
        destination: String,
        #[arg(short, long)]
        via: String,
        #[arg(short, long)]
        dev: String,
        #[arg(short, long)]
        priority: u8,
    },

    #[command(visible_alias = "show")]
    Show,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct ForwardEntry {
    next_label: u32,
    ifindex: u32,
    next_hop_hash: u32,
    _pad: [u8; 2],
}

struct FastPathTable {
    _bpf: Ebpf,
    table: HashMap<aya::maps::MapData, u32, ForwardEntry>,
}

struct NhipCtl {
    fpt: FastPathTable,
    addr_cache: StdHashMap<u32, String>,
    iface_names: StdHashMap<u32, String>,
}

fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(":").collect();
    if parts.len() != 6 {
        anyhow::bail!("Invalid MAC-address: {}", s);
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }
    Ok(mac)
}

fn open_fastpath_table() -> Result<FastPathTable> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../nhipd-ebpf/target/bpfel-unknown-none/release/libnhipd_ebpf.a"
    ))
    .context("Failed to open FastPath Table")?;

    let map = bpf
        .take_map("FASTPATH_TABLE")
        .context("FastPass Table not found")?;

    let table = HashMap::try_from(map).context("Failed to open FastPath Table")?;

    Ok(FastPathTable { _bpf: bpf, table })
}

fn colorize(text: &str, ansi_code: &str) -> String {
    format!("{}{}{}", ansi_code, text, ansi_color::RESET)
}

fn expand_tilde(addr: &str, dev: &str, config: &[AddressEntry]) -> Result<String> {
    if let Some(rest) = addr.strip_prefix('~') {
        let entry = config
            .iter()
            .find(|e| e.ifname == dev)
            .context(format!("Interface {} not configured", dev))?;

        if entry.prefix == "none" || entry.prefix.is_empty() {
            anyhow::bail!("Interface {} has no prefix", dev);
        }

        return Ok(format!("{}{}", entry.prefix, rest));
    }

    return Ok(addr.to_string());
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut fpt = open_fastpath_table()?;
    let mut ctl = NhipCtl {
        fpt,
        addr_cache: StdHashMap::new(),
        iface_names: StdHashMap::new(),
    };

    match cli.command {
        Commands::Addr { action } => match action {
            AddrAction::Show { dev } => {
                let config = load_addrs();

                println!(
                    "{}{:-^60}{}",
                    ansi_color::BOLD,
                    " NHIP Addresses ",
                    ansi_color::RESET
                );
                println!(
                    "{}{:<15} {:<20} {:<25}{}",
                    ansi_color::BOLD,
                    "Interface",
                    "Addresses",
                    "Prefix",
                    ansi_color::RESET
                );

                for entry in &config {
                    if let Some(ref filter_dev) = dev {
                        if &entry.ifname != filter_dev {
                            continue;
                        }
                    }
                    let addrs = entry.addresses.join(", ");
                    println!(
                        "{:<15} {:<20} {:<25}",
                        colorize(&entry.ifname, ansi_color::BOLD),
                        colorize(&addrs, ansi_color::CYAN),
                        colorize(&entry.prefix, ansi_color::MAGENTA)
                    );
                }
            }
            AddrAction::Add {
                address,
                dev,
                prefix,
            } => {
                let mut config = load_addrs()?;

                let expanded_addr = expand_tilde(&address, &dev, &config)?;

                if let Some(entry) = config.iter_mut().find(|e| e.ifname == dev) {
                    if !entry.addresses.contains(&expanded_addr) {
                        entry.addresses.push(expanded_addr.clone());
                    }
                    entry.prefix = prefix.clone().unwrap_or(entry.prefix.clone());
                } else {
                    let prefix: String = match &prefix {
                        Some(p) => p.clone(),
                        None => String::from("none"),
                    };
                    config.push(AddressEntry {
                        ifname: dev.clone(),
                        prefix,
                        addresses: vec![expanded_addr.clone()],
                    })
                }
                write_addrs(&config)?;
                let prefix_str = match &prefix {
                    Some(p) => format!("(prefix: {})", p),
                    None => String::from(""),
                };
                println!(
                    "Added address {} to interface {} {}",
                    colorize(&expanded_addr, ansi_color::CYAN),
                    colorize(&dev, ansi_color::BOLD),
                    colorize(&prefix_str, ansi_color::MAGENTA)
                );
            }
            AddrAction::Delete { address, dev } => {
                let mut config = load_addrs()?;

                let expanded_addr = expand_tilde(&address, &dev, &config)?;

                if let Some(entry) = config.iter_mut().find(|e| e.ifname == dev) {
                    entry.addresses.retain(|a| a != &expanded_addr);
                    write_addrs(&config)?;
                    println!(
                        "Removed address {} from interface {}",
                        colorize(&expanded_addr, ansi_color::CYAN),
                        colorize(&dev, ansi_color::BOLD)
                    )
                } else {
                    println!(
                        "Interface {} has not address {}",
                        colorize(&dev, ansi_color::BOLD),
                        colorize(&expanded_addr, ansi_color::CYAN)
                    );
                    return Ok(());
                }
            }
        },
        Commands::Route { action } => match action {
            RouteAction::Show => {
                let config = load_routes()?;

                println!(
                    "{} NHIP Routing Table {}",
                    ansi_color::BOLD,
                    ansi_color::RESET
                );

                println!(
                    "{}{:<35} {:<25} {:<10} {:<10} {:<10}{}",
                    ansi_color::BOLD,
                    "Destination",
                    "Via",
                    "Interface",
                    "Proto",
                    "Priority",
                    ansi_color::RESET
                );
                println!("{}", "-".repeat(64));
                for route in &config {
                    let dest = if &route.destination == "default" {
                        colorize("default", ansi_color::RED)
                    } else {
                        route.destination.clone()
                    };

                    let proto = format!("{:?}", &route.proto).to_lowercase();

                    println!(
                        "{:<35} {:<25} {:<10} {:<10} {:<10}",
                        dest, &route.next_hop, &route.dev, proto, &route.priority
                    );
                }
            }
            RouteAction::Add {
                destination,
                via,
                dev,
                priority,
            } => {
                let addr_config = load_addrs()?;
                let mut route_config = load_routes()?;

                let expanded_via = expand_tilde(&via, &dev, &addr_config)?;
                let expanded_dest = expand_tilde(&destination, &dev, &addr_config)?;

                if route_config.iter().any(|r| {
                    r.destination == expanded_dest
                        && r.dev == dev
                        && r.next_hop == expanded_via
                        && r.proto == RoutingProto::Static
                        && r.priority == priority
                }) {
                    println!("This route already exist");
                    return Ok(());
                }

                route_config.push(RouteEntry {
                    destination: expanded_dest.clone(),
                    next_hop: expanded_via.clone(),
                    dev: dev.clone(),
                    proto: RoutingProto::Static,
                    priority: priority,
                });
                write_routes(&route_config)?;

                // eBPF sychronization
                let ifindex = ifname_to_index(&dev)?;

                println!(
                    "Added route to {} via {} through interface {}",
                    colorize(&expanded_dest, ansi_color::GREEN),
                    colorize(&expanded_via, ansi_color::CYAN),
                    colorize(&dev, ansi_color::BOLD)
                );
            }
            RouteAction::Delete {
                destination,
                via,
                dev,
                priority,
            } => {
                let addr_config = load_addrs()?;
                let mut route_config = load_routes()?;

                let expanded_via = expand_tilde(&via, &dev, &addr_config)?;
                let expanded_dest = expand_tilde(&destination, &dev, &addr_config)?;

                if !route_config.iter().any(|r| r.destination == expanded_dest) {
                    println!("No route to destination");
                    return Ok(());
                }

                if expanded_dest == "default" {
                    route_config.retain(|r| r.destination != "default");
                } else {
                    route_config.retain(|r| {
                        !(r.destination == expanded_dest
                            && r.dev == dev.clone()
                            && r.next_hop == expanded_via.clone()
                            && r.priority == priority
                            && r.proto == RoutingProto::Static)
                    });
                }

                write_routes(&route_config)?;

                println!(
                    "Route {} deleted",
                    colorize(&expanded_dest, ansi_color::GREEN)
                )
            }
        },
    }

    Ok(())
}
