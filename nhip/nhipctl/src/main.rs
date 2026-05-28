// ./nhip/nhipctl/src/main.rs

use std::{os::unix::net::UnixStream, path::Path};
use std::io::Write;

use aya::{Pod, maps::MapData};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nhip_cfg::*;
use bytemuck::{Zeroable};
use nhip_core::addr::{parse_node_id, validate_addr};



#[derive(Parser)]
#[command(name = "nhipctl")]
#[command(about = "NHIP control manager (with argument abbreviation support)")]
#[command(infer_long_args = true)]
#[command(infer_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[repr(C)]
#[derive(Clone, Copy, Zeroable)]
struct NharpEntry {
    mac: [u8; 6],
    _pad: [u8; 2],
}

unsafe impl Pod for NharpEntry {}

#[repr(C)]
#[derive(Clone, Copy, Zeroable)]
struct NharpKey {
    ifindex: u32,
    node_id: u32,
}

unsafe impl Pod for NharpKey {}

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

    #[command(visible_alias = "n")]
    Neighbor {
        #[command(subcommand)]
        action: NeighborAction,
    }
}

#[derive(Subcommand)]
enum AddrAction {
    #[command(visible_alias = "new")]
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

    #[command(visible_alias = "list")]
    Show {
        #[arg(short, long)]
        dev: Option<String>,
    },
}

#[derive(Subcommand)]
enum RouteAction {
    #[command(visible_alias = "new")]
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

    #[command(visible_alias = "list")]
    Show,
}

#[derive(Subcommand)]
enum NeighborAction {
    #[command(visible_alias = "new")]
    Add {
        node_id: u32,
        #[arg(short, long)]
        at: String,
        #[arg(short, long)]
        dev: String,
    },
    #[command(visible_alias = "del")]
    Delete {
        node_id: u32,
        #[arg(short, long)]
        dev: String,
    },
    // #[command(visible_alias = "search")]
    // Resolve {                                                                                                                                                                                                                                                                                                                                                                                   
    //     node_id: u32,
    //     #[arg(short, long)]
    //     dev: String
    // },
    #[command(visible_alias = "list")]
    Show,
}

pub fn ensure_configs() -> Result<()> {
    let config_dir = "/etc/nhip";
    std::fs::create_dir_all(config_dir)?;

    // addresses.conf
    let addr_path = format!("{}/addresses.conf", config_dir);
    if !Path::new(&addr_path).exists() {
        std::fs::write(&addr_path, "[]\n")?;
        log::info!("Created default {}", addr_path);
    }

    // routes.conf
    let routes_path = format!("{}/routes.conf", config_dir);
    if !Path::new(&routes_path).exists() {
        std::fs::write(&routes_path, "[]\n")?;
        log::info!("Created default {}", routes_path);
    }

    // static_ngh.conf
    let nharp_path = format!("{}/static_ngh.conf", config_dir);
    if !Path::new(&nharp_path).exists() {
        std::fs::write(&nharp_path, "{}\n")?;
        log::info!("Created default {}", nharp_path);
    }

    Ok(())
}

fn main() -> Result<()> {
    ensure_configs()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Addr { action } => match action {
            AddrAction::Show { dev } => {
                let config = load_addrs()?;

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

                let parts = expanded_addr.split(':').collect::<Vec<&str>>();
                if parts.len() != 2 {
                    anyhow::bail!("Invalid NHIP address");
                }
                let network_part_str = parts[0];
                let node_id_str = parts[1];
                let _node_id = parse_node_id(node_id_str.as_bytes())
                    .context(format!("Failed to parse NodeID: {}", node_id_str))?;
                let _network_part = validate_addr(network_part_str.as_bytes());
                

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
        Commands::Neighbor { action } => match action {
            NeighborAction::Add { 
                node_id, 
                at, 
                dev 
            } => {
                let mut config = load_static_ngh()?;
                let local_mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", dev))?
                    .trim()
                    .to_string();
                config.entry(local_mac)
                    .or_insert_with(|| Vec::new())
                    .push(NharpConfigEntry { node_id, mac: at.clone() });
                
                write_static_ngh(&config)?;

                println!("Added NodeID resolving: {} is at {} (dev {})",
                    colorize(&node_id.to_string(), ansi_color::GREEN),
                    colorize(&at, ansi_color::YELLOW),
                    colorize(&dev, ansi_color::BOLD)

                );
            }
            NeighborAction::Delete { 
                node_id, 
                dev 
            } => {
                let mut config = load_static_ngh()?;
                let local_mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", dev))?
                    .trim()
                    .to_string();
                if let Some(entries) = config.get_mut(&local_mac) {
                    entries.retain(|e| !(e.node_id == node_id));
                    if entries.is_empty() {
                        config.remove(&local_mac);
                    }
                }
                write_static_ngh(&config)?;
                println!("Deleted NodeID resolving: {} via dev {}",
                    colorize(&node_id.to_string(), ansi_color::GREEN),
                    colorize(&dev, ansi_color::BOLD))
            }
            // TODO: nhipctl neighbor resolve
            // NeighborAction::Resolve { 
            //     node_id, 
            //     dev 
            // } => {
            //     let config = load_static_ngh()?;
            //     let local_mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", dev))?
            //     .trim()
            //     .to_string();
            //     if let Some(entries) = config.get(&local_mac) {
            //         for entry in entries.iter() {
            //             if entry.node_id == node_id {
            //                 println!("Already resolved: {} is at {} (dev {})",
            //                     colorize(&node_id.to_string(), ansi_color::GREEN),
            //                     colorize(&entry.mac, ansi_color::YELLOW),
            //                     colorize(&dev, ansi_color::BOLD)
            //                 )
            //             }
                        
            //         }
            //     } else {
            //         let mut stream = UnixStream::connect("/var/run/nhipd.sock")?;
            //         let cmd = format!("RESOLVE {} {}", node_id, ifname_to_index(&dev)?);
            //         stream.write(cmd.as_bytes())?;
            //         return Ok(())
            //     }
            // },
            NeighborAction::Show => {
                // Load static config
                let config = load_static_ngh()?;

                // Load dynamic from eBPF map
                let hostname = std::fs::read_to_string("/etc/hostname")
                    .unwrap_or_else(|_| "default".to_string()).trim().to_string();
                let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/nharp", hostname))
                    .context("Failed to open NHARP_TABLE")?;
                let map = aya::maps::Map::HashMap(map_data);
                let table: aya::maps::HashMap<&MapData, NharpKey, NharpEntry> = aya::maps::HashMap::try_from(&map)?;
                
                // Header
                println!(
                    "{}{:<10} {:<35} {:<20} {:<10}{}",
                    ansi_color::BOLD,
                    "Interface",
                    "NodeID",
                    "MAC",
                    "Type",
                    ansi_color::RESET
                );

                // Show Static
                for (local_mac_str, entries) in &config {
                    let local_mac = parse_mac(&local_mac_str)?;
                    let ifname = get_ifname_from_mac(&local_mac)?;
                    for entry in entries {
                        let node_id = entry.node_id;
                        let remote_mac = entry.mac.clone();

                        // output
                        println!(
                            "{:<10} {:<35} {:<20} {:<10}",
                            ifname,
                            node_id,
                            remote_mac,
                            "Static",
                        );
                    }
                }

                // Show dynamic
                for entry in table.iter() {
                    match entry {
                        Ok((key, mac_entry)) => {
                            let ifname = ifname_from_index(key.ifindex)
                                .context(format!("Interface with index {} not found", &key.ifindex))?;
                            let node_id = key.node_id;
                            let mac = mac_entry.mac;

                            // dbg
                            let ifindex = ifname_to_index(&ifname)?;
                            println!("nharp_lookup: ifindex={} node_id={}", ifindex, node_id);
                            let bytes: &[u8] = unsafe {
                                std::slice::from_raw_parts(&key as *const _ as *const u8, 8)
                            };
                            println!("BYTES: {:02X?}", bytes);

                            // output
                            println!(
                                "{:<10} {:<35} {:<20} {:<10}",
                                ifname,
                                node_id,
                                mac_to_str(&mac)?,
                                "eBPF",
                            );

                        }
                        Err(e) => {
                            anyhow::bail!("Failed to read entry: {}", e);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
