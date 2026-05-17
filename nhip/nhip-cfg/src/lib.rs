use serde::{Serialize, Deserialize};
use std::{fs::{read_dir, read_to_string, write}};
use anyhow::{Context, Result};

pub fn ifname_to_index(iface: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{}/ifindex", iface);

    let idx_str = std::fs::read_to_string(&path)
        .context(format!("Interface {} not found in /sys/class/net", iface))?;

    let idx: u32= idx_str.trim().parse()
        .context("Failed to parse ID to a number")?;
    Ok(idx)
}

pub fn ifname_from_index(ifindex: u32) -> Option<String> {
    if let Ok(entries) = read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = format!("/sys/class/net/{}/ifindex", name);
            if let Ok(idx_str) = read_to_string(&path) {
                if let Ok(idx) = idx_str.trim().parse::<u32>() {
                    if idx == ifindex {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

// Addresses

pub type AddressTable = Vec<AddressEntry>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressEntry {
    pub ifname: String,
    pub prefix: String,
    pub addresses: Vec<String>,
}

pub fn load_addrs() -> Result<Vec<AddressEntry>> {
    let content = read_to_string("/etc/nhip/addresses.conf")
        .context("Failed to read addresses.conf")?;
    serde_json::from_str(&content)
        .context("Failed to parse addresses.conf")
} 

pub fn write_addrs(config: &Vec<AddressEntry>) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    write("/etc/nhip/addresses.conf", json)
        .context("Failed to write addresses.conf")
}

// Routing

pub type RoutingTable = Vec<RouteEntry>;

#[derive(Serialize, Deserialize, Debug)]
pub struct RouteEntry {
    pub destination: String,
    pub next_hop: String,
    pub dev: String,
    pub proto: RoutingProto,
    pub priority: u8,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RoutingProto {
    Static,
    Ospf,
    Rip,
}

pub fn load_routes() -> Result<Vec<RouteEntry>> {
    let content = std::fs::read_to_string("/etc/nhip/routes.conf")
        .context("Failed to read routes.conf")?;
    serde_json::from_str(&content)
        .context("Failed to parse routes.conf")
}

pub fn write_routes(config: &Vec<RouteEntry>) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write("/etc/nhip/routes.conf", json)
        .context("Failed to write routes.conf")
}