use serde::{Serialize, Deserialize};
use std::{fs::{read_dir, read_to_string, write}, collections::HashMap as StdHashMap};
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

pub fn parse_mac(string: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = string.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("Invalid MAC-address: {}", string);
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)?;
    }

    Ok(mac)
}

pub fn mac_to_str(mac: &[u8; 6]) -> Result<String> {
    let mac_str = mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":");

    Ok(mac_str)
}

pub fn build_eth_header(src_addr: [u8; 6], dst_addr: [u8; 6], ether_type: u16) -> [u8; 14] {
    let mut header = [0u8; 14];
    header[0..6].copy_from_slice(&dst_addr);
    header[6..12].copy_from_slice(&src_addr);
    header[12..14].copy_from_slice(&ether_type.to_be_bytes());
    header
}

pub fn get_mac(ifindex: u32) -> Result<[u8; 6]> {
    let ifname = ifname_from_index(ifindex)
        .context(format!("Interface with index {} not found", ifindex))?;

    let mac_path = format!("/sys/class/net/{}/address", ifname);
    let mac_str = read_to_string(&mac_path)
        .context(format!("Failed to read MAC-address for {}", ifname))?;
    let mac_str = mac_str.trim();

    let parts: Vec<&str> = mac_str.split(':').collect();
    anyhow::ensure!(parts.len() == 6, "Invalid MAC format: {}", mac_str);

    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .context(format!("Invalid MAC-octet: {}", part))?;
    }

    Ok(mac)
}

pub fn proto_to_ad(proto: &RoutingProto) -> u8 {
    match proto {
        RoutingProto::Static => 1,
        RoutingProto::Ospf => 110,
        RoutingProto::Rip => 120,
        RoutingProto::Unknown => 255,
    }
}

pub fn get_ifaces() -> Result<Vec<String>> {
    let mut ifaces = Vec::new();
    let dir = std::fs::read_dir("/sys/class/net")
        .context("Failed to read /sys/class/net. Is this directory exist?")?;

    for entry in dir {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name != "lo" && !name.is_empty() {
            ifaces.push(name);
        }
    }
    if ifaces.is_empty() {
        anyhow::bail!("No allowed network interfaces found");
    }
    log::info!("Found interfaces: {:?}", ifaces);
    Ok(ifaces)
}

pub fn get_ifname_from_mac(mac: &[u8; 6]) -> Result<String> {
    let ifaces = get_ifaces().expect("No network interfaces found");
    for ifname in ifaces {
        let parsed_mac = parse_mac(&read_to_string(format!("/sys/class/net/{}/address", ifname))?)?;
        if mac == &parsed_mac {
            return Ok(ifname)
        }
    }

    anyhow::bail!("No interface with this MAC found");
}


// Addresses

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub next_hop: String,
    pub dev: String,
    pub proto: RoutingProto,
    pub priority: u8,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum RoutingProto {
    Static,
    Ospf,
    Rip,
    Unknown,
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

// NHARP 

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NharpConfigEntry {
    pub node_id: u32,
    pub mac: String,
}

pub fn load_static_ngh() -> Result<StdHashMap<String, Vec<NharpConfigEntry>>> {
    let content = std::fs::read_to_string("/etc/nhip/static_ngh.conf")
        .context("Failed to read static_ngh.conf")?;
    serde_json::from_str(&content)
        .context("Failed to parse static_ngh.conf")
}

pub fn write_static_ngh(config: &StdHashMap<String, Vec<NharpConfigEntry>>) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write("/etc/nhip/static_ngh.conf", json)
        .context("Failed to write static_ngh.conf")
}