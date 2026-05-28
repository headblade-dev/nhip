use nhip_core::header::{NHIP_DEFAULT_TTL, NHIP_VERSION, NhipHeader};
use serde::{Serialize, Deserialize};
use std::{fs::{read_dir, read_to_string, write}, collections::HashMap as StdHashMap};
use anyhow::{Context, Result};
use nhip_core::addr::parse_node_id;

#[allow(unused)] // colors
pub mod ansi_color {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const CYAN: &str = "\x1b[36m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const RED: &str = "\x1b[31m";
}

///
/// Check if specified NodeID is assigned on `ifindex`
/// 
/// * `ifindex` - interface to check
/// * `node_id` - node_id to check
/// 
/// # Behavior
/// * Loads addresses config from file
/// * Finds `node_id` in config entries
/// * Returns `Ok(true)` if found, otherwise `Ok(false)`
/// 
pub fn is_my_node_id(ifindex: u32, node_id: u32) -> Result<bool> {
    //  ---------------------
    //  Load config from file
    //  ---------------------
    let config = load_addrs()?;

    //  -----------------------------------
    //  Get ifname and return error on fail
    //  -----------------------------------
    let ifname = ifname_from_index(ifindex).ok_or_else(|| {
        log::error!("Failed to get ifname from index (nhipd:342)");
        anyhow::anyhow!("Failed to get ifname from index (nhipd:342)")
    })?;

    //  -----------------------------
    //  Find NodeID in config entries
    //  -----------------------------
    let found = config
        .iter()
        .filter(|entry| entry.ifname == ifname)
        .flat_map(|entry| entry.addresses.iter()) // перемещаем каждый address
        .filter_map(|addr| {
            addr.rsplit(':')
                .next()
                .map(|raw| (addr, raw))  
        })
        .find_map(|(addr, raw_id)| match parse_node_id(raw_id.as_bytes()) {
            Ok(parsed) => {
                log::debug!("Parsed: {}, argument: {}", parsed, node_id);
                if parsed == node_id {
                    Some(true)   // found!
                } else {
                    None         // not found!
                }
            }
            Err(_) => {
                log::warn!("Failed to parse NodeID (nhipd:351) for address {}", addr);
                None
            }
        });

    //  -----------------------------------------------------------------------------
    //  Return Ok(true) if NodeID found on this interface, otherwise return Ok(false)
    //  -----------------------------------------------------------------------------
    Ok(found.unwrap_or(false))
}

///
/// Apply color ANSI-Code for string slice and return colored String
/// 
/// * `text` - text to apply color
/// * `ansi_color` - ANSI-Code to apply (from `ansi_color` module)
/// 
/// # Behavior
/// * Uses `format!` with variables in this order: `color + text + default_style`
/// * Returns a colored `String` ready to be inserted into unformatted text.
/// 
pub fn colorize(text: &str, ansi_color: &str) -> String {
    format!("{}{}{}", ansi_color, text, ansi_color::RESET)
}

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

///
/// Pick `node_id`, associated with netpart of destination address
/// 
/// * `candidates` - list of pairs `(netpart, node_id)`
/// * `dst_netpart` - netpart of destination
/// 
pub fn pick_node_id_for_netpart<'a>(candidates: &'a [(String, u32)], dst_netpart: &str) -> Option<u32> {
    for (net, id) in candidates {
        if net == dst_netpart {
            return Some(*id);
        }
    }
    None
}

pub fn build_eth_header(src_addr: [u8; 6], dst_addr: [u8; 6], ether_type: u16) -> [u8; 14] {
    let mut header = [0u8; 14];
    header[0..6].copy_from_slice(&dst_addr);
    header[6..12].copy_from_slice(&src_addr);
    header[12..14].copy_from_slice(&ether_type.to_be_bytes());
    header
}

pub fn build_nhip_packet(
    src_addr: &[u8],
    src_node_id: u32,
    dst_addr: &[u8],
    dst_node_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut hdr = NhipHeader::new();
    hdr.set_version_flags(NHIP_VERSION, 0);
    hdr.pointer = 0;
    hdr.ttl = NHIP_DEFAULT_TTL;
    hdr.next_header = 0x01; // ICMP-NHIP (заглушка)
    hdr.link_label = 0; // Slow Path
    hdr.dst_addr_len = dst_addr.len() as u16;
    hdr.src_addr_len = src_addr.len() as u16;
    hdr.payload_length = payload.len() as u16;

    let mut buf = Vec::new();
    buf.extend_from_slice(bytemuck::bytes_of(&hdr));
    buf.extend_from_slice(dst_addr);
    buf.extend_from_slice(&dst_node_id.to_be_bytes());
    buf.extend_from_slice(src_addr);
    buf.extend_from_slice(&src_node_id.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn expand_tilde(addr: &str, dev: &str, config: &[AddressEntry]) -> Result<String> {
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