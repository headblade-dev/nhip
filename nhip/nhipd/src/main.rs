use aya::{
        Ebpf, include_bytes_aligned, maps::{HashMap, MapData, MapError, Stack}, programs::{Xdp, XdpFlags}
};
use anyhow::{Context, Result};
use bytemuck::{Pod, Zeroable};
use env_logger::fmt::ConfigurableFormat;
use nharp::packet::NharpPacket;
use nhip_core::{
    header::{NHIP_ETHERTYPE, NHIP_HEADER_LEN},
    label
};
use nhip_cfg::*;
use std::{any, hash::Hash, ops::RemAssign, sync::Arc};
use tokio::{signal, sync::Mutex};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct NharpEntry {
    mac: [u8; 6],
    _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
struct ForwardEntry {
    next_label: u32,
    ifindex: u32,
    dmac: [u8; 6],
    _pad: [u8; 2],
}

struct NhipDaemon {
    bpf: Arc<Mutex<Ebpf>>,
    ifaces: Vec<String>,
}
impl NhipDaemon {
    // Find MAC by NodeID in NHARP cache
    async fn nharp_lookup(&self, node_id: u32) -> Result<Option<[u8;6]>> {
        let mut bpf = self.bpf.lock().await;
        if let Some(map) = bpf.map_mut("NHARP_TABLE") {
            let table: HashMap<_, u32, NharpEntry> = HashMap::try_from(map)?;
            Ok(table.get(&node_id).map(|e| e.mac))
        } else {
            Ok(None)
        }
    }

    // Add entry to NHARP cache
    async fn nharp_insert(&self, node_id: u32, mac: [u8;6]) -> Result<()> {
        let mut bpf = self.bpf.lock().await;
        let map = bpf.map_mut("NHARP_TABLE").context("NHARP_TABLE not found")?;
        table.insert(node_id, NharpEntry {mac, _pad: [0; 2] }, 0)?;
        log::info!("NHARP: {} -> {:02x?}", node_id, mac);
        Ok(())
    }

    // Handle NHARP-packet
    async fn handle_nharp(
        &self, 
        src_mac: [u8; 6], 
        packet: &NharpPacket,
    ) -> Result<()> {
        if packet.is_request() {
            // TODO: replace 0 with real ifindex from AF_XDP or AF_PACKET
            if self.is_my_node_id(0, packet.target_node_id) {
                log::info!("NHARP: Request received: Who has {}? Tell {}",
                            packet.target_node_id, packet.source_mac);
                self.nharp_insert(packet.source_node_id, mac).await?;
                // TODO: send reply
            }
        } else if packet.is_reply() {
            log::info!("NHARP: Reply received: {} is at {:02x?}",
                        packet.source_node_id, packet.source_mac);
            self.nharp_insert(packet.target_node_id, packet.source_mac);
        } else {}
        Ok(())
    }

    async fn is_my_node_id(&self, ifindex: u32, node_id: u32) -> Result<bool> {
        let config = load_addrs()?;
        let ifname = ifname_from_index(ifindex)?;
        let config = load_addrs()?;
        for entry in config {
            for addr in entry.addresses {
                
                if addr == ifname {
                    return Ok(true)
                }
            }
        }
        Ok(false)
    }

    // Start eBPF and connect intefaces:
    async fn new(ifaces: Vec<String>) -> Result<Self> {
        // Load eBPF bytecode
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/libnhipd_ebpf.a"
        ))
        .context("Failed to load eBPF bytecode")?;
        
        // Get XDP program
        let xdp_prog: &mut Xdp = bpf
            .program_mut("nhipd_xdp")
            .context("XDP program 'nhipd_xdp' not found in eBPF object")?
            .try_into()
            .context("Failed to cast program to XDP")?;

        // Connect to interfaces
        for iface in &ifaces {
            xdp_prog
                .attach(iface.as_str(),XdpFlags::default())
                .context(format!("Failed to attach XDP to {}", iface))?;
            log::info!("Attached XDP to {}", iface);
        }

        Ok(Self {
            bpf: Arc::new(Mutex::new(bpf)),
            ifaces,
        })
    }
    
    // Adding entries to FastPath Table
    async fn insert_fastpath(
        &self,
        label: u32,
        next_label: u32,
        ifindex: u32,
        dmac: [u8; 6],
    ) -> Result<()> {
        let entry = ForwardEntry {
            next_label,
            ifindex,
            dmac,
            _pad: [0, 2],
        };

        let mut bpf = self.bpf.lock().await;
        let map_data = bpf.map_mut("FASTPATH_TABLE")
                .context("Failed to access FASTPATH_TABLE")?;
        let mut table: HashMap<&mut MapData, u32, ForwardEntry> = aya::maps::HashMap::try_from(map_data)?;
        
        table.insert(label, entry, 0)?;
        log::info!("NHIPd FastPath: label {} -> {} allocated", label, next_label);
        Ok(())
    }


    // TODO: slowpass_handler
    async fn slowpass_handler(&self) {
        loop {}
    }
}

fn get_ifaces() -> Result<Vec<String>> {
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    log::info!("nhipd starting...");

    let ifaces = get_ifaces()?;
    let daemon = Arc::new(NhipDaemon::new(ifaces).await?);
    log::info!("NHIP Daemon started");

    let daemon_clone = daemon.clone();
    tokio::spawn(async move {
        daemon_clone.slowpass_handler().await;
    });

    tokio::signal::ctrl_c().await?;
    log::info!("Received SIGINT, NHIP Daemon shutting down.");
    Ok(())
}