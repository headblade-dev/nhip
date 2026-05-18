use anyhow::{Context, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{HashMap, MapData},
    programs::{Xdp, XdpFlags},
    Pod
};
use bytemuck::{Zeroable};
use network_types::eth::{EthHdr};
use nharp::packet::{NharpPacket};
use nhip_cfg::*;
use nhip_core::{
    header::{NHIP_ETHERTYPE, NHIP_VERSION, NHIPHeader, next_header},
    label::get_link_hash,
};
use std::{fs::{read_to_string}, sync::Arc};
use tokio::{sync::Mutex};

#[repr(C)]
#[derive(Clone, Copy, Zeroable)]
struct NharpEntry {
    mac: [u8; 6],
    _pad: [u8; 2],
}

unsafe impl Pod for NharpEntry {}

type FastPathKey = u32;
type FastPathTable = HashMap<MapData, FastPathKey, ForwardEntry>;

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable)]
struct ForwardEntry {
    next_label: u32,
    ifindex: u32,
    dmac: [u8; 6],
    _pad: [u8; 2],
}

unsafe impl Pod for ForwardEntry {}

struct NhipDaemon {
    bpf: Arc<Mutex<Ebpf>>,
    ifaces: Vec<String>,
}
impl NhipDaemon {
    // Find MAC by NodeID in NHARP cache
    async fn nharp_lookup(&self, node_id: u32) -> Result<Option<[u8; 6]>> {
        panic!()
    }

    #[allow(unused)]
    async fn nharp_send_reply(
        &self,
        ifindex: u32,
        target_mac: [u8; 6],
        target_node_id: u32,
        target_addr: &[u8],
        my_mac: [u8; 6],
        my_node_id: u32,
        my_addr: &[u8],
    ) -> Result<()> {
        let nharp = NharpPacket::reply(my_node_id, my_mac, target_node_id);

        let mut nhip_hdr = NHIPHeader::new();
        nhip_hdr.set_version_flags(NHIP_VERSION, 0);
        nhip_hdr.link_label = get_link_hash(&my_mac, &target_mac);
        nhip_hdr.next_header = next_header::NHARP;
        nhip_hdr.dst_addr_len = target_addr.len() as u16;
        nhip_hdr.src_addr_len = my_addr.len() as u16;
        nhip_hdr.payload_length = NharpPacket::SIZE as u16;

        let mut eth_hdr = EthHdr {
            dst_addr: target_mac, 
            src_addr: my_mac, 
            ether_type: NHIP_ETHERTYPE.to_be()
        };
        Ok(())
    }

    // Add entry to NHARP cache
    async fn nharp_insert(&self, node_id: u32, mac: [u8; 6]) -> Result<()> {
        let mut bpf = self.bpf.lock().await;
        let map = bpf
            .map_mut("NHARP_TABLE")
            .context("NHARP_TABLE not found")?;
        let mut table: HashMap<_, u32, NharpEntry> = HashMap::try_from(map)?;
        table.insert(node_id, NharpEntry { mac, _pad: [0; 2] }, 0)?;
        log::info!("NHARP: {} -> {:02x?}", node_id, mac);
        Ok(())
    }

    

    // Handle NHARP-packet
    async fn handle_nharp(
        &self,
        ifindex: u32,
        src_mac: [u8; 6],
        src_addr: &[u8],
        src_node_id: u32,
        packet: &NharpPacket,
    ) -> Result<()> {
        self.nharp_insert(packet.source_node_id, packet.source_mac).await?;

        if packet.is_request() {
            // TODO: replace 0 with real ifindex from AF_XDP or AF_PACKET
            let test_ifindex: u32 = 0;
            let dst_node_id = packet.target_node_id;
            let src_node_id = packet.source_node_id;

            if self.is_my_node_id(0, packet.target_node_id).await.unwrap() {
                log::info!(
                    "NHARP: Request received to me: Who has {}? Tell {:02x?}",
                    dst_node_id,
                    packet.source_mac
                );

                let my_mac = get_mac(ifindex)?;

                self.nharp_insert(packet.source_node_id, packet.source_mac).await?;
                
                // TODO: nharp send reply
                
            }
        } else if packet.is_reply() {
            log::info!(
                "NHARP: Reply received: {} is at {:02x?}",
                src_node_id,
                packet.source_mac
            );
            self.nharp_insert(packet.target_node_id, packet.source_mac).await?;
        } else {
        }
        Ok(())
    }

    async fn is_my_node_id(&self, ifindex: u32, node_id: u32) -> Result<bool> {
        let config = load_addrs()?;
        let ifname = ifname_from_index(ifindex)
            .context("Failed to get ifname from ifindex")?;
        let config = load_addrs()?;
        for entry in config {
            for addr in entry.addresses {
                if addr == ifname {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    // Start eBPF and connect intefaces:
    async fn new(ifaces: Vec<String>, bpf: Arc<Mutex<Ebpf>>) -> Result<Self> {
        let mut bpf_locked = bpf.lock().await;

        // Get XDP program
        let xdp_prog: &mut Xdp = bpf_locked
            .program_mut("nhipd_xdp")
            .context("XDP program 'nhipd_xdp' not found in eBPF object")?
            .try_into()
            .context("Failed to cast program to XDP")?;

        // Connect to interfaces
        for iface in &ifaces {
            xdp_prog
                .attach(iface.as_str(), XdpFlags::default())
                .context(format!("Failed to attach XDP to {}", iface))?;
            log::info!("Attached XDP to {}", iface);
        }

        drop(bpf_locked);

        Ok(Self {
            bpf: bpf,
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
        let map_data = bpf
            .map_mut("FASTPATH_TABLE")
            .context("Failed to access FASTPATH_TABLE")?;
        let mut table: HashMap<&mut MapData, u32, ForwardEntry> =
            aya::maps::HashMap::try_from(map_data)?;

        table.insert(label, entry, 0)?;
        log::info!(
            "NHIPd FastPath: label {} -> {} allocated",
            label,
            next_label
        );
        Ok(())
    }

    // TODO: slowpass_handler
    async fn slowpass_handler(&self) {
        loop {}
    }

    async fn init_fastpath_table(bpf: &mut Ebpf) -> Result<FastPathTable> {
    let map = bpf.take_map("FASTPATH_TABLE")
        .context("FastPath Table not found or moved")?;

    let table = HashMap::<MapData, u32, ForwardEntry>::try_from(map)?;                        
    Ok(table)
}
}


fn get_mac(ifindex: u32) -> Result<[u8; 6]> {
    let ifname = nhip_cfg::ifname_from_index(ifindex)
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

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../nhipd-ebpf/target/bpfel-unknown-none/release/libnhipd_ebpf.a"
    )).context("Failed to load eBPF bytecode")?;

    std::fs::create_dir_all("/sys/fs/bpf/nhip")?;

    // Pin FastPath Table
    let fpt = bpf.take_map("FASTPATH_TABLE")
        .context("Failed to take FASTPATH_TABLE")?;
    fpt.pin("/sys/fs/bpf/nhip/fastpath")
        .context("Failed to pin FASTPATH_TABLE. Is target directory exist?")?;

    std::fs::create_dir_all("/sys/fs/bpf/nhip")?;

    let bpf = Arc::new(Mutex::new(bpf));

    let ifaces = get_ifaces()?;
    let daemon = Arc::new(NhipDaemon::new(ifaces, bpf).await?);
    log::info!("NHIP Daemon started");
    

    let daemon_clone = daemon.clone();
    tokio::spawn(async move {
        daemon_clone.slowpass_handler().await;
    });

    tokio::signal::ctrl_c().await?;
    log::info!("Received SIGINT, NHIP Daemon shutting down.");
    Ok(())
}
