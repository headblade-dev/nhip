use anyhow::{Context, Result};
use aya::{
    Ebpf, Pod, include_bytes_aligned, maps::{HashMap, Map, MapData}, programs::{Xdp, XdpFlags}
};
use bytemuck::{Zeroable};
use nharp::packet::{NharpPacket};
use nhip_cfg::*;
use nhip_core::{
    addr::parse_node_id, header::NHIP_ETHERTYPE
};
use std::{fs::read_to_string, os::fd::{AsRawFd, RawFd}, sync::Arc};
use tokio::io::unix::AsyncFd;

struct RawSocket {
    async_fd: AsyncFd<RawFd>,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        *self.async_fd.get_ref()
    }
}

impl RawSocket {
    fn new() -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET, 
                libc::SOCK_RAW | libc::SOCK_NONBLOCK, 
                (libc::ETH_P_ALL as i32).to_be())
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let buf_size: libc::c_int = 1024 * 1024 * 16; // 16 MB of buffer
        unsafe {
            libc::setsockopt( // for send
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt( // for receive
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let async_fd = AsyncFd::new(fd)
            .context("Failed to register AsyncFd")?;
        Ok(Self { async_fd })
    }

    async fn send(&self, ifindex: u32, data: &[u8]) -> Result<()> {
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8]
        };

        let mut guard = self.async_fd.writable().await?;
        let fd = *guard.get_inner();

        let ret = unsafe {
            libc::sendto(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                log::warn!("NHIP Daemon: TX buffer full, packet dropped on ifindex {}", ifindex);
                return Ok(());
            }
            return Err(err.into());
        }
        Ok(())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            let fd = *guard.get_inner();

            let ret = unsafe {
                libc::recv(
                    fd, 
                    buf.as_mut_ptr() as *mut libc::c_void, 
                    buf.len(), 
                    0
                )
            };

            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Err(err.into());
            }

            return Ok(ret as usize);
        }
    }

    
}

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
    bpf: Ebpf,
    ifaces: Vec<String>,
    socket: RawSocket,
}
impl NhipDaemon {
    // Find MAC by NodeID in NHARP cache
    async fn nharp_lookup(&self, node_id: u32) -> Result<Option<[u8; 6]>> {
        unimplemented!()
        // TODO: nharp_lookup(node_id: u32)
    }

    async fn nharp_send_reply(
        &self,
        ifindex: u32,
        remote_mac: [u8; 6],
        remote_node_id: u32,
        local_mac: [u8; 6],
        local_node_id: u32,
        packet: &NharpPacket
    ) -> Result<()> {
        // 1. Payload (DATA)
        let packet_data = NharpPacket::new_reply(local_node_id, local_mac, remote_node_id);

        // 2. Ethernet (L2)
        let eth_header = build_eth_header(
            local_mac,
            remote_mac,
            NHIP_ETHERTYPE
        );

        // 3. Write to a buffer
        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&eth_header));
        buf.extend_from_slice(bytemuck::bytes_of(&packet_data));

        // 4. Send
        self.send_raw_packet(ifindex, &buf).await?;
        Ok(())
    }

    async fn send_raw_packet(&self, ifindex: u32, buf: &[u8]) -> Result<()> {
        // TODO: sending raw packets via sockets
        unimplemented!();
    }

    // Add entry to NHARP cache
    async fn nharp_insert(&self, node_id: u32, mac: [u8; 6]) -> Result<()> {
        let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "default".to_string());
        let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/fastpath", hostname))
            .context("Failed to load FastPath Table from pin")?;
        let map = Map::HashMap(map_data);
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
        for entry in config {
            if entry.ifname == ifname {
                for addr in &entry.addresses {
                    if let Some(config_node_id_raw) = addr.rsplit(':').next() {
                        if let Ok(parsed_id) = parse_node_id(config_node_id_raw.as_bytes()) {
                            if parsed_id == node_id {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    // Start eBPF and connect intefaces:
    async fn new(ifaces: Vec<String>, mut bpf: Ebpf) -> Result<Self> {
        // Get XDP program
        let xdp_prog: &mut Xdp = bpf
            .program_mut("nhipd_xdp")
            .context("XDP program 'nhipd_xdp' not found in eBPF object")?
            .try_into()
            .context("Failed to cast program to XDP")?;

        // Connect to interfaces
        for iface in &ifaces {
            // XDP
            xdp_prog
                .attach(iface.as_str(), XdpFlags::default())
                .context(format!("Failed to attach XDP to {}", iface))?;
            log::info!("Attached XDP to {}", iface);
        }

        let socket = RawSocket::new()?;

        Ok(Self {
            bpf: bpf,
            ifaces,
            socket,
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

        // Get FastPath Table
        let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "default".to_string());
        let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/fastpath", hostname))?;
        let map = Map::HashMap(map_data);
        let mut fpt = HashMap::try_from(map)
            .context("InspectFastPath: Failed to load FastPath Table")?;

        fpt.insert(label, entry, 0)?;
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
}

fn build_eth_header(src_addr: [u8; 6], dst_addr: [u8; 6], ether_type: u16) -> [u8; 14] {
    let mut header = [0u8; 14];
    header[0..6].copy_from_slice(&dst_addr);
    header[6..12].copy_from_slice(&src_addr);
    header[12..14].copy_from_slice(&ether_type.to_be_bytes());
    header
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

#[cfg_attr(
    feature = "single_thread", 
    tokio::main(flavor = "current_thread")
)]
#[cfg_attr(
    not(feature = "single_thread"), 
    tokio::main(flavor = "multi_thread")
)]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    
    #[cfg(feature = "single_thread")]
    log::info!("Starting NHIP Daemon in single-thread mode");
    #[cfg(not(feature = "single_thread"))]
    log::info!("Starting NHIP Daemon in multi-thread mode");

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../nhipd-ebpf/target/bpfel-unknown-none/release/libnhipd_ebpf.a"
    )).context("Failed to load eBPF bytecode")?;

    // Pin eBPF tables
    std::fs::create_dir_all("/sys/fs/bpf/nhip")?;
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "default".to_string());
    let base_pin_dir = format!("/sys/fs/bpf/nhip/{}", hostname);

    // Pin FastPath Table
    let fpt = bpf.take_map("FASTPATH_TABLE")
        .context("Failed to take FASTPATH_TABLE")?;
    fpt.pin(format!("{}/fastpath", base_pin_dir))
        .context("Failed to pin FASTPATH_TABLE. Is target directory exist?")?;

    // Pin NHARP Table
    let nharp_table = bpf.take_map("NHARP_TABLE")
        .context("Failed to take NHARP_TABLE")?;
    nharp_table.pin(format!("{}/nharp", base_pin_dir))
        .context("Failed to pin NHARP_TABLE. Is target directory exist?")?;

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
