// .nhip/nhipd/src/main.rs

use anyhow::{Context, Result};
use aya::{
    Ebpf, Pod, include_bytes_aligned, maps::{HashMap, Map, MapData}, programs::{Xdp, XdpFlags}
};
use bytemuck::{Zeroable};
use nharp::{NHARP_ETHER_TYPE, packet::NharpPacket};
use nhip_cfg::*;
use nhip_core::{
    addr::{get_node_id_from_addr_str, parse_node_id}, header::{NHIP_ETHERTYPE, NHIP_HEADER_LEN, NhipHeader}
};
use std::{fs::read_to_string, os::{fd::{AsRawFd, RawFd}}, sync::Arc};
use tokio::io::unix::AsyncFd;
use tokio::time::{sleep, Duration};

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
            libc::setsockopt( // for receive
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &buf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt( // for send
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

    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, u32)> {
        loop {
            let mut guard = self.async_fd.readable().await?;
            let fd = *guard.get_inner();

            let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addrlen: libc::socklen_t = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

            let ret = unsafe {
                libc::recvfrom(
                    fd, 
                    buf.as_mut_ptr() as *mut libc::c_void, 
                    buf.len(), 
                    0,
                    &mut sll as *mut _ as *mut libc::sockaddr,
                    &mut addrlen as *mut libc::socklen_t                    
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

            return Ok((ret as usize, sll.sll_ifindex as u32));
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable)]
struct ForwardEntry {
    next_label: u64,
    ifindex: u32,
    dmac: [u8; 6],
    _pad: [u8; 2],
}

unsafe impl Pod for ForwardEntry {}

struct NhipDaemon {
    _bpf: Ebpf,
    ifaces: Vec<String>,
    socket: RawSocket,
}
impl NhipDaemon {
    // Find MAC by NodeID in NHARP cache
    async fn nharp_lookup(&self, node_id: u32) -> Result<Option<[u8; 6]>> {
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "default".to_string());
        let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/nharp", hostname))
            .context("Failed to open NHARP_TABLE")?;

        let map = Map::HashMap(map_data);
        let table: HashMap<&MapData, u32, NharpEntry> = HashMap::try_from(&map)?;

        match table.get(&node_id, 0) {
            Ok(entry) => Ok(Some(entry.mac)),
            Err(_) => Ok(None)
        }
    }

    async fn nharp_send_reply(
        &self,
        ifindex: u32,
        remote_mac: [u8; 6],
        remote_node_id: u32,
        local_mac: [u8; 6],
        local_node_id: u32,
    ) -> Result<()> {
        // 1. Payload (DATA)
        let packet_data = NharpPacket::new_reply(local_node_id, local_mac, remote_node_id);

        // 2. Ethernet (L2)
        let eth_header = build_eth_header(
            local_mac,
            remote_mac,
            NHARP_ETHER_TYPE
        );

        // 3. Write to a buffer
        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&eth_header));
        buf.extend_from_slice(bytemuck::bytes_of(&packet_data));

        // 4. Send
        self.socket.send(ifindex, &buf).await
    }

    async fn nharp_send_request(
        &self,
        ifindex: u32,
        remote_node_id: u32
    ) -> Result<()> {
        let local_node_id = self.get_node_if_from_ifindex(ifindex).await?
            .context(format!("Failed to get NodeID for interface {}", ifname_from_index(ifindex).unwrap_or(String::from("<unknown>"))))?;
        let local_mac = get_mac(ifindex)?;
        let packet_data = NharpPacket::new_request(
            local_node_id, 
            local_mac, 
            remote_node_id);

        let eth_header = build_eth_header(
            local_mac,
            [255u8; 6],
            NHARP_ETHER_TYPE
        );

        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&eth_header));
        buf.extend_from_slice(bytemuck::bytes_of(&packet_data));

        self.socket.send(ifindex, &buf).await
    }

    // Add entry to NHARP cache
    async fn nharp_insert(&self, node_id: u32, mac: [u8; 6]) -> Result<()> {
        let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "default".to_string());
        let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/nharp", hostname))
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
        packet: &NharpPacket,
    ) -> Result<()> {
        let remote_node_id = packet.source_node_id;
        let local_node_id = packet.target_node_id;

        self.nharp_insert(packet.source_node_id, packet.source_mac).await?;

        if packet.is_request() {

            if self.is_my_node_id(ifindex, local_node_id).await? {
                log::info!(
                    "NHARP: Request received to me: Who has {}? Tell {:02x?}",
                    remote_node_id,
                    packet.source_mac
                );

                self.nharp_send_reply(
                    ifindex, 
                    packet.source_mac, 
                    packet.source_node_id, 
                    get_mac(ifindex)?, 
                    packet.target_node_id
                ).await?;
                
            }
        } else if packet.is_reply() {
            log::info!(
                "NHARP: Reply received: {} is at {:02x?}",
                remote_node_id,
                packet.source_mac
            );
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
            _bpf: bpf,
            ifaces,
            socket,
        })
    }

    // Adding entries to FastPath Table
    async fn insert_fastpath(
        &self,
        label: u64,
        next_label: u64,
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

    async fn get_node_if_from_ifindex(&self, ifindex: u32) -> Result<Option<u32>> {
        let config = load_addrs()?;
        let ifname = ifname_from_index(ifindex)
            .context("Failed to get ifname from ifindex")?;
        for entry in config {
            if entry.ifname == ifname {
                for addr in &entry.addresses {
                    if let Some(config_node_id_raw) = addr.rsplit(':').next() {
                        if let Ok(parsed_id) = parse_node_id(config_node_id_raw.as_bytes()) {
                            return Ok(Some(parsed_id))
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    async fn forward_slowpass(&self,
        nhip_header: &NhipHeader, 
        rest: &[u8]
    ) -> Result<()> {
        let dst_addr_len = nhip_header.dst_addr_len as usize;
        let src_addr_len = nhip_header.src_addr_len as usize;
        let pointer = nhip_header.pointer;

        // Check rest size
        let min_rest = dst_addr_len + 4 + src_addr_len + 4; // 2 addrs + 2 node_ids
        if rest.len() < min_rest {
            log::warn!("Too short NHIP packet variable part: {} bytes, need {}", rest.len(), min_rest);
            return Ok(())
        }

        // Parse addresses
        let dst_addr = &rest[..dst_addr_len];
        let dst_node_id = u32::from_be_bytes(rest[dst_addr_len .. (dst_addr_len + 4)].try_into()?);

        let src_addr = &rest[(dst_addr_len + 4) .. (dst_addr_len + 4 + src_addr_len)];
        let src_node_id = u32::from_be_bytes(
            rest[(dst_addr_len + 4 + src_addr_len) .. (dst_addr_len + 8 + src_addr_len)]
        .try_into()?);

        let pointed_dst_addr = if pointer > 0 && (pointer as usize) < dst_addr.len() {
            &dst_addr[pointer as usize..]
        } else {
            dst_addr
        };

        let payload = &rest[dst_addr_len + 8 + src_addr_len..];

        let routes = load_routes()?;
        
        let pointed_dst_str = std::str::from_utf8(pointed_dst_addr)
            .context("Pointed destination address is not a valid UTF-8 string")?;

        let prefix = if pointer > 0 && (pointer as usize) < dst_addr.len() {
            std::str::from_utf8(&dst_addr[..pointer as usize])?
        } else {
            ""
        };

        let blocks: Vec<&str> = pointed_dst_str
            .split('.')
            .collect();

        let mut candidates: Vec<&RouteEntry> = routes
            .iter()
            .filter(|r| r.destination == "default")
            .collect();

        let mut processed_str = String::from(prefix);
        for (i, block) in blocks.iter().enumerate() {
            if i > 0 {
                processed_str.push('.');
            }
            processed_str.push_str(block);

            let matching: Vec<&RouteEntry> = routes
                .iter()
                .filter(|r| r.destination == processed_str)
                .collect();

            if !matching.is_empty() {
                candidates.extend(matching);
            }
        }

        let best_ad = candidates
            .iter()
            .map(|r| proto_to_ad(&r.proto))
            .min()
            .unwrap_or(255);

        candidates.retain(|r| proto_to_ad(&r.proto) == best_ad);

        let best_priority = candidates
            .iter()
            .map(|r| r.priority)
            .min()
            .unwrap_or(255);

        candidates.retain(|r| &r.priority == &best_priority);

        if candidates.len() > 1 {
            let max_len = candidates
                .iter()
                .map(|r| r.destination.len())
                .max()
                .unwrap_or(0);
            candidates.retain(|r| r.destination.len() == max_len);
        }

        let route = candidates.first()
            .context(format!("No route to destination: {}{}", prefix, pointed_dst_str))?;

        // == Redirecting == 
        let next_node_id = get_node_id_from_addr_str(&route.next_hop).ok()
            .context("Failed to get NodeID from next hop address")?;
        let out_ifindex = ifname_to_index(&route.dev)?;
        let local_mac = get_mac(out_ifindex)?;
        

        // nharp lookup
        let next_mac = self.nharp_lookup(next_node_id).await?;
        match next_mac {
            Some(_) => {}
            None => {
                self.nharp_send_request(
                    out_ifindex, 
                    next_node_id
                ).await?;
                log::warn!("SlowPass: Can't find MAC-address for NodeID :{}. Packet has been dropped. Sending NHARP request...", next_node_id);
                return Ok(())
            }
        }
        let next_mac = next_mac.unwrap();

        let new_label = nhip_core::label::get_link_hash(&local_mac, &next_mac, dst_addr);

        let new_pointer = if route.destination == "default" {
            pointer
        } else {
            let raw_pointer = route.destination.len() as u8 + 1;

            if raw_pointer as usize >= dst_addr.len() || dst_addr[raw_pointer as usize] == b':' {
                0xFF
            } else {
                raw_pointer
            }
        };


        let current_label = u64::from_be(nhip_header.link_label);

        self.insert_fastpath(current_label, new_label, out_ifindex, next_mac).await?;

        let mut new_hdr = *nhip_header;
        new_hdr.link_label = new_label.to_be();
        new_hdr.pointer = new_pointer;
        new_hdr.ttl -= 1;

        let eth_bytes = build_eth_header(local_mac, next_mac, NHIP_ETHERTYPE);

        let nhip_bytes = bytemuck::bytes_of(&new_hdr);
        
        let mut buf = Vec::new();
        // ethernet
        buf.extend_from_slice(&eth_bytes);
        // nhip
        buf.extend_from_slice(nhip_bytes);
        // addresses
        buf.extend_from_slice(dst_addr);
        buf.extend_from_slice(&dst_node_id.to_be_bytes());
        buf.extend_from_slice(src_addr);
        buf.extend_from_slice(&src_node_id.to_be_bytes());
        // payload
        buf.extend_from_slice(payload);

        self.socket.send(out_ifindex, &buf).await
    }

    async fn recv_handler(&self) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        loop {
            let (n, ifindex) = match self.socket.recv(&mut buf).await {
                Ok(res) => res,
                Err(e)=> {
                    log::error!("recv error: {}", e);
                    continue;
                }
            };

            let data = &buf[..n];

            // Min Ethernet header length (14 bytes)
            if data.len() < 14 {
                log::warn!("Short packet: {} bytes", data.len());
                continue;
            }

            // Ethernet header
            let mut dst_mac = [0u8; 6];
            let mut src_mac = [0u8; 6];
            dst_mac.copy_from_slice(&data[..6]);
            src_mac.copy_from_slice(&data[6..12]);
            let ether_type = u16::from_be_bytes([data[12], data[13]]);

            match ether_type {
                // NHARP
                NHARP_ETHER_TYPE => {
                    let payload = &data[14..];

                    if payload.len() < 15 {
                        log::warn!("NHARP payload too short: {} bytes", payload.len());
                        continue;
                    }

                    let packet: &NharpPacket = bytemuck::from_bytes(&payload[..15]);

                    if let Err(e) = self.handle_nharp(ifindex, packet).await {
                        log::error!("Failed to handle NHARP packet: {}", e);
                    };
                }

                NHIP_ETHERTYPE => {
                    let nhip_bytes = &data[14..];

                    if nhip_bytes.len() < NHIP_HEADER_LEN {
                        log::warn!("NHIP packet is too short: {} bytes", nhip_bytes.len());
                        continue;
                    }

                    let nhip_header: &NhipHeader = bytemuck::from_bytes(&nhip_bytes[..NHIP_HEADER_LEN]);

                    // get all after static header part: addresses and payload
                    let rest: &[u8] = &nhip_bytes[NHIP_HEADER_LEN..];
                    
                    // send to SlowPass
                    self.forward_slowpass(nhip_header, rest).await?;
                }

                _ => {}
            }
        }
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

fn proto_to_ad(proto: &RoutingProto) -> u8 {
    match proto {
        RoutingProto::Static => 1,
        RoutingProto::Ospf => 110,
        RoutingProto::Rip => 120,
        RoutingProto::Unknown => 255,
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

    // Pinning eBPF tables
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

    // Pin IFACE_MAC Table
    let iface_mac_table = bpf.take_map("IFACE_MAC")
        .context("Failed to take IFACE_MAC table")?;
    iface_mac_table.pin(format!("{}/iface_mac", base_pin_dir))
        .context("Failed to pin IFACE_MAC table. Is target directory exist?")?;


    // Start daemon
    let ifaces = get_ifaces()?;
    let daemon = Arc::new(NhipDaemon::new(ifaces, bpf).await?);
    log::info!("NHIP Daemon started");
    
    // setting up receiver
    let daemon_receiver: Arc<NhipDaemon> = daemon.clone();
    tokio::spawn(async move {
        daemon_receiver.recv_handler().await
            .expect("Failed to start receiver");
    });


    // when mac-addresses changes - write IFACE_MAC
    let daemon_mac_checker = daemon.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;

            let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or(String::from("default"));

            for ifname in &daemon_mac_checker.ifaces {
                let ifindex = match ifname_to_index(ifname) {
                    Ok(idx) => idx,
                    Err(_) => continue,
                };

                let current_mac = match get_mac(ifindex) {
                    Ok(mac) => mac,
                    Err(_) => continue,
                };

                if let Ok(map_data) = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/iface_mac", hostname)) {
                    let map = Map::HashMap(map_data);
                    if let Ok(mut table) = HashMap::<MapData, u32, [u8; 6]>::try_from(map) {
                        table.insert(ifindex, current_mac, 0).ok();
                    }
                }


            }
        }
    });

    tokio::signal::ctrl_c().await?;
    log::info!("Received SIGINT, NHIP Daemon shutting down.");
    Ok(())
}
