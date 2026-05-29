// external
use anyhow::{Context, Result};
use aya::{
    Ebpf, maps::{HashMap, Map, MapData}, programs::{Xdp, XdpFlags}
};
use bytemuck::{self as bm};
use nharp::{NHARP_ETHER_TYPE, packet::NharpPacket};

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::oneshot;

// local crates
use nhip_cfg::*;
use nhip_core::{
    addr::{get_node_id_from_addr_str, parse_node_id}, header::{NHIP_DEFAULT_TTL, NHIP_ETHERTYPE, NHIP_HEADER_LEN, NHIP_VERSION, NhipHeader, next_header}
};
use crate::socket::RawSocket;
use crate::nharp_ctl::{NharpEntry, NharpKey};

pub struct NhipDaemon {
    pub _bpf: Ebpf,
    pub ifaces: Vec<String>,
    pub socket: RawSocket,
    pub pong_sender: Arc<Mutex<Option<oneshot::Sender<String>>>>,
    pub nharp_table: RwLock<HashMap<MapData, NharpKey, NharpEntry>>,
}
impl NhipDaemon {
    ///
    /// Updates IFACE_MAC table if MAC-addresses has been changed
    /// 
    /// *Using only for MAC-updater background task*
    /// 
    pub async fn update_iface_mac_maps(&self) -> Result<()> {
        let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or(String::from("default")).trim().to_string();

        for ifname in &self.ifaces {
            let ifindex = match ifname_to_index(&ifname) {
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
        Ok(())
    }

    /// 
    /// Initialize the daemon.
    /// 
    /// * `ifaces` - list of interface names that the daemon shoud attach to.
    /// * `bpf` - already-loaded eBPF object (the XDP program is extrated from it)
    /// 
    /// # Behavior
    /// * Attaches the XDP program to every interface in `ifaces`
    /// * Creates a raw AF_SOCKET wrapped in a `AsyncFd`
    /// 
    pub async fn new(ifaces: Vec<String>, mut bpf: Ebpf) -> Result<Self> {
        //  ------------------------------
        //  Load the XDP program from eBPF
        //  ------------------------------
        let xdp_prog: &mut Xdp = bpf
            .program_mut("nhipd_xdp")
            .context("XDP program 'nhipd_xdp' not found in eBPF object")?
            .try_into()
            .context("Failed to cast program to XDP")?;

        xdp_prog.load().context("Failed to load XDP Program")?;

        //  ------------------------
        //  Attach XDP to interfaces
        //  ------------------------
        for iface in &ifaces {
            // XDP
            xdp_prog
                .attach(iface.as_str(), XdpFlags::default())
                .context(format!("Failed to attach XDP to {}", iface))?;
            log::info!("Attached XDP to {}", iface);
        }

        //  ---------------------------------------------
        //  Create raw socket for sending Ethernet-frames
        //  ---------------------------------------------
        let socket = RawSocket::new()?;

        //  ------------------------------------------------
        //  Prepare directory where eBPF maps will be pinned
        //  ------------------------------------------------
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "default".to_string())
            .trim()
            .to_string();

        let base_pin_dir = format!("/sys/fs/bpf/nhip/{}", hostname);
        // Clean any prevous pins (useful for restarts during development)
        let _ = std::fs::remove_dir_all(&base_pin_dir);
        std::fs::create_dir_all(&base_pin_dir)
            .context(format!("Failed to create pin directory '{}'", &base_pin_dir))?;

        //  -----------------------------------------------------------------------
        //  Pin maps we need and wrap NharpTable to a high-level HashMap for RwLock
        //  -----------------------------------------------------------------------
        //  FastPath table
        let fpt = bpf
            .take_map("FASTPATH_TABLE")
            .context("Failed to take FASTPATH_TABLE")?;
        fpt.pin(format!("{base_pin_dir}/fastpath"))
            .context("Failed to pin FASTPATH_TABLE")?;

        // NHARP Table
        let nharp_map = bpf
            .take_map("NHARP_TABLE")
            .context("Failed to take NHARP_TABLE")?;
        nharp_map.pin(format!("{base_pin_dir}/nharp"))
            .context("Failed to pin NHARP_TABLE")?;

        // IFACE_MAC table (used by other parts of the daemon)
        let iface_mac_map = bpf
            .take_map("IFACE_MAC")
            .context("Failed to take IFACE_MAC")?;
        iface_mac_map.pin(format!("{base_pin_dir}/iface_mac"))
            .context("Failed to pin IFACE_MAC")?;

        // HashMap for RwLock<NHARP_TABLE>
        let map_data = MapData::from_pin(format!("/sys/fs/bpf/nhip/{}/nharp", hostname))
            .context("Failed to open NHARP_TABLE")?;
        let map = Map::HashMap(map_data);
        let nharp_table = HashMap::try_from(map)
            .context("Failed to convert NHARP map to HashMap wrapper")?;

        //  ------------------------
        //  Return the daemon struct
        //  ------------------------
        Ok(Self {
            _bpf: bpf,   // keep the eBPF object alive for keeping XDP alive)
            ifaces,
            socket,
            pong_sender: Arc::new(Mutex::new(None)),
            nharp_table: RwLock::new(nharp_table),
        })
    }

    ///
    /// Find all addresses associated with interface
    /// 
    /// * `ifindex` - kernel interface index
    /// 
    pub async fn get_addrs_from_ifindex(&self, ifindex: u32) -> Result<Vec<(String, u32)>> {
        //  --------------------------------
        //  Load the configuration from file
        //  --------------------------------
        let config = load_addrs()
            .context("Failed to load addresses")?;

        //  ----------------------------------------
        //  Resolve the interface name using ifindex
        //  ----------------------------------------
        let ifname = ifname_from_index(ifindex)
            .context(format!("Failed to get ifname from ifindex {ifindex}"))?;

        //  --------------------------------------------
        //  Walk through all addresses of this interface
        //  --------------------------------------------
        let result: Vec<(String, u32)> = config
            .iter()
            .filter(|entry| entry.ifname == ifname)
            .flat_map(|entry| entry.addresses.iter())
            .filter_map(|addr| {
                let mut parts = addr.rsplitn(2, ':');
                let raw_node_id = parts.next()?;
                let netpart = parts.next()?.to_string();
                match parse_node_id(raw_node_id.as_bytes()) {
                    Ok(node) => Some((netpart, node)),
                    Err(_) => {
                        log::debug!("Failed to parse NodeID from address {addr}");
                        None
                    }
                }
            })
            .collect();

        Ok(result)
    }

    pub async fn recv_handler(&self) -> Result<()> {
        let mut buf = vec![0u8; 2048];
        log::debug!("Receive handler started");
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

                    log::debug!("Received NHARP packet, processing...");

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

                    let dst_netpart = &rest[..nhip_header.dst_addr_len as usize];
                    let dst_node_id = u32::from_le_bytes(
                        rest[(nhip_header.dst_addr_len as usize) .. (nhip_header.dst_addr_len as usize + 4)]
                            .try_into()?
                    );

                    let src_netpart = &rest[
                        (nhip_header.dst_addr_len as usize + 4)
                        ..
                        (nhip_header.dst_addr_len as usize + 4 + nhip_header.src_addr_len as usize)
                    ];
                    let src_node_id = u32::from_le_bytes(
                        rest[
                            (nhip_header.dst_addr_len as usize + 4 + nhip_header.src_addr_len as usize) 
                            .. 
                            (nhip_header.dst_addr_len as usize + 8 + nhip_header.src_addr_len as usize)
                        ].try_into()?
                    );

                    let payload = &rest[(nhip_header.dst_addr_len as usize + 8 + nhip_header.src_addr_len as usize)..];
                    
                    let config = match load_addrs() {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            log::error!("Failed to load addresses: {}", e);
                            return Ok(());
                        }
                    };
                    let ifname = match ifname_from_index(ifindex) {
                        Some(str) => str,
                        None => {
                            log::error!("Failed to get ifname from index (nhipd:748)");
                            return Ok(());
                        }
                    };
                        
                    let is_my_net = config.iter()
                        .filter(|e| e.ifname == ifname)
                        .flat_map(|e| e.addresses.iter())
                        .any(|addr| {
                            let netpart = addr.rsplit(':').nth(1).unwrap_or("");
                            netpart.as_bytes() == dst_netpart
                        });
                    
                    let is_my_node_id = match is_my_node_id(ifindex, dst_node_id) {
                        Ok(value) => value,
                        Err(e) => {
                            anyhow::bail!("Failed to check is_my_node_id for idx {} and node_id {}: {}", ifindex, dst_node_id, e);
                        }
                    };

                    if !is_my_net || !is_my_node_id {
                        log::error!("unexpected !is_my_net || !is_my_node_id");
                        if let Err(e) = self.forward_slowpass(nhip_header, rest, ifindex).await {
                            log::error!("Forward SlowPass error at nhipd:771: {}", e);
                        }
                    } else {
                        let src_netpart_str = std::str::from_utf8(src_netpart).unwrap_or("(invalid)");
                        let dst_netpart_str = std::str::from_utf8(dst_netpart).unwrap_or("(invalid)");
                        log::debug!("Received packer with local destination");

                        match nhip_header.next_header {
                            next_header::NHIPPING => {
                                log::debug!("Received ping from {}:{}", src_netpart_str, src_node_id);

                                if let Err(e) = self.pingpong(
                                    &format!("{}:{}", dst_netpart_str, dst_node_id),
                                    &format!("{}:{}", src_netpart_str, src_node_id),
                                    ifindex,
                                    payload,
                                    2
                                ).await {
                                    log::error!("Failed to send pong: {}", e);
                                    return Ok(())
                                }
                            }

                            next_header::NHIPPONG => {
                                log::debug!("Received pong from {}:{}", src_netpart_str, src_node_id);

                                let msg = format!("PONG {}:{} {}:{}\n",
                                    src_netpart_str, src_node_id,
                                    dst_netpart_str, dst_node_id
                                );
                                if let Some(tx) = self.pong_sender.lock().await.take() {
                                    if let Err(e) = tx.send(msg) {
                                        log::error!("Failed to send PONG oneshot: {}", e);
                                    }
                                } else {
                                    log::error!("pong_sender is None while trying to send PONG oneshot");
                                }
                            }

                            _ => {}
                        }
                    }
                }

                _ => {
                    log::trace!("Ignored ether_type={:#06x}", ether_type);
                }
            }
        }
    }

    pub async fn pingpong(
        &self,
        local_addr: &str, 
        remote_addr: &str, 
        ifindex: u32, 
        payload: &[u8],
        oper: u8
    ) -> Result<()> {
        let remote_node_id = get_node_id_from_addr_str(remote_addr)
            .context("NHIPD PING(): No NodeID for destination")?;
        let remote_netpart = remote_addr.split(':').next()
            .context("NHIPD PING(): Failed to parse destination")?
            .as_bytes();

        let local_node_id = get_node_id_from_addr_str(local_addr)
            .context("NHIPD PING(): No NodeID for source")?;
        let local_netpart = local_addr.split(':').next()
            .context("NHIPD PING(): Failed to parse source")?
            .as_bytes();

        let local_mac = get_mac(ifindex)?;

        let remote_netpart_str = std::str::from_utf8(remote_netpart)?;

        // NHARP Lookup
        let remote_mac = match self.nharp_lookup(ifindex, remote_node_id).await {
            Some(mac) => {
                log::debug!("pingpong: found mac {:02x?}", mac);
                mac
            }
            None => {
                log::debug!("pingpong: mac not found");
                self.nharp_send_request(ifindex, remote_node_id, remote_netpart_str).await?;
                tokio::time::sleep(Duration::from_millis(100)).await;
                [0xFFu8; 6]
            }
        };

        let eth_header = build_eth_header(local_mac, remote_mac, NHIP_ETHERTYPE);
        let mut nhip_header = NhipHeader::new();
        nhip_header.link_label = 0;
        nhip_header.pointer = 0;
        nhip_header.next_header = if oper == 1 {next_header::NHIPPING} else {next_header::NHIPPONG};
        nhip_header.src_addr_len = local_netpart.len() as u16;
        nhip_header.dst_addr_len = remote_netpart.len() as u16;
        nhip_header.set_version_flags(NHIP_VERSION, 0);
        nhip_header.payload_length = payload.len() as u16;
        nhip_header.ttl = NHIP_DEFAULT_TTL;

        let mut buf = Vec::new();
        buf.extend_from_slice(bm::bytes_of(&eth_header));
        buf.extend_from_slice(bm::bytes_of(&nhip_header));
        buf.extend_from_slice(remote_netpart);
        buf.extend_from_slice(&remote_node_id.to_le_bytes());
        buf.extend_from_slice(local_netpart);
        buf.extend_from_slice(&local_node_id.to_le_bytes());
        buf.extend_from_slice(payload);

        self.socket.send(ifindex, &buf).await?;

        let oper_str = if oper == 1 { "ping" } else { "pong" };
        log::debug!("Sent {} to :{}, oper = {}, next header {}", oper_str, remote_node_id, oper, nhip_header.next_header);
        Ok(())
    }
}
