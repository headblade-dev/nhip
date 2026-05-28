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
use crate::forward::ForwardEntry;

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
    /// Finds MAC-address for destination NodeID using NHARP cache
    /// 
    /// * `ifindex` - outgoing interface
    /// * `node_id` - destination NodeID
    /// 
    async fn nharp_lookup(&self, ifindex:u32, node_id: u32) -> Option<[u8; 6]> {
        //  ------------------------------------------
        //  Obtain a read-only view of the NHARP table
        //  ------------------------------------------
        let table = self.nharp_table.read().await;

        //  -----------------
        //  Build the map key and find NHARP entry
        //  -----------------
        let key = NharpKey { ifindex, node_id };

        // Find entry
        match table.get(&key, 0) {
            Ok(entry) => Some(entry.mac),
            Err(e) => {
                log::info!("NHARP Lookup miss for {node_id} (ifindex {ifindex}): {e}");
                None
            }
        }
    }

    ///
    /// Send NHARP reply.
    /// 
    /// * `ifindex` - outgouing interface index
    /// * `remote_mac` - MAC-address of destination
    /// * `remote_node_id` - NodeID of destination
    /// * `local_mac` - MAC-addres of the outgoing interface
    /// * `local_node_id` - NodeID that we advertise
    /// 
    /// The reply tells the remote host that *our NodeID* is reacheble at the specified MAC-address.
    /// 
    async fn nharp_send_reply(
        &self,
        ifindex: u32,
        remote_mac: [u8; 6],
        remote_node_id: u32,
        local_mac: [u8; 6],
        local_node_id: u32,
    ) -> Result<()> {
        //  -----------------------
        //  Build the NHARP payload
        //  -----------------------
        let payload = NharpPacket::new_reply(
            local_node_id, 
            local_mac, 
            remote_node_id
        );

        //  -------------------------------
        //  Build the Ethernet frame header
        //  -------------------------------
        let eth_header = build_eth_header(
            local_mac,
            remote_mac,
            NHARP_ETHER_TYPE
        );

        //  --------------------------------
        //  Serialize everything to a buffer
        //  --------------------------------
        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&eth_header));
        buf.extend_from_slice(bytemuck::bytes_of(&payload));

        //  --------------------------------
        //  Send the packet through a socket
        //  --------------------------------
        self.socket.send(ifindex, &buf).await?;
        Ok(())
    }

    ///
    /// Send NHARP request
    /// 
    /// * `ifindex` - outgoing interface index
    /// * `remote_node_id` - destination NodeID
    /// * `remote_netpart` - network part of destination address
    /// 
    /// # Behavior
    /// * Gets all addresses on selected interface
    /// * Find local NodeID in the same network as the destination
    /// * Builds and send NHARP request
    async fn nharp_send_request(
        &self,
        ifindex: u32,
        remote_node_id: u32,
        remote_netpart: &str
    ) -> Result<()> {
        //  -----------------
        //  Get source NodeID
        //  -----------------
        let candidates = self
            .get_addrs_from_ifindex(ifindex)
            .await
            .context(format!("Failed to get addresses for interface with index {ifindex}"))?;
        
        let local_node_id = pick_node_id_for_netpart(&candidates, remote_netpart) 
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No NodeID configured on interface {} that matches destination network '{}'",
                    ifname_from_index(ifindex).unwrap_or("<unknown>".to_string()),
                    remote_netpart
                )
            })?;
        
        
        //  -------------------
        //  Build NHARP request
        //  -------------------
        let local_mac = get_mac(ifindex)?;

        // Nharp payload
        let packet_data = NharpPacket::new_request(
            local_node_id, 
            local_mac, 
            remote_node_id);
        
        // Ethernet frame header
        let eth_header = build_eth_header(
            local_mac,
            [255u8; 6],
            NHARP_ETHER_TYPE
        );

        //  --------------------------------
        //  Serialize everything to a buffer
        //  --------------------------------
        let mut buf = Vec::new();
        buf.extend_from_slice(bytemuck::bytes_of(&eth_header));
        buf.extend_from_slice(bytemuck::bytes_of(&packet_data));

        log::debug!("Sending NHARP request to :{}", remote_node_id);

        //  ------------
        //  Send request
        //  ------------
        self.socket.send(ifindex, &buf).await?;
        Ok(())
    }

    // Add entry to NHARP cache
    async fn nharp_insert(&self, ifindex: u32, node_id: u32, mac: [u8; 6]) -> Result<()> {
        log::info!("NHARP insert: {} -> {:02x?}", node_id, mac);
        
        let mut table = self.nharp_table.write().await;

        let key = NharpKey { ifindex, node_id };

        table.insert(key, NharpEntry { mac, _pad: [0; 2] }, 0)?;
        Ok(())
    }

    

    /// Process incoming NHARP packet
    /// * `ifindex` – the interface on which the packet was received.
    /// * `packet` – the parsed NHARP packet.
    /// 
    /// # Behavior
    /// This function inserts the sender into the NHARP cache and send response if target is belongs to a local machine
    async fn handle_nharp(
        &self,
        ifindex: u32,
        packet: &NharpPacket,
    ) -> Result<()> {
        // Cache the remote and local NodeIDs
        let remote_node_id = u32::from_be(packet.source_node_id);
        let local_node_id = u32::from_be(packet.target_node_id);

        // Insert NHARP entry about remote machine
        self.nharp_insert(ifindex, remote_node_id, packet.source_mac).await?;

        //  --------------------------------------------------------------------------
        //  If this is a request and the target NodeID is one of our own, send a reply
        //  --------------------------------------------------------------------------
        if packet.is_request() && self.is_my_node_id(ifindex, local_node_id).await? {
            log::info!(
                "NHARP: Request received: Who has ~:{}? Tell ~:{}",
                local_node_id,
                remote_node_id
            );

            self.nharp_send_reply(
                ifindex, 
                packet.source_mac, 
                remote_node_id, 
                get_mac(ifindex)?, 
                local_node_id
            ).await?;

            log::debug!("NHARP: Sending reply: ~:{} is at {:02x?}",
                local_node_id,
                get_mac(ifindex)?
            );
        }
        Ok(())
    }
    async fn is_my_node_id(&self, ifindex: u32, node_id: u32) -> Result<bool> {
        // 1. Load addresses configuration
        let config = load_addrs()?;

        // 2. Get ifname and return error on fail
        let ifname = ifname_from_index(ifindex).ok_or_else(|| {
            log::error!("Failed to get ifname from index (nhipd:342)");
            anyhow::anyhow!("Failed to get ifname from index (nhipd:342)")
        })?;

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
                        Some(true)   // found! stop iterating
                    } else {
                        None
                    }
                }
                Err(_) => {
                    log::warn!("Failed to parse NodeID (nhipd:351) for address {}", addr);
                    None
                }
            });

        // Address not found - return false
        Ok(found.unwrap_or(false))
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
    /// Insert a forwarding entry into the FastPath eBPF map.
    /// 
    /// * `label` - key of the map; current link-label.
    /// * `next_label` - the label which replaces current label for processing on the next-hop machine.
    /// * `ifindex` - outgoing interface index.
    /// * `dmac` - destination MAC address for the next-hop
    /// 
    /// # Behavior
    /// * Opens the FastPath map from pinned state
    /// * Inserts the `ForwardEntry` and logs the allocation
    /// 
    async fn insert_fastpath(
        &self,
        label: u64,
        next_label: u64,
        ifindex: u32,
        dmac: [u8; 6],
    ) -> Result<()> {
        //  -----------------------------------------------------
        //  Build the ForwardEntry that will be stored in the map
        //  -----------------------------------------------------
        let entry = ForwardEntry {
            next_label,
            ifindex,
            dmac,
            _pad: [0, 2],
        };

        //  ------------------------
        //  Open the pinned FastPath
        //  ------------------------
        let hostname = std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "default".to_string())
            .trim()
            .to_string();
        let map_path = format!("/sys/fs/bpf/nhip/{hostname}/fastpath");
        let map_data = MapData::from_pin(map_path)
            .context("Failed to open FastPath map")?;
        let map = Map::HashMap(map_data);
        let mut fastpath = HashMap::try_from(map)
            .context("Failed to convert FastPath map to HashMap")?;
        //  -----------------------------------
        //  Insert the entry and emit a logline
        //  -----------------------------------
        fastpath
            .insert(label, entry, 0)
            .context(format!("Failed to insert FastPath entry fo label {label}"))?;

        log::info!(
            "NHIPd FastPath: label {label:#x} -> {next_label:#x} allocated on ifindex {ifindex}",
        );
        Ok(())
    }

    ///
    /// Find all addresses associated with interface
    /// 
    /// * `ifindex` - kernel interface index
    /// 
    async fn get_addrs_from_ifindex(&self, ifindex: u32) -> Result<Vec<(String, u32)>> {
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

    async fn forward_slowpass(
        &self,
        nhip_header: &NhipHeader, 
        rest: &[u8],
        recv_ifindex: u32,
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
        let dst_node_id = u32::from_le_bytes(rest[dst_addr_len .. (dst_addr_len + 4)].try_into()?);

        let src_addr = &rest[(dst_addr_len + 4) .. (dst_addr_len + 4 + src_addr_len)];
        let src_node_id = u32::from_le_bytes(
            rest[(dst_addr_len + 4 + src_addr_len) .. (dst_addr_len + 8 + src_addr_len)]
        .try_into()?);

        let src_addr_str = std::str::from_utf8(src_addr)?;

        let pointed_dst_addr = if pointer > 0 && (pointer as usize) < dst_addr.len() {
            &dst_addr[pointer as usize..]
        } else {
            dst_addr
        };

        let payload = &rest[dst_addr_len + 8 + src_addr_len..];

        let routes = load_routes();
        if let Err(e) = &routes {
            log::error!("Failed to load routes nhipd:486: {}", e);
        }
        let routes = routes?;
        
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

        candidates.retain(|r| r.priority == best_priority);


        if candidates.is_empty() {
            log::warn!("No candidates for destination, checking local net");
            let config = match load_addrs() {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Failed to load addresses nhipd:548: {}", e);
                    return Ok(());
                }
            };
            let ifname = ifname_from_index(recv_ifindex)
                .context("forward_slowpass(): if candidates.is_empty(): Failed to get ifname from index")?;
            let dst_addr_utf8 = match std::str::from_utf8(dst_addr) {
                Ok(dst) => dst,
                Err(e) => {
                    log::error!("Failed to parse dst_addr bytes into utf8 str: {}", e);
                    return Ok(())
                }
            };
            let is_local = config.iter()
                .filter(|e| e.ifname == ifname)
                .flat_map(|e| e.addresses.iter())
                .any(|addr| {
                    let net = addr.rsplit(':').nth(1).unwrap_or("");
                    net == dst_addr_utf8
            });

            if is_local {
                let local_mac = match get_mac(recv_ifindex) {
                    Ok(mac) => mac,
                    Err(e) => {
                        log::error!("Failed to get mac for interface with index {} (nhipd:567): {}", recv_ifindex, e);
                        return Ok(())
                    }
                };
                let remote_mac = match self.nharp_lookup(recv_ifindex, dst_node_id).await {
                    Some(mac) => mac,
                    None => {
                        self.nharp_send_request(recv_ifindex, dst_node_id, &src_addr_str).await?;
                        log::warn!("NHARP miss for connected host — packet dropped");
                        return Ok(());
                    }
                };

                let eth_bytes = build_eth_header(local_mac, remote_mac, NHIP_ETHERTYPE);
                let mut new_hdr = *nhip_header;
                new_hdr.ttl -= 1;

                let mut buf = Vec::new();
                buf.extend_from_slice(&eth_bytes);
                buf.extend_from_slice(bytemuck::bytes_of(&new_hdr));
                buf.extend_from_slice(dst_addr);
                buf.extend_from_slice(&dst_node_id.to_le_bytes());
                buf.extend_from_slice(src_addr);
                buf.extend_from_slice(&src_node_id.to_le_bytes());
                buf.extend_from_slice(payload);

                if let Err(e) = self.socket.send(recv_ifindex, &buf).await {
                    log::error!("Failed to send data (nhipd:594): {}", e);
                    return Ok(())
                };
                log::info!("Connected delivery: {}:{} via ifindex {}", 
                    String::from_utf8_lossy(dst_addr), dst_node_id, recv_ifindex);
                return Ok(());
            } else {
                log::error!("Has no candidates and dst is not local")
            }
        }

        if candidates.len() > 1 {
            let max_len = candidates
                .iter()
                .map(|&r| r.destination.len())
                .max()
                .unwrap_or(0);
            candidates.retain(|&r| r.destination.len() == max_len);
        }

        let route = candidates.first();
        if route.is_none() {
            log::error!("No route to destination: {}{}", prefix, pointed_dst_str);
        } 

        let route = *route.unwrap();
        

        // == Redirecting == 
        let next_node_id = get_node_id_from_addr_str(&route.next_hop).ok()
            .context("Failed to get NodeID from next hop address")?;
        let out_ifindex = ifname_to_index(&route.dev)?;
        let local_mac = get_mac(out_ifindex)?;
        

        // nharp lookup
        let next_mac = self.nharp_lookup(out_ifindex, next_node_id).await;
        match next_mac {
            Some(_) => {}
            None => {
                self.nharp_send_request(
                    out_ifindex, 
                    next_node_id,
                    &src_addr_str
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
        new_hdr.link_label = new_label;
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
        buf.extend_from_slice(&dst_node_id.to_le_bytes());
        buf.extend_from_slice(src_addr);
        buf.extend_from_slice(&src_node_id.to_le_bytes());
        // payload
        buf.extend_from_slice(payload);

        self.socket.send(out_ifindex, &buf).await
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
                    
                    let is_my_node_id = match self.is_my_node_id(ifindex, dst_node_id).await {
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
