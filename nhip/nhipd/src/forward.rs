use aya::{Pod, maps::{Map, HashMap, MapData}};
use bytemuck::Zeroable;
use anyhow::{Result, Context};
use nhip_cfg::{RouteEntry, build_eth_header, get_mac, ifname_from_index, ifname_to_index, load_addrs, load_routes, proto_to_ad};
use nhip_core::{addr::get_node_id_from_addr_str, header::{NHIP_ETHERTYPE, NhipHeader}};

use crate::daemon::NhipDaemon;

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable)]
pub struct ForwardEntry {
    pub next_label: u64,
    pub ifindex: u32,
    pub dmac: [u8; 6],
    pub _pad: [u8; 2],
}

unsafe impl Pod for ForwardEntry {}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
struct NhipDynamic<'a> {
    dst_netpart:        &'a [u8],
    dst_node_id:        u32,
    src_netpart:        &'a [u8],
    src_node_id:        u32,
    payload:            &'a [u8],
    pointed_dst:        &'a [u8],
}

impl NhipDaemon {
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
    pub async fn insert_fastpath(
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

    //  ----------------
    //  SlowPath Helpers
    //  ----------------

    ///
    /// Parses the dynamic part of an NHIP packet.
    /// 
    /// * `hdr` - static NHIP header (address lengths and pointer).
    /// * `rest` - bytes after the static header (netparts, node IDs, payload).
    /// 
    /// # Behavior
    /// * Splits `rest` into destination and source netparts, node IDs, and payload.
    /// * Applies `hdr.pointer` to derive the pointed destination netpart.
    /// 
    #[allow(dead_code)]
    fn parse_slowpass_body<'a>(
        &self,
        hdr: &NhipHeader,
        rest: &'a [u8],
    ) -> Result<NhipDynamic<'a>> {
        //  -----------------------------------
        //  Get length of addresses and pointer
        //  -----------------------------------
        let dst_len = hdr.dst_addr_len as usize;
        let src_len = hdr.src_addr_len as usize;
        let pointer = hdr.pointer as usize;

        //  -------------------------------------
        //  Destination netpart + NodeID
        //  -------------------------------------
        //      * first `dst_len` bytes of `dst_netpart`
        //      * 4 bytes of NodeID
        //  -------------------------------------
        let dst_netpart = &rest[..dst_len];
        let dst_node_id = u32::from_le_bytes(
            rest[
                dst_len         // from dst_netpart end
                ..
                dst_len + 4     // 4 bytes (this is dst_node_id end)
            ].try_into()?
        );

        //  --------------------------------------------------------------------
        //  Destination netpart + NodeID 
        //  --------------------------------------------------------------------
        //      * after `dst_node_id`: there is `src_len` bytes of `src_netpart`
        //      * 4 bytes of NodeID
        //  --------------------------------------------------------------------
        let src_netpart = &rest[
            dst_len + 4                 // from dst_node_id end
            ..
            (dst_len + 4) + src_len     // src_len bytes (this is src_netpart end)
        ];
        let src_node_id = u32::from_le_bytes(
            rest[
                (dst_len + 4) + src_len         // from src_netpart end
                ..
                (dst_len + 4) + src_len + 4     // 4 bytes (this is src_node_id end)
            ].try_into()?
        );

        //  -------------------------------
        //  Payload - rest of the `rest` :)
        //  -------------------------------
        let payload = &rest[
            dst_len + 8 + src_len   // from src_node_id end (collapsed two 4 to one 8)
            ..                      // to end of `rest`
        ];

        //  ---------------------------
        //  Pointed destination netpart
        //  ---------------------------
        let pointed_dst = if pointer > 0 && pointer < dst_netpart.len() {
            &dst_netpart[pointer..]
        } else {
            dst_netpart
        };

        //  --------------------------
        //  Build and return structure
        //  --------------------------
        Ok(NhipDynamic {
            src_netpart,
            src_node_id,
            dst_netpart,
            dst_node_id,
            payload,
            pointed_dst
        })
    }

    ///
    /// Collects route table candidates for a hierarchical destination.
    /// 
    /// * `routes` - loaded routing table entries.
    /// * `dst_before_pointer` - destination netpart bytes before `nhip_header.pointer`.
    /// * `pointed_dst` - UTF-8 suffix of the destination netpart after the pointer.
    /// 
    /// # Behavior
    /// * Seeds candidates with all routes whose `destination` is `default`.
    /// * Walks dot-separated blocks of `pointed_dst`, appending each to `dst_before_pointer`
    ///   and extending candidates with exact `destination` matches.
    /// 
    #[allow(dead_code)]
    fn collect_candidates<'a>(
        routes: &'a [RouteEntry],
        dst_before_pointer: &str,
        pointed_dst: &str,
    ) -> Vec<&'a RouteEntry> {
        //  --------------------------------
        //  Add default routes to candidates
        //  --------------------------------
        let mut candidates: Vec<&RouteEntry> = routes
            .iter()
            .filter(|r| r.destination == "default")
            .collect();

        //  -------------------------------------------------
        //  Walk pointed_dst blocks and match route destinations
        //  -------------------------------------------------
        let mut processed_str = String::from(dst_before_pointer);
        for (i, block) in pointed_dst.split('.').enumerate() {
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
        candidates
    }

    ///
    /// Performs userspace slow-path forwarding for an NHIP packet.
    /// 
    /// * `nhip_header` - static NHIP header of the packet.
    /// * `rest` - dynamic part after the static header (netparts, node IDs, payload).
    /// * `recv_ifindex` - interface index the packet arrived on.
    /// 
    /// # Behavior
    /// * Parses the packet body and loads routes from `/etc/nhip/routes.conf`.
    /// * Builds route candidates from `nhip_header.pointer` and the destination netpart.
    /// * Selects the best route by administrative distance, priority, and destination length.
    /// * If no route matches, attempts connected delivery on a local netpart.
    /// * Otherwise resolves the next hop via NHARP, installs a FastPath entry, and
    ///   forwards the packet on the egress interface.
    /// 
    pub async fn forward_slowpass(
        &self,
        nhip_header: &NhipHeader,
        rest: &[u8],
        recv_ifindex: u32,
    ) -> Result<()> {
        let dst_addr_len = nhip_header.dst_addr_len as usize;
        let src_addr_len = nhip_header.src_addr_len as usize;
        let pointer = nhip_header.pointer;

        //  -----------------------------------
        //  Validate dynamic part size
        //  -----------------------------------
        let min_rest = dst_addr_len + 4 + src_addr_len + 4;
        if rest.len() < min_rest {
            log::warn!(
                "Too short NHIP packet variable part: {} bytes, need {}",
                rest.len(),
                min_rest
            );
            return Ok(());
        }

        //  -----------------------------------
        //  Parse destination and source fields
        //  -----------------------------------
        let dst_addr = &rest[..dst_addr_len];
        let dst_node_id = u32::from_le_bytes(
            rest[dst_addr_len..(dst_addr_len + 4)].try_into()?,
        );

        let src_addr = &rest[(dst_addr_len + 4)..(dst_addr_len + 4 + src_addr_len)];
        let src_node_id = u32::from_le_bytes(
            rest[(dst_addr_len + 4 + src_addr_len)..(dst_addr_len + 8 + src_addr_len)]
                .try_into()?,
        );

        let src_addr_str = std::str::from_utf8(src_addr)?;

        let pointed_dst_addr = if pointer > 0 && (pointer as usize) < dst_addr.len() {
            &dst_addr[pointer as usize..]
        } else {
            dst_addr
        };

        let payload = &rest[dst_addr_len + 8 + src_addr_len..];

        //  ------------------------
        //  Load routing table
        //  ------------------------
        let routes = load_routes();
        if let Err(e) = &routes {
            log::error!("Failed to load routes: {}", e);
        }
        let routes = routes?;

        //  -------------------------------------------------
        //  Split destination netpart by header pointer
        //  -------------------------------------------------
        let pointed_dst_str = std::str::from_utf8(pointed_dst_addr)
            .context("Pointed destination address is not a valid UTF-8 string")?;

        let dst_before_pointer = if pointer > 0 && (pointer as usize) < dst_addr.len() {
            std::str::from_utf8(&dst_addr[..pointer as usize])?
        } else {
            ""
        };

        //  --------------------------------
        //  Collect route candidates
        //  --------------------------------
        let blocks: Vec<&str> = pointed_dst_str.split('.').collect();

        let mut candidates: Vec<&RouteEntry> = routes
            .iter()
            .filter(|r| r.destination == "default")
            .collect();

        let mut processed_str = String::from(dst_before_pointer);
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

        //  ------------------------------------------
        //  Filter by administrative distance (proto based)
        //  ------------------------------------------
        let best_ad = candidates
            .iter()
            .map(|r| proto_to_ad(&r.proto))
            .min()
            .unwrap_or(255);

        candidates.retain(|r| proto_to_ad(&r.proto) == best_ad);

        //  ----------------------
        //  Filter by route priority
        //  ----------------------
        let best_priority = candidates
            .iter()
            .map(|r| r.priority)
            .min()
            .unwrap_or(255);

        candidates.retain(|r| r.priority == best_priority);

        //  ---------------------------------------------
        //  Connected delivery when no route candidates
        //  ---------------------------------------------
        if candidates.is_empty() {
            log::warn!("No candidates for destination, checking local net");
            let config = match load_addrs() {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Failed to load addresses: {}", e);
                    return Ok(());
                }
            };
            let ifname = ifname_from_index(recv_ifindex).context(
                "forward_slowpass: failed to get ifname from recv_ifindex",
            )?;
            let dst_addr_utf8 = match std::str::from_utf8(dst_addr) {
                Ok(dst) => dst,
                Err(e) => {
                    log::error!("Failed to parse dst_addr bytes into utf8 str: {}", e);
                    return Ok(());
                }
            };
            let is_local = config
                .iter()
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
                        log::error!(
                            "Failed to get mac for interface with index {}: {}",
                            recv_ifindex,
                            e
                        );
                        return Ok(());
                    }
                };
                let remote_mac = match self.nharp_lookup(recv_ifindex, dst_node_id).await {
                    Some(mac) => mac,
                    None => {
                        self.nharp_send_request(recv_ifindex, dst_node_id, src_addr_str)
                            .await?;
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
                    log::error!("Failed to send connected delivery: {}", e);
                    return Ok(());
                }
                log::info!(
                    "Connected delivery: {}:{} via ifindex {}",
                    String::from_utf8_lossy(dst_addr),
                    dst_node_id,
                    recv_ifindex
                );
                return Ok(());
            } else {
                log::error!("Has no candidates and dst is not local");
            }
        }

        //  ---------------------------------------------
        //  Prefer longest matching route destination
        //  ---------------------------------------------
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
            log::error!(
                "No route to destination: {}{}",
                dst_before_pointer,
                pointed_dst_str
            );
        }

        let route = *route.unwrap();

        //  -------------------------
        //  Resolve next hop (NHARP)
        //  -------------------------
        let next_node_id = get_node_id_from_addr_str(&route.next_hop)
            .ok()
            .context("Failed to get NodeID from next hop address")?;
        let out_ifindex = ifname_to_index(&route.dev)?;
        let local_mac = get_mac(out_ifindex)?;

        let next_mac = self.nharp_lookup(out_ifindex, next_node_id).await;
        match next_mac {
            Some(_) => {}
            None => {
                self.nharp_send_request(out_ifindex, next_node_id, src_addr_str)
                    .await?;
                log::warn!(
                    "SlowPass: Can't find MAC for NodeID {}. Packet dropped; NHARP request sent",
                    next_node_id
                );
                return Ok(());
            }
        }
        let next_mac = next_mac.unwrap();

        //  -----------------------------------------
        //  Install FastPath and rewrite NHIP header
        //  -----------------------------------------
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

        self.insert_fastpath(current_label, new_label, out_ifindex, next_mac)
            .await?;

        let mut new_hdr = *nhip_header;
        new_hdr.link_label = new_label;
        new_hdr.pointer = new_pointer;
        new_hdr.ttl -= 1;

        //  -------------------------
        //  Build frame and transmit
        //  -------------------------
        let eth_bytes = build_eth_header(local_mac, next_mac, NHIP_ETHERTYPE);
        let nhip_bytes = bytemuck::bytes_of(&new_hdr);

        let mut buf = Vec::new();
        buf.extend_from_slice(&eth_bytes);
        buf.extend_from_slice(nhip_bytes);
        buf.extend_from_slice(dst_addr);
        buf.extend_from_slice(&dst_node_id.to_le_bytes());
        buf.extend_from_slice(src_addr);
        buf.extend_from_slice(&src_node_id.to_le_bytes());
        buf.extend_from_slice(payload);

        self.socket.send(out_ifindex, &buf).await
    }
}
