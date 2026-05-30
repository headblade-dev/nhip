use aya::{Pod, maps::{Map, HashMap, MapData}};
use bytemuck::Zeroable;
use anyhow::{Result, Context};
use nhip_cfg::{AddressEntry, RouteEntry, build_eth_header, get_mac, ifname_to_index, insert_route, load_addrs, load_routes, proto_to_ad};
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
struct NhipDynamic<'a> {
    dst_netpart:        &'a [u8],
    dst_node_id:        u32,
    src_netpart:        &'a [u8],
    src_node_id:        u32,
    payload:            &'a [u8],
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

    /// 
    /// Updates routes config with directly-connected routes
    /// (for background task only)
    /// 
    #[allow(unused)]
    pub async fn check_connected(&self) -> Result<()>{
        //  -----------------------
        //  Load configs fron files
        //  -----------------------
        let addr_cfg: Vec<AddressEntry> = load_addrs()?;
        let mut routes_cfg: Vec<RouteEntry> = load_routes()?;

        //  --------------------------------------------
        //  Retain only interfaces from daemon structure
        //  --------------------------------------------
        let filtered_addr_cfg: Vec<&AddressEntry> = addr_cfg
            .iter()
            .filter(|e| self.ifaces.contains(&e.ifname))
            .collect();

        //  -------------------------------------------------------------------------
        //  Collect all local addresses with their interfaces and add route to config
        //  -------------------------------------------------------------------------
        for entry in filtered_addr_cfg {
            for addr in &entry.addresses {
                if let Some(netpart) = addr.split(':').next() {
                    if netpart.is_empty() {
                        continue;
                    }

                    if let Err(e) = insert_route(
                        netpart, 
                        "local:0", 
                        &entry.ifname, 
                        0
                    ) {
                        continue;
                    };

                }
            }
        }

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
    fn parse_dynamic<'a>(
        &self,
        hdr: &NhipHeader,
        rest: &'a [u8],
    ) -> Result<NhipDynamic<'a>> {
        //  -----------------------------------
        //  Get length of addresses and pointer
        //  -----------------------------------
        let dst_len = hdr.dst_addr_len as usize;
        let src_len = hdr.src_addr_len as usize;

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

        //  --------------------------
        //  Build and return structure
        //  --------------------------
        Ok(NhipDynamic {
            src_netpart,
            src_node_id,
            dst_netpart,
            dst_node_id,
            payload
        })
    }

    ///
    /// Takes only one route from routing table.
    /// 
    /// * `routes` - loaded routing table entries.
    /// * `dst_before_pointer` - destination netpart bytes before `nhip_header.pointer`.
    /// * `pointed_dst` - UTF-8 suffix of the destination netpart after the pointer.
    /// 
    fn select_route<'a>(
        &self,
        routes: &'a Vec<RouteEntry>,
        dst_before_pointer: &str,
        dst_after_pointer: &str,
    ) -> Option<&'a RouteEntry> {
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
        for block in dst_after_pointer.split('.') {
            // add .<block> to a string with which we will compare routes
            processed_str.push('.');
            processed_str.push_str(block);

            // add to candidates all routes which is same with a comparing string
            // first in buffer
            let matching: Vec<&RouteEntry> = routes
                .iter()
                .filter(|r| r.destination == processed_str)
                .collect();
            // if buffer is not empty - add this routes to the final candidates
            if !matching.is_empty() {
                candidates.extend(matching);
            }
        }
        match Self::filter_candidates(candidates) {
            None => {
                log::warn!("No route to destination: {processed_str}");
                return None;
            }
            Some(route) => Some(route)
        }
    }

    ///
    /// Takes the most suitable route from the list of candidates
    /// 
    /// * `candidates` - list of routes
    /// 
    /// # Behavior
    /// * Filters by **administrative distance** *(proto-based metric)*
    /// * Filters by **priority** *(config-based metric)*
    /// * FIlters by **longest-prefix match** *(length of the routes destination)*
    /// * Returns only one `&RouteEntry` with `Option` wrapping
    /// 
    fn filter_candidates(mut candidates: Vec<&RouteEntry>) -> Option<&RouteEntry> {
        //  --------------------------
        //  Filter by AD (proto-based)
        //  --------------------------
        let best_ad = candidates
            .iter()
            .map(|r| proto_to_ad(&r.proto))
            .min()
            .unwrap_or(255);

        candidates.retain(|r| proto_to_ad(&r.proto) == best_ad);

        //  -----------------------------------
        //  Filter by `priority` (config-based)
        //  -----------------------------------
        let best_priority = candidates
            .iter()
            .map(|r| r.priority)
            .min()
            .unwrap_or(255);

        candidates.retain(|r| r.priority == best_priority);

        //  ------------------------------
        //  Filter by longest-prefix match
        //  ------------------------------
        if candidates.len() > 1 {
            let max_len = candidates
                .iter()
                .map(|&r| r.destination.len())
                .max()
                .unwrap_or(0);
            candidates.retain(|&r| r.destination.len() == max_len);
        };

        //  ----------------------------------------------------------
        //  Take first route (now routes in `candidates` are the same)
        //  ----------------------------------------------------------
        candidates.first().copied()
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
    ) -> Result<()> {
        let dst_addr_len = nhip_header.dst_addr_len as usize;
        let src_addr_len = nhip_header.src_addr_len as usize;
        let pointer = nhip_header.pointer;

        //  --------------------------
        //  Validate dynamic part size
        //  --------------------------
        let min_rest = dst_addr_len + 4 + src_addr_len + 4;
        if rest.len() < min_rest {
            log::warn!(
                "Too short NHIP packet variable part: {} bytes, need {}",
                rest.len(),
                min_rest
            );
            return Ok(());
        }

        //  ---------------------------------------------
        //  Parse dynamic fields of NHIP header + payload
        //  ---------------------------------------------
        let dynamic_part = self.parse_dynamic(nhip_header, rest)?;
        
        let dst_netpart = dynamic_part.dst_netpart;
        let dst_node_id = dynamic_part.dst_node_id;
        let src_netpart = dynamic_part.src_netpart;
        let src_node_id = dynamic_part.src_node_id;
        let payload = dynamic_part.payload;

        let src_netpart_str = std::str::from_utf8(src_netpart)?;

        //  -------
        //  Routing
        //  -------  
        // load config      
        let routes = load_routes();
        if let Err(e) = &routes {
            log::error!("Failed to load routes: {e}");
        }
        let routes = routes?;

        // parse dst using pointer
        let dst_before_pointer = if pointer > 0 && (pointer as usize) < dst_netpart.len() {
            std::str::from_utf8(&dst_netpart[..pointer as usize])?
        } else {
            ""
        };
        let dst_after_pointer = if pointer > 0 && (pointer as usize) < dst_netpart.len() {
            std::str::from_utf8(&dst_netpart[pointer as usize..])?
        } else {
            ""
        };

        // find route
        let route = match self.select_route(&routes, dst_before_pointer, dst_after_pointer) {
            Some(r) => r,
            None => {
                log::error!("No route to destination");
                return Ok(());
            }
        };

        //  -------------
        //  Find next hop
        //  -------------
        // local
        let out_ifindex = ifname_to_index(&route.dev)?;
        let local_mac = get_mac(out_ifindex)?;

        // remote
        let next_node_id = if &route.next_hop == "local:1" {
            dst_node_id
        } else {
            get_node_id_from_addr_str(&route.next_hop)
                .ok()
                .context("Failed to get NodeID from next hop address")?
        };

        let next_mac = match (route.next_hop.as_str(), next_node_id) { 
            ("local:1", 1000000000) => [255u8; 6],
            // TODO multicast routing
            _ => match self.nharp_lookup(out_ifindex, next_node_id).await {
                Some(mac) => mac,
                None => {
                    self.nharp_send_request(out_ifindex, next_node_id, src_netpart_str)
                        .await?;
                    log::warn!(
                        "SlowPass: Can't find MAC for NodeID {}. Packet dropped. Sent NHARP request.",
                        next_node_id
                    );
                    return Ok(());
                }
            }
        };

        //  ---------------------------------------------
        //  Insert FastPath entry and rebuild NHIP header
        //  ---------------------------------------------
        // next label
        let new_label = nhip_core::label::get_link_hash(&local_mac, &next_mac, dst_netpart);

        // pointer
        let new_pointer = if route.destination == "default" {
            pointer
        } else {
            let raw_pointer = route.destination.len() as u8 + 1;

            if raw_pointer as usize >= dst_netpart.len() || dst_netpart[raw_pointer as usize] == b':' {
                0xFF
            } else {
                raw_pointer
            }
        };
        
        // current label
        let current_label = u64::from_be(nhip_header.link_label);

        self.insert_fastpath(current_label, new_label, out_ifindex, next_mac)
            .await?;

        // build nhip header
        let mut new_hdr = *nhip_header;
        new_hdr.link_label = new_label;
        new_hdr.pointer = new_pointer;
        new_hdr.ttl -= 1;
        let nhip_bytes = bytemuck::bytes_of(&new_hdr);

        // build ethernet header
        let eth_bytes = build_eth_header(local_mac, next_mac, NHIP_ETHERTYPE);
        
        //  ----------------------
        //  Serialize and transmit
        //  ----------------------
        let mut buf = Vec::new();
        buf.extend_from_slice(&eth_bytes);
        buf.extend_from_slice(nhip_bytes);
        buf.extend_from_slice(dst_netpart);
        buf.extend_from_slice(&dst_node_id.to_le_bytes());
        buf.extend_from_slice(src_netpart);
        buf.extend_from_slice(&src_node_id.to_le_bytes());
        buf.extend_from_slice(payload);

        self.socket.send(out_ifindex, &buf).await
    }
}
