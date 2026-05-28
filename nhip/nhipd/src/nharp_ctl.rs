use anyhow::{Context, Result};
use aya::Pod;
use bytemuck::Zeroable;
use nharp::{NHARP_ETHER_TYPE, packet::NharpPacket};
use nhip_cfg::{build_eth_header, get_mac, ifname_from_index, is_my_node_id, pick_node_id_for_netpart};

use crate::daemon::NhipDaemon;

#[repr(C)]
#[derive(Clone, Copy, Zeroable, PartialEq, Eq, Hash)]
pub struct NharpEntry {
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
}

unsafe impl Pod for NharpEntry {}

#[repr(C)]
#[derive(Clone, Copy, Zeroable, PartialEq, Eq, Hash)]
pub struct NharpKey {
    pub ifindex: u32,
    pub node_id: u32,
}

unsafe impl Pod for NharpKey {}

impl NhipDaemon {
    /// 
    /// Finds MAC-address for destination NodeID using NHARP cache
    /// 
    /// * `ifindex` - outgoing interface
    /// * `node_id` - destination NodeID
    /// 
    pub async fn nharp_lookup(&self, ifindex:u32, node_id: u32) -> Option<[u8; 6]> {
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

    /// Process incoming NHARP packet
    /// * `ifindex` – the interface on which the packet was received.
    /// * `packet` – the parsed NHARP packet.
    /// 
    /// # Behavior
    /// This function inserts the sender into the NHARP cache and send response if target is belongs to a local machine
    pub async fn handle_nharp(
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
        if packet.is_request() && is_my_node_id(ifindex, local_node_id)? {
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
    pub async fn nharp_send_reply(
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
    pub async fn nharp_send_request(
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

    ///
    /// Adds entry to the NHARP cache
    /// 
    /// * `ifindex` - associated interface
    /// * `node_id` - remote NodeID
    /// * 'mac' - MAC-address associated with NodeID of remote machine
    /// 
    /// # Behavior
    /// * Gets mutable access to `nharp_table`
    /// * Builds `NharpKey` and insert a value associated with this key
    /// 
    pub async fn nharp_insert(&self, ifindex: u32, node_id: u32, mac: [u8; 6]) -> Result<()> {
        log::info!("NHARP insert: {} -> {:02x?}", node_id, mac);
        
        //  ------------------------------------
        //  Get mutable access to the NharpTable
        //  ------------------------------------
        let mut table = self.nharp_table.write().await;

        //  --------------------------
        //  Build key and insert entry
        //  --------------------------
        let key = NharpKey { ifindex, node_id };

        table.insert(key, NharpEntry { mac, _pad: [0; 2] }, 0)
            .context(format!("Failed to insert NHARP entry for NodeID :{node_id} on ifindex `{ifindex}`"))?;
        
        Ok(())
    }
}