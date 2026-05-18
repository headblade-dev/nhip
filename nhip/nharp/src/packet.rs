use core::mem;
use bytemuck::{Zeroable, Pod};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct NharpPacket {
    pub oper: u8,
    pub target_node_id: u32,
    pub source_node_id: u32,
    pub source_mac: [u8; 6],
}

impl NharpPacket {
    pub const SIZE: usize = 15;

    pub fn is_request(&self) -> bool {
        self.oper == 1
    }

    pub fn is_reply(&self) -> bool {
        self.oper == 2
    }

    pub fn new_reply(src_node_id: u32, src_mac: [u8; 6], dst_node_id: u32) -> Self {
        NharpPacket {
            oper: 2,
            target_node_id: dst_node_id,
            source_node_id: src_node_id,
            source_mac: src_mac,
        }
    }

    pub fn new_request(src_node_id: u32, src_mac: [u8; 6], dst_node_id: u32) -> Self {
        NharpPacket {
            oper: 1,
            target_node_id: dst_node_id,
            source_node_id: src_node_id,
            source_mac: src_mac,
        }
    }
}

const _: () = {
    if mem::size_of::<NharpPacket>() != NharpPacket::SIZE {
        panic!("NHARP Packet size is incorrect");
    }
};
