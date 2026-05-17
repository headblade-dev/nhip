use core::mem;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NharpPacket {
    pub oper: u8,
    pub target_node_id: u32,
    pub source_node_id: u32,
    pub source_mac: [u8; 6],
}

impl NharpPacket {
    pub const SIZE: usize = 15;
}

impl NharpPacket {
    pub fn is_request(&self) -> bool {
        self.oper == 1
    }

    pub fn is_reply(&self) -> bool {
        self.oper == 2
    }
}

const _: () = {
    if mem::size_of::<NharpPacket>() != NharpPacket::SIZE {
        panic!("NHARP Packet size is incorrect");
    }
};
