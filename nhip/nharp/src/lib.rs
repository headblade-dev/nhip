
pub mod packet;

pub const NHARP_ETHER_TYPE: u16 = 0x88b6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Request = 1,
    Reply = 2,
}

impl Operation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Operation::Request),
            2 => Some(Operation::Reply),
            _ => None,
        }
    }
}