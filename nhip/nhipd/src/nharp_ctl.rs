use aya::Pod;
use bytemuck::Zeroable;

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

