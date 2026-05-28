use aya::Pod;
use bytemuck::Zeroable;

#[repr(C)]
#[derive(Clone, Copy, Debug, Zeroable)]
pub struct ForwardEntry {
    pub next_label: u64,
    pub ifindex: u32,
    pub dmac: [u8; 6],
    pub _pad: [u8; 2],
}

unsafe impl Pod for ForwardEntry {}