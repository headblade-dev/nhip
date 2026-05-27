use bytemuck::{Zeroable, Pod};

pub const NHIP_ETHERTYPE: u16 = 0x88B5;

pub const NHIP_HEADER_LEN: usize = 18;

pub const NHIP_DEFAULT_TTL: u8 = 64;

pub const NHIP_VERSION: u8 = 0x01;

// Next header
pub mod next_header {
    pub const NHIPPING: u8 = 0x01;
    pub const NHIPPONG: u8 = 0x02;
    pub const TCP: u8 = 0x06;
    pub const UDP: u8 = 0x11;
}

pub mod flags {
    pub const MULTICAST: u8 = 0b1000; // bit 3
    pub const BROADCAST: u8 = 0b0100; // bit 2
    pub const RESERVERD: u8 = 0b0011; // bits 0-1
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct NhipHeader {
    pub version_flags: u8,
    pub pointer: u8,
    pub ttl: u8,
    pub next_header: u8,
    pub payload_length: u16,
    pub link_label: u64,
    pub dst_addr_len: u16,
    pub src_addr_len: u16,
}

impl Default for NhipHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl NhipHeader {
    // init
    pub fn new() -> Self {
        NhipHeader { 
            version_flags: NHIP_VERSION,
            pointer: 0, 
            ttl: NHIP_DEFAULT_TTL, 
            next_header: next_header::NHIPPING, 
            payload_length: 15, 
            link_label: 0, 
            src_addr_len: 0, 
            dst_addr_len: 0 }
    }

    // get version
    #[inline]
    pub fn version(&self) -> u8 {
        self.version_flags >> 4
    }

    // get flags
    #[inline]
    pub fn flags(&self) -> u8 {
        self.version_flags & 0x0F
    }

    // set version and flags
    #[inline]
    pub fn set_version_flags (&mut self, version: u8, flags: u8) {
        self.version_flags = (version << 4) | (flags & 0x0F);
    } 

    // check multicast flag
    #[inline]
    pub fn is_multicast (&self) -> bool {
        self.flags() & flags::MULTICAST != 0
    }

    // check broadcast flag
    #[inline]
    pub fn is_broadcast (&self) -> bool {
        self.flags() & flags::BROADCAST != 0
    }

    // set multicast flag
    #[inline]
    pub fn set_multicast (&mut self, on: bool) {
        let f = self.flags();
        let new_f = if on { 
            f | flags::MULTICAST 
        } else { 
            f & !flags::MULTICAST
        };
        self.set_version_flags(self.version(), new_f);
    }

    // set broadcast flag
    #[inline]
    pub fn set_broadcast (&mut self, on: bool) {
        let f = self.flags();
        let new_f = if on { 
            f | flags::BROADCAST
        } else { 
            f & !flags::BROADCAST
        };
        self.set_version_flags(self.version(), new_f);
    }

    // get total header length with addresses
    #[inline]
    pub fn total_header_len(&self) -> usize {
        NHIP_HEADER_LEN 
            + self.dst_addr_len as usize + 4 
            + self.src_addr_len as usize + 4
    }

    // get total packet length (header + payload)
    #[inline]
    pub fn total_packet_len(&self) -> usize {
        self.total_header_len() + self.payload_length as usize
    }
}