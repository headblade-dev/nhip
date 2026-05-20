/*
    FNV-la hash-function for hash-label calculation from destination address
    FNV-la is fast, simple and has good distribution for short keys
*/

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

pub mod label {
    pub const UNKNOWN: u64 = 0;
    pub const EGRESS: u64 = 0xFF_FF_FF_FF_FF_FF_FF_FF;
    pub const MIN_USER: u64 = 32;
}

/**
 * FNV-la calculating function 
 * 
 * Using for link-label generating fromtwo MAC-adresses
 * and for anti-spoofing
 */
fn fnvla(data: &[u8]) -> u64 {
    let mut hash: u64 = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/**
 * Link-Hash calculating
 */
pub fn get_link_hash(mac_a: &[u8; 6], mac_b: &[u8; 6], dst_addr: &[u8]) -> u64 {
    let (lower, upper) = if mac_a < mac_b {
        (mac_a, mac_b)
    } else {
        (mac_b, mac_a)
    };

    let mut buf = [0u8; 12 + 152];
    buf[..6].copy_from_slice(lower);
    buf[6..12].copy_from_slice(upper);
    let len = dst_addr.len().min(152);
    buf[12..12+len].copy_from_slice(dst_addr);
    fnvla(&buf)
}
