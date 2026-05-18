/*
    FNV-la hash-function for hash-label calculation from destination address
    FNV-la is fast, simple and has good distribution for short keys
*/

const FNV_OFFSET: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

pub mod label {
    pub const UNKNOWN: u32 = 0;
    pub const EGRESS: u32 = 0xFFFFFFFF;
    pub const MIN_USER: u32 = 16;
}

/**
 * FNV-la calculating function 
 * 
 * Using for link-label generating fromtwo MAC-adresses
 * and for anti-spoofing
 */
fn fnvla(data: &[u8]) -> u32 {
    let mut hash: u32 = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/**
 * Link-Hash calculating
 */
pub fn get_link_hash(mac_a: &[u8; 6], mac_b: &[u8; 6]) -> u32 {
    let (lower, upper) = if mac_a < mac_b {
        (mac_a, mac_b)
    } else {
        (mac_b, mac_a)
    };

    let mut buf = [0u8; 12];
    buf[..6].copy_from_slice(lower);
    buf[6..].copy_from_slice(upper);
    fnvla(&buf)
}
