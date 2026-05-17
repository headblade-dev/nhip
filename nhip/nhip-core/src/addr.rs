pub const MAX_ADDR_BLOCKS: u8 = 8;
pub const MAX_BLOCK_LEN: usize = 16;

pub const MAX_ADDR_LEN: usize = 
    MAX_ADDR_BLOCKS as usize * MAX_BLOCK_LEN // blocks
    + (MAX_ADDR_BLOCKS as usize - 1);        // periods

pub const MAX_NODE_ID_LEN: usize = 16;
pub const BLOCK_SEPARATOR:u8 = b'.';
pub const ADDR_PARTS_SEPARATOR:u8 = b':';
pub const BROADCAST_NODE_ID: u32 = 1_000_000_000;
pub const MAX_NODE_ID: u32 = 1_073_741_823;

// address validation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrErr {
    Empty,
    TooLong,
    TooManyBlocks,
    BlockTooLong,
    NodeIdTooLong,
    InvalidChar,
    NoNodeId,
    EmptyBlock,
    NodeIdOutOfRange,
}

/**
 * Network-part validation
 */
pub fn validate_addr(addr: &[u8]) -> Result<(), AddrErr> {
    if addr.is_empty() {
        return Err(AddrErr::Empty);
    }
    if addr.len() > MAX_ADDR_LEN {
        return Err(AddrErr::TooLong);
    }

    let mut block_count: u8 = 1;
    let mut block_len: usize = 0;

    for &byte in addr {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => {
                block_len += 1;
                if block_len > MAX_BLOCK_LEN {
                    return Err(AddrErr::BlockTooLong);
                }
            }
            BLOCK_SEPARATOR => {
                if block_len == 0 {
                    return Err(AddrErr::EmptyBlock);
                }

                block_count += 1;
                if block_count > MAX_ADDR_BLOCKS {
                    return Err(AddrErr::TooManyBlocks);
                }
            }

            _ => return Err(AddrErr::InvalidChar)
        }
    }

    if block_len == 0 {
        return Err(AddrErr::EmptyBlock);
    }

    return Ok(())
}


/**
 * Pointer validation
 *  pointer = 0 - start of network-part
 *  pointer = 0xFF - start of NodeID
 *  if pointer !=0, then dst_addr[pointer-1] must be b'.'
 */
pub fn validate_pointer(addr: &[u8], pointer: u8) -> bool {
    if pointer == 0 || pointer == 0xFF{
        return true;
    }
    let idx = pointer as usize;
    if idx > addr.len() {
        return false;
    }
    addr[idx - 1] == BLOCK_SEPARATOR
}

/**
 * Calculate next pointer
 * if needed block is last, returns 0xFF
 */
#[allow(unused)]
pub fn next_pointer(addr: &[u8]) -> Option<u8> {
    unimplemented!()
}


fn is_letter(b: u8) -> bool {
    matches!(b, b'g' | b'G' | b'm' | b'M' | b'k' | b'K')
}

fn letter_multiplier(b: u8) -> Option<u32> {
    match b {
        b'g' | b'G' => Some(1_000_000_000),
        b'm' | b'M' => Some(1_000_000),
        b'k' | b'K' => Some(1_000),
        _ => None,
    }
}
/*
    ===== NodeID formatting rules =====
    1. Letter multipliers:
        g - billions
        m - millions
        k - thousands
            1g73m12k3 = 1_073_012_3
    
    2. Dots:
        2.1. If dot is right after letter multiplier, then the digit after this dot is the next digit after the letter:
            1g.73 = 1_073_000_000
        2.2. Otherwise, the digits are counted from right to left:
            1g73 = 1_000_000_073
    
    3. Truncating leading zeros in digits:
        0.032.007.001 - 32.7.1

    4. NodeID Formatting is creative place for system administrator:
        0.001.012.36 can be:
        1m12.36
        1m.12.36
        1m12k36
        1.12.36
        1.012.36
        and more other variants

    5. No matter what NodeID Formatting methods you choose, the NHIP packet header always stores a number like 0_012_013_456
*/
pub fn parse_node_id(raw: &[u8]) -> Result<u32, AddrErr> {
    if raw.is_empty() {
        return Err(AddrErr::NoNodeId);
    }

    if raw.len() > MAX_NODE_ID_LEN {
        return Err(AddrErr::NodeIdTooLong);
    }

    let bytes = raw;
    let len = bytes.len();

    // check if node id uses letter formatting
    let has_letters = bytes.iter().any(|&b| is_letter(b));

    if !has_letters {
        let mut result: u32 = 0;
        for &b in bytes {
            if b == b'.' {
                continue;
            }

            if !b.is_ascii_digit() {
                return Err(AddrErr::InvalidChar)
            }

            result = result * 10 + (b - b'0') as u32;
        }
    
        return Ok(result)
    } 
    
    let mut result: u32 = 0;
    let mut i = 0;
    let mut next_multiplier: Option<u32> = None;

    while i < len {
        if bytes[i] == b'.' {
            if i > 0 && is_letter(bytes[i - 1]) {
                next_multiplier = match bytes[i - 1] {
                    b'g' | b'G' => Some(1_000_000),
                    b'm' | b'M' => Some(1_000),
                    b'k' | b'K' => Some(1),
                    _ => None
                };
            }
            i += 1;
            continue;
        }

        let start = i;
        while i < len && bytes[i].is_ascii_digit() {
            i += 1;
        }

        let num: u32 = if i == start {
            0
        } else {
            let mut n: u32 = 0;
            for j in start..i {
                n = n * 10 + (bytes[j] - b'0') as u32;
            }
            n
        };

        if i < len && is_letter(bytes[i]) {
            let mult = letter_multiplier(bytes[i]).unwrap();
            i += 1;
            result += num * mult;
            next_multiplier = None;
        } else if let Some(mult) = next_multiplier.take() {
            result += num * mult;
        } else {
            result += num;
        }
    }

    if result > MAX_NODE_ID {
        return Err(AddrErr::NodeIdOutOfRange);
    }

    Ok(result)
}