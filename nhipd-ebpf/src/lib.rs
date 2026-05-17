#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray},
    programs::XdpContext
};
use aya_log_ebpf::info;
use core::mem;
use network_types::eth::{EthHdr};
use nhip_core::header::{NHIPHeader, NHIP_ETHERTYPE, NHIP_HEADER_LEN};
use bytemuck::{Pod, Zeroable};


// ===== eBPF Maps =====

// Temporal packet data buffer
#[map]
static BUF: PerCpuArray<[u8; 1500]> = PerCpuArray::with_max_entries(1, 0);

/** 
 *  FASTPATH_TABLE
 *  Key: link_label
 *  Value: ForwardEntry
 */
#[map]
static FASTPATH_TABLE: HashMap<u32, ForwardEntry> = HashMap::with_max_entries(8092, 0);

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct ForwardEntry {
    next_label: u32,
    ifindex: u32,
    dmac: [u8; 6],
    _pad: [u8; 2],
}

/**
 *  NHARP_TABLE
 *  Key: dst_node_id
 *  Value: NharpEntry
 */
#[map]
static NHARP_TABLE: HashMap<u32, NharpEntry> = HashMap::with_max_entries(8192, 0);

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct NharpEntry {
    mac: [u8; 6],
    _pad: [u8; 2],
}

// ===== Constants =====
// Default-label - packet need to use Slow Path
const LABEL_DEFAULT: u32 = 0;
// Egress-label - packet in destination network
const LABEL_EGRESS: u32 = 0xFFFF_FFFF;

// ===== XDP Entrypoint =====
#[xdp]
pub fn nhipd_xdp(ctx: XdpContext) -> u32 {
    let ptr = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;

    // Ethernet
    if (ptr as usize) + mem::size_of::<EthHdr>() > end as usize {
        return xdp_action::XDP_PASS;
    }
    let eth_header: &EthHdr = unsafe { &*(ptr as *const EthHdr) };
    if eth_header.ether_type != NHIP_ETHERTYPE{
        return xdp_action::XDP_PASS;
    }

    // NHIP Header
    let nhip_ptr = unsafe { ptr.add(mem::size_of::<EthHdr>()) } as *const u8;
    if (nhip_ptr as usize) + NHIP_HEADER_LEN > end as usize {
        return xdp_action::XDP_PASS;
    }
    let nhip_hdr: &NHIPHeader = unsafe { &*(nhip_ptr as *const NHIPHeader) };
    let link_label = u32::from_be(nhip_hdr.link_label);

    // Slow Path: link_label == 0
    if link_label == LABEL_DEFAULT {
        info!(&ctx, "NHIP SlowPath: Label is 0. Pass to userspace");
        return xdp_action::XDP_PASS;
    }

    // Fast Path lookup
    if let Some(entry) = unsafe { FASTPATH_TABLE.get(&link_label) } {
        if entry.next_label == LABEL_EGRESS {
            info!(&ctx, "NHIP FastPath: reached destination (link label is {}", link_label);
            return xdp_action::XDP_PASS;
        }
        info!(&ctx, "NHIP FastPath: {} -> {} via ifindex {}",
                link_label, entry.next_label, entry.ifindex);

        // TODO: label, dmac, XDP_REDIRECT
        return xdp_action::XDP_REDIRECT;
    }

    // Miss: label is not found and not zero -> drop
    info!(&ctx, "NHIP Miss: label {} not found, dropping", link_label);
    xdp_action::XDP_DROP
}



#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}