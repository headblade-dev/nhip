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
use nhip_core::header::{NhipHeader, NHIP_ETHERTYPE, NHIP_HEADER_LEN};
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
#[map(name = "FASTPATH_TABLE")]
static mut FASTPATH_TABLE: HashMap<u64, ForwardEntry> = HashMap::with_max_entries(8092, 0);

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct ForwardEntry {
    next_label: u64,
    ifindex: u32,
    dmac: [u8; 6],
    _pad: [u8; 2],
}

/**
 *  NHARP_TABLE
 *  Key: dst_node_id
 *  Value: NharpEntry
 */
#[map(name = "NHARP_TABLE")]
static mut NHARP_TABLE: HashMap<u32, NharpEntry> = HashMap::with_max_entries(8192, 0);

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct NharpEntry {
    mac: [u8; 6],
    _pad: [u8; 2],
}

/**
 *  IFACE_MAC
 *  Key: ifindex
 *  Value: mac
 */
#[map(name = "IFACE_MAC")]
static mut IFACE_MAC: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(256, 0);

// ===== Constants =====
// Default-label - packet need to use Slow Path
const LABEL_DEFAULT: u64 = 0;
// Egress-label - packet in destination network
const LABEL_EGRESS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

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
    let nhip_hdr: &NhipHeader = unsafe { &*(nhip_ptr as *const NhipHeader) };
    let link_label = u64::from_be(nhip_hdr.link_label);

    // Slow Path: link_label == 0
    if link_label == LABEL_DEFAULT {
        info!(&ctx, "NHIP SlowPath: Label is 0. Pass to userspace");
        return xdp_action::XDP_PASS;
    }

    #[allow(static_mut_refs)]
    // Fast Path lookup and redirect
    if let Some(entry) = unsafe { FASTPATH_TABLE.get(&link_label) } {
        // Check if packet reached destination
        if entry.next_label == LABEL_EGRESS {
            return xdp_action::XDP_PASS;
        }

        // Replace link-label in this packet (Nhip Header)
        let nhip_mut = unsafe { &mut *(nhip_ptr as *mut NhipHeader) };
        nhip_mut.link_label = entry.next_label.to_be();

        // Replace MAC-addresses in this packet (Ethernet header)
        let eth_mut = unsafe { &mut *(ptr as *mut EthHdr) };
        eth_mut.dst_addr = entry.dmac;

        let ifindex = entry.ifindex;
        if let Some(&src_mac) = unsafe { IFACE_MAC.get(&ifindex) } {
            eth_mut.src_addr = src_mac;
        }

        if unsafe { aya_ebpf::helpers::bpf_redirect(ifindex, 0) == 0 } {
            return xdp_action::XDP_REDIRECT;
        }
        return xdp_action::XDP_DROP;
    }

    // Miss: label is not found and not zero -> pass to userspace
    xdp_action::XDP_PASS
}



#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}