#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, xdp_action},
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, XskMap, lpm_trie::Key as LpmKey},
    programs::XdpContext,
};
use core::mem::size_of;
use zeroio_xdp_common::{
    XDP_ACL_DROP, XDP_PORT_ACTION_REDIRECT_XSK, XDP_PROTO_TCP, XDP_PROTO_UDP,
    XDP_SPLICE_FLAG_HAIRPIN_TX, XdpAclRule, XdpCounters, XdpFlowKey, XdpInterfaceMode, XdpIpV4,
    XdpIpV6, XdpPortKey, XdpPortRule, XdpRateBucket, XdpRuntimeConfig, XdpSpliceTarget,
    csum_replace_ipv6, csum_replace_u16, csum_replace_u32, pack_ipv4,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    proto: u16,
}

#[repr(C)]
struct VlanHdr {
    tci: u16,
    inner_proto: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    vihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

#[repr(C)]
struct Ipv6Hdr {
    ver_tc_fl: [u8; 4],
    payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    doff_res: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[repr(C)]
struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    check: u16,
}

/// Per-CPU scratch storage keeping every eBPF stack frame well under the 512-byte limit.
#[repr(C)]
struct XdpScratch {
    flow: XdpFlowKey,
    lpm_v6: LpmKey<XdpIpV6>,
    rate_init: XdpRateBucket,
    old_src_v6: [u8; 16],
    old_dst_v6: [u8; 16],
}

#[map(name = "ZEROIO_CONFIG")]
static ZEROIO_CONFIG: Array<XdpRuntimeConfig> = Array::with_max_entries(1, 0);

#[map(name = "ZEROIO_COUNTERS")]
static ZEROIO_COUNTERS: PerCpuArray<XdpCounters> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "ZEROIO_SCRATCH")]
static ZEROIO_SCRATCH: PerCpuArray<XdpScratch> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "ZEROIO_ACL_V4")]
static ZEROIO_ACL_V4: LpmTrie<XdpIpV4, XdpAclRule> =
    LpmTrie::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map(name = "ZEROIO_ACL_V6")]
static ZEROIO_ACL_V6: LpmTrie<XdpIpV6, XdpAclRule> =
    LpmTrie::with_max_entries(16_384, BPF_F_NO_PREALLOC);

#[map(name = "ZEROIO_RATE_V4")]
static ZEROIO_RATE_V4: LruHashMap<XdpIpV4, XdpRateBucket> = LruHashMap::with_max_entries(65_536, 0);

#[map(name = "ZEROIO_RATE_V6")]
static ZEROIO_RATE_V6: LruHashMap<XdpIpV6, XdpRateBucket> = LruHashMap::with_max_entries(65_536, 0);

#[map(name = "ZEROIO_PORTS")]
static ZEROIO_PORTS: HashMap<XdpPortKey, XdpPortRule> = HashMap::with_max_entries(1_024, 0);

#[map(name = "ZEROIO_SPLICE")]
static ZEROIO_SPLICE: HashMap<XdpFlowKey, XdpSpliceTarget> = HashMap::with_max_entries(65_536, 0);

#[map(name = "ZEROIO_XSKS")]
static ZEROIO_XSKS: XskMap = XskMap::with_max_entries(4_096, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start.saturating_add(offset).saturating_add(len) > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();
    if start.saturating_add(offset).saturating_add(len) > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[inline(always)]
fn counters_mut() -> Option<&'static mut XdpCounters> {
    let ptr = ZEROIO_COUNTERS.get_ptr_mut(0)?;
    // SAFETY: PerCpuArray slot 0 is exclusively owned by the currently executing CPU.
    Some(unsafe { &mut *ptr })
}

#[inline(always)]
fn scratch_mut() -> Option<&'static mut XdpScratch> {
    let ptr = ZEROIO_SCRATCH.get_ptr_mut(0)?;
    // SAFETY: PerCpuArray slot 0 is exclusively owned by the currently executing CPU.
    Some(unsafe { &mut *ptr })
}

#[inline(always)]
fn check_rate_bucket(
    bucket: &mut XdpRateBucket,
    now_ns: u64,
    is_pure_syn: bool,
    cfg: &XdpRuntimeConfig,
) -> (bool, bool) {
    if cfg.rate_window_ns == 0 {
        return (false, false);
    }
    if now_ns.saturating_sub(bucket.window_start_ns) >= cfg.rate_window_ns {
        bucket.window_start_ns = now_ns;
        bucket.packets = 1;
        bucket.syn_packets = u64::from(is_pure_syn);
        return (false, false);
    }
    bucket.packets = bucket.packets.saturating_add(1);
    if is_pure_syn {
        bucket.syn_packets = bucket.syn_packets.saturating_add(1);
    }
    let syn_limited =
        is_pure_syn && cfg.syn_flood_guard != 0 && cfg.rate_max_syn > 0 && bucket.syn_packets > cfg.rate_max_syn;
    let pkt_limited = cfg.rate_max_packets > 0 && bucket.packets > cfg.rate_max_packets;
    (pkt_limited, syn_limited)
}

#[inline(never)]
fn check_acl_and_rate_v4(
    src_ip: [u8; 4],
    is_pure_syn: bool,
    cfg: &XdpRuntimeConfig,
    scratch: &mut XdpScratch,
) -> u8 {
    let acl_key = LpmKey::new(32, XdpIpV4 { addr: src_ip });
    if let Some(rule) = ZEROIO_ACL_V4.get(&acl_key)
        && rule.action == XDP_ACL_DROP
    {
        return 1; // ACL drop
    }
    if cfg.rate_limit_enabled == 0 {
        return 0;
    }
    // SAFETY: bpf_ktime_get_ns is a stateless kernel helper returning monotonic ns.
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let rkey = XdpIpV4 { addr: src_ip };
    if let Some(ptr) = ZEROIO_RATE_V4.get_ptr_mut(&rkey) {
        // SAFETY: verifier tracks non-null LRU map value pointer for the current program run.
        let bucket = unsafe { &mut *ptr };
        let (pkt_lim, syn_lim) = check_rate_bucket(bucket, now_ns, is_pure_syn, cfg);
        if syn_lim {
            return 3;
        }
        if pkt_lim {
            return 2;
        }
        return 0;
    }
    scratch.rate_init = XdpRateBucket {
        window_start_ns: now_ns,
        packets: 1,
        syn_packets: u64::from(is_pure_syn),
    };
    let _ = ZEROIO_RATE_V4.insert(&rkey, &scratch.rate_init, 0);
    0
}

#[inline(never)]
fn check_acl_and_rate_v6(
    src_ip: &[u8; 16],
    is_pure_syn: bool,
    cfg: &XdpRuntimeConfig,
    scratch: &mut XdpScratch,
) -> u8 {
    scratch.lpm_v6.prefix_len = 128;
    scratch.lpm_v6.data.addr = *src_ip;
    if let Some(rule) = ZEROIO_ACL_V6.get(&scratch.lpm_v6)
        && rule.action == XDP_ACL_DROP
    {
        return 1; // ACL drop
    }
    if cfg.rate_limit_enabled == 0 {
        return 0;
    }
    // SAFETY: bpf_ktime_get_ns is a stateless kernel helper returning monotonic ns.
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let rkey = &scratch.lpm_v6.data;
    if let Some(ptr) = ZEROIO_RATE_V6.get_ptr_mut(rkey) {
        // SAFETY: verifier tracks non-null LRU map value pointer for the current program run.
        let bucket = unsafe { &mut *ptr };
        let (pkt_lim, syn_lim) = check_rate_bucket(bucket, now_ns, is_pure_syn, cfg);
        if syn_lim {
            return 3;
        }
        if pkt_lim {
            return 2;
        }
        return 0;
    }
    scratch.rate_init = XdpRateBucket {
        window_start_ns: now_ns,
        packets: 1,
        syn_packets: u64::from(is_pure_syn),
    };
    let _ = ZEROIO_RATE_V6.insert(rkey, &scratch.rate_init, 0);
    0
}

#[inline(always)]
fn flow_hash_queue(key: &XdpFlowKey, ctx: &XdpContext, queue_count: u32) -> u32 {
    if queue_count == 0 {
        return ctx.rx_queue_index();
    }
    let s0 = u32::from_be_bytes([key.src_ip[12], key.src_ip[13], key.src_ip[14], key.src_ip[15]]);
    let d0 = u32::from_be_bytes([key.dst_ip[12], key.dst_ip[13], key.dst_ip[14], key.dst_ip[15]]);
    let p = (u32::from(key.src_port) << 16) ^ u32::from(key.dst_port);
    let mix = s0 ^ d0 ^ p ^ u32::from(key.proto);
    mix % queue_count
}

#[inline(never)]
fn try_splice_v4(
    ctx: &XdpContext,
    l3_offset: usize,
    l4_offset: usize,
    flow: &XdpFlowKey,
    pkt_bytes: u64,
) -> Option<u32> {
    let target_ptr = ZEROIO_SPLICE.get_ptr_mut(flow)?;
    // SAFETY: target_ptr points to a valid ZEROIO_SPLICE map entry for this key.
    let target = unsafe { &mut *target_ptr };
    if target.is_v6 != 0 {
        return None;
    }

    let ip_ptr = ptr_at_mut::<Ipv4Hdr>(ctx, l3_offset).ok()?;
    // SAFETY: ptr_at_mut verified [l3_offset .. l3_offset + sizeof(Ipv4Hdr)] <= data_end.
    let ip = unsafe { &mut *ip_ptr };

    let old_src = u32::from_be_bytes(ip.src_addr);
    let old_dst = u32::from_be_bytes(ip.dst_addr);
    let new_src_octets = [
        target.new_src_ip[12],
        target.new_src_ip[13],
        target.new_src_ip[14],
        target.new_src_ip[15],
    ];
    let new_dst_octets = [
        target.new_dst_ip[12],
        target.new_dst_ip[13],
        target.new_dst_ip[14],
        target.new_dst_ip[15],
    ];
    let new_src = u32::from_be_bytes(new_src_octets);
    let new_dst = u32::from_be_bytes(new_dst_octets);

    let mut l3_csum = u16::from_be_bytes(ip.check.to_ne_bytes());
    l3_csum = csum_replace_u32(l3_csum, old_src, new_src);
    l3_csum = csum_replace_u32(l3_csum, old_dst, new_dst);
    ip.src_addr = new_src_octets;
    ip.dst_addr = new_dst_octets;
    ip.check = u16::from_ne_bytes(l3_csum.to_be_bytes());

    let new_sport_be = target.new_src_port.to_be();
    let new_dport_be = target.new_dst_port.to_be();

    if flow.proto == XDP_PROTO_TCP {
        let tcp_ptr = ptr_at_mut::<TcpHdr>(ctx, l4_offset).ok()?;
        // SAFETY: ptr_at_mut verified [l4_offset .. l4_offset + sizeof(TcpHdr)] <= data_end.
        let tcp = unsafe { &mut *tcp_ptr };
        let mut l4_csum = u16::from_be_bytes(tcp.check.to_ne_bytes());
        l4_csum = csum_replace_u32(l4_csum, old_src, new_src);
        l4_csum = csum_replace_u32(l4_csum, old_dst, new_dst);
        l4_csum = csum_replace_u16(l4_csum, flow.src_port, target.new_src_port);
        l4_csum = csum_replace_u16(l4_csum, flow.dst_port, target.new_dst_port);
        tcp.src_port = new_sport_be;
        tcp.dst_port = new_dport_be;
        tcp.check = u16::from_ne_bytes(l4_csum.to_be_bytes());
    } else if flow.proto == XDP_PROTO_UDP {
        let udp_ptr = ptr_at_mut::<UdpHdr>(ctx, l4_offset).ok()?;
        // SAFETY: ptr_at_mut verified [l4_offset .. l4_offset + sizeof(UdpHdr)] <= data_end.
        let udp = unsafe { &mut *udp_ptr };
        if udp.check != 0 {
            let mut l4_csum = u16::from_be_bytes(udp.check.to_ne_bytes());
            l4_csum = csum_replace_u32(l4_csum, old_src, new_src);
            l4_csum = csum_replace_u32(l4_csum, old_dst, new_dst);
            l4_csum = csum_replace_u16(l4_csum, flow.src_port, target.new_src_port);
            l4_csum = csum_replace_u16(l4_csum, flow.dst_port, target.new_dst_port);
            if l4_csum == 0 {
                l4_csum = 0xFFFF;
            }
            udp.check = u16::from_ne_bytes(l4_csum.to_be_bytes());
        }
        udp.src_port = new_sport_be;
        udp.dst_port = new_dport_be;
    }

    if (target.flags & XDP_SPLICE_FLAG_HAIRPIN_TX) != 0 {
        let eth_ptr = ptr_at_mut::<EthHdr>(ctx, 0).ok()?;
        // SAFETY: ptr_at_mut verified [0 .. sizeof(EthHdr)] <= data_end.
        let eth = unsafe { &mut *eth_ptr };
        let orig_dst = eth.dst;
        eth.dst = eth.src;
        eth.src = orig_dst;
        target.packets = target.packets.saturating_add(1);
        target.bytes = target.bytes.saturating_add(pkt_bytes);
        return Some(xdp_action::XDP_TX);
    }

    target.packets = target.packets.saturating_add(1);
    target.bytes = target.bytes.saturating_add(pkt_bytes);
    Some(xdp_action::XDP_PASS)
}

#[inline(never)]
fn try_splice_v6(
    ctx: &XdpContext,
    l3_offset: usize,
    l4_offset: usize,
    scratch: &mut XdpScratch,
    pkt_bytes: u64,
) -> Option<u32> {
    let target_ptr = ZEROIO_SPLICE.get_ptr_mut(&scratch.flow)?;
    // SAFETY: target_ptr points to a valid ZEROIO_SPLICE map entry for this key.
    let target = unsafe { &mut *target_ptr };
    if target.is_v6 == 0 {
        return None;
    }

    let ip_ptr = ptr_at_mut::<Ipv6Hdr>(ctx, l3_offset).ok()?;
    // SAFETY: ptr_at_mut verified [l3_offset .. l3_offset + sizeof(Ipv6Hdr)] <= data_end.
    let ip = unsafe { &mut *ip_ptr };
    scratch.old_src_v6 = ip.src_addr;
    scratch.old_dst_v6 = ip.dst_addr;
    ip.src_addr = target.new_src_ip;
    ip.dst_addr = target.new_dst_ip;

    let new_sport_be = target.new_src_port.to_be();
    let new_dport_be = target.new_dst_port.to_be();

    if scratch.flow.proto == XDP_PROTO_TCP {
        let tcp_ptr = ptr_at_mut::<TcpHdr>(ctx, l4_offset).ok()?;
        // SAFETY: ptr_at_mut verified [l4_offset .. l4_offset + sizeof(TcpHdr)] <= data_end.
        let tcp = unsafe { &mut *tcp_ptr };
        let mut l4_csum = u16::from_be_bytes(tcp.check.to_ne_bytes());
        l4_csum = csum_replace_ipv6(l4_csum, scratch.old_src_v6, target.new_src_ip);
        l4_csum = csum_replace_ipv6(l4_csum, scratch.old_dst_v6, target.new_dst_ip);
        l4_csum = csum_replace_u16(l4_csum, scratch.flow.src_port, target.new_src_port);
        l4_csum = csum_replace_u16(l4_csum, scratch.flow.dst_port, target.new_dst_port);
        tcp.src_port = new_sport_be;
        tcp.dst_port = new_dport_be;
        tcp.check = u16::from_ne_bytes(l4_csum.to_be_bytes());
    } else if scratch.flow.proto == XDP_PROTO_UDP {
        let udp_ptr = ptr_at_mut::<UdpHdr>(ctx, l4_offset).ok()?;
        // SAFETY: ptr_at_mut verified [l4_offset .. l4_offset + sizeof(UdpHdr)] <= data_end.
        let udp = unsafe { &mut *udp_ptr };
        let mut l4_csum = u16::from_be_bytes(udp.check.to_ne_bytes());
        l4_csum = csum_replace_ipv6(l4_csum, scratch.old_src_v6, target.new_src_ip);
        l4_csum = csum_replace_ipv6(l4_csum, scratch.old_dst_v6, target.new_dst_ip);
        l4_csum = csum_replace_u16(l4_csum, scratch.flow.src_port, target.new_src_port);
        l4_csum = csum_replace_u16(l4_csum, scratch.flow.dst_port, target.new_dst_port);
        if l4_csum == 0 {
            l4_csum = 0xFFFF;
        }
        udp.src_port = new_sport_be;
        udp.dst_port = new_dport_be;
        udp.check = u16::from_ne_bytes(l4_csum.to_be_bytes());
    }

    if (target.flags & XDP_SPLICE_FLAG_HAIRPIN_TX) != 0 {
        let eth_ptr = ptr_at_mut::<EthHdr>(ctx, 0).ok()?;
        // SAFETY: ptr_at_mut verified [0 .. sizeof(EthHdr)] <= data_end.
        let eth = unsafe { &mut *eth_ptr };
        let orig_dst = eth.dst;
        eth.dst = eth.src;
        eth.src = orig_dst;
        target.packets = target.packets.saturating_add(1);
        target.bytes = target.bytes.saturating_add(pkt_bytes);
        return Some(xdp_action::XDP_TX);
    }

    target.packets = target.packets.saturating_add(1);
    target.bytes = target.bytes.saturating_add(pkt_bytes);
    Some(xdp_action::XDP_PASS)
}

#[inline(always)]
fn try_xdp(ctx: &XdpContext) -> u32 {
    let pkt_bytes = ctx.data_end().saturating_sub(ctx.data()) as u64;
    let mut ctrs = counters_mut();
    let cfg = match ZEROIO_CONFIG.get(0) {
        Some(c) => *c,
        None => XdpRuntimeConfig::default(),
    };

    if cfg.mode == XdpInterfaceMode::Observe as u8 {
        if let Some(c) = ctrs {
            c.packets = c.packets.saturating_add(1);
            c.passed = c.passed.saturating_add(1);
        }
        return xdp_action::XDP_PASS;
    }

    let Ok(eth_ptr) = ptr_at::<EthHdr>(ctx, 0) else {
        if let Some(c) = ctrs {
            c.packets = c.packets.saturating_add(1);
            c.parse_errors = c.parse_errors.saturating_add(1);
            c.passed = c.passed.saturating_add(1);
        }
        return xdp_action::XDP_PASS;
    };
    // SAFETY: ptr_at verified Ethernet header bounds against data_end.
    let mut ethertype = u16::from_be(unsafe { (*eth_ptr).proto });
    let mut offset = size_of::<EthHdr>();

    for _ in 0..2 {
        if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
            let Ok(vlan_ptr) = ptr_at::<VlanHdr>(ctx, offset) else {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            };
            // SAFETY: ptr_at verified VLAN header bounds against data_end.
            ethertype = u16::from_be(unsafe { (*vlan_ptr).inner_proto });
            offset += size_of::<VlanHdr>();
        } else {
            break;
        }
    }

    let Some(scratch) = scratch_mut() else {
        if let Some(c) = ctrs {
            c.packets = c.packets.saturating_add(1);
            c.passed = c.passed.saturating_add(1);
        }
        return xdp_action::XDP_PASS;
    };

    let l3_offset = offset;
    let (is_v6, proto, l4_offset, src_v4) = match ethertype {
        ETHERTYPE_IPV4 => {
            let Ok(ip_ptr) = ptr_at::<Ipv4Hdr>(ctx, l3_offset) else {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            };
            // SAFETY: ptr_at verified IPv4 fixed header bounds against data_end.
            let ip = unsafe { &*ip_ptr };
            let ihl = usize::from(ip.vihl & 0x0F) * 4;
            if (ip.vihl >> 4) != 4 || ihl < 20 {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            }
            if (u16::from_be(ip.frag_off) & 0x3FFF) != 0 {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            }
            scratch.flow.src_ip = pack_ipv4(ip.src_addr);
            scratch.flow.dst_ip = pack_ipv4(ip.dst_addr);
            (false, ip.proto, l3_offset + ihl, ip.src_addr)
        }
        ETHERTYPE_IPV6 => {
            let Ok(ip_ptr) = ptr_at::<Ipv6Hdr>(ctx, l3_offset) else {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            };
            // SAFETY: ptr_at verified IPv6 fixed header bounds against data_end.
            let ip = unsafe { &*ip_ptr };
            if (ip.ver_tc_fl[0] >> 4) != 6 {
                if let Some(c) = ctrs {
                    c.packets = c.packets.saturating_add(1);
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            }
            scratch.flow.src_ip = ip.src_addr;
            scratch.flow.dst_ip = ip.dst_addr;
            (true, ip.next_hdr, l3_offset + size_of::<Ipv6Hdr>(), [0u8; 4])
        }
        _ => {
            if let Some(c) = ctrs {
                c.packets = c.packets.saturating_add(1);
                c.passed = c.passed.saturating_add(1);
            }
            return xdp_action::XDP_PASS;
        }
    };

    if let Some(c) = ctrs.as_deref_mut() {
        c.packets = c.packets.saturating_add(1);
    }

    let (src_port, dst_port, is_pure_syn) = match proto {
        XDP_PROTO_TCP => {
            let Ok(tcp_ptr) = ptr_at::<TcpHdr>(ctx, l4_offset) else {
                if let Some(c) = ctrs {
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            };
            // SAFETY: ptr_at verified TCP fixed header bounds against data_end.
            let tcp = unsafe { &*tcp_ptr };
            let pure_syn = (tcp.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN;
            (u16::from_be(tcp.src_port), u16::from_be(tcp.dst_port), pure_syn)
        }
        XDP_PROTO_UDP => {
            let Ok(udp_ptr) = ptr_at::<UdpHdr>(ctx, l4_offset) else {
                if let Some(c) = ctrs {
                    c.parse_errors = c.parse_errors.saturating_add(1);
                    c.passed = c.passed.saturating_add(1);
                }
                return xdp_action::XDP_PASS;
            };
            // SAFETY: ptr_at verified UDP header bounds against data_end.
            let udp = unsafe { &*udp_ptr };
            (u16::from_be(udp.src_port), u16::from_be(udp.dst_port), false)
        }
        _ => {
            if let Some(c) = ctrs {
                c.passed = c.passed.saturating_add(1);
            }
            return xdp_action::XDP_PASS;
        }
    };

    // 1) ACL LPM + per-IP rate limit / SYN guard.
    let drop_reason = if is_v6 {
        let src_v6 = scratch.flow.src_ip;
        check_acl_and_rate_v6(&src_v6, is_pure_syn, &cfg, scratch)
    } else {
        check_acl_and_rate_v4(src_v4, is_pure_syn, &cfg, scratch)
    };
    if drop_reason != 0 {
        if let Some(c) = ctrs {
            match drop_reason {
                1 => c.acl_dropped = c.acl_dropped.saturating_add(1),
                3 => c.syn_rate_limited = c.syn_rate_limited.saturating_add(1),
                _ => c.rate_limited = c.rate_limited.saturating_add(1),
            }
            c.dropped = c.dropped.saturating_add(1);
        }
        return xdp_action::XDP_DROP;
    }

    if cfg.mode != XdpInterfaceMode::Proxy as u8 {
        if let Some(c) = ctrs {
            c.passed = c.passed.saturating_add(1);
        }
        return xdp_action::XDP_PASS;
    }

    // 2) Proxy mode: L4 eBPF splice / NAT fast-path.
    scratch.flow.src_port = src_port;
    scratch.flow.dst_port = dst_port;
    scratch.flow.proto = proto;
    scratch.flow.is_v6 = u8::from(is_v6);
    scratch.flow._pad = [0; 2];

    let splice_verdict = if is_v6 {
        try_splice_v6(ctx, l3_offset, l4_offset, scratch, pkt_bytes)
    } else {
        try_splice_v4(ctx, l3_offset, l4_offset, &scratch.flow, pkt_bytes)
    };
    if let Some(action) = splice_verdict {
        if let Some(c) = ctrs {
            c.spliced = c.spliced.saturating_add(1);
        }
        return action;
    }

    // 3) Proxy mode: Port-based AF_XDP XSK redirect.
    let port_key = XdpPortKey {
        port: dst_port,
        proto,
        _pad: 0,
    };
    if let Some(rule_ptr) = ZEROIO_PORTS.get_ptr(&port_key) {
        // SAFETY: rule_ptr points to a valid ZEROIO_PORTS entry.
        let rule = unsafe { *rule_ptr };
        if rule.action == XDP_PORT_ACTION_REDIRECT_XSK {
            let queue = if rule.queue_override >= 0 {
                rule.queue_override as u32
            } else {
                flow_hash_queue(&scratch.flow, ctx, cfg.xsk_queue_count)
            };
            if let Ok(action) = ZEROIO_XSKS.redirect(queue, 0) {
                if let Some(c) = ctrs {
                    c.redirected = c.redirected.saturating_add(1);
                }
                return action;
            }
            if let Some(c) = ctrs {
                c.xsk_drops = c.xsk_drops.saturating_add(1);
                c.passed = c.passed.saturating_add(1);
            }
            return xdp_action::XDP_PASS;
        }
    }

    if cfg.default_drop_unmatched != 0 {
        if let Some(c) = ctrs {
            c.dropped = c.dropped.saturating_add(1);
        }
        return xdp_action::XDP_DROP;
    }

    if let Some(c) = ctrs {
        c.passed = c.passed.saturating_add(1);
    }
    xdp_action::XDP_PASS
}

#[xdp]
pub fn zeroio_xdp(ctx: XdpContext) -> u32 {
    try_xdp(&ctx)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
