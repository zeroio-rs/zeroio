#![cfg_attr(not(feature = "std"), no_std)]

//! Shared `#[repr(C)]` ABI types and `no_std` helpers for Zeroio XDP eBPF maps,
//! counters, ACL/rate-limit rules, L4 splice forwarding, and userspace dataplane control.

/// Default UMEM frame size for standard-MTU AF_XDP queues.
pub const XDP_DEFAULT_FRAME_SIZE: u32 = 2048;

/// IP protocol number constants shared across eBPF and userspace parsers.
pub const XDP_PROTO_TCP: u8 = 6;
pub const XDP_PROTO_UDP: u8 = 17;

/// ACL verdict actions stored in [`XdpAclRule::action`].
pub const XDP_ACL_ALLOW: u8 = 1;
pub const XDP_ACL_DROP: u8 = 2;

/// Port routing actions stored in [`XdpPortRule::action`].
pub const XDP_PORT_ACTION_PASS: u8 = 0;
pub const XDP_PORT_ACTION_REDIRECT_XSK: u8 = 1;

/// Splice output flags stored in [`XdpSpliceTarget::flags`].
pub const XDP_SPLICE_FLAG_HAIRPIN_TX: u8 = 1 << 0;

/// Operating mode of a network interface under Zeroio XDP.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpInterfaceMode {
    /// Attach XDP and sample statistics without dropping or redirecting traffic.
    Observe = 0,
    /// Enforce ACL blocklists and per-IP rate limits at driver RX, passing valid flows to the kernel stack.
    Protect = 1,
    /// Enforce protection rules, execute L4 eBPF splice/NAT forwards, and redirect selected ports to AF_XDP.
    Proxy = 2,
}

/// Global per-interface runtime policy read by the XDP program from `ZEROIO_CONFIG`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdpRuntimeConfig {
    /// [`XdpInterfaceMode`] encoded as `u8` (0 = Observe, 1 = Protect, 2 = Proxy).
    pub mode: u8,
    /// When non-zero, drop L3/L4 traffic not matching any `ZEROIO_PORTS` / `ZEROIO_SPLICE` entry in `Proxy` mode.
    pub default_drop_unmatched: u8,
    /// Enable per-source-IP fixed-window rate limiting when non-zero.
    pub rate_limit_enabled: u8,
    /// Enable dedicated SYN packet cap (`rate_max_syn`) when non-zero.
    pub syn_flood_guard: u8,
    /// Number of active XSK queues in `ZEROIO_XSKS` (`0` = use `ctx.rx_queue_index()`).
    pub xsk_queue_count: u32,
    /// Fixed rate-limit window duration in nanoseconds.
    pub rate_window_ns: u64,
    /// Maximum total packets allowed per source IP per window (`0` = unlimited).
    pub rate_max_packets: u64,
    /// Maximum pure-SYN packets allowed per source IP per window (`0` = unlimited).
    pub rate_max_syn: u64,
}

impl Default for XdpRuntimeConfig {
    fn default() -> Self {
        Self {
            mode: XdpInterfaceMode::Protect as u8,
            default_drop_unmatched: 0,
            rate_limit_enabled: 0,
            syn_flood_guard: 0,
            xsk_queue_count: 0,
            rate_window_ns: 1_000_000_000,
            rate_max_packets: 0,
            rate_max_syn: 0,
        }
    }
}

/// IPv4 address key for LPM ACL tries and per-IP rate maps (network byte order).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XdpIpV4 {
    pub addr: [u8; 4],
}

/// IPv6 address key for LPM ACL tries and per-IP rate maps (network byte order).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XdpIpV6 {
    pub addr: [u8; 16],
}

/// ACL rule stored in `ZEROIO_ACL_V4` / `ZEROIO_ACL_V6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpAclRule {
    pub action: u8,
    pub _pad: [u8; 7],
}

/// Per-IP fixed-window rate-limit state stored in eBPF LRU maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpRateBucket {
    pub window_start_ns: u64,
    pub packets: u64,
    pub syn_packets: u64,
}

/// Port-level XDP routing key (`port` in host byte order, `proto` = TCP/UDP).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XdpPortKey {
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// Port-level routing rule stored in `ZEROIO_PORTS`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpPortRule {
    /// [`XDP_PORT_ACTION_PASS`] or [`XDP_PORT_ACTION_REDIRECT_XSK`].
    pub action: u8,
    pub _pad: [u8; 3],
    /// When `>= 0`, redirect to this specific XSK queue index; when `< 0`, steer by RX queue / flow hash.
    pub queue_override: i32,
}

/// Canonical 5-tuple flow key (network byte order IP octets, host byte order ports).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct XdpFlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub is_v6: u8,
    pub _pad: [u8; 2],
}

/// L4 eBPF splice / NAT rewrite entry stored in `ZEROIO_SPLICE`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpSpliceTarget {
    pub new_src_ip: [u8; 16],
    pub new_dst_ip: [u8; 16],
    pub new_src_port: u16,
    pub new_dst_port: u16,
    pub is_v6: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
    pub packets: u64,
    pub bytes: u64,
}

/// Per-CPU XDP verdict counters aggregated in userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpCounters {
    pub packets: u64,
    pub passed: u64,
    pub dropped: u64,
    pub redirected: u64,
    pub parse_errors: u64,
    pub xsk_drops: u64,
    pub rate_limited: u64,
    pub spliced: u64,
    pub acl_dropped: u64,
    pub syn_rate_limited: u64,
}

/// Pack an IPv4 4-byte address into an IPv4-mapped `[u8; 16]` slot (`::ffff:a.b.c.d`).
#[inline]
pub const fn pack_ipv4(ip: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip[0], ip[1], ip[2], ip[3],
    ]
}

/// Incremental RFC 1624 checksum update when replacing a 16-bit big-endian word
/// inside an IPv4/TCP/UDP packet.
///
/// `old_csum` and the returned checksum are in host-endian representation of the
/// big-endian 16-bit header field (`u16::from_be_bytes`). `old_val` and `new_val`
/// are likewise 16-bit header words (`u16::from_be_bytes`).
#[inline]
pub const fn csum_replace_u16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!old_csum) as u32;
    sum += (!old_val) as u32;
    sum += new_val as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Incremental RFC 1624 checksum update when replacing a 32-bit field (such as an IPv4 address).
#[inline]
pub const fn csum_replace_u32(old_csum: u16, old_val: u32, new_val: u32) -> u16 {
    let c1 = csum_replace_u16(old_csum, (old_val >> 16) as u16, (new_val >> 16) as u16);
    csum_replace_u16(c1, (old_val & 0xFFFF) as u16, (new_val & 0xFFFF) as u16)
}

/// Incremental RFC 1624 checksum update when replacing a 128-bit IPv6 address.
#[inline]
pub const fn csum_replace_ipv6(mut csum: u16, old_ip: [u8; 16], new_ip: [u8; 16]) -> u16 {
    let mut i = 0usize;
    while i < 16 {
        let old_w = u16::from_be_bytes([old_ip[i], old_ip[i + 1]]);
        let new_w = u16::from_be_bytes([new_ip[i], new_ip[i + 1]]);
        csum = csum_replace_u16(csum, old_w, new_w);
        i += 2;
    }
    csum
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_rfc1071(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
            i += 2;
        }
        if i < bytes.len() {
            sum += u32::from(u16::from_be_bytes([bytes[i], 0]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn abi_sizes_are_aligned() {
        assert_eq!(core::mem::size_of::<XdpRuntimeConfig>(), 32);
        assert_eq!(core::mem::size_of::<XdpIpV4>(), 4);
        assert_eq!(core::mem::size_of::<XdpIpV6>(), 16);
        assert_eq!(core::mem::size_of::<XdpAclRule>(), 8);
        assert_eq!(core::mem::size_of::<XdpRateBucket>(), 24);
        assert_eq!(core::mem::size_of::<XdpPortKey>(), 4);
        assert_eq!(core::mem::size_of::<XdpPortRule>(), 8);
        assert_eq!(core::mem::size_of::<XdpFlowKey>(), 40);
        assert_eq!(core::mem::size_of::<XdpSpliceTarget>(), 56);
        assert_eq!(core::mem::size_of::<XdpCounters>(), 80);
    }

    #[test]
    fn incremental_checksum_matches_full_recompute() {
        // Minimal 20-byte IPv4 header with src=10.0.0.1, dst=10.0.0.2
        let mut hdr = [
            0x45, 0x00, 0x00, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let c0 = full_rfc1071(&hdr);
        hdr[10..12].copy_from_slice(&c0.to_be_bytes());
        assert_eq!(full_rfc1071(&hdr), 0);

        let old_src = u32::from_be_bytes([10, 0, 0, 1]);
        let new_src = u32::from_be_bytes([192, 0, 2, 99]);
        hdr[12..16].copy_from_slice(&new_src.to_be_bytes());
        let c1 = csum_replace_u32(c0, old_src, new_src);
        hdr[10..12].copy_from_slice(&c1.to_be_bytes());
        assert_eq!(full_rfc1071(&hdr), 0);
    }
}
