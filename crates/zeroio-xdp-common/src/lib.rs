#![cfg_attr(not(feature = "std"), no_std)]

//! Shared `#[repr(C)]` ABI types for Zeroio XDP eBPF maps, counters, and
//! userspace dataplane control.

/// Default UMEM frame size for standard-MTU AF_XDP queues.
pub const XDP_DEFAULT_FRAME_SIZE: u32 = 2048;

/// IP protocol number constants shared across eBPF and userspace parsers.
pub const XDP_PROTO_TCP: u8 = 6;
pub const XDP_PROTO_UDP: u8 = 17;

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

/// Per-IP fixed-window rate-limit state stored in eBPF maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XdpRateBucket {
    pub window_start_ns: u64,
    pub packets: u64,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_sizes_are_aligned() {
        assert_eq!(core::mem::size_of::<XdpFlowKey>(), 40);
        assert_eq!(core::mem::size_of::<XdpRateBucket>(), 16);
        assert_eq!(core::mem::size_of::<XdpCounters>(), 56);
    }
}
