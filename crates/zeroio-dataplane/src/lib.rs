//! Thread-per-core dataplane runtime, UMEM management, neighbor/ARP state,
//! XSK device abstractions, and Linux AF_XDP + eBPF control.

pub mod clock;
pub mod device;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod neighbor;
pub mod reactor;
pub mod runtime;
pub mod umem;

pub use clock::TransportClock;
pub use device::{LoopbackXskDevice, TxSubmitError, XskDevice};
pub use neighbor::{
    ArpIpv4Packet, ETHERTYPE_ARP, NeighborEntry, NeighborTable, encode_arp_reply_ipv4,
    parse_arp_ipv4,
};
pub use reactor::{PollOutcome, QueueConfig, QueueReactor, QueueStats};
pub use runtime::{ConfigError, DataplaneHandle, DataplaneManager, WorkerPlan};
pub use umem::{DEFAULT_FRAME_HEADROOM, UmemConfig, UmemFrameToken, UmemSlab};
pub use zeroio_core::{PacketView, TransportInstant};
pub use zeroio_xdp_common::{XDP_DEFAULT_FRAME_SIZE, XdpCounters, XdpInterfaceMode};

/// Requested XDP program attach mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum XdpAttachMode {
    /// Prefer driver/native mode, falling back to generic SKB mode if unsupported.
    #[default]
    Auto,
    /// Require driver/native XDP mode.
    Native,
    /// Force generic SKB XDP mode.
    Generic,
}

/// Effective AF_XDP socket bind mode reported by the kernel or test device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XskBindMode {
    /// Hardware DMA zero-copy (`XDP_ZEROCOPY`).
    ZeroCopy,
    /// Kernel-assisted copy mode (`XDP_COPY`).
    Copy,
    /// Kernel socket fallback (no XSK bound for this queue/protocol).
    KernelFallback,
}

/// Per-interface dataplane configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    pub mode: XdpInterfaceMode,
    pub attach_mode: XdpAttachMode,
    pub frame_size: u32,
    pub queues: Vec<u32>,
    pub cpus: Vec<usize>,
    pub prefer_zerocopy: bool,
}

impl InterfaceConfig {
    /// Create a default interface policy in [`XdpInterfaceMode::Protect`].
    pub fn protect(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: XdpInterfaceMode::Protect,
            attach_mode: XdpAttachMode::Auto,
            frame_size: XDP_DEFAULT_FRAME_SIZE,
            queues: vec![0],
            cpus: vec![0],
            prefer_zerocopy: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interface_uses_protect_and_standard_frame_size() {
        let cfg = InterfaceConfig::protect("eth0");
        assert_eq!(cfg.mode, XdpInterfaceMode::Protect);
        assert_eq!(cfg.frame_size, 2048);
        assert!(cfg.prefer_zerocopy);
        assert!(cfg.validate().is_ok());
    }
}
