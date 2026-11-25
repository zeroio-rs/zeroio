//! Thread-per-core dataplane abstractions and XDP/kernel transport policy.

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

/// Effective AF_XDP socket bind mode reported by the kernel.
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
    /// Construct a default `Protect`-mode interface configuration with standard
    /// 2048-byte UMEM frames.
    pub fn protect(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: XdpInterfaceMode::Protect,
            attach_mode: XdpAttachMode::Auto,
            frame_size: XDP_DEFAULT_FRAME_SIZE,
            queues: Vec::new(),
            cpus: Vec::new(),
            prefer_zerocopy: true,
        }
    }
}

/// Ownership token for one UMEM frame slot inside a per-queue dataplane loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UmemFrameToken {
    pub queue: u32,
    pub addr: u64,
    pub len: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interface_uses_protect_and_standard_frame_size() {
        let cfg = InterfaceConfig::protect("eth0");
        assert_eq!(cfg.name, "eth0");
        assert_eq!(cfg.mode, XdpInterfaceMode::Protect);
        assert_eq!(cfg.frame_size, XDP_DEFAULT_FRAME_SIZE);
        assert!(cfg.prefer_zerocopy);
    }
}
