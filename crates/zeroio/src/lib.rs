//! Zeroio: open-source, memory-safe Rust network dataplane.
//!
//! This facade crate re-exports [`zeroio_core`] (congestion control,
//! zero-copy packet inspection, sans-I/O TCP/UDP primitives, and deterministic
//! simulator), [`zeroio_dataplane`] (thread-per-core XDP/AF_XDP and kernel
//! policy types), and [`zeroio_xdp_common`] (shared eBPF ABI types).

pub use zeroio_core::*;
pub use zeroio_dataplane as dataplane;
pub use zeroio_xdp_common as xdp_common;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_core_and_dataplane() {
        let cfg = dataplane::InterfaceConfig::protect("eth0");
        assert_eq!(cfg.frame_size, xdp_common::XDP_DEFAULT_FRAME_SIZE);
        let _now = TransportInstant::from_micros(1);
    }
}
