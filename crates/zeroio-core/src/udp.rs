//! Lightweight UDP session flow key primitives for per-core datagram demuxing.

use core::net::SocketAddr;

/// 4-tuple identifying a bi-directional UDP session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

impl UdpFlowKey {
    pub fn new(local: SocketAddr, peer: SocketAddr) -> Self {
        Self { local, peer }
    }
}
