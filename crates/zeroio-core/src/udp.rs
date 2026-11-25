//! Lightweight UDP session flow key and bounded per-core session table
//! for sans-I/O datagram demultiplexing and idle eviction.

use crate::TransportInstant;
use crate::tcp::{ConnHandle, ConnSlab};
use core::net::SocketAddr;
use std::collections::HashMap;
use std::time::Duration;

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

/// Per-session state tracked for an active UDP flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpSession {
    pub flow: UdpFlowKey,
    pub created_at: TransportInstant,
    pub last_active: TransportInstant,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub peer_mac: Option<[u8; 6]>,
    pub user_tag: u64,
}

/// Bounded O(1)-lookup per-core UDP session table backed by [`ConnSlab`].
pub struct UdpTable {
    slab: ConnSlab<UdpSession>,
    by_flow: HashMap<UdpFlowKey, ConnHandle>,
    max_sessions: usize,
}

impl UdpTable {
    /// Create a UDP session table capped at `max_sessions` concurrent flows.
    pub fn new(max_sessions: usize) -> Self {
        let cap = max_sessions.min(4096);
        Self {
            slab: ConnSlab::with_capacity(cap),
            by_flow: HashMap::with_capacity(cap),
            max_sessions,
        }
    }

    pub fn len(&self) -> usize {
        self.slab.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slab.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.max_sessions
    }

    /// Look up an existing session handle by 4-tuple in O(1) average time.
    pub fn lookup(&self, flow: &UdpFlowKey) -> Option<ConnHandle> {
        self.by_flow.get(flow).copied()
    }

    /// Look up an existing session or allocate a new one if capacity allows.
    pub fn get_or_insert(&mut self, flow: UdpFlowKey, now: TransportInstant) -> Option<ConnHandle> {
        if let Some(&handle) = self.by_flow.get(&flow) {
            return Some(handle);
        }
        if self.slab.len() >= self.max_sessions {
            return None;
        }
        let session = UdpSession {
            flow,
            created_at: now,
            last_active: now,
            rx_packets: 0,
            rx_bytes: 0,
            tx_packets: 0,
            tx_bytes: 0,
            peer_mac: None,
            user_tag: 0,
        };
        let handle = self.slab.try_insert(session)?;
        self.by_flow.insert(flow, handle);
        Some(handle)
    }

    pub fn get(&self, handle: ConnHandle) -> Option<&UdpSession> {
        self.slab.get(handle)
    }

    pub fn get_mut(&mut self, handle: ConnHandle) -> Option<&mut UdpSession> {
        self.slab.get_mut(handle)
    }

    /// Account inbound datagram bytes and refresh `last_active`.
    pub fn record_rx(&mut self, handle: ConnHandle, bytes: u64, now: TransportInstant) -> bool {
        let Some(sess) = self.slab.get_mut(handle) else {
            return false;
        };
        sess.rx_packets = sess.rx_packets.saturating_add(1);
        sess.rx_bytes = sess.rx_bytes.saturating_add(bytes);
        sess.last_active = sess.last_active.max(now);
        true
    }

    /// Account outbound datagram bytes and refresh `last_active`.
    pub fn record_tx(&mut self, handle: ConnHandle, bytes: u64, now: TransportInstant) -> bool {
        let Some(sess) = self.slab.get_mut(handle) else {
            return false;
        };
        sess.tx_packets = sess.tx_packets.saturating_add(1);
        sess.tx_bytes = sess.tx_bytes.saturating_add(bytes);
        sess.last_active = sess.last_active.max(now);
        true
    }

    /// Remove a session explicitly and recycle its slab slot.
    pub fn remove(&mut self, handle: ConnHandle) -> Option<UdpSession> {
        let sess = self.slab.remove(handle)?;
        self.by_flow.remove(&sess.flow);
        Some(sess)
    }

    /// Evict all sessions idle for at least `idle_ttl`, returning how many were removed.
    pub fn expire_idle(&mut self, now: TransportInstant, idle_ttl: Duration) -> usize {
        let mut expired = Vec::new();
        for (&flow, &handle) in &self.by_flow {
            if let Some(sess) = self.slab.get(handle)
                && now.duration_since(sess.last_active) >= idle_ttl
            {
                expired.push((flow, handle));
            }
        }
        let count = expired.len();
        for (flow, handle) in expired {
            self.by_flow.remove(&flow);
            self.slab.remove(handle);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_table_lifecycle_capacity_and_expiry() {
        let f1 = UdpFlowKey::new(
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:1001".parse().unwrap(),
        );
        let f2 = UdpFlowKey::new(
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:1002".parse().unwrap(),
        );
        let f3 = UdpFlowKey::new(
            "10.0.0.1:443".parse().unwrap(),
            "10.0.0.2:1003".parse().unwrap(),
        );

        let mut tbl = UdpTable::new(2);
        let t0 = TransportInstant::from_micros(1_000);
        let h1 = tbl.get_or_insert(f1, t0).unwrap();
        let h2 = tbl.get_or_insert(f2, t0).unwrap();
        assert_eq!(tbl.get_or_insert(f3, t0), None);

        assert!(tbl.record_rx(h1, 1200, TransportInstant::from_micros(5_000)));
        assert!(tbl.record_tx(h1, 600, TransportInstant::from_micros(5_500)));
        let s1 = tbl.get(h1).unwrap();
        assert_eq!(s1.rx_packets, 1);
        assert_eq!(s1.rx_bytes, 1200);
        assert_eq!(s1.tx_bytes, 600);

        // At t = 35_000us with 30ms TTL: f2 (last_active 1_000) expires, f1 (5_500) stays? 35_000 - 5_500 = 29_500 < 30_000.
        let evicted = tbl.expire_idle(
            TransportInstant::from_micros(35_000),
            Duration::from_millis(30),
        );
        assert_eq!(evicted, 1);
        assert_eq!(tbl.get(h2), None);
        assert!(tbl.get(h1).is_some());
        assert_eq!(tbl.lookup(&f2), None);

        // Slot recycled for f3.
        let h3 = tbl
            .get_or_insert(f3, TransportInstant::from_micros(35_000))
            .unwrap();
        assert_ne!(h3, h2);
        assert_eq!(tbl.get(h2), None);
        assert_eq!(tbl.len(), 2);
    }
}
