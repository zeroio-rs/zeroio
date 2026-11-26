//! Multi-connection sans-I/O TCP stack coordinator owning [`ConnSlab`],
//! listener ports, stateless SYN cookies, indexed min-heap deadlines, and
//! [`PathTable`] priors.

use crate::TransportInstant;
use crate::edgecc::PathPrior;
use crate::packet::{
    IP_PROTO_TCP, PacketView, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFrameSpec, TcpOptions,
    encode_tcp_frame,
};
use crate::path_table::{DEFAULT_CAPACITY, DEFAULT_TTL, PathKey, PathTable};
use crate::tcp::conn::{TcpConfig, TcpConn, TcpConnSnapshot, TcpFourTuple};
use crate::tcp::cookie::{SynCookieKey, generate_syn_cookie, verify_syn_cookie};
use crate::tcp::seq::SeqNum;
use crate::tcp::{ConnHandle, ConnSlab, TcpState};
use core::cmp::Ordering;
use core::net::{IpAddr, SocketAddr};
use std::collections::{HashMap, HashSet, VecDeque};

/// Errors returned by [`TcpStack`] control operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpError {
    /// Connection table reached `max_connections`.
    CapacityReached,
    /// Connection handle is invalid or already closed.
    UnknownConnection,
    /// Port is already registered in the listener table.
    PortAlreadyListening,
    /// Operation is invalid in the current TCP state.
    InvalidState,
    /// Local and peer IP address families do not match.
    AddressFamilyMismatch,
}

#[derive(Clone, Copy, Debug)]
struct StatelessReply {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_id: Option<u16>,
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    ttl: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SchedEntry {
    at: TransportInstant,
    order: u64,
    handle: ConnHandle,
}

impl Ord for SchedEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.at
            .cmp(&other.at)
            .then_with(|| self.order.cmp(&other.order))
    }
}

impl PartialOrd for SchedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Indexed min-heap storing at most one cancellable deadline per active `ConnSlab` slot.
#[derive(Default)]
struct ConnSchedule {
    heap: Vec<SchedEntry>,
    slots: Vec<Option<usize>>,
    next_order: u64,
}

impl ConnSchedule {
    fn swap_nodes(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        self.slots[self.heap[a].handle.index as usize] = Some(a);
        self.slots[self.heap[b].handle.index as usize] = Some(b);
    }

    fn sift_up(&mut self, mut idx: usize) {
        while idx > 0 {
            let parent = (idx - 1) / 2;
            if self.heap[idx] < self.heap[parent] {
                self.swap_nodes(idx, parent);
                idx = parent;
            } else {
                break;
            }
        }
    }

    fn sift_down(&mut self, mut idx: usize) {
        let len = self.heap.len();
        loop {
            let left = idx * 2 + 1;
            if left >= len {
                break;
            }
            let right = left + 1;
            let best = if right < len && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[best] < self.heap[idx] {
                self.swap_nodes(idx, best);
                idx = best;
            } else {
                break;
            }
        }
    }

    fn remove_at(&mut self, idx: usize) -> SchedEntry {
        let last = self.heap.len() - 1;
        if idx != last {
            self.swap_nodes(idx, last);
        }
        let popped = self.heap.pop().unwrap();
        self.slots[popped.handle.index as usize] = None;
        if idx < self.heap.len() {
            self.sift_up(idx);
            self.sift_down(idx);
        }
        popped
    }

    fn set(&mut self, handle: ConnHandle, at: TransportInstant) {
        let slot = handle.index as usize;
        if slot >= self.slots.len() {
            self.slots.resize(slot + 1, None);
        }
        if let Some(idx) = self.slots[slot]
            && self.heap[idx].handle == handle
            && self.heap[idx].at == at
        {
            return;
        }
        self.next_order = self.next_order.wrapping_add(1);
        let entry = SchedEntry {
            at,
            order: self.next_order,
            handle,
        };
        if let Some(idx) = self.slots[slot] {
            let prev = core::mem::replace(&mut self.heap[idx], entry);
            if entry < prev {
                self.sift_up(idx);
            } else {
                self.sift_down(idx);
            }
        } else {
            let idx = self.heap.len();
            self.heap.push(entry);
            self.slots[slot] = Some(idx);
            self.sift_up(idx);
        }
    }

    fn remove(&mut self, handle: ConnHandle) {
        let slot = handle.index as usize;
        let Some(&Some(idx)) = self.slots.get(slot) else {
            return;
        };
        if self.heap[idx].handle != handle {
            return;
        }
        let _ = self.remove_at(idx);
    }

    fn peek_deadline(&self) -> Option<TransportInstant> {
        self.heap.first().map(|e| e.at)
    }

    fn pop_due(&mut self, now: TransportInstant) -> Option<ConnHandle> {
        if self.heap.first().is_some_and(|e| e.at <= now) {
            Some(self.remove_at(0).handle)
        } else {
            None
        }
    }
}

fn path_key_for(local: IpAddr, peer: IpAddr) -> PathKey {
    let prefix_len = match peer {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 64,
    };
    PathKey {
        egress_ifindex: 0,
        local_ip: local,
        dst_prefix: peer,
        prefix_len,
    }
}

/// Sans-I/O multi-connection TCP stack.
pub struct TcpStack {
    config: TcpConfig,
    slab: ConnSlab<TcpConn>,
    by_flow: HashMap<TcpFourTuple, ConnHandle>,
    listeners: HashSet<u16>,
    schedule: ConnSchedule,
    due_scratch: Vec<ConnHandle>,
    path_table: PathTable,
    cookie_key: SynCookieKey,
    isn_counter: u32,
    accepted_queue: VecDeque<ConnHandle>,
    stateless_replies: VecDeque<StatelessReply>,
}

impl TcpStack {
    /// Create a new sans-I/O TCP stack with the given configuration and SYN-cookie key.
    pub fn new(config: TcpConfig, cookie_key: SynCookieKey) -> Self {
        let initial_cap = config.max_connections.min(1024);
        Self {
            slab: ConnSlab::with_capacity(initial_cap),
            by_flow: HashMap::with_capacity(initial_cap),
            listeners: HashSet::new(),
            schedule: ConnSchedule::default(),
            due_scratch: Vec::with_capacity(64),
            path_table: PathTable::new(DEFAULT_CAPACITY, DEFAULT_TTL),
            cookie_key,
            isn_counter: 0x1020_3040,
            accepted_queue: VecDeque::with_capacity(32),
            stateless_replies: VecDeque::with_capacity(32),
            config,
        }
    }

    pub fn config(&self) -> &TcpConfig {
        &self.config
    }

    pub fn active_connections(&self) -> usize {
        self.slab.len()
    }

    pub fn path_table(&self) -> &PathTable {
        &self.path_table
    }

    pub fn path_table_mut(&mut self) -> &mut PathTable {
        &mut self.path_table
    }

    /// Start listening for inbound SYNs on `port`.
    pub fn listen(&mut self, port: u16) -> Result<(), TcpError> {
        if !self.listeners.insert(port) {
            return Err(TcpError::PortAlreadyListening);
        }
        Ok(())
    }

    /// Stop listening on `port` (existing established connections remain open).
    pub fn unlisten(&mut self, port: u16) {
        self.listeners.remove(&port);
    }

    fn next_isn(&mut self, flow: &TcpFourTuple, now: TransportInstant) -> SeqNum {
        self.isn_counter = self.isn_counter.wrapping_add(64_000);
        let mix = (now.micros() as u32)
            ^ u32::from(flow.local.port()).rotate_left(16)
            ^ u32::from(flow.peer.port());
        SeqNum(self.isn_counter.wrapping_add(mix))
    }

    fn lookup_prior(
        &mut self,
        local: IpAddr,
        peer: IpAddr,
        now: TransportInstant,
    ) -> Option<PathPrior> {
        let key = path_key_for(local, peer);
        self.path_table.lookup(&key, now)
    }

    fn schedule_conn(&mut self, handle: ConnHandle) {
        if let Some(conn) = self.slab.get(handle)
            && conn.state != TcpState::Closed
            && let Some(due) = conn.next_deadline()
        {
            self.schedule.set(handle, due);
        } else {
            self.schedule.remove(handle);
        }
    }

    fn reclaim_closed(&mut self, handle: ConnHandle, now: TransportInstant) {
        let should_reclaim = self
            .slab
            .get(handle)
            .is_some_and(|c| c.state == TcpState::Closed);
        if !should_reclaim {
            return;
        }
        self.schedule.remove(handle);
        if let Some(conn) = self.slab.remove(handle) {
            self.by_flow.remove(&conn.flow);
            let key = path_key_for(conn.flow.local.ip(), conn.flow.peer.ip());
            self.path_table.record(key, conn.path_sample(), now);
        }
    }

    /// Initiate an active outbound connection (`SynSent`).
    pub fn connect(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
        peer_mac: [u8; 6],
        now: TransportInstant,
    ) -> Result<ConnHandle, TcpError> {
        if local.is_ipv4() != peer.is_ipv4() {
            return Err(TcpError::AddressFamilyMismatch);
        }
        if self.slab.len() >= self.config.max_connections {
            return Err(TcpError::CapacityReached);
        }
        let flow = TcpFourTuple::new(local, peer);
        if self.by_flow.contains_key(&flow) {
            return Err(TcpError::InvalidState);
        }
        let iss = self.next_isn(&flow, now);
        let prior = self.lookup_prior(local.ip(), peer.ip(), now);
        let conn = TcpConn::new_active(flow, peer_mac, iss, now, &self.config, prior);
        let handle = self
            .slab
            .try_insert(conn)
            .ok_or(TcpError::CapacityReached)?;
        self.by_flow.insert(flow, handle);
        self.schedule_conn(handle);
        Ok(handle)
    }

    /// Pop the next newly established passive connection.
    pub fn accept(&mut self) -> Option<ConnHandle> {
        while let Some(h) = self.accepted_queue.pop_front() {
            if self.slab.get(h).is_some() {
                return Some(h);
            }
        }
        None
    }

    /// Queue outbound application bytes on a connection.
    pub fn send(&mut self, handle: ConnHandle, data: &[u8]) -> Result<usize, TcpError> {
        let conn = self
            .slab
            .get_mut(handle)
            .ok_or(TcpError::UnknownConnection)?;
        let n = conn.send(data);
        self.schedule_conn(handle);
        Ok(n)
    }

    /// Read received contiguous payload bytes from a connection.
    pub fn recv(&mut self, handle: ConnHandle, dst: &mut [u8]) -> Result<usize, TcpError> {
        let conn = self
            .slab
            .get_mut(handle)
            .ok_or(TcpError::UnknownConnection)?;
        let n = conn.recv(dst);
        if n > 0 {
            self.schedule_conn(handle);
        }
        Ok(n)
    }

    /// Borrow unread contiguous receive slices without copying.
    pub fn peek_rx(&self, handle: ConnHandle) -> Result<(&[u8], &[u8]), TcpError> {
        let conn = self.slab.get(handle).ok_or(TcpError::UnknownConnection)?;
        Ok(conn.peek_rx())
    }

    /// Consume `n` bytes previously inspected via [`TcpStack::peek_rx`].
    pub fn consume_rx(&mut self, handle: ConnHandle, n: usize) -> Result<usize, TcpError> {
        let conn = self
            .slab
            .get_mut(handle)
            .ok_or(TcpError::UnknownConnection)?;
        let taken = conn.consume_rx(n);
        if taken > 0 {
            self.schedule_conn(handle);
        }
        Ok(taken)
    }

    /// Initiate graceful connection close (`FIN`).
    pub fn close(&mut self, handle: ConnHandle) -> Result<(), TcpError> {
        let conn = self
            .slab
            .get_mut(handle)
            .ok_or(TcpError::UnknownConnection)?;
        conn.close();
        self.schedule_conn(handle);
        Ok(())
    }

    /// Abort a connection immediately (`RST`).
    pub fn abort(&mut self, handle: ConnHandle) -> Result<(), TcpError> {
        let conn = self
            .slab
            .get_mut(handle)
            .ok_or(TcpError::UnknownConnection)?;
        conn.abort();
        self.schedule_conn(handle);
        Ok(())
    }

    pub fn snapshot(&self, handle: ConnHandle) -> Option<TcpConnSnapshot> {
        self.slab.get(handle).map(TcpConn::snapshot)
    }

    /// Process one parsed inbound Ethernet/IP/TCP frame.
    ///
    /// Malformed or checksum-invalid packets fail closed and are ignored.
    pub fn on_rx(&mut self, now: TransportInstant, view: &PacketView<'_>) {
        if view.proto != IP_PROTO_TCP || !view.verify_checksums() {
            return;
        }
        let Some(th) = view.tcp_header() else {
            return;
        };
        let flow = TcpFourTuple::new(view.dst_addr(), view.src_addr());

        if let Some(&handle) = self.by_flow.get(&flow) {
            if let Some(conn) = self.slab.get_mut(handle) {
                let was_passive_syn = conn.state == TcpState::SynReceived;
                conn.on_rx(now, view, &th);
                if was_passive_syn && conn.take_newly_established() {
                    self.accepted_queue.push_back(handle);
                }
            }
            if self
                .slab
                .get(handle)
                .is_some_and(|c| c.state == TcpState::Closed)
            {
                self.reclaim_closed(handle, now);
            } else {
                self.schedule_conn(handle);
            }
            return;
        }

        // No existing connection for this 4-tuple.
        if (th.flags & TCP_FLAG_RST) != 0 {
            return;
        }

        let listening = self.listeners.contains(&view.dst_port);
        if listening && (th.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN {
            if self.config.syn_cookies {
                let peer_mss = th
                    .parse_options()
                    .and_then(|o| o.mss)
                    .unwrap_or(1460)
                    .min(self.config.mss);
                let (cookie_isn, _tier_mss) = generate_syn_cookie(
                    self.cookie_key,
                    flow.local,
                    flow.peer,
                    th.seq,
                    peer_mss,
                    now,
                );
                self.stateless_replies.push_back(StatelessReply {
                    src_mac: self.config.src_mac,
                    dst_mac: view.src_mac(),
                    vlan_id: view.vlan_id,
                    src: flow.local,
                    dst: flow.peer,
                    seq: cookie_isn,
                    ack: th.seq.wrapping_add(1),
                    flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                    window: u16::MAX,
                    mss: Some(peer_mss),
                    ttl: self.config.ttl,
                });
                return;
            }
            if self.slab.len() >= self.config.max_connections {
                return;
            }
            let iss = self.next_isn(&flow, now);
            let prior = self.lookup_prior(flow.local.ip(), flow.peer.ip(), now);
            let conn =
                TcpConn::new_passive(flow, view.src_mac(), iss, &th, now, &self.config, prior);
            if let Some(handle) = self.slab.try_insert(conn) {
                self.by_flow.insert(flow, handle);
                self.schedule_conn(handle);
            }
            return;
        }

        // Stateless SYN-cookie 3rd ACK validation.
        if listening
            && self.config.syn_cookies
            && (th.flags & TCP_FLAG_ACK) != 0
            && (th.flags & TCP_FLAG_SYN) == 0
            && let Some(cookie_mss) =
                verify_syn_cookie(self.cookie_key, flow.local, flow.peer, th.seq, th.ack, now)
            && self.slab.len() < self.config.max_connections
        {
            let prior = self.lookup_prior(flow.local.ip(), flow.peer.ip(), now);
            let mut conn = TcpConn::new_from_cookie(
                flow,
                view.src_mac(),
                &th,
                cookie_mss,
                now,
                &self.config,
                prior,
            );
            conn.on_rx(now, view, &th);
            let _ = conn.take_newly_established();
            if let Some(handle) = self.slab.try_insert(conn) {
                self.by_flow.insert(flow, handle);
                self.accepted_queue.push_back(handle);
                self.schedule_conn(handle);
            }
            return;
        }

        // Unmatched non-SYN packet -> stateless RST (RFC 9293 §3.10.7.1).
        let (seq, ack, flags) = if (th.flags & TCP_FLAG_ACK) != 0 {
            (th.ack, 0, TCP_FLAG_RST)
        } else {
            let seg_len = view.payload().len() as u32 + u32::from((th.flags & TCP_FLAG_SYN) != 0);
            (0, th.seq.wrapping_add(seg_len), TCP_FLAG_RST | TCP_FLAG_ACK)
        };
        self.stateless_replies.push_back(StatelessReply {
            src_mac: self.config.src_mac,
            dst_mac: view.src_mac(),
            vlan_id: view.vlan_id,
            src: flow.local,
            dst: flow.peer,
            seq,
            ack,
            flags,
            window: 0,
            mss: None,
            ttl: self.config.ttl,
        });
    }

    /// Advance all due connection timers (RTO, delayed ACK, TIME_WAIT cleanup).
    pub fn on_timer(&mut self, now: TransportInstant) {
        self.due_scratch.clear();
        while let Some(handle) = self.schedule.pop_due(now) {
            self.due_scratch.push(handle);
        }
        for i in 0..self.due_scratch.len() {
            let handle = self.due_scratch[i];
            if let Some(conn) = self.slab.get_mut(handle) {
                conn.on_timer(now);
            }
            self.reclaim_closed(handle, now);
            self.schedule_conn(handle);
        }
    }

    /// Earliest upcoming deadline across all active connections, if any.
    pub fn next_deadline(&self) -> Option<TransportInstant> {
        if !self.stateless_replies.is_empty() {
            return Some(TransportInstant::ZERO);
        }
        self.schedule.peek_deadline()
    }

    /// Poll all ready outbound frames (stateless replies + due connection segments).
    pub fn poll_tx(
        &mut self,
        now: TransportInstant,
        tx_buf: &mut [u8],
        mut emit: impl FnMut(&[u8]) -> bool,
    ) {
        while let Some(reply) = self.stateless_replies.front().copied() {
            let opts = TcpOptions {
                mss: reply.mss,
                ..TcpOptions::default()
            };
            let spec = TcpFrameSpec {
                src_mac: reply.src_mac,
                dst_mac: reply.dst_mac,
                vlan_id: reply.vlan_id,
                src_ip: reply.src.ip(),
                dst_ip: reply.dst.ip(),
                ip_ecn: 0,
                ttl: reply.ttl,
                src_port: reply.src.port(),
                dst_port: reply.dst.port(),
                seq: reply.seq,
                ack: reply.ack,
                flags: reply.flags,
                ae: false,
                window: reply.window,
                options: opts,
                payload: &[],
            };
            let Ok(len) = encode_tcp_frame(tx_buf, &spec) else {
                self.stateless_replies.pop_front();
                continue;
            };
            if !emit(&tx_buf[..len]) {
                return;
            }
            self.stateless_replies.pop_front();
        }

        self.due_scratch.clear();
        while let Some(handle) = self.schedule.pop_due(now) {
            self.due_scratch.push(handle);
        }

        let mut stopped = false;
        let len = self.due_scratch.len();
        for i in 0..len {
            let handle = self.due_scratch[i];
            if !stopped && let Some(conn) = self.slab.get_mut(handle) {
                conn.poll_tx(now, tx_buf, &mut |wire| {
                    if emit(wire) {
                        true
                    } else {
                        stopped = true;
                        false
                    }
                });
            }
            self.reclaim_closed(handle, now);
            self.schedule_conn(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_schedule_updates_in_place_and_ignores_stale_generation() {
        let mut sched = ConnSchedule::default();
        let old = ConnHandle {
            index: 3,
            generation: 1,
        };
        let fresh = ConnHandle {
            index: 3,
            generation: 2,
        };
        let other = ConnHandle {
            index: 7,
            generation: 1,
        };

        sched.set(other, TransportInstant::from_micros(500));
        sched.set(old, TransportInstant::from_micros(900));
        sched.remove(old);
        sched.set(fresh, TransportInstant::from_micros(200));
        // Updating the same slot must not grow heap.
        for t in 100..200 {
            sched.set(fresh, TransportInstant::from_micros(t));
        }
        assert_eq!(sched.heap.len(), 2);
        // Stale handle cannot cancel `fresh`.
        sched.remove(old);
        assert_eq!(
            sched.peek_deadline(),
            Some(TransportInstant::from_micros(199))
        );
        assert_eq!(
            sched.pop_due(TransportInstant::from_micros(199)),
            Some(fresh)
        );
        assert_eq!(sched.pop_due(TransportInstant::from_micros(499)), None);
        assert_eq!(
            sched.pop_due(TransportInstant::from_micros(500)),
            Some(other)
        );
        assert_eq!(sched.peek_deadline(), None);
    }
}
