//! Multi-connection sans-I/O TCP stack coordinator owning [`ConnSlab`],
//! listener ports, stateless SYN cookies, [`TimingWheel`] deadlines, and
//! [`PathTable`] priors.

use crate::TransportInstant;
use crate::edgecc::PathPrior;
use crate::packet::{
    IP_PROTO_TCP, PacketView, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN, TcpFrameSpec, TcpOptions,
    encode_tcp_frame,
};
use crate::path_table::{DEFAULT_CAPACITY, DEFAULT_TTL, PathKey, PathTable};
use crate::sched::{FlowId, TimingWheel};
use crate::tcp::conn::{TcpConfig, TcpConn, TcpConnSnapshot, TcpFourTuple};
use crate::tcp::cookie::{SynCookieKey, generate_syn_cookie, verify_syn_cookie};
use crate::tcp::seq::SeqNum;
use crate::tcp::{ConnHandle, ConnSlab, TcpState};
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

fn handle_to_flow_id(h: ConnHandle) -> FlowId {
    (u64::from(h.index) << 32) | u64::from(h.generation)
}

fn flow_id_to_handle(id: FlowId) -> ConnHandle {
    ConnHandle {
        index: (id >> 32) as u32,
        generation: id as u32,
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
    wheel: TimingWheel,
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
            wheel: TimingWheel::new(),
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
            && let Some(due) = conn.next_deadline()
        {
            let _ = self.wheel.schedule(handle_to_flow_id(handle), due);
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
        self.wheel.advance_to(now);
        let handles: Vec<ConnHandle> = self.by_flow.values().copied().collect();
        for handle in handles {
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
        let mut min_due: Option<TransportInstant> = None;
        for &handle in self.by_flow.values() {
            if let Some(conn) = self.slab.get(handle)
                && let Some(due) = conn.next_deadline()
            {
                min_due = Some(min_due.map_or(due, |m| m.min(due)));
            }
        }
        min_due
    }

    /// Poll all ready outbound frames (stateless replies + scheduled connection segments).
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

        // Drain due timing-wheel slots first, then ensure all active connections with
        // immediate work are polled cleanly.
        while let Some(fid) = self.wheel.pop_due(now, &mut |_id, _gen| true) {
            let h = flow_id_to_handle(fid);
            if let Some(conn) = self.slab.get_mut(h) {
                conn.poll_tx(now, tx_buf, &mut emit);
            }
        }

        let handles: Vec<ConnHandle> = self.by_flow.values().copied().collect();
        for handle in handles {
            if let Some(conn) = self.slab.get_mut(handle)
                && conn.next_deadline().is_some_and(|d| d <= now)
            {
                conn.poll_tx(now, tx_buf, &mut emit);
            }
            self.reclaim_closed(handle, now);
            self.schedule_conn(handle);
        }
    }
}
