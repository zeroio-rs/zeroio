//! Single-core non-blocking queue event loop uniting [`XskDevice`], [`TcpStack`],
//! [`UdpTable`], [`NeighborTable`], [`Scheduler`], and [`Codel`].

use crate::device::{TxSubmitError, XskDevice};
use crate::neighbor::{NeighborTable, encode_arp_reply_ipv4, parse_arp_ipv4};
use crate::umem::UmemFrameToken;
use core::net::{IpAddr, SocketAddr};
use std::collections::VecDeque;
use std::time::Duration;
use zeroio_core::codel::{Codel, CodelAction, DEFAULT_INTERVAL, DEFAULT_TARGET, Stamp};
use zeroio_core::packet::{IP_PROTO_TCP, IP_PROTO_UDP, PacketView, UdpFrameSpec, encode_udp_frame};
use zeroio_core::sched::{Admit, MAX_BUSY_WAIT_US, Scheduler};
use zeroio_core::{SynCookieKey, TcpConfig, TcpStack, TransportInstant, UdpFlowKey, UdpTable};

const DEFAULT_RX_BATCH_SIZE: usize = 64;
const TX_SCRATCH_BYTES: usize = 2048;
const UDP_SCHED_FLOW_ID: u64 = u64::MAX;

/// Per-queue configuration for a [`QueueReactor`].
#[derive(Clone, Debug)]
pub struct QueueConfig {
    pub queue_id: u32,
    pub local_mac: [u8; 6],
    pub local_ips: Vec<IpAddr>,
    pub tcp: TcpConfig,
    pub cookie_key: SynCookieKey,
    pub max_udp_sessions: usize,
    pub max_neighbors: usize,
    pub rx_batch_size: usize,
    pub rate_bps: Option<u64>,
    pub link_overhead_bytes: u64,
    pub busy_wait_budget_us: u64,
    pub neighbor_ttl: Duration,
    pub udp_idle_ttl: Duration,
}

impl QueueConfig {
    /// Construct a queue configuration with sensible dataplane defaults.
    pub fn new(
        queue_id: u32,
        local_mac: [u8; 6],
        local_ips: Vec<IpAddr>,
        cookie_key: SynCookieKey,
    ) -> Self {
        let tcp = TcpConfig {
            src_mac: local_mac,
            ..TcpConfig::default()
        };
        Self {
            queue_id,
            local_mac,
            local_ips,
            tcp,
            cookie_key,
            max_udp_sessions: 4096,
            max_neighbors: 1024,
            rx_batch_size: DEFAULT_RX_BATCH_SIZE,
            rate_bps: None,
            link_overhead_bytes: 24,
            busy_wait_budget_us: MAX_BUSY_WAIT_US,
            neighbor_ttl: Duration::from_secs(300),
            udp_idle_ttl: Duration::from_secs(60),
        }
    }
}

/// Cumulative packet and error counters recorded by a [`QueueReactor`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub tx_kicks: u64,
    pub tx_drops: u64,
    pub arp_requests: u64,
    pub arp_replies_sent: u64,
    pub tcp_rx: u64,
    pub udp_rx: u64,
    pub udp_tx: u64,
    pub parse_errors: u64,
}

/// Per-iteration counts returned by [`QueueReactor::poll_once`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollOutcome {
    pub rx_frames: usize,
    pub tx_frames: usize,
    pub udp_datagrams: usize,
    pub arp_handled: usize,
    pub reclaimed_completions: usize,
}

/// Single-core non-blocking transport reactor bound to one [`XskDevice`] queue.
pub struct QueueReactor<D: XskDevice> {
    device: D,
    config: QueueConfig,
    tcp: TcpStack,
    udp: UdpTable,
    neighbors: NeighborTable,
    scheduler: Scheduler,
    codel: Codel,
    stats: QueueStats,
    rx_scratch: Vec<UmemFrameToken>,
    tx_scratch: Vec<u8>,
    deferred_tx: VecDeque<UmemFrameToken>,
    last_udp_evict: TransportInstant,
}

impl<D: XskDevice> QueueReactor<D> {
    /// Create a queue reactor owning `device` and pre-allocating all hot-path scratch storage.
    pub fn new(device: D, mut config: QueueConfig) -> Self {
        config.tcp.src_mac = config.local_mac;
        let rx_batch = config.rx_batch_size.max(1);
        let tcp = TcpStack::new(config.tcp.clone(), config.cookie_key);
        let udp = UdpTable::new(config.max_udp_sessions.max(16));
        let neighbors = NeighborTable::new(config.max_neighbors.max(16));
        let scheduler = Scheduler::new(config.rate_bps, config.link_overhead_bytes);
        let codel = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        Self {
            device,
            config,
            tcp,
            udp,
            neighbors,
            scheduler,
            codel,
            stats: QueueStats::default(),
            rx_scratch: Vec::with_capacity(rx_batch),
            tx_scratch: vec![0u8; TX_SCRATCH_BYTES],
            deferred_tx: VecDeque::with_capacity(rx_batch),
            last_udp_evict: TransportInstant::ZERO,
        }
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn tcp(&self) -> &TcpStack {
        &self.tcp
    }

    pub fn tcp_mut(&mut self) -> &mut TcpStack {
        &mut self.tcp
    }

    pub fn udp(&self) -> &UdpTable {
        &self.udp
    }

    pub fn udp_mut(&mut self) -> &mut UdpTable {
        &mut self.udp
    }

    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    pub fn neighbors_mut(&mut self) -> &mut NeighborTable {
        &mut self.neighbors
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler
    }

    pub fn codel(&self) -> &Codel {
        &self.codel
    }

    pub fn stats(&self) -> QueueStats {
        self.stats
    }

    pub fn config(&self) -> &QueueConfig {
        &self.config
    }

    fn owns_ip(&self, ip: IpAddr) -> bool {
        self.config.local_ips.contains(&ip)
    }

    /// Encode and enqueue a UDP datagram onto the queue's TX ring.
    pub fn send_udp(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
        peer_mac: Option<[u8; 6]>,
        vlan_id: Option<u16>,
        payload: &[u8],
        now: TransportInstant,
    ) -> Result<usize, TxSubmitError> {
        let dst_mac = match peer_mac {
            Some(mac) => mac,
            None => self
                .neighbors
                .lookup(&peer.ip(), now, self.config.neighbor_ttl)
                .map(|(mac, _)| mac)
                .ok_or(TxSubmitError::DeviceError(libc_enonet()))?,
        };
        let mut tok = self
            .device
            .alloc_tx_frame()
            .ok_or(TxSubmitError::NoFreeFrames)?;
        let spec = UdpFrameSpec {
            src_mac: self.config.local_mac,
            dst_mac,
            vlan_id,
            src_ip: local.ip(),
            dst_ip: peer.ip(),
            ip_ecn: 0,
            ttl: self.config.tcp.ttl,
            src_port: local.port(),
            dst_port: peer.port(),
            payload,
        };
        let encoded_len = {
            let Some(buf) = self.device.frame_buf_mut(tok.addr) else {
                return Err(TxSubmitError::FrameTooLarge);
            };
            encode_udp_frame(buf, &spec).map_err(|_| TxSubmitError::FrameTooLarge)?
        };
        tok.len = encoded_len as u32;
        if let Admit::Wait(delay) =
            self.scheduler
                .charge(now, UDP_SCHED_FLOW_ID, encoded_len as u64)
        {
            self.scheduler
                .schedule(UDP_SCHED_FLOW_ID, 0, now.saturating_add(delay));
            self.deferred_tx.push_back(tok);
            return Ok(payload.len());
        }
        self.device.submit_tx(tok)?;
        self.stats.tx_frames += 1;
        self.stats.udp_tx += 1;
        let flow = UdpFlowKey::new(local, peer);
        if let Some(handle) = self.udp.get_or_insert(flow, now) {
            self.udp.record_tx(handle, payload.len() as u64, now);
        }
        self.device.kick_tx()?;
        self.stats.tx_kicks += 1;
        Ok(payload.len())
    }

    /// Execute one non-blocking RX -> protocol -> TX cycle without a UDP payload callback.
    pub fn poll_once(&mut self, now: TransportInstant) -> PollOutcome {
        self.poll_once_with(now, &mut |_, _, _| {})
    }

    /// Execute one non-blocking RX -> protocol -> TX cycle, invoking `on_udp` for each valid UDP datagram.
    pub fn poll_once_with(
        &mut self,
        now: TransportInstant,
        on_udp: &mut impl FnMut(UdpFlowKey, &[u8], TransportInstant),
    ) -> PollOutcome {
        let mut outcome = PollOutcome::default();
        let batch_max = self.config.rx_batch_size.max(1);
        outcome.reclaimed_completions = self.device.reclaim_completions(batch_max);

        self.drain_deferred_tx(now, &mut outcome);

        self.rx_scratch.clear();
        let received = self.device.recv_batch(batch_max, &mut self.rx_scratch);
        outcome.rx_frames = received;
        self.stats.rx_frames += received as u64;

        for idx in 0..self.rx_scratch.len() {
            let tok = self.rx_scratch[idx];
            if let Some(frame) = self.device.frame_data(tok) {
                if let Some(arp) = parse_arp_ipv4(frame) {
                    self.neighbors.learn(
                        IpAddr::V4(arp.sender_ip),
                        arp.sender_mac,
                        arp.vlan_id,
                        now,
                    );
                    outcome.arp_handled += 1;
                    if arp.is_request {
                        self.stats.arp_requests += 1;
                        if self.owns_ip(IpAddr::V4(arp.target_ip)) {
                            self.send_arp_reply(arp, &mut outcome);
                        }
                    }
                } else if let Some(view) = PacketView::parse(frame) {
                    self.neighbors
                        .learn(view.src_ip, view.src_mac(), view.vlan_id, now);
                    if view.proto == IP_PROTO_TCP {
                        self.stats.tcp_rx += 1;
                        self.tcp.on_rx(now, &view);
                    } else if view.proto == IP_PROTO_UDP && view.verify_checksums() {
                        let payload = view.payload();
                        let flow = UdpFlowKey::new(view.dst_addr(), view.src_addr());
                        self.stats.udp_rx += 1;
                        outcome.udp_datagrams += 1;
                        if let Some(handle) = self.udp.get_or_insert(flow, now) {
                            self.udp.record_rx(handle, payload.len() as u64, now);
                        }
                        on_udp(flow, payload, now);
                    }
                } else {
                    self.stats.parse_errors += 1;
                }
            }
            self.device.recycle_rx(tok);
        }

        self.tcp.on_timer(now);
        if now.duration_since(self.last_udp_evict) >= Duration::from_secs(1) {
            self.udp.expire_idle(now, self.config.udp_idle_ttl);
            self.last_udp_evict = now;
        }

        self.flush_tcp_tx(now, &mut outcome);
        outcome
    }

    fn drain_deferred_tx(&mut self, now: TransportInstant, outcome: &mut PollOutcome) {
        let mut kicked = false;
        while let Some(tok) = self.deferred_tx.front().copied() {
            let action = self.codel.dequeue(
                now,
                Stamp {
                    enqueued_at: now,
                    ecn: 0,
                },
                self.deferred_tx.len() <= 1,
            );
            if action == CodelAction::Drop {
                self.deferred_tx.pop_front();
                self.stats.tx_drops += 1;
                continue;
            }
            if self.device.submit_tx(tok).is_err() {
                break;
            }
            self.deferred_tx.pop_front();
            outcome.tx_frames += 1;
            self.stats.tx_frames += 1;
            kicked = true;
        }
        if kicked && self.device.kick_tx().is_ok() {
            self.stats.tx_kicks += 1;
        }
    }

    fn send_arp_reply(&mut self, arp: crate::neighbor::ArpIpv4Packet, outcome: &mut PollOutcome) {
        let Some(mut tok) = self.device.alloc_tx_frame() else {
            self.stats.tx_drops += 1;
            return;
        };
        let encoded_len = {
            let Some(buf) = self.device.frame_buf_mut(tok.addr) else {
                return;
            };
            let Some(len) = encode_arp_reply_ipv4(
                buf,
                arp.vlan_id,
                self.config.local_mac,
                arp.target_ip,
                arp.sender_mac,
                arp.sender_ip,
            ) else {
                return;
            };
            len
        };
        tok.len = encoded_len as u32;
        if self.device.submit_tx(tok).is_ok() {
            let _ = self.device.kick_tx();
            self.stats.arp_replies_sent += 1;
            self.stats.tx_frames += 1;
            self.stats.tx_kicks += 1;
            outcome.tx_frames += 1;
        } else {
            self.deferred_tx.push_back(tok);
        }
    }

    fn flush_tcp_tx(&mut self, now: TransportInstant, outcome: &mut PollOutcome) {
        let mut submitted_any = false;
        let device = &mut self.device;
        let scheduler = &mut self.scheduler;
        let stats = &mut self.stats;
        let codel = &mut self.codel;

        self.tcp.poll_tx(now, &mut self.tx_scratch, |wire| {
            let action = codel.dequeue(
                now,
                Stamp {
                    enqueued_at: now,
                    ecn: 0,
                },
                true,
            );
            if action == CodelAction::Drop {
                stats.tx_drops += 1;
                return true;
            }
            if let Admit::Wait(delay) = scheduler.charge(now, UDP_SCHED_FLOW_ID, wire.len() as u64)
            {
                scheduler.schedule(UDP_SCHED_FLOW_ID, 0, now.saturating_add(delay));
                return false;
            }
            let Some(mut tok) = device.alloc_tx_frame() else {
                return false;
            };
            let Some(dst) = device.frame_buf_mut(tok.addr) else {
                return false;
            };
            if wire.len() > dst.len() {
                stats.tx_drops += 1;
                return false;
            }
            dst[..wire.len()].copy_from_slice(wire);
            tok.len = wire.len() as u32;
            match device.submit_tx(tok) {
                Ok(()) => {
                    submitted_any = true;
                    stats.tx_frames += 1;
                    outcome.tx_frames += 1;
                    true
                }
                Err(_) => false,
            }
        });

        if submitted_any && self.device.kick_tx().is_ok() {
            self.stats.tx_kicks += 1;
        }
    }

    /// Compute how long the worker should sleep before the next timer/pacing deadline,
    /// returning `Duration::ZERO` within the configured [`MAX_BUSY_WAIT_US`] spin window.
    pub fn next_sleep_duration(&self, now: TransportInstant, idle_cap: Duration) -> Duration {
        let mut next_due = self.tcp.next_deadline();
        if let Some(sched_due) = self.scheduler.next_due() {
            next_due = Some(next_due.map_or(sched_due, |d| d.min(sched_due)));
        }
        let Some(due) = next_due else {
            return idle_cap;
        };
        let remaining = due.duration_since(now);
        let spin_budget = Duration::from_micros(self.config.busy_wait_budget_us);
        if remaining <= spin_budget {
            Duration::ZERO
        } else {
            (remaining - spin_budget).min(idle_cap)
        }
    }

    /// Execute one reactor step and sleep up to `idle_cap` via `poll_wait` when idle.
    pub fn run_step(&mut self, now: TransportInstant, idle_cap: Duration) -> PollOutcome {
        let outcome = self.poll_once(now);
        if outcome.rx_frames == 0 && outcome.tx_frames == 0 {
            let wait = self.next_sleep_duration(now, idle_cap);
            if !wait.is_zero() {
                self.device.poll_wait(wait);
            }
        }
        outcome
    }
}

const fn libc_enonet() -> i32 {
    101
}
