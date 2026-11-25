//! Per-connection sans-I/O TCP state machine integrating [`EdgeCc`],
//! [`AccEcn`], [`RateSampler`], [`RttState`], SACK, Timestamps/PAWS, and
//! zero-copy frame emission.

use crate::TransportInstant;
use crate::accecn::{AccEcn, EcnMode, Flags as AccEcnFlags};
use crate::cc::reference::{Bbr3Ref, CubicRef, NewRenoRef};
use crate::cc::{CcSnapshot, CongestionController};
use crate::edgecc::{EdgeCc, PathPrior, Tier};
use crate::packet::{
    PacketView, TCP_FLAG_ACK, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN, TcpFrameSpec, TcpHeaderView, TcpOptions, encode_tcp_frame_parts,
};
use crate::path_table::PathSample;
use crate::rate_sample::RateSampler;
use crate::rtt::RttState;
use crate::tcp::TcpState;
use crate::tcp::buffer::{RxBuffer, TxQueue};
use crate::tcp::seq::SeqNum;
use core::net::{IpAddr, SocketAddr};
use std::time::Duration;

const MAX_RTO_RETRIES: u32 = 8;
const MAX_SYN_RETRIES: u32 = 5;
const SYN_RTO: Duration = Duration::from_secs(1);

/// 4-tuple identifying a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpFourTuple {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

impl TcpFourTuple {
    pub fn new(local: SocketAddr, peer: SocketAddr) -> Self {
        Self { local, peer }
    }
}

/// Congestion controller selection for a [`crate::tcp::TcpStack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CcKind {
    EdgeCc { tier: Tier, trusted_ecn: bool },
    CubicRef,
    Bbr3Ref,
    NewRenoRef,
}

impl Default for CcKind {
    fn default() -> Self {
        Self::EdgeCc {
            tier: Tier::T2,
            trusted_ecn: false,
        }
    }
}

/// Stack-wide configuration for [`crate::tcp::TcpStack`].
#[derive(Clone, Debug)]
pub struct TcpConfig {
    pub mss: u16,
    pub rx_buf_size: usize,
    pub tx_buf_size: usize,
    pub max_connections: usize,
    pub enable_ecn: bool,
    pub active_ecn: bool,
    pub enable_timestamps: bool,
    pub enable_sack: bool,
    pub syn_cookies: bool,
    pub delayed_ack_delay: Duration,
    pub time_wait_duration: Duration,
    pub cc_kind: CcKind,
    pub src_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub ttl: u8,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            mss: 1460,
            rx_buf_size: 256 * 1024,
            tx_buf_size: 256 * 1024,
            max_connections: 65_536,
            enable_ecn: true,
            active_ecn: true,
            enable_timestamps: true,
            enable_sack: true,
            syn_cookies: false,
            delayed_ack_delay: Duration::from_millis(40),
            time_wait_duration: Duration::from_secs(4),
            cc_kind: CcKind::default(),
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            vlan_id: None,
            ttl: 64,
        }
    }
}

/// Per-connection observability snapshot.
#[derive(Clone, Debug)]
pub struct TcpConnSnapshot {
    pub state: TcpState,
    pub flow: TcpFourTuple,
    pub cc: CcSnapshot,
    pub rtt: RttState,
    pub ecn_mode: EcnMode,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub retransmits: u64,
    pub in_flight: u64,
    pub rx_available: usize,
    pub tx_queued: usize,
}

fn build_controller(
    kind: CcKind,
    mss: u64,
    prior: Option<PathPrior>,
) -> Box<dyn CongestionController> {
    match kind {
        CcKind::EdgeCc { tier, trusted_ecn } => {
            Box::new(EdgeCc::new(mss, tier, prior, trusted_ecn))
        }
        CcKind::CubicRef => Box::new(CubicRef::new(mss)),
        CcKind::Bbr3Ref => Box::new(Bbr3Ref::new(mss)),
        CcKind::NewRenoRef => Box::new(NewRenoRef::new(mss)),
    }
}

fn compute_wscale(buf_size: usize) -> u8 {
    let mut shift = 0u8;
    while shift < 14 && (usize::from(u16::MAX) << shift) < buf_size {
        shift += 1;
    }
    shift
}

fn default_mss_for(local: IpAddr, cfg_mss: u16) -> u16 {
    let family_cap = match local {
        IpAddr::V4(_) => 1460,
        IpAddr::V6(_) => 1440,
    };
    cfg_mss.min(family_cap).max(536)
}

#[inline]
fn ts_val_from(now: TransportInstant) -> u32 {
    // 1 ms TCP timestamp clock.
    (now.micros() / 1_000) as u32
}

#[inline]
fn pacing_gap_for(wire_bytes: usize, pacing_bps: Option<u64>) -> Duration {
    match pacing_bps {
        Some(bps) if bps > 0 => {
            let us = ((u128::from(wire_bytes as u64) * 1_000_000) / u128::from(bps)).min(1_000_000)
                as u64;
            Duration::from_micros(us)
        }
        _ => Duration::ZERO,
    }
}

/// Sans-I/O TCP connection state machine.
pub struct TcpConn {
    pub state: TcpState,
    pub flow: TcpFourTuple,
    pub src_mac: [u8; 6],
    pub peer_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub ttl: u8,

    iss: SeqNum,
    irs: SeqNum,
    effective_mss: u16,
    snd_wscale: u8,
    rcv_wscale: u8,
    peer_rwnd: u64,
    sack_enabled: bool,
    ts_enabled: bool,
    ts_recent: u32,
    ts_recent_set: bool,
    last_ack_sent: SeqNum,

    acc_ecn: AccEcn,
    cwr_pending: bool,
    rtt: RttState,
    sampler: RateSampler,
    cc: Box<dyn CongestionController>,
    rx: RxBuffer,
    tx: TxQueue,

    handshake_started_at: TransportInstant,
    connect_rtt: Option<Duration>,
    next_pacing_at: Option<TransportInstant>,
    delayed_ack_at: Option<TransportInstant>,
    delayed_ack_delay: Duration,
    rto_deadline: Option<TransportInstant>,
    rto_backoff: u32,
    syn_retries: u32,
    time_wait_at: Option<TransportInstant>,
    time_wait_duration: Duration,

    need_syn: bool,
    need_syn_ack: bool,
    ack_now: bool,
    ack_pending: bool,
    close_requested: bool,
    fin_sent: bool,
    fin_seq: Option<SeqNum>,
    fin_acked: bool,
    need_rst: bool,
    newly_established: bool,

    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub retransmits: u64,
    pub failed: bool,
    pub reorder_events: u64,
    pub delivered_segments: u64,
    last_retx_seq: Option<SeqNum>,
    last_retx_tsecr: Option<u32>,
}

impl TcpConn {
    /// Construct an active-open (`SynSent`) connection.
    pub(crate) fn new_active(
        flow: TcpFourTuple,
        peer_mac: [u8; 6],
        iss: SeqNum,
        now: TransportInstant,
        cfg: &TcpConfig,
        prior: Option<PathPrior>,
    ) -> Self {
        let mss = default_mss_for(flow.local.ip(), cfg.mss);
        let rcv_wscale = compute_wscale(cfg.rx_buf_size);
        let cc = build_controller(cfg.cc_kind, u64::from(mss), prior);
        Self {
            state: TcpState::SynSent,
            flow,
            src_mac: cfg.src_mac,
            peer_mac,
            vlan_id: cfg.vlan_id,
            ttl: cfg.ttl,
            iss,
            irs: SeqNum(0),
            effective_mss: mss,
            snd_wscale: 0,
            rcv_wscale,
            peer_rwnd: u64::from(u16::MAX),
            sack_enabled: cfg.enable_sack,
            ts_enabled: cfg.enable_timestamps,
            ts_recent: 0,
            ts_recent_set: false,
            last_ack_sent: SeqNum(0),
            acc_ecn: AccEcn::new(true, cfg.enable_ecn && cfg.active_ecn),
            cwr_pending: false,
            rtt: RttState::new(),
            sampler: RateSampler::new(),
            cc,
            rx: RxBuffer::new(SeqNum(0), cfg.rx_buf_size),
            tx: TxQueue::new(iss.add(1), cfg.tx_buf_size),
            handshake_started_at: now,
            connect_rtt: None,
            next_pacing_at: None,
            delayed_ack_at: None,
            delayed_ack_delay: cfg.delayed_ack_delay,
            rto_deadline: Some(now + SYN_RTO),
            rto_backoff: 0,
            syn_retries: 0,
            time_wait_at: None,
            time_wait_duration: cfg.time_wait_duration,
            need_syn: true,
            need_syn_ack: false,
            ack_now: false,
            ack_pending: false,
            close_requested: false,
            fin_sent: false,
            fin_seq: None,
            fin_acked: false,
            need_rst: false,
            newly_established: false,
            bytes_rx: 0,
            bytes_tx: 0,
            retransmits: 0,
            failed: false,
            reorder_events: 0,
            delivered_segments: 0,
            last_retx_seq: None,
            last_retx_tsecr: None,
        }
    }

    /// Construct a passive-open connection (`SynReceived`) from an inbound SYN.
    pub(crate) fn new_passive(
        flow: TcpFourTuple,
        peer_mac: [u8; 6],
        iss: SeqNum,
        syn: &TcpHeaderView<'_>,
        now: TransportInstant,
        cfg: &TcpConfig,
        prior: Option<PathPrior>,
    ) -> Self {
        let syn_opts = syn.parse_options().unwrap_or_default();
        let local_mss = default_mss_for(flow.local.ip(), cfg.mss);
        let eff_mss = syn_opts.mss.map(|m| m.clamp(536, local_mss)).unwrap_or(536);
        let (snd_wscale, rcv_wscale) = match syn_opts.window_scale {
            Some(ws) => (ws.min(14), compute_wscale(cfg.rx_buf_size)),
            None => (0, 0),
        };
        let irs = SeqNum(syn.seq);
        let mut acc_ecn = AccEcn::new(false, cfg.enable_ecn);
        let syn_ecn_flags = AccEcnFlags::new(
            syn.ae,
            (syn.flags & TCP_FLAG_CWR) != 0,
            (syn.flags & TCP_FLAG_ECE) != 0,
        );
        let _ = acc_ecn.answer_syn(syn_ecn_flags, false);

        let (ts_recent, ts_recent_set, ts_enabled) =
            match (cfg.enable_timestamps, syn_opts.timestamps) {
                (true, Some((tsval, _))) => (tsval, true, true),
                _ => (0, false, false),
            };
        let cc = build_controller(cfg.cc_kind, u64::from(eff_mss), prior);

        Self {
            state: TcpState::SynReceived,
            flow,
            src_mac: cfg.src_mac,
            peer_mac,
            vlan_id: cfg.vlan_id,
            ttl: cfg.ttl,
            iss,
            irs,
            effective_mss: eff_mss,
            snd_wscale,
            rcv_wscale,
            peer_rwnd: u64::from(syn.window) << snd_wscale,
            sack_enabled: cfg.enable_sack && syn_opts.sack_permitted,
            ts_enabled,
            ts_recent,
            ts_recent_set,
            last_ack_sent: irs.add(1),
            acc_ecn,
            cwr_pending: false,
            rtt: RttState::new(),
            sampler: RateSampler::new(),
            cc,
            rx: RxBuffer::new(irs.add(1), cfg.rx_buf_size),
            tx: TxQueue::new(iss.add(1), cfg.tx_buf_size),
            handshake_started_at: now,
            connect_rtt: None,
            next_pacing_at: None,
            delayed_ack_at: None,
            delayed_ack_delay: cfg.delayed_ack_delay,
            rto_deadline: Some(now + SYN_RTO),
            rto_backoff: 0,
            syn_retries: 0,
            time_wait_at: None,
            time_wait_duration: cfg.time_wait_duration,
            need_syn: false,
            need_syn_ack: true,
            ack_now: false,
            ack_pending: false,
            close_requested: false,
            fin_sent: false,
            fin_seq: None,
            fin_acked: false,
            need_rst: false,
            newly_established: false,
            bytes_rx: 0,
            bytes_tx: 0,
            retransmits: 0,
            failed: false,
            reorder_events: 0,
            delivered_segments: 0,
            last_retx_seq: None,
            last_retx_tsecr: None,
        }
    }

    /// Construct an `Established` connection directly from a verified SYN cookie.
    pub(crate) fn new_from_cookie(
        flow: TcpFourTuple,
        peer_mac: [u8; 6],
        ack_hdr: &TcpHeaderView<'_>,
        cookie_mss: u16,
        now: TransportInstant,
        cfg: &TcpConfig,
        prior: Option<PathPrior>,
    ) -> Self {
        let ack_opts = ack_hdr.parse_options().unwrap_or_default();
        let local_mss = default_mss_for(flow.local.ip(), cfg.mss);
        let eff_mss = cookie_mss.min(local_mss).max(536);
        let iss = SeqNum(ack_hdr.ack.wrapping_sub(1));
        let irs = SeqNum(ack_hdr.seq.wrapping_sub(1));
        let ts_enabled = cfg.enable_timestamps && ack_opts.timestamps.is_some();
        let ts_recent = ack_opts.timestamps.map(|(v, _)| v).unwrap_or(0);
        let cc = build_controller(cfg.cc_kind, u64::from(eff_mss), prior);

        Self {
            state: TcpState::Established,
            flow,
            src_mac: cfg.src_mac,
            peer_mac,
            vlan_id: cfg.vlan_id,
            ttl: cfg.ttl,
            iss,
            irs,
            effective_mss: eff_mss,
            snd_wscale: 0,
            rcv_wscale: 0,
            peer_rwnd: u64::from(ack_hdr.window),
            sack_enabled: false,
            ts_enabled,
            ts_recent,
            ts_recent_set: ts_enabled,
            last_ack_sent: irs.add(1),
            // SYN cookie paths never negotiate AccECN (D-D3).
            acc_ecn: AccEcn::new(false, false),
            cwr_pending: false,
            rtt: RttState::new(),
            sampler: RateSampler::new(),
            cc,
            rx: RxBuffer::new(irs.add(1), cfg.rx_buf_size),
            tx: TxQueue::new(iss.add(1), cfg.tx_buf_size),
            handshake_started_at: now,
            connect_rtt: None,
            next_pacing_at: None,
            delayed_ack_at: None,
            delayed_ack_delay: cfg.delayed_ack_delay,
            rto_deadline: None,
            rto_backoff: 0,
            syn_retries: 0,
            time_wait_at: None,
            time_wait_duration: cfg.time_wait_duration,
            need_syn: false,
            need_syn_ack: false,
            ack_now: false,
            ack_pending: false,
            close_requested: false,
            fin_sent: false,
            fin_seq: None,
            fin_acked: false,
            need_rst: false,
            newly_established: true,
            bytes_rx: 0,
            bytes_tx: 0,
            retransmits: 0,
            failed: false,
            reorder_events: 0,
            delivered_segments: 0,
            last_retx_seq: None,
            last_retx_tsecr: None,
        }
    }

    pub fn take_newly_established(&mut self) -> bool {
        let v = self.newly_established;
        self.newly_established = false;
        v
    }

    pub fn send(&mut self, data: &[u8]) -> usize {
        if self.close_requested
            || !matches!(
                self.state,
                TcpState::SynSent
                    | TcpState::SynReceived
                    | TcpState::Established
                    | TcpState::CloseWait
            )
        {
            return 0;
        }
        self.tx.push_data(data)
    }

    pub fn recv(&mut self, dst: &mut [u8]) -> usize {
        self.rx.read_into(dst)
    }

    pub fn close(&mut self) {
        if matches!(
            self.state,
            TcpState::Closed | TcpState::TimeWait | TcpState::LastAck | TcpState::Closing
        ) {
            return;
        }
        if matches!(self.state, TcpState::SynSent | TcpState::SynReceived) {
            self.state = TcpState::Closed;
            return;
        }
        self.close_requested = true;
    }

    pub fn abort(&mut self) {
        if self.state != TcpState::Closed {
            self.need_rst = true;
            self.failed = true;
        }
    }

    pub fn snapshot(&self) -> TcpConnSnapshot {
        TcpConnSnapshot {
            state: self.state,
            flow: self.flow,
            cc: self.cc.snapshot(),
            rtt: self.rtt,
            ecn_mode: self.acc_ecn.mode,
            bytes_rx: self.bytes_rx,
            bytes_tx: self.bytes_tx,
            retransmits: self.retransmits,
            in_flight: self.tx.in_flight_bytes(),
            rx_available: self.rx.available(),
            tx_queued: self.tx.queued_bytes(),
        }
    }

    pub fn path_sample(&self) -> PathSample {
        let snap = self.cc.snapshot();
        let bw_bps = snap
            .bandwidth_lo_bps
            .or(snap.bandwidth_hi_bps)
            .or(snap.pacing_rate_bps)
            .unwrap_or(0);
        let reorder = if self.delivered_segments > 0 {
            (self.reorder_events as f64 / self.delivered_segments as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        PathSample {
            bw_bps,
            base_rtt: snap.min_rtt.or(self.rtt.min_rtt).unwrap_or_default(),
            p_rand: snap
                .p_rand_milli
                .map(|m| f64::from(m) / 1000.0)
                .unwrap_or(0.0),
            alpha: snap
                .ecn_alpha_milli
                .map(|m| f64::from(m) / 1000.0)
                .unwrap_or(0.0),
            reorder,
            connect_rtt: self.connect_rtt,
            failed: self.failed,
        }
    }

    pub fn next_deadline(&self) -> Option<TransportInstant> {
        let mut earliest: Option<TransportInstant> = None;
        let mut consider = |t: Option<TransportInstant>| {
            if let Some(d) = t {
                earliest = Some(earliest.map_or(d, |e| e.min(d)));
            }
        };
        if self.need_syn || self.need_syn_ack || self.need_rst || self.ack_now {
            return Some(TransportInstant::ZERO);
        }
        if self.tx.has_lost() {
            consider(Some(self.next_pacing_at.unwrap_or(TransportInstant::ZERO)));
        }
        if self.tx.unsent_bytes() > 0 && self.can_send_new_data_window() {
            consider(Some(self.next_pacing_at.unwrap_or(TransportInstant::ZERO)));
        }
        if self.close_requested && self.tx.queued_bytes() == 0 && !self.fin_sent {
            return Some(TransportInstant::ZERO);
        }
        consider(self.delayed_ack_at);
        consider(self.rto_deadline);
        consider(self.time_wait_at);
        earliest
    }

    fn can_send_new_data_window(&self) -> bool {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return false;
        }
        let cwnd = self.cc.cwnd();
        let eff_win = cwnd.min(self.peer_rwnd);
        self.tx.in_flight_bytes() < eff_win
    }

    fn scaled_rx_window(&self) -> u16 {
        let win = self.rx.window_bytes() >> self.rcv_wscale;
        win.min(usize::from(u16::MAX)) as u16
    }

    fn base_options(&self, now: TransportInstant, include_sack: bool) -> TcpOptions {
        let mut opts = TcpOptions::default();
        if self.ts_enabled {
            opts.timestamps = Some((ts_val_from(now), self.ts_recent));
        }
        if include_sack && self.sack_enabled {
            self.rx.write_sack_options(&mut opts);
        }
        opts
    }

    fn ecn_ip_codepoint(&self, has_payload: bool) -> u8 {
        if has_payload && matches!(self.acc_ecn.mode, EcnMode::AccEcn | EcnMode::ClassicEcn) {
            2 // ECT(0)
        } else {
            0
        }
    }

    fn apply_ack_ecn_flags(&self, flags: &mut u8) -> bool {
        match self.acc_ecn.mode {
            EcnMode::AccEcn => {
                let ace = self.acc_ecn.peek_ace();
                if (ace & 0x01) != 0 {
                    *flags |= TCP_FLAG_ECE;
                }
                if (ace & 0x02) != 0 {
                    *flags |= TCP_FLAG_CWR;
                }
                (ace & 0x04) != 0
            }
            EcnMode::ClassicEcn => {
                if self.acc_ecn.ece_echo_pending() {
                    *flags |= TCP_FLAG_ECE;
                }
                if self.cwr_pending {
                    *flags |= TCP_FLAG_CWR;
                }
                false
            }
            EcnMode::NotEct | EcnMode::Pending => false,
        }
    }

    fn on_ack_emitted(&mut self) {
        if self.acc_ecn.mode == EcnMode::AccEcn {
            let _ = self.acc_ecn.make_ack();
        } else if self.acc_ecn.mode == EcnMode::ClassicEcn {
            if self.acc_ecn.ece_echo_pending() {
                let _ = self.acc_ecn.make_ack();
            }
            self.cwr_pending = false;
        }
        self.last_ack_sent = self.rx.rcv_nxt();
        self.ack_now = false;
        self.ack_pending = false;
        self.delayed_ack_at = None;
    }

    /// Process an inbound validated [`PacketView`] with decoded [`TcpHeaderView`].
    pub fn on_rx(&mut self, now: TransportInstant, view: &PacketView<'_>, th: &TcpHeaderView<'_>) {
        if self.state == TcpState::Closed {
            return;
        }
        let Some(opts) = th.parse_options() else {
            return;
        };

        // Handle RST first.
        if (th.flags & TCP_FLAG_RST) != 0 {
            let seq = SeqNum(th.seq);
            let valid_rst = if self.state == TcpState::SynSent {
                (th.flags & TCP_FLAG_ACK) != 0 && SeqNum(th.ack) == self.iss.add(1)
            } else {
                let win_end = self.rx.rcv_nxt().add(self.rx.window_bytes().max(1) as u32);
                seq.in_half_open(self.rx.rcv_nxt(), win_end) || seq == self.rx.rcv_nxt()
            };
            if valid_rst {
                self.state = TcpState::Closed;
                self.failed = true;
                self.rto_deadline = None;
                self.delayed_ack_at = None;
                self.time_wait_at = None;
            }
            return;
        }

        // SynSent state: expect SYN|ACK.
        if self.state == TcpState::SynSent {
            if (th.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)
                && SeqNum(th.ack) == self.iss.add(1)
            {
                self.irs = SeqNum(th.seq);
                self.rx = RxBuffer::new(self.irs.add(1), self.rx.capacity());
                self.last_ack_sent = self.irs.add(1);
                if let Some(peer_mss) = opts.mss {
                    let eff = peer_mss.clamp(536, self.effective_mss);
                    self.effective_mss = eff;
                    self.cc.on_mss_update(u64::from(eff));
                }
                match opts.window_scale {
                    Some(ws) => {
                        self.snd_wscale = ws.min(14);
                    }
                    None => {
                        self.snd_wscale = 0;
                        self.rcv_wscale = 0;
                    }
                }
                self.peer_rwnd = u64::from(th.window) << self.snd_wscale;
                self.sack_enabled = self.sack_enabled && opts.sack_permitted;
                if self.ts_enabled
                    && let Some((tsval, _)) = opts.timestamps
                {
                    self.ts_recent = tsval;
                    self.ts_recent_set = true;
                } else {
                    self.ts_enabled = false;
                }
                let syn_ack_ecn = AccEcnFlags::new(
                    th.ae,
                    (th.flags & TCP_FLAG_CWR) != 0,
                    (th.flags & TCP_FLAG_ECE) != 0,
                );
                self.acc_ecn.on_syn_ack(syn_ack_ecn);

                let hs_rtt = now.duration_since(self.handshake_started_at);
                self.connect_rtt = Some(hs_rtt);
                self.rtt.sample(hs_rtt);

                self.need_syn = false;
                self.rto_deadline = None;
                self.rto_backoff = 0;
                self.state = TcpState::Established;
                self.newly_established = true;
                self.ack_now = true;
            } else if (th.flags & TCP_FLAG_SYN) != 0 && (th.flags & TCP_FLAG_ACK) == 0 {
                // Simultaneous open: transition to SynReceived.
                self.irs = SeqNum(th.seq);
                self.rx = RxBuffer::new(self.irs.add(1), self.rx.capacity());
                self.state = TcpState::SynReceived;
                self.need_syn = false;
                self.need_syn_ack = true;
            }
            return;
        }

        // PAWS check on established/closing states (RFC 7323 §5).
        if self.ts_enabled
            && self.ts_recent_set
            && let Some((tsval, _)) = opts.timestamps
            && (tsval.wrapping_sub(self.ts_recent) as i32) < 0
        {
            self.ack_now = true;
            return;
        }

        // SynReceived -> Established on valid ACK.
        if self.state == TcpState::SynReceived {
            if (th.flags & TCP_FLAG_SYN) != 0 && SeqNum(th.seq) == self.irs {
                // Duplicate SYN -> re-emit SYN-ACK.
                self.need_syn_ack = true;
                return;
            }
            if (th.flags & TCP_FLAG_ACK) == 0 || SeqNum(th.ack) != self.iss.add(1) {
                return;
            }
            let hs_rtt = now.duration_since(self.handshake_started_at);
            self.connect_rtt = Some(hs_rtt);
            self.rtt.sample(hs_rtt);
            self.need_syn_ack = false;
            self.rto_deadline = None;
            self.rto_backoff = 0;
            self.state = TcpState::Established;
            self.newly_established = true;
        }

        // TIME_WAIT: re-ACK incoming FIN or duplicate segments and refresh timer.
        if self.state == TcpState::TimeWait {
            if (th.flags & TCP_FLAG_FIN) != 0 {
                self.ack_now = true;
                self.time_wait_at = Some(now + self.time_wait_duration);
            }
            return;
        }

        // Update timestamp recent value when segment starts at/before last_ack_sent (RFC 7323 §4.3).
        let seg_seq = SeqNum(th.seq);
        if self.ts_enabled
            && let Some((tsval, _)) = opts.timestamps
            && seg_seq.le(self.last_ack_sent)
        {
            self.ts_recent = tsval;
            self.ts_recent_set = true;
        }

        // Update peer advertised receive window.
        if (th.flags & TCP_FLAG_ACK) != 0 {
            self.peer_rwnd = u64::from(th.window) << self.snd_wscale;
        }

        // Process ACK / SACK / ECN feedback.
        if (th.flags & TCP_FLAG_ACK) != 0 {
            let ack_seq = SeqNum(th.ack);

            // Check FIN acknowledgment first if FIN was sent at `fin_seq`.
            let mut effective_data_ack = ack_seq;
            if let Some(fseq) = self.fin_seq
                && !self.fin_acked
                && ack_seq.ge(fseq.add(1))
            {
                self.fin_acked = true;
                effective_data_ack = fseq;
                match self.state {
                    TcpState::FinWait1 => self.state = TcpState::FinWait2,
                    TcpState::Closing => {
                        self.state = TcpState::TimeWait;
                        self.time_wait_at = Some(now + self.time_wait_duration);
                    }
                    TcpState::LastAck => {
                        self.state = TcpState::Closed;
                        self.rto_deadline = None;
                        return;
                    }
                    _ => {}
                }
            }

            // Decode peer ECN feedback.
            let mut ce_bytes = 0u64;
            if self.acc_ecn.handshake_done() {
                match self.acc_ecn.mode {
                    EcnMode::AccEcn => {
                        let ce_pkts = self.acc_ecn.on_ack_ace(th.ace_bits());
                        if ce_pkts > 0 {
                            ce_bytes = ce_pkts.saturating_mul(u64::from(self.effective_mss));
                            self.cwr_pending = true;
                        }
                    }
                    EcnMode::ClassicEcn => {
                        if (th.flags & TCP_FLAG_ECE) != 0 {
                            ce_bytes = u64::from(self.effective_mss);
                            self.cwr_pending = true;
                        }
                    }
                    EcnMode::NotEct | EcnMode::Pending => {}
                }
            }

            let prev_rto_backoff = self.rto_backoff;
            let outcome = self.tx.on_ack(
                effective_data_ack,
                opts.sack_slice(),
                ce_bytes,
                now,
                self.rtt.srtt,
                &mut self.sampler,
            );

            // Eifel / DSACK spurious retransmission check.
            let eifel_undo = prev_rto_backoff > 0
                && outcome.ack_advanced
                && self.last_retx_tsecr.is_some()
                && opts
                    .timestamps
                    .is_some_and(|(_, tsecr)| tsecr < self.last_retx_tsecr.unwrap_or(0));
            if outcome.spurious_retransmit || eifel_undo {
                self.cc.on_loss_undo(now);
            }

            if let Some(rtt_sample) = outcome.sample.rtt {
                self.rtt.sample(rtt_sample);
            }
            let in_flight = self.tx.in_flight_bytes();

            if outcome.sample.delivered > 0 || outcome.sample.lost > 0 || ce_bytes > 0 {
                self.cc
                    .on_rate_sample(&outcome.sample, in_flight, &self.rtt);
            }
            if ce_bytes > 0 {
                self.cc
                    .on_ecn_ce(now, ce_bytes, self.sampler.delivered_total(), in_flight);
            }
            if outcome.newly_lost_bytes > 0 {
                self.cc
                    .on_loss_event(now, outcome.newly_lost_bytes, in_flight, false);
            }

            if outcome.ack_advanced {
                self.rto_backoff = 0;
                self.last_retx_seq = None;
                self.last_retx_tsecr = None;
            }
            // Re-arm or clear RTO deadline based on remaining un-acked data.
            if self.tx.has_unacked() || (self.fin_sent && !self.fin_acked) {
                if outcome.ack_advanced {
                    let rto = self.rtt.rto() * (1u32 << self.rto_backoff.min(6));
                    self.rto_deadline = Some(now + rto);
                }
            } else {
                self.rto_deadline = None;
            }
        }

        // Process inbound payload + FIN.
        let payload = view.payload();
        let has_fin = (th.flags & TCP_FLAG_FIN) != 0;
        if !payload.is_empty() || has_fin {
            let rx_out = self.rx.on_segment(seg_seq, payload, has_fin);
            self.bytes_rx = self.bytes_rx.saturating_add(rx_out.newly_contiguous as u64);
            self.delivered_segments = self.delivered_segments.saturating_add(1);
            if rx_out.out_of_order {
                self.reorder_events = self.reorder_events.saturating_add(1);
            }

            let ecn_urgent = if !payload.is_empty() && self.acc_ecn.handshake_done() {
                self.acc_ecn
                    .on_segment(view.ip_ecn(), payload.len() as u64, now.micros())
            } else {
                false
            };

            if rx_out.fin_contiguous {
                self.ack_now = true;
                match self.state {
                    TcpState::Established => self.state = TcpState::CloseWait,
                    TcpState::FinWait1 => self.state = TcpState::Closing,
                    TcpState::FinWait2 => {
                        self.state = TcpState::TimeWait;
                        self.time_wait_at = Some(now + self.time_wait_duration);
                        self.rto_deadline = None;
                    }
                    _ => {}
                }
            } else if rx_out.out_of_order || rx_out.duplicate || ecn_urgent {
                self.ack_now = true;
            } else if rx_out.newly_contiguous > 0 {
                // Delayed ACK: every 2nd segment or after delayed_ack_delay.
                if self.ack_pending {
                    self.ack_now = true;
                } else {
                    self.ack_pending = true;
                    self.delayed_ack_at = Some(now + self.delayed_ack_delay);
                }
            }
        }
    }

    /// Handle active timers (SYN/Data RTO, delayed ACK, TIME_WAIT expiry).
    pub fn on_timer(&mut self, now: TransportInstant) {
        if let Some(tw) = self.time_wait_at
            && now >= tw
        {
            self.state = TcpState::Closed;
            self.time_wait_at = None;
            self.rto_deadline = None;
            return;
        }

        if let Some(dack) = self.delayed_ack_at
            && now >= dack
        {
            self.ack_now = true;
            self.delayed_ack_at = None;
        }

        if let Some(rto_at) = self.rto_deadline
            && now >= rto_at
        {
            match self.state {
                TcpState::SynSent => {
                    if self.syn_retries >= MAX_SYN_RETRIES {
                        self.state = TcpState::Closed;
                        self.failed = true;
                        self.rto_deadline = None;
                        return;
                    }
                    self.syn_retries += 1;
                    self.need_syn = true;
                    let next_rto = SYN_RTO * (1u32 << self.syn_retries.min(5));
                    self.rto_deadline = Some(now + next_rto);
                }
                TcpState::SynReceived => {
                    if self.syn_retries >= MAX_SYN_RETRIES {
                        self.state = TcpState::Closed;
                        self.failed = true;
                        self.rto_deadline = None;
                        return;
                    }
                    self.syn_retries += 1;
                    self.need_syn_ack = true;
                    let next_rto = SYN_RTO * (1u32 << self.syn_retries.min(5));
                    self.rto_deadline = Some(now + next_rto);
                }
                TcpState::Established
                | TcpState::FinWait1
                | TcpState::CloseWait
                | TcpState::Closing
                | TcpState::LastAck => {
                    if self.rto_backoff >= MAX_RTO_RETRIES {
                        self.need_rst = true;
                        self.failed = true;
                        self.rto_deadline = None;
                        return;
                    }
                    self.rto_backoff += 1;
                    let in_flight = self.tx.in_flight_bytes();
                    let _ = self.tx.on_rto();
                    self.cc.on_rto(now, in_flight);
                    self.next_pacing_at = Some(now);
                    if self.fin_sent && !self.fin_acked {
                        self.fin_sent = false; // re-emit FIN
                    }
                    let next_rto = self.rtt.rto() * (1u32 << self.rto_backoff.min(6));
                    self.rto_deadline = Some(now + next_rto);
                }
                TcpState::Closed | TcpState::Listen | TcpState::FinWait2 | TcpState::TimeWait => {
                    self.rto_deadline = None;
                }
            }
        }
    }

    /// Emit at most a bounded burst of ready segments into `tx_buf`, passing each
    /// encoded frame to `emit`. Stops immediately if `emit` returns `false`.
    pub fn poll_tx(
        &mut self,
        now: TransportInstant,
        tx_buf: &mut [u8],
        emit: &mut impl FnMut(&[u8]) -> bool,
    ) {
        if self.state == TcpState::Closed {
            return;
        }

        // 1) Pending RST.
        if self.need_rst {
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: 0,
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: self.tx.snd_nxt().raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags: TCP_FLAG_RST | TCP_FLAG_ACK,
                ae: false,
                window: 0,
                options: TcpOptions::default(),
                payload: &[],
            };
            if let Ok(len) = encode_tcp_frame_parts(tx_buf, &spec, &[], &[])
                && emit(&tx_buf[..len])
            {
                self.need_rst = false;
                self.state = TcpState::Closed;
            }
            return;
        }

        // 2) Active-open SYN.
        if self.need_syn {
            let ecn = self.acc_ecn.syn_flags(self.syn_retries > 0);
            let mut flags = TCP_FLAG_SYN;
            if ecn.cwr {
                flags |= TCP_FLAG_CWR;
            }
            if ecn.ece {
                flags |= TCP_FLAG_ECE;
            }
            let opts = TcpOptions {
                mss: Some(self.effective_mss),
                window_scale: Some(self.rcv_wscale),
                sack_permitted: self.sack_enabled,
                timestamps: self.ts_enabled.then_some((ts_val_from(now), 0)),
                ..TcpOptions::default()
            };
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: 0,
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: self.iss.raw(),
                ack: 0,
                flags,
                ae: ecn.ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            if let Ok(len) = encode_tcp_frame_parts(tx_buf, &spec, &[], &[])
                && emit(&tx_buf[..len])
            {
                self.need_syn = false;
            }
            return;
        }

        // 3) Passive-open SYN-ACK.
        if self.need_syn_ack {
            let mut flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
            let ae = match self.acc_ecn.mode {
                EcnMode::AccEcn => {
                    flags |= TCP_FLAG_CWR;
                    false
                }
                EcnMode::ClassicEcn => {
                    flags |= TCP_FLAG_ECE;
                    false
                }
                EcnMode::NotEct | EcnMode::Pending => false,
            };
            let opts = TcpOptions {
                mss: Some(self.effective_mss),
                window_scale: Some(self.rcv_wscale),
                sack_permitted: self.sack_enabled,
                timestamps: self
                    .ts_enabled
                    .then_some((ts_val_from(now), self.ts_recent)),
                ..TcpOptions::default()
            };
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: 0,
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: self.iss.raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags,
                ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            if let Ok(len) = encode_tcp_frame_parts(tx_buf, &spec, &[], &[])
                && emit(&tx_buf[..len])
            {
                self.need_syn_ack = false;
            }
            return;
        }

        // 4) Retransmits (fast/RTO).
        for _ in 0..8 {
            let Some((seq, seg_len)) = self.tx.next_retransmit() else {
                break;
            };
            if let Some(next_p) = self.next_pacing_at
                && now < next_p
            {
                break;
            }
            let Some((p1, p2)) = self.tx.slice_for(seq, seg_len) else {
                break;
            };
            let mut flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
            let ae = self.apply_ack_ecn_flags(&mut flags);
            let opts = self.base_options(now, true);
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: self.ecn_ip_codepoint(true),
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: seq.raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags,
                ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            let Ok(frame_len) = encode_tcp_frame_parts(tx_buf, &spec, p1, p2) else {
                break;
            };
            if !emit(&tx_buf[..frame_len]) {
                return;
            }
            self.on_ack_emitted();
            let marker = self.sampler.delivered_marker();
            let app_lim = self.sampler.app_limited_now();
            self.tx.mark_retransmitted(seq, now, marker, app_lim);
            self.retransmits = self.retransmits.saturating_add(1);
            self.last_retx_seq = Some(seq);
            self.last_retx_tsecr = Some(ts_val_from(now));
            self.next_pacing_at = Some(now + pacing_gap_for(frame_len, self.cc.pacing_rate()));
            if self.rto_deadline.is_none() {
                self.rto_deadline = Some(now + self.rtt.rto());
            }
        }

        // 5) New payload data segments bounded by min(cwnd, peer_rwnd) and pacing.
        for _ in 0..16 {
            let unsent = self.tx.unsent_bytes();
            if unsent == 0 || !self.can_send_new_data_window() {
                break;
            }
            if let Some(next_p) = self.next_pacing_at
                && now < next_p
            {
                break;
            }
            let cwnd = self.cc.cwnd();
            let eff_win = cwnd.min(self.peer_rwnd);
            let in_flight = self.tx.in_flight_bytes();
            let usable = eff_win.saturating_sub(in_flight);
            if usable == 0 {
                break;
            }
            let max_mss = usize::from(self.effective_mss);
            let seg_len = unsent.min(max_mss).min(usable as usize);
            if seg_len == 0 {
                break;
            }
            let seq = self.tx.snd_nxt();
            let Some((p1, p2)) = self.tx.slice_for(seq, seg_len) else {
                break;
            };
            if unsent == seg_len {
                self.sampler.mark_app_limited();
            }
            let mut flags = TCP_FLAG_ACK;
            if unsent == seg_len {
                flags |= TCP_FLAG_PSH;
            }
            let ae = self.apply_ack_ecn_flags(&mut flags);
            let opts = self.base_options(now, true);
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: self.ecn_ip_codepoint(true),
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: seq.raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags,
                ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            let Ok(frame_len) = encode_tcp_frame_parts(tx_buf, &spec, p1, p2) else {
                break;
            };
            if !emit(&tx_buf[..frame_len]) {
                return;
            }
            self.on_ack_emitted();
            let rel_seq = self.tx.rel_nxt();
            let rec = self
                .sampler
                .note_sent(rel_seq, seg_len as u64, now, false, None);
            self.tx.mark_new_sent(seg_len, rec);
            self.bytes_tx = self.bytes_tx.saturating_add(seg_len as u64);
            let new_in_flight = self.tx.in_flight_bytes();
            self.cc
                .on_sent(now, seg_len as u64, new_in_flight, rec.is_app_limited);
            self.next_pacing_at = Some(now + pacing_gap_for(frame_len, self.cc.pacing_rate()));
            if self.rto_deadline.is_none() {
                self.rto_deadline = Some(now + self.rtt.rto());
            }
        }

        // 6) Graceful FIN when send queue is completely drained.
        if self.close_requested && self.tx.queued_bytes() == 0 && !self.fin_sent {
            let fin_seq = self.fin_seq.unwrap_or_else(|| self.tx.snd_nxt());
            let mut flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
            let ae = self.apply_ack_ecn_flags(&mut flags);
            let opts = self.base_options(now, true);
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: 0,
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: fin_seq.raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags,
                ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            if let Ok(frame_len) = encode_tcp_frame_parts(tx_buf, &spec, &[], &[])
                && emit(&tx_buf[..frame_len])
            {
                self.on_ack_emitted();
                self.fin_sent = true;
                self.fin_seq = Some(fin_seq);
                match self.state {
                    TcpState::Established => self.state = TcpState::FinWait1,
                    TcpState::CloseWait => self.state = TcpState::LastAck,
                    _ => {}
                }
                if self.rto_deadline.is_none() {
                    self.rto_deadline = Some(now + self.rtt.rto());
                }
            }
            return;
        }

        // 7) Standalone ACK if needed.
        if self.ack_now {
            let mut flags = TCP_FLAG_ACK;
            let ae = self.apply_ack_ecn_flags(&mut flags);
            let opts = self.base_options(now, true);
            let spec = TcpFrameSpec {
                src_mac: self.src_mac,
                dst_mac: self.peer_mac,
                vlan_id: self.vlan_id,
                src_ip: self.flow.local.ip(),
                dst_ip: self.flow.peer.ip(),
                ip_ecn: 0,
                ttl: self.ttl,
                src_port: self.flow.local.port(),
                dst_port: self.flow.peer.port(),
                seq: self
                    .fin_seq
                    .map(|s| s.add(1))
                    .unwrap_or_else(|| self.tx.snd_nxt())
                    .raw(),
                ack: self.rx.rcv_nxt().raw(),
                flags,
                ae,
                window: self.scaled_rx_window(),
                options: opts,
                payload: &[],
            };
            if let Ok(frame_len) = encode_tcp_frame_parts(tx_buf, &spec, &[], &[])
                && emit(&tx_buf[..frame_len])
            {
                self.on_ack_emitted();
            }
        }
    }
}
