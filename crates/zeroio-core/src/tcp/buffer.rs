//! Bounded zero-panic RX reassembly buffer and TX scoreboard queue for sans-I/O TCP.

use crate::TransportInstant;
use crate::packet::{MAX_SACK_BLOCKS, SackBlock, TcpOptions};
use crate::rate_sample::{RateSample, RateSampler, TxRecord};
use crate::tcp::seq::SeqNum;
use std::collections::VecDeque;
use std::time::Duration;

/// Maximum out-of-order byte gaps held per connection (DoS-bounded).
pub const MAX_OOO_BLOCKS: usize = 16;

/// Duplicate ACK count that triggers fast retransmission (RFC 5681 / 6675).
const DUPACK_THRESH: u32 = 3;

/// Result of accepting an inbound TCP payload/FIN into [`RxBuffer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxAcceptOutcome {
    /// Bytes newly merged into the contiguous in-order stream (`RCV.NXT` advanced).
    pub newly_contiguous: usize,
    /// Segment arrived out of order (or left a gap) — caller should ACK immediately.
    pub out_of_order: bool,
    /// A duplicate segment was received — caller should ACK immediately.
    pub duplicate: bool,
    /// FIN became contiguous at `RCV.NXT`.
    pub fin_contiguous: bool,
}

#[derive(Clone, Copy, Debug)]
struct OooBlock {
    start: SeqNum,
    end: SeqNum,
    /// Monotonic touch sequence so RFC 2018 MRU SACK block comes first.
    mru_tick: u64,
}

/// Bounded RX ring buffer + fixed-capacity out-of-order reassembly staging.
pub struct RxBuffer {
    ring: Vec<u8>,
    read_pos: usize,
    len: usize,
    /// Staging scratch aligned with `rcv_nxt`: holds bytes for OOO offsets
    /// `[1 .. cap]` relative to `rcv_nxt`.
    ooo_buf: Vec<u8>,
    ooo_blocks: Vec<OooBlock>,
    rcv_nxt: SeqNum,
    fin_seq: Option<SeqNum>,
    fin_delivered: bool,
    mru_counter: u64,
}

impl RxBuffer {
    pub fn new(initial_rcv_nxt: SeqNum, capacity: usize) -> Self {
        let cap = capacity.max(1024);
        Self {
            ring: vec![0u8; cap],
            read_pos: 0,
            len: 0,
            ooo_buf: vec![0u8; cap],
            ooo_blocks: Vec::with_capacity(MAX_OOO_BLOCKS),
            rcv_nxt: initial_rcv_nxt,
            fin_seq: None,
            fin_delivered: false,
            mru_counter: 0,
        }
    }

    pub fn rcv_nxt(&self) -> SeqNum {
        self.rcv_nxt
    }

    pub fn available(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        self.ring.len()
    }

    /// Free contiguous receive window in bytes (never exceeds capacity).
    pub fn window_bytes(&self) -> usize {
        self.ring.len().saturating_sub(self.len)
    }

    pub fn fin_contiguous(&self) -> bool {
        self.fin_delivered
    }

    /// Read up to `dst.len()` contiguous in-order bytes from the buffer.
    pub fn read_into(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.len);
        if to_read == 0 {
            return 0;
        }
        let cap = self.ring.len();
        let first = (cap - self.read_pos).min(to_read);
        dst[..first].copy_from_slice(&self.ring[self.read_pos..self.read_pos + first]);
        if to_read > first {
            dst[first..to_read].copy_from_slice(&self.ring[..to_read - first]);
        }
        self.read_pos = (self.read_pos + to_read) % cap;
        self.len -= to_read;
        to_read
    }

    /// Accept a segment starting at `seq` with `data` and optional `has_fin`.
    pub fn on_segment(&mut self, seq: SeqNum, data: &[u8], has_fin: bool) -> RxAcceptOutcome {
        if has_fin {
            let candidate_fin = seq.add(data.len() as u32);
            if self.fin_seq.is_none() {
                self.fin_seq = Some(candidate_fin);
            }
        }

        let win = self.window_bytes();
        let win_end = self.rcv_nxt.add(win as u32);

        if data.is_empty() {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: false,
                duplicate: false,
                fin_contiguous,
            };
        }

        let seg_end = seq.add(data.len() as u32);

        // Entirely before RCV.NXT -> pure duplicate.
        if seg_end.le(self.rcv_nxt) {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: false,
                duplicate: true,
                fin_contiguous,
            };
        }

        // Entirely beyond receive window -> drop (duplicate/probe ACK).
        if seq.ge(win_end) {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: true,
                duplicate: false,
                fin_contiguous,
            };
        }

        // Trim left overlap (bytes < RCV.NXT) and right overflow (bytes >= win_end).
        let trim_left = if seq.lt(self.rcv_nxt) {
            self.rcv_nxt.offset_from(seq) as usize
        } else {
            0
        };
        let eff_start = seq.add(trim_left as u32);
        let max_avail = win_end.offset_from(eff_start) as usize;
        let eff_len = (data.len() - trim_left).min(max_avail);
        if eff_len == 0 {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: false,
                duplicate: trim_left > 0,
                fin_contiguous,
            };
        }
        let eff_data = &data[trim_left..trim_left + eff_len];
        let eff_end = eff_start.add(eff_len as u32);

        if eff_start == self.rcv_nxt {
            // Fast path: in-order delivery into ring.
            let old_nxt = self.rcv_nxt;
            self.write_ring(eff_data);
            self.rcv_nxt = eff_end;
            let mut newly = eff_len;

            // Drain any OOO blocks now contiguous with RCV.NXT.
            let mut drained_bytes = 0usize;
            while let Some(idx) = self
                .ooo_blocks
                .iter()
                .position(|b| b.start.le(self.rcv_nxt))
            {
                let blk = self.ooo_blocks.swap_remove(idx);
                if blk.end.gt(self.rcv_nxt) {
                    let skip = self.rcv_nxt.offset_from(blk.start) as usize;
                    let start_off = blk.start.offset_from(old_nxt) as usize + skip;
                    let take = blk.end.offset_from(self.rcv_nxt) as usize;
                    self.copy_from_ooo_to_ring(start_off, take);
                    self.rcv_nxt = blk.end;
                    newly += take;
                    drained_bytes = start_off + take;
                }
            }
            if !self.ooo_blocks.is_empty() {
                let shift = self.rcv_nxt.offset_from(old_nxt) as usize;
                let max_end = self
                    .ooo_blocks
                    .iter()
                    .map(|b| b.end.offset_from(old_nxt) as usize)
                    .max()
                    .unwrap_or(shift)
                    .max(drained_bytes);
                if max_end > shift && shift > 0 {
                    self.ooo_buf.copy_within(shift..max_end, 0);
                }
            }

            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: newly,
                out_of_order: !self.ooo_blocks.is_empty(),
                duplicate: false,
                fin_contiguous,
            };
        }

        // Out-of-order segment: check if it fits in OOO staging.
        let off = eff_start.offset_from(self.rcv_nxt) as usize;
        if off + eff_len > self.ooo_buf.len() {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: true,
                duplicate: false,
                fin_contiguous,
            };
        }

        // Check duplicate against existing OOO blocks.
        let already_covered = self
            .ooo_blocks
            .iter()
            .any(|b| eff_start.ge(b.start) && eff_end.le(b.end));
        if already_covered {
            let fin_contiguous = self.check_fin_contiguous();
            return RxAcceptOutcome {
                newly_contiguous: 0,
                out_of_order: true,
                duplicate: true,
                fin_contiguous,
            };
        }

        self.ooo_buf[off..off + eff_len].copy_from_slice(eff_data);
        self.insert_ooo_block(eff_start, eff_end);
        let fin_contiguous = self.check_fin_contiguous();
        RxAcceptOutcome {
            newly_contiguous: 0,
            out_of_order: true,
            duplicate: false,
            fin_contiguous,
        }
    }

    fn insert_ooo_block(&mut self, mut start: SeqNum, mut end: SeqNum) {
        self.mru_counter = self.mru_counter.wrapping_add(1);
        let tick = self.mru_counter;

        let mut i = 0usize;
        while i < self.ooo_blocks.len() {
            let b = self.ooo_blocks[i];
            if !(end.lt(b.start) || start.gt(b.end)) {
                if b.start.lt(start) {
                    start = b.start;
                }
                if b.end.gt(end) {
                    end = b.end;
                }
                self.ooo_blocks.swap_remove(i);
            } else {
                i += 1;
            }
        }

        if self.ooo_blocks.len() >= MAX_OOO_BLOCKS {
            // Drop the oldest non-MRU block to keep OOO state strictly bounded.
            if let Some((oldest_idx, _)) = self
                .ooo_blocks
                .iter()
                .enumerate()
                .min_by_key(|(_, b)| b.mru_tick)
            {
                self.ooo_blocks.swap_remove(oldest_idx);
            }
        }
        self.ooo_blocks.push(OooBlock {
            start,
            end,
            mru_tick: tick,
        });
    }

    fn check_fin_contiguous(&mut self) -> bool {
        if let Some(fin_seq) = self.fin_seq
            && !self.fin_delivered
            && self.rcv_nxt == fin_seq
        {
            self.rcv_nxt = self.rcv_nxt.add(1);
            self.fin_delivered = true;
        }
        self.fin_delivered
    }

    fn write_ring(&mut self, data: &[u8]) {
        let cap = self.ring.len();
        let write_pos = (self.read_pos + self.len) % cap;
        let first = (cap - write_pos).min(data.len());
        self.ring[write_pos..write_pos + first].copy_from_slice(&data[..first]);
        if data.len() > first {
            self.ring[..data.len() - first].copy_from_slice(&data[first..]);
        }
        self.len += data.len();
    }

    fn copy_from_ooo_to_ring(&mut self, ooo_off: usize, len: usize) {
        let cap = self.ring.len();
        let write_pos = (self.read_pos + self.len) % cap;
        let first = (cap - write_pos).min(len);
        self.ring[write_pos..write_pos + first]
            .copy_from_slice(&self.ooo_buf[ooo_off..ooo_off + first]);
        if len > first {
            self.ring[..len - first].copy_from_slice(&self.ooo_buf[ooo_off + first..ooo_off + len]);
        }
        self.len += len;
    }

    /// Populate RFC 2018 SACK blocks ordered most-recently-received first.
    pub fn write_sack_options(&self, opts: &mut TcpOptions) {
        if self.ooo_blocks.is_empty() {
            return;
        }
        let mut sorted: [Option<OooBlock>; MAX_OOO_BLOCKS] = [None; MAX_OOO_BLOCKS];
        let count = self.ooo_blocks.len().min(MAX_OOO_BLOCKS);
        for (i, blk) in self.ooo_blocks.iter().take(count).enumerate() {
            sorted[i] = Some(*blk);
        }
        sorted[..count].sort_by_key(|a| std::cmp::Reverse(a.unwrap().mru_tick));
        for blk in sorted[..count].iter().flatten().take(MAX_SACK_BLOCKS) {
            opts.push_sack(SackBlock {
                left: blk.start.raw(),
                right: blk.end.raw(),
            });
        }
    }
}

/// Metadata for a single transmitted (in-flight or retransmitted) TCP segment.
#[derive(Clone, Copy, Debug)]
struct TxSeg {
    seq: SeqNum,
    /// Monotonic relative byte offset from handshake completion (never wraps).
    rel_seq: u64,
    len: u32,
    first_tx_at: TransportInstant,
    sent_at: TransportInstant,
    delivered_at_send: u64,
    is_app_limited: bool,
    retransmitted: bool,
    sacked: bool,
    lost: bool,
}

/// Outcome of processing an inbound ACK + SACK list against [`TxQueue`].
#[derive(Clone, Debug)]
pub struct AckOutcome {
    pub sample: RateSample,
    pub ack_advanced: bool,
    pub duplicate_ack: bool,
    pub newly_lost_bytes: u64,
    pub spurious_retransmit: bool,
}

/// Bounded TX byte ring and segment scoreboard producing [`TxRecord`]s for [`RateSampler`].
pub struct TxQueue {
    ring: Vec<u8>,
    read_pos: usize,
    /// Total queued bytes starting at `snd_una` (sent-unacked + unsent).
    len: usize,
    snd_una: SeqNum,
    snd_nxt: SeqNum,
    /// Monotonic cumulative ACKed payload bytes since handshake completion.
    cum_acked_bytes: u64,
    /// Monotonic sent payload cursor since handshake completion.
    rel_nxt: u64,
    segs: VecDeque<TxSeg>,
    dup_acks: u32,
    /// Reusable scratch vector to keep ACK processing allocation-free after warmup.
    ack_scratch: Vec<TxRecord>,
}

impl TxQueue {
    pub fn new(initial_snd_una: SeqNum, capacity: usize) -> Self {
        let cap = capacity.max(1024);
        Self {
            ring: vec![0u8; cap],
            read_pos: 0,
            len: 0,
            snd_una: initial_snd_una,
            snd_nxt: initial_snd_una,
            cum_acked_bytes: 0,
            rel_nxt: 0,
            segs: VecDeque::with_capacity(64),
            dup_acks: 0,
            ack_scratch: Vec::with_capacity(32),
        }
    }

    pub fn snd_una(&self) -> SeqNum {
        self.snd_una
    }

    pub fn snd_nxt(&self) -> SeqNum {
        self.snd_nxt
    }

    pub fn cum_acked_bytes(&self) -> u64 {
        self.cum_acked_bytes
    }

    pub fn rel_nxt(&self) -> u64 {
        self.rel_nxt
    }

    pub fn queued_bytes(&self) -> usize {
        self.len
    }

    pub fn free_bytes(&self) -> usize {
        self.ring.len().saturating_sub(self.len)
    }

    pub fn unsent_bytes(&self) -> usize {
        let sent = self.snd_nxt.offset_from(self.snd_una) as usize;
        self.len.saturating_sub(sent)
    }

    pub fn in_flight_bytes(&self) -> u64 {
        let mut inflight = 0u64;
        for seg in &self.segs {
            if !seg.sacked && !seg.lost {
                inflight += u64::from(seg.len);
            }
        }
        inflight
    }

    pub fn has_unacked(&self) -> bool {
        !self.segs.is_empty()
    }

    pub fn has_lost(&self) -> bool {
        self.segs.iter().any(|s| s.lost && !s.sacked)
    }

    /// Enqueue outbound application bytes; returns number of bytes accepted.
    pub fn push_data(&mut self, data: &[u8]) -> usize {
        let accept = data.len().min(self.free_bytes());
        if accept == 0 {
            return 0;
        }
        let cap = self.ring.len();
        let write_pos = (self.read_pos + self.len) % cap;
        let first = (cap - write_pos).min(accept);
        self.ring[write_pos..write_pos + first].copy_from_slice(&data[..first]);
        if accept > first {
            self.ring[..accept - first].copy_from_slice(&data[first..accept]);
        }
        self.len += accept;
        accept
    }

    /// Borrow two slices covering `[seq, seq + len)` inside the TX ring without copying.
    pub fn slice_for(&self, seq: SeqNum, len: usize) -> Option<(&[u8], &[u8])> {
        let off = seq.offset_from(self.snd_una) as usize;
        if off + len > self.len {
            return None;
        }
        let cap = self.ring.len();
        let start = (self.read_pos + off) % cap;
        let first = (cap - start).min(len);
        let p1 = &self.ring[start..start + first];
        let p2 = if len > first {
            &self.ring[..len - first]
        } else {
            &[]
        };
        Some((p1, p2))
    }

    /// Record transmission of a brand-new segment at `SND.NXT`.
    pub fn mark_new_sent(&mut self, len: usize, rec: TxRecord) {
        let seq = self.snd_nxt;
        let rel_seq = self.rel_nxt;
        self.snd_nxt = self.snd_nxt.add(len as u32);
        self.rel_nxt = self.rel_nxt.saturating_add(len as u64);
        self.segs.push_back(TxSeg {
            seq,
            rel_seq,
            len: len as u32,
            first_tx_at: rec.first_tx_at,
            sent_at: rec.sent_at,
            delivered_at_send: rec.delivered_at_send,
            is_app_limited: rec.is_app_limited,
            retransmitted: false,
            sacked: false,
            lost: false,
        });
    }

    /// Return the earliest un-sacked segment marked `lost` for fast/RTO retransmission.
    pub fn next_retransmit(&self) -> Option<(SeqNum, usize)> {
        self.segs
            .iter()
            .find(|s| s.lost && !s.sacked)
            .map(|s| (s.seq, s.len as usize))
    }

    /// Record that a lost segment `[seq, seq + len)` was retransmitted.
    pub fn mark_retransmitted(
        &mut self,
        seq: SeqNum,
        now: TransportInstant,
        delivered_marker: u64,
        app_limited: bool,
    ) {
        if let Some(seg) = self.segs.iter_mut().find(|s| s.seq == seq) {
            seg.sent_at = now;
            seg.delivered_at_send = delivered_marker;
            seg.is_app_limited = app_limited;
            seg.retransmitted = true;
            seg.lost = false;
        }
    }

    /// Mark all un-sacked segments lost when RTO fires.
    pub fn on_rto(&mut self) -> u64 {
        let mut lost_bytes = 0u64;
        for seg in &mut self.segs {
            if !seg.sacked && !seg.lost {
                seg.lost = true;
                lost_bytes += u64::from(seg.len);
            }
        }
        self.dup_acks = 0;
        lost_bytes
    }

    /// Earliest `sent_at` timestamp of un-sacked segments (for RTO arming).
    pub fn oldest_unacked_sent_at(&self) -> Option<TransportInstant> {
        self.segs
            .iter()
            .filter(|s| !s.sacked)
            .map(|s| s.sent_at)
            .min()
    }

    /// Process an inbound ACK number and SACK blocks, updating `SND.UNA`,
    /// scoreboard, `RateSampler`, and loss/undo detection.
    pub fn on_ack(
        &mut self,
        ack: SeqNum,
        sack_blocks: &[SackBlock],
        ce_bytes: u64,
        now: TransportInstant,
        srtt: Option<Duration>,
        sampler: &mut RateSampler,
    ) -> AckOutcome {
        let prior_in_flight = self.in_flight_bytes();

        // Ignore ACKs above SND.NXT.
        if ack.gt(self.snd_nxt) {
            let sample =
                sampler.on_ack(now, &[], 0, ce_bytes, prior_in_flight, self.cum_acked_bytes);
            return AckOutcome {
                sample,
                ack_advanced: false,
                duplicate_ack: false,
                newly_lost_bytes: 0,
                spurious_retransmit: false,
            };
        }

        self.ack_scratch.clear();
        let mut ack_advanced = false;
        let mut spurious_retransmit = false;

        if ack.gt(self.snd_una) {
            ack_advanced = true;
            self.dup_acks = 0;
            let advance = ack.offset_from(self.snd_una) as usize;
            let cap = self.ring.len();
            self.read_pos = (self.read_pos + advance) % cap;
            self.len = self.len.saturating_sub(advance);
            self.snd_una = ack;
            self.cum_acked_bytes = self.cum_acked_bytes.saturating_add(advance as u64);

            while let Some(front) = self.segs.front() {
                let seg_end = front.seq.add(front.len);
                if seg_end.le(ack) {
                    let seg = self.segs.pop_front().unwrap();
                    if !seg.sacked {
                        self.ack_scratch.push(TxRecord {
                            seq: seg.rel_seq,
                            end_seq: seg.rel_seq + u64::from(seg.len),
                            sent_at: seg.sent_at,
                            first_tx_at: seg.first_tx_at,
                            delivered_at_send: seg.delivered_at_send,
                            is_app_limited: seg.is_app_limited,
                            is_retransmit: seg.retransmitted,
                        });
                    }
                } else {
                    break;
                }
            }
            // Handle partial ACK splitting a segment cleanly.
            if let Some(front) = self.segs.front_mut()
                && front.seq.lt(ack)
            {
                let cut = ack.offset_from(front.seq);
                if !front.sacked {
                    self.ack_scratch.push(TxRecord {
                        seq: front.rel_seq,
                        end_seq: front.rel_seq + u64::from(cut),
                        sent_at: front.sent_at,
                        first_tx_at: front.first_tx_at,
                        delivered_at_send: front.delivered_at_send,
                        is_app_limited: front.is_app_limited,
                        is_retransmit: front.retransmitted,
                    });
                }
                front.seq = ack;
                front.rel_seq += u64::from(cut);
                front.len = front.len.saturating_sub(cut);
            }
        }

        // Apply SACK blocks (including DSACK detection if block falls below SND.UNA).
        let mut highest_sacked: Option<SeqNum> = None;
        for blk in sack_blocks {
            let b_left = SeqNum(blk.left);
            let b_right = SeqNum(blk.right);
            if !b_right.gt(b_left) {
                continue;
            }
            if b_left.lt(self.snd_una) {
                // RFC 2883 DSACK: peer received a duplicate of already-ACKed bytes.
                spurious_retransmit = true;
                continue;
            }
            if b_right.gt(self.snd_nxt) {
                continue;
            }
            for seg in &mut self.segs {
                let seg_end = seg.seq.add(seg.len);
                if !seg.sacked && seg.seq.ge(b_left) && seg_end.le(b_right) {
                    seg.sacked = true;
                    seg.lost = false;
                    self.ack_scratch.push(TxRecord {
                        seq: seg.rel_seq,
                        end_seq: seg.rel_seq + u64::from(seg.len),
                        sent_at: seg.sent_at,
                        first_tx_at: seg.first_tx_at,
                        delivered_at_send: seg.delivered_at_send,
                        is_app_limited: seg.is_app_limited,
                        is_retransmit: seg.retransmitted,
                    });
                }
            }
            highest_sacked = Some(match highest_sacked {
                Some(h) if h.gt(b_right) => h,
                _ => b_right,
            });
        }

        // Track highest sacked across all scoreboard entries too.
        for seg in &self.segs {
            if seg.sacked {
                let seg_end = seg.seq.add(seg.len);
                highest_sacked = Some(match highest_sacked {
                    Some(h) if h.gt(seg_end) => h,
                    _ => seg_end,
                });
            }
        }

        let duplicate_ack = !ack_advanced && ack == self.snd_una && !self.segs.is_empty();
        if duplicate_ack {
            self.dup_acks = self.dup_acks.saturating_add(1);
        }

        // Loss detection:
        // 1) >=3 segments SACKed past an un-sacked segment, or >=3 pure dupacks for the head.
        // 2) RACK-style time threshold: un-sacked segment sent before `latest_sacked_tx - srtt/4`.
        let mut newly_lost_bytes = 0u64;
        let rack_thresh = srtt.map(|r| r / 4).unwrap_or(Duration::from_millis(5));
        let newest_acked_tx = self.ack_scratch.iter().map(|r| r.sent_at).max();

        let mut sacked_after = 0u32;
        for seg in self.segs.iter_mut().rev() {
            if seg.sacked {
                sacked_after = sacked_after.saturating_add(1);
                continue;
            }
            if seg.lost {
                continue;
            }
            let rack_lost = newest_acked_tx
                .map(|latest| {
                    latest.duration_since(seg.sent_at) >= rack_thresh
                        && highest_sacked.is_some_and(|h| seg.seq.lt(h))
                })
                .unwrap_or(false);
            let hole_lost = sacked_after >= DUPACK_THRESH;
            if hole_lost || rack_lost {
                seg.lost = true;
                newly_lost_bytes += u64::from(seg.len);
            }
        }
        if duplicate_ack
            && self.dup_acks >= DUPACK_THRESH
            && let Some(front) = self.segs.front_mut()
            && !front.sacked
            && !front.lost
        {
            front.lost = true;
            newly_lost_bytes += u64::from(front.len);
        }

        // Sort records by monotonic offset so RateSampler sees monotonic order.
        self.ack_scratch.sort_by_key(|r| r.seq);
        let sample = sampler.on_ack(
            now,
            &self.ack_scratch,
            newly_lost_bytes,
            ce_bytes,
            prior_in_flight,
            self.cum_acked_bytes,
        );

        AckOutcome {
            sample,
            ack_advanced,
            duplicate_ack,
            newly_lost_bytes,
            spurious_retransmit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rx_buffer_handles_ooo_reassembly_sack_and_wrap() {
        let isn = SeqNum(u32::MAX - 3);
        let mut rx = RxBuffer::new(isn, 4096);

        // Arrive [isn+4, isn+8) out of order.
        let r1 = rx.on_segment(isn.add(4), b"wxyz", false);
        assert_eq!(r1.newly_contiguous, 0);
        assert!(r1.out_of_order);

        let mut opts = TcpOptions::default();
        rx.write_sack_options(&mut opts);
        assert_eq!(
            opts.sack_slice(),
            &[SackBlock {
                left: isn.add(4).raw(),
                right: isn.add(8).raw()
            }]
        );

        // Fill the hole [isn, isn+4) -> merges both!
        let r2 = rx.on_segment(isn, b"abcd", false);
        assert_eq!(r2.newly_contiguous, 8);
        assert!(!r2.out_of_order);
        assert_eq!(rx.rcv_nxt(), isn.add(8));

        let mut out = [0u8; 16];
        let n = rx.read_into(&mut out);
        assert_eq!(&out[..n], b"abcdwxyz");
    }

    #[test]
    fn tx_queue_tracks_in_flight_sack_loss_and_rate_sample() {
        let mut sampler = RateSampler::new();
        let mut tx = TxQueue::new(SeqNum(1000), 16384);
        assert_eq!(tx.push_data(&[0xAA; 4000]), 4000);

        for i in 0..4u32 {
            let t = TransportInstant::from_micros(1_000 + u64::from(i) * 100);
            let rec = sampler.note_sent(u64::from(i * 1000), 1000, t, false, None);
            tx.mark_new_sent(1000, rec);
        }
        assert_eq!(tx.in_flight_bytes(), 4000);

        // Peer SACKs segments 1, 2, 3 (leaving segment 0 at 1000..2000 missing).
        let sack = [SackBlock {
            left: 2000,
            right: 5000,
        }];
        let out = tx.on_ack(
            SeqNum(1000),
            &sack,
            0,
            TransportInstant::from_micros(20_000),
            Some(Duration::from_millis(20)),
            &mut sampler,
        );
        assert!(out.duplicate_ack);
        assert_eq!(out.newly_lost_bytes, 1000);
        assert_eq!(tx.next_retransmit(), Some((SeqNum(1000), 1000)));
        assert_eq!(out.sample.delivered, 3000);
    }
}
