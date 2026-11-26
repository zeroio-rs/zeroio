//! Abstract `XskDevice` trait and portable in-memory 4-ring [`LoopbackXskDevice`]
//! implementation for cross-platform simulation and testing.

use crate::XskBindMode;
use crate::umem::{UmemConfig, UmemFrameToken, UmemSlab};
use std::collections::VecDeque;
use std::time::Duration;

/// Errors returned by [`XskDevice`] TX ring operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxSubmitError {
    RingFull,
    NoFreeFrames,
    FrameTooLarge,
    DeviceError(i32),
}

/// Queue-bound AF_XDP socket abstraction implemented by both the Linux UMEM/4-ring
/// driver and [`LoopbackXskDevice`].
pub trait XskDevice {
    fn queue_id(&self) -> u32;
    fn bind_mode(&self) -> XskBindMode;
    fn fd(&self) -> Option<i32>;

    /// Pull up to `max` received descriptors into `out`, returning count received.
    fn recv_batch(&mut self, max: usize, out: &mut Vec<UmemFrameToken>) -> usize;

    /// Borrow frame bytes corresponding to an RX [`UmemFrameToken`].
    fn frame_data(&self, token: UmemFrameToken) -> Option<&[u8]>;

    /// Allocate a TX UMEM frame slot.
    fn alloc_tx_frame(&mut self) -> Option<UmemFrameToken>;

    /// Mutably borrow the writable payload region of a TX UMEM frame (after headroom).
    fn frame_buf_mut(&mut self, addr: u64) -> Option<&mut [u8]>;

    /// Enqueue a populated TX UMEM frame onto the TX ring.
    fn submit_tx(&mut self, token: UmemFrameToken) -> Result<(), TxSubmitError>;

    /// Notify the kernel/NIC that TX descriptors are ready.
    fn kick_tx(&mut self) -> Result<(), TxSubmitError>;

    /// Return a consumed RX frame back to the Fill ring.
    fn recycle_rx(&mut self, token: UmemFrameToken);

    /// Drain up to `max` completed TX frames from the Completion ring.
    fn reclaim_completions(&mut self, max: usize) -> usize;

    /// Wait up to `timeout` for RX readiness.
    fn poll_wait(&mut self, timeout: Duration);
}

/// Portable in-memory 4-ring (`Fill`, `RX`, `TX`, `Completion`) XSK device backed by [`UmemSlab`].
pub struct LoopbackXskDevice {
    queue_id: u32,
    bind_mode: XskBindMode,
    slab: UmemSlab,
    fill_ring: VecDeque<u64>,
    rx_ring: VecDeque<(u64, u32)>,
    tx_ring: VecDeque<(u64, u32)>,
    comp_ring: VecDeque<u64>,
    rx_capacity: usize,
    tx_capacity: usize,
}

impl LoopbackXskDevice {
    /// Construct a loopback XSK device pre-populating half of UMEM into the Fill ring for RX.
    pub fn new(queue_id: u32, config: UmemConfig, bind_mode: XskBindMode) -> Self {
        let mut slab = UmemSlab::new(queue_id, config);
        let rx_cap = config.rx_ring_size as usize;
        let tx_cap = config.tx_ring_size as usize;
        let fill_target = (config.frame_count / 2).min(config.fill_ring_size) as usize;
        let mut fill_ring = VecDeque::with_capacity(config.fill_ring_size as usize);
        for _ in 0..fill_target {
            if let Some(tok) = slab.alloc_frame() {
                fill_ring.push_back(tok.addr);
            }
        }
        Self {
            queue_id,
            bind_mode,
            slab,
            fill_ring,
            rx_ring: VecDeque::with_capacity(rx_cap),
            tx_ring: VecDeque::with_capacity(tx_cap),
            comp_ring: VecDeque::with_capacity(config.comp_ring_size as usize),
            rx_capacity: rx_cap,
            tx_capacity: tx_cap,
        }
    }

    /// Inject a raw wire frame into the Fill/RX rings (simulates NIC DMA RX).
    pub fn push_rx_packet(&mut self, frame: &[u8]) -> bool {
        if self.rx_ring.len() >= self.rx_capacity {
            return false;
        }
        let Some(base_addr) = self.fill_ring.pop_front() else {
            return false;
        };
        let Some(dst) = self.slab.frame_buf_mut(base_addr) else {
            self.fill_ring.push_back(base_addr);
            return false;
        };
        if frame.len() > dst.len() {
            self.fill_ring.push_back(base_addr);
            return false;
        }
        dst[..frame.len()].copy_from_slice(frame);
        let data_addr = base_addr + u64::from(self.slab.config().headroom);
        self.rx_ring.push_back((data_addr, frame.len() as u32));
        true
    }

    /// Pop the next transmitted wire frame from the TX ring and return its UMEM address
    /// to the Completion ring (simulates NIC DMA TX completion).
    pub fn pop_tx_packet(&mut self) -> Option<Vec<u8>> {
        let (addr, len) = self.tx_ring.pop_front()?;
        let out = self.slab.frame_slice(addr, len).map(|s| s.to_vec());
        let fsize = u64::from(self.slab.config().frame_size);
        let base_addr = (addr / fsize) * fsize;
        self.comp_ring.push_back(base_addr);
        out
    }

    /// Forward all queued TX packets from `self` directly into `peer`'s RX ring.
    pub fn pump_tx_to(&mut self, peer: &mut LoopbackXskDevice) -> usize {
        let mut moved = 0usize;
        while let Some(pkt) = self.pop_tx_packet() {
            if peer.push_rx_packet(&pkt) {
                moved += 1;
            }
        }
        moved
    }

    pub fn free_tx_frames(&self) -> usize {
        self.slab.free_frames()
    }

    pub fn fill_ring_len(&self) -> usize {
        self.fill_ring.len()
    }
}

impl XskDevice for LoopbackXskDevice {
    fn queue_id(&self) -> u32 {
        self.queue_id
    }

    fn bind_mode(&self) -> XskBindMode {
        self.bind_mode
    }

    fn fd(&self) -> Option<i32> {
        None
    }

    fn recv_batch(&mut self, max: usize, out: &mut Vec<UmemFrameToken>) -> usize {
        let mut count = 0usize;
        while count < max
            && let Some((addr, len)) = self.rx_ring.pop_front()
        {
            out.push(UmemFrameToken {
                queue: self.queue_id,
                addr,
                len,
            });
            count += 1;
        }
        count
    }

    fn frame_data(&self, token: UmemFrameToken) -> Option<&[u8]> {
        self.slab.frame_slice(token.addr, token.len)
    }

    fn alloc_tx_frame(&mut self) -> Option<UmemFrameToken> {
        self.slab.alloc_frame()
    }

    fn frame_buf_mut(&mut self, addr: u64) -> Option<&mut [u8]> {
        self.slab.frame_buf_mut(addr)
    }

    fn submit_tx(&mut self, token: UmemFrameToken) -> Result<(), TxSubmitError> {
        if self.tx_ring.len() >= self.tx_capacity {
            return Err(TxSubmitError::RingFull);
        }
        if token.len as usize > self.slab.config().max_payload_bytes() {
            return Err(TxSubmitError::FrameTooLarge);
        }
        let data_addr = token.addr + u64::from(self.slab.config().headroom);
        self.tx_ring.push_back((data_addr, token.len));
        Ok(())
    }

    fn kick_tx(&mut self) -> Result<(), TxSubmitError> {
        Ok(())
    }

    fn recycle_rx(&mut self, token: UmemFrameToken) {
        let fsize = u64::from(self.slab.config().frame_size);
        let base_addr = (token.addr / fsize) * fsize;
        self.fill_ring.push_back(base_addr);
    }

    fn reclaim_completions(&mut self, max: usize) -> usize {
        let mut count = 0usize;
        while count < max
            && let Some(base_addr) = self.comp_ring.pop_front()
        {
            if self.slab.free_frame(base_addr) {
                count += 1;
            }
        }
        count
    }

    fn poll_wait(&mut self, _timeout: Duration) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_xsk_4_ring_lifecycle() {
        let cfg = UmemConfig {
            frame_count: 32,
            fill_ring_size: 16,
            comp_ring_size: 16,
            rx_ring_size: 16,
            tx_ring_size: 16,
            ..UmemConfig::default()
        };
        let mut dev_a = LoopbackXskDevice::new(0, cfg, XskBindMode::ZeroCopy);
        let mut dev_b = LoopbackXskDevice::new(0, cfg, XskBindMode::ZeroCopy);

        let mut tok = dev_a.alloc_tx_frame().unwrap();
        let buf = dev_a.frame_buf_mut(tok.addr).unwrap();
        buf[..4].copy_from_slice(b"ping");
        tok.len = 4;
        dev_a.submit_tx(tok).unwrap();
        assert_eq!(dev_a.pump_tx_to(&mut dev_b), 1);
        assert_eq!(dev_a.reclaim_completions(8), 1);

        let mut rx = Vec::new();
        assert_eq!(dev_b.recv_batch(8, &mut rx), 1);
        assert_eq!(dev_b.frame_data(rx[0]).unwrap(), b"ping");
        let fill_before = dev_b.fill_ring_len();
        dev_b.recycle_rx(rx[0]);
        assert_eq!(dev_b.fill_ring_len(), fill_before + 1);
    }
}
