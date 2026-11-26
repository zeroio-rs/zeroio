//! UMEM configuration, ownership tokens, and bounded portable frame slab.

use zeroio_xdp_common::XDP_DEFAULT_FRAME_SIZE;

/// Default per-frame headroom reserved before L2 bytes.
pub const DEFAULT_FRAME_HEADROOM: u32 = 256;

/// Ownership token for one UMEM frame slot inside a per-queue dataplane loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UmemFrameToken {
    pub queue: u32,
    pub addr: u64,
    pub len: u32,
}

/// UMEM and AF_XDP ring sizing parameters for one queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UmemConfig {
    pub frame_count: u32,
    pub frame_size: u32,
    pub headroom: u32,
    pub fill_ring_size: u32,
    pub comp_ring_size: u32,
    pub rx_ring_size: u32,
    pub tx_ring_size: u32,
}

impl Default for UmemConfig {
    fn default() -> Self {
        Self {
            frame_count: 4096,
            frame_size: XDP_DEFAULT_FRAME_SIZE,
            headroom: DEFAULT_FRAME_HEADROOM,
            fill_ring_size: 2048,
            comp_ring_size: 2048,
            rx_ring_size: 2048,
            tx_ring_size: 2048,
        }
    }
}

impl UmemConfig {
    /// Validate ring sizes (must be non-zero powers of two) and frame geometry.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.frame_count == 0 || !self.frame_size.is_power_of_two() || self.frame_size < 2048 {
            return Err("frame_size must be a power of two >= 2048 and frame_count > 0");
        }
        if self.headroom >= self.frame_size {
            return Err("headroom must be smaller than frame_size");
        }
        for ring in [
            self.fill_ring_size,
            self.comp_ring_size,
            self.rx_ring_size,
            self.tx_ring_size,
        ] {
            if ring == 0 || !ring.is_power_of_two() {
                return Err("AF_XDP ring sizes must be non-zero powers of two");
            }
        }
        Ok(())
    }

    pub fn total_bytes(&self) -> usize {
        (self.frame_count as usize).saturating_mul(self.frame_size as usize)
    }

    pub fn max_payload_bytes(&self) -> usize {
        self.frame_size.saturating_sub(self.headroom) as usize
    }
}

/// Safe, heap-backed UMEM frame pool for portable simulation, tests, and fallback paths.
pub struct UmemSlab {
    queue_id: u32,
    config: UmemConfig,
    mem: Vec<u8>,
    free_addrs: Vec<u64>,
}

impl UmemSlab {
    pub fn new(queue_id: u32, config: UmemConfig) -> Self {
        let count = config.frame_count.max(16) as usize;
        let fsize = config.frame_size.max(2048) as usize;
        let mem = vec![0u8; count * fsize];
        let mut free_addrs = Vec::with_capacity(count);
        for i in (0..count).rev() {
            free_addrs.push((i * fsize) as u64);
        }
        Self {
            queue_id,
            config,
            mem,
            free_addrs,
        }
    }

    pub fn config(&self) -> UmemConfig {
        self.config
    }

    pub fn free_frames(&self) -> usize {
        self.free_addrs.len()
    }

    pub fn alloc_frame(&mut self) -> Option<UmemFrameToken> {
        let addr = self.free_addrs.pop()?;
        Some(UmemFrameToken {
            queue: self.queue_id,
            addr,
            len: 0,
        })
    }

    pub fn free_frame(&mut self, addr: u64) -> bool {
        let fsize = u64::from(self.config.frame_size);
        let total = self.mem.len() as u64;
        if addr >= total || !addr.is_multiple_of(fsize) {
            return false;
        }
        self.free_addrs.push(addr);
        true
    }

    pub fn frame_slice(&self, addr: u64, len: u32) -> Option<&[u8]> {
        let start = usize::try_from(addr).ok()?;
        let end = start.checked_add(len as usize)?;
        self.mem.get(start..end)
    }

    pub fn frame_buf_mut(&mut self, addr: u64) -> Option<&mut [u8]> {
        let base = usize::try_from(addr).ok()?;
        let fsize = self.config.frame_size as usize;
        let frame_start = (base / fsize) * fsize;
        let data_start = frame_start + self.config.headroom as usize;
        let frame_end = frame_start + fsize;
        self.mem.get_mut(data_start..frame_end)
    }

    pub fn frame_slot_mut(&mut self, addr: u64, len: usize) -> Option<&mut [u8]> {
        let start = usize::try_from(addr).ok()?;
        let end = start.checked_add(len)?;
        self.mem.get_mut(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umem_slab_alloc_slice_and_free_roundtrip() {
        let cfg = UmemConfig {
            frame_count: 32,
            ..UmemConfig::default()
        };
        assert!(cfg.validate().is_ok());
        let mut slab = UmemSlab::new(0, cfg);
        assert_eq!(slab.free_frames(), 32);

        let tok = slab.alloc_frame().unwrap();
        assert_eq!(slab.free_frames(), 31);
        let buf = slab.frame_buf_mut(tok.addr).unwrap();
        buf[..5].copy_from_slice(b"hello");

        let data_addr = tok.addr + u64::from(cfg.headroom);
        assert_eq!(slab.frame_slice(data_addr, 5).unwrap(), b"hello");
        assert!(slab.free_frame(tok.addr));
        assert_eq!(slab.free_frames(), 32);
    }
}
