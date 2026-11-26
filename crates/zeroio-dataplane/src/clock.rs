//! Monotonic transport clock producing [`TransportInstant`] values.

use std::time::Instant;
use zeroio_core::TransportInstant;

/// Monotonic microsecond clock anchored at creation time.
#[derive(Clone, Copy, Debug)]
pub struct TransportClock {
    origin: Instant,
}

impl Default for TransportClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    #[inline]
    pub fn now(&self) -> TransportInstant {
        let us = self.origin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        TransportInstant::from_micros(us)
    }
}
