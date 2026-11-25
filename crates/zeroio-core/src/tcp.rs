//! Server-grade O(1) TCP connection table primitives (generation-checked slab
//! handles and state tracking) and the sans-I/O TCP protocol engine.

pub mod buffer;
pub mod conn;
pub mod cookie;
pub mod seq;
pub mod stack;

pub use conn::{CcKind, TcpConfig, TcpConn, TcpConnSnapshot, TcpFourTuple};
pub use cookie::{COOKIE_MSS_TABLE, SynCookieKey, generate_syn_cookie, verify_syn_cookie};
pub use seq::SeqNum;
pub use stack::{TcpError, TcpStack};

/// Generation-checked connection handle preventing stale timers or packets from
/// touching a recycled slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnHandle {
    pub index: u32,
    pub generation: u32,
}

/// Standard RFC 9293 TCP connection states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

/// Fixed-cost O(1) free-list slab for per-core TCP connection state.
pub struct ConnSlab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    active: usize,
}

impl<T> Default for ConnSlab<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ConnSlab<T> {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            active: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            slots: Vec::with_capacity(capacity),
            free: Vec::with_capacity(capacity),
            active: 0,
        }
    }

    /// Try to allocate a slot in amortized O(1) time without panicking on `u32` overflow.
    pub fn try_insert(&mut self, value: T) -> Option<ConnHandle> {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.value = Some(value);
            self.active += 1;
            return Some(ConnHandle {
                index,
                generation: slot.generation,
            });
        }
        let index = u32::try_from(self.slots.len()).ok()?;
        self.slots.push(Slot {
            generation: 1,
            value: Some(value),
        });
        self.active += 1;
        Some(ConnHandle {
            index,
            generation: 1,
        })
    }

    /// Allocate a slot in amortized O(1) time.
    pub fn insert(&mut self, value: T) -> ConnHandle {
        self.try_insert(value).expect("ConnSlab capacity overflow")
    }

    /// Look up a live slot in O(1) time, rejecting stale generations.
    pub fn get(&self, handle: ConnHandle) -> Option<&T> {
        let slot = self.slots.get(handle.index as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        slot.value.as_ref()
    }

    /// Mutably look up a live slot in O(1) time, rejecting stale generations.
    pub fn get_mut(&mut self, handle: ConnHandle) -> Option<&mut T> {
        let slot = self.slots.get_mut(handle.index as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        slot.value.as_mut()
    }

    /// Remove a live slot in O(1) time and bump its generation counter.
    pub fn remove(&mut self, handle: ConnHandle) -> Option<T> {
        let slot = self.slots.get_mut(handle.index as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        let value = slot.value.take()?;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.free.push(handle.index);
        self.active -= 1;
        Some(value)
    }

    pub fn len(&self) -> usize {
        self.active
    }

    pub fn is_empty(&self) -> bool {
        self.active == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slab_reuses_slots_and_rejects_stale_handles() {
        let mut slab = ConnSlab::with_capacity(4);
        let h1 = slab.insert(TcpState::Established);
        assert_eq!(slab.len(), 1);
        assert_eq!(slab.get(h1), Some(&TcpState::Established));

        assert_eq!(slab.remove(h1), Some(TcpState::Established));
        assert_eq!(slab.len(), 0);
        assert_eq!(slab.get(h1), None);

        let h2 = slab.insert(TcpState::SynSent);
        assert_eq!(h2.index, h1.index);
        assert_ne!(h2.generation, h1.generation);
        assert_eq!(slab.get(h1), None);
        assert_eq!(slab.get(h2), Some(&TcpState::SynSent));
    }
}
