//! Wrapping 32-bit TCP sequence number arithmetic (RFC 9293 §3.3).

/// 32-bit wrapping TCP sequence number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SeqNum(pub u32);

impl SeqNum {
    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn add(self, n: u32) -> Self {
        Self(self.0.wrapping_add(n))
    }

    #[inline]
    pub const fn sub(self, n: u32) -> Self {
        Self(self.0.wrapping_sub(n))
    }

    /// Signed distance `self - other` in modular 32-bit space (`i32` semantics).
    #[inline]
    pub const fn diff(self, other: Self) -> i32 {
        self.0.wrapping_sub(other.0) as i32
    }

    /// Unsigned forward distance `self - other` assuming `self >= other`.
    #[inline]
    pub const fn offset_from(self, base: Self) -> u32 {
        self.0.wrapping_sub(base.0)
    }

    /// `self < other` in RFC 9293 modular arithmetic.
    #[inline]
    pub const fn lt(self, other: Self) -> bool {
        self.diff(other) < 0
    }

    /// `self <= other` in RFC 9293 modular arithmetic.
    #[inline]
    pub const fn le(self, other: Self) -> bool {
        self.diff(other) <= 0
    }

    /// `self > other` in RFC 9293 modular arithmetic.
    #[inline]
    pub const fn gt(self, other: Self) -> bool {
        self.diff(other) > 0
    }

    /// `self >= other` in RFC 9293 modular arithmetic.
    #[inline]
    pub const fn ge(self, other: Self) -> bool {
        self.diff(other) >= 0
    }

    /// True if `lo <= self < hi` in wrapping sequence space.
    #[inline]
    pub const fn in_half_open(self, lo: Self, hi: Self) -> bool {
        self.ge(lo) && self.lt(hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_wraparound_arithmetic() {
        let a = SeqNum(u32::MAX - 10);
        let b = a.add(25);
        assert_eq!(b.0, 14);
        assert!(a.lt(b));
        assert!(b.gt(a));
        assert_eq!(b.diff(a), 25);
        assert_eq!(a.diff(b), -25);
        assert!(SeqNum(0).in_half_open(a, b));
        assert!(!b.in_half_open(a, b));
    }
}
