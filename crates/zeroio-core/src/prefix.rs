//! Cache-friendly longest-prefix-match (LPM) CIDR index backed by sorted
//! arrays bucketed per populated prefix length.
//!
//! Each lookup executes at most one binary search per distinct populated
//! mask length (`0..=32` for IPv4, `0..=128` for IPv6), making query latency
//! insensitive to dense `/8` or `/16` prefix concentration without external
//! dependencies or `unsafe` code.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
struct PrefixBucket<V> {
    prefix_len: u8,
    mask: u128,
    entries: Vec<(u128, V)>,
}

#[derive(Clone, Debug)]
struct FamilyIndex<V> {
    /// Sorted by descending `prefix_len` so the first hit during lookup is
    /// guaranteed to be the longest matching prefix.
    buckets: Vec<PrefixBucket<V>>,
    total: usize,
}

impl<V> Default for FamilyIndex<V> {
    fn default() -> Self {
        Self {
            buckets: Vec::new(),
            total: 0,
        }
    }
}

const fn ipv4_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        (u32::MAX << (32 - prefix_len)) as u128
    }
}

const fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[inline]
fn ipv4_bits(ip: Ipv4Addr) -> u128 {
    u128::from(u32::from(ip))
}

#[inline]
fn ipv6_bits(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

impl<V> FamilyIndex<V> {
    fn build(mut entries: Vec<(u8, u128, V)>, mask_fn: fn(u8) -> u128) -> Self {
        entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        // Deduplicate identical `(prefix_len, masked_addr)` keeping the last inserted / sorted item?
        // Actually `sort_by` preserves relative order for equal keys, so deduplicating by keeping
        // the latest in insertion order works cleanly with `dedup_by` reversing or manual sweep.
        let mut buckets: Vec<PrefixBucket<V>> = Vec::new();
        let mut total = 0usize;

        for (prefix_len, raw_addr, val) in entries {
            let mask = mask_fn(prefix_len);
            let addr = raw_addr & mask;
            let bucket = match buckets.last_mut() {
                Some(b) if b.prefix_len == prefix_len => b,
                _ => {
                    buckets.push(PrefixBucket {
                        prefix_len,
                        mask,
                        entries: Vec::new(),
                    });
                    buckets.last_mut().unwrap()
                }
            };
            if let Some(last) = bucket.entries.last_mut()
                && last.0 == addr
            {
                last.1 = val;
            } else {
                bucket.entries.push((addr, val));
                total += 1;
            }
        }

        Self { buckets, total }
    }

    fn insert(&mut self, prefix_len: u8, addr_bits: u128, val: V, mask_fn: fn(u8) -> u128) {
        let mask = mask_fn(prefix_len);
        let key = addr_bits & mask;
        // Buckets are sorted in descending `prefix_len` order.
        let pos = self.buckets.partition_point(|b| b.prefix_len > prefix_len);
        if let Some(bucket) = self.buckets.get_mut(pos)
            && bucket.prefix_len == prefix_len
        {
            match bucket.entries.binary_search_by_key(&key, |&(k, _)| k) {
                Ok(idx) => bucket.entries[idx].1 = val,
                Err(idx) => {
                    bucket.entries.insert(idx, (key, val));
                    self.total += 1;
                }
            }
            return;
        }
        self.buckets.insert(
            pos,
            PrefixBucket {
                prefix_len,
                mask,
                entries: vec![(key, val)],
            },
        );
        self.total += 1;
    }

    fn remove(&mut self, prefix_len: u8, addr_bits: u128, mask_fn: fn(u8) -> u128) -> Option<V> {
        let mask = mask_fn(prefix_len);
        let key = addr_bits & mask;
        let pos = self.buckets.partition_point(|b| b.prefix_len > prefix_len);
        let bucket = self.buckets.get_mut(pos)?;
        if bucket.prefix_len != prefix_len {
            return None;
        }
        let idx = bucket
            .entries
            .binary_search_by_key(&key, |&(k, _)| k)
            .ok()?;
        let (_, removed) = bucket.entries.remove(idx);
        self.total -= 1;
        if bucket.entries.is_empty() {
            self.buckets.remove(pos);
        }
        Some(removed)
    }

    fn lookup(&self, addr_bits: u128) -> Option<(u8, &V)> {
        for bucket in &self.buckets {
            let key = addr_bits & bucket.mask;
            if let Ok(idx) = bucket.entries.binary_search_by_key(&key, |&(k, _)| k) {
                return Some((bucket.prefix_len, &bucket.entries[idx].1));
            }
        }
        None
    }

    fn overlaps(
        &self,
        addr_bits: u128,
        query_len: u8,
        max_bits: u8,
        mask_fn: fn(u8) -> u128,
    ) -> bool {
        let q_mask = mask_fn(query_len);
        let all_bits = mask_fn(max_bits);
        for bucket in &self.buckets {
            let first = addr_bits & q_mask & bucket.mask;
            let last = first | ((!q_mask & all_bits) & bucket.mask);
            let start = bucket.entries.partition_point(|&(k, _)| k < first);
            if bucket.entries.get(start).is_some_and(|&(k, _)| k <= last) {
                return true;
            }
        }
        false
    }
}

/// Pure safe, longest-prefix-match IPv4/IPv6 CIDR index backed by sorted
/// per-prefix-length buckets.
#[derive(Clone, Debug)]
pub struct PrefixIndex<V> {
    v4: FamilyIndex<V>,
    v6: FamilyIndex<V>,
}

impl<V> Default for PrefixIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> PrefixIndex<V> {
    /// Create an empty [`PrefixIndex`].
    pub fn new() -> Self {
        Self {
            v4: FamilyIndex::default(),
            v6: FamilyIndex::default(),
        }
    }

    /// Build a [`PrefixIndex`] in batch using `O(N log N)` sorting per address family.
    ///
    /// Invalid prefix lengths (`> 32` for IPv4 or `> 128` for IPv6) are ignored.
    pub fn from_entries(entries: impl IntoIterator<Item = (IpAddr, u8, V)>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (ip, prefix_len, val) in entries {
            match ip {
                IpAddr::V4(addr) if prefix_len <= 32 => {
                    v4.push((prefix_len, ipv4_bits(addr) & ipv4_mask(prefix_len), val));
                }
                IpAddr::V6(addr) if prefix_len <= 128 => {
                    v6.push((prefix_len, ipv6_bits(addr) & ipv6_mask(prefix_len), val));
                }
                _ => {}
            }
        }
        Self {
            v4: FamilyIndex::build(v4, ipv4_mask),
            v6: FamilyIndex::build(v6, ipv6_mask),
        }
    }

    /// Number of stored CIDR entries across both IPv4 and IPv6.
    pub fn len(&self) -> usize {
        self.v4.total + self.v6.total
    }

    /// Returns `true` when the index contains no prefixes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all stored prefixes.
    pub fn clear(&mut self) {
        self.v4 = FamilyIndex::default();
        self.v6 = FamilyIndex::default();
    }

    /// Insert or overwrite a prefix `(ip, prefix_len)`. Returns `false` if `prefix_len`
    /// is out of bounds (`> 32` for IPv4 or `> 128` for IPv6).
    pub fn insert(&mut self, ip: IpAddr, prefix_len: u8, value: V) -> bool {
        match ip {
            IpAddr::V4(addr) if prefix_len <= 32 => {
                self.v4
                    .insert(prefix_len, ipv4_bits(addr), value, ipv4_mask);
                true
            }
            IpAddr::V6(addr) if prefix_len <= 128 => {
                self.v6
                    .insert(prefix_len, ipv6_bits(addr), value, ipv6_mask);
                true
            }
            _ => false,
        }
    }

    /// Remove an exact prefix `(ip, prefix_len)` if present.
    pub fn remove(&mut self, ip: IpAddr, prefix_len: u8) -> Option<V> {
        match ip {
            IpAddr::V4(addr) if prefix_len <= 32 => {
                self.v4.remove(prefix_len, ipv4_bits(addr), ipv4_mask)
            }
            IpAddr::V6(addr) if prefix_len <= 128 => {
                self.v6.remove(prefix_len, ipv6_bits(addr), ipv6_mask)
            }
            _ => None,
        }
    }

    /// Longest-prefix match lookup for `ip`, returning `(matched_prefix_len, &value)`.
    pub fn lookup(&self, ip: IpAddr) -> Option<(u8, &V)> {
        match ip {
            IpAddr::V4(addr) => self.v4.lookup(ipv4_bits(addr)),
            IpAddr::V6(addr) => self.v6.lookup(ipv6_bits(addr)),
        }
    }

    /// Return `true` if any indexed prefix overlaps `(ip, prefix_len)`.
    pub fn overlaps(&self, ip: IpAddr, prefix_len: u8) -> bool {
        match ip {
            IpAddr::V4(addr) if prefix_len <= 32 => {
                self.v4.overlaps(ipv4_bits(addr), prefix_len, 32, ipv4_mask)
            }
            IpAddr::V6(addr) if prefix_len <= 128 => {
                self.v6
                    .overlaps(ipv6_bits(addr), prefix_len, 128, ipv6_mask)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_match_and_overlaps() {
        let mut idx = PrefixIndex::from_entries([
            ("0.0.0.0".parse().unwrap(), 0, "default-v4"),
            ("10.0.0.0".parse().unwrap(), 8, "corp"),
            ("10.20.0.0".parse().unwrap(), 16, "region"),
            ("10.20.30.40".parse().unwrap(), 32, "host"),
            ("2001:db8::".parse().unwrap(), 32, "doc-v6"),
            ("2001:db8:abcd::".parse().unwrap(), 48, "tenant-v6"),
        ]);
        assert_eq!(idx.len(), 6);

        assert_eq!(
            idx.lookup("10.20.30.40".parse().unwrap()),
            Some((32, &"host"))
        );
        assert_eq!(
            idx.lookup("10.20.99.1".parse().unwrap()),
            Some((16, &"region"))
        );
        assert_eq!(idx.lookup("10.99.1.1".parse().unwrap()), Some((8, &"corp")));
        assert_eq!(
            idx.lookup("192.0.2.1".parse().unwrap()),
            Some((0, &"default-v4"))
        );
        assert_eq!(
            idx.lookup("2001:db8:abcd:1::5".parse().unwrap()),
            Some((48, &"tenant-v6"))
        );
        assert_eq!(
            idx.lookup("2001:db8:1::1".parse().unwrap()),
            Some((32, &"doc-v6"))
        );
        assert_eq!(idx.lookup("2001:db9::1".parse().unwrap()), None);

        assert!(idx.overlaps("10.20.30.0".parse().unwrap(), 24));
        assert!(!idx.overlaps("2001:db9::".parse().unwrap(), 32));

        assert_eq!(idx.remove("10.20.30.40".parse().unwrap(), 32), Some("host"));
        assert_eq!(
            idx.lookup("10.20.30.40".parse().unwrap()),
            Some((16, &"region"))
        );

        assert!(idx.insert("192.168.1.99".parse().unwrap(), 24, "lan"));
        assert_eq!(
            idx.lookup("192.168.1.1".parse().unwrap()),
            Some((24, &"lan"))
        );
        assert!(!idx.insert("1.2.3.4".parse().unwrap(), 33, "bad"));
    }
}
