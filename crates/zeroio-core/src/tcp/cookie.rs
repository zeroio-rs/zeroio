//! Stateless keyed SYN cookie generation & verification (RFC 4987) using
//! pure safe SipHash-2-4 (`#![forbid(unsafe_code)]`).

use crate::TransportInstant;
use core::net::SocketAddr;

/// Standard MSS tiers encoded into 3 bits of the SYN cookie.
pub const COOKIE_MSS_TABLE: [u16; 8] = [536, 1200, 1280, 1380, 1400, 1440, 1460, 8960];

/// Secret key for stateless SYN cookie generation.
#[derive(Clone, Copy, Debug)]
pub struct SynCookieKey {
    k0: u64,
    k1: u64,
}

impl SynCookieKey {
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// Derive a deterministic test/default key from a seed (callers in production
    /// should supply a CSPRNG key).
    pub const fn from_seed(seed: [u8; 16]) -> Self {
        let k0 = u64::from_le_bytes([
            seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7],
        ]);
        let k1 = u64::from_le_bytes([
            seed[8], seed[9], seed[10], seed[11], seed[12], seed[13], seed[14], seed[15],
        ]);
        Self { k0, k1 }
    }
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

fn siphash24_u64s(key: SynCookieKey, words: &[u64]) -> u64 {
    let mut v0 = 0x736f_6d65_7073_6575 ^ key.k0;
    let mut v1 = 0x646f_7261_6e64_6f6d ^ key.k1;
    let mut v2 = 0x6c79_6765_6e65_7261 ^ key.k0;
    let mut v3 = 0x7465_6462_7974_6573 ^ key.k1;

    for &m in words {
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let b = ((words.len() * 8) as u64) << 56;
    v3 ^= b;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;

    v2 ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn addr_words(addr: SocketAddr) -> [u64; 3] {
    match addr {
        SocketAddr::V4(v4) => [u64::from(u32::from(*v4.ip())), 0, u64::from(v4.port())],
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            let hi = u64::from_be_bytes([
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6],
                octets[7],
            ]);
            let lo = u64::from_be_bytes([
                octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14],
                octets[15],
            ]);
            [hi, lo, u64::from(v6.port())]
        }
    }
}

fn mss_to_index(mss: u16) -> u8 {
    let mut best = 0u8;
    for (idx, &val) in COOKIE_MSS_TABLE.iter().enumerate() {
        if val <= mss {
            best = idx as u8;
        }
    }
    best
}

#[inline]
fn time_bucket(now: TransportInstant) -> u32 {
    // 64-second ticks mod 32 (~34 minute wrap).
    ((now.micros() / 64_000_000) & 0x1F) as u32
}

fn cookie_mac(
    key: SynCookieKey,
    local: SocketAddr,
    peer: SocketAddr,
    peer_isn: u32,
    bucket: u32,
    mss_idx: u8,
) -> u32 {
    let l = addr_words(local);
    let p = addr_words(peer);
    let words = [
        l[0],
        l[1],
        l[2],
        p[0],
        p[1],
        p[2],
        u64::from(peer_isn),
        (u64::from(bucket) << 3) | u64::from(mss_idx & 0x07),
    ];
    (siphash24_u64s(key, &words) & 0x00FF_FFFF) as u32
}

/// Generate a 32-bit server ISN encoding `(bucket: 5b | mss_idx: 3b | mac: 24b)`.
pub fn generate_syn_cookie(
    key: SynCookieKey,
    local: SocketAddr,
    peer: SocketAddr,
    peer_isn: u32,
    peer_mss: u16,
    now: TransportInstant,
) -> (u32, u16) {
    let bucket = time_bucket(now);
    let mss_idx = mss_to_index(peer_mss);
    let mac = cookie_mac(key, local, peer, peer_isn, bucket, mss_idx);
    let isn = (bucket << 27) | (u32::from(mss_idx & 0x07) << 24) | mac;
    (isn, COOKIE_MSS_TABLE[usize::from(mss_idx)])
}

/// Verify an incoming ACK (`ack_num = server_isn + 1`, `seq_num = peer_isn + 1`).
/// Returns the encoded peer MSS tier when valid within the last 2 time buckets (~128s).
pub fn verify_syn_cookie(
    key: SynCookieKey,
    local: SocketAddr,
    peer: SocketAddr,
    seq_num: u32,
    ack_num: u32,
    now: TransportInstant,
) -> Option<u16> {
    let server_isn = ack_num.wrapping_sub(1);
    let peer_isn = seq_num.wrapping_sub(1);
    let bucket = (server_isn >> 27) & 0x1F;
    let mss_idx = ((server_isn >> 24) & 0x07) as u8;
    let mac = server_isn & 0x00FF_FFFF;

    let cur_bucket = time_bucket(now);
    let age = cur_bucket.wrapping_sub(bucket) & 0x1F;
    if age > 2 {
        return None;
    }
    let expected = cookie_mac(key, local, peer, peer_isn, bucket, mss_idx);
    if mac == expected {
        Some(COOKIE_MSS_TABLE[usize::from(mss_idx)])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_cookie_roundtrip_expiry_and_tamper_rejection() {
        let key = SynCookieKey::from_seed(*b"zeroio-cookie-01");
        let local: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let peer: SocketAddr = "198.51.100.9:54321".parse().unwrap();
        let t0 = TransportInstant::from_micros(100_000_000);

        let (isn, mss) = generate_syn_cookie(key, local, peer, 0xABCD_0001, 1460, t0);
        assert_eq!(mss, 1460);

        // Valid within same bucket and +1 bucket.
        assert_eq!(
            verify_syn_cookie(key, local, peer, 0xABCD_0002, isn.wrapping_add(1), t0),
            Some(1460)
        );
        let t1 = TransportInstant::from_micros(164_000_000);
        assert_eq!(
            verify_syn_cookie(key, local, peer, 0xABCD_0002, isn.wrapping_add(1), t1),
            Some(1460)
        );

        // Tampered port or seq fails.
        let bad_peer: SocketAddr = "198.51.100.9:54322".parse().unwrap();
        assert_eq!(
            verify_syn_cookie(key, local, bad_peer, 0xABCD_0002, isn.wrapping_add(1), t0),
            None
        );
        assert_eq!(
            verify_syn_cookie(key, local, peer, 0xABCD_0003, isn.wrapping_add(1), t0),
            None
        );

        // Expired after >2 buckets (~192s).
        let expired = TransportInstant::from_micros(300_000_000);
        assert_eq!(
            verify_syn_cookie(key, local, peer, 0xABCD_0002, isn.wrapping_add(1), expired),
            None
        );
    }
}
