//! Zero-copy L2/L3/L4 packet header inspection, RFC 1071 checksums, TCP option
//! codecs, and zero-allocation frame encoding for Ethernet, VLAN, IPv4/IPv6,
//! TCP, and UDP frames.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Ethernet frame type constants.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_QINQ: u16 = 0x88A8;

/// IP transport protocol numbers.
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;

/// Standard TCP flag bits (byte 13 of the TCP header).
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

/// Maximum TCP header options length in bytes (40 bytes = 10 × 32-bit words).
pub const MAX_TCP_OPTIONS_LEN: usize = 40;

/// Maximum SACK blocks that fit in a standard 40-byte TCP options header.
pub const MAX_SACK_BLOCKS: usize = 4;

/// A single RFC 2018 TCP SACK block (`[left, right)` in wrapping 32-bit sequence space).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

/// Decoded TCP header options (zero-allocation fixed storage).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<(u32, u32)>,
    pub sack_blocks: [SackBlock; MAX_SACK_BLOCKS],
    pub sack_len: u8,
}

impl TcpOptions {
    /// Parse TCP header options strictly; returns `None` on malformed length fields.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TCP_OPTIONS_LEN {
            return None;
        }
        let mut opts = Self::default();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let kind = bytes[pos];
            match kind {
                // End of Option List
                0 => break,
                // No-Operation
                1 => {
                    pos += 1;
                }
                _ => {
                    if pos + 1 >= bytes.len() {
                        return None;
                    }
                    let len = usize::from(bytes[pos + 1]);
                    if len < 2 || pos + len > bytes.len() {
                        return None;
                    }
                    let data = &bytes[pos + 2..pos + len];
                    match kind {
                        // MSS (kind 2, len 4)
                        2 => {
                            if len != 4 {
                                return None;
                            }
                            opts.mss = Some(u16::from_be_bytes([data[0], data[1]]));
                        }
                        // Window Scale (kind 3, len 3; RFC 7323 caps shift at 14)
                        3 => {
                            if len != 3 {
                                return None;
                            }
                            opts.window_scale = Some(data[0].min(14));
                        }
                        // SACK Permitted (kind 4, len 2)
                        4 => {
                            if len != 2 {
                                return None;
                            }
                            opts.sack_permitted = true;
                        }
                        // SACK blocks (kind 5, len = 2 + 8*n)
                        5 => {
                            if (len - 2) % 8 != 0 || len == 2 {
                                return None;
                            }
                            let count = ((len - 2) / 8).min(MAX_SACK_BLOCKS);
                            let mut i = 0usize;
                            while i < count && usize::from(opts.sack_len) < MAX_SACK_BLOCKS {
                                let base = i * 8;
                                let left = u32::from_be_bytes([
                                    data[base],
                                    data[base + 1],
                                    data[base + 2],
                                    data[base + 3],
                                ]);
                                let right = u32::from_be_bytes([
                                    data[base + 4],
                                    data[base + 5],
                                    data[base + 6],
                                    data[base + 7],
                                ]);
                                opts.sack_blocks[usize::from(opts.sack_len)] =
                                    SackBlock { left, right };
                                opts.sack_len += 1;
                                i += 1;
                            }
                        }
                        // Timestamps (kind 8, len 10)
                        8 => {
                            if len != 10 {
                                return None;
                            }
                            let tsval = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                            let tsecr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                            opts.timestamps = Some((tsval, tsecr));
                        }
                        // Unknown option: skip safely.
                        _ => {}
                    }
                    pos += len;
                }
            }
        }
        Some(opts)
    }

    /// Borrow parsed SACK blocks.
    pub fn sack_slice(&self) -> &[SackBlock] {
        &self.sack_blocks[..usize::from(self.sack_len).min(MAX_SACK_BLOCKS)]
    }

    /// Append a SACK block if space remains (up to [`MAX_SACK_BLOCKS`]).
    pub fn push_sack(&mut self, block: SackBlock) -> bool {
        let idx = usize::from(self.sack_len);
        if idx >= MAX_SACK_BLOCKS {
            return false;
        }
        self.sack_blocks[idx] = block;
        self.sack_len += 1;
        true
    }

    /// Encode options into `out`, 4-byte aligned with NOP/EOL padding.
    /// Returns `None` if `out` is too small or encoded options exceed 40 bytes.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut pos = 0usize;
        if let Some(mss) = self.mss {
            if pos + 4 > out.len() || pos + 4 > MAX_TCP_OPTIONS_LEN {
                return None;
            }
            out[pos] = 2;
            out[pos + 1] = 4;
            out[pos + 2..pos + 4].copy_from_slice(&mss.to_be_bytes());
            pos += 4;
        }
        if let Some(ws) = self.window_scale {
            if pos + 3 > out.len() || pos + 3 > MAX_TCP_OPTIONS_LEN {
                return None;
            }
            out[pos] = 3;
            out[pos + 1] = 3;
            out[pos + 2] = ws.min(14);
            pos += 3;
        }
        if self.sack_permitted {
            if pos + 2 > out.len() || pos + 2 > MAX_TCP_OPTIONS_LEN {
                return None;
            }
            out[pos] = 4;
            out[pos + 1] = 2;
            pos += 2;
        }
        if let Some((tsval, tsecr)) = self.timestamps {
            if pos + 10 > out.len() || pos + 10 > MAX_TCP_OPTIONS_LEN {
                return None;
            }
            out[pos] = 8;
            out[pos + 1] = 10;
            out[pos + 2..pos + 6].copy_from_slice(&tsval.to_be_bytes());
            out[pos + 6..pos + 10].copy_from_slice(&tsecr.to_be_bytes());
            pos += 10;
        }
        let sack_count = usize::from(self.sack_len).min(MAX_SACK_BLOCKS);
        if sack_count > 0 {
            let max_fit = (MAX_TCP_OPTIONS_LEN.saturating_sub(pos).saturating_sub(2)) / 8;
            let count = sack_count.min(max_fit);
            if count > 0 {
                let opt_len = 2 + count * 8;
                if pos + opt_len > out.len() || pos + opt_len > MAX_TCP_OPTIONS_LEN {
                    return None;
                }
                out[pos] = 5;
                out[pos + 1] = opt_len as u8;
                pos += 2;
                for block in &self.sack_blocks[..count] {
                    out[pos..pos + 4].copy_from_slice(&block.left.to_be_bytes());
                    out[pos + 4..pos + 8].copy_from_slice(&block.right.to_be_bytes());
                    pos += 8;
                }
            }
        }
        let padded = (pos + 3) & !3;
        if padded > out.len() || padded > MAX_TCP_OPTIONS_LEN {
            return None;
        }
        for b in &mut out[pos..padded] {
            *b = 1; // NOP padding to 4-byte boundary
        }
        Some(padded)
    }
}

/// Zero-copy view over a parsed TCP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpHeaderView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: usize,
    pub flags: u8,
    pub ae: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options_bytes: &'a [u8],
}

impl<'a> TcpHeaderView<'a> {
    /// Decode the TCP options slice without heap allocation.
    pub fn parse_options(&self) -> Option<TcpOptions> {
        TcpOptions::parse(self.options_bytes)
    }

    /// Extract the 3-bit `(AE, CWR, ECE)` value used by RFC 9768 AccECN.
    pub fn ace_bits(&self) -> u8 {
        let ae = u8::from(self.ae) << 2;
        let cwr = u8::from((self.flags & TCP_FLAG_CWR) != 0) << 1;
        let ece = u8::from((self.flags & TCP_FLAG_ECE) != 0);
        ae | cwr | ece
    }
}

/// Parsed L2/L3/L4 offsets and addresses referencing an immutable frame slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketView<'a> {
    pub frame: &'a [u8],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub l3_offset: usize,
    pub l4_offset: usize,
    pub payload_offset: usize,
    pub ip_end: usize,
    pub proto: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
}

impl<'a> PacketView<'a> {
    /// Parse an Ethernet + IPv4/IPv6 + TCP/UDP frame without copying bytes.
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < 14 {
            return None;
        }
        let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let mut offset = 14usize;
        let mut vlan_id = None;

        for _ in 0..2 {
            if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
                if frame.len() < offset + 4 {
                    return None;
                }
                let tci = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
                if vlan_id.is_none() {
                    vlan_id = Some(tci & 0x0FFF);
                }
                ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
                offset += 4;
            } else {
                break;
            }
        }

        let l3_offset = offset;
        let (proto, src_ip, dst_ip, l4_offset, ip_end) = match ethertype {
            ETHERTYPE_IPV4 => {
                if frame.len() < l3_offset + 20 {
                    return None;
                }
                let vihl = frame[l3_offset];
                if (vihl >> 4) != 4 {
                    return None;
                }
                let ihl = usize::from(vihl & 0x0F) * 4;
                let total_len = usize::from(u16::from_be_bytes([
                    frame[l3_offset + 2],
                    frame[l3_offset + 3],
                ]));
                if ihl < 20 || total_len < ihl || frame.len() < l3_offset + total_len {
                    return None;
                }
                let frag = u16::from_be_bytes([frame[l3_offset + 6], frame[l3_offset + 7]]);
                // Reject fragmented IPv4 packets in the fast-path parser.
                if (frag & 0x3FFF) != 0 {
                    return None;
                }
                let proto = frame[l3_offset + 9];
                let src = IpAddr::V4(Ipv4Addr::new(
                    frame[l3_offset + 12],
                    frame[l3_offset + 13],
                    frame[l3_offset + 14],
                    frame[l3_offset + 15],
                ));
                let dst = IpAddr::V4(Ipv4Addr::new(
                    frame[l3_offset + 16],
                    frame[l3_offset + 17],
                    frame[l3_offset + 18],
                    frame[l3_offset + 19],
                ));
                (proto, src, dst, l3_offset + ihl, l3_offset + total_len)
            }
            ETHERTYPE_IPV6 => {
                if frame.len() < l3_offset + 40 {
                    return None;
                }
                if (frame[l3_offset] >> 4) != 6 {
                    return None;
                }
                let payload_len = usize::from(u16::from_be_bytes([
                    frame[l3_offset + 4],
                    frame[l3_offset + 5],
                ]));
                let ip_end = l3_offset + 40 + payload_len;
                if frame.len() < ip_end {
                    return None;
                }
                let proto = frame[l3_offset + 6];
                let mut src_bytes = [0u8; 16];
                let mut dst_bytes = [0u8; 16];
                src_bytes.copy_from_slice(&frame[l3_offset + 8..l3_offset + 24]);
                dst_bytes.copy_from_slice(&frame[l3_offset + 24..l3_offset + 40]);
                (
                    proto,
                    IpAddr::V6(Ipv6Addr::from(src_bytes)),
                    IpAddr::V6(Ipv6Addr::from(dst_bytes)),
                    l3_offset + 40,
                    ip_end,
                )
            }
            _ => return None,
        };

        let (src_port, dst_port, tcp_flags, payload_offset) = match proto {
            IP_PROTO_TCP => {
                if ip_end < l4_offset + 20 {
                    return None;
                }
                let src_port = u16::from_be_bytes([frame[l4_offset], frame[l4_offset + 1]]);
                let dst_port = u16::from_be_bytes([frame[l4_offset + 2], frame[l4_offset + 3]]);
                let data_offset = usize::from(frame[l4_offset + 12] >> 4) * 4;
                if data_offset < 20 || ip_end < l4_offset + data_offset {
                    return None;
                }
                let tcp_flags = frame[l4_offset + 13];
                (src_port, dst_port, tcp_flags, l4_offset + data_offset)
            }
            IP_PROTO_UDP => {
                if ip_end < l4_offset + 8 {
                    return None;
                }
                let src_port = u16::from_be_bytes([frame[l4_offset], frame[l4_offset + 1]]);
                let dst_port = u16::from_be_bytes([frame[l4_offset + 2], frame[l4_offset + 3]]);
                let udp_len = usize::from(u16::from_be_bytes([
                    frame[l4_offset + 4],
                    frame[l4_offset + 5],
                ]));
                if udp_len < 8 || ip_end < l4_offset + udp_len {
                    return None;
                }
                (src_port, dst_port, 0, l4_offset + 8)
            }
            _ => return None,
        };

        Some(Self {
            frame,
            ethertype,
            vlan_id,
            l3_offset,
            l4_offset,
            payload_offset,
            ip_end,
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
        })
    }

    /// Borrow the L4 payload slice without copying.
    pub fn payload(&self) -> &'a [u8] {
        if self.proto == IP_PROTO_UDP && self.l4_offset + 8 <= self.ip_end {
            let udp_len = usize::from(u16::from_be_bytes([
                self.frame[self.l4_offset + 4],
                self.frame[self.l4_offset + 5],
            ]));
            let udp_end = (self.l4_offset + udp_len).min(self.ip_end);
            return &self.frame[self.payload_offset..udp_end];
        }
        &self.frame[self.payload_offset..self.ip_end]
    }

    /// Source MAC address from the Ethernet header.
    pub fn src_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.frame[6..12]);
        mac
    }

    /// Destination MAC address from the Ethernet header.
    pub fn dst_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.frame[0..6]);
        mac
    }

    /// Extract the 2-bit IP ECN field (RFC 3168: 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE).
    pub fn ip_ecn(&self) -> u8 {
        match self.ethertype {
            ETHERTYPE_IPV4 => self.frame[self.l3_offset + 1] & 0x03,
            ETHERTYPE_IPV6 => {
                let tc = ((self.frame[self.l3_offset] & 0x0F) << 4)
                    | (self.frame[self.l3_offset + 1] >> 4);
                tc & 0x03
            }
            _ => 0,
        }
    }

    /// Decode the TCP header if this packet is TCP.
    pub fn tcp_header(&self) -> Option<TcpHeaderView<'a>> {
        if self.proto != IP_PROTO_TCP || self.ip_end < self.l4_offset + 20 {
            return None;
        }
        let h = &self.frame[self.l4_offset..];
        let data_offset = usize::from(h[12] >> 4) * 4;
        if data_offset < 20 || self.ip_end < self.l4_offset + data_offset {
            return None;
        }
        Some(TcpHeaderView {
            src_port: self.src_port,
            dst_port: self.dst_port,
            seq: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            ack: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
            data_offset,
            flags: h[13],
            ae: (h[12] & 0x01) != 0,
            window: u16::from_be_bytes([h[14], h[15]]),
            checksum: u16::from_be_bytes([h[16], h[17]]),
            urgent_ptr: u16::from_be_bytes([h[18], h[19]]),
            options_bytes: &h[20..data_offset],
        })
    }

    /// Verify IPv4 header checksum (returns `true` for IPv6 which has no header checksum).
    pub fn verify_ipv4_checksum(&self) -> bool {
        if self.ethertype != ETHERTYPE_IPV4 {
            return true;
        }
        let hdr = &self.frame[self.l3_offset..self.l4_offset];
        internet_checksum(&[hdr]) == 0
    }

    /// Verify TCP or UDP checksum over the IPv4/IPv6 pseudo-header.
    pub fn verify_l4_checksum(&self) -> bool {
        let l4 = &self.frame[self.l4_offset..self.ip_end];
        if self.proto == IP_PROTO_UDP && self.ethertype == ETHERTYPE_IPV4 {
            let cksum = u16::from_be_bytes([l4[6], l4[7]]);
            if cksum == 0 {
                // RFC 768 allows UDP checksum 0 over IPv4 ("checksum disabled").
                return true;
            }
        }
        l4_pseudo_checksum(self.src_ip, self.dst_ip, self.proto, l4) == 0
    }

    /// Verify both L3 (IPv4) and L4 (TCP/UDP) checksums.
    pub fn verify_checksums(&self) -> bool {
        self.verify_ipv4_checksum() && self.verify_l4_checksum()
    }

    /// Source socket address.
    pub fn src_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    /// Destination socket address.
    pub fn dst_addr(&self) -> SocketAddr {
        SocketAddr::new(self.dst_ip, self.dst_port)
    }
}

/// Fold a 32-bit one's-complement sum into a 16-bit RFC 1071 checksum.
fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn sum_bytes(acc: &mut u32, bytes: &[u8]) {
    let (chunks, rem) = bytes.as_chunks::<2>();
    for c in chunks {
        *acc += u32::from(u16::from_be_bytes(*c));
    }
    if let Some(&b) = rem.first() {
        *acc += u32::from(u16::from_be_bytes([b, 0]));
    }
}

/// Compute the RFC 1071 Internet checksum across one or more contiguous slices.
pub fn internet_checksum(slices: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut carry_odd: Option<u8> = None;
    for &slice in slices {
        let mut s = slice;
        if let Some(prev) = carry_odd.take() {
            if let Some((&first, rest)) = s.split_first() {
                sum += u32::from(u16::from_be_bytes([prev, first]));
                s = rest;
            } else {
                carry_odd = Some(prev);
                continue;
            }
        }
        let (chunks, rem) = s.as_chunks::<2>();
        for c in chunks {
            sum += u32::from(u16::from_be_bytes(*c));
        }
        if let Some(&b) = rem.first() {
            carry_odd = Some(b);
        }
    }
    if let Some(rem) = carry_odd {
        sum += u32::from(u16::from_be_bytes([rem, 0]));
    }
    fold_checksum(sum)
}

/// Compute the TCP/UDP checksum including the IPv4 or IPv6 pseudo-header.
pub fn l4_pseudo_checksum(src: IpAddr, dst: IpAddr, proto: u8, l4_bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum_bytes(&mut sum, &s.octets());
            sum_bytes(&mut sum, &d.octets());
            sum += u32::from(proto);
            sum += l4_bytes.len() as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            sum_bytes(&mut sum, &s.octets());
            sum_bytes(&mut sum, &d.octets());
            let len_be = (l4_bytes.len() as u32).to_be_bytes();
            sum_bytes(&mut sum, &len_be);
            sum += u32::from(proto);
        }
        _ => return 0xFFFF,
    }
    sum_bytes(&mut sum, l4_bytes);
    fold_checksum(sum)
}

/// Errors returned by zero-allocation frame encoders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameEncodeError {
    /// Destination buffer is smaller than the encoded frame.
    BufferTooSmall,
    /// Source and destination IP families do not match.
    AddressFamilyMismatch,
    /// TCP options failed validation or exceeded 40 bytes.
    InvalidOptions,
    /// Frame exceeds the maximum IPv4/IPv6 single-packet length.
    PayloadTooLarge,
}

/// Parameters for encoding an Ethernet + IPv4/IPv6 + TCP packet.
#[derive(Clone, Copy, Debug)]
pub struct TcpFrameSpec<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_ecn: u8,
    pub ttl: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ae: bool,
    pub window: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

/// Parameters for encoding an Ethernet + IPv4/IPv6 + UDP packet.
#[derive(Clone, Copy, Debug)]
pub struct UdpFrameSpec<'a> {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_ecn: u8,
    pub ttl: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

fn write_l2_header(
    out: &mut [u8],
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_id: Option<u16>,
    ethertype: u16,
) -> Result<usize, FrameEncodeError> {
    let l2_len = if vlan_id.is_some() { 18 } else { 14 };
    if out.len() < l2_len {
        return Err(FrameEncodeError::BufferTooSmall);
    }
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(&src_mac);
    if let Some(vid) = vlan_id {
        out[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        out[14..16].copy_from_slice(&(vid & 0x0FFF).to_be_bytes());
        out[16..18].copy_from_slice(&ethertype.to_be_bytes());
    } else {
        out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    }
    Ok(l2_len)
}

struct L3HeaderParams {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ip_ecn: u8,
    ttl: u8,
    proto: u8,
    l4_total_len: usize,
}

fn write_l3_header(
    out: &mut [u8],
    l3_offset: usize,
    p: L3HeaderParams,
) -> Result<usize, FrameEncodeError> {
    match (p.src_ip, p.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total_len = 20 + p.l4_total_len;
            if total_len > usize::from(u16::MAX) {
                return Err(FrameEncodeError::PayloadTooLarge);
            }
            if out.len() < l3_offset + total_len {
                return Err(FrameEncodeError::BufferTooSmall);
            }
            let h = &mut out[l3_offset..l3_offset + 20];
            h[0] = 0x45;
            h[1] = p.ip_ecn & 0x03;
            h[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            h[4..6].copy_from_slice(&0u16.to_be_bytes());
            h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
            h[8] = p.ttl;
            h[9] = p.proto;
            h[10..12].copy_from_slice(&0u16.to_be_bytes());
            h[12..16].copy_from_slice(&s.octets());
            h[16..20].copy_from_slice(&d.octets());
            let cksum = internet_checksum(&[h]);
            h[10..12].copy_from_slice(&cksum.to_be_bytes());
            Ok(l3_offset + 20)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            if p.l4_total_len > usize::from(u16::MAX) {
                return Err(FrameEncodeError::PayloadTooLarge);
            }
            let total_len = 40 + p.l4_total_len;
            if out.len() < l3_offset + total_len {
                return Err(FrameEncodeError::BufferTooSmall);
            }
            let h = &mut out[l3_offset..l3_offset + 40];
            let ecn = p.ip_ecn & 0x03;
            h[0] = 0x60 | (ecn >> 4);
            h[1] = ecn << 4;
            h[2] = 0;
            h[3] = 0;
            h[4..6].copy_from_slice(&(p.l4_total_len as u16).to_be_bytes());
            h[6] = p.proto;
            h[7] = p.ttl;
            h[8..24].copy_from_slice(&s.octets());
            h[24..40].copy_from_slice(&d.octets());
            Ok(l3_offset + 40)
        }
        _ => Err(FrameEncodeError::AddressFamilyMismatch),
    }
}

/// Encode a complete Ethernet + IPv4/IPv6 + TCP frame from two payload slices
/// (e.g. a ring-buffer wrap) into `out` without heap allocation.
pub fn encode_tcp_frame_parts(
    out: &mut [u8],
    spec: &TcpFrameSpec<'_>,
    part1: &[u8],
    part2: &[u8],
) -> Result<usize, FrameEncodeError> {
    let ethertype = match (spec.src_ip, spec.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => ETHERTYPE_IPV4,
        (IpAddr::V6(_), IpAddr::V6(_)) => ETHERTYPE_IPV6,
        _ => return Err(FrameEncodeError::AddressFamilyMismatch),
    };
    let mut opt_buf = [0u8; MAX_TCP_OPTIONS_LEN];
    let opt_len = spec
        .options
        .encode(&mut opt_buf)
        .ok_or(FrameEncodeError::InvalidOptions)?;
    let tcp_hdr_len = 20 + opt_len;
    let payload_len = part1.len() + part2.len();
    let l4_total_len = tcp_hdr_len + payload_len;
    let l3_offset = write_l2_header(out, spec.src_mac, spec.dst_mac, spec.vlan_id, ethertype)?;
    let l4_offset = write_l3_header(
        out,
        l3_offset,
        L3HeaderParams {
            src_ip: spec.src_ip,
            dst_ip: spec.dst_ip,
            ip_ecn: spec.ip_ecn,
            ttl: spec.ttl,
            proto: IP_PROTO_TCP,
            l4_total_len,
        },
    )?;
    let frame_end = l4_offset + l4_total_len;
    if out.len() < frame_end {
        return Err(FrameEncodeError::BufferTooSmall);
    }
    let tcp = &mut out[l4_offset..frame_end];
    tcp[0..2].copy_from_slice(&spec.src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&spec.dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&spec.seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&spec.ack.to_be_bytes());
    let data_words = (tcp_hdr_len / 4) as u8;
    tcp[12] = (data_words << 4) | u8::from(spec.ae);
    tcp[13] = spec.flags;
    tcp[14..16].copy_from_slice(&spec.window.to_be_bytes());
    tcp[16..18].copy_from_slice(&0u16.to_be_bytes());
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
    if opt_len > 0 {
        tcp[20..tcp_hdr_len].copy_from_slice(&opt_buf[..opt_len]);
    }
    let p1_end = tcp_hdr_len + part1.len();
    if !part1.is_empty() {
        tcp[tcp_hdr_len..p1_end].copy_from_slice(part1);
    }
    if !part2.is_empty() {
        tcp[p1_end..].copy_from_slice(part2);
    }
    let cksum = l4_pseudo_checksum(spec.src_ip, spec.dst_ip, IP_PROTO_TCP, tcp);
    tcp[16..18].copy_from_slice(&cksum.to_be_bytes());
    Ok(frame_end)
}

/// Encode a complete Ethernet + IPv4/IPv6 + TCP frame into `out` without heap allocation.
pub fn encode_tcp_frame(
    out: &mut [u8],
    spec: &TcpFrameSpec<'_>,
) -> Result<usize, FrameEncodeError> {
    encode_tcp_frame_parts(out, spec, spec.payload, &[])
}

/// Encode a complete Ethernet + IPv4/IPv6 + UDP frame into `out` without heap allocation.
pub fn encode_udp_frame(
    out: &mut [u8],
    spec: &UdpFrameSpec<'_>,
) -> Result<usize, FrameEncodeError> {
    let ethertype = match (spec.src_ip, spec.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => ETHERTYPE_IPV4,
        (IpAddr::V6(_), IpAddr::V6(_)) => ETHERTYPE_IPV6,
        _ => return Err(FrameEncodeError::AddressFamilyMismatch),
    };
    let l4_total_len = 8 + spec.payload.len();
    let l3_offset = write_l2_header(out, spec.src_mac, spec.dst_mac, spec.vlan_id, ethertype)?;
    let l4_offset = write_l3_header(
        out,
        l3_offset,
        L3HeaderParams {
            src_ip: spec.src_ip,
            dst_ip: spec.dst_ip,
            ip_ecn: spec.ip_ecn,
            ttl: spec.ttl,
            proto: IP_PROTO_UDP,
            l4_total_len,
        },
    )?;
    let frame_end = l4_offset + l4_total_len;
    if out.len() < frame_end {
        return Err(FrameEncodeError::BufferTooSmall);
    }
    let udp = &mut out[l4_offset..frame_end];
    udp[0..2].copy_from_slice(&spec.src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&spec.dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(l4_total_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes());
    if !spec.payload.is_empty() {
        udp[8..].copy_from_slice(spec.payload);
    }
    let mut cksum = l4_pseudo_checksum(spec.src_ip, spec.dst_ip, IP_PROTO_UDP, udp);
    if cksum == 0 {
        // RFC 768 / RFC 8200: transmitted UDP checksum of 0 must be sent as 0xFFFF.
        cksum = 0xFFFF;
    }
    udp[6..8].copy_from_slice(&cksum.to_be_bytes());
    Ok(frame_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vlan_ipv4_tcp_payload() {
        let mut frame = Vec::new();
        // Dst MAC, Src MAC, 802.1Q tag (VLAN 42), IPv4 ethertype
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&[0xbb; 6]);
        frame.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        frame.extend_from_slice(&42u16.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // IPv4 header (20B) + TCP header (20B) + "hello" (5B) = 45B
        frame.extend_from_slice(&[
            0x45,
            0x00,
            0x00,
            45,
            0x00,
            0x01,
            0x40,
            0x00,
            64,
            IP_PROTO_TCP,
            0x00,
            0x00,
            10,
            0,
            0,
            1,
            10,
            0,
            0,
            2,
        ]);
        // TCP header (src 12345, dst 443, data offset 5 -> 20B, PSH|ACK = 0x18)
        frame.extend_from_slice(&12345u16.to_be_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        frame.extend_from_slice(b"hello");

        let view = PacketView::parse(&frame).expect("valid VLAN IPv4 TCP frame");
        assert_eq!(view.vlan_id, Some(42));
        assert_eq!(view.proto, IP_PROTO_TCP);
        assert_eq!(view.src_addr(), "10.0.0.1:12345".parse().unwrap());
        assert_eq!(view.dst_addr(), "10.0.0.2:443".parse().unwrap());
        assert_eq!(view.tcp_flags, 0x18);
        assert_eq!(view.payload(), b"hello");
    }

    #[test]
    fn tcp_frame_roundtrip_ipv4_and_ipv6_with_options_and_checksums() {
        let mut opts = TcpOptions {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamps: Some((123_456, 78_910)),
            ..TcpOptions::default()
        };
        opts.push_sack(SackBlock {
            left: 1000,
            right: 2000,
        });

        let mut buf = [0u8; 256];
        let spec4 = TcpFrameSpec {
            src_mac: [1, 2, 3, 4, 5, 6],
            dst_mac: [6, 5, 4, 3, 2, 1],
            vlan_id: Some(100),
            src_ip: "192.0.2.1".parse().unwrap(),
            dst_ip: "198.51.100.2".parse().unwrap(),
            ip_ecn: 3,
            ttl: 64,
            src_port: 443,
            dst_port: 55123,
            seq: 0x1122_3344,
            ack: 0x5566_7788,
            flags: TCP_FLAG_ACK | TCP_FLAG_ECE,
            ae: true,
            window: 32768,
            options: opts,
            payload: b"zeroio-payload",
        };
        let len4 = encode_tcp_frame(&mut buf, &spec4).unwrap();
        let view4 = PacketView::parse(&buf[..len4]).unwrap();
        assert!(view4.verify_checksums());
        assert_eq!(view4.ip_ecn(), 3);
        assert_eq!(view4.vlan_id, Some(100));
        assert_eq!(view4.payload(), b"zeroio-payload");
        let th = view4.tcp_header().unwrap();
        assert_eq!(th.seq, 0x1122_3344);
        assert_eq!(th.ack, 0x5566_7788);
        assert!(th.ae);
        assert_eq!(th.ace_bits(), 0b101);
        let parsed_opts = th.parse_options().unwrap();
        assert_eq!(parsed_opts.mss, Some(1460));
        assert_eq!(parsed_opts.window_scale, Some(7));
        assert!(parsed_opts.sack_permitted);
        assert_eq!(parsed_opts.timestamps, Some((123_456, 78_910)));
        assert_eq!(
            parsed_opts.sack_slice(),
            &[SackBlock {
                left: 1000,
                right: 2000
            }]
        );

        // Corrupt one payload byte -> checksum must fail.
        buf[len4 - 1] ^= 0xFF;
        let bad_view = PacketView::parse(&buf[..len4]).unwrap();
        assert!(!bad_view.verify_l4_checksum());

        // IPv6 TCP round-trip.
        let spec6 = TcpFrameSpec {
            src_ip: "2001:db8::1".parse().unwrap(),
            dst_ip: "2001:db8::2".parse().unwrap(),
            vlan_id: None,
            ip_ecn: 2,
            ..spec4
        };
        let len6 = encode_tcp_frame(&mut buf, &spec6).unwrap();
        let view6 = PacketView::parse(&buf[..len6]).unwrap();
        assert!(view6.verify_checksums());
        assert_eq!(view6.ip_ecn(), 2);
        assert_eq!(view6.payload(), b"zeroio-payload");
    }

    #[test]
    fn udp_frame_roundtrip_and_malformed_options_fail_closed() {
        let mut buf = [0u8; 256];
        let spec = UdpFrameSpec {
            src_mac: [0x10; 6],
            dst_mac: [0x20; 6],
            vlan_id: None,
            src_ip: "10.1.0.1".parse().unwrap(),
            dst_ip: "10.1.0.2".parse().unwrap(),
            ip_ecn: 1,
            ttl: 64,
            src_port: 8443,
            dst_port: 443,
            payload: b"quic-dgram",
        };
        let len = encode_udp_frame(&mut buf, &spec).unwrap();
        let view = PacketView::parse(&buf[..len]).unwrap();
        assert!(view.verify_checksums());
        assert_eq!(view.ip_ecn(), 1);
        assert_eq!(view.payload(), b"quic-dgram");

        // Malformed TCP option length (0 triggers infinite loop if unchecked).
        assert_eq!(TcpOptions::parse(&[2, 0, 0, 0]), None);
        assert_eq!(TcpOptions::parse(&[8, 10, 1, 2]), None);
        assert_eq!(TcpOptions::parse(&[5, 6, 0, 0, 0, 0]), None);
    }
}
