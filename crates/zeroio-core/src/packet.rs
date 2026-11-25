//! Zero-copy L2/L3/L4 packet header inspection for Ethernet, VLAN, IPv4/IPv6,
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
        &self.frame[self.payload_offset..self.ip_end]
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
}
