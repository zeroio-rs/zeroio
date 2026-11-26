//! Bounded L2 neighbor MAC/VLAN cache and pure safe IPv4 ARP codec.

use core::net::{IpAddr, Ipv4Addr};
use std::collections::HashMap;
use std::time::Duration;
use zeroio_core::TransportInstant;

pub const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

/// Cached L2 adjacency entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborEntry {
    pub mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub updated_at: TransportInstant,
    pub static_entry: bool,
}

/// Bounded per-core neighbor / ARP table.
pub struct NeighborTable {
    entries: HashMap<IpAddr, NeighborEntry>,
    max_entries: usize,
    default_gateway_mac: Option<[u8; 6]>,
}

impl NeighborTable {
    pub fn new(max_entries: usize) -> Self {
        let cap = max_entries.clamp(16, 4096);
        Self {
            entries: HashMap::with_capacity(cap),
            max_entries: max_entries.max(1),
            default_gateway_mac: None,
        }
    }

    pub fn set_default_gateway_mac(&mut self, mac: Option<[u8; 6]>) {
        self.default_gateway_mac = mac;
    }

    pub fn insert_static(&mut self, ip: IpAddr, mac: [u8; 6], vlan_id: Option<u16>) {
        self.evict_if_full(&ip);
        self.entries.insert(
            ip,
            NeighborEntry {
                mac,
                vlan_id,
                updated_at: TransportInstant::ZERO,
                static_entry: true,
            },
        );
    }

    pub fn learn(&mut self, ip: IpAddr, mac: [u8; 6], vlan_id: Option<u16>, now: TransportInstant) {
        if let Some(existing) = self.entries.get_mut(&ip) {
            if !existing.static_entry {
                existing.mac = mac;
                existing.vlan_id = vlan_id;
                existing.updated_at = now;
            }
            return;
        }
        self.evict_if_full(&ip);
        self.entries.insert(
            ip,
            NeighborEntry {
                mac,
                vlan_id,
                updated_at: now,
                static_entry: false,
            },
        );
    }

    fn evict_if_full(&mut self, incoming: &IpAddr) {
        if self.entries.contains_key(incoming) || self.entries.len() < self.max_entries {
            return;
        }
        if let Some(victim) = self
            .entries
            .iter()
            .filter(|(_, e)| !e.static_entry)
            .min_by_key(|(_, e)| e.updated_at)
            .map(|(k, _)| *k)
        {
            self.entries.remove(&victim);
        }
    }

    pub fn lookup(
        &self,
        ip: &IpAddr,
        now: TransportInstant,
        ttl: Duration,
    ) -> Option<([u8; 6], Option<u16>)> {
        if let Some(entry) = self.entries.get(ip)
            && (entry.static_entry || now.duration_since(entry.updated_at) < ttl)
        {
            return Some((entry.mac, entry.vlan_id));
        }
        self.default_gateway_mac.map(|mac| (mac, None))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Decoded Ethernet + IPv4 ARP packet summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpIpv4Packet {
    pub is_request: bool,
    pub vlan_id: Option<u16>,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Parse an Ethernet (with optional 802.1Q VLAN) ARP IPv4 frame without allocation.
pub fn parse_arp_ipv4(frame: &[u8]) -> Option<ArpIpv4Packet> {
    if frame.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let mut off = 14usize;
    let mut vlan_id = None;
    if ethertype == 0x8100 || ethertype == 0x88A8 {
        if frame.len() < off + 4 {
            return None;
        }
        vlan_id = Some(u16::from_be_bytes([frame[off], frame[off + 1]]) & 0x0FFF);
        ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
        off += 4;
    }
    if ethertype != ETHERTYPE_ARP || frame.len() < off + 28 {
        return None;
    }
    let arp = &frame[off..off + 28];
    let htype = u16::from_be_bytes([arp[0], arp[1]]);
    let ptype = u16::from_be_bytes([arp[2], arp[3]]);
    let hlen = arp[4];
    let plen = arp[5];
    let op = u16::from_be_bytes([arp[6], arp[7]]);
    if htype != ARP_HTYPE_ETHERNET
        || ptype != ARP_PTYPE_IPV4
        || hlen != 6
        || plen != 4
        || (op != ARP_OP_REQUEST && op != ARP_OP_REPLY)
    {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    let mut target_mac = [0u8; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    target_mac.copy_from_slice(&arp[18..24]);
    Some(ArpIpv4Packet {
        is_request: op == ARP_OP_REQUEST,
        vlan_id,
        sender_mac,
        sender_ip: Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]),
        target_mac,
        target_ip: Ipv4Addr::new(arp[24], arp[25], arp[26], arp[27]),
    })
}

/// Encode an Ethernet + IPv4 ARP reply directly into `out` without allocation.
pub fn encode_arp_reply_ipv4(
    out: &mut [u8],
    vlan_id: Option<u16>,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Option<usize> {
    let l2_len = if vlan_id.is_some() { 18 } else { 14 };
    let total = l2_len + 28;
    if out.len() < total {
        return None;
    }
    out[0..6].copy_from_slice(&target_mac);
    out[6..12].copy_from_slice(&sender_mac);
    if let Some(vid) = vlan_id {
        out[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        out[14..16].copy_from_slice(&(vid & 0x0FFF).to_be_bytes());
        out[16..18].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    } else {
        out[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    }
    let arp = &mut out[l2_len..total];
    arp[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    arp[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    arp[8..14].copy_from_slice(&sender_mac);
    arp[14..18].copy_from_slice(&sender_ip.octets());
    arp[18..24].copy_from_slice(&target_mac);
    arp[24..28].copy_from_slice(&target_ip.octets());
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbor_table_and_arp_reply_roundtrip() {
        let mut tbl = NeighborTable::new(4);
        let t0 = TransportInstant::from_micros(10_000);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        tbl.learn(ip, [0xaa; 6], Some(10), t0);
        assert_eq!(
            tbl.lookup(
                &ip,
                TransportInstant::from_micros(20_000),
                Duration::from_secs(30)
            ),
            Some(([0xaa; 6], Some(10)))
        );

        let mut buf = [0u8; 64];
        let len = encode_arp_reply_ipv4(
            &mut buf,
            Some(10),
            [0x02; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            [0xaa; 6],
            Ipv4Addr::new(10, 0, 0, 5),
        )
        .unwrap();
        let parsed = parse_arp_ipv4(&buf[..len]).unwrap();
        assert!(!parsed.is_request);
        assert_eq!(parsed.vlan_id, Some(10));
        assert_eq!(parsed.sender_mac, [0x02; 6]);
        assert_eq!(parsed.target_ip, Ipv4Addr::new(10, 0, 0, 5));
    }
}
