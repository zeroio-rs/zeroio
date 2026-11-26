//! End-to-end tests driving [`QueueReactor`] over in-memory 4-ring [`LoopbackXskDevice`] pairs.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use zeroio_core::sched::MAX_BUSY_WAIT_US;
use zeroio_core::{SynCookieKey, TcpConfig, TcpState, TransportInstant, UdpFlowKey};
use zeroio_dataplane::neighbor::ETHERTYPE_ARP;
use zeroio_dataplane::{LoopbackXskDevice, QueueConfig, QueueReactor, UmemConfig, XskBindMode};

fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    frame[0..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let arp = &mut frame[14..42];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&1u16.to_be_bytes());
    arp[8..14].copy_from_slice(&sender_mac);
    arp[14..18].copy_from_slice(&sender_ip.octets());
    arp[18..24].copy_from_slice(&[0u8; 6]);
    arp[24..28].copy_from_slice(&target_ip.octets());
    frame
}

fn pump_pair(
    a: &mut QueueReactor<LoopbackXskDevice>,
    b: &mut QueueReactor<LoopbackXskDevice>,
    now: TransportInstant,
) {
    a.device_mut().pump_tx_to(b.device_mut());
    b.device_mut().pump_tx_to(a.device_mut());
    a.poll_once(now);
    b.poll_once(now);
}

#[test]
fn loopback_arp_tcp_handshake_transfer_and_close() {
    let umem = UmemConfig::default();
    let client_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x01];
    let server_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x02];
    let client_ip = Ipv4Addr::new(10, 10, 0, 1);
    let server_ip = Ipv4Addr::new(10, 10, 0, 2);

    let mut client_cfg = QueueConfig::new(
        0,
        client_mac,
        vec![IpAddr::V4(client_ip)],
        SynCookieKey::from_seed([1u8; 16]),
    );
    client_cfg.tcp = TcpConfig::default();
    let mut server_cfg = QueueConfig::new(
        0,
        server_mac,
        vec![IpAddr::V4(server_ip)],
        SynCookieKey::from_seed([2u8; 16]),
    );
    server_cfg.tcp = TcpConfig::default();

    let mut client = QueueReactor::new(
        LoopbackXskDevice::new(0, umem, XskBindMode::Copy),
        client_cfg,
    );
    let mut server = QueueReactor::new(
        LoopbackXskDevice::new(0, umem, XskBindMode::Copy),
        server_cfg,
    );

    let mut now = TransportInstant::from_micros(10_000);
    let arp_req = build_arp_request(client_mac, client_ip, server_ip);
    assert!(server.device_mut().push_rx_packet(&arp_req));
    server.poll_once(now);
    assert_eq!(server.stats().arp_requests, 1);
    assert_eq!(server.stats().arp_replies_sent, 1);

    now = now.saturating_add(Duration::from_millis(1));
    pump_pair(&mut server, &mut client, now);
    assert_eq!(
        client
            .neighbors()
            .lookup(&IpAddr::V4(server_ip), now, Duration::from_secs(60)),
        Some((server_mac, None))
    );

    server.tcp_mut().listen(8080).unwrap();
    let conn_c = client
        .tcp_mut()
        .connect(
            SocketAddr::new(IpAddr::V4(client_ip), 40000),
            SocketAddr::new(IpAddr::V4(server_ip), 8080),
            server_mac,
            now,
        )
        .unwrap();

    for _ in 0..6 {
        now = now.saturating_add(Duration::from_millis(2));
        client.poll_once(now);
        pump_pair(&mut client, &mut server, now);
    }

    let conn_s = server
        .tcp_mut()
        .accept()
        .expect("server accepted connection");
    assert_eq!(
        client.tcp().snapshot(conn_c).unwrap().state,
        TcpState::Established
    );
    assert_eq!(
        server.tcp().snapshot(conn_s).unwrap().state,
        TcpState::Established
    );

    let msg = b"hello zeroio dataplane";
    assert_eq!(client.tcp_mut().send(conn_c, msg).unwrap(), msg.len());

    let mut rx_buf = [0u8; 64];
    let mut received = Vec::new();
    for _ in 0..8 {
        now = now.saturating_add(Duration::from_millis(2));
        client.poll_once(now);
        pump_pair(&mut client, &mut server, now);
        let n = server.tcp_mut().recv(conn_s, &mut rx_buf).unwrap();
        received.extend_from_slice(&rx_buf[..n]);
        if received.len() == msg.len() {
            break;
        }
    }
    assert_eq!(received, msg);

    client.tcp_mut().close(conn_c).unwrap();
    server.tcp_mut().close(conn_s).unwrap();
    for _ in 0..8 {
        now = now.saturating_add(Duration::from_millis(5));
        client.poll_once(now);
        server.poll_once(now);
        pump_pair(&mut client, &mut server, now);
    }

    assert!(matches!(
        client.tcp().snapshot(conn_c).map(|s| s.state),
        None | Some(TcpState::FinWait2 | TcpState::TimeWait | TcpState::Closed)
    ));
}

#[test]
fn loopback_udp_send_receive_and_sleep_budget() {
    let umem = UmemConfig::default();
    let mac_a = [0x02, 0xaa, 0x00, 0x00, 0x00, 0x01];
    let mac_b = [0x02, 0xaa, 0x00, 0x00, 0x00, 0x02];
    let ip_a = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1));
    let ip_b = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 2));

    let mut cfg_a = QueueConfig::new(0, mac_a, vec![ip_a], SynCookieKey::from_seed([3u8; 16]));
    cfg_a.busy_wait_budget_us = MAX_BUSY_WAIT_US;
    let cfg_b = QueueConfig::new(0, mac_b, vec![ip_b], SynCookieKey::from_seed([4u8; 16]));

    let mut a = QueueReactor::new(LoopbackXskDevice::new(0, umem, XskBindMode::Copy), cfg_a);
    let mut b = QueueReactor::new(LoopbackXskDevice::new(0, umem, XskBindMode::Copy), cfg_b);

    let now = TransportInstant::from_micros(50_000);
    a.neighbors_mut().insert_static(ip_b, mac_b, None);

    let local = SocketAddr::new(ip_a, 5000);
    let peer = SocketAddr::new(ip_b, 9000);
    assert_eq!(
        a.send_udp(local, peer, None, None, b"ping-udp", now)
            .unwrap(),
        8
    );

    assert_eq!(a.device_mut().pump_tx_to(b.device_mut()), 1);
    let mut seen = Vec::new();
    let out = b.poll_once_with(now, &mut |flow: UdpFlowKey, payload: &[u8], _| {
        seen.push((flow, payload.to_vec()));
    });
    assert_eq!(out.udp_datagrams, 1);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].1, b"ping-udp");
    assert_eq!(seen[0].0.local, peer);
    assert_eq!(seen[0].0.peer, local);

    // Idle sleep respects idle_cap when no deadlines are pending.
    let idle_sleep = a.next_sleep_duration(now, Duration::from_millis(5));
    assert_eq!(idle_sleep, Duration::from_millis(5));
}
