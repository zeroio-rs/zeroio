use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::time::Duration;
use zeroio_core::{
    CcKind, EcnMode, PacketView, SynCookieKey, TcpConfig, TcpStack, TcpState, Tier,
    TransportInstant, internet_checksum,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    C2S,
    S2C,
}

#[derive(Clone, Eq, PartialEq)]
struct WireFrame {
    deliver_at: TransportInstant,
    seq_order: u64,
    dir: Direction,
    bytes: Vec<u8>,
}

impl Ord for WireFrame {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deliver_at
            .cmp(&other.deliver_at)
            .then_with(|| self.seq_order.cmp(&other.seq_order))
    }
}

impl PartialOrd for WireFrame {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

struct WirePolicy {
    one_way: Duration,
    drop_c2s_indices: Vec<u64>,
    reorder_c2s_index: Option<(u64, Duration)>,
    mark_ce_c2s_from: Option<u64>,
    c2s_count: u64,
    s2c_count: u64,
}

impl WirePolicy {
    fn clean(one_way: Duration) -> Self {
        Self {
            one_way,
            drop_c2s_indices: Vec::new(),
            reorder_c2s_index: None,
            mark_ce_c2s_from: None,
            c2s_count: 0,
            s2c_count: 0,
        }
    }
}

fn stamp_ipv4_ce(frame: &mut [u8]) {
    let Some((eth, l3, l4)) =
        PacketView::parse(frame).map(|v| (v.ethertype, v.l3_offset, v.l4_offset))
    else {
        return;
    };
    if eth == zeroio_core::packet::ETHERTYPE_IPV4 {
        frame[l3 + 1] = (frame[l3 + 1] & !0x03) | 0x03;
        frame[l3 + 10] = 0;
        frame[l3 + 11] = 0;
        let cksum = internet_checksum(&[&frame[l3..l4]]);
        frame[l3 + 10..l3 + 12].copy_from_slice(&cksum.to_be_bytes());
    }
}

struct VirtualNetwork {
    client: TcpStack,
    server: TcpStack,
    policy: WirePolicy,
    queue: BinaryHeap<Reverse<WireFrame>>,
    order: u64,
    now: TransportInstant,
}

impl VirtualNetwork {
    fn new(client: TcpStack, server: TcpStack, policy: WirePolicy) -> Self {
        Self {
            client,
            server,
            policy,
            queue: BinaryHeap::new(),
            order: 0,
            now: TransportInstant::from_micros(1_000_000),
        }
    }

    fn enqueue(&mut self, dir: Direction, raw: &[u8]) {
        let mut bytes = raw.to_vec();
        match dir {
            Direction::C2S => {
                self.policy.c2s_count += 1;
                let idx = self.policy.c2s_count;
                if self.policy.drop_c2s_indices.contains(&idx) {
                    return;
                }
                if let Some(start) = self.policy.mark_ce_c2s_from
                    && idx >= start
                {
                    stamp_ipv4_ce(&mut bytes);
                }
                let extra = self
                    .policy
                    .reorder_c2s_index
                    .and_then(|(target, d)| (target == idx).then_some(d))
                    .unwrap_or(Duration::ZERO);
                self.order += 1;
                self.queue.push(Reverse(WireFrame {
                    deliver_at: self.now + self.policy.one_way + extra,
                    seq_order: self.order,
                    dir,
                    bytes,
                }));
            }
            Direction::S2C => {
                self.policy.s2c_count += 1;
                self.order += 1;
                self.queue.push(Reverse(WireFrame {
                    deliver_at: self.now + self.policy.one_way,
                    seq_order: self.order,
                    dir,
                    bytes,
                }));
            }
        }
    }

    fn poll_both(&mut self) {
        let mut tx_buf = [0u8; 2048];
        let mut c2s_frames = Vec::new();
        self.client.poll_tx(self.now, &mut tx_buf, |f| {
            c2s_frames.push(f.to_vec());
            true
        });
        for f in c2s_frames {
            self.enqueue(Direction::C2S, &f);
        }

        let mut s2c_frames = Vec::new();
        self.server.poll_tx(self.now, &mut tx_buf, |f| {
            s2c_frames.push(f.to_vec());
            true
        });
        for f in s2c_frames {
            self.enqueue(Direction::S2C, &f);
        }
    }

    fn step_until(&mut self, max_time: TransportInstant) {
        let mut steps = 0usize;
        while self.now <= max_time {
            steps += 1;
            assert!(
                steps < 200_000,
                "virtual network simulation stalled at {:?}",
                self.now
            );
            self.client.on_timer(self.now);
            self.server.on_timer(self.now);
            self.poll_both();

            let next_wire = self.queue.peek().map(|r| r.0.deliver_at);
            let next_c = self.client.next_deadline();
            let next_s = self.server.next_deadline();
            let next_ev = [next_wire, next_c, next_s].into_iter().flatten().min();

            let Some(ev) = next_ev else {
                self.now = max_time;
                break;
            };
            let target = ev.max(self.now);
            if target > max_time {
                self.now = max_time;
                break;
            }
            self.now = target;

            while let Some(top) = self.queue.peek() {
                if top.0.deliver_at > self.now {
                    break;
                }
                let pkt = self.queue.pop().unwrap().0;
                if let Some(view) = PacketView::parse(&pkt.bytes) {
                    match pkt.dir {
                        Direction::C2S => self.server.on_rx(self.now, &view),
                        Direction::S2C => self.client.on_rx(self.now, &view),
                    }
                }
            }
        }
    }
}

fn make_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xFF) as u8).collect()
}

#[test]
fn handshake_bulk_transfer_graceful_close_and_path_table_warm_start() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x01];
    let s_mac = [0x02, 0, 0, 0, 0, 0x02];
    let c_addr: SocketAddr = "10.10.0.1:40000".parse().unwrap();
    let s_addr: SocketAddr = "10.10.0.2:443".parse().unwrap();

    let mut client_cfg = TcpConfig {
        src_mac: c_mac,
        time_wait_duration: Duration::from_millis(200),
        ..TcpConfig::default()
    };
    client_cfg.cc_kind = CcKind::EdgeCc {
        tier: Tier::T2,
        trusted_ecn: true,
    };

    let mut server_cfg = TcpConfig {
        src_mac: s_mac,
        time_wait_duration: Duration::from_millis(200),
        ..TcpConfig::default()
    };
    server_cfg.cc_kind = CcKind::EdgeCc {
        tier: Tier::T2,
        trusted_ecn: true,
    };

    let client = TcpStack::new(client_cfg, SynCookieKey::from_seed(*b"client-seed-0001"));
    let mut server = TcpStack::new(server_cfg, SynCookieKey::from_seed(*b"server-seed-0002"));
    server.listen(443).unwrap();

    let mut net = VirtualNetwork::new(client, server, WirePolicy::clean(Duration::from_millis(5)));
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();

    // Complete 3-way handshake.
    net.step_until(net.now + Duration::from_millis(30));
    let sh = net.server.accept().expect("server accepted connection");
    assert_eq!(
        net.client.snapshot(ch).unwrap().state,
        TcpState::Established
    );
    assert_eq!(
        net.server.snapshot(sh).unwrap().state,
        TcpState::Established
    );
    assert_eq!(net.client.snapshot(ch).unwrap().ecn_mode, EcnMode::AccEcn);

    // Send 192 KiB client -> server in chunks.
    let data = make_payload(192 * 1024);
    let mut sent = 0usize;
    let mut received = Vec::with_capacity(data.len());
    let mut rx_buf = [0u8; 32 * 1024];

    for _ in 0..40 {
        if sent < data.len() {
            sent += net.client.send(ch, &data[sent..]).unwrap();
        }
        net.step_until(net.now + Duration::from_millis(25));
        loop {
            let n = net.server.recv(sh, &mut rx_buf).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&rx_buf[..n]);
        }
        if received.len() == data.len() {
            break;
        }
    }
    assert_eq!(
        received.len(),
        data.len(),
        "got {} vs {}",
        received.len(),
        data.len()
    );
    assert_eq!(received, data);

    // Echo 4 KiB server -> client.
    let echo = make_payload(4096);
    assert_eq!(net.server.send(sh, &echo).unwrap(), echo.len());
    net.step_until(net.now + Duration::from_millis(80));
    let mut got_echo = vec![0u8; echo.len()];
    let mut got_n = 0usize;
    while got_n < echo.len() {
        let n = net.client.recv(ch, &mut got_echo[got_n..]).unwrap();
        if n == 0 {
            break;
        }
        got_n += n;
    }
    assert_eq!(&got_echo[..got_n], &echo[..]);

    // Graceful close both sides -> TIME_WAIT -> Closed & PathTable updated.
    net.client.close(ch).unwrap();
    net.server.close(sh).unwrap();
    net.step_until(net.now + Duration::from_millis(500));
    assert_eq!(net.client.active_connections(), 0);
    assert_eq!(net.server.active_connections(), 0);

    // Second connection to same server IP inherits a valid PathPrior.
    let c2: SocketAddr = "10.10.0.1:40001".parse().unwrap();
    let ch2 = net.client.connect(c2, s_addr, s_mac, net.now).unwrap();
    assert_eq!(
        net.client.snapshot(ch2).unwrap().cc.mode,
        "paced_start",
        "second flow should warm-start from PathTable prior"
    );
}

#[test]
fn ipv6_vlan_transfers_with_cubic_and_bbr3() {
    for kind in [CcKind::CubicRef, CcKind::Bbr3Ref] {
        let c_mac = [0x02, 0, 0, 0, 0, 0x11];
        let s_mac = [0x02, 0, 0, 0, 0, 0x12];
        let c_addr: SocketAddr = "[2001:db8::1]:51000".parse().unwrap();
        let s_addr: SocketAddr = "[2001:db8::2]:8443".parse().unwrap();

        let client_cfg = TcpConfig {
            src_mac: c_mac,
            vlan_id: Some(77),
            cc_kind: kind,
            ..TcpConfig::default()
        };
        let server_cfg = TcpConfig {
            src_mac: s_mac,
            vlan_id: Some(77),
            cc_kind: kind,
            ..TcpConfig::default()
        };

        let client = TcpStack::new(client_cfg, SynCookieKey::from_seed(*b"v6-client-000001"));
        let mut server = TcpStack::new(server_cfg, SynCookieKey::from_seed(*b"v6-server-000002"));
        server.listen(8443).unwrap();

        let mut net =
            VirtualNetwork::new(client, server, WirePolicy::clean(Duration::from_millis(3)));
        let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();
        net.step_until(net.now + Duration::from_millis(20));
        let sh = net.server.accept().unwrap();

        let data = make_payload(96 * 1024);
        let mut sent = 0usize;
        let mut recv = Vec::with_capacity(data.len());
        let mut buf = [0u8; 16384];
        for _ in 0..30 {
            if sent < data.len() {
                sent += net.client.send(ch, &data[sent..]).unwrap();
            }
            net.step_until(net.now + Duration::from_millis(20));
            loop {
                let n = net.server.recv(sh, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                recv.extend_from_slice(&buf[..n]);
            }
            if recv.len() == data.len() {
                break;
            }
        }
        assert_eq!(recv, data);
    }
}

#[test]
fn syn_cookie_stateless_accept_and_transfer() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x21];
    let s_mac = [0x02, 0, 0, 0, 0, 0x22];
    let c_addr: SocketAddr = "192.0.2.10:33333".parse().unwrap();
    let s_addr: SocketAddr = "192.0.2.20:80".parse().unwrap();

    let client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"ck-client-000001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            syn_cookies: true,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"ck-server-000002"),
    );
    server.listen(80).unwrap();

    let mut net = VirtualNetwork::new(client, server, WirePolicy::clean(Duration::from_millis(4)));
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();

    // Deliver SYN only (at +4ms).
    net.step_until(net.now + Duration::from_millis(5));
    assert_eq!(
        net.server.active_connections(),
        0,
        "SYN cookie listener must not allocate state on SYN"
    );

    // Complete SYN-ACK + 3rd ACK.
    net.step_until(net.now + Duration::from_millis(20));
    let sh = net.server.accept().expect("cookie handshake established");
    assert_eq!(net.server.active_connections(), 1);
    assert_eq!(
        net.server.snapshot(sh).unwrap().state,
        TcpState::Established
    );

    let msg = b"stateless-cookie-payload";
    assert_eq!(net.client.send(ch, msg).unwrap(), msg.len());
    net.step_until(net.now + Duration::from_millis(20));
    let mut out = [0u8; 64];
    let n = net.server.recv(sh, &mut out).unwrap();
    assert_eq!(&out[..n], msg);
}

#[test]
fn packet_loss_and_reordering_recover_via_sack_and_rto() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x31];
    let s_mac = [0x02, 0, 0, 0, 0, 0x32];
    let c_addr: SocketAddr = "10.20.0.1:41000".parse().unwrap();
    let s_addr: SocketAddr = "10.20.0.2:443".parse().unwrap();

    let client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"loss-client-0001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"loss-server-0002"),
    );
    server.listen(443).unwrap();

    // Drop packet #1 (initial SYN -> handshake RTO!), packet #5 (mid-flight),
    // and packet #12 (tail), plus reorder packet #6 by 15ms.
    let mut policy = WirePolicy::clean(Duration::from_millis(5));
    policy.drop_c2s_indices = vec![1, 5, 12];
    policy.reorder_c2s_index = Some((6, Duration::from_millis(15)));

    let mut net = VirtualNetwork::new(client, server, policy);
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();

    // Wait past SYN RTO (1s) for handshake recovery.
    net.step_until(net.now + Duration::from_millis(1_150));
    let sh = net.server.accept().expect("SYN RTO recovered handshake");

    let data = make_payload(40 * 1024);
    let mut sent = 0usize;
    let mut recv = Vec::with_capacity(data.len());
    let mut buf = [0u8; 16384];
    for _ in 0..30 {
        if sent < data.len() {
            sent += net.client.send(ch, &data[sent..]).unwrap();
        }
        net.step_until(net.now + Duration::from_millis(100));
        loop {
            let n = net.server.recv(sh, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            recv.extend_from_slice(&buf[..n]);
        }
        if recv.len() == data.len() {
            break;
        }
    }
    assert_eq!(recv, data);
    assert!(net.client.snapshot(ch).unwrap().retransmits >= 1);
}

#[test]
fn accecn_ce_marking_drives_immediate_feedback_and_cc_response() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x41];
    let s_mac = [0x02, 0, 0, 0, 0, 0x42];
    let c_addr: SocketAddr = "10.30.0.1:42000".parse().unwrap();
    let s_addr: SocketAddr = "10.30.0.2:443".parse().unwrap();

    let client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            cc_kind: CcKind::EdgeCc {
                tier: Tier::T2,
                trusted_ecn: true,
            },
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"ecn-client-00001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"ecn-server-00002"),
    );
    server.listen(443).unwrap();

    let mut policy = WirePolicy::clean(Duration::from_millis(5));
    policy.mark_ce_c2s_from = Some(3);

    let mut net = VirtualNetwork::new(client, server, policy);
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();
    net.step_until(net.now + Duration::from_millis(25));
    let sh = net.server.accept().unwrap();

    let data = make_payload(64 * 1024);
    let mut sent = 0usize;
    let mut recv = Vec::with_capacity(data.len());
    let mut buf = [0u8; 16384];
    for _ in 0..20 {
        if sent < data.len() {
            sent += net.client.send(ch, &data[sent..]).unwrap();
        }
        net.step_until(net.now + Duration::from_millis(20));
        loop {
            let n = net.server.recv(sh, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            recv.extend_from_slice(&buf[..n]);
        }
        if recv.len() == data.len() {
            break;
        }
    }
    assert_eq!(recv, data);
    let snap = net.client.snapshot(ch).unwrap();
    assert_eq!(snap.ecn_mode, EcnMode::AccEcn);
    assert!(
        snap.cc.ecn_alpha_milli.unwrap_or(0) > 0,
        "CE marks must raise EdgeCC ecn_alpha_milli"
    );
}

#[test]
fn malformed_checksums_and_unmatched_ports_fail_closed() {
    let s_mac = [0x02, 0, 0, 0, 0, 0x52];
    let c_mac = [0x02, 0, 0, 0, 0, 0x51];
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"sec-server-00001"),
    );

    // Send valid SYN to closed port 9999 -> must emit RST|ACK and allocate 0 connections.
    let mut frame = [0u8; 256];
    let len = zeroio_core::encode_tcp_frame(
        &mut frame,
        &zeroio_core::TcpFrameSpec {
            src_mac: c_mac,
            dst_mac: s_mac,
            vlan_id: None,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            ip_ecn: 0,
            ttl: 64,
            src_port: 12345,
            dst_port: 9999,
            seq: 100,
            ack: 0,
            flags: zeroio_core::packet::TCP_FLAG_SYN,
            ae: false,
            window: 65535,
            options: zeroio_core::TcpOptions::default(),
            payload: &[],
        },
    )
    .unwrap();

    // Corrupt checksum -> silently ignored (no RST emitted).
    let mut bad = frame[..len].to_vec();
    bad[len - 1] ^= 0x01;
    let bad_view = PacketView::parse(&bad).unwrap();
    let t0 = TransportInstant::from_micros(10_000);
    server.on_rx(t0, &bad_view);
    let mut out_buf = [0u8; 256];
    let mut emitted = Vec::new();
    server.poll_tx(t0, &mut out_buf, |f| {
        emitted.push(f.to_vec());
        true
    });
    assert!(emitted.is_empty());

    // Valid SYN to closed port -> RST|ACK emitted.
    let good_view = PacketView::parse(&frame[..len]).unwrap();
    server.on_rx(t0, &good_view);
    server.poll_tx(t0, &mut out_buf, |f| {
        emitted.push(f.to_vec());
        true
    });
    assert_eq!(emitted.len(), 1);
    let rst_view = PacketView::parse(&emitted[0]).unwrap();
    assert_ne!(rst_view.tcp_flags & zeroio_core::packet::TCP_FLAG_RST, 0);
    assert_eq!(server.active_connections(), 0);
}

#[test]
fn adversarial_mutated_frames_capacity_bounds_and_abort_rst() {
    let s_mac = [0x02, 0, 0, 0, 0, 0x62];
    let c_mac = [0x02, 0, 0, 0, 0, 0x61];
    let s_addr: SocketAddr = "10.40.0.2:443".parse().unwrap();
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            max_connections: 2,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"adv-server-00001"),
    );
    server.listen(443).unwrap();

    // Deterministic pseudo-random mutated packets never panic.
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut scratch = [0u8; 128];
    let t0 = TransportInstant::from_micros(50_000);
    for i in 0..500usize {
        let len = (i % 128) + 1;
        for b in &mut scratch[..len] {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xFF) as u8;
        }
        if let Some(view) = PacketView::parse(&scratch[..len]) {
            server.on_rx(t0, &view);
        }
    }

    // Connection capacity cap rejects 3rd active dial cleanly without panicking.
    let c1: SocketAddr = "10.40.0.1:10001".parse().unwrap();
    let c2: SocketAddr = "10.40.0.1:10002".parse().unwrap();
    let c3: SocketAddr = "10.40.0.1:10003".parse().unwrap();
    let h1 = server.connect(s_addr, c1, c_mac, t0).unwrap();
    let _h2 = server.connect(s_addr, c2, c_mac, t0).unwrap();
    assert_eq!(
        server.connect(s_addr, c3, c_mac, t0),
        Err(zeroio_core::TcpError::CapacityReached)
    );

    // Abort emits RST and frees slab slot for c3.
    server.abort(h1).unwrap();
    let mut tx_buf = [0u8; 512];
    let mut rst_seen = false;
    server.poll_tx(t0, &mut tx_buf, |f| {
        if let Some(v) = PacketView::parse(f)
            && (v.tcp_flags & zeroio_core::packet::TCP_FLAG_RST) != 0
        {
            rst_seen = true;
        }
        true
    });
    assert!(rst_seen);
    assert!(server.snapshot(h1).is_none());
    assert!(server.connect(s_addr, c3, c_mac, t0).is_ok());
}

#[test]
fn tlp_recovers_tail_loss_faster_than_rto() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x71];
    let s_mac = [0x02, 0, 0, 0, 0, 0x72];
    let c_addr: SocketAddr = "10.50.0.1:43000".parse().unwrap();
    let s_addr: SocketAddr = "10.50.0.2:443".parse().unwrap();

    let client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"tlp-client-00001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"tlp-server-00002"),
    );
    server.listen(443).unwrap();

    // C2S #1=SYN, #2=3rd ACK, #3=first data segment -> drop ONLY #3 (tail loss).
    let mut policy = WirePolicy::clean(Duration::from_millis(5));
    policy.drop_c2s_indices = vec![3];

    let mut net = VirtualNetwork::new(client, server, policy);
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();
    net.step_until(net.now + Duration::from_millis(25));
    let sh = net.server.accept().unwrap();

    let msg = b"tail-loss-probe-payload";
    assert_eq!(net.client.send(ch, msg).unwrap(), msg.len());

    // Step only 120ms (< 200ms RTO_MIN!). TLP must fire around ~60ms and recover.
    net.step_until(net.now + Duration::from_millis(120));
    let mut out = [0u8; 64];
    let n = net.server.recv(sh, &mut out).unwrap();
    assert_eq!(&out[..n], msg);
    assert_eq!(net.client.snapshot(ch).unwrap().retransmits, 1);
}

#[test]
fn zero_window_probe_and_zero_copy_peek_consume_recover_stall() {
    let c_mac = [0x02, 0, 0, 0, 0, 0x81];
    let s_mac = [0x02, 0, 0, 0, 0, 0x82];
    let c_addr: SocketAddr = "10.60.0.1:44000".parse().unwrap();
    let s_addr: SocketAddr = "10.60.0.2:443".parse().unwrap();

    let client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"zwp-client-00001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            rx_buf_size: 1024,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"zwp-server-00002"),
    );
    server.listen(443).unwrap();

    let mut net = VirtualNetwork::new(client, server, WirePolicy::clean(Duration::from_millis(5)));
    let ch = net.client.connect(c_addr, s_addr, s_mac, net.now).unwrap();
    net.step_until(net.now + Duration::from_millis(25));
    let sh = net.server.accept().unwrap();

    // Queue 2560 bytes (> server's 1024-byte RX window) -> server advertises rwnd=0.
    let data = make_payload(2560);
    assert_eq!(net.client.send(ch, &data).unwrap(), data.len());
    net.step_until(net.now + Duration::from_millis(50));

    // Drain first 1024 bytes using zero-copy peek_rx + consume_rx.
    let mut received = Vec::with_capacity(data.len());
    let (p1, p2) = net.server.peek_rx(sh).unwrap();
    let first_take = p1.len() + p2.len();
    assert_eq!(first_take, 1024);
    received.extend_from_slice(p1);
    received.extend_from_slice(p2);
    assert_eq!(net.server.consume_rx(sh, first_take).unwrap(), first_take);

    // Advance past ZWP persist timer so client probes and drains remaining 1536 bytes.
    for _ in 0..8 {
        net.step_until(net.now + Duration::from_millis(260));
        let (s1, s2) = net.server.peek_rx(sh).unwrap();
        let avail = s1.len() + s2.len();
        if avail > 0 {
            received.extend_from_slice(s1);
            received.extend_from_slice(s2);
            net.server.consume_rx(sh, avail).unwrap();
        }
        if received.len() == data.len() {
            break;
        }
    }
    assert_eq!(received, data);
}
