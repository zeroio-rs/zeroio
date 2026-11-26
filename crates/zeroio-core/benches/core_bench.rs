use core::net::{IpAddr, Ipv4Addr};
use std::hint::black_box;
use std::time::{Duration, Instant};
use zeroio_core::packet::{
    AccEcnOption, PacketView, TCP_FLAG_ACK, TcpFrameSpec, TcpOptions, encode_tcp_frame,
};
use zeroio_core::rate_sample::RateSampler;
use zeroio_core::tcp::SeqNum;
use zeroio_core::tcp::buffer::TxQueue;
use zeroio_core::{
    PrefixIndex, SynCookieKey, TcpConfig, TcpStack, TransportInstant, extract_tls_sni,
};

fn bench_op(name: &str, iters: u64, mut f: impl FnMut(u64)) {
    // Warmup
    for i in 0..1000 {
        f(i);
    }
    let start = Instant::now();
    for i in 0..iters {
        f(i);
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iters as f64;
    let ops_per_sec = iters as f64 / elapsed.as_secs_f64().max(1e-9);
    println!("{name:<36} {ns_per_op:8.1} ns/op   ({ops_per_sec:>10.0} ops/s)");
}

fn main() {
    let mut frame_buf = [0u8; 256];
    let opts = TcpOptions {
        timestamps: Some((100_000, 99_990)),
        acc_ecn: Some(AccEcnOption {
            e0b: Some(4096),
            ceb: Some(0),
            e1b: Some(0),
        }),
        ..TcpOptions::default()
    };
    let spec = TcpFrameSpec {
        src_mac: [0x02; 6],
        dst_mac: [0x04; 6],
        vlan_id: Some(42),
        src_ip: "192.0.2.1".parse().unwrap(),
        dst_ip: "198.51.100.2".parse().unwrap(),
        ip_ecn: 2,
        ttl: 64,
        src_port: 443,
        dst_port: 55123,
        seq: 0x1000_0000,
        ack: 0x2000_0000,
        flags: TCP_FLAG_ACK,
        ae: false,
        window: 32768,
        options: opts,
        payload: b"GET / HTTP/1.1\r\nHost: zeroio.rs\r\n\r\n",
    };
    let encoded_len = encode_tcp_frame(&mut frame_buf, &spec).unwrap();

    bench_op("encode_tcp_frame(ipv4+vlan+opts)", 200_000, |i| {
        let mut s = spec;
        s.seq = i as u32;
        let len = encode_tcp_frame(black_box(&mut frame_buf), black_box(&s)).unwrap();
        black_box(len);
    });

    let wire_slice = frame_buf[..encoded_len].to_vec();
    bench_op("PacketView::parse+verify_checksums", 200_000, |_| {
        let view = PacketView::parse(black_box(&wire_slice)).unwrap();
        black_box(view.verify_checksums());
        black_box(view.tcp_header());
    });

    // Minimal TLS ClientHello for SNI extraction benchmark.
    let hello = [
        0x16, 0x03, 0x01, 0x00, 0x3b, 0x01, 0x00, 0x00, 0x37, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x02,
        0x13, 0x01, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00, 0x09,
        b'z', b'e', b'r', b'o', b'i', b'o', b'.', b'r', b's',
    ];
    bench_op("extract_tls_sni", 500_000, |_| {
        black_box(extract_tls_sni(black_box(&hello)));
    });

    // Establish one client/server pair and measure stack poll/rx round-trip.
    let c_mac = [0x02, 0, 0, 0, 0, 1];
    let s_mac = [0x02, 0, 0, 0, 0, 2];
    let c_addr = "10.0.0.1:40000".parse().unwrap();
    let s_addr = "10.0.0.2:443".parse().unwrap();
    let mut client = TcpStack::new(
        TcpConfig {
            src_mac: c_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"bench-client-001"),
    );
    let mut server = TcpStack::new(
        TcpConfig {
            src_mac: s_mac,
            ..TcpConfig::default()
        },
        SynCookieKey::from_seed(*b"bench-server-002"),
    );
    server.listen(443).unwrap();
    let mut now = TransportInstant::from_micros(1_000_000);
    let ch = client.connect(c_addr, s_addr, s_mac, now).unwrap();
    let mut buf = [0u8; 2048];
    for _ in 0..4 {
        let mut c2s = Vec::new();
        client.poll_tx(now, &mut buf, |f| {
            c2s.push(f.to_vec());
            true
        });
        now = now + Duration::from_millis(1);
        for f in c2s {
            if let Some(v) = PacketView::parse(&f) {
                server.on_rx(now, &v);
            }
        }
        let mut s2c = Vec::new();
        server.poll_tx(now, &mut buf, |f| {
            s2c.push(f.to_vec());
            true
        });
        now = now + Duration::from_millis(1);
        for f in s2c {
            if let Some(v) = PacketView::parse(&f) {
                client.on_rx(now, &v);
            }
        }
    }
    let sh = server.accept().unwrap();
    let payload = [0x5Au8; 1024];
    let mut drain = [0u8; 2048];
    bench_op("TcpStack 1KiB send+tx+rx+recv", 10_000, |_| {
        let _ = client.send(ch, &payload);
        let mut c2s = Vec::new();
        client.poll_tx(now, &mut buf, |f| {
            c2s.push(f.to_vec());
            true
        });
        now = now + Duration::from_micros(50);
        for f in c2s {
            if let Some(v) = PacketView::parse(&f) {
                server.on_rx(now, &v);
            }
        }
        let _ = server.recv(sh, &mut drain);
        let mut s2c = Vec::new();
        server.poll_tx(now, &mut buf, |f| {
            s2c.push(f.to_vec());
            true
        });
        now = now + Duration::from_micros(50);
        for f in s2c {
            if let Some(v) = PacketView::parse(&f) {
                client.on_rx(now, &v);
            }
        }
    });

    // Establish 4,096 concurrent connections on server/client, keep 4,095 idle and exercise 1 hot flow.
    let mut cfg_4k = TcpConfig {
        src_mac: s_mac,
        max_connections: 8192,
        ..TcpConfig::default()
    };
    let mut idle_server = TcpStack::new(
        cfg_4k.clone(),
        SynCookieKey::from_seed(*b"bench-srv-4k-001"),
    );
    idle_server.listen(443).unwrap();
    cfg_4k.src_mac = c_mac;
    let mut idle_client = TcpStack::new(cfg_4k, SynCookieKey::from_seed(*b"bench-cli-4k-002"));
    let t4k = TransportInstant::from_micros(2_000_000);
    let active_h = idle_client.connect(c_addr, s_addr, s_mac, t4k).unwrap();
    let mut tmp_buf = [0u8; 2048];
    for _ in 0..3 {
        let mut pkts = Vec::new();
        idle_client.poll_tx(t4k, &mut tmp_buf, |f| {
            pkts.push(f.to_vec());
            true
        });
        for p in pkts {
            if let Some(v) = PacketView::parse(&p) {
                idle_server.on_rx(t4k, &v);
            }
        }
        let mut replies = Vec::new();
        idle_server.poll_tx(t4k, &mut tmp_buf, |f| {
            replies.push(f.to_vec());
            true
        });
        for r in replies {
            if let Some(v) = PacketView::parse(&r) {
                idle_client.on_rx(t4k, &v);
            }
        }
    }
    let active_sh = idle_server.accept().unwrap();
    for idx in 1..4096u32 {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(
            10,
            ((idx >> 16) & 0xff) as u8,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        let local_port = 10000 + (idx % 50000) as u16;
        let _ = idle_client.connect(
            std::net::SocketAddr::new(peer_ip, local_port),
            s_addr,
            s_mac,
            t4k,
        );
    }
    let mut bench_t = t4k + Duration::from_secs(10);
    bench_op("TcpStack(4k-conns) 1KiB round-trip", 10_000, |_| {
        let _ = idle_client.send(active_h, &payload);
        let mut c2s = Vec::new();
        idle_client.poll_tx(bench_t, &mut tmp_buf, |f| {
            c2s.push(f.to_vec());
            true
        });
        bench_t = bench_t + Duration::from_micros(50);
        for f in c2s {
            if let Some(v) = PacketView::parse(&f) {
                idle_server.on_rx(bench_t, &v);
            }
        }
        let _ = idle_server.recv(active_sh, &mut drain);
        let _ = idle_server.next_deadline();
        idle_server.on_timer(bench_t);
        let mut s2c = Vec::new();
        idle_server.poll_tx(bench_t, &mut tmp_buf, |f| {
            s2c.push(f.to_vec());
            true
        });
        bench_t = bench_t + Duration::from_micros(50);
        for f in s2c {
            if let Some(v) = PacketView::parse(&f) {
                idle_client.on_rx(bench_t, &v);
            }
        }
    });

    // TxQueue steady-state in-order ACK benchmark at 256-segment inflight window.
    let mut sampler = RateSampler::new();
    let mut txq = TxQueue::new(SeqNum(0), 512 * 1024);
    let chunk = [0xAAu8; 1024];
    for _ in 0..255 {
        txq.push_data(&chunk);
        let rec = sampler.note_sent(txq.rel_nxt(), 1024, now, false, None);
        txq.mark_new_sent(1024, rec);
    }
    bench_op("TxQueue cum-ack (256-seg window)", 100_000, |_| {
        txq.push_data(&chunk);
        let rec = sampler.note_sent(txq.rel_nxt(), 1024, now, false, None);
        txq.mark_new_sent(1024, rec);
        let ack_target = txq.snd_una().add(1024);
        let out = txq.on_ack(
            ack_target,
            &[],
            0,
            now,
            Some(Duration::from_millis(20)),
            &mut sampler,
        );
        black_box(out.sample.delivered);
    });

    // PrefixIndex longest-prefix lookup over 10,000 IPv4 + IPv6 CIDRs.
    let mut entries = Vec::with_capacity(10_000);
    for i in 0..8_000u32 {
        let b1 = ((i >> 8) & 0xFF) as u8;
        let b2 = (i & 0xFF) as u8;
        let len = match i % 4 {
            0 => 8,
            1 => 16,
            2 => 24,
            _ => 32,
        };
        entries.push((IpAddr::V4(Ipv4Addr::new(100, b1, b2, 1)), len, i));
    }
    for i in 0..2_000u32 {
        let addr = std::net::Ipv6Addr::new(
            0x2001,
            0x0db8,
            (i >> 8) as u16,
            (i & 0xFF) as u16,
            0,
            0,
            0,
            1,
        );
        entries.push((IpAddr::V6(addr), 48, i));
    }
    let pfx = PrefixIndex::from_entries(entries);
    bench_op("PrefixIndex::lookup(10k-cidrs)", 200_000, |i| {
        let q = if i & 1 == 0 {
            IpAddr::V4(Ipv4Addr::new(
                100,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
                42,
            ))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001,
                0x0db8,
                ((i >> 8) & 0x1F) as u16,
                (i & 0xFF) as u16,
                1,
                2,
                3,
                4,
            ))
        };
        black_box(pfx.lookup(black_box(q)));
    });
}
