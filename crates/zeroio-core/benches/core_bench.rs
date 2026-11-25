use std::hint::black_box;
use std::time::{Duration, Instant};
use zeroio_core::packet::{
    AccEcnOption, PacketView, TCP_FLAG_ACK, TcpFrameSpec, TcpOptions, encode_tcp_frame,
};
use zeroio_core::{SynCookieKey, TcpConfig, TcpStack, TransportInstant, extract_tls_sni};

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
}
