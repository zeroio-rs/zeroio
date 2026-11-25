# Zeroio

**Open-source, memory-safe Rust network dataplane** — unifying XDP/AF_XDP packet filtering & forwarding, congestion control (`EdgeCC`, BBRv3, CUBIC, NewReno), zero-copy packet inspection (SNI / QUIC DCID), and a high-concurrency userspace TCP/UDP transport core.

Licensed under **0BSD** (Zero-Clause BSD).

## Architecture

Zeroio separates pure, platform-independent protocol & congestion-control logic (`forbid(unsafe_code)`, sans-I/O) from eBPF kernel programs and OS dataplane drivers:

| Crate | Role | Safety / Target |
| --- | --- | --- |
| [`zeroio`](crates/zeroio) | Unified public facade crate | Pure Rust, cross-platform |
| [`zeroio-core`](crates/zeroio-core) | Congestion control (`EdgeCC`, BBRv3, CUBIC), deterministic network simulator (`sim`), zero-copy L2–L4 packet view, TLS SNI / QUIC DCID inspection, and sans-I/O TCP/UDP core | `#![forbid(unsafe_code)]`, sans-I/O |
| [`zeroio-xdp-common`](crates/zeroio-xdp-common) | Shared `#[repr(C)]` ABI types for XDP eBPF maps, flow keys, rate buckets, and counters | `no_std`-compatible |
| [`zeroio-xdp-ebpf`](crates/zeroio-xdp-ebpf) | XDP/eBPF kernel dataplane (ACL drop, per-IP rate limiting, L4 splice/NAT, AF_XDP redirect) | Nightly BPF (`bpfel-unknown-none`) |
| [`zeroio-dataplane`](crates/zeroio-dataplane) | Thread-per-core dataplane runtime configuration, AF_XDP UMEM/XSK queue abstractions, and kernel fallback policy | Cross-platform control, Linux AF_XDP execution |

## Design Principles

1. **Pure safe core (`forbid(unsafe_code)`)**: Protocol state machines, congestion control, scheduling, and packet parsing live in `zeroio-core` with zero runtime or OS dependencies.
2. **Thread-per-core & sans-I/O**: Designed to avoid cross-thread `mpsc` hops and contiguous ring-buffer copies between NIC RX queues and protocol state machines.
3. **O(1) / O(log N) server-grade scheduling**: Generation-checked slab handles, timing wheels, and ready-queue dispatch instead of linear per-socket scans.
4. **Deterministic simulation (`sim`)**: Validate congestion control, packet loss, reordering, and pacing in milliseconds on macOS/Linux without requiring root or real NICs.
5. **Dual-mode pragmatism**: Use XDP `protect` (driver-level DDoS drop/rate-limit) + L4 eBPF splice alongside kernel TCP/BBR where appropriate, and swap in userspace TCP/QUIC on `XDP_ZEROCOPY` hardware without changing application integration.

## Quick Start

```bash
# Check and test the workspace (macOS & Linux)
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings

# Run the deterministic congestion-control simulator example
cargo run -p zeroio-core --release --example sim_acceptance
```

## License

This project is licensed under the [Zero-Clause BSD (0BSD)](LICENSE) license.
