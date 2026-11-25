# Zeroio

[![Crates.io](https://img.shields.io/crates/v/zeroio.svg)](https://crates.io/crates/zeroio)
[![Docs.rs](https://docs.rs/zeroio/badge.svg)](https://docs.rs/zeroio)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue.svg)](LICENSE)
[![CI](https://github.com/zeroio-rs/zeroio/actions/workflows/ci.yml/badge.svg)](https://github.com/zeroio-rs/zeroio/actions/workflows/ci.yml)

**Memory-safe, zero-copy Rust network dataplane** — unifying XDP/AF_XDP packet filtering & forwarding, modern congestion control, zero-copy L2–L4.5 packet inspection (SNI / QUIC DCID), and a server-grade sans-I/O userspace transport core.

Licensed under **0BSD** (Zero-Clause BSD).

## Why Zeroio?

Existing userspace Rust stacks such as `smoltcp` are optimized for embedded and low-concurrency environments (linear socket scans, contiguous ring-buffer copies). **Zeroio** targets high-concurrency servers, proxies, and edge gateways:

- **Pure safe protocol core (`#![forbid(unsafe_code)]`)**: Congestion control, packet parsing, inspection, scheduling, and state machines live in `zeroio-core` with zero OS or async-runtime dependencies.
- **Zero-copy & Thread-per-Core**: Built around owned UMEM frame tokens, scatter-gather slices, and per-queue polling loops — avoiding cross-thread `mpsc` hops and redundant payload copies.
- **O(1) / O(log N) server primitives**: Generation-checked slab handles (`ConnSlab`), timing wheels (`TimingWheel`), DRR pacing scheduler, and CoDel AQM.
- **XDP-native defense & bypass**: Keep driver-level ACL/rate-limit protection and L4 eBPF splice while allowing L7 traffic to either use kernel TCP/BBR (`XDP_PASS`) or run on AF_XDP `XDP_ZEROCOPY` hardware.
- **Deterministic simulation (`sim`)**: Test packet loss, reordering, shared-bottleneck inference, and congestion-control behavior in milliseconds on macOS or Linux without root privileges.

## Workspace Crates

| Crate | Role | Safety / Target |
| --- | --- | --- |
| [`zeroio`](crates/zeroio) | Unified public facade crate | Pure Rust, cross-platform |
| [`zeroio-core`](crates/zeroio-core) | Congestion control (`EdgeCC`, BBRv3, CUBIC, NewReno), `sim` deterministic simulator, zero-copy `PacketView`, TLS SNI / QUIC DCID inspection, and sans-I/O TCP/UDP primitives | `#![forbid(unsafe_code)]`, sans-I/O |
| [`zeroio-xdp-common`](crates/zeroio-xdp-common) | Shared `#[repr(C)]` ABI types for XDP eBPF maps, 5-tuple keys, rate buckets, and per-CPU counters | `no_std`-compatible |
| [`zeroio-xdp-ebpf`](crates/zeroio-xdp-ebpf) | XDP/eBPF kernel program (driver-level ACL, per-IP rate limiting, L4 splice/NAT, AF_XDP redirect) | Nightly BPF (`bpfel-unknown-none`) |
| [`zeroio-dataplane`](crates/zeroio-dataplane) | Thread-per-core dataplane configuration, AF_XDP UMEM/XSK queue abstractions, and kernel fallback policy | Cross-platform control, Linux AF_XDP execution |

## Status & Roadmap (`v0.1.0`)

- **Included in `v0.1.0`**:
  - `zeroio-core`: `EdgeCC`, BBRv3/CUBIC/NewReno reference controllers, `RateSampler`, `RttState`, `AccEcn`, `PathModel`, `Inference`, `Envelope`, `Codel`, `Scheduler`, `TimingWheel`, `sim`, zero-copy `PacketView`, `extract_tls_sni`, `inspect_quic_header`, and `ConnSlab`.
  - `zeroio-xdp-common` & `zeroio-xdp-ebpf`: baseline `#[repr(C)]` ABI types and XDP `XDP_PASS` + per-CPU counter entrypoint.
  - `zeroio-dataplane` & `zeroio`: cross-platform configuration/policy abstractions and facade exports.
- **Next milestones**:
  - Full sans-I/O server TCP state machine in `zeroio-core` with zero-copy scatter-gather RX/TX rings.
  - Linux AF_XDP `XDP_ZEROCOPY` per-queue reactor and eBPF ACL / rate-limit / L4 splice programs.

## Quick Start

```bash
# Run workspace checks and tests
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings

# Run the deterministic congestion-control simulator
cargo run -p zeroio-core --release --example sim_acceptance
```

## License

Licensed under the [Zero-Clause BSD (0BSD)](LICENSE) license.
