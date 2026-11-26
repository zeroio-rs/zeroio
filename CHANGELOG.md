# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `zeroio-core`: complete sans-I/O TCP stack (`TcpStack`, `TcpConn`, `TcpConfig`, `SeqNum`, `RxBuffer`, `TxQueue`, `SynCookieKey`) with indexed O(log N) `ConnSchedule` min-heap timer/TX dispatch (zero per-tick `Vec` allocations), O(1) `TxQueue` `in_flight_bytes`/`has_lost` tracking and cumulative-ACK fast paths, Tail Loss Probe (RFC 8985 TLP), Zero-Window Probe (ZWP), and zero-copy `peek_rx`/`consume_rx` stream API; bounded UDP session table (`UdpTable`, `UdpSession`); sorted-bucket longest-prefix-match `PrefixIndex`; RFC 1071 IPv4/TCP/UDP checksums; TCP option codecs (`MSS`, `WindowScale`, `SACK`, `Timestamps`, RFC 9768 `AccECN` Order 0/1 Kind 172/174); zero-allocation Ethernet/VLAN/IPv4/IPv6 frame encoders (`encode_tcp_frame`, `encode_udp_frame`); zero-dependency microbenchmarks (`benches/core_bench.rs`); and end-to-end virtual-wire integration tests (`tests/tcp_stack.rs`).
- `zeroio-xdp-common`: expanded `no_std` eBPF ABI (`XdpRuntimeConfig`, `XdpIpV4`, `XdpIpV6`, `XdpAclRule`, `XdpPortKey`, `XdpPortRule`, `XdpSpliceTarget`, extended `XdpRateBucket` and `XdpCounters`) plus `no_std` RFC 1624 incremental checksum update helpers (`csum_replace_u16`, `csum_replace_u32`, `csum_replace_ipv6`, `pack_ipv4`).
- `zeroio-xdp-ebpf`: full `Observe` / `Protect` / `Proxy` XDP eBPF dataplane (`ZEROIO_ACL_V4`/`V6` LPM tries, `ZEROIO_RATE_V4`/`V6` per-IP & SYN-flood LRU limiters, `ZEROIO_SPLICE` IPv4/IPv6 L4 NAT/hairpin `XDP_TX`, and `ZEROIO_PORTS` -> `ZEROIO_XSKS` `XDP_REDIRECT`), compiled and linked cleanly for `bpfel-unknown-none`.
- `zeroio-dataplane`: cross-platform UMEM slab & frame-token lifecycle (`UmemConfig`, `UmemSlab`), neighbor/ARP table & codec (`NeighborTable`, `parse_arp_ipv4`, `encode_arp_reply_ipv4`), transport clock (`TransportClock`), abstract `XskDevice` + in-memory 4-ring `LoopbackXskDevice`, non-blocking single-core `QueueReactor` (ARP + TCP/UDP dispatch + CoDel/Scheduler + 50us busy-wait budget), thread-per-core `DataplaneManager` + `InterfaceConfig` validation, end-to-end loopback tests (`tests/dataplane_loopback.rs`), and Linux `#[cfg(target_os = "linux")]` `AF_XDP` 4-ring driver (`AfXdpDevice` with explicit `XDP_ZEROCOPY -> XDP_COPY` fallback), `aya` XDP controller (`XdpController`), and `sched_setaffinity` CPU pinning.

## [0.1.0] - 2026-11-26

### Added
- `zeroio-core`: `#![forbid(unsafe_code)]` sans-I/O transport core including `EdgeCc`, reference congestion controllers (`Bbr3Ref`, `CubicRef`, `NewRenoRef`, `LossBlindRef`), `RateSampler`, `RttState`, `AccEcn`, `PathModel`, `Inference`, `Envelope`, `Codel`, `Scheduler`, `TimingWheel`, `ConnSlab`, zero-copy `PacketView`, TLS SNI / QUIC header inspection, and deterministic network simulator (`sim`).
- `zeroio-xdp-common`: `no_std`-compatible `#[repr(C)]` XDP ABI types (`XdpInterfaceMode`, `XdpFlowKey`, `XdpRateBucket`, `XdpCounters`).
- `zeroio-xdp-ebpf`: baseline Aya XDP eBPF entrypoint (`XDP_PASS` + per-CPU `XdpCounters`).
- `zeroio-dataplane`: `InterfaceConfig`, `XdpAttachMode`, `XskBindMode`, and `UmemFrameToken` abstractions.
- `zeroio`: unified `0BSD` public facade crate published on crates.io and docs.rs.
