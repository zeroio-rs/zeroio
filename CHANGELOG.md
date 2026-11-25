# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-26

### Added
- `zeroio-core`: `#![forbid(unsafe_code)]` sans-I/O transport core including `EdgeCc`, reference congestion controllers (`Bbr3Ref`, `CubicRef`, `NewRenoRef`, `LossBlindRef`), `RateSampler`, `RttState`, `AccEcn`, `PathModel`, `Inference`, `Envelope`, `Codel`, `Scheduler`, `TimingWheel`, `ConnSlab`, zero-copy `PacketView`, TLS SNI / QUIC header inspection, and deterministic network simulator (`sim`).
- `zeroio-xdp-common`: `no_std`-compatible `#[repr(C)]` XDP ABI types (`XdpInterfaceMode`, `XdpFlowKey`, `XdpRateBucket`, `XdpCounters`).
- `zeroio-xdp-ebpf`: baseline Aya XDP eBPF entrypoint (`XDP_PASS` + per-CPU `XdpCounters`).
- `zeroio-dataplane`: `InterfaceConfig`, `XdpAttachMode`, `XskBindMode`, and `UmemFrameToken` abstractions.
- `zeroio`: unified `0BSD` public facade crate published on crates.io and docs.rs.
