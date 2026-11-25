# Zeroio Architecture & Invariants

## 1. Crate Dependency Graph

```text
          +-------------------+
          |      zeroio       |  (public facade crate)
          +---------+---------+
                    |
        +-----------+-----------+
        |                       |
        v                       v
+---------------+     +--------------------+
|  zeroio-core  |     |  zeroio-dataplane  |
|  (#![forbid(  |     |  (thread-per-core  |
|   unsafe)])   |     |   AF_XDP / XSK)    |
+---------------+     +---------+----------+
        ^                       |
        |                       v
        |             +--------------------+     +-------------------+
        +-------------+ zeroio-xdp-common  |<----+  zeroio-xdp-ebpf  |
                      | (no_std #[repr(C)])|     | (kernel XDP prog) |
                      +--------------------+     +-------------------+
```

## 2. Core Design Invariants

### 2.1 Sans-I/O Separation (`zeroio-core`)
- `zeroio-core` contains **zero** syscalls, sockets, timers, threads, or async runtimes.
- All time-dependent algorithms accept [`TransportInstant`] explicitly so identical state machines run identically in production dataplane workers and in the deterministic `sim` event-driven simulator.
- `unsafe` is forbidden at crate level (`#![forbid(unsafe_code)]`).

### 2.2 Stable Kernel/Userspace ABI (`zeroio-xdp-common`)
- Must always compile under `no_std` (`--no-default-features`) so `zeroio-xdp-ebpf` and `zeroio-dataplane` share one source of truth.
- Every map key, value, and counter struct is `#[repr(C)]` with explicit padding fields and `size_of` / alignment unit tests.

### 2.3 Zero-Copy Frame Ownership (`zeroio-dataplane`)
- NIC RX/TX operates over pre-registered UMEM slabs divided into fixed frames (`XDP_DEFAULT_FRAME_SIZE`, default 2048 B).
- Each packet buffer in flight is tracked by an owned `UmemFrameToken { queue, addr, len }` bound to a single per-queue worker core.
- Frames are parsed in place via zero-copy slices (`PacketView`, `extract_tls_sni`, `inspect_quic_header`) and returned directly to the AF_XDP Fill/TX rings without intermediate payload copies or cross-thread channel hops.

### 2.4 Explicit XDP Operating Modes & Fallback
- `Observe`: attach XDP, collect per-CPU `XdpCounters`, pass all packets (`XDP_PASS`).
- `Protect`: enforce driver-level ACL and per-IP rate limiting in eBPF; valid flows continue to kernel TCP/BBR (`XDP_PASS`).
- `Proxy`: enforce protection, run eBPF L4 splice/NAT where eligible, and `XDP_REDIRECT` matched ports into per-queue `XskMap` sockets (`XDP_ZEROCOPY` preferred, `XDP_COPY` or `KernelFallback` explicitly surfaced—never silently masked).
