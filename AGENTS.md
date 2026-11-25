# AGENTS.md — Zeroio Engineering & Repository Constraints

Zeroio is an **open-source (0BSD), memory-safe, zero-copy Rust network dataplane**.
Keep this repository lean, clean, and strictly decoupled from private downstream products.

## 1. Repository Cleanliness & Documentation Discipline

- **No process-artifact bloat**: Never commit `tasks/`, `plans/`, `evidence/`, `perf-reports/`, `CURSOR.md`, `todo.md`, AI handoff notes, or dated investigation logs (`*-2026-*.md`) into this repository. Keep investigation notes in Issues, PR descriptions, or an untracked `.local/` directory.
- **Allowed top-level Markdown files only**:
  - `README.md` — crate overview, status, and quick start
  - `AGENTS.md` — engineering & agent constraints (this file)
  - `ARCHITECTURE.md` — crate boundaries, ownership model, and dataplane invariants
  - `CHANGELOG.md` — release history by semantic version
- **API documentation lives in code**: Document public items with `//!` / `///` Rustdoc comments checked by CI (`RUSTDOCFLAGS="-D warnings"`). Do not duplicate API reference docs in separate Markdown files.

## 2. Crate Boundaries & Safety Invariants

| Crate | Allowed Scope | Hard Invariant |
| --- | --- | --- |
| `zeroio-xdp-common` | Shared `#[repr(C)]` ABI types & constants | Must compile with `--no-default-features` (`#![no_std]`). Explicit padding and layout tests required for every ABI struct. |
| `zeroio-core` | Congestion control, packet parsing/inspection, sans-I/O TCP/UDP, scheduling, deterministic `sim` | **`#![forbid(unsafe_code)]`**. Pure sans-I/O: zero OS sockets, zero async runtime deps, no `std::time::Instant::now()` inside state machines (pass `TransportInstant` explicitly). |
| `zeroio-dataplane` | Thread-per-core AF_XDP / UMEM / XSK runtime & kernel fallback | `unsafe` strictly confined to Linux FFI/UMEM/ring modules with a `// SAFETY:` comment on every `unsafe` block. |
| `zeroio-xdp-ebpf` | Kernel XDP/eBPF program (`bpfel-unknown-none`) | Verifier-safe bounded loops, explicit bounds checks, `// SAFETY:` on every `unsafe` block, `publish = false`. |
| `zeroio` | Public facade crate | Re-exports stable public surfaces only; no implementation logic. |

## 3. Hot-Path & Reliability Rules

- **Zero per-packet heap allocation**: No `Vec`, `String`, `Box`, or `format!` on L2–L4 parsing, SNI/QUIC inspection, congestion control, pacing, or XSK RX/TX packet loops.
- **No panics on untrusted wire input**: Never call `unwrap()`, `expect()`, `panic!()`, or unchecked indexing on packet bytes or remote peer fields. Malformed inputs must fail-closed with typed errors or drop/parse counters.
- **Thread-per-Core ownership**: Per-queue dataplane loops own their UMEM frame slots (`UmemFrameToken`) and connection slabs (`ConnSlab`) without cross-thread `mpsc` hops or mutexes on the packet path.
- **No silent degradation**: Never swallow errors, fabricate metrics/success states, or disable safety checks to make tests pass.
- **Deterministic simulation first**: New congestion-control, scheduling, or TCP state-machine behavior must have reproducible tests in `zeroio-core` (`sim` / unit tests) before dataplane integration.

## 4. Lints, Formatting & Toolchain

- Toolchain pinned to **Rust `1.100.0`** (`edition = "2024"`).
- Workspace lints deny all compiler warnings, broken/private Rustdoc links, `dbg!`, `todo!`, `unimplemented!`, and undocumented `unsafe` blocks.
- **Eliminate warnings at the root cause**: Never add blanket `#[allow(...)]` or `--cap-lints`. If an exception is genuinely unavoidable, use narrowly scoped `#[expect(lint, reason = "...")]`.

## 5. Open-Source & Clean-Room IP Policy (`0BSD`)

- Every crate in this repository (except `zeroio-xdp-ebpf` which is `publish = false`) is published under **`0BSD`**.
- **Strict decoupling**: Never reference or embed private downstream infrastructure, internal domains, production IPs, credentials, proprietary business logic, or internal product names.
- Do not copy code from GPL/AGPL or incompatible-license repositories.

## 6. Verification Gate & Commit Conventions

Run before pushing or opening a PR:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo check -p zeroio-xdp-common --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

- Commits use Conventional Commits (`<scope>: <summary>`, e.g. `core: ...`, `dataplane: ...`, `xdp: ...`, `ci: ...`).
- Author/committer must be the repository owner (`Zypixh <moying8259@gmail.com>`); no bot/AI `Co-Authored-By` trailers.
