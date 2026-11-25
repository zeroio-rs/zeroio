## Summary

<!-- Describe the scope and motivation of this change. -->

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo check --workspace --all-targets`
- [ ] `cargo check -p zeroio-xdp-common --no-default-features`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`

## Invariants Checklist

- [ ] No `unsafe` introduced into `zeroio-core`; any `unsafe` in `zeroio-dataplane` / `zeroio-xdp-ebpf` has a `// SAFETY:` comment.
- [ ] No per-packet heap allocations or panicking unwraps on untrusted wire input.
- [ ] No process artifacts (`tasks/`, `evidence/`, dated logs) or private downstream references committed.
