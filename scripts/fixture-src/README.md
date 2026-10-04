# Hand-written Cargo fixture sources

These projects are **hand-written fixture sources** (SHA-127), not real-build output. They
are inputs: `scripts/regen-fixtures-cargo.sh` copies each one into `.cache/`, builds it for
real with `cargo auditable` for `thumbv7em-none-eabihf`, and writes the build's output
(`cargo metadata`, `cargo tree`, the ELF and its `.dep-v0` list) under `fixtures/cargo-*/`.
Only that script writes `fixtures/`; see `docs/fixtures.md`.

| Project | Fixture | Why it exists |
|---------|---------|---------------|
| `cargo-deps/` | `fixtures/cargo-deps/` | The dependency kinds the keelsign demo app (`fixtures/cargo-keelsign/`) does not have: a git dependency (`panic-halt` at a pinned commit), a path dependency (`crates/board-support`), a dev-dependency (`static_assertions`, never linked) and a host-only `cfg(unix)` dependency (`itoa`, never built for the target). |
| `cargo-old-heapless/` | `fixtures/cargo-old-heapless/` | A deliberately old crate, `heapless =0.5.6` (GHSA-qgwf-r2jj-2ccv, fixed in 0.6.1), so the CI job `grype-cargo-advisory` can check grype finds a known advisory in rollcall's output. |

Each has its own `[workspace]` table, so it is not part of the rollcall workspace, and a
committed `Cargo.lock`, so `--locked` builds resolve the same crates every time.
