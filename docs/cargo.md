# Cargo

`rollcall generate --cargo` (a package directory) or `--cargo-metadata` (captured
`cargo metadata` output) turns a Rust firmware binary into a CycloneDX 1.6 SBOM. Its crates come
from `cargo metadata`. For a binary built with `cargo auditable` (`--elf`), the crates come from
the `.dep-v0` section, so the SBOM lists exactly what was linked.

## Usage

```sh
cargo auditable build --release --target thumbv7em-none-eabihf
rollcall generate --cargo . --target thumbv7em-none-eabihf \
  --elf target/thumbv7em-none-eabihf/release/app -o sbom.cdx.json
```

The flags, purls, evidence and warnings are in the [README](../README.md#cargo-ingestion). The
module docs of `rollcall_core::cargo` have the full mapping.

## Auto-detect

`rollcall generate DIR` treats DIR as Cargo when it holds `Cargo.toml`, a package directory, as
`--cargo DIR`. Otherwise it treats DIR as Cargo when it holds `cargo-metadata.json`, captured
metadata, as `--cargo-metadata DIR/cargo-metadata.json`. `--elf`, `--include-unlinked` and
(for a package directory) `--target` are not inferred; pass them with DIR. `--target` with
captured metadata exits 64, because the metadata was resolved when it was captured.

```console
$ rollcall detect fixtures/cargo-keelsign
cargo
```

Every ecosystem's signal is in the [docs index](README.md#ecosystems).

## Further reading

- [fixtures.md](fixtures.md#cargo-fixtures): the Cargo fixtures.
