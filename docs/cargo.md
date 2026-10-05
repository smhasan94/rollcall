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

The flags, purls, evidence and warnings are under [Ingestion](#ingestion) below. The
module docs of `rollcall_core::cargo` have the full mapping.

## Ingestion

`--cargo DIR` runs `cargo metadata --format-version 1 --locked [--filter-platform TRIPLE]` in
the package directory, so its own `.cargo/config.toml` applies (`$CARGO`, else `cargo` on
PATH; it needs a `Cargo.lock`). Cargo may use the network to resolve sources it has not
cached; set `CARGO_NET_OFFLINE=true` to forbid that. `--cargo-metadata FILE` reads that output
from a file instead (capture it with
`--filter-platform` so it is resolved for the binary's target). The root package is the
product and its one `application` image; every crate is a `library` component.

- With `--elf FILE`, a binary built with `cargo auditable`, the crates its `.dep-v0` section
  lists are the components: exactly what went into the binary, build-only crates (proc macros,
  build-script dependencies) included. Crates only in the metadata (dev-dependencies, crates of
  other platforms, crates the build did not need) are left out, or, with
  `--include-unlinked`, listed with CycloneDX `scope: excluded`. grype and osv-scanner ignore
  `scope`, so they still report vulnerabilities in crates marked excluded. An ELF without `.dep-v0`
  ("not built with `cargo auditable`") or built from another package is an error (exit 65).
- Without `--elf`, the components are the normal and build dependencies the metadata
  resolves (what `cargo tree -e normal,build` lists), with a warning. Without `--target`,
  `--cargo` lists every platform's dependencies, with a warning.
- Purls: crates.io `pkg:cargo/<name>@<version>`; git
  `pkg:generic/<name>@<version>?vcs_url=git%2B<url>%40<commit>`; path
  `pkg:generic/<name>@<version>` (no host path). A git source whose revision is not a full
  commit sha (a branch, say) gets a `vcs_url` without one, and a warning. Two crates with the
  same name and version from different sources are an error (exit 65). The licence is the
  crate's `license` field (the legacy `MIT/Apache-2.0` form read as `MIT OR Apache-2.0`).
- Evidence: `cargo-metadata` (name, version, purl, licence, and one `feature:<name>` name
  entry per enabled feature) and `cargo-auditable` (name and version, for each crate the
  binary lists), located at the input's file name. Features are cargo's unified set, so with
  resolver 2 a crate built for both host and target shows the union.
- A workspace without a root package (a virtual workspace) is an error: run it in the
  binary's package. One application image per run; a bootloader and an application are two
  runs combined with `merge`.

The full mapping is in the `rollcall_core::cargo` module docs. `fixtures/cargo-*/` hold real
`cargo auditable` builds, among them keelsign's `examples/nrf52840-hello`
([fixtures.md](fixtures.md#cargo-fixtures)).

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
