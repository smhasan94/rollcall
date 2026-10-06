# Changelog

All notable changes to rollcall are documented in this file. The format is based on
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and rollcall follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); see
[docs/versioning.md](docs/versioning.md) for what counts as a breaking change and for the MSRV
policy. The identifier database (`rollcall-identifiers`) is versioned on its own.

## [Unreleased]

### Added

- **`rollcall assay` skeleton and the CBOM model (SHA-138).** Crypto assets in the model
  (`cryptographic-asset` components with CycloneDX 1.6 `cryptoProperties`: algorithm,
  protocol, certificate and related crypto material), each with evidence (source line, ELF
  symbol, Kconfig symbol or Cargo feature) and a high/medium/low confidence with a one-line
  reason. The CycloneDX writer emits `cryptoProperties` and the reader reads them back
  losslessly. `rollcall assay --model|--source|--build|--elf --format cyclonedx|md` writes a
  CBOM or a Markdown summary table; it has no detectors yet, so a build gives an empty CBOM
  marked `rollcall:assay:detectors` = `none`. See [docs/assay.md](docs/assay.md).
- **Algorithm catalogue (SHA-139).** `crates/rollcall-assay/db/algorithms.yaml`, the single
  source of truth for the algorithms `rollcall assay` reports (RSA, DSA, DH, ECDSA, ECDH,
  Ed25519, X25519, AES modes, ChaCha20-Poly1305, SHA-2, SHA-3, SHAKE, HMAC, HKDF, PBKDF2, ML-KEM,
  ML-DSA, SLH-DSA, LMS, HSS, XMSS, XMSS^MT): each parameter set's classical and NIST quantum
  security level with its source, a quantum-risk class (shor-broken, grover-weakened, pq-safe)
  and the CycloneDX words. A loader, lint and `(algorithm, parameter set)` lookup in
  `rollcall-assay` that returns the CycloneDX `algorithmProperties` (unknown entries are an
  error), a JSON Schema as the export contract, and `scripts/check-catalogue-sync.sh` for
  cbom-infra's copy. See [docs/catalogue.md](docs/catalogue.md).

## [0.1.0] - 2026-10-05

The first release. Release notes: [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md).

### Added

- **Core model and CycloneDX writer (E1).** A component-graph model with evidence,
  confidence and deterministic ordering, `bom-ref`s derived from content, and a CycloneDX 1.6
  JSON writer validated against the vendored official schema. `--timestamp` and
  `--serial-number` make the output byte-identical across runs.
- **Zephyr ingestion and MCUboot merge (E2).** `rollcall generate --zephyr` reads `west spdx`,
  `west list`, Kconfig `.config` and `build_info.yml`; `--sysbuild` makes one product of
  MCUboot and the application; `--product NAME[@VERSION]` names it. `rollcall merge` combines
  separately generated SBOMs and binary blobs from a `--blob-manifest` into one product
  hierarchy. Real Zephyr v4.4.2 build fixtures for the nRF52840 DK.
- **Identifier database (E3).** Module to upstream purl and CPE resolution, seeded with Zephyr
  modules and fork-to-upstream version tables, packaged and versioned on its own, with
  `rollcall identifiers lint`, a CI lint and a contribution guide.
- **Subsystem decomposition and blobs (E4).** The `zephyr` component split into the
  subsystems the build enabled (Kconfig) and linked (link map); static-archive blobs typed as
  `library`.
- **VEX engine (E5).** `rollcall vex`: a rule format evaluated against Kconfig evidence, a
  starter rule pack with worked examples, CycloneDX VEX and OpenVEX output, and optional
  signing (Ed25519 or Sigstore cosign) with `rollcall vex verify`.
- **Scan and validate (E6).** `rollcall scan` runs grype and osv-scanner, normalises and
  triages their findings and exits 0 to 3 for CI. `rollcall validate` checks the CycloneDX 1.6
  schema and the CISA 2026 and CRA profiles. `rollcall report` writes a readiness report
  (Markdown and `rollcall-report/1` JSON).
- **Distribution (E7).** The GitHub Action (`action/`) with a pull-request comment, a diff
  against the base branch (`rollcall diff`) and a gate on new findings; release binaries for
  Linux (amd64, arm64), macOS (universal) and Windows (amd64) with `SHA256SUMS`;
  `cargo install rollcall`; `pip install rollcall`; the docs site; this changelog,
  `SECURITY.md` and the versioning policy.
- **More ecosystems (E8).** Cargo (`cargo metadata` and the `cargo auditable` dependency list),
  ESP-IDF (subsystem split and Espressif blobs) and PlatformIO; `rollcall detect` and
  `rollcall generate DIR` tell the four apart.
- **Adoption (E9).** `rollcall csaf` exports CSAF 2.0 VEX documents for cra-clock; the Zephyr
  `west spdx` gap analysis.

### Changed

- The `rollcall` crate is now the command-line binary (`cargo install rollcall`), replacing the
  `rollcall-cli` package, which is no longer published (its 0.0.1 placeholder stays).
- README simplified; reference material moved into docs/ (installing, cli, building).

### Removed

- The reserved `rollcall generate --format spdx` value, which printed "not implemented". SPDX
  export is deferred ([#37](https://github.com/smhasan94/rollcall/issues/37)).

## [0.0.1] - 2026-09-29

### Added

- Placeholder releases reserving the names `rollcall`, `rollcall-core`, `rollcall-cli` and
  `rollcall-assay` on crates.io and `rollcall` on PyPI.

[Unreleased]: https://github.com/smhasan94/rollcall/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/smhasan94/rollcall/releases/tag/v0.1.0
[0.0.1]: https://pypi.org/project/rollcall/0.0.1/
