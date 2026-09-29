# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

## Status

Skeleton. Every subcommand exists but prints `not implemented` and exits 64. The 0.0.1
releases of `rollcall`, `rollcall-core`, `rollcall-cli` and `rollcall-assay` on crates.io and
`rollcall` on PyPI are placeholders that reserve the names.

## Workspace layout

| Crate            | Purpose                                                        |
|------------------|----------------------------------------------------------------|
| `rollcall-core`  | Component-graph model and ingestion.                           |
| `rollcall-cli`   | The `rollcall` binary.                                         |
| `rollcall-assay` | Cryptographic inventory (CycloneDX CBOM), run as `rollcall assay`. |
| `rollcall`       | Name-reservation placeholder; no code.                         |

`python/` holds the placeholder for the `pip install rollcall` wrapper.

## Subcommands

| Command             | Description                                                              |
|---------------------|--------------------------------------------------------------------------|
| `rollcall generate` | Generate a CycloneDX SBOM from firmware build metadata                   |
| `rollcall validate` | Validate an SBOM against the CycloneDX schema and rollcall's rules       |
| `rollcall merge`    | Merge bootloader, application and blob SBOMs into one product hierarchy  |
| `rollcall vex`      | Emit VEX statements for an SBOM                                          |
| `rollcall scan`     | Scan an SBOM for known vulnerabilities                                   |
| `rollcall assay`    | Produce a CycloneDX CBOM (cryptographic inventory) for a build           |

## Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | Success (including `--help`, `--version`) |
| 64   | Usage error, or subcommand not implemented |

## Building

```sh
cargo build && cargo test
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
