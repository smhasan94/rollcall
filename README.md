# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

## Status

Early development. `rollcall generate` renders a rollcall model (the internal
`rollcall-model/1` JSON form) as a CycloneDX 1.6 JSON SBOM, and `rollcall validate --schema`
checks a document against the official CycloneDX 1.6 JSON schema. Ingesting real build
metadata (`west spdx`, `west list`, Kconfig, MCUboot) is not implemented yet, and neither are
`merge`, `vex`, `scan` and `assay`, which print `not implemented` and exit 64. The 0.0.1
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

## Usage

```sh
# Render a model as CycloneDX 1.6 JSON (stdout, or -o FILE).
rollcall generate --model product.model.json -o product.cdx.json

# Pin the timestamp (RFC 3339, normalised to UTC) and/or the serial number for
# reproducible output. By default the timestamp is the current time and the serial number
# is derived from the model's content.
rollcall generate --model product.model.json --timestamp 2026-01-02T03:04:05Z \
    --serial-number urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79

# Check a document against the vendored CycloneDX 1.6 JSON schema.
rollcall validate --schema product.cdx.json
```

`generate --format spdx` is reserved and not implemented yet. The same model and options
always produce byte-identical output; changing only `--timestamp` changes only the
`timestamp` line. How each model field maps to CycloneDX is documented in the
`rollcall_core::cyclonedx` module docs (`cargo doc -p rollcall-core --open`).

`validate` prints `<file>: valid CycloneDX 1.6` on success, or `<file>: <n> schema
violation(s)` followed by one `  <JSON pointer>: <message>` line per violation, sorted.

### Known scanner behaviour

grype (verified with 0.119.0) silently ignores CycloneDX components of type
`operating-system`. It treats them as distro information, not packages, so it does not scan
them for vulnerabilities. rollcall labels components accurately anyway: how an RTOS kernel
such as Zephyr is typed is decided at ingestion. osv-scanner is unaffected.

## Exit codes

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| 0    | Success (including `--help`, `--version`)                                |
| 1    | `validate`: the document has schema violations                           |
| 64   | Usage error (bad arguments, bad `--timestamp` or `--serial-number`), or subcommand/format not implemented |
| 65   | Input is malformed: not JSON, not UTF-8, too deeply nested, or an invalid model |
| 66   | Input file missing or unreadable (including a directory)                 |
| 74   | Output cannot be written                                                 |

## CycloneDX schema

The official CycloneDX 1.6 JSON schemas (`bom-1.6.schema.json`, `spdx.schema.json`,
`jsf-0.82.schema.json`) are vendored verbatim in `crates/rollcall-core/schema/cyclonedx/`,
pinned to CycloneDX/specification tag `1.6.2` (commit
`e833d732337dd33aceb45ff1991f896796f1e5e7`), and compiled into the binary, so validation
never uses the network. `SOURCE.md` there records the URLs and SHA-256s. To re-fetch them,
run `scripts/vendor-cyclonedx-schema.sh`, which refuses any file whose SHA-256 does not match.

## Building

```sh
cargo build && cargo test
```

Golden files (`crates/rollcall-core/tests/golden/`) are never edited by hand. Regenerate all of
them, and re-run the tests that compare against them, with one command:

```sh
scripts/regen-golden.sh
```

`scripts/smoke-scan.sh --install` (needs the network) downloads pinned, SHA-256-verified
releases of grype and osv-scanner into `.cache/tools/`, renders the fixtures in
`crates/rollcall-core/tests/data/`, and checks that both scanners load them without
warnings, see every component, and report zero findings for the minimal fixture. It prints a
PASS/FAIL table and runs in CI as the `smoke` job.

## Publishing the placeholders

Crates must be published dependencies first: `rollcall-core` and `rollcall-assay`, then
`rollcall-cli`, then `rollcall` (or simply `cargo publish --workspace`, which orders them).
Then the PyPI placeholder:

```sh
cd python && uv build && uv publish
```

Check the reservations with `ROLLCALL_CRATES_OWNER=<crates.io login> ./scripts/check-names.sh`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
