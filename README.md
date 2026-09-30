# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

## Status

Early development. `rollcall generate --zephyr <build-dir>` ingests a Zephyr image build
directory (`west spdx` documents, `west list` output, Kconfig `.config`, `build_info.yml`) and
writes a CycloneDX 1.6 JSON SBOM; `rollcall generate --model` renders a rollcall model (the
internal `rollcall-model/1` JSON form) the same way; and `rollcall validate --schema` checks a
document against the official CycloneDX 1.6 JSON schema. Merging the MCUboot bootloader into
the same product is not implemented yet, and neither are `merge`, `vex`, `scan` and `assay`,
which print `not implemented` and exit 64. The 0.0.1 releases of `rollcall`, `rollcall-core`,
`rollcall-cli` and `rollcall-assay` on crates.io and `rollcall` on PyPI are placeholders that
reserve the names.

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
# Generate an SBOM from a Zephyr image build directory (stdout, or -o FILE).
west list -f "{name} {path} {revision} {url}" > west-list.txt
rollcall generate --zephyr build/app --west-list west-list.txt --include-sdk -o app.cdx.json

# Render a model as CycloneDX 1.6 JSON.
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

Exactly one of `--model` and `--zephyr` is required; `--west-list` and `--include-sdk` only
go with `--zephyr`.

`validate` prints `<file>: valid CycloneDX 1.6` on success, or `<file>: <n> schema
violation(s)` followed by one `  <JSON pointer>: <message>` line per violation, sorted.

### Zephyr ingestion

Pass the *image* build directory, the one holding `build_info.yml` and `spdx/` (with
sysbuild that is `build/<app>/`, not `build/`; the top-level directory is refused with a
message naming the image directory to use). Run `west spdx --init -d <build>` before the
build and `west spdx -d <build>` after it to create `spdx/`.

- Required: `build_info.yml` and `spdx/zephyr.spdx`.
- Optional, each with a `rollcall generate: warning: …` line on stderr when missing (the
  exit code stays 0): `spdx/app.spdx`, `spdx/build.spdx`, `spdx/modules-deps.spdx`,
  `zephyr/.config`, and the `--west-list` file. A `--west-list` file that is named but
  missing is an error.
- The application is the product and its one `application` image. Zephyr is an
  `operating-system` component versioned by its release (e.g. `4.4.2`), with the commit it
  was built from recorded as `pkg:github/zephyrproject-rtos/zephyr@<sha>` purl evidence.
- Every west module appears exactly once as a `library` component whose version is the git
  revision it was built at (from `west list`, else from `zephyr.spdx`), with the upstream
  purl, cpe and supplier from `modules-deps.spdx` when the module declares them, and a purl
  pinned to the revision otherwise.
- `spdx/zephyr.spdx` decides which modules exist. A `west list` row for Zephyr itself (as in a
  T2 workspace, where the application is the manifest repository) becomes evidence on the
  Zephyr component; any other row that is not a module of the build is ignored with a warning.
- `--include-sdk` adds the toolchain as an `application` component (`zephyr-sdk`, versioned
  `major.minor` from `CONFIG_TOOLCHAIN_ZEPHYR_<M>_<N>`).
- `west list` output comes from `west list -f "{name} {path} {revision} {url}"` run in the
  west workspace.

Every fact carries evidence naming the file and line it came from. The full mapping is in the
`rollcall_core::zephyr` module docs.

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
| 65   | Input is malformed: not JSON, not UTF-8, too deeply nested, or an invalid model; or a Zephyr input (SPDX, `west list`, `.config`, `build_info.yml`) is malformed, or `--zephyr` names a sysbuild top-level directory |
| 66   | Input file missing or unreadable (including a directory), including a required Zephyr input or the `--west-list` file |
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

Golden files (`crates/rollcall-core/tests/golden/`, including the Zephyr ingestion goldens in
`golden/zephyr/`) are never edited by hand. Regenerate all of
them, and re-run the tests that compare against them, with one command:

```sh
scripts/regen-golden.sh
```

`scripts/smoke-scan.sh --install` (needs the network) downloads pinned, SHA-256-verified
releases of grype and osv-scanner into `.cache/tools/`, renders the fixtures in
`crates/rollcall-core/tests/data/`, and checks that both scanners load them without
warnings, see every component, and report zero findings for the minimal fixture. It prints a
PASS/FAIL table and runs in CI as the `smoke` job.

## Zephyr build fixtures

`fixtures/zephyr/` holds real build outputs (`west spdx`, `west list`, Kconfig `.config`,
`build_info.yml`, maps, stripped ELFs and hex images) from a pinned, vanilla Zephyr v4.4.2
built for `nrf52840dk/nrf52840` with sysbuild and MCUboot, in three variants (baseline,
Bluetooth, TLS). `MANIFEST.json` there records the pins and the SHA-256 of every file. They
are produced only by `scripts/regen-fixtures.sh`; the committed copy comes from the
`regen-fixtures` workflow. See [docs/fixtures.md](docs/fixtures.md).

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
