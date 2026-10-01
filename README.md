# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

## Status

Early development. `rollcall generate --zephyr <build-dir>` ingests a Zephyr image build
directory (`west spdx` documents, `west list` output, Kconfig `.config`, `build_info.yml`) and
writes a CycloneDX 1.6 JSON SBOM; with `--sysbuild` it ingests every image of a sysbuild
build (the MCUboot bootloader and the application) into one product. `rollcall merge`
combines separately generated SBOMs, and opaque binary blobs listed in a `--blob-manifest`,
into one product hierarchy. `rollcall generate --model` renders a rollcall model (the
internal `rollcall-model/1` JSON form) the same way; and `rollcall validate --schema` checks a
document against the official CycloneDX 1.6 JSON schema. `vex`, `scan` and `assay` are not
implemented yet; they print `not implemented` and exit 64. The 0.0.1 releases of `rollcall`,
`rollcall-core`, `rollcall-cli` and `rollcall-assay` on crates.io and `rollcall` on PyPI are
placeholders that reserve the names.

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

# A sysbuild build (MCUboot + application) as one product, in one step...
rollcall generate --zephyr build --sysbuild --west-list west-list.txt -o product.cdx.json

# ...or by hand: generate each image, then merge them under one product. The result is
# byte-identical to --sysbuild when --product names the application.
rollcall generate --zephyr build/app --west-list west-list.txt -o app.cdx.json
rollcall generate --zephyr build/mcuboot --west-list west-list.txt -o mcuboot.cdx.json
rollcall merge app.cdx.json mcuboot.cdx.json --product app -o product.cdx.json

# Add opaque binary blobs (radio firmware, vendor libraries) from a manifest.
rollcall merge product.cdx.json --blob-manifest blobs.yaml --product widget@1.2.0 -o widget.cdx.json
```

`generate --format spdx` is reserved and not implemented yet. The same model and options
always produce byte-identical output; changing only `--timestamp` changes only the
`timestamp` line. How each model field maps to CycloneDX is documented in the
`rollcall_core::cyclonedx` module docs (`cargo doc -p rollcall-core --open`).

Exactly one of `--model` and `--zephyr` is required; `--west-list`, `--include-sdk`,
`--sysbuild` and `--identifier-db` only go with `--zephyr`, and `--workspace` needs both
`--identifier-db` and `--west-list`.

### Merging

`rollcall merge FILE… [--product NAME[@VERSION]] [--blob-manifest FILE]` reads CycloneDX 1.6
documents (losslessly for documents rollcall wrote) and merges them. Each input's images
become images of the merged product; images and components with the same identity (kind,
name, version) at the same place are deduplicated, with their evidence merged, and a fact
the inputs disagree about is an error (exit 65). With `--product`, every input's images are
moved under that product: it replaces each input's root, so the roots' own facts (supplier,
purl, cpe, hashes, licence) and evidence are dropped. `NAME[@VERSION]` is split at the last
`@`, so a scoped name needs an explicit version (`--product @scope/widget@1.0.0`;
`--product @scope/widget` is rejected). Without `--product` the inputs must name the same
product and version, and a conflict names both files. Merging a document with itself gives
the same document. `--timestamp`, `--serial-number` and `-o` work as for `generate`.

A blob manifest lists files relative to the manifest's directory; relative paths may use
`..` to reach outside it, and absolute paths are accepted too. Each path must name a regular
file (a directory, FIFO or device is refused, exit 66):

```yaml
blobs:
  - path: s140_nrf52_7.3.0_softdevice.hex   # name, version, supplier recognised
    licence: LicenseRef-Nordic-5-Clause
  - name: radio-fw
    version: 2.1.0
    supplier: Example Radio Ltd
    path: radio/radio-fw.bin
    purl: pkg:generic/example/radio-fw@2.1.0
```

Each entry becomes a `blob` image with the file's SHA-256, the supplier, and the property
`rollcall:opaque` = `contents not analysed; hashes computed from the file`. Built-in
recognisers fill a missing name, version or supplier for Nordic SoftDevices
(`s<nnn>_nrf5<n>_<M.m.p>_softdevice.hex`) and common Espressif, Nordic and Silicon Labs HAL
libraries; licences are never guessed. Without input documents, `--product` is required.

`validate` prints `<file>: valid CycloneDX 1.6` on success, or `<file>: <n> schema
violation(s)` followed by one `  <JSON pointer>: <message>` line per violation, sorted.

### Zephyr ingestion

Pass the *image* build directory, the one holding `build_info.yml` and `spdx/` (with
sysbuild that is `build/<app>/`, not `build/`; the top-level directory is refused with a
message naming the image directory to use), or the sysbuild top-level directory with
`--sysbuild`, which reads the image list from its `build_info.yml` (`domains.yaml` is not
used), ingests every image (`--west-list` and `--include-sdk` apply to each) and merges them
under a product named after the `MAIN` application. Warnings are prefixed with the image
name. Two images that ingest to the same image (e.g. a second MCUboot build next to
`mcuboot`, both `bootloader:mcuboot`) are an error naming both directories (exit 65). Run `west spdx --init -d <build>` before the
build and `west spdx -d <build>` after it to create `spdx/`.

- Required: `build_info.yml` and `spdx/zephyr.spdx`.
- Optional, each with a `rollcall generate: warning: …` line on stderr when missing (the
  exit code stays 0): `spdx/app.spdx`, `spdx/build.spdx`, `spdx/modules-deps.spdx`,
  `zephyr/.config`, and the `--west-list` file. A `--west-list` file that is named but
  missing is an error.
- The application is the product and its one `application` image. An MCUboot build
  (`CONFIG_MCUBOOT=y`) is instead a `bootloader` image named `mcuboot`. Zephyr is an
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

### Identifier database

`--identifier-db FILE` resolves each module to its *upstream* project: the version of the
fork revision the build used, and from it the upstream purl, cpe and supplier that
vulnerability scanners match. It is optional; without it the output is unchanged.

```yaml
schema: 1
modules:
  mbedtls:
    upstream:
      name: Mbed TLS
      homepage: https://github.com/Mbed-TLS/mbedtls   # optional
      supplier: arm                                   # optional
    purl: pkg:github/Mbed-TLS/mbedtls@v{version}
    cpe: cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*  # optional
    version_rule:                                     # one of:
      kind: manual                                    #   manual: revision -> version table
      table:
        a3e190fe44c78d1ba67f55979e1257328cc7d0d8: 4.1.0
#   kind: git_tag,    pattern: '^v(?P<version>\d+\.\d+\.\d+)$'
#   kind: file_regex, file: include/version.h, pattern: '...(?P<version>...)...'
```

`git_tag` matches the revision itself, or a tag pointing at it; `file_regex` searches a
file in the module's sources. Both need the module sources, found with `--workspace DIR`
(the west workspace: each module is at `DIR/<west list path>`, so `--workspace` requires
`--west-list`, and `--identifier-db`; without either it is a usage error, exit 64).
Quote versions that YAML would read as numbers (`'2.0'`). The database is checked when it
is loaded: a malformed entry, an unknown key, or a purl or cpe template that does not render
to a valid purl or CPE 2.3 name is an error naming the file and line (exit 65); a missing
file is exit 66.

The module's `version` stays the git revision; the upstream version is recorded as evidence
and drives the purl and cpe, which are only filled in when a version was found (otherwise a
warning says why). A purl or cpe from `spdx/modules-deps.spdx` wins over the database (a
differing purl is a warning; a differing cpe is not). A module the database does not list gets one warning per run
(also across every image with `--sysbuild`), and after the warnings `rollcall generate`
prints a stub entry for each such module to stderr, ready to paste under `modules:`: fill in
the `""` blanks and `<vendor>`/`<product>` (or delete the lines marked optional). The exit
code stays 0.

rollcall carries a small seed database in `crates/rollcall-core/db/identifiers.yaml`.

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
| 64   | Usage error (bad arguments, bad `--timestamp`, `--serial-number` or `--product`, `merge --blob-manifest` without inputs or `--product`), or subcommand/format not implemented |
| 65   | Input is malformed: not JSON, not UTF-8, too deeply nested, or an invalid model; or a Zephyr input (SPDX, `west list`, `.config`, `build_info.yml`) or the `--identifier-db` file is malformed, or `--zephyr` names a sysbuild top-level directory without `--sysbuild` (or an image directory with it); or a `merge` input is not a readable CycloneDX 1.6 document, the inputs conflict (including different product names or versions without `--product`), or the blob manifest is malformed |
| 66   | Input file missing or unreadable (including a directory), including a required Zephyr input, the `--west-list` or `--identifier-db` file, a `merge` input, the blob manifest or a blob it lists |
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
