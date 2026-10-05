# Command-line reference

Every `rollcall` subcommand, the flags of `generate`, `merge` and `validate`, how a directory's
ecosystem is detected, and every exit code. Each ecosystem, VEX, scanning, the readiness
report and CSAF have their own pages; see the [docs index](README.md).

## Subcommands

| Command             | Description                                                              |
|---------------------|--------------------------------------------------------------------------|
| `rollcall generate` | Generate a CycloneDX SBOM from firmware build metadata                   |
| `rollcall validate` | Validate an SBOM against the CycloneDX schema and rollcall's rules       |
| `rollcall merge`    | Merge bootloader, application and blob SBOMs into one product hierarchy  |
| `rollcall vex`      | Emit VEX statements for an SBOM                                          |
| `rollcall scan`     | Scan an SBOM for known vulnerabilities                                   |
| `rollcall assay`    | Produce a CycloneDX CBOM (cryptographic inventory) for a build           |
| `rollcall identifiers` | Inspect and lint the identifier database                              |
| `rollcall report`   | Produce a readiness report (Markdown or JSON) for an SBOM                |
| `rollcall diff`     | Compare a build's SBOM and findings with its base branch's (Markdown or JSON) |
| `rollcall csaf`     | Export scan and VEX results as a CSAF 2.0 VEX document                   |
| `rollcall detect`   | Print which ecosystem a build or project directory is (as `generate DIR` tells it) |

`assay` is not implemented yet; it prints `not implemented` and exits 64.

Where each is documented:

- `generate`: [Usage](#usage) below, and the ecosystem guides: [Zephyr](zephyr.md),
  [Cargo](cargo.md), [ESP-IDF](esp-idf.md), [PlatformIO](platformio.md);
- `merge`: [Merging](#merging);
- `validate`: [Validating](#validating) and [validate.md](validate.md);
- `detect`: [Auto-detect](#auto-detect);
- `identifiers`: [identifiers.md](identifiers.md#using-the-database);
- `vex`: [vex-rules.md](vex-rules.md);
- `scan`: [scan.md](scan.md);
- `report`: [report.md](report.md);
- `diff`: [diff.md](diff.md);
- `csaf`: [cra-clock.md](cra-clock.md#rollcall-csaf).

## Usage

```sh
# Generate an SBOM from a Zephyr image build directory (stdout, or -o FILE).
west list -f "{name} {path} {revision} {url}" > west-list.txt
rollcall generate --zephyr build/app --west-list west-list.txt --include-sdk -o app.cdx.json

# Render a model (the `rollcall-model/1` JSON form) as CycloneDX 1.6 JSON.
rollcall generate --model product.model.json -o product.cdx.json

# Pin the timestamp (RFC 3339, normalised to UTC) and/or the serial number for
# reproducible output. By default the timestamp is the current time and the serial number
# is derived from the model's content.
rollcall generate --model product.model.json --timestamp 2026-01-02T03:04:05Z \
    --serial-number urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79

# Check a document against the vendored CycloneDX 1.6 JSON schema.
rollcall validate --schema product.cdx.json

# ...and against the CISA 2026 and CRA profiles (docs/validate.md); --json for CI.
rollcall validate --schema --profile all product.cdx.json

# A sysbuild build (MCUboot + application) as one product, in one step...
rollcall generate --zephyr build --sysbuild --west-list west-list.txt -o product.cdx.json

# Name and version the product while generating it. Byte-identical to generate --sysbuild
# followed by merge --product widget@1.2.3.
rollcall generate --zephyr build --sysbuild --product widget@1.2.3 -o widget.cdx.json

# ...or by hand: generate each image, then merge them under one product. The result is
# byte-identical to --sysbuild when --product names the application.
rollcall generate --zephyr build/app --west-list west-list.txt -o app.cdx.json
rollcall generate --zephyr build/mcuboot --west-list west-list.txt -o mcuboot.cdx.json
rollcall merge app.cdx.json mcuboot.cdx.json --product app -o product.cdx.json

# Resolve each module to its upstream purl and CPE with the identifier database, and lint it.
rollcall generate --zephyr build --sysbuild --west-list west-list.txt --identify -o product.cdx.json
rollcall --version
rollcall identifiers lint

# Add opaque binary blobs (radio firmware, vendor libraries) from a manifest.
rollcall merge product.cdx.json --blob-manifest blobs.yaml --product widget@1.2.0 -o widget.cdx.json

# A Rust firmware binary built with `cargo auditable build --release`: cargo metadata
# resolved for its target, and the crates its .dep-v0 section says were linked.
rollcall generate --cargo . --target thumbv7em-none-eabihf \
  --elf target/thumbv7em-none-eabihf/release/app -o app.cdx.json
# ...from captured `cargo metadata --format-version 1 --filter-platform <target>` output,
# also listing the crates the binary does not link, as `scope: excluded`.
rollcall generate --cargo-metadata cargo-metadata.json --elf app.elf --include-unlinked

# An ESP-IDF project after `idf.py build`: ESP-IDF and its subsystems, managed components, and
# the linked Espressif blobs, hashed from the ESP-IDF tree (--idf-path, else $IDF_PATH).
rollcall generate --esp-idf . --idf-path "$IDF_PATH" -o app.cdx.json

# A PlatformIO project after `pio run`: the framework, the platform and every installed
# library of one environment, with versions from the core directory (--pio-core, else
# $PLATFORMIO_CORE_DIR, else exact pins in platformio.ini).
rollcall generate --platformio . --env esp32dev --pio-core ~/.platformio -o app.cdx.json

# Any of the four, told from the directory's files; --ecosystem to choose, `detect` to ask.
rollcall generate build -o app.cdx.json
rollcall generate . --ecosystem platformio --env esp32dev -o app.cdx.json
rollcall detect build
```

The output is CycloneDX 1.6 JSON. SPDX export is deferred
([#37](https://github.com/smhasan94/rollcall/issues/37)); `--format` accepts only `cyclonedx`. The same model and options
always produce byte-identical output; changing only `--timestamp` changes only the
`timestamp` line. How each model field maps to CycloneDX is documented in the
`rollcall_core::cyclonedx` module docs (`cargo doc -p rollcall-core --open`).

Exactly one input is required: a positional `DIR`, or one of `--model`, `--zephyr`,
`--cargo`, `--cargo-metadata`, `--esp-idf` and `--platformio`. The flags of one ecosystem go
with its input flag, or with a `DIR` of that ecosystem (anything else exits 64):

- `--west-list`, `--include-sdk`, `--sysbuild`, `--identifier-db` and `--identify` go with
  Zephyr, and `--workspace` needs `--west-list` and one of `--identifier-db` or `--identify`;
- `-v`/`--verbose` goes with Zephyr or ESP-IDF;
- `--target` goes with a Cargo package directory, `--elf` with any Cargo input, and
  `--include-unlinked` needs `--elf`;
- `--build` and `--idf-path` go with ESP-IDF;
- `--env` and `--pio-core` go with PlatformIO;
- `--ecosystem` needs `DIR`;
- `--product` goes with every input but `--model`.

What each ecosystem reads and how it maps to CycloneDX is in its guide:
[Zephyr](zephyr.md#ingestion), [Cargo](cargo.md#ingestion), [ESP-IDF](esp-idf.md) and
[PlatformIO](platformio.md). The identifier database flags (`--identify`, `--identifier-db`,
`--workspace`, the global `--identifiers`) are in [identifiers.md](identifiers.md#using-the-database).

`--product NAME[@VERSION]` puts the generated images under that product exactly as
`merge --product` does (same parsing: split at the last `@`, so `@scope/widget@1.0.0`), and
the output is byte-identical to `generate` followed by `merge --product` with the same spec.
It works with or without `--sysbuild`, and with every input but `--model`: on a single image
it renames and versions that image's product. An invalid spec (an empty name or version, or `@scope/widget` with no version) is a
usage error (exit 64).

## Merging

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
  - name: vendor-crypto
    version: 1.0.0
    supplier: Example Radio Ltd
    path: lib/vendor-crypto.bin
    kind: library                           # optional: firmware | library
    image: app                              # optional: the image it belongs to
```

Each entry becomes a `blob` image with the file's SHA-256, the supplier, and the property
`rollcall:opaque` = `contents not analysed; hashes computed from the file`. Built-in
recognisers fill a missing name, version or supplier for Nordic SoftDevices
(`s<nnn>_nrf5<n>_<M.m.p>_softdevice.hex`) and common Espressif, Nordic and Silicon Labs HAL
libraries; licences are never guessed. Without input documents, `--product` is required.

Each blob is a dependency of the product root, or, with `image: NAME`, of the merged
product's image of that name (e.g. the application that links a vendor library). An `image:`
that no image (other than a blob) is called, or that several are, is an error (exit 65).

The optional `kind:` (`firmware` or `library`) sets the blob's CycloneDX component `type`;
it does not change its `rollcall:image-kind`, which is always `blob`. Any other value is a
malformed manifest (exit 65). Without `kind:`, the type comes from the built-in recogniser
(SoftDevices are `firmware`, vendor libraries `library`), then from the file extension, and
otherwise is `firmware`. A blob that is already in an input SBOM with a different type is a
merge conflict (exit 65). The extensions:

| Extension (any case)    | CycloneDX `type` |
|-------------------------|------------------|
| `.a`, `.lib`, `.o`      | `library`        |
| `.hex`, `.bin`, `.elf`  | `firmware`       |
| anything else           | `firmware`       |

## Validating

`validate` needs `--schema`, `--profile`, or both.

- `--schema` prints `<file>: valid CycloneDX 1.6` on success. On failure it prints
  `<file>: <n> schema violation(s)` followed by one `  <JSON pointer>: <message>` line per
  violation, sorted.
- `--profile cisa-2026|cra|all|PATH` checks the document against regulator profiles: the
  CISA 2026 SBOM minimum elements, and the EU Cyber Resilience Act with BSI TR-03183-2. It
  checks:
  - supplier, name, version, a purl or cpe, and a hash on every component;
  - a timestamp, an author or tool, and a root component on the document;
  - a dependency graph that reaches every component from the root;
  - for CRA only, a complete list of top-level dependencies, with each image represented.

  Each failed check is reported with the component's `bom-ref`, the fix, and the clause it
  encodes.
- `--json` prints one JSON object for CI.

The profiles are YAML data in `crates/rollcall-core/profiles/`. See
[validate.md](validate.md) for the checks, output formats and citations.
`rollcall validate --schema` also recognises a CSAF document and checks it as
[`rollcall csaf`](cra-clock.md#rollcall-csaf) does.

## Auto-detect

`rollcall generate DIR` and `rollcall detect DIR` tell which ecosystem a directory is from the
files at its top, never their contents:

| Ecosystem | DIR holds | Read as |
|-----------|-----------|---------|
| `zephyr` | `build_info.yml` | `--zephyr DIR`, with `--sysbuild` when `domains.yaml` is there and `--west-list DIR/west-list.txt` when that is |
| `cargo` | `Cargo.toml`, else `cargo-metadata.json` | `--cargo DIR`, else `--cargo-metadata DIR/cargo-metadata.json` |
| `esp-idf` | `sdkconfig` and `build/project_description.json` | `--esp-idf DIR` |
| `platformio` | `platformio.ini` | `--platformio DIR` |

A directory that several ecosystems match is an error listing them (exit 64), and one that
none matches is an error listing what was looked for (exit 66). There is no precedence:
`--ecosystem zephyr|cargo|esp-idf|platformio` chooses. `rollcall detect DIR` prints the
ecosystem's name, and the Action's `ecosystem: auto` runs it. `generate DIR` is byte-identical
to the explicit flags for every fixture in the repository. The ecosystem comparison table is in
the [docs index](README.md#ecosystems).

## Exit codes

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| 0    | Success (including `--help`, `--version`)                                |
| 1    | `validate`: the document has schema violations or error-severity profile findings; `vex verify`: the signature does not verify; `identifiers lint`: the database has findings; `scan`: an open finding at or above `--fail-on`; `diff`: a new open finding at or above `--fail-on`; `csaf`: no finding about a component of the product, so nothing to export (nothing is written; the warnings say what was left out) |
| 2    | `scan`: an unresolved finding, with `--fail-on-unresolved` |
| 3    | `scan`: a scanner is missing or failed, or its output cannot be read |
| 64   | Usage error (bad arguments, `validate` without `--schema` or `--profile` or with an unknown profile name, bad `--timestamp`, `--serial-number` or `--product`, a `generate DIR` that several ecosystems match, a `generate` flag of another ecosystem than the input's, a `--env` the PlatformIO project does not have (or several environments and no `--env` or single `default_envs`), `detect` on a directory several ecosystems match, `report` or `diff` without `--format`, `diff --base-scan` or `--base-report` without `--base-sbom`, `merge --blob-manifest` without inputs or `--product`, a `vex --kconfig` that names no image of the product, names one twice, or omits `IMAGE=` for a multi-image product; `vex` flags that do not combine, such as `--embed` without `--format cyclonedx`, `--format cyclonedx` without `--sbom`, or `--sign` without `-o`; `csaf` without `--scan`, with a bad `--id` or `--tlp`, or without a publisher: no `--publisher`/`--publisher-namespace` and no SBOM supplier name/URL, or a namespace that is not an absolute URI), or subcommand not implemented |
| 65   | Input is malformed: not JSON, not UTF-8, too deeply nested, or an invalid model; or a Zephyr input (SPDX, `west list`, `.config`, `build_info.yml`) or the identifier database (`--identifier-db`, `--identifiers`, `$ROLLCALL_IDENTIFIERS`, also for `--version`) is malformed or has a `db_version` this rollcall does not accept, or `--zephyr` names a sysbuild top-level directory without `--sysbuild` (or an image directory with it); or a `merge` input is not a readable CycloneDX 1.6 document, the inputs conflict (including different product names or versions without `--product`), or the blob manifest is malformed; or a `vex` input (SBOM, model, `--kconfig`, findings, rules, signing key, signature file) is malformed, with `file:line:column` for rules, or the SBOM cannot take the requested VEX output (no `serialNumber` for `--format cyclonedx`, a `serialNumber` that is not a lowercase `urn:uuid:` or a `version` below 1, a non-empty `vulnerabilities` for `--embed`); or a `validate --profile` file is malformed; or a `report` input (the SBOM, a `--scan` or a `--vex` file) is malformed or not a format it reads; or a `diff` input (an SBOM, a scan or a report) is malformed or has the wrong `schema`; or a `scan` SBOM or `--vex` document is malformed; or a `csaf` input (the SBOM, a `--scan` or a `--vex` file) is malformed or not a format it reads; or `cargo metadata` output (`--cargo-metadata`, or `--cargo` when cargo fails) is malformed, has no root package or names two packages the binary's list cannot tell apart, or the `--elf` has no `.dep-v0` section, a malformed one, or was built from another package; or an `--esp-idf` input (`project_description.json`, `sdkconfig`, `dependencies.lock`, an `idf_component.yml`, the link map) is malformed; or a `--platformio` input (`platformio.ini`, with its line; a `library.json`, `.piopm`, `platform.json` or `package.json`) is malformed |
| 66   | Input file missing or unreadable (including a directory), including a required Zephyr input, the `--west-list` file or an explicit identifier database (`--identifier-db`, `--identifiers` or `$ROLLCALL_IDENTIFIERS`, also for `--version`), a `merge` input, the blob manifest or a blob it lists, a `vex` input, a `report` input, a `csaf` input, a `diff` input, a `validate --profile` file, or a `scan` SBOM, `--vex` document or `--db-path` directory, or the `--cargo-metadata` file, the `--elf` file or `--cargo DIR`'s `Cargo.toml`, or `--esp-idf DIR`'s `sdkconfig` or `build/project_description.json`, or `--platformio DIR`'s `platformio.ini`; or a `generate DIR` or `detect DIR` that is not a directory or that no ecosystem matches (or not the one `--ecosystem` names) |
| 69   | `vex --sign cosign` / `vex verify --cosign`: cosign is not installed, or keyless signing failed (no OIDC identity); `generate --cargo`: cargo cannot be run (`$CARGO`, else `cargo` on PATH) |
| 70   | Internal error (`vex`, `validate --json`, `report --format json`, `scan --json`, `diff --format json`: the report cannot be serialised; `csaf`: the document fails the CSAF 2.0 schema or a mandatory check, e.g. an SBOM CPE outside CSAF's pattern, and is not written) |
| 74   | Output cannot be written (for `scan`, also: its temporary directory cannot be created) |

The pip wrapper adds two of its own: 65 when a downloaded binary fails its checksum, and 69
when there is no release binary for the platform or the download fails (see
[Installing](installing.md#the-pip-wrapper)).
