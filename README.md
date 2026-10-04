# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

## Status

Early development. `rollcall generate --zephyr <build-dir>` ingests a Zephyr image build
directory (`west spdx` documents, `west list` output, Kconfig `.config`, `build_info.yml`) and
writes a CycloneDX 1.6 JSON SBOM; with `--sysbuild` it ingests every image of a sysbuild
build (the MCUboot bootloader and the application) into one product. `rollcall generate
--cargo` lists a Rust firmware binary's crates from `cargo metadata` and, for a binary built
with `cargo auditable`, its embedded `.dep-v0` list (see [Cargo ingestion](#cargo-ingestion)). `rollcall merge`
combines separately generated SBOMs, and opaque binary blobs listed in a `--blob-manifest`,
into one product hierarchy. `rollcall generate --model` renders a rollcall model (the
internal `rollcall-model/1` JSON form) the same way; and `rollcall validate --schema` checks a
document against the official CycloneDX 1.6 JSON schema, and `--profile` against the CISA 2026
and EU CRA SBOM profiles. `rollcall vex` triages grype or
osv-scanner findings for an SBOM with VEX rules and Kconfig evidence (see [VEX rules](#vex-rules)).
`rollcall report` writes a readiness report for an SBOM (see [Readiness report](#readiness-report)).
`rollcall scan` runs grype and/or osv-scanner on an SBOM, normalises their findings, triages
them with VEX documents and exits 0–3 for CI (see [Scanning](#scanning)).
`assay` is not implemented yet; it prints `not implemented` and exits 64. The 0.0.1 releases of `rollcall`,
`rollcall-core`, `rollcall-cli` and `rollcall-assay` on crates.io and `rollcall` on PyPI are
placeholders that reserve the names.

## Workspace layout

| Crate            | Purpose                                                        |
|------------------|----------------------------------------------------------------|
| `rollcall-core`  | Component-graph model and ingestion.                           |
| `rollcall-cli`   | The `rollcall` binary.                                         |
| `rollcall-assay` | Cryptographic inventory (CycloneDX CBOM), run as `rollcall assay`. |
| `rollcall-identifiers` | The identifier database (data only), versioned on its own (`db_version`). |
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
| `rollcall identifiers` | Inspect and lint the identifier database                              |
| `rollcall report`   | Produce a readiness report (Markdown or JSON) for an SBOM                |
| `rollcall diff`     | Compare a build's SBOM and findings with its base branch's (Markdown or JSON) |

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
```

`generate --format spdx` is reserved and not implemented yet. The same model and options
always produce byte-identical output; changing only `--timestamp` changes only the
`timestamp` line. How each model field maps to CycloneDX is documented in the
`rollcall_core::cyclonedx` module docs (`cargo doc -p rollcall-core --open`).

Exactly one of `--model`, `--zephyr`, `--cargo` and `--cargo-metadata` is required;
`--west-list`, `--include-sdk`, `--sysbuild`, `--product`, `--identifier-db`, `--identify`
and `-v`/`--verbose` only go with `--zephyr`, and `--workspace` needs `--west-list` and one of
`--identifier-db` or `--identify`. `--target` only goes with `--cargo`, `--elf` with `--cargo`
or `--cargo-metadata`, and `--include-unlinked` needs `--elf`.

With `--zephyr`, the `zephyr` component is split into one `library` subcomponent per Zephyr
subsystem (Bluetooth host, IP stack, USB, logging, …) that the build's `zephyr/.config`
enables *and* whose code `zephyr/zephyr.map` (the GNU ld map) shows was linked; libraries are
traced to their sources through `spdx/build.spdx`. A subsystem that is enabled but whose code
was garbage-collected is left out, and `--verbose` prints a `rollcall generate: note: …` line
saying so; notes never change the SBOM. Without the map or `.config`, `zephyr` is not split
(a warning). How the split works and how to add a subsystem is in
[docs/subsystems.md](docs/subsystems.md).

`--product NAME[@VERSION]` puts the generated images under that product exactly as
`merge --product` does (same parsing: split at the last `@`, so `@scope/widget@1.0.0`), and
the output is byte-identical to `generate` followed by `merge --product` with the same spec.
It works with or without `--sysbuild`: without it, it renames and versions the single-image
product. An invalid spec (an empty name or version, or `@scope/widget` with no version) is a
usage error (exit 64).

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
[`docs/validate.md`](docs/validate.md) for the checks, output formats and citations.

### Zephyr ingestion

Pass the *image* build directory, the one holding `build_info.yml` and `spdx/` (with
sysbuild that is `build/<app>/`, not `build/`; the top-level directory is refused with a
message naming the image directory to use), or the sysbuild top-level directory with
`--sysbuild`, which reads the image list from its `build_info.yml` (`domains.yaml` is not
used), ingests every image (`--west-list` and `--include-sdk` apply to each) and merges them
under a product named after the `MAIN` application, unless `--product` names it. Warnings are prefixed with the image
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

What `west spdx` leaves out and how rollcall fills it, with every claim reproducible against
the fixtures: [`docs/zephyr-gaps.md`](docs/zephyr-gaps.md).

### Cargo ingestion

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
([docs/fixtures.md](docs/fixtures.md)).

### Identifier database

`--identify` resolves each module to its *upstream* project with the active identifier
database (see *Database versions* below): the version of the fork revision the build used,
and from it the upstream purl, cpe and supplier that vulnerability scanners match.
`--identifier-db FILE` does the same with that file, as does the global `--identifiers PATH`.
Resolution is optional; without any of these the output is unchanged.

```yaml
schema: 1
modules:
  mbedtls:
    upstream:
      name: Mbed TLS
      homepage: https://github.com/Mbed-TLS/mbedtls   # optional
      supplier: Arm                                   # optional
    purl: 'pkg:generic/mbedtls@{version}?vcs_url=git+https://github.com/Mbed-TLS/mbedtls'
    cpe: 'cpe:2.3:a:trustedfirmware:mbed_tls:{version}:*:*:*:*:*:*:*'   # optional
    cpe_aliases: ['cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*']   # optional
    version_rule:                                     # one of:
      kind: manual                                    #   manual: revision -> version table
      table:
        'a3e190fe44c78d1ba67f55979e1257328cc7d0d8': '4.1.0'
#   kind: git_tag,    pattern: '^v(?P<version>\d+\.\d+\.\d+)$'
#   kind: file_regex, file: include/version.h, pattern: '...(?P<version>...)...'
```

`git_tag` matches the revision itself, or a tag pointing at it; `file_regex` searches a
file in the module's sources. Both need the module sources, found with `--workspace DIR`
(the west workspace: each module is at `DIR/<west list path>`, so `--workspace` requires
`--west-list`, and `--identifier-db` or `--identify`; without either it is a usage error,
exit 64).
Quote revisions and versions, which YAML could otherwise read as numbers (`'2.0'`, or a
commit such as `1e753266…`). The database is checked when it
is loaded: a malformed entry, an unknown key, or a purl or cpe template that does not render
to a valid purl or CPE 2.3 name is an error naming the file and line (exit 65); a missing
file is exit 66.

The module's `version` stays the git revision; the upstream version is recorded as evidence
and drives the purl and cpe, which are only filled in when a version was found (otherwise a
warning says why). A purl or cpe from `spdx/modules-deps.spdx` wins over the database (a
differing purl or cpe is a warning, except a purl naming the same repository or a cpe that
is one of the database's `cpe_aliases`). Every other CPE (the database's when the SPDX one won,
and each of its `cpe_aliases`: further NVD vendor:products the same project's CVEs are filed
under) is written as an additional CPE: a `syft:cpe23` property, which grype matches on, and
an `evidence.identity` entry. A module the database does not list gets one warning per run
(also across every image with `--sysbuild`), and after the warnings `rollcall generate`
prints a stub entry for each such module to stderr, ready to paste under `modules:`: fill in
the `""` blanks and `<vendor>`/`<product>` (or delete the lines marked optional). The exit
code stays 0.

rollcall carries a seed database, `crates/rollcall-identifiers/db/identifiers.yaml`,
covering 33 common Zephyr modules, each fork revision pinned by Zephyr v4.2.0 to v4.4.2
mapped to its upstream version (`pkg:generic` purls; CPEs only from the NVD CPE dictionary).
Its conventions and how the versions are derived are in
[docs/identifiers.md](docs/identifiers.md); how to add a module is in
[CONTRIBUTING.md](CONTRIBUTING.md). Separately, `crates/rollcall-core/db/subsystems.yaml`
maps Zephyr subsystems to their Kconfig symbols and source paths, checked against the pinned
Zephyr tree by `scripts/verify-subsystems.sh`; it ships only with rollcall (see
[docs/subsystems.md](docs/subsystems.md)).

#### Database versions

The identifier database is its own artifact: the `rollcall-identifiers` crate, whose version
is the database's `db_version` (`db_version: '1.0.0'` in the YAML). A new database is a new
release of that crate, or the tarball `scripts/package-identifiers.sh` builds, not a new
rollcall. The active database is, in order:

1. `--identifiers PATH` (global; read by `generate` and `--version` only), or
   `generate --identifier-db FILE`;
2. `$ROLLCALL_IDENTIFIERS`;
3. the newest compatible database in the cache directory that is newer than the embedded
   one: `<cache>/rollcall/identifiers/<db_version>/identifiers.yaml`, where `<cache>` is
   `$ROLLCALL_CACHE_DIR`, else `$XDG_CACHE_HOME`, else `~/.cache` (`%LOCALAPPDATA%` on
   Windows);
4. the database embedded in rollcall.

A PATH may be the YAML file or a directory holding `identifiers.yaml`, or the word
`embedded` (`--identifiers embedded`, `ROLLCALL_IDENTIFIERS=embedded`), which pins the
embedded database and ignores the cache; a file called `embedded` is `./embedded`. rollcall
accepts a
`db_version` of at least 1.0.0 with major version 1: a MINOR bump adds modules, a PATCH bump
fixes entries, and a MAJOR bump (a schema change) needs a newer rollcall. An explicit
database outside that range is an error (exit 65); a database with no `db_version` (your own,
built from stub entries) is used as is. Cache entries outside the range, older than the
embedded database, malformed, or whose `db_version` is not their directory name are skipped
with a warning.

The cache is trusted only as far as its permissions: on Unix, a cache root, entry directory
or `identifiers.yaml` writable by group or others (any of mode `0o022`) is skipped with a
warning, as is a symlink that leads out of the cache root, since whoever can write there
could change your SBOMs. Dotfiles, plain files and directories whose names are not versions
are ignored silently, and a relative `$ROLLCALL_CACHE_DIR` or `$XDG_CACHE_HOME` is ignored.
To rule the cache out entirely, pin the embedded database with `--identifiers embedded`.

Installing a release without upgrading rollcall (distribution of the release tarballs:
see [issue #16](https://github.com/smhasan94/rollcall/issues/16)):

```sh
mkdir -p ~/.cache/rollcall/identifiers
tar -xzf rollcall-identifiers-1.1.0.tar.gz -C ~/.cache/rollcall/identifiers
rollcall --version
# rollcall 0.0.1
# identifiers 1.1.0 (cache /home/me/.cache/rollcall/identifiers/1.1.0/identifiers.yaml)
# identifiers 1.0.0 (embedded, minimum 1.0.0)
```

`rollcall --version` prints the active database (when it is not the embedded one) and the
embedded one, side by side (`-V` with a subcommand, e.g. `rollcall --version vex`, prints the
version and ignores the subcommand). `generate` names a database picked up from the cache in
a note on stderr.

Whenever modules are resolved, the SBOM records which database did it, without any path, so
the output stays byte-identical wherever the database lives: `metadata.properties`
`rollcall:identifiers:db-version` (the `db_version`, or `unversioned`) and
`rollcall:identifiers:source` (`embedded`, `flag`, `env` or `cache`). `merge` carries them
over, keeping every distinct value of its inputs.

`scripts/package-identifiers.sh` builds the release tarball byte-identically on every run of
a given toolchain (python3 and its zlib build; another zlib may compress differently), and
`scripts/check-identifiers-package.sh` checks that and that rollcall reads the tarball from a
cache directory.

`rollcall identifiers lint [PATH] [--fixtures DIR]… [--expect-version VERSION]` checks a
database (default: the embedded one, whose `db_version` must be the `rollcall-identifiers`
version): schema, purl and CPE syntax, duplicate and unsorted modules, `db_version`, that every
`manual` table row resolves, and with `--fixtures` that every module of those Zephyr builds
resolves to a purl. Findings go to stderr as `file:line: rule: message`; exit 1 on any.
`scripts/lint-identifiers.sh` runs it on the tree's database against `fixtures/zephyr`, as
the CI job `identifiers-lint` does.

### VEX rules

`rollcall vex` reads an SBOM (`--sbom`, CycloneDX 1.6) or a model (`--model`), scanner output
(`--findings`, grype `-o json` or osv-scanner `--format json`, repeatable), VEX rules
(`--rules`, YAML, repeatable) and optionally each image's Kconfig (`--kconfig IMAGE=FILE`,
repeatable), and writes a `rollcall-vex/1` JSON report: a statement for each finding a rule
decides, and each other finding under `unresolved` with a rule template to fill in.

```sh
rollcall vex --sbom product.cdx.json \
  --kconfig mcuboot=build/mcuboot/zephyr/.config \
  --kconfig app=build/app/zephyr/.config \
  --findings grype.json --rules vex-rules.yml -o vex.json
```

```yaml
version: 1
rules:
  - id: mbedtls-dtls-compiled-out
    match:
      purl: "pkg:github/mbed-tls/mbedtls@*"   # or name; * matches anything (case-sensitive,
                                              # against the canonical purl)
      cves: [CVE-2022-35409]                  # optional
      versions: ">=2.28.0, <2.28.5"           # optional semver range
    when:                                     # optional; all must hold
      - kconfig_off: CONFIG_MBEDTLS_SSL_PROTO_DTLS
    status: not_affected                      # not_affected | affected | fixed | under_investigation
    justification: code_not_present           # CycloneDX or OpenVEX word, kept as written;
                                              # only for not_affected
    detail: DTLS is compiled out.
```

- **Kconfig is per image.** A `kconfig_off` condition on a component is judged only by the
  `.config` of the component's own image (in a sysbuild product, MCUboot's mbedtls by
  MCUboot's `.config`). A bare `--kconfig FILE` is accepted only for a single-image product;
  naming an image the product does not have, or one image twice, is a usage error (64).
  Evidence cites the file as `IMAGE/zephyr/.config`, never by the path given.
- **Unknown is never true.** Without evidence for a condition (no `.config` for the image, or a
  symbol the `.config` does not mention) it is unknown, and the finding stays unresolved
  (needs evidence). The same goes for a version that is not a release version (a
  git-describe or pre-release suffix such as `v3.7.0-123-gabc` or `-rc1`, or a git SHA with
  no release version in the purl) when a rule has `versions` or `version_in`.
- **Not yet evidenced from the CLI:** `cargo_feature_off` and `symbol_not_linked` conditions
  always need evidence (the finding stays unresolved) because `rollcall vex` cannot yet
  supply Cargo features or the linked-symbol list.
- **Subsystems:** `match.subsystem` must name an entry of the subsystem table
  (`crates/rollcall-core/db/subsystems.yaml`); any other name is a rules error at the rule's
  line (exit 65). It matches a nested subcomponent by name: a subsystem split
  out of the `zephyr` component (see `docs/subsystems.md`). It applies only to findings joined
  to that subcomponent (by its subpath purl such as
  `pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/host`, its cpe, or its name and
  version). Real scanner findings do not join subsystems today: grype and osv-scanner report
  Zephyr CVEs against the CPE `zephyrproject:zephyr`, which only the `zephyr` component has, so
  a `match.subsystem` rule never applies to them.
- **Precedence:** the most specific matching rule wins (naming CVEs, then a version range,
  then exact purl over purl glob over name), then the higher `priority`; equally ranked
  rules that disagree are a conflict, reported as a warning naming each rule, and the
  finding stays unresolved.
- **Aliases:** reports of one vulnerability under different ids (e.g. a RUSTSEC and a GHSA
  advisory for the same CVE, or grype and osv-scanner) are merged per component; the entry's
  id is the CVE when there is one.
- **bom-refs:** with `--sbom`, statements cite the document's own `bom-ref`s.

Unresolved findings and conflicts are summarised on stderr; the exit code stays 0.

`--starter-rules` adds rollcall's starter rule pack (`vex-rules.yaml`, shipped with the
identifier database): Mbed TLS modules compiled out, Bluetooth, the MCUmgr serial transports
and file systems switched off, and the TLS client or server side not linked. `rollcall vex
lint RULES… --kconfig FILE | --zephyr-tree DIR` warns about any `kconfig_off` symbol that does
not exist (a misspelt symbol makes a rule silently never apply); exit 1 on any warning. The
rule format, the starter pack and five worked examples are in
[docs/vex-rules.md](docs/vex-rules.md).

### VEX documents and signing

`--format` picks what `rollcall vex` writes: `rollcall` (the default, the report above),
`openvex` (an OpenVEX v0.2.0 document whose products are the components' purls, as grype's
`--vex` matches them) or `cyclonedx` (a standalone CycloneDX 1.6 VEX document whose
`vulnerabilities[].affects[].ref` are BOM-Links into the `--sbom`). Only statements are
rendered; unresolved findings are listed on stderr. The SBOM itself stays VEX-free unless
you ask for `--embed` (with `--format cyclonedx`), which writes a copy of the SBOM with a
`vulnerabilities` array added and its `version` incremented by one (CycloneDX: a modified
BOM's version should be incremented; the `serialNumber` stays). Only the `version` value
and the added array differ from the input; an SBOM without `version` (implicitly 1) gets
`"version": 2`. The input file is never modified. `--timestamp` and `--id` pin the
document's timestamp and id for reproducible output; by default the id is derived from the
statements, the SBOM and the format, so the OpenVEX and CycloneDX documents get different
ids. The SBOM's `serialNumber` must be a lowercase `urn:uuid:` and its `version` at least 1.

```sh
rollcall vex --sbom product.cdx.json --kconfig app=build/app/zephyr/.config \
  --findings grype.json --rules vex-rules.yml --format openvex -o product.openvex.json
grype sbom:product.cdx.json --vex product.openvex.json   # not_affected findings suppressed
```

`--sign local:key.pem` writes a detached Ed25519 signature (`rollcall-signature/1` JSON) of
the output to `OUTPUT.sig`; `rollcall vex verify OUTPUT --key key.pub.pem` checks it and
says whether the document was modified, signed by another key, or carries an invalid
signature (exit 1). Create a key with `openssl genpkey -algorithm ed25519 -out key.pem` and
its public half with `openssl pkey -in key.pem -pubout -out key.pub.pem`.

`--sign cosign` signs keylessly with Sigstore through `cosign sign-blob`, writing
`OUTPUT.sigstore.json`; `rollcall vex verify OUTPUT --cosign --certificate-identity …
--certificate-oidc-issuer …` verifies it with `cosign verify-blob`. This needs `cosign` on
`PATH` and an OIDC identity (in GitHub Actions, `permissions: id-token: write`; elsewhere
cosign prints a login URL on stderr, which rollcall passes through). Without cosign, or with
an unreadable or malformed `--sign local:` key, rollcall exits (69, 66 or 65) before writing
anything. `vex verify --cosign` requires `--certificate-identity` or
`--certificate-identity-regexp`, and `--certificate-oidc-issuer`; a missing document or
bundle is exit 66, so exit 1 always means the signature did not verify.

### Scanning

`rollcall scan SBOM` runs the scanners on `PATH` (`--scanner grype|osv|auto`, default
`auto`), merges their findings into one list (one entry per vulnerability per component, the
same id and component whichever scanner reported it), applies `--vex` documents (OpenVEX,
CycloneDX VEX standalone or embedded, or `rollcall-vex/1`; suppressed findings are shown,
not hidden) and prints a table, or `rollcall-scan/1` JSON with `--json`. `--fail-on
SEVERITY` exits 1 on an open finding at or above it, `--fail-on-unresolved` exits 2 on an
unresolved one, and a missing or failing scanner exits 3. `--db-path DIR` scans offline with
pre-downloaded databases. Details, the exit-code table and the offline workflow are in
[docs/scan.md](docs/scan.md).

```sh
rollcall scan product.cdx.json --vex product.openvex.json --fail-on high
```

### Known scanner behaviour

grype (verified with 0.119.0) silently ignores CycloneDX components of type
`operating-system`. It treats them as distro information, not packages, so it does not scan
them for vulnerabilities. rollcall labels components accurately anyway: how an RTOS kernel
such as Zephyr is typed is decided at ingestion. osv-scanner is unaffected.

## Readiness report

`rollcall report` says how ready an SBOM is to hand over, as Markdown for people
(`--format md`) or `rollcall-report/1` JSON for machines (`--format json`, schema
[`docs/report-schema.json`](docs/report-schema.json)):

```sh
rollcall generate --zephyr build --sysbuild --west-list west-list.txt --identify -o product.cdx.json
rollcall report product.cdx.json --format md \
  --scan grype.json --vex vex.cdx.json --timestamp 2026-01-02T03:04:05Z -o report.md
```

It opens with a plain-language summary, then gives a score out of 100, coverage (the share
of the product, images and components with a PURL, CPE, hash and licence), one row per
component, unresolved modules with a paste-ready identifier-database stub each, open
findings by severity (`--scan`: grype or osv-scanner JSON, repeatable), VEX coverage
(`--vex`: any `rollcall vex` output format, repeatable), and the CycloneDX schema and
`cisa-2026`/`cra` profile results. The score is integer basis points rounded down, so only
a perfect SBOM scores 100: identified 25, hashed 15, licensed 15, validation 25, modules
resolved 10, vulnerabilities closed 10 (not assessed without `--scan`, and left out of the
total). [`docs/report.md`](docs/report.md) documents the formula and every input. The output
is deterministic and leaves out the SBOM's serial number, timestamp and the input paths, so
two builds' reports diff cleanly. The exit code is 0 whenever a report is written, whatever
the score.

## GitHub Action

[`action/`](action/README.md) is `rollcall-action`, a composite GitHub Action: it generates
the SBOM, validates it, scans it with grype, writes VEX with the starter rule pack and your
rules, reports on it and uploads everything as a workflow artifact. On a pull request it runs
`rollcall diff` against the base branch's artifact ([`docs/diff.md`](docs/diff.md)), posts (or
updates) one comment with the readiness summary and the component and finding diff, and fails
the check on new findings at or above `fail-on`:

```yaml
      - uses: smhasan94/rollcall/action@main # pin to a release tag or commit SHA
        with:
          build-dir: build
          fail-on: high
```

[`action/README.md`](action/README.md) has the copy-paste workflow, every input and output,
and the permissions it needs. `.github/workflows/rollcall-example.yml` runs it on this
repository's own fixtures.

`rollcall diff` can also be run on its own:

```sh
rollcall diff --sbom sbom.cdx.json --scan scan.json --report report.json \
  --base-sbom base/sbom.cdx.json --base-scan base/scan.json --base-report base/report.json \
  --fail-on high --format md -o comment.md
```

## Exit codes

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| 0    | Success (including `--help`, `--version`)                                |
| 1    | `validate`: the document has schema violations or error-severity profile findings; `vex verify`: the signature does not verify; `identifiers lint`: the database has findings; `scan`: an open finding at or above `--fail-on`; `diff`: a new open finding at or above `--fail-on` |
| 2    | `scan`: an unresolved finding, with `--fail-on-unresolved` |
| 3    | `scan`: a scanner is missing or failed, or its output cannot be read |
| 64   | Usage error (bad arguments, `validate` without `--schema` or `--profile` or with an unknown profile name, bad `--timestamp`, `--serial-number` or `--product`, `report` or `diff` without `--format`, `diff --base-scan` or `--base-report` without `--base-sbom`, `merge --blob-manifest` without inputs or `--product`, a `vex --kconfig` that names no image of the product, names one twice, or omits `IMAGE=` for a multi-image product; `vex` flags that do not combine, such as `--embed` without `--format cyclonedx`, `--format cyclonedx` without `--sbom`, or `--sign` without `-o`), or subcommand/format not implemented |
| 65   | Input is malformed: not JSON, not UTF-8, too deeply nested, or an invalid model; or a Zephyr input (SPDX, `west list`, `.config`, `build_info.yml`) or the identifier database (`--identifier-db`, `--identifiers`, `$ROLLCALL_IDENTIFIERS`, also for `--version`) is malformed or has a `db_version` this rollcall does not accept, or `--zephyr` names a sysbuild top-level directory without `--sysbuild` (or an image directory with it); or a `merge` input is not a readable CycloneDX 1.6 document, the inputs conflict (including different product names or versions without `--product`), or the blob manifest is malformed; or a `vex` input (SBOM, model, `--kconfig`, findings, rules, signing key, signature file) is malformed, with `file:line:column` for rules, or the SBOM cannot take the requested VEX output (no `serialNumber` for `--format cyclonedx`, a `serialNumber` that is not a lowercase `urn:uuid:` or a `version` below 1, a non-empty `vulnerabilities` for `--embed`); or a `validate --profile` file is malformed; or a `report` input (the SBOM, a `--scan` or a `--vex` file) is malformed or not a format it reads; or a `diff` input (an SBOM, a scan or a report) is malformed or has the wrong `schema`; or a `scan` SBOM or `--vex` document is malformed; or `cargo metadata` output (`--cargo-metadata`, or `--cargo` when cargo fails) is malformed, has no root package or names two packages the binary's list cannot tell apart, or the `--elf` has no `.dep-v0` section, a malformed one, or was built from another package |
| 66   | Input file missing or unreadable (including a directory), including a required Zephyr input, the `--west-list` file or an explicit identifier database (`--identifier-db`, `--identifiers` or `$ROLLCALL_IDENTIFIERS`, also for `--version`), a `merge` input, the blob manifest or a blob it lists, a `vex` input, a `report` input, a `diff` input, a `validate --profile` file, or a `scan` SBOM, `--vex` document or `--db-path` directory, or the `--cargo-metadata` file, the `--elf` file or `--cargo DIR`'s `Cargo.toml` |
| 69   | `vex --sign cosign` / `vex verify --cosign`: cosign is not installed, or keyless signing failed (no OIDC identity); `generate --cargo`: cargo cannot be run (`$CARGO`, else `cargo` on PATH) |
| 70   | Internal error (`vex`, `validate --json`, `report --format json`, `scan --json`, `diff --format json`: the report cannot be serialised) |
| 74   | Output cannot be written (for `scan`, also: its temporary directory cannot be created) |

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

`fixtures/cargo-*/` hold real `cargo auditable` builds for `thumbv7em-none-eabihf`
(`cargo metadata`, `cargo tree`, the ELF and its `.dep-v0` list): keelsign's
`examples/nrf52840-hello` at a pinned commit, and the hand-written projects in
`scripts/fixture-src/`. They are produced only by `scripts/regen-fixtures-cargo.sh`
(`scripts/regen-fixtures.sh --variant cargo-…`).

## Publishing the placeholders

Crates must be published dependencies first: `rollcall-identifiers`, then `rollcall-core`
and `rollcall-assay`, then `rollcall-cli`, then `rollcall` (or simply
`cargo publish --workspace`, which orders them). `rollcall-identifiers` is versioned on its
own (its version is the database's `db_version`); a database-only release is
`cargo publish -p rollcall-identifiers` plus the tarball from `scripts/package-identifiers.sh`.
Then the PyPI placeholder:

```sh
cd python && uv build && uv publish
```

Check the reservations with `ROLLCALL_CRATES_OWNER=<crates.io login> ./scripts/check-names.sh`.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
