# Zephyr `west spdx` gap analysis

`west spdx` is Zephyr's own SBOM generator. It runs after a build and writes SPDX documents
describing the sources that went into one image. It is a good base: the documents are
accurate about files, hashes and licences, and they come from the build system itself.

This page lists five things a firmware SBOM needs, for vulnerability management and for the
EU Cyber Resilience Act, that `west spdx` does not give today, and shows how rollcall fills
each gap as a companion tool that reads `west spdx` output. It ends with four proposals for
Zephyr. Every claim about `west spdx` output is shown with a command run against real build
output in this repository; scanner behaviour is cited from
[docs/identifiers.md](identifiers.md#scanner-behaviour) and the
[README](../README.md#known-scanner-behaviour). The output printed under each command is
checked in CI.

Everything here is pinned to **Zephyr v4.4.2** (commit `dccb0959`) and **west 1.5.0**, the
versions the fixtures were built with, on `nrf52840dk/nrf52840` with sysbuild and MCUboot.
Where Zephyr's `main` branch has moved since, an "On `main`" note says so. Those notes were
checked against `main` at commit `89402088` (2026-10-03).

This page covers:

- [How to reproduce](#how-to-reproduce)
- [What west spdx produces](#what-west-spdx-produces)
- [Gap 1: Identifiers](#gap-1-identifiers)
- [Gap 2: Subsystem split](#gap-2-subsystem-split)
- [Gap 3: MCUboot and sysbuild](#gap-3-mcuboot-and-sysbuild)
- [Gap 4: Blobs](#gap-4-blobs)
- [Gap 5: CycloneDX](#gap-5-cyclonedx)
- [rollcall as the companion](#rollcall-as-the-companion)
- [Proposals upstream](#proposals-upstream)
- [Outreach log](#outreach-log) and [Responses](#responses)
- [References](#references)

## How to reproduce

From the repository root:

```sh
cargo build -p rollcall
scripts/check-doc-examples.sh docs/zephyr-gaps.md
scripts/check-doc-links.sh docs/zephyr-gaps.md
```

`check-doc-examples.sh` runs every `$ ` command in the console blocks below, in one
temporary directory that links to the repository's `fixtures/` and `crates/`, with the
freshly built `rollcall` first on `PATH`. Each command must print exactly the lines shown
under it. Files that a command writes (`baseline.cdx.json`, say) stay in that directory and
are used by later commands. `check-doc-links.sh` checks that every link on this page
resolves; `--offline` checks only the links inside the repository.

The fixtures are real build output, captured by `scripts/regen-fixtures.sh` and described in
[docs/fixtures.md](fixtures.md). Only the blob example in [Gap 4](#gap-4-blobs) uses
hand-written test data, and it says so.

## What west spdx produces

The pin:

```console
$ jq -r '"zephyr \(.zephyr.tag) \(.zephyr.commit)", "west \(.west.version)"' fixtures/zephyr/MANIFEST.json
zephyr v4.4.2 dccb09599635bdff17633fa7e9dab014b91dce90
west 1.5.0
```

For each image, `west spdx -d <image build dir>` writes four SPDX 2.3 tag-value documents.
The baseline build has two images, the application `with_mcuboot` and the bootloader
`mcuboot`:

```console
$ ls fixtures/zephyr/baseline/*/spdx
fixtures/zephyr/baseline/mcuboot/spdx:
app.spdx
build.spdx
modules-deps.spdx
zephyr.spdx

fixtures/zephyr/baseline/with_mcuboot/spdx:
app.spdx
build.spdx
modules-deps.spdx
zephyr.spdx
$ grep -h '^SPDXVersion' fixtures/zephyr/baseline/*/spdx/*.spdx | sort -u
SPDXVersion: SPDX-2.3
```

- `zephyr.spdx` lists the Zephyr and module source files that were compiled, one package per
  repository.
- `app.spdx` lists the application's own sources.
- `build.spdx` lists the build outputs (libraries and `zephyr.elf`) with `GENERATED_FROM`
  relationships back to the sources.
- `modules-deps.spdx` carries the identifiers (purl, CPE) that modules declare.

The file-level detail is real and useful. Every source file has a SHA-256 and a licence:

```console
$ grep -c '^FileName' fixtures/zephyr/baseline/with_mcuboot/spdx/*.spdx
fixtures/zephyr/baseline/with_mcuboot/spdx/app.spdx:1
fixtures/zephyr/baseline/with_mcuboot/spdx/build.spdx:25
fixtures/zephyr/baseline/with_mcuboot/spdx/modules-deps.spdx:0
fixtures/zephyr/baseline/with_mcuboot/spdx/zephyr.spdx:125
$ grep -c -e '^FileChecksum: SHA256' -e '^LicenseInfoInFile' fixtures/zephyr/baseline/with_mcuboot/spdx/zephyr.spdx
250
$ grep -c 'GENERATED_FROM' fixtures/zephyr/baseline/with_mcuboot/spdx/build.spdx
129
```

rollcall does not replace any of this. It reads these four documents and adds what is
missing.

**On `main`:** `west spdx --init` is deprecated and will be removed in Zephyr 5.0: a build
with `CONFIG_BUILD_OUTPUT_META` now asks CMake for the file-based API itself. `--spdx-version`
also accepts `3.0` and `3.1` (3.1 marked experimental). See the 4.5 migration guide and
`scripts/west_commands/spdx.py` in [References](#references).

## Gap 1: Identifiers

A vulnerability scanner can only match a component it can name: a purl or a CPE with the
upstream project's release version. `west spdx` gets close but not all the way.

**(a) Only modules that declare identifiers get them.** `modules-deps.spdx` copies each
module's `security.external-references` from its `zephyr/module.yml` (`walker.py`
`setupModulesDocument`, [line 430](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py#L430)).
In the baseline build, two of the six modules (mbedtls and tf-psa-crypto) declare them, and
four (cmsis, cmsis_6, hal_nordic, mcuboot) do not:

```console
$ grep -E '^(PackageName|ExternalRef)' fixtures/zephyr/baseline/with_mcuboot/spdx/modules-deps.spdx
PackageName: zephyr
ExternalRef: PACKAGE-MANAGER purl pkg:github/zephyrproject-rtos/zephyr@v4.4.2
ExternalRef: SECURITY cpe23Type cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*
PackageName: cmsis-deps
PackageName: cmsis_6-deps
PackageName: hal_nordic-deps
PackageName: mbed_tls
ExternalRef: SECURITY cpe23Type cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:github/Mbed-TLS/mbedtls@v4.1.0
PackageName: mcuboot-deps
PackageName: tf-psa-crypto
ExternalRef: SECURITY cpe23Type cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:github/Mbed-TLS/TF-PSA-Crypto@v1.1.0
```

**(b) Module versions are fork commits.** Zephyr builds modules from its own forks, so each
module's `PackageVersion` is the commit the manifest pins, not an upstream release. A scanner
cannot look up `512cc7e8…` in a vulnerability database. Issue
[#117299](https://github.com/zephyrproject-rtos/zephyr/issues/117299) asks for release tags
on module repositories for the same reason, and
[#53479](https://github.com/zephyrproject-rtos/zephyr/issues/53479) asks how to tell which
upstream CVEs apply to a forked module.

```console
$ grep -E '^Package(Name|Version)' fixtures/zephyr/baseline/with_mcuboot/spdx/zephyr.spdx
PackageName: zephyr
PackageVersion: 4.4.2
PackageName: cmsis-sources
PackageVersion: 512cc7e895e8491696b61f7ba8066b4a182569b8
PackageName: cmsis_6-sources
PackageVersion: 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74
PackageName: hal_nordic-sources
PackageVersion: 44fd3d44b15cb75f80a25b4679f91d2787e28664
PackageName: mbedtls-sources
PackageVersion: a3e190fe44c78d1ba67f55979e1257328cc7d0d8
PackageName: mcuboot-sources
PackageVersion: 6d3b3d2c38ab20c242e5b9abb04d050086383eb2
PackageName: tf-psa-crypto-sources
PackageVersion: dc575a2ddcc8cb16275d24c42a52eaf79ebe2231
```

**(c) What rollcall adds.** rollcall's identifier database maps each fork commit to the
upstream release it carries ([docs/identifiers.md](identifiers.md#version-derivation)). With
it, every module gets a purl naming the upstream project and release. The component's
`version` stays the commit, because that is what was built:

```console
$ rollcall generate --zephyr fixtures/zephyr/baseline --sysbuild \
    --west-list fixtures/zephyr/baseline/west-list.txt \
    --identifier-db crates/rollcall-identifiers/db/identifiers.yaml \
    --timestamp 2026-01-02T03:04:05Z -o baseline.cdx.json
$ jq -r '.components[] | select(.name == "with_mcuboot") | .components[] | [.name, .version, .purl] | join(" ")' baseline.cdx.json
cmsis 512cc7e895e8491696b61f7ba8066b4a182569b8 pkg:generic/cmsis@5.9.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2FARM-software%2FCMSIS_5
cmsis_6 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 pkg:generic/cmsis@6.1.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2FARM-software%2FCMSIS_6
hal_nordic 44fd3d44b15cb75f80a25b4679f91d2787e28664 pkg:generic/nrfx@4.2.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2FNordicSemiconductor%2Fnrfx
mbedtls a3e190fe44c78d1ba67f55979e1257328cc7d0d8 pkg:github/mbed-tls/mbedtls@v4.1.0
mcuboot 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 pkg:generic/mcuboot@2.4.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fmcu-tools%2Fmcuboot
tf-psa-crypto dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 pkg:github/mbed-tls/tf-psa-crypto@v1.1.0
zephyr 4.4.2 pkg:github/zephyrproject-rtos/zephyr@v4.4.2
```

**(d) The purl type is an open question.** Zephyr's module files write
`pkg:github/Mbed-TLS/mbedtls@v4.1.0`. osv-scanner reads the `github` purl type as the
GitHub Actions ecosystem, so it looks the library up among Actions
([docs/identifiers.md](identifiers.md#scanner-behaviour)). rollcall's own convention is
`pkg:generic/<upstream>@<version>?vcs_url=git+<upstream repository>`
([PURL convention](identifiers.md#purl-convention)). When a module declares its own purl,
though, rollcall respects it: Zephyr's purl stays the component's purl (in canonical
lower case), and rollcall's generic purl and the fork purl are kept as evidence. Neither
type makes osv-scanner find C library advisories today, so this is a question for the purl
and Zephyr communities, not something rollcall can settle alone:

```console
$ jq -r '.components[] | select(.name == "with_mcuboot") | .components[] | select(.name == "mbedtls") | .purl, (.evidence.identity[] | select(.field == "purl") | .methods[].value)' baseline.cdx.json
pkg:github/mbed-tls/mbedtls@v4.1.0
pkg:generic/mbedtls@4.1.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2FMbed-TLS%2Fmbedtls
pkg:github/zephyrproject-rtos/mbedtls@a3e190fe44c78d1ba67f55979e1257328cc7d0d8
pkg:github/Mbed-TLS/mbedtls@v4.1.0
```

**(e) One CPE is not always enough.** NVD files Mbed TLS CVEs under two vendors:
`trustedfirmware:mbed_tls` and the older, deprecated `arm:mbed_tls`. For Mbed TLS 3.6.4 the
two lists do not overlap (6 and 7 CVEs, checked on 2026-10-01; see
[docs/identifiers.md](identifiers.md#scanner-behaviour)). The module file names only `arm`.
This example is the Zephyr v4.2.0 build in `fixtures/zephyr-old-mbedtls/`, whose Mbed TLS
fork carries 3.6.4. rollcall keeps Zephyr's CPE as the primary and adds the other vendor as
a `syft:cpe23` property, which grype reads, so grype searches both:

```console
$ grep -h 'cpe:2.3:a:arm:mbed_tls' fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/spdx/modules-deps.spdx
ExternalRef: SECURITY cpe23Type cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*
$ rollcall generate --zephyr fixtures/zephyr-old-mbedtls/old-mbedtls --sysbuild \
    --west-list fixtures/zephyr-old-mbedtls/old-mbedtls/west-list.txt \
    --identifier-db crates/rollcall-identifiers/db/identifiers.yaml \
    --timestamp 2026-01-02T03:04:05Z -o old-mbedtls.cdx.json
$ jq -r '.components[] | select(.name == "mbedtls") | .components[] | select(.name == "mbedtls") | "cpe \(.cpe)", (.properties[] | select(.name == "syft:cpe23") | "\(.name) \(.value)")' old-mbedtls.cdx.json
cpe cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*
syft:cpe23 cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*
```

**(f) Zephyr's own CPE, and how it is typed.** Since
[#105915](https://github.com/zephyrproject-rtos/zephyr/issues/105915) was fixed, `west spdx`
writes Zephyr's CPE, `cpe:2.3:o:zephyrproject:zephyr:<version>`, with part `o` (operating
system). rollcall emits the same CPE on a CycloneDX `operating-system` component. That is an
accurate label, but grype (0.119.0) does not scan CycloneDX `operating-system` components at
all: it treats them as distro information. So Zephyr's own CVEs do not show up in grype from
either SBOM once it is converted to CycloneDX (see
[Known scanner behaviour](../README.md#known-scanner-behaviour)). How an RTOS kernel should
be typed is an ecosystem question, and one of the proposals below.

```console
$ grep -h 'cpe:2.3:o:zephyrproject' fixtures/zephyr/baseline/with_mcuboot/spdx/zephyr.spdx
ExternalRef: SECURITY cpe23Type cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*
$ jq -r '.components[] | select(.name == "with_mcuboot") | .components[] | select(.name == "zephyr") | [.type, .cpe] | join(" ")' baseline.cdx.json
operating-system cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*
```

**On `main`:** #117299 and #53479 are still open. I have not re-checked each module's
`module.yml` on `main`.

## Gap 2: Subsystem split

Zephyr is one repository, but many of its CVEs are in a subsystem: Bluetooth, networking,
USB, the file systems. Whether a CVE matters depends on whether that subsystem was built in.
`west spdx` records Zephyr as one package with one CPE, so an SBOM reader cannot tell a
Bluetooth build from one without Bluetooth, except by reading file paths:

```console
$ grep -c '^PackageName: zephyr$' fixtures/zephyr/bt/beacon/spdx/zephyr.spdx
1
$ grep -c 'subsys/bluetooth' fixtures/zephyr/bt/beacon/spdx/zephyr.spdx
35
```

rollcall splits the Zephyr component into subcomponents, using the image's Kconfig and its
linker map, and gives each a purl with a subpath into the Zephyr repository
([docs/subsystems.md](subsystems.md#the-split)). A Bluetooth beacon:

```console
$ rollcall generate --zephyr fixtures/zephyr/bt --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o bt.cdx.json
$ jq -r '.components[] | select(.name == "beacon") | .components[] | select(.name == "zephyr") | .components[] | "\(.name) \(.purl)"' bt.cdx.json
bluetooth-controller pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/controller
bluetooth-host pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/host
logging pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/logging
```

A TLS HTTP server over USB:

```console
$ rollcall generate --zephyr fixtures/zephyr/tls --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o tls.cdx.json
$ jq -r '.components[] | select(.name == "http_server") | .components[] | select(.name == "zephyr") | .components[] | .name' tls.cdx.json
filesystem
ip-stack
json
logging
mbedtls-integration
networking-core
shell
tls-sockets
usb-device
```

The same application, `smp_svr`, built with Bluetooth on and off. Only the Bluetooth build
lists the Bluetooth subsystems:

```console
$ for b in smp-bt smp-serial; do rollcall generate --zephyr fixtures/zephyr-smp/$b --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o $b.cdx.json; done
$ for b in smp-bt smp-serial; do echo "$b: $(jq -r '[.components[] | select(.name == "smp_svr") | .components[] | select(.name == "zephyr") | .components[].name] | join(" ")' $b.cdx.json)"; done
smp-bt: bluetooth-controller bluetooth-host dfu logging mcumgr
smp-serial: dfu logging mcumgr
$ grep -h -e '^CONFIG_BT=' -e '^# CONFIG_BT is' fixtures/zephyr-smp/smp-bt/smp_svr/zephyr/.config \
    fixtures/zephyr-smp/smp-serial/smp_svr/zephyr/.config
CONFIG_BT=y
# CONFIG_BT is not set
```

This is what makes "not affected: the code is not present" VEX statements possible, with
the build itself as evidence ([docs/vex-rules.md](vex-rules.md)). The subsystem names and
their purl subpaths are rollcall's own convention; no shared one exists yet.

## Gap 3: MCUboot and sysbuild

A product built with sysbuild is several images: here MCUboot and the application. `west
spdx` works on one image build directory at a time. Run against the sysbuild top-level
directory it does not produce documents
([#105917](https://github.com/zephyrproject-rtos/zephyr/issues/105917)), so the fixtures run
it once per image, and nothing at the top level describes the product:

```console
$ ls fixtures/zephyr/baseline
build_info.yml
domains.yaml
mcuboot
west-list.txt
with_mcuboot
zephyr
$ grep -h '^DocumentNamespace' fixtures/zephyr/baseline/*/spdx/app.spdx
DocumentNamespace: http://spdx.org/spdxdocs/rollcall-baseline-mcuboot/app
DocumentNamespace: http://spdx.org/spdxdocs/rollcall-baseline-with_mcuboot/app
```

The two sets of documents are unrelated: no document says that they ship together. Their
namespaces are only stable because the fixture script passes `-n`; by default `west spdx`
uses `http://spdx.org/spdxdocs/zephyr-<random UUID>`, a new one on every run
([spdx.py line 103](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/spdx.py#L103)).
So regenerating the SBOM for an unchanged build gives it a new identity, and nothing in the
document ties it to the build it describes.

The sysbuild top level does know the images and their roles, in its `build_info.yml`:

```console
$ grep -h -A2 '^   - name:' fixtures/zephyr/baseline/build_info.yml | grep -v source-dir
   - name: 'with_mcuboot'
     type: 'MAIN'
   - name: 'mcuboot'
     type: 'BOOTLOADER'
```

`rollcall generate --sysbuild` reads that list, ingests each image's `west spdx` output and
writes one product with an image per domain, each marked bootloader or application. The
`bom-ref`s are derived from content, so the same build gives a byte-identical document:

```console
$ jq -r '.metadata.component | "\(.type) \(.name) \(."bom-ref")"' baseline.cdx.json
firmware with_mcuboot product:522ecf4e0d7a9bd6627cb7dc2de20445
$ jq -r '.components[] | "\(.name) \(."bom-ref") \(.properties[] | select(.name == "rollcall:image-kind") | .value)"' baseline.cdx.json
mcuboot image:4c16469be39e3d2752a45ea8ca6dd665 bootloader
with_mcuboot image:84d1e2994560e6b81f17ac46adb9c12c application
$ jq -r '.dependencies[] | select(.ref | startswith("product:")) | .dependsOn[]' baseline.cdx.json
image:4c16469be39e3d2752a45ea8ca6dd665
image:84d1e2994560e6b81f17ac46adb9c12c
$ rollcall generate --zephyr fixtures/zephyr/baseline --sysbuild \
    --west-list fixtures/zephyr/baseline/west-list.txt \
    --identifier-db crates/rollcall-identifiers/db/identifiers.yaml \
    --timestamp 2026-01-02T03:04:05Z -o again.cdx.json
$ cmp baseline.cdx.json again.cdx.json && echo identical
identical
```

This matters beyond rollcall. RFC
[#120474](https://github.com/zephyrproject-rtos/zephyr/issues/120474) (safety assertions
bound to `west spdx` output) asks which build identity should be the authoritative product
context across sysbuild and multi-image builds. A per-image document with a random
namespace cannot be that context.

**On `main`:** #105917 is still open.

## Gap 4: Blobs

Many Zephyr products ship binary blobs: radio firmware, vendor libraries, prebuilt images.
Zephyr already describes them in `module.yml` (`blobs:` with path, SHA-256, version, licence
and URL, used by `west blobs`; see the
[binary blobs documentation](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/doc/contribute/bin_blobs.rst)).
`west spdx` does not use that information. Its walker builds the documents from the CMake
targets of the build and the sources they compile
([`walkTargets`](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py#L477) and
[`collectPendingSourceFiles`](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py#L566)), and the only
part of a module's metadata it reads is `security.external-references`
([line 430](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py#L430)). It has no code
path for `blobs:`: the word does not occur in `walker.py`. So a blob that is linked into an
image, or flashed next to it, does not appear in the SPDX documents as a blob.

The fixture builds link no vendor blobs, as the output shows: nothing in their SPDX
documents mentions one.

```console
$ grep -c -i -e opaque -e blob fixtures/zephyr/baseline/*/spdx/*.spdx || true
fixtures/zephyr/baseline/mcuboot/spdx/app.spdx:0
fixtures/zephyr/baseline/mcuboot/spdx/build.spdx:0
fixtures/zephyr/baseline/mcuboot/spdx/modules-deps.spdx:0
fixtures/zephyr/baseline/mcuboot/spdx/zephyr.spdx:0
fixtures/zephyr/baseline/with_mcuboot/spdx/app.spdx:0
fixtures/zephyr/baseline/with_mcuboot/spdx/build.spdx:0
fixtures/zephyr/baseline/with_mcuboot/spdx/modules-deps.spdx:0
fixtures/zephyr/baseline/with_mcuboot/spdx/zephyr.spdx:0
```

Because of that, the rollcall side of this example uses **hand-written test data**:
`crates/rollcall-core/tests/data/blobs/blobs.yaml`, which names a fake SoftDevice and a fake
`libphy.a` (a few bytes of text each, not real binaries).
`rollcall merge --blob-manifest` adds each blob as its own image, marked opaque, with a
SHA-256 of the file:

```console
$ rollcall merge baseline.cdx.json \
    --blob-manifest crates/rollcall-core/tests/data/blobs/blobs.yaml \
    --timestamp 2026-01-02T03:04:05Z -o with-blobs.cdx.json
$ jq -r '.components[] | select(any(.properties[]; .name == "rollcall:image-kind" and .value == "blob")) | "\(.type) \(.name) \(.version) \(.hashes[0].alg) \(.hashes[0].content)"' with-blobs.cdx.json
library libphy 5.2.1 SHA-256 40a0cdacd5afb8e813d7e72396cf1faf2ea3fe52d306216aed61de44fe35d977
firmware s140_nrf52_softdevice 7.3.0 SHA-256 3051d54d0d3116c3818e01bbc6c8ad9d7023a1dad799f97392e440fd5a546fa6
$ jq -r '.components[] | select(.name == "libphy") | .properties[] | select(.name == "rollcall:opaque") | .value' with-blobs.cdx.json
contents not analysed; hashes computed from the file
$ shasum -a 256 crates/rollcall-core/tests/data/blobs/libphy.a | cut -d' ' -f1
40a0cdacd5afb8e813d7e72396cf1faf2ea3fe52d306216aed61de44fe35d977
```

See also [Blobs in docs/subsystems.md](subsystems.md#blobs).

## Gap 5: CycloneDX

Zephyr v4.4.2 writes SPDX 2.2 or 2.3 only, and every image of every fixture build is SPDX
2.3:

```console
$ grep -h '^SPDXVersion' fixtures/zephyr/*/*/spdx/*.spdx fixtures/zephyr-smp/*/*/spdx/*.spdx | sort -u
SPDXVersion: SPDX-2.3
```

Some tools and supply chains ask for CycloneDX instead. rollcall writes CycloneDX 1.6,
which has a `firmware` component type, nested components for a product's images, and
`evidence.identity` to record where each identifier came from. rollcall's output is valid
CycloneDX 1.6:

```console
$ rollcall validate --schema baseline.cdx.json
baseline.cdx.json: valid CycloneDX 1.6
$ rollcall validate --schema with-blobs.cdx.json
with-blobs.cdx.json: valid CycloneDX 1.6
```

Valid is not the same as complete. Checked against the CISA 2026 minimum elements and the
CRA profile (BSI TR-03183-2), the baseline SBOM still has gaps that neither tool can fill
from the build alone. The 19 missing hashes are the 16 components built from source (each
image's modules, Zephyr and its subsystems), the product and its 2 images. The product and
the 2 images also have no version, supplier or identifier, which only the manufacturer
knows (`rollcall merge --product NAME@VERSION` sets the product's name and version):

```console
$ (rollcall validate --profile all --json baseline.cdx.json || true) \
    | jq -r '.profile | "errors \(.errors) warnings \(.warnings)", (.findings | group_by(.check)[] | "\(.[0].check) \(length)")'
errors 28 warnings 0
component.hash 19
component.identifier 3
component.supplier 3
component.version 3
```

See [docs/validate.md](validate.md) for what each check means and where it comes from.

**On `main`:** `west spdx` adds SPDX 3.0 and an experimental 3.1. It has serializers for
SPDX 2 and SPDX 3 only (`scripts/pylib/zspdx/serializers/`), and no CycloneDX output.

## rollcall as the companion

rollcall is not meant to replace `west spdx`. It reads its output, plus the files the build
already leaves behind, and writes one CycloneDX 1.6 product SBOM. On v4.4 each image's build
directory must be prepared with `west spdx --init` before the build, and every image,
MCUboot included, needs `CONFIG_BUILD_OUTPUT_META`, or `west spdx` stops
([walker.py line 150](https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py#L150)):

```sh
west spdx --init -d build/app        # v4.4 only, before the build (deprecated on main)
west spdx --init -d build/mcuboot
west build -b nrf52840dk/nrf52840 --sysbuild -d build app -- \
  -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
west spdx -d build/app               # once per image
west spdx -d build/mcuboot
west list -f "{name} {path} {revision} {url}" > west-list.txt
rollcall generate --zephyr build --sysbuild --west-list west-list.txt -o product.cdx.json
```

If the Zephyr community would find it useful, I would like to offer this as a west
extension command, so it fits the usual workflow. It is **not built yet**; this is the
interface I have in mind:

```sh
west rollcall -d BUILD_DIR [--sysbuild] [-o FILE] [-- ROLLCALL_ARGS...]
```

- `-d BUILD_DIR`: an image build directory, or with `--sysbuild` the sysbuild top level.
- It runs `west spdx` on each image that has no `spdx/` yet, writes the `west list` output
  to a temporary file, and then runs
  `rollcall generate --zephyr BUILD_DIR [--sysbuild] --west-list <tmp> -o FILE`.
- Anything after `--` goes to `rollcall generate` unchanged (for example
  `--identifier-db`).

## Proposals upstream

These are the four things I would like to ask Zephyr about. Each one would make `west spdx`
output more useful on its own, with or without rollcall.

1. **External references for every manifest module, with upstream versions.** Every module
   in `west.yml` declares `security.external-references` in its `module.yml`: a purl and,
   where NVD lists the project, a CPE, naming the upstream release the fork carries.
   Today two of the six modules in these builds do (Gap 1).
2. **Per-domain and product-level output under sysbuild.** `west spdx` on a sysbuild
   directory writes each domain's documents plus one product document that references them,
   with an identity derived from the build, not a random UUID (Gap 3, #105917, #120474).
3. **A subsystem convention.** An agreed way to name the Zephyr subsystems built into an
   image, for example purl subpaths into the Zephyr repository as rollcall does (Gap 2), so
   that VEX statements can say "Bluetooth host not present" in a way every tool reads.
4. **A stance on CPE part `o` versus `a`, and on component type.** Zephyr is published in
   NVD as an operating system (`cpe:2.3:o:…`). In CycloneDX that suggests an
   `operating-system` component, which grype does not scan (Gap 1 (f)). Guidance from Zephyr
   and the CycloneDX community on how an RTOS kernel should be typed would let every tool
   agree.

## Outreach log

One row per draft in [docs/outreach/](outreach/). The Posted and Link columns are filled in
when the post is made.

| Venue | Draft | Posted | Link | Status |
|-------|-------|--------|------|--------|
| Zephyr RFC #120474 (GitHub issue comment) | [zephyr-rfc-120474-comment.md](outreach/zephyr-rfc-120474-comment.md) | | | draft |
| Zephyr GitHub Discussions, Discord `#security`, Security Working Group agenda | [zephyr-working-group-thread.md](outreach/zephyr-working-group-thread.md) | | | draft |
| CycloneDX (specification Discussions, OWASP Slack `#cyclonedx`), OpenSSF SBOM Everywhere SIG, purl-spec Discussions | [firmware-sbom-talk.md](outreach/firmware-sbom-talk.md) | | | draft |

## Responses

None yet. Acknowledgements, conventions adopted upstream and objections will be summarised
here, each with a link, as they arrive.

## References

- Zephyr v4.4.2 `west spdx` command:
  <https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/spdx.py>
- Zephyr v4.4.2 SPDX walker:
  <https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/scripts/west_commands/zspdx/walker.py>
- Zephyr `main` `west spdx` command:
  <https://github.com/zephyrproject-rtos/zephyr/blob/main/scripts/west_commands/spdx.py>
- Zephyr `main` SPDX serializers:
  <https://github.com/zephyrproject-rtos/zephyr/tree/main/scripts/pylib/zspdx/serializers>
- Zephyr 4.5 migration guide (`west spdx --init` deprecated):
  <https://github.com/zephyrproject-rtos/zephyr/blob/main/doc/releases/migration-guide-4.5.rst>
- `west spdx` documentation:
  <https://docs.zephyrproject.org/latest/develop/west/zephyr-cmds.html#software-bill-of-materials-west-spdx>
- Zephyr binary blobs:
  <https://github.com/zephyrproject-rtos/zephyr/blob/v4.4.2/doc/contribute/bin_blobs.rst>
- Mbed TLS module file at the v4.4.2 pin:
  <https://github.com/zephyrproject-rtos/mbedtls/blob/a3e190fe44c78d1ba67f55979e1257328cc7d0d8/zephyr/module.yml>
- Zephyr #117299, versioned releases for module repositories:
  <https://github.com/zephyrproject-rtos/zephyr/issues/117299>
- Zephyr #105915, Zephyr's CPE missing from the SBOM (fixed):
  <https://github.com/zephyrproject-rtos/zephyr/issues/105915>
- Zephyr #105917, `west spdx` with sysbuild:
  <https://github.com/zephyrproject-rtos/zephyr/issues/105917>
- Zephyr #53479, CVEs in Zephyr modules:
  <https://github.com/zephyrproject-rtos/zephyr/issues/53479>
- Zephyr RFC #120474, safety context bound to `west spdx` output:
  <https://github.com/zephyrproject-rtos/zephyr/issues/120474>
- CycloneDX specification #1122, safety perspective for SRAC:
  <https://github.com/CycloneDX/specification/issues/1122>
- Zephyr Security Working Group:
  <https://github.com/zephyrproject-rtos/zephyr/wiki/Security-Working-Group>
- Package URL specification: <https://github.com/package-url/purl-spec>
- OpenSSF SBOM Everywhere SIG: <https://github.com/ossf/sbom-everywhere>
- rollcall: [docs/identifiers.md](identifiers.md), [docs/subsystems.md](subsystems.md),
  [docs/validate.md](validate.md), [docs/vex-rules.md](vex-rules.md),
  [docs/fixtures.md](fixtures.md), [README](../README.md#zephyr-ingestion)
