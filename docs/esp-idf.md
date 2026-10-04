# ESP-IDF

`rollcall generate --esp-idf` turns an ESP-IDF project, after `idf.py build`, into a CycloneDX
1.6 SBOM. The SBOM lists:

- ESP-IDF itself as one component, with its version, purl, CPE, supplier and licence;
- the subsystems that matter for vulnerability tracking (Mbed TLS, lwIP, ESP-TLS, Wi-Fi,
  Bluedroid, NimBLE), split out of it when the `sdkconfig` enables them *and* the link map
  shows their code linked;
- every component the IDF Component Manager resolved (`dependencies.lock`);
- Espressif's prebuilt Wi-Fi, PHY, coexistence and Bluetooth controller libraries as opaque
  blob images with SHA-256 hashes and supplier Espressif Systems.

The ingester is `rollcall_core::esp_idf`; its module documentation has the same tables in
API terms.

## Usage

```sh
idf.py build
rollcall generate --esp-idf . --idf-path "$IDF_PATH" -o sbom.cdx.json
```

| Flag | Meaning |
|------|---------|
| `--esp-idf DIR` | the project directory, the one holding `sdkconfig` |
| `--build DIR` | the build directory, relative to the working directory (default: `build` inside the `--esp-idf` directory) |
| `--idf-path DIR` | the ESP-IDF tree the build used, to hash the blobs and read the version file. Default: `$IDF_PATH` when it is set, and a note on stderr names the tree read |
| `--verbose` | also print notes: subsystems the `sdkconfig` enables but whose code was not linked |
| `--timestamp`, `--serial-number`, `-o` | as for every `generate` input |

Exit codes are those of `rollcall generate`: 0 on success, 66 when a required input is
missing or unreadable, 65 when an input is malformed (the message names the file), 64 on a
usage error.

On the Wi-Fi + TLS fixture (`examples/protocols/https_request`):

```console
$ rollcall generate --esp-idf fixtures/esp-idf/wifi-tls --idf-path fixtures/esp-idf/wifi-tls/idf --timestamp 2026-01-02T03:04:05Z -o wifi-tls.cdx.json
$ jq -r '.components[0].components[] | "\(.type) \(.name) \(.version)"' wifi-tls.cdx.json
framework esp-idf 5.5.1
library protocol_examples_common 5.5.1
$ jq -r '.components[0].components[] | select(.name == "esp-idf") | .components[] | "\(.name) \(.version) \(.cpe // "-")"' wifi-tls.cdx.json
esp-tls 5.5.1 -
lwip 2.2.0d cpe:2.3:a:lwip_project:lwip:2.2.0d:*:*:*:*:*:*:*
mbedtls 3.6.4 cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*
wifi 5.5.1 -
$ jq -r '.components[1:][] | "\(.name) \(.hashes[0].alg) \(.supplier.name)"' wifi-tls.cdx.json
libcore SHA-256 Espressif Systems
libespnow SHA-256 Espressif Systems
libnet80211 SHA-256 Espressif Systems
libphy SHA-256 Espressif Systems
libpp SHA-256 Espressif Systems
librtc SHA-256 Espressif Systems
```

## Inputs

Paths are relative to the project directory; `build/` is the build directory and `<idf>` the
ESP-IDF tree.

| Input | Required | Used for |
|-------|----------|----------|
| `build/project_description.json` | yes | project name and version; `git_revision` (the ESP-IDF version, e.g. `v5.5.1`); `target`; the `idf_path` and `build_dir` the build saw, to read the map's paths |
| `sdkconfig` | yes | which subsystems are enabled; the ESP-IDF version in its header comment; `CONFIG_IDF_TARGET` |
| `dependencies.lock` | no; a warning when `main/idf_component.yml` exists | every managed component: version, source, component hash, and the edges between them |
| `main/idf_component.yml` | no | the project's direct dependencies when the lock does not list them (lock format 1) |
| `managed_components/<namespace>__<name>/idf_component.yml` | no; a warning | a registry or git component's licence |
| `build/<project_name>.map` | no; a warning (no split, no blobs) | which subsystems and blobs are linked |
| `<idf>/components/esp_common/include/esp_idf_version.h`, `<idf>/version.txt` | no | the ESP-IDF version file, cross-checked against `git_revision` |
| `<idf>/<blob path>` | no; a warning (blobs without hashes) | each linked blob's SHA-256 |

`sdkconfig` has the syntax of a Kconfiglib `.config` and is read by the same parser as
Zephyr's `.config`. `build/config/sdkconfig.json` is derived from it and is not read.

## Mapping

| Input | SBOM |
|-------|------|
| `project_name`, `project_version` | the product (`metadata.component`) and its application image, whose purl is `pkg:generic/<project_name>@<project_version>` |
| ESP-IDF: `git_revision`, else the lock's `idf` entry, else the `sdkconfig` header | a `framework` component `esp-idf`: version without the leading `v`, purl `pkg:generic/esp-idf@<version>?vcs_url=git+https://github.com/espressif/esp-idf`, CPE `cpe:2.3:a:espressif:esp-idf:<version>` for a release `X.Y.Z`, supplier Espressif Systems, licence Apache-2.0 |
| each emitted subsystem | a `library` subcomponent of `esp-idf` (see [Subsystems](#subsystems)) |
| each `dependencies.lock` entry other than `idf` | a `library` component of the image, named as in the lock (`espressif/mdns`), purl per [Package URLs](#package-urls), licence from its `idf_component.yml` |
| each linked blob | a blob image (see [Blobs](#blobs)) the application image depends on |
| `direct_dependencies` and each entry's `dependencies` | `dependsOn` edges: image → `esp-idf` and each direct dependency; component → component; `idf` → `esp-idf` |

`esp-idf` is a `framework`, not an `operating-system`: grype does not match vulnerabilities
against operating-system components.

A managed component's version is the lock's. A git source's version is the commit it is
locked at. A `local` component inside the ESP-IDF tree (such as the examples'
`protocol_examples_common`) gets ESP-IDF's version, because the lock records `*` for it. The
supplier is Espressif Systems for the `espressif` namespace and for components inside the
ESP-IDF tree.

Every fact carries evidence (`rollcall:evidence` properties) at its project-relative input:
`project-description`, `sdkconfig` (with the symbol's line), `dependencies-lock` (the
component hash as `hash` evidence `sha256:<hex>`), `idf-component-yml`, `linker-map` (the
first linked object and its line, as `esp-idf/lwip/liblwip.a(tcp.c.obj)` or, for a blob,
`esp-idf/components/esp_wifi/lib/esp32/libpp.a(pp.o)`: never an absolute path, so the SBOM
does not depend on where the project or the tree lives), `esp-idf-table` (a subsystem's
upstream purl and CPEs), `idf-version-file`, and `idf-blob` (each blob's SHA-256).

## Subsystems

An `sdkconfig` alone cannot say what an image contains. ESP-IDF sets `CONFIG_MBEDTLS_TLS_ENABLED`
in every project that builds the mbedtls component, including `hello_world`. So rollcall
splits a subsystem out of `esp-idf` only when both conditions hold:

1. one of its enabling symbols is `y` or `m` in `sdkconfig`, and
2. the link map shows one of its archives' objects in the image, under the same rule as the
   Zephyr split: an input section with a non-zero size in an allocated output section.
   Objects compiled from ESP-IDF's own port files (`components/mbedtls/port`, listed as `glue`
   in the table) do not count.

An enabled subsystem with nothing linked stays in `esp-idf`, and so does a linked one that is
not enabled. Both cases are printed as notes with `--verbose`. `hello_world` links only
Espressif's SHA driver from `libmbedcrypto.a`, so it has no `mbedtls` subcomponent:

```console
$ rollcall generate --esp-idf fixtures/esp-idf/hello-world --timestamp 2026-01-02T03:04:05Z -o hello-world.cdx.json
$ jq -r '[.components[0].components[] | select(.name == "esp-idf") | .components // [] | length] | .[0]' hello-world.cdx.json
0
```

The table is `crates/rollcall-core/db/esp-idf.yaml` (`rollcall-esp-idf/1`), checked against
ESP-IDF v5.5.1:

| Subsystem | Enabling symbols | Archives (build-relative) | Version | CPE |
|-----------|------------------|---------------------------|---------|-----|
| `bluedroid` | `CONFIG_BT_BLUEDROID_ENABLED` | `esp-idf/bt/libbt.a` | ESP-IDF's | none |
| `esp-tls` | `CONFIG_ESP_TLS_USING_MBEDTLS`, `CONFIG_ESP_TLS_USING_WOLFSSL` | `esp-idf/esp-tls/libesp-tls.a` | ESP-IDF's | none |
| `lwip` | `CONFIG_LWIP_ENABLE` | `esp-idf/lwip/liblwip.a` | lwIP's: `2.2.0d` for v5.5.1 | `lwip_project:lwip` |
| `mbedtls` | `CONFIG_MBEDTLS_TLS_DISABLED`, `CONFIG_MBEDTLS_TLS_ENABLED` | `libmbedcrypto.a`, `libmbedtls.a`, `libmbedx509.a` under `esp-idf/mbedtls/mbedtls/library/` | Mbed TLS's: `3.6.4` for v5.5.1 | `trustedfirmware:mbed_tls`, and `arm:mbed_tls` as an additional CPE |
| `nimble` | `CONFIG_BT_NIMBLE_ENABLED` | `esp-idf/bt/libbt.a` | ESP-IDF's | none |
| `wifi` | `CONFIG_ESP_WIFI_ENABLED` | `esp-idf/esp_wifi/libesp_wifi.a`, `esp-idf/wpa_supplicant/libwpa_supplicant.a` | ESP-IDF's | none |

A subsystem with an upstream version for the build's ESP-IDF tag (Mbed TLS, lwIP) carries
the upstream project's purl in the form the identifier database gives a Zephyr module
(`pkg:generic/<name>@<version>?vcs_url=git+<repository>`). The repository is the Espressif
fork that ESP-IDF's `.gitmodules` points at, so a purl-keyed VEX rule for Mbed TLS matches in
both ecosystems:

- `pkg:generic/mbedtls@3.6.4?vcs_url=git+https://github.com/espressif/mbedtls`
- `pkg:generic/lwip@2.2.0d?vcs_url=git+https://github.com/espressif/esp-lwip`

Every other subsystem's purl is the `esp-idf` purl with its directory as subpath, for example
`…esp-idf#components/esp-tls`. Mbed TLS also gets `cpe:2.3:a:arm:mbed_tls:<version>` as an
additional CPE (a `syft:cpe23` property). That vendor:product is deprecated in the dictionary,
but NVD still files Mbed TLS CVEs under it, as the identifier database's `cpe_aliases` records.
A subsystem's licence is the table's (Mbed TLS: `Apache-2.0 OR GPL-2.0-or-later`; lwIP:
`BSD-3-Clause`), else ESP-IDF's. The upstream versions per ESP-IDF tag come from the tree:
`MBEDTLS_VERSION_STRING` in `components/mbedtls/mbedtls/include/mbedtls/build_info.h`, and
`LWIP_VERSION_STRING` in `components/lwip/lwip/src/include/lwip/init.h`. Espressif's lwIP
reports `2.2.0d`; by lwIP's scheme the `d` suffix means in development toward 2.2.0. For an
ESP-IDF tag the table does not list, the subsystem takes ESP-IDF's version, the
`esp-idf`-subpath purl and no CPE, with a warning. The CPE vendor:product pairs were
confirmed with `scripts/nvd-spot-check.sh`.

`libbt.a` holds whichever Bluetooth host the `sdkconfig` selects, so `bluedroid` and `nimble`
share it; ESP-IDF never builds both. Neither fixture enables Bluetooth, so the Bluetooth
entries are covered by unit tests only.

## Package URLs

There is no purl type for the ESP Component Registry, so registry components are
`pkg:generic` with the registry as `repository_url`.

| Source (`dependencies.lock`) | purl |
|------------------------------|------|
| ESP-IDF itself (`idf`) | `pkg:generic/esp-idf@<version>?vcs_url=git+https://github.com/espressif/esp-idf` |
| registry (`service`) | `pkg:generic/<namespace>/<name>@<version>?repository_url=https://components.espressif.com` (the lock's `registry_url`, without a trailing `/`) |
| `git` | `pkg:generic/[<namespace>/]<name>@<commit>?vcs_url=git+<url>@<commit>#<path>`. Without a full commit there is no version and no `@<commit>`, with a warning |
| `local`, inside the ESP-IDF tree | the `esp-idf` purl with the directory as subpath (`#examples/common_components/protocol_examples_common`) |
| `local` elsewhere, or an unknown source type | none, with a warning: a host path is not an identifier |

CPEs come only from the table: ESP-IDF, Mbed TLS and lwIP. Registry components get none,
because NVD lists none for them.

## Blobs

ESP-IDF ships parts of its Wi-Fi, PHY, coexistence and Bluetooth controller stacks as
prebuilt static libraries:

| Directory (in the ESP-IDF tree) | What | Licence |
|---------------------------------|------|---------|
| `components/bt/controller` | Bluetooth controller | Apache-2.0 |
| `components/esp_coex/lib` | Wi-Fi/Bluetooth coexistence | Apache-2.0 |
| `components/esp_phy/lib` | PHY and RF calibration | Apache-2.0 |
| `components/esp_wifi/lib` | Wi-Fi MAC, 802.11 and mesh | Apache-2.0 |

Each archive under one of these directories with an object linked into the image becomes a
blob image. Its CycloneDX type is `library`, and the writer marks it with
`rollcall:opaque` (rollcall does not look inside it). Its name is the file name without `.a`
(`libnet80211`) and its version is ESP-IDF's. Its purl is the `esp-idf` purl with the file
as subpath, its supplier is Espressif Systems and its licence is the directory's. With
`--idf-path` (or `$IDF_PATH`) it also gets the SHA-256 of the file. Without one it is listed
without a hash, and one warning says so:

```console
$ env -u IDF_PATH rollcall generate --esp-idf fixtures/esp-idf/wifi-tls --timestamp 2026-01-02T03:04:05Z -o no-idf-path.cdx.json
$ jq -r '[.components[1:][] | .hashes // [] | length] | add' no-idf-path.cdx.json
0
```

An archive the map lists as pulled in, but whose sections were all garbage-collected, is not
a blob of the image. In the `wifi-tls` fixture this is `libmesh.a`.

Pass the tree the build actually used. A different ESP-IDF checkout gives other hashes.

## Warnings

Non-fatal problems are printed as `rollcall generate: warning: <file>: <message>`, sorted:

- a missing optional input (lock, a managed component's manifest, the link map), or a
  `project_description.json` without `idf_path` (no blob can be recognised in the map);
- a direct dependency or a component's dependency that has no entry in the lock (no edge);
- an ESP-IDF version that is not a release (`-dirty`, commits after the tag), or that two
  sources disagree about (the `git_revision` wins);
- a build of another ESP-IDF tag than the table was checked against;
- a managed component with no purl, a git source without a full commit, an invalid licence, or
  a manifest version that differs from the lock's;
- blobs without hashes (no `--idf-path`), or a blob file that cannot be read.

## Determinism

The same inputs give a byte-identical SBOM. The lock is read into a sorted map, the split
follows the table's order and the map's sorted objects, every component, edge and evidence
entry is kept in a sorted set, and no absolute path, clock or iteration order reaches the
output. The project-relative file names are the only locations evidence cites.

## Limitations

- No ELF analysis: what is linked comes from the GNU ld map. Without the map there is no
  split and no blob.
- A `local` component outside the ESP-IDF tree has no purl.
- The application image's purl, `pkg:generic/<project_name>@<project_version>`, is a local
  identifier: no registry resolves it, and two projects with the same name and version (every
  unchanged `hello_world`, version `1`, say) get the same one. Give each product a distinct
  `project()` name and set `PROJECT_VER`, or put the SBOM under your product's name with
  `rollcall merge sbom.cdx.json --product NAME@VERSION`.
- Upstream versions of Mbed TLS and lwIP are known only for the ESP-IDF tags in the table.
- The table is checked against ESP-IDF v5.5.1 for esp32. Other chips use other blob directories
  under the same table directories, but only esp32 is covered by a fixture.

## Fixtures

`fixtures/esp-idf/` holds two real builds for esp32. Both are vanilla ESP-IDF examples built
in the Docker image `espressif/idf:v5.5.1`, pinned by its multi-arch index digest
`sha256:dfa2d076c796769c07c155eba6c672b9f395aec943b2ba3701b73379b5f9e884`:

| Variant | Example | What it links |
|---------|---------|---------------|
| `hello-world` | `examples/get-started/hello_world` | ESP-IDF only (`MINIMAL_BUILD`); no lock, no blobs |
| `wifi-tls` | `examples/protocols/https_request` | Wi-Fi, lwIP, ESP-TLS and Mbed TLS; the Wi-Fi and PHY blobs; `protocol_examples_common` |

Each `fixtures/esp-idf/<variant>/` keeps the files rollcall reads: `sdkconfig`,
`dependencies.lock` and `main/idf_component.yml` (when the example has them),
`build/project_description.json`, and `build/<project>.map` without its
`Cross Reference Table` (transform `strip-cref`; rollcall does not read it, and it is most of
the map). It also keeps `idf/components/esp_common/include/esp_idf_version.h` and, under
`idf/`, every Espressif blob archive the map lists as an archive member, at its path in the
tree. `fixtures/esp-idf/MANIFEST.json` records the image, tag, digest and target, each
variant's build commands and blobs, and the size and SHA-256 of every file. The builds run
at the container paths `/project/<variant>` and `/opt/esp/idf`, so no host path reaches
the fixtures. The fixture tests check this.

`https_request` was chosen over the esp_websocket_client example for the Wi-Fi + TLS
fixture. Both build cleanly in the pinned image, and the websocket example is not in the
ESP-IDF tree; it is the `espressif/esp_websocket_client` registry component's `target`
example. Against `hello_world`, `https_request` adds exactly the Wi-Fi/TLS subsystems, the
blobs, and its one managed component, `protocol_examples_common`, the helper that brings
Wi-Fi up. The websocket example adds two registry components on top
(`espressif/esp_websocket_client` and `espressif/cjson`) and pulls in `tcp_transport`, so its
diff is less clear. Registry and git sources are covered by unit tests.

### Regenerating

```sh
scripts/regen-fixtures-esp-idf.sh --check-stable   # or: scripts/regen-fixtures.sh --variant esp-idf
```

The script needs Docker and, on first run, the network to pull the image (about 4 GB
compressed, 12 GB unpacked). It builds each variant in a fresh container
(`idf.py set-target esp32`, `idf.py build`) and collects the files. It fails if a host path
is left in a text file. With `--check-stable` it builds everything twice and requires
byte-identical trees. It runs `cargo test -p rollcall-core --test fixtures_esp_idf` on the
staged tree before replacing `fixtures/esp-idf/`, then `scripts/regen-golden.sh` refreshes
the goldens. `--remove-image` deletes the image afterwards to free disk.

The `regen-esp-idf` job of the `regen-fixtures` workflow runs the script on `ubuntu-24.04`
(linux/amd64). **CI is canonical**: its `esp-idf-fixtures` artifact is downloaded and
committed by hand. A local run (on arm64 the image runs natively) gives the same file set
and passes the same checks.

### Bumping the pin

1. Choose the new tag and read its index digest:
   `docker buildx imagetools inspect espressif/idf:<tag>`.
2. Set `IDF_TAG` and `IDF_IMAGE_DIGEST` in `scripts/regen-fixtures-esp-idf.sh`.
3. Check the table against the new tree: the symbols (`grep -r "config <SYMBOL>"` in its
   `Kconfig` files), the archives (in a build's map), the blob directories, the port files
   listed as `glue`, and the upstream versions. Add an `upstream_versions` entry for the new
   tag and set `idf.tag`.
4. Regenerate the fixtures and the goldens, and review both diffs.
