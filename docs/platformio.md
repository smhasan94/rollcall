# PlatformIO

`rollcall generate --platformio` (or `rollcall generate DIR`, which detects it) turns a
PlatformIO project, after `pio run` or `pio pkg install`, into a CycloneDX 1.6 SBOM. The SBOM
lists, for one environment:

- the framework (Arduino, ESP-IDF, Zephyr) as one component. For a framework package in
  rollcall's table it names the upstream project, with its version, purl, CPE, supplier and
  licence: `framework-arduinoespressif32` 3.20017.241212 is `arduino-esp32` 2.0.17;
- the development platform (`espressif32`) as a `platform` component with CycloneDX
  `scope: excluded`, because it is build tooling and is not shipped;
- every library PlatformIO installed for the environment, as `<owner>/<name>` with its version,
  a registry purl and, as evidence, the upstream repository's purl.

The ingester is `rollcall_core::platformio`; its module documentation has the same tables in
API terms.

## Usage

```sh
pio run -e esp32dev
rollcall generate --platformio . --env esp32dev --pio-core ~/.platformio -o sbom.cdx.json
```

| Flag | Meaning |
|------|---------|
| `--platformio DIR` | the project directory, the one holding `platformio.ini` |
| `--env NAME` | the environment. Default: the one `default_envs` names, else the project's only environment. If there are several environments and no single default, rollcall exits 64 and lists them |
| `--pio-core DIR` | the PlatformIO core directory the build used (`~/.platformio` by default in PlatformIO), for the installed platform and framework versions. Default: `$PLATFORMIO_CORE_DIR` when it is set, with a note on stderr naming it. Without either, the versions come from exact pins in `platformio.ini` |
| `--product NAME[@VERSION]` | put the product under that name, as `merge --product` does |
| `--timestamp`, `--serial-number`, `-o` | as for every `generate` input |

Exit codes are those of `rollcall generate`: 0 on success, 66 when `platformio.ini` is missing
or unreadable, 65 when an input is malformed (the message names the file, and for
`platformio.ini` the line), and 64 on a usage error, such as an unknown `--env`.

On the fixture (an Arduino-ESP32 sketch with three `lib_deps`):

```console
$ rollcall generate fixtures/platformio/arduino-mqtt --pio-core fixtures/platformio/arduino-mqtt/pio-core --timestamp 2026-01-02T03:04:05Z -o arduino-mqtt.cdx.json
$ jq -r '.components[0].components[] | "\(.type) \(.name) \(.version) \(.scope // "required")"' arduino-mqtt.cdx.json
framework arduino-esp32 2.0.17 required
library bblanchon/ArduinoJson 7.2.1 required
library knolleary/PubSubClient 2.8 required
library mathertel/OneButton 2.6.1 required
platform espressif32 6.10.0 excluded
$ jq -r '.components[0].components[] | select(.type == "library") | .purl' arduino-mqtt.cdx.json
pkg:generic/bblanchon/ArduinoJson@7.2.1?repository_url=https:%2F%2Fregistry.platformio.org
pkg:generic/knolleary/PubSubClient@2.8?repository_url=https:%2F%2Fregistry.platformio.org
pkg:generic/mathertel/OneButton@2.6.1?repository_url=https:%2F%2Fregistry.platformio.org
$ jq -r '.components[0].components[] | select(.type == "framework") | .purl, .cpe, .supplier.name' arduino-mqtt.cdx.json
pkg:generic/arduino-esp32@2.0.17?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Farduino-esp32
cpe:2.3:a:espressif:arduino-esp32:2.0.17:*:*:*:*:*:*:*
Espressif Systems
```

Without the core directory, the exact pins in `platformio.ini` give the same versions:

```console
$ rollcall generate fixtures/platformio/arduino-mqtt --timestamp 2026-01-02T03:04:05Z -o no-core.cdx.json
$ jq -r '.components[0].components[] | "\(.name) \(.version)"' no-core.cdx.json
arduino-esp32 2.0.17
bblanchon/ArduinoJson 7.2.1
knolleary/PubSubClient 2.8
mathertel/OneButton 2.6.1
espressif32 6.10.0
```

## Inputs

Paths are relative to the project directory. `<env>` is the environment and `<core>` the core
directory, which evidence cites as `pio-core/` whatever its real path.

| Input | Required | Used for |
|-------|----------|----------|
| `platformio.ini` | yes | the environments, and the chosen one's `platform`, `framework`, `lib_deps` and `platform_packages` |
| `.pio/libdeps/<env>/<library>/.piopm` | no; a warning when `lib_deps` is set but nothing is installed | each installed library's name, registry owner, installed version and source URL |
| `.pio/libdeps/<env>/<library>/library.json` | no | its version as published, `repository`, `license` and `dependencies` |
| `<core>/platforms/<platform>/.piopm`, `platform.json` | no | the platform's installed version and licence, and which package each framework is |
| `<core>/packages/<framework package>/.piopm`, `package.json` | no | the framework package's installed version and licence |

`platformio.ini` is read as PlatformIO Core 6.1.18 reads it (a Python `configparser`
dialect; `platformio/project/config.py`):

- **Inheritance** (`walk_options`). An option is searched for in the section, then in the
  sections its `extends` names, the *last* named first and depth first (each named section's
  own `extends` before the next), and for an `[env:NAME]` in the `[env]` base section last
  of all. With `extends = a, b`, `b` wins over `a`. Any section can `extends`. A name that is no
  section is skipped, as PlatformIO skips it, with a warning.
- **Interpolation.** `${section.option}` is the option as resolved for that section,
  `${env.option}` reads `[env]`, `${this.option}` the section being resolved, and
  `${this.__env__}` its environment name.
- **Option names** are case-insensitive (stored lowercase, as configparser does); section names
  are not.
- **Multi-line values.** A value can continue over several lines, with `;` and `#` comments.
- **What is not resolved.** `${sysenv.NAME}` and PlatformIO's built-in `${PROJECT_DIR}`,
  `${PROJECT_HASH}` and `${UNIX_TIME}` depend on the build machine, and any other `${NAME}`
  without a section is a SCons variable PlatformIO leaves as written. All are left as written,
  with a warning.
- **Errors.** A malformed file is an error naming the line: an option outside a section, a
  broken header, a duplicate section or option, an unknown reference, `${this.__env__}` outside
  an environment, or a loop of references or `extends`.
- **Bounds.** Resolution is memoised and bounded: at most 10 000 steps (sections searched,
  `extends` edges and references followed), references nested at most 64 deep, and 1 MiB per
  value. A file beyond those is an error naming the line, never a hang.

The platform and framework package versions live in the PlatformIO core directory, not in
`.pio/`. That is why rollcall reads the core directory (`--pio-core`, else
`$PLATFORMIO_CORE_DIR`). When neither is given, it falls back to exact pins:
`platform = espressif32 @ 6.10.0`, and `platformio/framework-arduinoespressif32 @
3.20017.241212` in `platform_packages`. A range such as `^6.10.0` pins nothing, so the version
is then unknown, with a warning.

## Mapping

| Input | SBOM |
|-------|------|
| the project directory's name | the product (`metadata.component`) and its application image, purl `pkg:generic/<name>` |
| each `framework` value | a `framework` component. For a framework package in the table, the upstream project with its release, purl, CPE (for an `X.Y.Z` release), supplier and licence; otherwise the package itself with its registry purl |
| `platform` | a `platform` component with `scope: excluded`, with its version, registry purl and licence |
| each library under `.pio/libdeps/<env>/` | a `library` component named `<owner>/<name>`. Its version is `library.json`'s when that agrees with `.piopm`, else `.piopm`'s (with a warning). It gets a purl (see [Package URLs](#package-urls)) and a licence from `library.json` |
| `lib_deps`, each `library.json` `dependencies` | `dependsOn` edges: image → each framework and each `lib_deps` library; library → library |

A library's version is spelled as its `library.json` publishes it (`2.8`, as the registry
lists it). PlatformIO records the same version as semver (`2.8.0`) in `.piopm`.

The framework table is `crates/rollcall-core/db/platformio.yaml` (`rollcall-platformio/1`):

| Package | Framework | Component | Purl | CPE |
|---------|-----------|-----------|------|-----|
| `framework-arduinoespressif32` | `arduino` on `espressif32` | `arduino-esp32` | `pkg:generic/arduino-esp32@<version>?vcs_url=git+https://github.com/espressif/arduino-esp32` | `cpe:2.3:a:espressif:arduino-esp32:<version>:*:*:*:*:*:*:*` |
| `framework-espidf` | `espidf` on `espressif32` | `esp-idf` | `pkg:generic/esp-idf@<version>?vcs_url=git+https://github.com/espressif/esp-idf` | `cpe:2.3:a:espressif:esp-idf:<version>:*:*:*:*:*:*:*` |
| `framework-zephyr` | `zephyr` | `zephyr` | `pkg:github/zephyrproject-rtos/zephyr@v<version>` | `cpe:2.3:o:zephyrproject:zephyr:<version>:-:*:*:*:*:*:*` |

A PlatformIO framework package's version encodes the upstream release in its middle number:
`3.20017.241212` is 2, 00, 17, that is Arduino-ESP32 2.0.17. The table's `versions` hold the
releases checked by hand, against the package `scripts/regen-fixtures-platformio.sh` installs.
Any other version is decoded by that rule, with a warning, and then gets the purl but no CPE:
a CPE is emitted only for a release checked by hand.

The CPE vendor:product pairs were confirmed against the NVD dictionary with
`scripts/nvd-spot-check.sh`. NVD lists `espressif:arduino-esp32`, but none of the three
fixture libraries, so libraries get no CPE.

The ESP-IDF libraries precompiled into Arduino-ESP32 are not split out of `arduino-esp32`.

Every fact carries evidence (`rollcall:evidence` properties) at its project-relative input:

- `platformio-ini`: the environment, each `lib_deps` entry and each pin, with its line;
- `piopm`;
- `library-json`, which includes the upstream purl;
- `platform-json` and `package-json`;
- `platformio-table`: a framework's upstream version, purl and CPE.

No evidence location is an absolute path. The core directory is cited as `pio-core/...`, so
the SBOM does not depend on where the project or the core directory lives.

## Package URLs

`pkg:platformio` is not a registered purl type. `pkg:github` is read by osv-scanner as a
GitHub Action. So, as for the ESP Component Registry, a registry package is `pkg:generic` with
the registry as `repository_url`:

| Package | Purl |
|---------|------|
| a registry library, platform or package (`.piopm` has an owner) | `pkg:generic/<owner>/<name>@<version>?repository_url=https://registry.platformio.org` |
| a library installed from a repository (`.piopm` `spec.uri`) | `pkg:generic/<name>@<version>?vcs_url=git+<url>` |
| a library installed from an archive URL (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar`) | `pkg:generic/<name>@<version>?download_url=<url>` |
| a library installed from a local path (`file://`, `symlink://`, a path) | none, with a warning: a host path is not an identifier, and it never reaches the SBOM |
| neither | none, with a warning |
| a framework in the table | the table's upstream purl |

A library's upstream purl, `pkg:generic/<name>@<version>?vcs_url=git+<repository>` from its
`library.json` `repository`, is recorded as `purl` evidence (confidence 0.7), not as the
component's purl. The registry's version usually equals the upstream release, but rollcall
cannot check it. If a `platformio` purl type is ever registered, the registry purl becomes
`pkg:platformio/<owner>/<name>@<version>`, and the evidence keeps the upstream one.

## Auto-detect

`rollcall generate DIR` and `rollcall detect DIR` treat a directory as PlatformIO when it
holds `platformio.ini`. They look only at the top of DIR, by file name. Each ecosystem has its
own signal:

| Ecosystem | DIR holds | Guide |
|-----------|-----------|-------|
| `zephyr` | `build_info.yml` (a sysbuild when `domains.yaml` is there too; `west-list.txt` is used as the west list) | [zephyr.md](zephyr.md) |
| `cargo` | `Cargo.toml` (a package), else `cargo-metadata.json` (captured metadata) | [cargo.md](cargo.md) |
| `esp-idf` | `sdkconfig` and `build/project_description.json` | [esp-idf.md](esp-idf.md) |
| `platformio` | `platformio.ini` | this guide |

There is no precedence between them:

- A directory that several ecosystems match exits 64, listing them. Pass
  `--ecosystem zephyr|cargo|esp-idf|platformio` to choose one.
- A directory that none matches exits 66, listing what it looked for.

A PlatformIO project built with `framework = espidf` is PlatformIO only. It keeps its
configuration in `sdkconfig.<env>` and its ESP-IDF build under `.pio/build/<env>/`, so it does
not look like an ESP-IDF project.

```console
$ rollcall detect fixtures/platformio/arduino-mqtt
platformio
$ rollcall detect fixtures/esp-idf/wifi-tls
esp-idf
```

With DIR, the flags apply as for that ecosystem's own input flag. A flag of another ecosystem
exits 64, for example `--west-list` on a PlatformIO DIR.

The Action's `ecosystem: auto` runs `rollcall detect`.

## Warnings

Warnings go to stderr as `rollcall generate: warning: <location>: <message>`, sorted and
deduplicated:

- no library is installed for the environment (run `pio pkg install -e <env>`);
- a `lib_deps` entry with no installed library. That is a framework's built-in library (such
  as `WiFi`), or one not installed yet;
- a `library.json` dependency that is not installed;
- `.piopm` and `library.json` disagreeing about a version;
- a library that publishes no licence (the fixture's ArduinoJson and PubSubClient), or a
  licence that is not an SPDX expression;
- a `library.json` `dependencies` entry rollcall cannot read (skipped; the rest is kept);
- a library installed from a local path (no purl);
- `[platformio] core_dir`, `libdeps_dir` or `extra_configs` set (rollcall does not follow them);
- an `extends` naming no section (skipped);
- a platform or framework whose version is unknown (no core directory and no exact pin);
- a framework package not in the table (no upstream identifiers), or one whose upstream
  version was decoded rather than checked;
- a core directory without the platform or package;
- `${sysenv.…}`, a built-in variable or a SCons variable left as written.
- a `[DEFAULT]` section, or a `%` in a value rollcall reads (configparser features not
  modelled; see [Limitations](#limitations));

The fixture ingests with two warnings: ArduinoJson and PubSubClient publish no licence.

## Determinism

The same inputs give a byte-identical SBOM:

- directories are read in name order;
- every collection is sorted;
- `bom-ref`s are derived from content;
- no absolute path, clock or iteration order reaches the output.

The project directory's name names the product. A test moves the project and its core
directory elsewhere and checks that the SBOM is unchanged.

## Limitations

- **One environment per SBOM.** Generate each environment you ship, and merge them with
  `rollcall merge` if they are one product.
- **Not split into subsystems.** The framework is one component. Arduino-ESP32 bundles a
  precompiled ESP-IDF, and its libraries are not split out (a follow-up).
- **Built-in and local libraries are not listed.** A framework's built-in libraries
  (`WiFi`, `Wire`) are not under `.pio/libdeps/`. Libraries in the project's own `lib/`
  directory are not listed either.
- **Toolchains and tools are left out.** `toolchain-xtensa-esp32` and `tool-esptoolpy` are
  build tooling.
- **Non-default directories are not followed.** `libdeps_dir`, `core_dir` and
  `extra_configs` in `[platformio]` are not read.
- **No hashes.** PlatformIO records no checksum in `.piopm`.
- **configparser's `%`-interpolation and `[DEFAULT]` are not modelled.** PlatformIO reads
  `platformio.ini` with configparser's default interpolation (`%%` is `%`, `%(name)s` another
  option) and applies a `[DEFAULT]` section to every section. rollcall reads values as written
  and treats `[DEFAULT]` as an ordinary section. It warns, with the line, when the file has a
  `[DEFAULT]` section or a value it reads (`platform`, `framework`, `lib_deps`,
  `platform_packages`, `default_envs`, `extends`) contains `%`.

## Fixtures

`fixtures/platformio/arduino-mqtt/` is a real `pio run -e esp32dev` (SHA-131) of the
hand-written project in `scripts/fixture-src/platformio/arduino-mqtt/`: a Wi-Fi, MQTT and
button sketch that uses its three `lib_deps`. The build runs in
`python:3.12-slim-bookworm`, pinned by digest
`sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4` (linux/amd64).
PlatformIO Core is installed from `scripts/fixture-src/platformio/requirements.txt` with
`pip install --require-hashes`. The pins:

| Pin | Version |
|-----|---------|
| PlatformIO Core | 6.1.18 |
| platform `espressif32` | 6.10.0 |
| `framework-arduinoespressif32` | 3.20017.241212 (Arduino-ESP32 2.0.17) |
| `bblanchon/ArduinoJson` | 7.2.1 |
| `knolleary/PubSubClient` | 2.8 |
| `mathertel/OneButton` | 2.6.1 |

The fixture keeps only metadata, with no sources, toolchains or build output:

- `platformio.ini`;
- each library's `.pio/libdeps/esp32dev/<library>/library.json` and `.piopm`;
- `pio-core/`, a copy of the platform's and the framework package's `.piopm`,
  `platform.json` and `package.json` from the build's core directory.

**The fixture is not vulnerability-free.** Arduino-ESP32 2.0.17, the newest release
PlatformIO's official `espressif32` platform ships, has known open CVEs, and scanners report
them: grype matches them through the `cpe:2.3:a:espressif:arduino-esp32:2.0.17:*:*:*:*:*:*:*`
CPE. The `rollcall example` workflow's `platformio` job therefore runs with `fail-on: none`.
It proves the PlatformIO pipeline and CPE-based scanning rather than a clean bill: it asserts
the scan reports open findings on `arduino-esp32`, and it pins no CVE ids, because the
vulnerability database changes.

`fixtures/platformio/MANIFEST.json` records the pins, the build command and every file's size
and SHA-256. `crates/rollcall-core/tests/fixtures_platformio.rs` checks the committed tree.

The build needs the network: PyPI, and the PlatformIO registry for the platform, the toolchain,
the framework and the libraries. The copy built by the `regen-fixtures` workflow's
`regen-platformio` job on `ubuntu-24.04` (artifact `platformio-fixtures`, uploaded with its
hidden files) is canonical: CI is canonical, and the artifact is committed by hand.

### Regenerating

```sh
scripts/regen-fixtures-platformio.sh --check-stable
# or: scripts/regen-fixtures.sh --variant platformio --check-stable
```

The script builds in a fresh container, then checks the result:

- every pin above holds after the build, and exactly the three libraries are installed;
- no file holds a host or container path;
- with `--check-stable`, a second build is byte-identical to the first;
- the staged tree passes `cargo test -p rollcall-core --test fixtures_platformio`.

Only then does it replace `fixtures/platformio/`. It also checks that git ignores none of the
hidden files. `--remove-image` deletes the python image afterwards. Then run
`scripts/regen-golden.sh` and review the golden diff.

### Bumping the pins

1. Change the pins in `scripts/fixture-src/platformio/arduino-mqtt/platformio.ini` and the
   matching `*_VERSION` and `LIB_PINS` lines in `scripts/regen-fixtures-platformio.sh`. For a
   new PlatformIO Core, regenerate `requirements.txt` with `pip download --only-binary=:all:
   platformio==<version>` in the pinned image, and hash each wheel.
2. For a new framework package, add its version and checked upstream release to `versions` in
   `crates/rollcall-core/db/platformio.yaml`.
3. Run the script with `--check-stable`, then `scripts/regen-golden.sh`.
4. Commit the CI artifact as the fixture.
