# rollcall documentation

rollcall turns firmware build metadata into CycloneDX 1.6 SBOMs. This index lists the guides;
the top-level [README](../README.md) has every command, flag and exit code. The same pages are
published as the docs site, <https://smhasan94.github.io/rollcall/> (built from this directory
by `scripts/build-docs.sh`; the table of contents is [SUMMARY.md](SUMMARY.md)).

## Getting started

| Page | What it covers |
|------|----------------|
| [quickstart.md](quickstart.md) | from a Zephyr build directory to a validated SBOM and a readiness report |
| [ci.md](ci.md) | the GitHub Action recipe, and a readiness badge |
| [faq-cra-cisa.md](faq-cra-cisa.md) | what the CRA and the CISA minimum elements ask of an SBOM, in plain language |

## Ecosystems

`rollcall generate` reads four ecosystems, each through its own input flag, or through a
positional `DIR` that `rollcall generate DIR` and `rollcall detect DIR` recognise by the files at
its top (the Action's `ecosystem: auto` does the same). A directory that several ecosystems
match exits 64 listing them (pass `--ecosystem` to choose), and one that none matches exits 66.

| Ecosystem | Input flag | Auto-detect signal | Inputs read | Framework or OS component | Libraries | Guide |
|-----------|------------|--------------------|-------------|---------------------------|-----------|-------|
| `zephyr` | `--zephyr DIR` (`--sysbuild` for a sysbuild top-level directory) | `build_info.yml` (a sysbuild with `domains.yaml`; `west-list.txt` read as the west list) | `west spdx` documents, `west list`, Kconfig `.config`, the link map, `build_info.yml`, `domains.yaml` | `zephyr`, split into subsystems; MCUboot as a bootloader image | west modules, resolved by the identifier database | [zephyr.md](zephyr.md) |
| `cargo` | `--cargo DIR` or `--cargo-metadata FILE` | `Cargo.toml` (a package), else `cargo-metadata.json` (captured) | `cargo metadata`, the `cargo auditable` `.dep-v0` section of `--elf` | none (a Rust binary) | crates, `pkg:cargo` | [cargo.md](cargo.md) |
| `esp-idf` | `--esp-idf DIR` | `sdkconfig` and `build/project_description.json` | `project_description.json`, `sdkconfig`, `dependencies.lock`, `idf_component.yml`, the link map, the ESP-IDF tree's blobs | `esp-idf`, split into subsystems; Espressif blobs as blob images | managed components, ESP Component Registry purls | [esp-idf.md](esp-idf.md) |
| `platformio` | `--platformio DIR` | `platformio.ini` | `platformio.ini`, `.pio/libdeps/<env>/*/library.json` and `.piopm`, the core directory's platform and framework packages | the framework's upstream project (`arduino-esp32`, `esp-idf`, `zephyr`); the platform with `scope: excluded` | installed libraries, PlatformIO registry purls | [platformio.md](platformio.md) |

On the repository's fixtures:

```console
$ rollcall detect fixtures/zephyr/tls
zephyr
$ rollcall detect fixtures/cargo-keelsign
cargo
$ rollcall detect fixtures/esp-idf/wifi-tls
esp-idf
$ rollcall detect fixtures/platformio/arduino-mqtt
platformio
```

## Guides

| Guide | What it covers |
|-------|----------------|
| [zephyr.md](zephyr.md) | Zephyr ingestion in short, with links to the details |
| [subsystems.md](subsystems.md) | splitting the `zephyr` component into subsystems |
| [zephyr-gaps.md](zephyr-gaps.md) | what `west spdx` leaves out, and how rollcall fills it |
| [identifiers.md](identifiers.md) | the identifier database: purl and CPE conventions for Zephyr modules |
| [contributing-identifiers.md](contributing-identifiers.md) | adding a module to the identifier database |
| [cargo.md](cargo.md) | Cargo ingestion in short |
| [esp-idf.md](esp-idf.md) | ESP-IDF ingestion |
| [platformio.md](platformio.md) | PlatformIO ingestion |
| [fixtures.md](fixtures.md) | the real-build fixtures every ingester is tested against |
| [validate.md](validate.md) | `rollcall validate`: schema and regulator profiles |
| [vex-rules.md](vex-rules.md) | VEX rules |
| [scan.md](scan.md) | `rollcall scan` |
| [report.md](report.md) | the readiness report |
| [diff.md](diff.md) | `rollcall diff` and the Action's pull-request comment |
| [cra-clock.md](cra-clock.md) | the CSAF 2.0 handoff to cra-clock |
| [versioning.md](versioning.md) | semantic versioning, the MSRV and how a release is made |
| [releases/v0.1.0.md](releases/v0.1.0.md) | release notes for v0.1.0 |
