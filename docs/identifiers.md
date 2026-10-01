# Identifiers

How rollcall names a Zephyr module's upstream project so that vulnerability scanners can match
it: the purl and CPE conventions of the seed identifier database
(`crates/rollcall-identifiers/db/identifiers.yaml`, embedded in rollcall and used by
`rollcall generate --identify`, or passed as a file with `--identifier-db`), and how each
module's upstream version is derived from the fork commit Zephyr pins. How the database is
versioned and released, and how to add a module, are in [CONTRIBUTING.md](../CONTRIBUTING.md).

A Zephyr module is built from a fork (`zephyrproject-rtos/mbedtls` at a commit), but
scanners know the *upstream* project and release. The component keeps the fork commit as its
`version`; the database adds the upstream version as evidence and uses it to render the purl
and CPE. Its schema is documented in the `rollcall_core::identify` module docs.

## PURL convention

Every entry's purl is

```
pkg:generic/<upstream name>@<upstream version>?vcs_url=git+<upstream repository>
```

for example `pkg:generic/mbedtls@3.6.4?vcs_url=git+https://github.com/Mbed-TLS/mbedtls`
(written percent-encoded in the SBOM). FatFs and SEGGER RTT, which publish no git
repository, have no `vcs_url`.

- **Why `pkg:generic`.** A registry type (`pkg:cargo`, `pkg:pypi`, …) is only right when the
  code itself is published in that registry; none of these C projects is. `pkg:github` is not
  used for upstream identity: osv-scanner reads `pkg:github` as the *GitHub Actions*
  ecosystem, so it would look the library up among Actions.
- **The fork stays visible.** The purl pinned to the fork commit
  (`pkg:github/zephyrproject-rtos/<repo>@<commit>`, from `west list`) is kept as purl evidence.
- **Modules that are their own upstream.** `hal_stm32` and `hal_nxp` are Zephyr-maintained
  aggregates of vendor code with no single upstream release, so their purl names the Zephyr
  repository and their version is the pinned commit.
- **Precedence.** A purl that Zephyr's own `spdx/modules-deps.spdx` gives a module wins over
  the database's (a differing one is a warning), and the database's is kept as evidence.
  Zephyr v4.4 writes `pkg:github/Mbed-TLS/mbedtls@v4.1.0` for mbedtls, which rollcall emits in
  canonical form as `pkg:github/mbed-tls/mbedtls@v4.1.0`, so in the E2 fixtures that is the
  component's purl. CPEs follow the same precedence; see *Which CPE wins* below.

## CPE convention

A module gets a CPE **only when its upstream's vendor:product is in the NVD CPE dictionary**
(and is not deprecated there). No CPE is constructed for the rest: a made-up vendor:product
matches nothing in NVD-backed scanners and would only look like coverage. Each module without
a CPE says why, in a `# No cpe:` comment in the database and in the module table below.

- The vendor:product is the dictionary's current one. Mbed TLS and TF-PSA-Crypto are listed
  under `trustedfirmware`; NVD has deprecated nearly all of its `arm:mbed_tls` entries.
- The version is written the way the dictionary writes it: FatFs as `r0.16` (the template is
  `fatfs:r{version}`), ESP-IDF x.y.0 releases as `x.y` (as ESP-IDF tags them), OpenThread's
  dated reference releases as `YYYY-MM-DD`.
- **Aliases.** NVD sometimes files one project's CVEs under more than one dictionary
  vendor:product, for example after a project changes hands. An entry's `cpe_aliases` lists
  the others; each must itself be a dictionary pair (deprecated ones count, as long as NVD
  still files CVEs under them). The seed has four aliases, checked against the NVD CVE API on
  2026-10-01:
  - mbedtls and mbedtls-3.6: `arm:mbed_tls`. For 3.6.4, 7 of the 13 CVEs are filed only there.
  - cjson: `cjson_project:cjson`, which holds 3 CVEs.
  - hostap: `w1.fi:hostapd`. hostapd 2.11 holds 2 CVEs, and wpa_supplicant 2.11 holds none.

  `arm:tf-psa-crypto` also carries 2 CVEs, but it is not in the dictionary, so it is not an
  alias. Zephyr's own SPDX names it for tf-psa-crypto, though, so builds keep it as the primary
  CPE (see below).
- Coverage on the E2 fixtures (`fixture_modules_resolve_a_purl_and_nvd_listed_modules_their_cpe`):
  6 modules (cmsis, cmsis_6, hal_nordic, mbedtls, mcuboot, tf-psa-crypto) in 6 image builds,
  36 module components. All 36 get an upstream purl from the database. mbedtls and
  tf-psa-crypto (2 of 6 modules, 12 of 36 components) are NVD-listed and carry their dictionary
  CPE: the primary is `arm:…` from Zephyr's SPDX, and the dictionary's `trustedfirmware:…` is
  an additional CPE. The other four modules have no dictionary entry and carry no CPE.

**Known ingestion gap ([issue #12](https://github.com/smhasan94/rollcall/issues/12)).** Builds
from the Zephyr v4.2 era are not fully joined. Their `west spdx` writes module package names
with hyphens for underscores (`cmsis-6-sources`, `hal-nordic-sources`), and purl ExternalRefs
with the SPDX 2.2 category `PACKAGE_MANAGER`. So in `fixtures/zephyr-old-mbedtls/` the modules
`cmsis_6` and `hal_nordic` are not joined to their `west list` rows: they appear as unknown
modules `cmsis-6` and `hal-nordic`. That build's own purls are not read either, so the
database's apply. mbedtls, whose name has no underscore, is joined normally and keeps its SPDX
CPE. Making the join tolerant of both spellings is tracked as issue #12.

### Which CPE wins

A component has one primary `cpe` and any number of additional CPEs:

1. **Primary.** If `spdx/modules-deps.spdx` gives a CPE, it is the primary, as it is for the
   purl. Otherwise the database's `cpe` is. A database `cpe` that differs from the SPDX one
   triggers a warning, unless the SPDX CPE is one of the database's `cpe_aliases` (the same
   project under another NVD vendor). A differing purl triggers a warning unless both name
   the same repository (a `pkg:github` namespace/name equal to a `vcs_url` repository,
   ignoring case). Either way the database's value is kept as evidence.
2. **Additional.** Every other distinct CPE: the database's `cpe` when the SPDX one won, and
   each rendered `cpe_aliases` entry. Duplicates of the primary are dropped. They are sorted.
3. **Output.** The primary goes in the CycloneDX `cpe` field. Each additional CPE is written
   twice:
   - as a `syft:cpe23` property, the name syft and grype read (grype ignores
     `evidence.identity`);
   - as its own `evidence.identity` entry with `field: cpe` and `concludedValue` set to that
     CPE, the CycloneDX 1.6 standard place.

   The CycloneDX reader turns `syft:cpe23` properties back into additional CPEs.

The dictionary was checked on 2026-10-01 with the NVD CPE API (`scripts/nvd-spot-check.sh`
for exact pairs, plus keyword searches for each project's name). Re-check when adding a
module or when a project changes hands.

## Version derivation

Every fork in the seed is pinned by commit, so every module except `cjson` and `zephyr` uses
a `manual` rule: a table from each commit pinned by Zephyr v4.2.0, v4.2.1, v4.2.2, v4.3.0,
v4.3.1, v4.4.0, v4.4.1 and v4.4.2 (the pinned release and the two before it) to its upstream
version. `cjson` (pinned by none of these releases) and `zephyr` use a `git_tag` rule. A
`file_regex` rule reads the module's sources at generate time, which needs `--workspace`;
the seed's tables need nothing but the revision, so the regex runs once, in the script, and
its answer is stored.

The rows between `# BEGIN generated` and `# END generated` in each table are written only by
`scripts/regen-version-tables.sh` (network; caches in `.cache/version-tables/`), which
fetches each release's `west.yml`, writes the pin list
`crates/rollcall-core/tests/data/zephyr-manifest-pins.txt`, derives a version for every pinned
commit with `scripts/version-tables.py`, and fails if any pinned commit is left without one.
Hand-curated rows, if a module ever needs one, go outside the markers and cite their source.
Revisions and versions are quoted, so a hex commit such as `1e753266…` is never read as a
number. To cover a new Zephyr release, add its tag to `ZEPHYR_TAGS` in the script, run it,
and review the diff like code.

How a version is derived, per module (the `DERIVE` table in `scripts/version-tables.py`):

| Method | What it reads | Used for |
|---|---|---|
| file | a version file of the fork at the pinned commit (raw.githubusercontent.com), matched by a regex | mbedtls, mbedtls-3.6, tf-psa-crypto, mcuboot, lvgl, hal_nordic (nrfx), hal_espressif (ESP-IDF), hal_rpi_pico (Pico SDK), segger, fatfs, nanopb, zcbor, picolibc, percepio, tinycrypt (`README.zephyr`) |
| tag | the newest upstream release tag that is an ancestor of the pinned commit (blobless clone of fork and upstream) | cmsis_6, cmsis-dsp, littlefs, openthread, trusted-firmware-m, tf-m-tests, loramac-node, hostap, liblc3, uoscore-uedhoc |
| log | the newest fork commit subject naming an imported upstream release, for forks that import releases as snapshots with no shared history | cmsis (`(CMSIS 5.9.0)`), libmetal and open-amp (`update … to release v2025.10.0`), hal_silabs (`Import HAL version 2025.12.0`) |
| self | the commit itself | hal_stm32, hal_nxp |

A version file can name a release before it exists: ESP-IDF bumps
`esp_idf_version.h` at the start of a cycle. So hal_espressif's version is checked against the
upstream release tag's date (GitHub API). A fork commit made before tag `vX.Y` existed is
recorded as `X.Y-dev`, a development snapshot. Zephyr v4.4's forks give `6.1-dev`, since
v6.1 was tagged on 2026-08-25. Upstream tags are re-fetched on every run, so a release made
since the last run is picked up.

Version files were chosen over tags where the fork carries one, because it states the
release the code is, while a tag only bounds it from below. Where the obvious file states
something else, it is not used. CMSIS-Core's header holds the Core version, not the CMSIS
release. CMSIS-DSP's `version.py` is the Python wrapper's version. `sl_platform_version.h`
is a component version, not the Simplicity SDK release.

## Scanner behaviour

| Scanner | Matches on | Consequence |
|---|---|---|
| grype 0.119.0 | the CPE (`cpe-match`); the purl type does not matter for these packages | no CPE, no findings; the CPE's vendor:product decides which CVEs are found |
| osv-scanner 2.6.0 | the purl's ecosystem | `pkg:generic` maps to no ecosystem, `pkg:github` to GitHub Actions; neither finds C library advisories |

**Mbed TLS vendor split.** NVD files some Mbed TLS CVEs under `trustedfirmware:mbed_tls`
and others under the deprecated `arm:mbed_tls`. For 3.6.4, on 2026-10-01, the NVD CVE API
gives two disjoint lists:

- `trustedfirmware:mbed_tls:3.6.4`: 6 CVEs (CVE-2026-25833, -25834, -34873, -34874, -34875,
  -34876).
- `arm:mbed_tls:3.6.4`: 7 CVEs (CVE-2025-54764, -59438, -66442, CVE-2026-25835, -34871,
  -34872, -34877).

grype reports exactly the CVEs of the CPEs it searches. It searches the `cpe` and every
`syft:cpe23` property, so with the alias emitted as an additional CPE it finds all 13.

The grype check (`scripts/smoke-scan.sh --only old-mbedtls`, CI job `grype-expected-cves`)
generates an SBOM with the seed database for the real Zephyr v4.2.0 build in
`fixtures/zephyr-old-mbedtls/` (see docs/fixtures.md), whose mbedTLS fork commit is Mbed TLS
3.6.4. Its own `modules-deps.spdx` names `arm:mbed_tls:3.6.4`, which stays the primary CPE; the
database's `trustedfirmware:mbed_tls:3.6.4` is an additional CPE. The check requires two
things:

- every CVE in `crates/rollcall-core/tests/data/old-mbedtls-expected-cves.txt` is reported (the
  union of both vendors' lists);
- grype searched both CPEs.

## NVD spot-check

`scripts/nvd-spot-check.sh` queries the NVD CPE API for each CPE given. Versioned CPEs the
seed emits, run 2026-10-01T19:30:17Z:

| CPE | totalResults | non-deprecated |
|---|---|---|
| `cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*` | 1 | 1 |
| `cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*` | 1 | 1 |
| `cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*` | 1 | 1 |
| `cpe:2.3:o:zephyrproject:zephyr:4.2.0:*:*:*:*:*:*:*` | 4 | 4 |
| `cpe:2.3:a:semtech:loramac-node:4.7.0:*:*:*:*:*:*:*` | 1 | 1 |
| `cpe:2.3:a:elm-chan:fatfs:r0.16:*:*:*:*:*:*:*` | 1 | 1 |
| `cpe:2.3:a:linaro:openamp:2025.10.0:*:*:*:*:*:*:*` | 1 | 1 |

Every vendor:product the seed uses, run 2026-10-01T19:31:09Z (non-deprecated entries):
`davegamble:cjson` 49, `elm-chan:fatfs` 30, `espressif:esp-idf` 173, `w1.fi:wpa_supplicant` 77,
`semtech:loramac-node` 35, `trustedfirmware:mbed_tls` 165, `nanopb_project:nanopb` 49,
`linaro:openamp` 22, `google:openthread` 6, `trustedfirmware:tf-psa-crypto` 3,
`trustedfirmware:trusted_firmware-m` (part `o`) 48, `zephyrproject:zephyr` (part `o`) 162.

Some versions the seed derives are not (yet) listed as dictionary entries (checked
2026-10-01T19:33:59Z): `wpa_supplicant:2.11`, `trusted_firmware-m:2.2.2` and
`nanopb:1.0.0-dev` return 0; `esp-idf:5.1.6` and `esp-idf:6.1` are listed. The vendor:product
is still the right name, and NVD's CVE configurations use version ranges, which grype matches.

Exact lookups for the likeliest names of modules without a CPE, run 2026-10-01T19:32:52Z, all
returned 0 results: `mcu-tools:mcuboot`, `lvgl:lvgl`, `littlefs_project:littlefs`,
`nordicsemi:nrfx`, `arm:cmsis`, `intel:tinycrypt`, `raspberrypi:pico-sdk`, `google:liblc3`,
`silabs:simplicity_sdk`. Keyword searches of the dictionary for mcuboot, nrfx, lvgl, littlefs,
tinycrypt, zcbor, picolibc, libmetal, liblc3, pico-sdk, percepio, tracealyzer, systemview,
uoscore, uedhoc and cmsis-dsp found no entry for these projects. The search for "cmsis" found
only `o:arm:cmsis-rtos`, a different product.

Re-run:

```
scripts/nvd-spot-check.sh 'cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*' \
  'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*' \
  'cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*' \
  'cpe:2.3:o:zephyrproject:zephyr:4.2.0:*:*:*:*:*:*:*' \
  'cpe:2.3:a:semtech:loramac-node:4.7.0:*:*:*:*:*:*:*' \
  'cpe:2.3:a:elm-chan:fatfs:r0.16:*:*:*:*:*:*:*' \
  'cpe:2.3:a:linaro:openamp:2025.10.0:*:*:*:*:*:*:*'
```

## Module table

Versions are those derived for the commits Zephyr v4.2.0 to v4.4.2 pin. The reason for each
missing CPE was checked against the NVD CPE dictionary on 2026-10-01.

| Module | Upstream | Versions (v4.2.0–v4.4.2) | Version source | CPE |
|---|---|---|---|---|
| `cjson` | [cJSON](https://github.com/DaveGamble/cJSON) | — | `git_tag` rule (a tag revision such as `v1.7.18`) | `a:davegamble:cjson`, alias `a:cjson_project:cjson` |
| `cmsis` | [CMSIS 5](https://github.com/ARM-software/CMSIS_5) | 5.9.0 | newest fork commit subject (first parent) matching `\(CMSIS (?P<v>\d+\.\d+\.\d+)\)` | none: CMSIS-Core: not in the NVD CPE dictionary (only arm:cmsis-rtos, a different product). |
| `cmsis-dsp` | [CMSIS-DSP](https://github.com/ARM-software/CMSIS-DSP) | 1.16.2 | newest ancestor tag of https://github.com/ARM-software/CMSIS-DSP matching `^v(?P<v>\d+\.\d+\.\d+)$` | none: CMSIS-DSP: not in the NVD CPE dictionary. |
| `cmsis_6` | [CMSIS 6](https://github.com/ARM-software/CMSIS_6) | 6.1.0 | newest ancestor tag of https://github.com/ARM-software/CMSIS_6 matching `^v(?P<v>\d+\.\d+\.\d+)$` | none: CMSIS 6: not in the NVD CPE dictionary (only arm:cmsis-rtos, a different product). |
| `fatfs` | [FatFs](http://elm-chan.org/fsw/ff/) | 0.15a, 0.16 | file: `include/ff.h` or `ff.h` | `a:elm-chan:fatfs` |
| `hal_espressif` | [ESP-IDF](https://github.com/espressif/esp-idf) | 5.1.6, 6.1-dev | file: `components/esp_common/include/esp_idf_version.h` (`-dev` before the upstream release tag) | `a:espressif:esp-idf` |
| `hal_nordic` | [nrfx](https://github.com/NordicSemiconductor/nrfx) | 3.12.1, 3.14.0, 4.2.0 | file: `nrfx/CHANGELOG.md` | none: nrfx: not in the NVD CPE dictionary. |
| `hal_nxp` | [hal_nxp (MCUXpresso SDK for Zephyr)](https://github.com/zephyrproject-rtos/hal_nxp) | 4 commits | self: the fork is the upstream; version = commit | none: aggregates MCUXpresso SDK drivers pinned to an mcuxsdk-manifests commit, not an SDK release, so nxp:mcuxpresso_software_development_kit has no version to match. |
| `hal_rpi_pico` | [Raspberry Pi Pico SDK](https://github.com/raspberrypi/pico-sdk) | 2.1.0, 2.2.0 | file: `pico_sdk_version.cmake` | none: Raspberry Pi Pico SDK: not in the NVD CPE dictionary. |
| `hal_silabs` | [Simplicity SDK](https://github.com/SiliconLabs/simplicity_sdk) | 2025.6.0, 2025.6.2, 2025.12.0 | newest fork commit subject (first parent) matching `^simplicity_sdk: Import HAL version (?P<v>\d{4}\.\d+\.\d+)$` | none: Simplicity SDK: not in the NVD CPE dictionary (silabs:gecko_software_development_kit is its predecessor, a different product). |
| `hal_stm32` | [hal_stm32 (STM32Cube for Zephyr)](https://github.com/zephyrproject-rtos/hal_stm32) | 4 commits | self: the fork is the upstream; version = commit | none: aggregates the per-series STM32Cube packages (st:stm32cubef4, ...), each with its own version; no single dictionary entry. |
| `hostap` | [hostap (wpa_supplicant)](https://w1.fi/) | 2.11 | newest ancestor tag of https://w1.fi/hostap.git matching `^hostap_(?P<a>\d+)_(?P<b>\d+)$` | `a:w1.fi:wpa_supplicant`, alias `a:w1.fi:hostapd` |
| `liblc3` | [liblc3](https://github.com/google/liblc3) | 1.1.2 | newest ancestor tag of https://github.com/google/liblc3 matching `^v(?P<v>\d+\.\d+\.\d+)$` | none: not in the NVD CPE dictionary. |
| `libmetal` | [libmetal](https://github.com/OpenAMP/libmetal) | 2025.04.0, 2025.10.0 | newest fork commit subject (first parent) matching `^lib: update libmetal to release v(?P<v>\d{4}\.\d{2}\.\d+)$` | none: not in the NVD CPE dictionary. |
| `littlefs` | [littlefs](https://github.com/littlefs-project/littlefs) | 2.11.0 | newest ancestor tag of https://github.com/littlefs-project/littlefs matching `^v(?P<v>\d+\.\d+\.\d+)$` | none: not in the NVD CPE dictionary. |
| `loramac-node` | [LoRaMac-node](https://github.com/Lora-net/LoRaMac-node) | 4.7.0 | newest ancestor tag of https://github.com/Lora-net/LoRaMac-node matching `^v(?P<v>\d+\.\d+\.\d+)$` | `a:semtech:loramac-node` |
| `lvgl` | [LVGL](https://github.com/lvgl/lvgl) | 9.3.0, 9.5.0 | file: `lv_version.h` | none: not in the NVD CPE dictionary. |
| `mbedtls` | [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | 3.6.4, 3.6.5, 3.6.6, 4.1.0 | file: `include/mbedtls/build_info.h` or `include/mbedtls/version.h` | `a:trustedfirmware:mbed_tls`, alias `a:arm:mbed_tls` |
| `mbedtls-3.6` | [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | 3.6.6 | file: `include/mbedtls/build_info.h` | `a:trustedfirmware:mbed_tls`, alias `a:arm:mbed_tls` |
| `mcuboot` | [MCUboot](https://github.com/mcu-tools/mcuboot) | 2.1.0-dev, 2.3.0-dev, 2.4.0, 2.4.0-rc1 | file: `boot/zephyr/VERSION` | none: not in the NVD CPE dictionary. |
| `nanopb` | [nanopb](https://github.com/nanopb/nanopb) | 1.0.0-dev | file: `pb.h` | `a:nanopb_project:nanopb` |
| `open-amp` | [OpenAMP](https://github.com/OpenAMP/open-amp) | 2025.04.0, 2025.10.0 | newest fork commit subject (first parent) matching `^lib: update open-amp lib to release v(?P<v>\d{4}\.\d{2}\.\d+)$` | `a:linaro:openamp` |
| `openthread` | [OpenThread](https://github.com/openthread/openthread) | 2023-07-06, 2025-06-12 | newest ancestor tag of https://github.com/openthread/openthread matching `^thread-reference-(?P<y>\d{4})(?P<m>\d{2})(?P<d>\d{2})$` | `o:google:openthread` |
| `percepio` | [Percepio TraceRecorder](https://github.com/percepio/TraceRecorderSource) | 4.10.3, 4.11.1 | file: `TraceRecorder/include/trcRecorder.h` | none: TraceRecorder / Tracealyzer: not in the NVD CPE dictionary. |
| `picolibc` | [picolibc](https://github.com/picolibc/picolibc) | 1.8.10 | file: `meson.build` | none: not in the NVD CPE dictionary. |
| `segger` | [SEGGER RTT and SystemView](https://www.segger.com/products/development-tools/systemview/) | 3.58 | file: `SEGGER/SEGGER_RTT.h` | none: SEGGER RTT / SystemView: not in the NVD CPE dictionary. |
| `tf-m-tests` | [TF-M Tests](https://git.trustedfirmware.org/TF-M/tf-m-tests.git) | 2.2.2 | newest ancestor tag of https://git.trustedfirmware.org/TF-M/tf-m-tests.git matching `^TF-Mv(?P<v>\d+\.\d+\.\d+)$` | none: not in the NVD CPE dictionary. |
| `tf-psa-crypto` | [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto) | 1.1.0 | file: `include/tf-psa-crypto/build_info.h` or `include/tf-psa-crypto/version.h` | `a:trustedfirmware:tf-psa-crypto` |
| `tinycrypt` | [TinyCrypt](https://github.com/intel/tinycrypt) | 0.2.8 | file: `README.zephyr` | none: not in the NVD CPE dictionary. |
| `trusted-firmware-m` | [Trusted Firmware-M](https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git) | 2.2.0, 2.2.2 | newest ancestor tag of https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git matching `^TF-Mv(?P<v>\d+\.\d+\.\d+)$` | `o:trustedfirmware:trusted_firmware-m` |
| `uoscore-uedhoc` | [uOSCORE / uEDHOC](https://github.com/eriptic/uoscore-uedhoc) | 3.0.5 | newest ancestor tag of https://github.com/eriptic/uoscore-uedhoc matching `^v(?P<v>\d+\.\d+\.\d+)$` | none: not in the NVD CPE dictionary. |
| `zcbor` | [zcbor](https://github.com/NordicSemiconductor/zcbor) | 0.9.1 | file: `zcbor/VERSION` or `VERSION` | none: not in the NVD CPE dictionary. |
| `zephyr` | [Zephyr RTOS](https://github.com/zephyrproject-rtos/zephyr) | — | `git_tag` rule (a tag revision such as `v4.4.2`) | `o:zephyrproject:zephyr` |
