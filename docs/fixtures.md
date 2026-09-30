# Zephyr build fixtures

`fixtures/zephyr/` holds the outputs of real Zephyr builds: a vanilla, pinned Zephyr release
built for `nrf52840dk/nrf52840` with sysbuild and MCUboot, in three variants. rollcall's Zephyr
ingestion is developed and tested against them.

They are produced only by `scripts/regen-fixtures.sh` and never edited by hand. The copy
committed to the repository is the one built by the `regen-fixtures` GitHub Actions workflow on
`ubuntu-24.04`: **CI is canonical**. A local run is for development; it produces the same file
set and passes the same checks, but byte identity across operating systems is not promised
(different host compilers build the host tools, and the manifest records the host).

## What is here

```
fixtures/zephyr/
  MANIFEST.json                 pins, build commands, and path/size/sha256 of every file
  <variant>/
    west-list.txt               `west list -f "{name} {path} {revision} {url}"`
    build_info.yml              sysbuild's build_info.yml
    domains.yaml                sysbuild's domains (images and flash order)
    zephyr/.config              sysbuild Kconfig (SB_CONFIG_*)
    <app>/                      the application image
      build_info.yml
      zephyr/.config            application Kconfig
      zephyr/zephyr.map         linker map
      zephyr/zephyr.meta        CONFIG_BUILD_OUTPUT_META: modules and revisions
      zephyr/zephyr.elf         final ELF, debug sections stripped
      zephyr/zephyr.signed.hex  MCUboot-signed image
      spdx/{app,zephyr,build,modules-deps}.spdx   `west spdx` output, SPDX 2.3
    mcuboot/                    the MCUboot image, same files except
      zephyr/zephyr.hex         (unsigned) in place of zephyr.signed.hex
```

| Variant    | Sample                                  | Extra configuration                               | App image      | Intended options                                              |
|------------|-----------------------------------------|---------------------------------------------------|----------------|---------------------------------------------------------------|
| `baseline` | `samples/sysbuild/with_mcuboot`         | none (the sample's `sysbuild.conf` enables MCUboot) | `with_mcuboot` | `CONFIG_BT` off, `CONFIG_MBEDTLS` off                         |
| `bt`       | `samples/bluetooth/beacon`              | `SB_CONFIG_BOOTLOADER_MCUBOOT=y`                   | `beacon`       | `CONFIG_BT=y`, `CONFIG_MBEDTLS` off                           |
| `tls`      | `samples/net/sockets/http_server`       | `SB_CONFIG_BOOTLOADER_MCUBOOT=y`, `EXTRA_CONF_FILE="overlay-usbd.conf;overlay-tls.conf"`, `EXTRA_DTC_OVERLAY_FILE=usbd_cdc_ncm.overlay` | `http_server` | `CONFIG_MBEDTLS=y`, `CONFIG_NET_SOCKETS_SOCKOPT_TLS=y`, `CONFIG_BT` off |

Every variant builds MCUboot through sysbuild (`SB_CONFIG_BOOTLOADER_MCUBOOT=y`) with its
default RSA-2048 development key, and every image is built with `CONFIG_BUILD_OUTPUT_META=y`,
which `west spdx` needs. From the workspace top directory, each variant is:

```sh
west spdx --init -d build/<variant>/<app>
west spdx --init -d build/<variant>/mcuboot
west build -b nrf52840dk/nrf52840 --sysbuild -d build/baseline zephyr/samples/sysbuild/with_mcuboot \
  -- -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
west build -b nrf52840dk/nrf52840 --sysbuild -d build/bt zephyr/samples/bluetooth/beacon \
  -- -DSB_CONFIG_BOOTLOADER_MCUBOOT=y -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
west build -b nrf52840dk/nrf52840 --sysbuild -d build/tls zephyr/samples/net/sockets/http_server \
  -- -DSB_CONFIG_BOOTLOADER_MCUBOOT=y "-DEXTRA_CONF_FILE=overlay-usbd.conf;overlay-tls.conf" \
     -DEXTRA_DTC_OVERLAY_FILE=usbd_cdc_ncm.overlay \
     -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
PYTHONHASHSEED=0 west spdx -d build/<variant>/<image> --spdx-version 2.3 \
  -n http://spdx.org/spdxdocs/rollcall-<variant>-<image>      # for <app> and mcuboot
```

`west spdx --init` runs before the build, on each image's own build directory: it only creates
the empty CMake file-API query `<dir>/.cmake/api/v1/query/codemodel-v2`, and sysbuild then
configures the image in that same directory. The builds never use `-p always`; the script
deletes `build/<variant>` first instead. The exact argv of each build is in `MANIFEST.json`
under `variants.<v>.build_command`.

**The `tls` variant uses a fallback sample.** The ticket's planned sample was
`samples/net/sockets/echo_client` with `overlay-802154.conf;overlay-tls.conf`. On this board
and Zephyr release it stops at Kconfig: `CONFIG_MAX_THREAD_BYTES` needs `USERSPACE`,
`CONFIG_NET_IF_MAX_IPV4_COUNT` needs IPv4, and `MBEDTLS_SSL_PROTO_DTLS` needs
`MBEDTLS_SSL_PROTO_TLS1_2`, and Zephyr treats these Kconfig warnings as errors. The planned
fallback, `samples/net/sockets/echo_server` with the same overlays, fails on the same DTLS
dependency; forcing `CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y` then fails to compile in
tf-psa-crypto's `md.c` under `-Werror`. Neither sample's `overlay-tls.conf` is built by any
upstream test in this release. Any IEEE 802.15.4 build on this board also makes `west spdx`
crash (`AttributeError` at `zspdx/walker.py:704`): hal_nordic always defines the
`nrf-802154-serialization` library but does not build it here, and the SPDX walker does not
handle an unbuilt library that depends on a built one. So the `tls` variant is
`samples/net/sockets/http_server` with its own `overlay-usbd.conf`, `overlay-tls.conf` and
`usbd_cdc_ncm.overlay`, each built by upstream CI: an HTTPS server using TLS sockets over a
USB CDC-NCM network interface. No Zephyr file is patched and no Kconfig option is forced. The
reason is recorded in `MANIFEST.json` as `variants.tls.fallback`.

## Pins

All pins are constants at the top of `scripts/regen-fixtures.sh` and are copied into
`MANIFEST.json`.

| What                 | Pin                                                                         |
|----------------------|-----------------------------------------------------------------------------|
| Zephyr               | `v4.4.2` = `dccb09599635bdff17633fa7e9dab014b91dce90`, from https://github.com/zephyrproject-rtos/zephyr |
| Modules              | the revisions in Zephyr's `west.yml`, filtered by `manifest.project-filter` `-.*,+hal_nordic,+cmsis,+cmsis_6,+mbedtls,+tf-psa-crypto,+mcuboot`; listed in `MANIFEST.json` `modules` |
| Zephyr SDK           | `1.0.1`: `zephyr-sdk-1.0.1_<host>_minimal.tar.xz` plus `toolchain_gnu_<host>_arm-zephyr-eabi.tar.xz` (GCC 14.3.0), SHA-256 checked against the release's `sha256.sum` |
| Python tools         | `west==1.5.0`, `reuse==6.2.0`, `imgtool==2.4.0` exactly, plus Zephyr's `scripts/requirements-base.txt` and MCUboot's `zephyr/requirements.txt`, which float (see below) |
| Board                | `nrf52840dk/nrf52840`                                                       |

**Exact and floating pins.** Exact: the Zephyr commit, every module revision (from Zephyr's
`west.yml` at that commit), the SDK bundles (by SHA-256) and so GCC, and `west`, `reuse` and
`imgtool`, whose versions the script re-checks on every run, even when the venv already exists.
Floating: the other Python packages. Zephyr's and MCUboot's requirement files give ranges
(`pyelftools>=0.29`, `PyYAML>=6.0`, `cryptography>=40.0.0`, ...), so pip installs whatever is
current when the venv is created. The full sorted `pip freeze` is recorded in `MANIFEST.json` as
`python.freeze`, together with the versions of `west`, `reuse`, `imgtool`, `pyelftools` and
`PyYAML`. Host tools (`cmake`, `ninja`, the host C compiler, `python3`) also float; only the
minimum versions under **Prerequisites** are checked.

Each variant also has `variants.<v>.built_with`: the host, `sdk.gcc_version` and `python`
(including `freeze`) it was actually built with. They are the same as the top-level values when
all variants are built together. A variant carried over by `--variant` keeps the `built_with` it
had in the existing manifest.

The SDK is installed without its host tools (QEMU, OpenOCD and so on are not needed to build),
with the arm toolchain in `<sdk>/gnu/arm-zephyr-eabi`, where the SDK's CMake looks for it. The
script refuses a Zephyr checkout whose `HEAD` is not the pinned commit, any module whose `HEAD`
is not its manifest revision, and any of those repositories with local modifications
(`git status --porcelain` not empty). The build directories, the venv and west's own files are
in the workspace top directory, outside every project repository, so they do not count.

## Prerequisites

Supported hosts: Linux x86_64, Linux aarch64, macOS on Apple silicon.

- **macOS:** Xcode Command Line Tools (`xcode-select --install`) and
  `brew install cmake ninja`. Python 3.10 or later.
- **Ubuntu 24.04:**
  `sudo apt-get install -y --no-install-recommends git cmake ninja-build gperf python3 python3-venv curl xz-utils file`.
  This is a superset of what the workflow installs (`ninja-build gperf xz-utils file`): the
  GitHub-hosted `ubuntu-24.04` image already has the rest.
- `cmake` 3.20 or later, `ninja`, `python3` 3.10 or later, `git`, `curl`, `tar`, `xz`, and
  `sha256sum` or `shasum`. `dtc` is not required.
- About 4 GB of free disk under `.cache/` (SDK about 0.8 GB, workspace about 1 GB, build
  directories up to about 0.5 GB while a variant builds; `--check-stable` keeps two staging
  copies of the fixtures, a few MB each).
- Network access on the first run: GitHub for Zephyr, its modules and the SDK; PyPI for the
  Python tools.
- A Rust toolchain: the script runs `cargo test -p rollcall-core --test fixtures` on the staged
  result before installing it.
- Any `bash` from 3.2 (macOS's `/bin/bash`) up.

## Regenerating

Locally, from the repository root:

```sh
scripts/regen-fixtures.sh --check-stable
```

This installs the SDK into `.cache/zephyr-sdk`, sets up the west workspace and its Python venv
in `.cache/zephyr-workspace` (each step is skipped when its marker file exists), builds every
variant twice from scratch, compares the two runs, runs
`cargo test -p rollcall-core --test fixtures` on the staged tree (through
`ROLLCALL_FIXTURES_DIR`), and only if that passes replaces `fixtures/zephyr/` (the old tree is
put back if the swap fails half-way). It then prints `git status` for the fixtures. Build logs
are in `.cache/fixtures-logs/`. Other options: `--variant V` (repeatable) builds only some
variants and carries the others over from the existing output (it warns, and the staged tree
then fails the tests and is not installed, if a variant has nothing to carry over);
`--skip-setup` downloads nothing; `--keep-build` keeps `build/<variant>`. The locations can be moved with `ROLLCALL_ZEPHYR_WORKSPACE`,
`ROLLCALL_ZEPHYR_SDK` and `ROLLCALL_FIXTURES_OUT`. `scripts/regen-fixtures.sh --help` lists
everything.

The canonical fixtures come from the `regen-fixtures` workflow
(`.github/workflows/regen-fixtures.yml`), which runs the same script with `--check-stable` on
`ubuntu-24.04`, compares the result with the committed fixtures (a report in the job summary
only; that step always succeeds) and uploads `fixtures/zephyr` as the `zephyr-fixtures`
artifact. It runs on pull requests that change the script or the workflow, and on demand; the
artifact of either kind of run is canonical. On demand:

```sh
gh workflow run regen-fixtures.yml --ref <branch>
gh run list --workflow regen-fixtures.yml --branch <branch> --limit 1   # note the run id
gh run watch <run-id>
rm -rf fixtures/zephyr
gh run download <run-id> -n zephyr-fixtures -D fixtures/zephyr
cargo test -p rollcall-core --test fixtures
git add fixtures/zephyr && git commit
```

The `zephyr-fixtures` artifact holds only the fixture tree, so it can be downloaded straight
into `fixtures/zephyr`. A second artifact, `zephyr-fixtures-reports`, holds
`compare-stable.txt` (run 1 against run 2), `compare-committed.txt` (the new fixtures against
the committed ones) and the build logs. Review the fixture diff like code.

## Determinism

`--check-stable` builds everything twice from scratch into the same build paths and runs
`scripts/regen-fixtures.sh compare`, which requires the same file set and byte-identical files,
with three exceptions, each masked only as far as needed. Any file that cannot be read or
parsed under its rule is a FAIL, even when both sides fail the same way.

- **`*.spdx`:** `west spdx` writes the current time in `Created:`, and `build.spdx` refers to
  the other documents by SHA1 in `ExternalDocumentRef:`, which changes with them. The compare
  replaces the value of each `Created:` line with `<masked>` (the line is kept, so an extra or
  missing `Created:` line is a difference), and replaces the 40-hex SHA1 at the end of each
  `ExternalDocumentRef: DocumentRef-<name> <namespace> SHA1: <sha1>` line with `<masked>`
  (name and namespace are still compared). Both files must be UTF-8 and start with
  `SPDXVersion: SPDX-`. It also sorts each consecutive run of `Relationship:` lines before
  comparing, so a line moved into a different run is still a difference: `build.spdx` lists a target's `HAS_PREREQUISITE` and
  `STATIC_LINK` relationships in the order of CMake's file-API codemodel, and CMake does not
  keep that order stable between two configures of the same tree (the set of relationships is
  identical; only their order moves). Running `west spdx` again on one build tree gives
  identical output. The committed files keep the real values and order.
- **`*.signed.hex`:** imgtool signs with RSA-PSS, whose salt is random, so the signature
  differs on every build. The compare parses the Intel HEX and requires, unmasked, the same
  sequence of records (type, address, byte count, and the payload of every non-data record) and
  the same line terminator on every line. It then finds the MCUboot image header and the TLV
  area, requires exactly one TLV of type `0x20` (`IMAGE_TLV_RSA2048_PSS`, the only signature
  type in these images) at the same offset with the same length on both sides, and zeroes only
  that TLV's value (256 bytes). Every other byte (the 0x200-byte header, the image, the SHA-256
  TLV `0x10`, the key-hash TLV `0x01`) must match.
- **`MANIFEST.json`:** compared as JSON, ignoring the `sha256` of those two kinds of file.

What the script does to make the rest stable:

- `SOURCE_DATE_EPOCH` is set to the commit time of the pinned Zephyr commit (recorded in
  `MANIFEST.json` as `zephyr.source_date_epoch`). GCC uses it for `__DATE__` and `__TIME__`,
  which e.g. `lib/posix/options/uname.c` compiles in; without it, a static library in the `tls`
  build (and so its checksum in `build.spdx`) changes on every build.
- `west spdx` runs with `PYTHONHASHSEED=0`. `reuse` returns a file's copyright notices as a
  set, so without a fixed hash seed their order in `zephyr.spdx` and `app.spdx` changes from run
  to run.
- **Path normalisation:** every text fixture (`.config`, `build_info.yml`, `domains.yaml`,
  `zephyr.meta`, `zephyr.map`, `*.spdx`, `west-list.txt`) has the workspace top directory
  replaced by `/zephyrproject` and the SDK directory by `/zephyr-sdk`, both in their logical
  and physical (`pwd -P`, e.g. macOS `/private/...`) forms, longest first. Before replacing, it
  fails if either directory is immediately followed by another path character
  (`[A-Za-z0-9_.-]`), so a sibling such as `<workspace>2` is never half-replaced. (That check
  runs on the original text because the placeholder `/zephyrproject` is legitimately followed by
  `-` in URLs like `github.com/zephyrproject-rtos`.) Afterwards it fails if the workspace path,
  the SDK path or `$HOME` is still present in any of them. Files changed
  this way have `"transform": "normalise-paths"` in the manifest. Binary files are not touched.
- `CCACHE_DISABLE=1`: Zephyr uses ccache when it is installed, and a cache hit in the second
  run would compare an object file with itself rather than with a fresh compile.
- west runs with empty global and system configuration (`WEST_CONFIG_GLOBAL`,
  `WEST_CONFIG_SYSTEM`), and `ZEPHYR_MODULES`, `EXTRA_ZEPHYR_MODULES` and similar variables are
  unset, so nothing from the user's environment reaches the build.
- `MANIFEST.json` is written with sorted keys and sorted file entries, and contains no
  timestamps or host names (it does record the host OS and architecture).

What is not stable across build locations: the debug information in object files and
libraries embeds the absolute build path, so building in a different directory (another
machine, or another `ROLLCALL_ZEPHYR_WORKSPACE`) changes the `.debug_*` section sizes in
`zephyr.map`, the checksums of intermediate libraries in `build.spdx`, and the unstripped ELF's
`source_sha256` in the manifest. The stripped `zephyr.elf`, the hex images, every `.config`,
`build_info.yml`, `domains.yaml`, `zephyr.meta`, `west-list.txt` and the other SPDX documents
come out the same. `--check-stable` builds both runs in the same place, so it is not affected;
this is why the CI build is the canonical one.

## Trimming

- `zephyr.elf` is `arm-zephyr-eabi-strip --strip-debug` output; the manifest records the
  original ELF's SHA-256 as `source_sha256` and `"transform": "strip-debug"`. Symbols and all
  loadable sections are kept.
- Only the files listed under **What is here** are kept; object files, `compile_commands.json`,
  CMake caches and the unsigned app `.hex`/`.bin` are not.
- The whole tree must stay under 50 MB; it is a few MB, so Git LFS is not used.

In `.gitattributes`, everything under `fixtures/zephyr/` is `-text` and `linguist-generated`,
so Git never converts line endings there on checkout or commit and every SHA-256 in the
manifest keeps matching. That rule comes after the repository-wide `*.json text eol=lf`, so it
also covers `MANIFEST.json`. The MCUboot `zephyr.hex` files from objcopy have CRLF line
endings; every other text fixture is LF. `*.map` has diffs turned off and `*.elf` is binary.

## Checks

`crates/rollcall-core/tests/fixtures.rs` (part of `cargo test --workspace`) checks the committed
tree, or the tree named by `ROLLCALL_FIXTURES_DIR`:

- the manifest pins Zephyr `v4.4.2` at a 40-hex commit and SDK `1.0.1`, with three variants;
- each variant has the full file set, and the manifest lists exactly the files on disk, with
  matching sizes and SHA-256s;
- the tree is under 50,000,000 bytes, measured from disk;
- each variant's application `.config` has the intended options on and off (see the table
  above), and every variant enables MCUboot through sysbuild;
- every SPDX document is SPDX 2.3 with a `http://spdx.org/spdxdocs/rollcall-<variant>-<image>/`
  namespace;
- no text fixture contains `/Users/`, `/home/`, `/private/`, `/root/`, `/work/` or
  `/opt/hostedtoolcache`, and `build_info.yml` uses `/zephyrproject`;
- `scripts/regen-fixtures.sh compare` passes identical copies of the tree and a flipped byte
  inside the signature TLV or reordered relationships within a run, and fails a flipped image
  byte, a CRLF-converted hex, a `.config` value change, a relationship moved to another run or
  retargeted, an extra `Created:` line, and garbage or empty SPDX on both sides (skipped only if
  `bash` or `python3` is missing);
- this document has its sections.

`crates/rollcall-core/tests/zephyr.rs` ingests every image build (`<variant>/<app>` and
`<variant>/mcuboot`) through `rollcall_core::zephyr`, checks the result is schema-valid
CycloneDX 1.6, and compares the module set and revisions against each variant's
`west-list.txt`.

## Bumping the pin

1. Change `ZEPHYR_TAG` and `ZEPHYR_COMMIT` (check with
   `git ls-remote https://github.com/zephyrproject-rtos/zephyr 'refs/tags/<tag>^{}'`) and, if
   needed, `SDK_VERSION` and the six SDK SHA-256s from the sdk-ng release's `sha256.sum`, and
   the Python tool pins.
2. If a build needs a module that the project filter leaves out, add only that module to
   `PROJECT_FILTER` and say so here.
3. Delete `.cache/zephyr-workspace` (and `.cache/zephyr-sdk` for a new SDK) and run
   `scripts/regen-fixtures.sh --check-stable` locally until it passes.
4. Update the pins asserted in `crates/rollcall-core/tests/fixtures.rs` and in this document.
5. Push, run the `regen-fixtures` workflow, download its artifact as above and commit it.
