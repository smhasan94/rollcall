#!/usr/bin/env bash
# Regenerate the Zephyr build fixtures under fixtures/zephyr/ from a pinned, vanilla Zephyr
# workspace. See docs/fixtures.md. The fixtures are never edited by hand.
#
# NEEDS THE NETWORK on first run: clones Zephyr and its modules, downloads the Zephyr SDK
# (SHA-256 verified) and installs the pinned Python tools into a venv. About 4 GB of disk.
#
# Usage:
#   scripts/regen-fixtures.sh [--variant V]... [--check-stable] [--skip-setup] [--keep-build]
#   scripts/regen-fixtures.sh compare DIR_A DIR_B
#   scripts/regen-fixtures.sh --variant cargo-… [--check-stable] [--skip-setup]
#   scripts/regen-fixtures.sh --variant esp-idf[-…] [--check-stable]
#
#   A `cargo-*` variant (cargo-keelsign, cargo-deps, cargo-old-heapless) hands the whole
#   command line to scripts/regen-fixtures-cargo.sh, which builds the Cargo fixtures
#   (fixtures/cargo-*/); see that script.
#   An `esp-idf` or `esp-idf-*` variant (esp-idf, esp-idf-hello-world, esp-idf-wifi-tls) hands
#   it to scripts/regen-fixtures-esp-idf.sh, which builds the ESP-IDF fixtures
#   (fixtures/esp-idf/) in the pinned espressif/idf Docker image; see that script.
#
#   --variant V      build only variant V (baseline, bt or tls); repeatable. Default: all.
#                    Unselected variants already in the output are carried over unchanged,
#                    with the provenance (`built_with`) recorded when they were built.
#                    `--variant old-mbedtls` (alone) builds the separately pinned old-mbedTLS
#                    tree instead: Zephyr v4.2.0, SDK 0.17.2, its own workspace and SDK
#                    directory, output fixtures/zephyr-old-mbedtls; fixtures/zephyr is not
#                    touched. `--variant smp-serial` and/or `--variant smp-bt` (alone)
#                    build the smp set: the main pins plus the zcbor module (MCUmgr needs
#                    it), its own workspace, output fixtures/zephyr-smp.
#   --check-stable   build everything twice, from scratch, and compare the two trees
#                    (see `compare`); fails without touching the output if they differ.
#   --skip-setup     do not download, clone or pip-install anything; the pins are still
#                    asserted against what is already there.
#   --keep-build     keep the Zephyr build directories (default: deleted after collection).
#
#   compare A B      compare two fixture trees: identical file sets, and every file
#                    byte-equal except:
#                    - *.spdx: the value of `Created:` lines, the SHA1 at the end of
#                      `ExternalDocumentRef:` lines, and the order of lines within each run
#                      of `Relationship:` lines are ignored;
#                    - *.signed.hex: the bytes of the single RSA-PSS signature TLV (0x20) are
#                      ignored; record layout and line endings must match;
#                    - MANIFEST.json: the sha256 of those two kinds of file is ignored.
#                    Prints a PASS/FAIL table; exits 1 on any difference or unreadable file.
#
# The staged result must pass `cargo test -p rollcall-core --test fixtures` (run with
# ROLLCALL_FIXTURES_DIR pointing at it) before it replaces the output.
#
# Environment (each applies to the pin set being built; defaults in brackets for the main set,
# then for old-mbedtls, then for smp):
#   ROLLCALL_ZEPHYR_WORKSPACE  west workspace [.cache/zephyr-workspace, .cache/zephyr-workspace-v4.2.0,
#                              .cache/zephyr-workspace-smp]
#   ROLLCALL_ZEPHYR_SDK        Zephyr SDK install dir [.cache/zephyr-sdk, .cache/zephyr-sdk-0.17.2,
#                              .cache/zephyr-sdk]
#   ROLLCALL_FIXTURES_OUT      output directory [fixtures/zephyr, fixtures/zephyr-old-mbedtls,
#                              fixtures/zephyr-smp]
#
# Every setup step is idempotent: it is skipped when its marker file exists. Build logs go to
# .cache/fixtures-logs/; with --check-stable, the staging trees and compare-stable.txt stay in
# .cache/fixtures-staging/.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

# --- Pins -----------------------------------------------------------------------------------
# Three pin sets. The main one (fixtures/zephyr: baseline, bt, tls); old-mbedtls
# (fixtures/zephyr-old-mbedtls), a build against an older Zephyr whose mbedTLS has known CVEs;
# and smp (fixtures/zephyr-smp), the main pins plus the zcbor module, for the MCUmgr
# smp_svr sample built with Bluetooth off (smp-serial) and on (smp-bt).
# select_pins sets the per-set values; everything else is shared.
ZEPHYR_URL=https://github.com/zephyrproject-rtos/zephyr
WEST_VERSION=1.5.0
REUSE_VERSION=6.2.0
IMGTOOL_VERSION=2.4.0
BOARD=nrf52840dk/nrf52840
ALL_VARIANTS=(baseline bt tls old-mbedtls smp-serial smp-bt)
BASE_PROJECT_FILTER="-.*,+hal_nordic,+cmsis,+cmsis_6,+mbedtls,+tf-psa-crypto,+mcuboot"
WEST_UPDATE_ARGS=(--narrow -o=--depth=1)
# Placeholders that replace host-specific directories in every text fixture.
WS_PLACEHOLDER=/zephyrproject
SDK_PLACEHOLDER=/zephyr-sdk

# select_pins <set>: the Zephyr release, SDK, default directories and variants of a pin set.
select_pins() {
    case "$1" in
        main)
            PIN_SET=main
            ZEPHYR_TAG=v4.4.2
            ZEPHYR_COMMIT=dccb09599635bdff17633fa7e9dab014b91dce90
            SDK_VERSION=1.0.1
            # SDK 1.x: the GNU toolchain bundle unpacks under <sdk>/gnu.
            SDK_ARM_PREFIX=toolchain_gnu_
            SDK_TOOLCHAIN_PARENT=gnu
            DEFAULT_WS=.cache/zephyr-workspace
            DEFAULT_SDK=.cache/zephyr-sdk
            DEFAULT_OUT=fixtures/zephyr
            VARIANTS=(baseline bt tls)
            PROJECT_FILTER="$BASE_PROJECT_FILTER"
            ;;
        smp)
            # The main pins, plus zcbor: MCUmgr depends on it (without it CONFIG_MCUMGR
            # resolves to n and drivers/console/uart_mcumgr.c does not compile). A set of
            # its own so the main fixtures' workspace, and so their output, do not change.
            PIN_SET=smp
            ZEPHYR_TAG=v4.4.2
            ZEPHYR_COMMIT=dccb09599635bdff17633fa7e9dab014b91dce90
            SDK_VERSION=1.0.1
            SDK_ARM_PREFIX=toolchain_gnu_
            SDK_TOOLCHAIN_PARENT=gnu
            DEFAULT_WS=.cache/zephyr-workspace-smp
            DEFAULT_SDK=.cache/zephyr-sdk
            DEFAULT_OUT=fixtures/zephyr-smp
            VARIANTS=(smp-serial smp-bt)
            PROJECT_FILTER="$BASE_PROJECT_FILTER,+zcbor"
            ;;
        old-mbedtls)
            PIN_SET=old-mbedtls
            ZEPHYR_TAG=v4.2.0
            ZEPHYR_COMMIT=413b789deb391d3a37d06b463288a5fe765ee57e
            # zephyr/SDK_VERSION at v4.2.0.
            SDK_VERSION=0.17.2
            # SDK 0.17: the toolchain bundle unpacks to <sdk>/arm-zephyr-eabi.
            SDK_ARM_PREFIX=toolchain_
            SDK_TOOLCHAIN_PARENT=.
            DEFAULT_WS=.cache/zephyr-workspace-v4.2.0
            DEFAULT_SDK=.cache/zephyr-sdk-0.17.2
            DEFAULT_OUT=fixtures/zephyr-old-mbedtls
            VARIANTS=(old-mbedtls)
            PROJECT_FILTER="$BASE_PROJECT_FILTER"
            ;;
        *) return 1 ;;
    esac
    SDK_URL_BASE="https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${SDK_VERSION}"
}

# SHA-256 of zephyr-sdk-<version>_<host>_minimal.tar.xz (sdk-ng release sha256.sum).
sdk_minimal_sha256() {
    case "$SDK_VERSION/$1" in
        1.0.1/linux-x86_64) echo ca9bc0ff66fafca1dac9d592a36d953cf16d096a9d09b1c0357f021cf9f6a7eb ;;
        1.0.1/linux-aarch64) echo d79c5bfc68e679488659bea289a4026e52a64f03338875c8c9c850fff13cee30 ;;
        1.0.1/macos-aarch64) echo 867063901f39528a6175a80ebc20367bd6cb440593e7e2650eda30392f1f6b65 ;;
        0.17.2/linux-x86_64) echo a95082150d5df6255f682f05eab00228b858444b581db90ec47e5ded090ca74d ;;
        0.17.2/linux-aarch64) echo 439e1bc94823ce7ca833ce46232acff9cae4cbbc7eb440875d7363c9094e243b ;;
        0.17.2/macos-aarch64) echo ef9d34fda0a92037c98b7c28824e536f9418f92b3eeecc15098641e843c7d7c8 ;;
        *) return 1 ;;
    esac
}

# SHA-256 of the arm-zephyr-eabi toolchain bundle, <SDK_ARM_PREFIX><host>_arm-zephyr-eabi.tar.xz
# (sdk-ng release sha256.sum).
sdk_arm_sha256() {
    case "$SDK_VERSION/$1" in
        1.0.1/linux-x86_64) echo 21b85981cb5a1818d9bc53d82af80f208946ec038b982ff1907287572ed3a634 ;;
        1.0.1/linux-aarch64) echo b9805b691f2f0a8926c92694cae378d05ba07b76abca745e216fcc52753cc4d6 ;;
        1.0.1/macos-aarch64) echo 4008edb5d4840cd994aedd7f1309bfb63e7243729d57839ebf1cc83c1f17c886 ;;
        0.17.2/linux-x86_64) echo ecbfb362a9347b247848d5d8ffa7bd7ff566689bbb47cddeb7e504c87f143d17 ;;
        0.17.2/linux-aarch64) echo 32579e7fa4e56cf0d5312eac0021e92d9ec47ed2ce6ec0e7f6b37bf9779a4fd7 ;;
        0.17.2/macos-aarch64) echo 83bc167273d9208121c2ebe67a0f4a29910efeba2c0d47928f17e85e88f82007 ;;
        *) return 1 ;;
    esac
}

# --- Variants -------------------------------------------------------------------------------
# variant_sample <v>: the sample directory, relative to the workspace topdir.
variant_sample() {
    case "$1" in
        baseline) echo zephyr/samples/sysbuild/with_mcuboot ;;
        bt) echo zephyr/samples/bluetooth/beacon ;;
        tls) echo zephyr/samples/net/sockets/http_server ;;
        old-mbedtls) echo zephyr/tests/crypto/mbedtls ;;
        smp-serial | smp-bt) echo zephyr/samples/subsys/mgmt/mcumgr/smp_svr ;;
        *) return 1 ;;
    esac
}

# variant_app <v>: the application image (sysbuild domain) name.
variant_app() {
    case "$1" in
        baseline) echo with_mcuboot ;;
        bt) echo beacon ;;
        tls) echo http_server ;;
        old-mbedtls) echo mbedtls ;;
        smp-serial | smp-bt) echo smp_svr ;;
        *) return 1 ;;
    esac
}

# variant_extra_conf <v>: EXTRA_CONF_FILE value, empty for none.
variant_extra_conf() {
    case "$1" in
        tls) echo "overlay-usbd.conf;overlay-tls.conf" ;;
        smp-serial | smp-bt) echo serial.conf ;;
        *) echo "" ;;
    esac
}

# variant_extra_args <v>: further -D arguments for the application image, one per line.
# smp-bt is smp-serial with Bluetooth on and nothing else changed: the BT-off/BT-on pair
# (SHA-108). The sample compiles src/bluetooth.c only with CONFIG_MCUMGR_TRANSPORT_BT.
variant_extra_args() {
    case "$1" in
        smp-bt) printf '%s\n' -DCONFIG_BT=y -DCONFIG_BT_PERIPHERAL=y -DCONFIG_MCUMGR_TRANSPORT_BT=y ;;
        *) ;;
    esac
}

# variant_extra_dtc <v>: EXTRA_DTC_OVERLAY_FILE value, empty for none.
variant_extra_dtc() {
    case "$1" in
        tls) echo "usbd_cdc_ncm.overlay" ;;
        *) echo "" ;;
    esac
}

# variant_fallback <v>: why the variant departs from the original plan, empty if it does not.
# Recorded in MANIFEST.json and explained in docs/fixtures.md.
variant_fallback() {
    case "$1" in
        tls) echo "planned sample samples/net/sockets/echo_client with overlay-802154.conf;overlay-tls.conf aborts on Kconfig warnings on this board; the planned fallback samples/net/sockets/echo_server with the same overlays fails on MBEDTLS_SSL_PROTO_DTLS needing MBEDTLS_SSL_PROTO_TLS1_2, and with that forced, tf-psa-crypto md.c fails -Werror; any IEEE 802.15.4 build also crashes west spdx (zspdx walker.py:704, the unbuilt hal_nordic target nrf-802154-serialization); using samples/net/sockets/http_server with its own overlay-usbd.conf, overlay-tls.conf and usbd_cdc_ncm.overlay (TLS sockets over USB CDC-NCM), each built by upstream CI" ;;
        old-mbedtls) echo "planned a TLS sample like the tls variant: at v4.2.0 samples/net/sockets/http_server declares depends_on netif, and nrf52840dk has no network interface without the USB CDC-NCM overlays (overlay-usbd.conf, usbd_cdc_ncm.overlay) that only exist in later releases; using tests/crypto/mbedtls, which builds Mbed TLS (CONFIG_MBEDTLS_BUILTIN) and links its self-tests, and is built by upstream CI" ;;
        *) echo "" ;;
    esac
}

# variant_build_argv <v>: prints the `west build` argv, one argument per line.
variant_build_argv() {
    local v="$1" extra dtc
    extra="$(variant_extra_conf "$v")"
    dtc="$(variant_extra_dtc "$v")"
    printf '%s\n' west build -b "$BOARD" --sysbuild -d "build/$v" "$(variant_sample "$v")" --
    # with_mcuboot's and smp_svr's own sysbuild.conf enable MCUboot; the other samples need
    # it set.
    case "$v" in
        baseline | smp-serial | smp-bt) ;;
        *) printf '%s\n' -DSB_CONFIG_BOOTLOADER_MCUBOOT=y ;;
    esac
    [[ -z "$extra" ]] || printf '%s\n' "-DEXTRA_CONF_FILE=$extra"
    [[ -z "$dtc" ]] || printf '%s\n' "-DEXTRA_DTC_OVERLAY_FILE=$dtc"
    variant_extra_args "$v"
    printf '%s\n' -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
}

# --- Helpers --------------------------------------------------------------------------------
die() {
    echo "regen-fixtures: $*" >&2
    exit 2
}

log() {
    echo "regen-fixtures: $*"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# version_ge <have> <want>: true if dotted version have >= want.
version_ge() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" == "$2" ]]
}

check_prereqs() {
    local tool
    for tool in git cmake ninja python3 curl tar xz cmp cargo; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required (see docs/fixtures.md)"
    done
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
        die "sha256sum or shasum is required"
    local cmake_v py_v
    cmake_v="$(cmake --version | awk 'NR == 1 {print $3}')"
    version_ge "$cmake_v" 3.20 || die "cmake >= 3.20 required, found $cmake_v"
    py_v="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    version_ge "$py_v" 3.10 || die "python3 >= 3.10 required, found $py_v"
}

# host_platform: the SDK host name for this machine.
host_platform() {
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64 | Linux/amd64) echo linux-x86_64 ;;
        Linux/aarch64 | Linux/arm64) echo linux-aarch64 ;;
        Darwin/arm64 | Darwin/aarch64) echo macos-aarch64 ;;
        *) die "unsupported host $(uname -s)/$(uname -m); see docs/fixtures.md" ;;
    esac
}

# download <url> <dest> <sha256>: fetches to a temporary file, checks the hash, then moves it.
download() {
    local url="$1" dest="$2" want="$3" tmp got
    tmp="$(mktemp "$(dirname "$dest")/.download.XXXXXX")"
    if ! curl -fsSL --retry 3 -o "$tmp" "$url"; then
        rm -f "$tmp"
        die "download failed: $url"
    fi
    got="$(sha256_of "$tmp")"
    if [[ "$got" != "$want" ]]; then
        rm -f "$tmp"
        die "sha256 mismatch for $url: expected $want, got $got"
    fi
    mv "$tmp" "$dest"
}

# --- Setup ----------------------------------------------------------------------------------
# install_sdk: the minimal SDK bundle (without its host tools) plus the arm-zephyr-eabi GNU
# toolchain, which goes where the SDK's CMake looks for it: <sdk>/gnu/arm-zephyr-eabi.
install_sdk() {
    local marker="$SDK/.rollcall-sdk-$SDK_VERSION-$HOST"
    if [[ ! -f "$marker" ]]; then
        [[ "$SKIP_SETUP" -eq 0 ]] || die "SDK not installed in $SDK and --skip-setup given"
        local dl="$CACHE/downloads"
        mkdir -p "$dl" "$SDK"
        log "installing Zephyr SDK $SDK_VERSION ($HOST) into $SDK"
        [[ -f "$dl/$SDK_MINIMAL_FILE" ]] ||
            download "$SDK_URL_BASE/$SDK_MINIMAL_FILE" "$dl/$SDK_MINIMAL_FILE" "$SDK_MINIMAL_SHA256"
        [[ -f "$dl/$SDK_ARM_FILE" ]] ||
            download "$SDK_URL_BASE/$SDK_ARM_FILE" "$dl/$SDK_ARM_FILE" "$SDK_ARM_SHA256"
        # Re-check cached archives: a leftover from an interrupted run must still match.
        [[ "$(sha256_of "$dl/$SDK_MINIMAL_FILE")" == "$SDK_MINIMAL_SHA256" ]] ||
            die "cached $dl/$SDK_MINIMAL_FILE has the wrong sha256; delete it and rerun"
        [[ "$(sha256_of "$dl/$SDK_ARM_FILE")" == "$SDK_ARM_SHA256" ]] ||
            die "cached $dl/$SDK_ARM_FILE has the wrong sha256; delete it and rerun"
        # Host tools (QEMU, OpenOCD, ...) are not needed to build and are left out.
        tar -xJf "$dl/$SDK_MINIMAL_FILE" -C "$SDK" --strip-components=1 \
            --exclude="zephyr-sdk-$SDK_VERSION/hosttools" \
            --exclude="zephyr-sdk-$SDK_VERSION/hosttools/*"
        mkdir -p "$SDK/$SDK_TOOLCHAIN_PARENT"
        tar -xJf "$dl/$SDK_ARM_FILE" -C "$SDK/$SDK_TOOLCHAIN_PARENT"
        rm -f "$dl/$SDK_MINIMAL_FILE" "$dl/$SDK_ARM_FILE"
        touch "$marker"
    fi
    [[ "$(cat "$SDK/sdk_version")" == "$SDK_VERSION" ]] ||
        die "$SDK/sdk_version is not $SDK_VERSION"
    local tc="$SDK/$SDK_TOOLCHAIN_PARENT/arm-zephyr-eabi/bin"
    [[ -x "$tc/arm-zephyr-eabi-gcc" ]] ||
        die "arm-zephyr-eabi toolchain missing under $SDK/$SDK_TOOLCHAIN_PARENT"
    export ZEPHYR_SDK_INSTALL_DIR="$SDK"
    export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
    STRIP="$tc/arm-zephyr-eabi-strip"
    GCC_VERSION="$("$tc/arm-zephyr-eabi-gcc" -dumpversion)"
}

# setup_python: a venv inside the workspace with the pinned tools and Zephyr's and MCUboot's
# build requirements.
setup_python() {
    local marker="$WS/.venv/.rollcall-python-west$WEST_VERSION-reuse$REUSE_VERSION-imgtool$IMGTOOL_VERSION"
    if [[ ! -f "$marker" ]]; then
        [[ "$SKIP_SETUP" -eq 0 ]] || die "Python venv not set up in $WS/.venv and --skip-setup given"
        log "creating venv $WS/.venv"
        [[ -x "$WS/.venv/bin/python" ]] || python3 -m venv "$WS/.venv"
        "$WS/.venv/bin/python" -m pip install -q --disable-pip-version-check \
            "west==$WEST_VERSION" "reuse==$REUSE_VERSION" "imgtool==$IMGTOOL_VERSION"
        touch "$marker.pending"
    fi
    export PATH="$WS/.venv/bin:$PATH"
    local west_v
    west_v="$(west --version | awk '{print $NF}' | sed 's/^v//')"
    [[ "$west_v" == "$WEST_VERSION" ]] || die "west in $WS/.venv is $west_v, pinned $WEST_VERSION"
}

# setup_python_requirements: needs the workspace, since the requirement files live in it.
setup_python_requirements() {
    local marker="$WS/.venv/.rollcall-python-west$WEST_VERSION-reuse$REUSE_VERSION-imgtool$IMGTOOL_VERSION"
    if [[ -f "$marker.pending" ]]; then
        "$WS/.venv/bin/python" -m pip install -q --disable-pip-version-check \
            "west==$WEST_VERSION" "reuse==$REUSE_VERSION" "imgtool==$IMGTOOL_VERSION" \
            -r "$WS/zephyr/scripts/requirements-base.txt" \
            -r "$WS/bootloader/mcuboot/zephyr/requirements.txt"
        mv "$marker.pending" "$marker"
    fi
    # The versions that matter to the fixtures, the full `pip freeze` (the requirement files
    # float), and a re-check of the exact pins even when the venv marker already existed.
    PY_VERSIONS="$(WANT_REUSE="$REUSE_VERSION" WANT_IMGTOOL="$IMGTOOL_VERSION" \
        WANT_WEST="$WEST_VERSION" "$WS/.venv/bin/python" - <<'EOF'
import json
import os
import subprocess
import sys
from importlib.metadata import version, PackageNotFoundError

out = {}
for name in ["west", "reuse", "imgtool", "pyelftools", "PyYAML"]:
    try:
        out[name] = version(name)
    except PackageNotFoundError:
        out[name] = None
for name, want in [("west", "WANT_WEST"), ("reuse", "WANT_REUSE"), ("imgtool", "WANT_IMGTOOL")]:
    if out[name] != os.environ[want]:
        sys.exit("%s in the venv is %s, pinned %s" % (name, out[name], os.environ[want]))
freeze = subprocess.run(
    [sys.executable, "-m", "pip", "freeze", "--disable-pip-version-check"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()
out["freeze"] = sorted((l.strip() for l in freeze if l.strip()), key=str.lower)
print(json.dumps(out, sort_keys=True))
EOF
)" || die "Python venv in $WS/.venv does not match the pins; delete it and rerun"
}

# setup_workspace: shallow clone of the pinned tag, `west init -l`, the project filter, a
# narrow shallow `west update`; then every project is checked against its manifest revision.
setup_workspace() {
    local marker="$WS/.rollcall-workspace-$ZEPHYR_COMMIT"
    mkdir -p "$WS"
    if [[ ! -f "$marker" ]]; then
        [[ "$SKIP_SETUP" -eq 0 ]] || die "workspace not set up in $WS and --skip-setup given"
        if [[ ! -d "$WS/zephyr/.git" ]]; then
            log "cloning Zephyr $ZEPHYR_TAG into $WS/zephyr"
            git -c advice.detachedHead=false clone -q --depth 1 --branch "$ZEPHYR_TAG" \
                "$ZEPHYR_URL" "$WS/zephyr"
        fi
    fi
    local head
    head="$(git -C "$WS/zephyr" rev-parse 'HEAD^{commit}')"
    [[ "$head" == "$ZEPHYR_COMMIT" ]] ||
        die "$WS/zephyr is at $head, expected $ZEPHYR_TAG = $ZEPHYR_COMMIT"
    if [[ ! -f "$marker" ]]; then
        [[ -d "$WS/.west" ]] || (cd "$WS" && west init -l zephyr)
        (cd "$WS" && west config manifest.project-filter -- "$PROJECT_FILTER")
        log "west update ${WEST_UPDATE_ARGS[*]}"
        (cd "$WS" && west update "${WEST_UPDATE_ARGS[@]}")
        touch "$marker"
    fi
    local filter
    filter="$(cd "$WS" && west config manifest.project-filter)"
    [[ "$filter" == "$PROJECT_FILTER" ]] ||
        die "manifest.project-filter is '$filter', expected '$PROJECT_FILTER'"
    local name path rev actual
    local repos=("zephyr")
    while read -r name path rev; do
        [[ "$name" != manifest ]] || continue
        actual="$(git -C "$WS/$path" rev-parse 'HEAD^{commit}' 2>/dev/null)" ||
            die "project $name ($path) is not checked out; rerun without --skip-setup"
        [[ "$actual" == "$rev" ]] || die "project $name is at $actual, manifest says $rev"
        repos+=("$path")
    done < <(cd "$WS" && west list -f '{name} {path} {revision}')
    # Vanilla means unmodified, not just the right HEAD. The build directories, the venv and
    # west's own files all live in the workspace topdir, outside every project repository, so
    # they never show up here.
    local changes
    for path in "${repos[@]}"; do
        changes="$(git -C "$WS/$path" status --porcelain)" ||
            die "git status failed in $WS/$path"
        if [[ -n "$changes" ]]; then
            printf '%s\n' "$changes" | head -20 | sed 's/^/  /' >&2
            die "$WS/$path has local modifications (above); restore it or delete the workspace"
        fi
    done
    export ZEPHYR_BASE="$WS/zephyr"
    # GCC takes __DATE__ and __TIME__ (used by e.g. lib/posix/options/uname.c) from this, so
    # builds are reproducible; the pinned commit's own timestamp keeps it meaningful.
    SOURCE_DATE_EPOCH="$(git -C "$WS/zephyr" log -1 --format=%ct "$ZEPHYR_COMMIT")"
    export SOURCE_DATE_EPOCH
}

# --- Build and collect ----------------------------------------------------------------------
# build_variant <v> <log>: fresh sysbuild build into $WS/build/<v>, SPDX for both images.
# All output goes to <log>; its tail is printed if anything fails.
build_variant() {
    local v="$1" logfile="$2" app img line
    app="$(variant_app "$v")"
    local argv=()
    while IFS= read -r line; do argv+=("$line"); done < <(variant_build_argv "$v")
    # The subshell runs as a background job and is waited for: a subshell used directly as an
    # `if`/`||` condition would run with `set -e` silently disabled inside it.
    local rc=0
    (
        cd "$WS"
        rm -rf "build/$v"
        # The CMake file-API query must exist in each image's build dir before CMake first
        # runs there; sysbuild then configures the images into these same directories.
        west spdx --init -d "build/$v/$app"
        west spdx --init -d "build/$v/mcuboot"
        "${argv[@]}"
        for img in "$app" mcuboot; do
            # reuse returns copyright notices as a set; a fixed hash seed fixes their order.
            PYTHONHASHSEED=0 west spdx -d "build/$v/$img" --spdx-version 2.3 \
                -n "http://spdx.org/spdxdocs/rollcall-$v-$img"
        done
        west list -f '{name} {path} {revision} {url}' >"build/$v/west-list.txt"
    ) >"$logfile" 2>&1 &
    wait $! || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        tail -n 60 "$logfile" >&2
        die "building $v failed (exit $rc); full log: $logfile"
    fi
}

# copy_file <src> <dest>
copy_file() {
    [[ -f "$1" ]] || die "expected build output missing: $1"
    mkdir -p "$(dirname "$2")"
    cp "$1" "$2"
}

# collect_image <build_img_dir> <dest_img_dir> <rel_prefix> <is_app>
collect_image() {
    local src="$1" dest="$2" rel="$3" is_app="$4" f
    copy_file "$src/build_info.yml" "$dest/build_info.yml"
    for f in .config zephyr.map zephyr.meta; do
        copy_file "$src/zephyr/$f" "$dest/zephyr/$f"
    done
    [[ -f "$src/zephyr/zephyr.elf" ]] || die "expected build output missing: $src/zephyr/zephyr.elf"
    mkdir -p "$dest/zephyr"
    "$STRIP" --strip-debug -o "$dest/zephyr/zephyr.elf" "$src/zephyr/zephyr.elf"
    printf '%s\t%s\t%s\n' "$rel/zephyr/zephyr.elf" strip-debug \
        "$(sha256_of "$src/zephyr/zephyr.elf")" >>"$TRANSFORMS"
    if [[ "$is_app" -eq 1 ]]; then
        copy_file "$src/zephyr/zephyr.signed.hex" "$dest/zephyr/zephyr.signed.hex"
    else
        copy_file "$src/zephyr/zephyr.hex" "$dest/zephyr/zephyr.hex"
    fi
    for f in app zephyr build modules-deps; do
        copy_file "$src/spdx/$f.spdx" "$dest/spdx/$f.spdx"
    done
}

# collect_variant <v> <stage>: copies the fixture file set of one build into <stage>/<v>.
collect_variant() {
    local v="$1" stage="$2" app b
    app="$(variant_app "$v")"
    b="$WS/build/$v"
    rm -rf "${stage:?}/$v"
    copy_file "$b/west-list.txt" "$stage/$v/west-list.txt"
    copy_file "$b/build_info.yml" "$stage/$v/build_info.yml"
    copy_file "$b/domains.yaml" "$stage/$v/domains.yaml"
    # The sysbuild Kconfig output (SB_CONFIG_*).
    copy_file "$b/zephyr/.config" "$stage/$v/zephyr/.config"
    collect_image "$b/$app" "$stage/$v/$app" "$v/$app" 1
    collect_image "$b/mcuboot" "$stage/$v/mcuboot" "$v/mcuboot" 0
}

# sed_escape <string>: escapes a literal for use as a sed BRE pattern with `|` delimiters.
sed_escape() {
    printf '%s' "$1" | sed -e 's/[]\/$*.^|[]/\\&/g'
}

# ere_escape <string>: escapes a literal for use in a grep -E pattern.
ere_escape() {
    printf '%s' "$1" | sed -e 's/[]\/$*.^|[+?(){}]/\\&/g'
}

# normalise_text <dir>: rewrites host paths in every text fixture under <dir> to the
# placeholders, then fails if any host path is left.
normalise_text() {
    local dir="$1" f p
    # Longest first, so a path is never replaced by a shorter prefix of itself.
    local pairs=()
    for p in "$WS_REAL" "$WS_LOGICAL" "/private$WS_LOGICAL"; do pairs+=("$p|$WS_PLACEHOLDER"); done
    for p in "$SDK_REAL" "$SDK_LOGICAL" "/private$SDK_LOGICAL"; do pairs+=("$p|$SDK_PLACEHOLDER"); done
    local script="" from to froms=()
    while IFS='|' read -r from to; do
        script+="s|$(sed_escape "$from")|$to|g;"
        froms+=("$from")
    done < <(printf '%s\n' "${pairs[@]}" | awk -F'|' '{print length($1) "\t" $0}' |
        sort -t$'\t' -k1,1nr -k2 | cut -f2- | awk '!seen[$0]++')
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(text_files "$dir")
    [[ ${#files[@]} -gt 0 ]] || die "no text fixtures found under $dir"
    # A host path must end at a path boundary: `<ws>2/...` or `<ws>.old` would otherwise become
    # `/zephyrproject2/...`. Checked before replacing, because the placeholder itself is
    # legitimately followed by `-` in URLs such as github.com/zephyrproject-rtos.
    for from in "${froms[@]}"; do
        if grep -lE -- "$(ere_escape "$from")[A-Za-z0-9_.-]" "${files[@]}" >/dev/null; then
            grep -lE -- "$(ere_escape "$from")[A-Za-z0-9_.-]" "${files[@]}" | sed 's/^/  /' >&2
            die "'$from' is followed by more path characters in the files above; not normalising"
        fi
    done
    for f in "${files[@]}"; do
        sed -e "$script" "$f" >"$f.tmp"
        if ! cmp -s "$f" "$f.tmp"; then
            printf '%s\t%s\t\n' "${f#"$dir"/}" normalise-paths >>"$TRANSFORMS"
        fi
        mv "$f.tmp" "$f"
    done
    local needles=("$WS_REAL" "$WS_LOGICAL" "$SDK_REAL" "$SDK_LOGICAL")
    [[ -z "${HOME:-}" || "$HOME" == / ]] || needles+=("$HOME")
    for p in "${needles[@]}"; do
        if grep -rlF -- "$p" "${files[@]}" >/dev/null; then
            grep -rlF -- "$p" "${files[@]}" | sed 's/^/  /' >&2
            die "host path '$p' is still present in the files above after normalisation"
        fi
    done
}

# text_files <dir>: the text artefacts, sorted.
text_files() {
    find "$1" -type f \( -name .config -o -name build_info.yml -o -name domains.yaml \
        -o -name zephyr.meta -o -name zephyr.map -o -name '*.spdx' -o -name west-list.txt \) |
        LC_ALL=C sort
}

# write_manifest <stage>: MANIFEST.json describing the pins and every file in <stage>.
write_manifest() {
    local stage="$1" v
    local variants_present=()
    for v in "${VARIANTS[@]}"; do
        [[ -d "$stage/$v" ]] && variants_present+=("$v")
    done
    local vfile="$META/variants.tsv"
    : >"$vfile"
    for v in "${variants_present[@]}"; do
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$v" "$(variant_sample "$v")" "$(variant_app "$v")" \
            "$(variant_extra_conf "$v")" "$(variant_extra_dtc "$v")" \
            "$(variant_build_argv "$v" | paste -sd $'\x1f' -)" "$(variant_fallback "$v")" >>"$vfile"
    done
    STAGE="$stage" VFILE="$vfile" TRANSFORMS="$TRANSFORMS" PY_VERSIONS="$PY_VERSIONS" \
        CARRIED="$CARRIED" OLD_MANIFEST="$OUT_ABS/MANIFEST.json" \
        ZEPHYR_URL="$ZEPHYR_URL" ZEPHYR_TAG="$ZEPHYR_TAG" ZEPHYR_COMMIT="$ZEPHYR_COMMIT" \
        SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        SDK_VERSION="$SDK_VERSION" HOST="$HOST" SDK_MINIMAL_FILE="$SDK_MINIMAL_FILE" \
        SDK_MINIMAL_SHA256="$SDK_MINIMAL_SHA256" SDK_ARM_FILE="$SDK_ARM_FILE" \
        SDK_ARM_SHA256="$SDK_ARM_SHA256" GCC_VERSION="$GCC_VERSION" \
        WEST_VERSION="$WEST_VERSION" PROJECT_FILTER="$PROJECT_FILTER" \
        WEST_UPDATE_ARGS="$(printf '%s\n' "${WEST_UPDATE_ARGS[@]}")" BOARD="$BOARD" \
        WS_PLACEHOLDER="$WS_PLACEHOLDER" SDK_PLACEHOLDER="$SDK_PLACEHOLDER" \
        python3 - <<'EOF'
import hashlib
import json
import os

env = os.environ
stage = env["STAGE"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


transforms = {}
with open(env["TRANSFORMS"], encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        path, kind, source = (line.split("\t") + ["", ""])[:3]
        entry = transforms.setdefault(path, {"transform": [], "source_sha256": ""})
        if kind not in entry["transform"]:
            entry["transform"].append(kind)
        if source:
            entry["source_sha256"] = source

files = []
for root, dirs, names in os.walk(stage):
    for name in names:
        full = os.path.join(root, name)
        rel = os.path.relpath(full, stage).replace(os.sep, "/")
        if rel == "MANIFEST.json":
            continue
        entry = {"path": rel, "bytes": os.path.getsize(full), "sha256": sha256(full)}
        t = transforms.get(rel)
        if t:
            entry["transform"] = "+".join(t["transform"])
            if t["source_sha256"]:
                entry["source_sha256"] = t["source_sha256"]
        files.append(entry)
files.sort(key=lambda e: e["path"])

variants = {}
first_variant = None
with open(env["VFILE"], encoding="utf-8") as f:
    for line in f:
        v, sample, app, extra, dtc, argv, fallback = line.rstrip("\n").split("\t")
        first_variant = first_variant or v
        variants[v] = {
            "sample": sample,
            "extra_conf_files": [x for x in extra.split(";") if x],
            "extra_dtc_overlay_files": [x for x in dtc.split(";") if x],
            "images": {"app": app, "mcuboot": "mcuboot"},
            "build_command": argv.split("\x1f"),
            "spdx_namespace_prefix": "http://spdx.org/spdxdocs/rollcall-%s" % v,
        }
        if fallback:
            variants[v]["fallback"] = fallback

# Provenance per variant: what this run used, or, for a variant carried over from the existing
# output by --variant, what that output recorded (its own built_with, else its top level).
host_os, _, host_arch = env["HOST"].partition("-")
python = json.loads(env["PY_VERSIONS"])
this_run = {
    "host": {"os": host_os, "arch": host_arch},
    "sdk": {"gcc_version": env["GCC_VERSION"]},
    "python": python,
}
carried = env["CARRIED"].split()
old = {}
if carried:
    with open(env["OLD_MANIFEST"], encoding="utf-8") as f:
        old = json.load(f)
for v in variants:
    if v not in carried:
        variants[v]["built_with"] = this_run
        continue
    prev = old.get("variants", {}).get(v, {}).get("built_with")
    if prev is None:
        prev = {
            "host": old.get("host"),
            "sdk": {"gcc_version": old.get("sdk", {}).get("gcc_version")},
            "python": old.get("python"),
        }
    variants[v]["built_with"] = prev

modules = []
if first_variant:
    with open(os.path.join(stage, first_variant, "west-list.txt"), encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) != 4 or parts[0] == "manifest":
                continue
            name, path, revision, url = parts
            modules.append({"name": name, "path": path, "revision": revision, "url": url})
modules.sort(key=lambda m: m["name"])

manifest = {
    "format": "rollcall-fixtures/1",
    "generator": "scripts/regen-fixtures.sh",
    "zephyr": {
        "url": env["ZEPHYR_URL"],
        "tag": env["ZEPHYR_TAG"],
        "commit": env["ZEPHYR_COMMIT"],
        "source_date_epoch": int(env["SOURCE_DATE_EPOCH"]),
    },
    "sdk": {
        "version": env["SDK_VERSION"],
        "host": env["HOST"],
        "bundles": {
            "minimal": {"file": env["SDK_MINIMAL_FILE"], "sha256": env["SDK_MINIMAL_SHA256"]},
            "arm-zephyr-eabi": {"file": env["SDK_ARM_FILE"], "sha256": env["SDK_ARM_SHA256"]},
        },
        "gcc_version": env["GCC_VERSION"],
    },
    "west": {
        "version": env["WEST_VERSION"],
        "project_filter": env["PROJECT_FILTER"],
        "update_args": [a for a in env["WEST_UPDATE_ARGS"].split("\n") if a],
    },
    "python": python,
    "host": {"os": host_os, "arch": host_arch},
    "board": env["BOARD"],
    "path_placeholders": {
        env["WS_PLACEHOLDER"]: "west workspace topdir",
        env["SDK_PLACEHOLDER"]: "Zephyr SDK install directory",
    },
    "modules": modules,
    "variants": variants,
    "files": files,
    "total_bytes": sum(e["bytes"] for e in files),
}
with open(os.path.join(stage, "MANIFEST.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(manifest, f, sort_keys=True, indent=2)
    f.write("\n")
EOF
}

# --- Compare --------------------------------------------------------------------------------
# Each helper is one Python process that reads both files and exits 0 only when they are equal
# under its rule; any error (unreadable, malformed, unexpected layout) exits 1.

# signed_hex_equal <a> <b>: two MCUboot-signed Intel HEX images are equal except for the bytes
# of the RSA-PSS signature, whose salt is random. Unmasked and required identical: every
# record's type, address and byte count, every non-data record's payload, every line
# terminator, and every data byte outside the signature. Each image must carry exactly one
# signature TLV, of type 0x20 (IMAGE_TLV_RSA2048_PSS), at the same offset with the same length.
signed_hex_equal() {
    python3 - "$1" "$2" <<'EOF'
import struct
import sys

SIG_TLV = 0x20  # IMAGE_TLV_RSA2048_PSS, the only signature type in these images


def load(path):
    with open(path, "rb") as f:
        lines = f.read().splitlines(keepends=True)
    if not lines:
        raise ValueError("%s: empty" % path)
    shape, mem, base = [], {}, 0
    for n, line in enumerate(lines, 1):
        body = line.rstrip(b"\r\n")
        term = line[len(body):]
        if not body.startswith(b":"):
            raise ValueError("%s:%d: not an Intel HEX record" % (path, n))
        raw = bytes.fromhex(body[1:].decode("ascii"))
        if len(raw) < 5 or len(raw) != raw[0] + 5 or sum(raw) & 0xFF:
            raise ValueError("%s:%d: bad record" % (path, n))
        count, addr, kind = raw[0], (raw[1] << 8) | raw[2], raw[3]
        data = raw[4 : 4 + count]
        shape.append((term, kind, addr, count, b"" if kind == 0 else data))
        if kind == 0:
            for i, b in enumerate(data):
                mem[base + addr + i] = b
        elif kind == 2:
            base = int.from_bytes(data, "big") << 4
        elif kind == 4:
            base = int.from_bytes(data, "big") << 16
        elif kind not in (1, 3, 5):
            raise ValueError("%s:%d: unknown record type %d" % (path, n, kind))
    if not mem:
        raise ValueError("%s: no data" % path)
    lo, hi = min(mem), max(mem)
    if hi - lo >= 1 << 24:
        raise ValueError("%s: data spans more than 16 MiB" % path)
    buf = bytearray(b"\xff" * (hi - lo + 1))
    for a, b in mem.items():
        buf[a - lo] = b
    return shape, lo, buf


def mask(path, buf):
    magic, _load, hdr, prot, img = struct.unpack_from("<IIHHI", buf, 0)
    if magic != 0x96F3B83D:
        raise ValueError("%s: no MCUboot image header" % path)
    off = hdr + img + prot
    tlv_magic, tlv_total = struct.unpack_from("<HH", buf, off)
    if tlv_magic != 0x6907:
        raise ValueError("%s: no TLV info at 0x%x" % (path, off))
    end = off + tlv_total
    if end > len(buf):
        raise ValueError("%s: TLV area runs past the end of the image" % path)
    off += 4
    sigs = []
    while off < end:
        kind, length = struct.unpack_from("<HH", buf, off)
        if off + 4 + length > end:
            raise ValueError("%s: TLV at 0x%x runs past the TLV area" % (path, off))
        if kind == SIG_TLV:
            sigs.append((off + 4, length))
            buf[off + 4 : off + 4 + length] = bytes(length)
        off += 4 + length
    if len(sigs) != 1:
        raise ValueError("%s: %d signature TLVs of type 0x20, expected 1" % (path, len(sigs)))
    return sigs[0]


try:
    shape_a, lo_a, a = load(sys.argv[1])
    shape_b, lo_b, b = load(sys.argv[2])
    if shape_a != shape_b or lo_a != lo_b:
        print("signed_hex_equal: record layout or line endings differ", file=sys.stderr)
        sys.exit(1)
    if mask(sys.argv[1], a) != mask(sys.argv[2], b):
        print("signed_hex_equal: signature TLV position differs", file=sys.stderr)
        sys.exit(1)
    sys.exit(0 if a == b else 1)
except Exception as e:  # any failure to read or parse is a difference, never a pass
    print("signed_hex_equal: %s" % e, file=sys.stderr)
    sys.exit(1)
EOF
}

# spdx_equal <a> <b>: two SPDX tag-value documents are equal once, in each, the value of every
# `Created:` line is replaced by `<masked>` (the line itself stays), the 40-hex SHA1 at the end
# of every `ExternalDocumentRef:` line is replaced by `<masked>`, and each consecutive run of
# `Relationship:` lines is sorted (their order follows CMake's file-API codemodel, which varies
# between configures). Both files must be UTF-8 and start with `SPDXVersion: SPDX-`.
spdx_equal() {
    python3 - "$1" "$2" <<'EOF'
import re
import sys

CREATED = re.compile(r"^Created: .*$")
EXTREF = re.compile(r"^(ExternalDocumentRef: DocumentRef-\S+ \S+ SHA1: )[0-9a-f]{40}$")


def canonical(path):
    with open(path, "rb") as f:
        text = f.read().decode("utf-8")
    lines = text.splitlines(keepends=True)
    if not lines or not lines[0].startswith("SPDXVersion: SPDX-"):
        raise ValueError("%s: not an SPDX tag-value document" % path)
    out, run = [], []
    for line in lines:
        body = line.rstrip("\r\n")
        term = line[len(body):]
        if body.startswith("Created:"):
            body = CREATED.sub("Created: <masked>", body)
        elif body.startswith("ExternalDocumentRef:"):
            body = EXTREF.sub(r"\1<masked>", body)
        line = body + term
        if body.startswith("Relationship:"):
            run.append(line)
            continue
        out.extend(sorted(run))
        run = []
        out.append(line)
    out.extend(sorted(run))
    return out


try:
    sys.exit(0 if canonical(sys.argv[1]) == canonical(sys.argv[2]) else 1)
except Exception as e:  # any failure to read or parse is a difference, never a pass
    print("spdx_equal: %s" % e, file=sys.stderr)
    sys.exit(1)
EOF
}

# manifest_equal <a> <b>: equal apart from the sha256 of *.spdx and *.signed.hex entries.
manifest_equal() {
    python3 - "$1" "$2" <<'EOF'
import json
import sys


def load(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or not isinstance(doc.get("files"), list):
        raise ValueError("%s: not a fixtures manifest" % path)
    for entry in doc["files"]:
        if not isinstance(entry, dict):
            raise ValueError("%s: file entry is not an object" % path)
        p = str(entry.get("path", ""))
        if p.endswith(".spdx") or p.endswith(".signed.hex"):
            entry.pop("sha256", None)
    return doc


try:
    a, b = load(sys.argv[1]), load(sys.argv[2])
    if a != b:
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                print("manifest_equal: '%s' differs" % key, file=sys.stderr)
        sys.exit(1)
except Exception as e:  # any failure to read or parse is a difference, never a pass
    print("manifest_equal: %s" % e, file=sys.stderr)
    sys.exit(1)
EOF
}

# compare_trees <a> <b>: prints a PASS/FAIL table; returns 1 on any difference.
compare_trees() {
    local a="$1" b="$2" failed=0 f rule result
    [[ -d "$a" ]] || die "compare: not a directory: $a"
    [[ -d "$b" ]] || die "compare: not a directory: $b"
    local list_a list_b
    list_a="$(cd "$a" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)"
    list_b="$(cd "$b" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)"
    printf '%-6s  %-14s  %s\n' RESULT RULE PATH
    printf '%-6s  %-14s  %s\n' ------ -------------- ----
    if [[ "$list_a" == "$list_b" ]]; then
        printf '%-6s  %-14s  %s\n' PASS file-set "($(wc -l <<<"$list_a" | tr -d ' ') files)"
    else
        failed=1
        printf '%-6s  %-14s  %s\n' FAIL file-set "differs:"
        diff <(echo "$list_a") <(echo "$list_b") | grep '^[<>]' | sed 's/^/        /' || true
    fi
    while IFS= read -r f; do
        [[ -n "$f" && -f "$b/$f" ]] || continue
        case "$f" in
            MANIFEST.json) rule=manifest ;;
            *.spdx) rule=spdx-masked ;;
            *.signed.hex) rule=sig-masked ;;
            *) rule="cmp" ;;
        esac
        result=PASS
        case "$rule" in
            manifest) manifest_equal "$a/$f" "$b/$f" || result=FAIL ;;
            spdx-masked) spdx_equal "$a/$f" "$b/$f" || result=FAIL ;;
            sig-masked) signed_hex_equal "$a/$f" "$b/$f" || result=FAIL ;;
            cmp) cmp -s "$a/$f" "$b/$f" || result=FAIL ;;
        esac
        [[ "$result" == PASS ]] || failed=1
        printf '%-6s  %-14s  %s\n' "$result" "$rule" "$f"
    done <<<"$list_a"
    echo
    if [[ "$failed" -ne 0 ]]; then
        echo "compare: FAIL"
        return 1
    fi
    echo "compare: PASS"
}

# --- Main -----------------------------------------------------------------------------------
# Runs under bash 3.2 (macOS /bin/bash) as well as bash 4+: with `set -u`, bash 3.2 treats
# "${arr[@]}" of an empty array as unbound, so every array expanded here is non-empty by
# construction (or checked, as in normalise_text) before it is used.
if [[ "${1:-}" == compare ]]; then
    [[ $# -eq 3 ]] || die "usage: $0 compare DIR_A DIR_B"
    command -v python3 >/dev/null 2>&1 || die "compare needs python3"
    compare_trees "$2" "$3"
    exit $?
fi

# The Cargo fixtures (SHA-127) and the ESP-IDF fixtures (SHA-129) have their own scripts and
# pins.
for arg in "$@"; do
    case "$arg" in
        cargo-*) exec "$REPO_ROOT/scripts/regen-fixtures-cargo.sh" "$@" ;;
        esp-idf | esp-idf-*) exec "$REPO_ROOT/scripts/regen-fixtures-esp-idf.sh" "$@" ;;
    esac
done

SELECTED=()
CHECK_STABLE=0
SKIP_SETUP=0
KEEP_BUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant)
            [[ $# -ge 2 ]] || die "--variant needs a value"
            variant_sample "$2" >/dev/null || die "unknown variant '$2' (known: ${ALL_VARIANTS[*]})"
            SELECTED+=("$2")
            shift 2
            ;;
        --check-stable) CHECK_STABLE=1 && shift ;;
        --skip-setup) SKIP_SETUP=1 && shift ;;
        --keep-build) KEEP_BUILD=1 && shift ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done
# old-mbedtls and smp are pin sets with their own output trees, so they are never mixed with
# the others.
select_pins main
if [[ ${#SELECTED[@]} -gt 0 && " ${SELECTED[*]} " == *" old-mbedtls "* ]]; then
    for v in "${SELECTED[@]}"; do
        [[ "$v" == old-mbedtls ]] ||
            die "--variant old-mbedtls has its own pins and output; build it on its own"
    done
    select_pins old-mbedtls
elif [[ ${#SELECTED[@]} -gt 0 && " ${SELECTED[*]} " =~ \ smp-(serial|bt)\  ]]; then
    for v in "${SELECTED[@]}"; do
        [[ "$v" == smp-serial || "$v" == smp-bt ]] ||
            die "--variant $v: smp-serial and smp-bt have their own pins and output; build them on their own"
    done
    select_pins smp
fi
[[ ${#SELECTED[@]} -gt 0 ]] || SELECTED=("${VARIANTS[@]}")

check_prereqs
HOST="$(host_platform)"
SDK_MINIMAL_FILE="zephyr-sdk-${SDK_VERSION}_${HOST}_minimal.tar.xz"
SDK_MINIMAL_SHA256="$(sdk_minimal_sha256 "$HOST")" || die "no pinned SDK $SDK_VERSION for $HOST"
SDK_ARM_FILE="${SDK_ARM_PREFIX}${HOST}_arm-zephyr-eabi.tar.xz"
SDK_ARM_SHA256="$(sdk_arm_sha256 "$HOST")" || die "no pinned SDK $SDK_VERSION toolchain for $HOST"

CACHE="$REPO_ROOT/.cache"
mkdir -p "$CACHE"
WS="${ROLLCALL_ZEPHYR_WORKSPACE:-$DEFAULT_WS}"
SDK="${ROLLCALL_ZEPHYR_SDK:-$DEFAULT_SDK}"
OUT="${ROLLCALL_FIXTURES_OUT:-$DEFAULT_OUT}"
mkdir -p "$WS" "$SDK" "$(dirname "$OUT")"
# Logical (as given, made absolute) and physical (symlinks resolved, e.g. macOS /private)
# forms of each directory; both are normalised away.
WS_LOGICAL="$(cd "$WS" && pwd -L)"
WS_REAL="$(cd "$WS" && pwd -P)"
SDK_LOGICAL="$(cd "$SDK" && pwd -L)"
SDK_REAL="$(cd "$SDK" && pwd -P)"
WS="$WS_REAL"
SDK="$SDK_REAL"
OUT_ABS="$(cd "$(dirname "$OUT")" && pwd -P)/$(basename "$OUT")"

# Isolate west from any user or system configuration, and Zephyr from extra modules.
export WEST_CONFIG_GLOBAL="$WS/.rollcall-west-global-config"
export WEST_CONFIG_SYSTEM="$WS/.rollcall-west-system-config"
unset ZEPHYR_MODULES EXTRA_ZEPHYR_MODULES ZEPHYR_EXTRA_MODULES BOARD_ROOT SOC_ROOT \
    DTS_ROOT SNIPPET_ROOT ZEPHYR_SDK_INSTALL_DIR ZEPHYR_TOOLCHAIN_VARIANT PYTHONHASHSEED \
    SOURCE_DATE_EPOCH
# Zephyr uses ccache when it is installed; a cache hit would let --check-stable compare an
# object with itself instead of with a fresh compile.
export CCACHE_DISABLE=1

t0=$SECONDS
install_sdk
setup_python
setup_workspace
setup_python_requirements
log "setup done in $((SECONDS - t0))s (Zephyr $ZEPHYR_TAG, SDK $SDK_VERSION $HOST, gcc $GCC_VERSION)"

STAGING="$CACHE/fixtures-staging"
LOGS="$CACHE/fixtures-logs"
rm -rf "$STAGING" "$LOGS"
mkdir -p "$STAGING" "$LOGS"

# run_once <n>: builds every selected variant into $STAGING/run<n>, carries unselected
# variants over from the current output, and writes the manifest.
run_once() {
    local n="$1" v t
    local stage="$STAGING/run$n"
    META="$STAGING/meta$n"
    TRANSFORMS="$META/transforms.tsv"
    mkdir -p "$stage" "$META"
    : >"$TRANSFORMS"
    for v in "${SELECTED[@]}"; do
        t=$SECONDS
        log "run $n: building $v"
        build_variant "$v" "$LOGS/run$n-$v.log"
        collect_variant "$v" "$stage"
        [[ "$KEEP_BUILD" -eq 1 ]] || rm -rf "${WS:?}/build/$v"
        log "run $n: $v done in $((SECONDS - t))s"
    done
    normalise_text "$stage"
    CARRIED=""
    for v in "${VARIANTS[@]}"; do
        [[ ! -d "$stage/$v" ]] || continue
        if [[ -d "$OUT_ABS/$v" ]]; then
            log "run $n: keeping existing $v (its built_with is carried over too)"
            cp -R "$OUT_ABS/$v" "$stage/$v"
            carry_transforms "$v"
            CARRIED+=" $v"
        else
            log "WARNING: variant $v was not selected and $OUT has no $v to carry over;" \
                "the result lacks it and will fail the fixture tests, so it will not be installed"
        fi
    done
    write_manifest "$stage"
}

# carry_transforms <v>: keeps the transform records of a carried-over variant.
carry_transforms() {
    [[ -f "$OUT_ABS/MANIFEST.json" ]] || return 0
    python3 - "$OUT_ABS/MANIFEST.json" "$1" >>"$TRANSFORMS" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    doc = json.load(f)
for e in doc.get("files", []):
    if e.get("path", "").startswith(sys.argv[2] + "/") and e.get("transform"):
        for kind in e["transform"].split("+"):
            print("%s\t%s\t%s" % (e["path"], kind, e.get("source_sha256", "")))
EOF
}

run_once 1
if [[ "$CHECK_STABLE" -eq 1 ]]; then
    run_once 2
    log "comparing run 1 with run 2"
    if ! compare_trees "$STAGING/run1" "$STAGING/run2" | tee "$STAGING/compare-stable.txt"; then
        die "the two runs differ (see $STAGING/compare-stable.txt); output left unchanged"
    fi
fi

# The fixture tests run against the staged tree, so a tree that fails them is never installed.
log "running cargo test -p rollcall-core --test fixtures on the staged tree"
if ! ROLLCALL_FIXTURES_DIR="$STAGING/run1" cargo test -q -p rollcall-core --test fixtures --locked; then
    die "the staged fixtures fail the fixture tests; $OUT left unchanged (staged tree: $STAGING/run1)"
fi

# Replace the output: the old tree is kept aside until the new one is in place, and put back
# if anything fails in between.
restore_old_output() {
    if [[ ! -e "$OUT_ABS" && -e "$OUT_ABS.old" ]]; then
        mv "$OUT_ABS.old" "$OUT_ABS"
        echo "regen-fixtures: restored the previous $OUT" >&2
    fi
}
rm -rf "$OUT_ABS.old"
trap restore_old_output EXIT
[[ ! -e "$OUT_ABS" ]] || mv "$OUT_ABS" "$OUT_ABS.old"
mv "$STAGING/run1" "$OUT_ABS"
trap - EXIT
rm -rf "$OUT_ABS.old"
[[ "$CHECK_STABLE" -eq 1 ]] || rm -rf "$STAGING"
log "fixtures written to $OUT (total $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total_bytes"])' "$OUT_ABS/MANIFEST.json") bytes) in $((SECONDS - t0))s"
git status --short -- "$OUT"
