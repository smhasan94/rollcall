#!/usr/bin/env bash
# Regenerate the Cargo build fixtures under fixtures/cargo-*/ from real `cargo auditable`
# builds for thumbv7em-none-eabihf (SHA-127). See docs/fixtures.md. The fixtures are never
# edited by hand. `scripts/regen-fixtures.sh --variant cargo-…` runs this script.
#
# NEEDS THE NETWORK on first run: installs the pinned toolchain target and tools, clones the
# keelsign repository and downloads every crate into an isolated CARGO_HOME under .cache/.
#
# Usage:
#   scripts/regen-fixtures-cargo.sh [--variant V]... [--check-stable] [--skip-setup]
#
#   --variant V      build only V; repeatable. Default: all of
#                      cargo-keelsign      keelsign's examples/nrf52840-hello at KEELSIGN_COMMIT
#                      cargo-deps          scripts/fixture-src/cargo-deps (git, path, dev and
#                                          host-only dependencies)
#                      cargo-old-heapless  scripts/fixture-src/cargo-old-heapless (heapless
#                                          =0.5.6, a known advisory)
#                    Each variant is its own tree, fixtures/<variant>/; unselected trees are not
#                    touched.
#   --check-stable   build everything twice and require byte-identical trees; fails without
#                    touching the output if not. The second run uses different project
#                    directories, a different tools directory and a fresh CARGO_HOME (so it
#                    downloads every crate again), so it also proves the output does not depend
#                    on any of those paths.
#   --skip-setup     install and clone nothing; the pins are still asserted.
#
# Each tree holds:
#   firmware.elf            the release ELF, built with debug info off, debuginfo stripped and
#                           build paths remapped (see build_env in MANIFEST.json)
#   dep-v0.json             `rust-audit-info firmware.elf`: the binary's own crate list
#   cargo-metadata.json     `cargo metadata --format-version 1 --filter-platform <target>`
#   cargo-metadata.all.json `cargo metadata --format-version 1` (every platform)
#   cargo-tree.txt          `cargo tree --target <target> -e normal,build --prefix none`
#   MANIFEST.json           pins, commands, and the size and SHA-256 of every file
# Build-machine paths in the text files are replaced with /cargo-fixture/<package> (the
# project directory) and /cargo-home (CARGO_HOME); any other host path left fails the run.
#
# How `cargo auditable` is run: `cargo auditable build` sets RUSTC_WORKSPACE_WRAPPER to its
# own absolute path, and cargo hashes that path into the root crate's `-C metadata`, so the
# ELF would depend on where the tools are installed. The script does what `cargo auditable
# build` does (cargo-auditable 0.7.7, src/cargo_auditable.rs) with the wrapper as the bare
# name `cargo-auditable`, which cargo finds on PATH: RUSTC_WORKSPACE_WRAPPER=cargo-auditable,
# CARGO_AUDITABLE_ORIG_ARGS (the cargo flags it reads back) and `cargo build`. The name on
# PATH is checked to resolve to the pinned binary. The ELF then does not depend on the tools
# path, which --check-stable checks.
#
# The builds run in a temporary directory outside $HOME (mktemp -d), so no `.cargo/config`
# of the user or the repository applies; the run fails if any parent directory of a build
# holds one anyway. CARGO_HOME is isolated too. Paths with spaces are refused.
#
# The staged result must pass `cargo test -p rollcall-core --test fixtures_cargo` (run with
# ROLLCALL_CARGO_FIXTURES_DIR pointing at it) before it replaces the output.
#
# Environment:
#   ROLLCALL_KEELSIGN_REPO  a local keelsign clone to read KEELSIGN_COMMIT from (read only:
#                           `git archive`, never a checkout) [.cache/keelsign, cloned from
#                           KEELSIGN_URL]
#   ROLLCALL_CARGO_TOOLS    where the pinned tools are installed [.cache/tools]; any path
#                           gives the same fixtures
#   ROLLCALL_CARGO_HOME     the isolated CARGO_HOME the builds use [.cache/cargo-fixtures-home]
#
# Logs go to .cache/cargo-fixtures-logs/; with --check-stable the staged trees stay in
# .cache/cargo-fixtures-staging/.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

# --- Pins -----------------------------------------------------------------------------------
RUST_TOOLCHAIN=1.91.1
TARGET=thumbv7em-none-eabihf
# 0.7.7 recognises flip-link as a bare linker (0.7.6 passed `-Wl,-u,…`, which rust-lld
# rejects; SHA-127 spike).
CARGO_AUDITABLE_VERSION=0.7.7
RUST_AUDIT_INFO_VERSION=0.5.4
# keelsign's nrf52840-hello links with flip-link (its .cargo/config.toml).
FLIP_LINK_VERSION=0.1.12
KEELSIGN_URL=https://github.com/smhasan94/keelsign
KEELSIGN_COMMIT=9db3bab149f057a1063d6f12a88453f1986929c5
KEELSIGN_PATH=examples/nrf52840-hello
ALL_VARIANTS=(cargo-keelsign cargo-deps cargo-old-heapless)
SRC_PLACEHOLDER=/cargo-fixture
CARGO_HOME_PLACEHOLDER=/cargo-home
# The cargo flags of the build, as `cargo auditable build` would pass them on to its rustc
# wrapper (CargoArgs in cargo-auditable 0.7.7).
AUDITABLE_ORIG_ARGS='{"offline":true,"locked":true,"frozen":false,"config":[]}'

# variant_package <v>: the root package (and binary) name.
variant_package() {
    case "$1" in
        cargo-keelsign) echo nrf52840-hello ;;
        cargo-deps) echo rollcall-cargo-deps ;;
        cargo-old-heapless) echo rollcall-cargo-old-heapless ;;
        *) return 1 ;;
    esac
}

# variant_source <v>: where the project comes from, as recorded in the manifest.
variant_source() {
    case "$1" in
        cargo-keelsign) echo "$KEELSIGN_URL@$KEELSIGN_COMMIT:$KEELSIGN_PATH" ;;
        cargo-deps) echo scripts/fixture-src/cargo-deps ;;
        cargo-old-heapless) echo scripts/fixture-src/cargo-old-heapless ;;
        *) return 1 ;;
    esac
}

log() { echo "regen-fixtures-cargo: $*" >&2; }
die() {
    echo "regen-fixtures-cargo: error: $*" >&2
    exit 1
}

# no_spaces <what> <path>: refuses a path with whitespace (it would split the rustflags).
no_spaces() {
    [[ "$2" != *[[:space:]]* ]] || die "$1 path '$2' contains whitespace; use one without"
}

SELECTED=()
CHECK_STABLE=0
SKIP_SETUP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant)
            [[ $# -ge 2 ]] || die "--variant needs a value"
            variant_package "$2" >/dev/null || die "unknown variant '$2' (known: ${ALL_VARIANTS[*]})"
            SELECTED+=("$2")
            shift 2
            ;;
        --check-stable) CHECK_STABLE=1 && shift ;;
        --skip-setup) SKIP_SETUP=1 && shift ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ ${#SELECTED[@]} -gt 0 ]] || SELECTED=("${ALL_VARIANTS[@]}")

for tool in rustup cargo git python3 tar mktemp; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

CACHE="$REPO_ROOT/.cache"
TOOLS="${ROLLCALL_CARGO_TOOLS:-$CACHE/tools}"
FIXTURE_CARGO_HOME="${ROLLCALL_CARGO_HOME:-$CACHE/cargo-fixtures-home}"
KEELSIGN_REPO="${ROLLCALL_KEELSIGN_REPO:-$CACHE/keelsign}"
STAGING="$CACHE/cargo-fixtures-staging"
LOGS="$CACHE/cargo-fixtures-logs"
mkdir -p "$CACHE" "$TOOLS" "$FIXTURE_CARGO_HOME"
TOOLS="$(cd "$TOOLS" && pwd -P)"
FIXTURE_CARGO_HOME="$(cd "$FIXTURE_CARGO_HOME" && pwd -P)"
no_spaces tools "$TOOLS"
no_spaces CARGO_HOME "$FIXTURE_CARGO_HOME"

# tool_installed <crate> <version>: whether `cargo install --root $TOOLS` recorded it.
tool_installed() {
    [[ -f "$TOOLS/.crates.toml" ]] && grep -q "^\"$1 $2 (" "$TOOLS/.crates.toml"
}

# --- Setup ----------------------------------------------------------------------------------
if [[ "$SKIP_SETUP" -eq 0 ]]; then
    rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal >&2
    rustup "+$RUST_TOOLCHAIN" target add "$TARGET" >&2
    for pin in "cargo-auditable $CARGO_AUDITABLE_VERSION" "rust-audit-info $RUST_AUDIT_INFO_VERSION" \
        "flip-link $FLIP_LINK_VERSION"; do
        read -r crate version <<<"$pin"
        if ! tool_installed "$crate" "$version"; then
            log "installing $crate $version into $TOOLS"
            cargo "+$RUST_TOOLCHAIN" install --locked --force --version "$version" --root "$TOOLS" "$crate" >&2
        fi
    done
    if [[ ! -d "$KEELSIGN_REPO/.git" && ! -f "$KEELSIGN_REPO/HEAD" ]]; then
        [[ -z "${ROLLCALL_KEELSIGN_REPO:-}" ]] || die "ROLLCALL_KEELSIGN_REPO=$KEELSIGN_REPO is not a git repository"
        log "cloning $KEELSIGN_URL into $KEELSIGN_REPO"
        git clone --quiet --filter=blob:none --no-checkout "$KEELSIGN_URL" "$KEELSIGN_REPO"
    fi
    if ! git -C "$KEELSIGN_REPO" cat-file -e "$KEELSIGN_COMMIT^{commit}" 2>/dev/null; then
        # Only the script's own clone is ever fetched into; a given repository is read only.
        [[ -z "${ROLLCALL_KEELSIGN_REPO:-}" ]] ||
            die "$KEELSIGN_REPO has no commit $KEELSIGN_COMMIT; fetch it there first"
        git -C "$KEELSIGN_REPO" fetch --quiet origin "$KEELSIGN_COMMIT"
    fi
fi

# --- Pins asserted --------------------------------------------------------------------------
RUSTC_VERSION="$(rustc "+$RUST_TOOLCHAIN" --version)" || die "toolchain $RUST_TOOLCHAIN is not installed"
[[ "$RUSTC_VERSION" == "rustc $RUST_TOOLCHAIN "* ]] || die "rustc +$RUST_TOOLCHAIN reports '$RUSTC_VERSION'"
rustup "+$RUST_TOOLCHAIN" target list --installed | grep -qx "$TARGET" ||
    die "target $TARGET is not installed for $RUST_TOOLCHAIN (rustup +$RUST_TOOLCHAIN target add $TARGET)"
for pin in "cargo-auditable $CARGO_AUDITABLE_VERSION" "rust-audit-info $RUST_AUDIT_INFO_VERSION" \
    "flip-link $FLIP_LINK_VERSION"; do
    read -r crate version <<<"$pin"
    tool_installed "$crate" "$version" || die "$crate $version is not installed in $TOOLS (run without --skip-setup)"
    [[ -x "$TOOLS/bin/$crate" ]] || die "$TOOLS/bin/$crate is missing"
done
git -C "$KEELSIGN_REPO" cat-file -e "$KEELSIGN_COMMIT^{commit}" 2>/dev/null ||
    die "$KEELSIGN_REPO has no commit $KEELSIGN_COMMIT"

# Build directories live outside $HOME and the repository, so no `.cargo/config` above them
# applies; they are removed on exit.
BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rollcall-cargo-fixtures.XXXXXX")"
BUILD_ROOT="$(cd "$BUILD_ROOT" && pwd -P)"
trap 'rm -rf "$BUILD_ROOT"' EXIT
no_spaces "build" "$BUILD_ROOT"
case "$BUILD_ROOT/" in
    "${HOME:-/nonexistent-home}/"* | "$REPO_ROOT/"*)
        die "the temporary directory $BUILD_ROOT is under \$HOME or the repository; set TMPDIR elsewhere"
        ;;
esac

# check_no_parent_config <dir>: fails if any directory above <dir> holds a cargo config.
check_no_parent_config() {
    local d
    d="$(dirname "$1")"
    while :; do
        for f in "$d/.cargo/config" "$d/.cargo/config.toml"; do
            [[ ! -e "$f" ]] || die "$f would apply to the fixture build in $1; move it or set TMPDIR"
        done
        [[ "$d" != / ]] || break
        d="$(dirname "$d")"
    done
}

# Every cargo invocation of a build runs with exactly this environment: the pinned toolchain,
# the run's isolated CARGO_HOME (no user config), the run's tools first on PATH, and nothing
# from the caller that changes flags. Global RUSTFLAGS is never used: it would replace the
# project's own target rustflags (keelsign's flip-link linker) and reach host build scripts.
# RUN_TOOLS, RUN_CARGO_HOME and REMAP_FLAGS are set per run and per variant.
ORIGINAL_PATH="$PATH"
fixture_env() {
    env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CARGO_BUILD_TARGET \
        -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET_DIR -u RUSTC_WRAPPER -u CARGO_BUILD_RUSTC_WRAPPER \
        -u RUSTC_WORKSPACE_WRAPPER -u CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER -u CARGO_AUDITABLE_ORIG_ARGS \
        -u RUSTC -u RUSTDOC -u CARGO_TARGET_THUMBV7EM_NONE_EABIHF_LINKER -u SOURCE_DATE_EPOCH \
        -u CARGO_NET_OFFLINE \
        PATH="$RUN_TOOLS/bin:$ORIGINAL_PATH" \
        RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN" \
        CARGO_HOME="$RUN_CARGO_HOME" \
        CARGO_TERM_COLOR=never \
        CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_RELEASE_DEBUG=0 \
        CARGO_PROFILE_RELEASE_STRIP=debuginfo \
        CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS="$REMAP_FLAGS" \
        "$@"
}
fixture_cargo() { fixture_env cargo "$@"; }

# check_run_env: the run's cargo is the pinned toolchain's, and the bare `cargo-auditable`
# cargo will run as the wrapper is the run's pinned binary.
check_run_env() {
    local version wrapper
    version="$(REMAP_FLAGS="" fixture_cargo --version)" || die "cargo --version failed"
    [[ "$version" == "cargo $RUST_TOOLCHAIN "* ]] || die "cargo in the build environment is '$version', not $RUST_TOOLCHAIN"
    wrapper="$(REMAP_FLAGS="" fixture_env sh -c 'command -v cargo-auditable')" ||
        die "cargo-auditable is not on the build PATH"
    [[ "$(cd "$(dirname "$wrapper")" && pwd -P)/$(basename "$wrapper")" == "$RUN_TOOLS/bin/cargo-auditable" ]] ||
        die "cargo-auditable on the build PATH is $wrapper, not $RUN_TOOLS/bin/cargo-auditable"
}

# stage_source <v> <dir>: a fresh copy of the variant's project in <dir> (no target/).
stage_source() {
    local v="$1" dir="$2" tmp
    rm -rf "$dir"
    mkdir -p "$(dirname "$dir")"
    case "$v" in
        cargo-keelsign)
            tmp="$(mktemp -d "$(dirname "$dir")/.keelsign.XXXXXX")"
            git -C "$KEELSIGN_REPO" archive --format=tar "$KEELSIGN_COMMIT" "$KEELSIGN_PATH" | tar -x -C "$tmp"
            mv "$tmp/$KEELSIGN_PATH" "$dir"
            rm -rf "$tmp"
            ;;
        *)
            cp -R "$REPO_ROOT/$(variant_source "$v")" "$dir"
            rm -rf "$dir/target"
            ;;
    esac
}

# normalise <file> <src> <package>: replaces build-machine paths.
normalise() {
    python3 - "$@" "$RUN_CARGO_HOME" "$SRC_PLACEHOLDER" "$CARGO_HOME_PLACEHOLDER" <<'EOF'
import sys

path, src, package, home, src_ph, home_ph = sys.argv[1:7]
with open(path, "rb") as f:
    data = f.read()
pairs = sorted({(src, f"{src_ph}/{package}"), (home, home_ph)}, key=lambda p: -len(p[0]))
for old, new in pairs:
    data = data.replace(old.encode(), new.encode())
with open(path, "wb") as f:
    f.write(data)
EOF
}

# check_no_host_paths <dir>: fails if any file still holds a build-machine path.
check_no_host_paths() {
    python3 - "$1" "$REPO_ROOT" "${HOME:-/nonexistent-home}" "$RUN_CARGO_HOME" "$RUN_TOOLS" "$BUILD_ROOT" <<'EOF'
import os
import sys

root = sys.argv[1]
needles = set(sys.argv[2:]) | {"/Users/", "/home/", "/private/", "/var/folders/", "/tmp/", "C:\\"}
bad = []
for dirpath, _, files in os.walk(root):
    for name in files:
        p = os.path.join(dirpath, name)
        with open(p, "rb") as f:
            data = f.read()
        for n in sorted(needles):
            if n and n.encode() in data:
                bad.append(f"{os.path.relpath(p, root)}: {n}")
if bad:
    print("host paths left:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
EOF
}

# build_variant <v> <run>: builds the variant and collects its tree into $STAGING/run<run>/<v>.
build_variant() {
    local v="$1" run="$2" package src out log
    package="$(variant_package "$v")"
    src="$BUILD_ROOT/build$run/$v/$package"
    out="$STAGING/run$run/$v"
    log="$LOGS/run$run-$v.log"
    stage_source "$v" "$src"
    src="$(cd "$src" && pwd -P)"
    no_spaces project "$src"
    check_no_parent_config "$src"
    REMAP_FLAGS="--remap-path-prefix=$src=$SRC_PLACEHOLDER/$package --remap-path-prefix=$RUN_CARGO_HOME=$CARGO_HOME_PLACEHOLDER"
    mkdir -p "$out"
    (
        cd "$src"
        # Every platform's crates, so the unfiltered metadata below works offline.
        fixture_cargo fetch --locked
        # What `cargo auditable build --release --locked --offline` does, with a bare wrapper
        # name (see the header).
        # fixture_env unsets both variables first; these `env` operands set them after.
        fixture_env RUSTC_WORKSPACE_WRAPPER=cargo-auditable \
            CARGO_AUDITABLE_ORIG_ARGS="$AUDITABLE_ORIG_ARGS" \
            cargo build --release --locked --offline --target "$TARGET"
    ) >"$log" 2>&1 || die "$v: build failed (log: $log)"
    local elf="$src/target/$TARGET/release/$package"
    [[ -f "$elf" ]] || die "$v: no ELF at $elf"
    cp "$elf" "$out/firmware.elf"
    "$RUN_TOOLS/bin/rust-audit-info" "$out/firmware.elf" >"$out/dep-v0.json" ||
        die "$v: rust-audit-info found no .dep-v0 section in the ELF"
    (
        cd "$src"
        fixture_cargo metadata --format-version 1 --locked --offline --filter-platform "$TARGET" \
            >"$out/cargo-metadata.json"
        fixture_cargo metadata --format-version 1 --locked --offline >"$out/cargo-metadata.all.json"
        fixture_cargo tree --locked --offline --target "$TARGET" -e normal,build --prefix none \
            --format '{p}' >"$out/cargo-tree.txt"
    ) 2>>"$log" || die "$v: cargo metadata / cargo tree failed (log: $log)"
    for f in cargo-metadata.json cargo-metadata.all.json cargo-tree.txt; do
        normalise "$out/$f" "$src" "$package"
    done
    check_no_host_paths "$out" || die "$v: build-machine paths left in $out"
    write_manifest "$v" "$out"
    rm -rf "$BUILD_ROOT/build$run/$v"
}

# write_manifest <v> <dir>: MANIFEST.json for one tree.
write_manifest() {
    local v="$1" dir="$2" package
    package="$(variant_package "$v")"
    python3 - "$dir" "$v" "$package" "$(variant_source "$v")" "$AUDITABLE_ORIG_ARGS" <<EOF
import hashlib
import json
import os
import platform
import sys

root, variant, package, source, orig_args = sys.argv[1:6]
normalised = {"cargo-metadata.json", "cargo-metadata.all.json", "cargo-tree.txt"}
files = []
for name in sorted(os.listdir(root)):
    if name == "MANIFEST.json":
        continue
    with open(os.path.join(root, name), "rb") as f:
        data = f.read()
    entry = {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if name in normalised:
        entry["transform"] = "normalise-paths"
    files.append(entry)
manifest = {
    "format": "rollcall-fixtures/1",
    "generator": "scripts/regen-fixtures-cargo.sh",
    "ecosystem": "cargo",
    "variant": variant,
    "package": package,
    "source": source,
    "pins": {
        "rust_toolchain": "$RUST_TOOLCHAIN",
        "rustc": "$RUSTC_VERSION",
        "target": "$TARGET",
        "cargo_auditable": "$CARGO_AUDITABLE_VERSION",
        "rust_audit_info": "$RUST_AUDIT_INFO_VERSION",
        "flip_link": "$FLIP_LINK_VERSION",
    },
    "build_command": ["cargo", "build", "--release", "--locked", "--offline", "--target", "$TARGET"],
    "build_env": {
        "RUSTUP_TOOLCHAIN": "$RUST_TOOLCHAIN",
        "RUSTC_WORKSPACE_WRAPPER": "cargo-auditable",
        "CARGO_AUDITABLE_ORIG_ARGS": orig_args,
        "PATH": "<tools>/bin first: the pinned cargo-auditable, rust-audit-info and flip-link (the tools path does not affect the output)",
        "CARGO_HOME": "an isolated directory, remapped to $CARGO_HOME_PLACEHOLDER",
        "CARGO_PROFILE_RELEASE_DEBUG": "0",
        "CARGO_PROFILE_RELEASE_STRIP": "debuginfo",
        "CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS":
            "--remap-path-prefix=<project dir>=$SRC_PLACEHOLDER/" + package
            + " --remap-path-prefix=<CARGO_HOME>=$CARGO_HOME_PLACEHOLDER",
    },
    "commands": {
        "dep-v0.json": "rust-audit-info firmware.elf",
        "cargo-metadata.json": "cargo metadata --format-version 1 --locked --offline --filter-platform $TARGET",
        "cargo-metadata.all.json": "cargo metadata --format-version 1 --locked --offline",
        "cargo-tree.txt": "cargo tree --locked --offline --target $TARGET -e normal,build --prefix none --format {p}",
    },
    "path_placeholders": {
        "$SRC_PLACEHOLDER/" + package: "the project directory",
        "$CARGO_HOME_PLACEHOLDER": "CARGO_HOME (registry and git checkouts)",
    },
    "host": {"os": platform.system().lower(), "arch": platform.machine().lower()},
    "files": files,
    "total_bytes": sum(e["bytes"] for e in files),
}
if variant == "cargo-keelsign":
    manifest["keelsign"] = {"url": "$KEELSIGN_URL", "commit": "$KEELSIGN_COMMIT", "path": "$KEELSIGN_PATH"}
with open(os.path.join(root, "MANIFEST.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
EOF
}

# --- Main -----------------------------------------------------------------------------------
t0=$SECONDS
rm -rf "$STAGING" "$LOGS"
mkdir -p "$STAGING" "$LOGS"
REMAP_FLAGS=""

RUN_TOOLS="$TOOLS"
RUN_CARGO_HOME="$FIXTURE_CARGO_HOME"
check_run_env
for v in "${SELECTED[@]}"; do
    log "run 1: building $v"
    build_variant "$v" 1
done
if [[ "$CHECK_STABLE" -eq 1 ]]; then
    # Run 2: other project directories, a copy of the tools elsewhere and a fresh CARGO_HOME.
    RUN_TOOLS="$BUILD_ROOT/tools-run2"
    mkdir -p "$RUN_TOOLS/bin"
    cp "$TOOLS/bin/cargo-auditable" "$TOOLS/bin/rust-audit-info" "$TOOLS/bin/flip-link" "$RUN_TOOLS/bin/"
    RUN_TOOLS="$(cd "$RUN_TOOLS" && pwd -P)"
    RUN_CARGO_HOME="$BUILD_ROOT/cargo-home-run2"
    mkdir -p "$RUN_CARGO_HOME"
    RUN_CARGO_HOME="$(cd "$RUN_CARGO_HOME" && pwd -P)"
    check_run_env
    for v in "${SELECTED[@]}"; do
        log "run 2: building $v (tools $RUN_TOOLS, CARGO_HOME $RUN_CARGO_HOME)"
        build_variant "$v" 2
    done
    log "comparing run 1 with run 2"
    if ! diff -r "$STAGING/run1" "$STAGING/run2" >"$STAGING/compare-stable.txt" 2>&1; then
        cat "$STAGING/compare-stable.txt" >&2
        die "the two runs differ (see $STAGING/compare-stable.txt); output left unchanged"
    fi
    log "compare: PASS (byte-identical)"
fi

# The fixture tests run against each staged tree, so a tree that fails them is never installed.
for v in "${SELECTED[@]}"; do
    log "running cargo test -p rollcall-core --test fixtures_cargo on the staged $v"
    if ! ROLLCALL_CARGO_FIXTURES_DIR="$STAGING/run1/$v" cargo test -q -p rollcall-core \
        --test fixtures_cargo --locked >&2; then
        die "the staged $v fails the fixture tests; fixtures/$v left unchanged (staged: $STAGING/run1/$v)"
    fi
done

for v in "${SELECTED[@]}"; do
    out="$REPO_ROOT/fixtures/$v"
    rm -rf "$out.old"
    [[ ! -e "$out" ]] || mv "$out" "$out.old"
    if ! cp -R "$STAGING/run1/$v" "$out"; then
        rm -rf "$out"
        [[ ! -e "$out.old" ]] || mv "$out.old" "$out"
        die "could not install fixtures/$v; the previous tree is restored"
    fi
    rm -rf "$out.old"
    log "fixtures/$v written ($(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total_bytes"])' "$out/MANIFEST.json") bytes)"
done
[[ "$CHECK_STABLE" -eq 1 ]] || rm -rf "$STAGING"
log "done in $((SECONDS - t0))s"
git status --short -- fixtures/cargo-*
