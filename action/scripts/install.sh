#!/usr/bin/env bash
# rollcall-action step 1: install rollcall, the pinned grype (and, with `scanner: auto`, the
# pinned osv-scanner), and the identifier database the inputs ask for.
#
# Inputs (environment):
#   RC_ROLLCALL_VERSION      `source` (default): build rollcall from the action's own checkout
#                            (`cargo build --release --locked -p rollcall-cli`); or a release
#                            tag such as v0.1.0: download rollcall-<tag>-<os>-<arch>.tar.gz and
#                            SHA256SUMS from that GitHub release and verify the tarball
#   RC_IDENTIFIERS_VERSION   `embedded` (default), or a db_version: download
#                            rollcall-identifiers-<v>.tar.gz and SHA256SUMS from the release
#                            identifiers-v<v> and verify it
#   RC_SCANNER               grype (default) or auto (also install osv-scanner)
#   ROLLCALL_BIN             an existing rollcall binary to use instead (tests, self-hosted)
#   ROLLCALL_TOOLS_DIR       where tools go (default $RUNNER_TEMP/rollcall-tools); a pinned
#                            grype or osv-scanner already there is reused
#   RC_RELEASE_REPO          the repository releases come from (default: the action's own,
#                            else smhasan94/rollcall)
#
# Outputs: rollcall-bin (the binary's path), identifiers (`embedded` or a directory).
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

GRYPE_VERSION=0.119.0
OSV_SCANNER_VERSION=2.6.0

# SHA-256 of the grype release tarballs (as scripts/smoke-scan.sh pins them).
grype_sha256() {
    case "$1" in
        linux_amd64) echo 3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b ;;
        linux_arm64) echo 29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8 ;;
        darwin_arm64) echo 500c9b2b6c089d21481815f57a553fabbd441ec7d1e79d95e3aaf40c3bfc7e36 ;;
        darwin_amd64) echo ea106d3ab9573d654871ad9e3e89be2237506ff3f8c170e5aeacb59da4def2b8 ;;
        *) return 1 ;;
    esac
}

# SHA-256 of the osv-scanner release binaries (as scripts/smoke-scan.sh pins them).
osv_sha256() {
    case "$1" in
        linux_amd64) echo ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 ;;
        linux_arm64) echo 2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4 ;;
        darwin_arm64) echo 98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4 ;;
        darwin_amd64) echo 60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca ;;
        *) return 1 ;;
    esac
}

TOOLS="${ROLLCALL_TOOLS_DIR:-${RUNNER_TEMP:-/tmp}/rollcall-tools}"
mkdir -p "$TOOLS"
TOOLS="$(cd "$TOOLS" && pwd)"
RELEASE_REPO="${RC_RELEASE_REPO:-${GITHUB_ACTION_REPOSITORY:-smhasan94/rollcall}}"
[[ -n "$RELEASE_REPO" ]] || RELEASE_REPO=smhasan94/rollcall

# download URL DEST: fetches URL to DEST (retried by curl).
download() {
    curl -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"
}

# sums_entry SUMS NAME: the SHA-256 SUMS (sha256sum format) lists for NAME.
sums_entry() {
    awk -v name="$2" '$2 == name || $2 == "*" name {print $1}' "$1" | head -n 1
}

install_rollcall() {
    if [[ -n "${ROLLCALL_BIN:-}" ]]; then
        [[ -x "$ROLLCALL_BIN" ]] || die "ROLLCALL_BIN=$ROLLCALL_BIN is not executable"
        write_output rollcall-bin "$ROLLCALL_BIN"
        return
    fi
    local version="${RC_ROLLCALL_VERSION:-source}" bin
    if [[ "$version" == source ]]; then
        local root
        root="$(cd "$RC_ACTION_DIR/.." && pwd)"
        [[ -f "$root/Cargo.toml" ]] || die "rollcall-version: source needs the rollcall repository around the action (no $root/Cargo.toml)"
        # Install the pinned toolchain explicitly: not every rustup installs it on first use.
        local channel
        channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml" 2>/dev/null | head -n 1)"
        if [[ -n "$channel" ]] && command -v rustup >/dev/null 2>&1; then
            rustup toolchain install "$channel" --profile minimal >&2 ||
                die "cannot install the Rust toolchain $channel"
        fi
        log "building rollcall from source in $root"
        (cd "$root" && cargo build --release --locked -p rollcall-cli) >&2 ||
            die "cargo build of rollcall failed"
        bin="${CARGO_TARGET_DIR:-$root/target}/release/rollcall"
    else
        local plat asset dir
        plat="$(platform)"
        asset="rollcall-${version}-${plat%_*}-${plat#*_}.tar.gz"
        dir="$TOOLS/rollcall-$version"
        mkdir -p "$dir"
        download "https://github.com/$RELEASE_REPO/releases/download/$version/$asset" "$dir/$asset"
        download "https://github.com/$RELEASE_REPO/releases/download/$version/SHA256SUMS" "$dir/SHA256SUMS"
        local want
        want="$(sums_entry "$dir/SHA256SUMS" "$asset")"
        [[ -n "$want" ]] || die "SHA256SUMS of $version does not list $asset"
        sha256_check "$dir/$asset" "$want"
        tar -xzf "$dir/$asset" -C "$dir"
        bin="$(find "$dir" -type f -name rollcall -perm -u+x | head -n 1)"
        [[ -n "$bin" ]] || die "$asset holds no rollcall binary"
    fi
    "$bin" --version >&2 || die "$bin does not run"
    write_output rollcall-bin "$bin"
}

install_identifiers() {
    local version="${RC_IDENTIFIERS_VERSION:-embedded}"
    if [[ "$version" == embedded ]]; then
        write_output identifiers embedded
        return
    fi
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 64 "identifiers-version must be embedded or a db_version such as 1.0.0, not '$version'"
    local tag="identifiers-v$version" asset="rollcall-identifiers-$version.tar.gz"
    local dir="$TOOLS/identifiers"
    mkdir -p "$dir"
    download "https://github.com/$RELEASE_REPO/releases/download/$tag/$asset" "$dir/$asset"
    download "https://github.com/$RELEASE_REPO/releases/download/$tag/SHA256SUMS" "$dir/SHA256SUMS"
    local want
    want="$(sums_entry "$dir/SHA256SUMS" "$asset")"
    [[ -n "$want" ]] || die "SHA256SUMS of $tag does not list $asset"
    sha256_check "$dir/$asset" "$want"
    tar -xzf "$dir/$asset" -C "$dir"
    [[ -f "$dir/$version/identifiers.yaml" ]] || die "$asset has no $version/identifiers.yaml"
    write_output identifiers "$dir/$version"
}

# has_version BIN VERSION-COMMAND PREFIX VERSION: whether BIN reports VERSION.
has_version() {
    [[ -x "$1" ]] || return 1
    local text
    text="$(GRYPE_CHECK_FOR_APP_UPDATE=false "$1" "$2" 2>/dev/null)" || return 1
    [[ "$(awk -v p="$3" 'index($0, p) == 1 {print $NF}' <<<"$text" | head -n 1)" == "$4" ]]
}

install_grype() {
    if has_version "$TOOLS/grype" version "Version:" "$GRYPE_VERSION"; then
        log "grype $GRYPE_VERSION already in $TOOLS"
        return
    fi
    local plat want tarball
    plat="$(platform)"
    want="$(grype_sha256 "$plat")" || die "no pinned grype for $plat"
    tarball="grype_${GRYPE_VERSION}_${plat}.tar.gz"
    download "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${tarball}" "$TOOLS/$tarball"
    sha256_check "$TOOLS/$tarball" "$want"
    tar -xzf "$TOOLS/$tarball" -C "$TOOLS" grype
    rm -f "$TOOLS/$tarball"
    chmod +x "$TOOLS/grype"
    log "installed grype $GRYPE_VERSION ($plat, sha256 $want)"
}

install_osv_scanner() {
    if has_version "$TOOLS/osv-scanner" --version "osv-scanner version:" "$OSV_SCANNER_VERSION"; then
        log "osv-scanner $OSV_SCANNER_VERSION already in $TOOLS"
        return
    fi
    local plat want
    plat="$(platform)"
    want="$(osv_sha256 "$plat")" || die "no pinned osv-scanner for $plat"
    download "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${plat}" "$TOOLS/osv-scanner"
    sha256_check "$TOOLS/osv-scanner" "$want"
    chmod +x "$TOOLS/osv-scanner"
    log "installed osv-scanner $OSV_SCANNER_VERSION ($plat, sha256 $want)"
}

main() {
    # The version becomes part of a URL and a path: refuse anything but a plain tag.
    [[ "${RC_ROLLCALL_VERSION:-source}" =~ ^v?[0-9A-Za-z._-]+$ ]] ||
        die 64 "rollcall-version must be source or a release tag such as v0.1.0, not '${RC_ROLLCALL_VERSION}'"
    case "${RC_SCANNER:-grype}" in
        grype | auto) ;;
        *) die 64 "scanner must be grype or auto, not '${RC_SCANNER}'" ;;
    esac
    install_rollcall
    install_identifiers
    install_grype
    if [[ "${RC_SCANNER:-grype}" == auto ]]; then
        install_osv_scanner
    fi
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        echo "$TOOLS" >>"$GITHUB_PATH"
    fi
    write_output tools-dir "$TOOLS"
}

main "$@"
