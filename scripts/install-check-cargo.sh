#!/usr/bin/env bash
# Install check: `cargo install rollcall` of a release gives a working `rollcall --version`.
#
# Usage: scripts/install-check-cargo.sh TAG
#
# Runs `cargo install rollcall --version =<version> --locked` into a fresh root (retrying while
# the new version propagates through the crates.io index), then checks that the installed
# binary's `--version` starts with `rollcall <version>` and that `--help` exits 0.
#
# Environment:
#   ROLLCALL_INSTALL_ROOT       the install root (default: a new temporary directory)
#   ROLLCALL_INSTALL_ATTEMPTS   cargo install attempts (default 10)
#   ROLLCALL_RETRY_DELAY        seconds between attempts (default 30)
#
# Exit codes: 0 pass; 1 the install or the check failed; 64 usage error.
set -euo pipefail

die() {
    local code="$1"
    shift
    echo "::error::install-check-cargo: $*" >&2
    exit "$code"
}

[[ $# -eq 1 ]] || die 64 "usage: install-check-cargo.sh TAG"
tag="$1"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
    die 64 "TAG must be a release tag such as v0.1.0, not '$tag'"
version="${tag#v}"
root="${ROLLCALL_INSTALL_ROOT:-$(mktemp -d)}"
attempts="${ROLLCALL_INSTALL_ATTEMPTS:-10}"
delay="${ROLLCALL_RETRY_DELAY:-30}"

attempt=1
until cargo install rollcall --version "=$version" --locked --root "$root"; do
    [[ "$attempt" -lt "$attempts" ]] ||
        die 1 "cargo install rollcall --version =$version failed $attempts times"
    echo "install-check-cargo: attempt $attempt failed; retrying in ${delay}s (index propagation)" >&2
    attempt=$((attempt + 1))
    sleep "$delay"
done

bin="$root/bin/rollcall"
[[ -x "$bin" ]] || die 1 "cargo install put no rollcall binary in $root/bin"
out="$("$bin" --version)" || die 1 "$bin --version failed"
first="$(head -n 1 <<<"$out")"
[[ "$first" == "rollcall $version" ]] ||
    die 1 "$bin --version printed '$first', not 'rollcall $version'"
"$bin" --help >/dev/null || die 1 "$bin --help failed"
echo "$out"
echo "install-check-cargo: PASS cargo install rollcall $version: $first"
