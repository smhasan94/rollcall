#!/usr/bin/env bash
# Install check: a wrapper whose embedded checksum is wrong refuses the real release binary.
#
# Usage: scripts/install-check-tamper.sh TAG --wheel FILE
#
# FILE is a wheel built after `python/scripts/embed-release.py --sums <TAG's SHA256SUMS>
# --tamper` (every embedded digest has one digit flipped). In a fresh virtual environment with
# an empty cache, `rollcall --version` must:
#
#   - exit 65, with `rollcall: checksum mismatch for rollcall-TAG-<platform>.<ext>: expected
#     <embedded>, got <actual>; the download was discarded` on stderr;
#   - print nothing on stdout (rollcall never ran);
#   - leave no file in the cache (no binary, no download).
#
# Environment:
#   ROLLCALL_PYTHON             the Python to create the venv with (default python3, else python)
#   ROLLCALL_RELEASE_BASE_URL   where the release assets are (default: the GitHub release)
#
# Unix only (macOS, Linux).
#
# Exit codes: 0 the install was refused as it must be; 1 it was not; 64 usage error.
set -euo pipefail

die() {
    local code="$1"
    shift
    echo "::error::install-check-tamper: $*" >&2
    exit "$code"
}

[[ $# -eq 3 && "$2" == --wheel ]] || die 64 "usage: install-check-tamper.sh TAG --wheel FILE"
tag="$1" wheel="$3"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
    die 64 "TAG must be a release tag such as v0.1.0, not '$tag'"
[[ -f "$wheel" ]] || die 64 "no such wheel: $wheel"
py="${ROLLCALL_PYTHON:-}"
if [[ -z "$py" ]]; then
    if command -v python3 >/dev/null 2>&1; then py=python3; else py=python; fi
fi

work="$(mktemp -d)"
"$py" -m venv "$work/venv" || die 1 "$py -m venv failed"
if [[ -d "$work/venv/Scripts" ]]; then bindir="$work/venv/Scripts"; else bindir="$work/venv/bin"; fi
"$bindir/python" -m pip install --disable-pip-version-check --no-cache-dir "$wheel" ||
    die 1 "pip install $wheel failed"

export ROLLCALL_CACHE_DIR="$work/cache"
unset ROLLCALL_BIN
rc=0
"$bindir/rollcall" --version >"$work/stdout" 2>"$work/stderr" || rc=$?
cat "$work/stderr" >&2
[[ "$rc" -eq 65 ]] || die 1 "rollcall --version exited $rc, not 65: the tampered checksum did not abort the install"
grep -Eq "^rollcall: checksum mismatch for rollcall-$tag-[a-z0-9-]+\.(tar\.gz|zip): expected [0-9a-f]{64}, got [0-9a-f]{64}; the download was discarded$" "$work/stderr" ||
    die 1 "stderr does not say 'rollcall: checksum mismatch for rollcall-$tag-…: expected …, got …; the download was discarded'"
[[ ! -s "$work/stdout" ]] || die 1 "rollcall printed on stdout, so a binary ran: $(head -c 200 "$work/stdout")"
left="$(find "$ROLLCALL_CACHE_DIR" -type f 2>/dev/null | head -n 5)"
[[ -z "$left" ]] || die 1 "files were left in the cache: $left"
echo "install-check-tamper: PASS the tampered wheel refused the download (exit 65) and cached nothing"
