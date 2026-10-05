#!/usr/bin/env bash
# Install check: `pip install rollcall` of a release gives a working `rollcall --version`, and
# the binary it ran is the published one.
#
# Usage: scripts/install-check-pip.sh TAG [--wheel FILE]
#
# In a fresh virtual environment: `pip install rollcall==<PEP 440 version>` from PyPI (FILE
# itself with --wheel, as the release workflow does before publishing), retried while the
# upload propagates. Then, with an empty cache:
#
#   - `rollcall --version` (the wrapper's first run: download, verify, cache) starts with
#     `rollcall <version>`, and `rollcall --help` exits 0;
#   - the installed package is version <PEP 440 version> for TAG;
#   - the SHA-256 embedded in the package for this platform's asset equals the release's
#     SHA256SUMS entry for it, which equals the SHA-256 of the asset downloaded again here;
#   - the cache holds the binary.
#
# Environment:
#   ROLLCALL_PYTHON             the Python to create the venv with (default python3, else python)
#   ROLLCALL_RELEASE_BASE_URL   where the release assets are (default: the GitHub release)
#   ROLLCALL_INSTALL_ATTEMPTS   pip install attempts (default 10)
#   ROLLCALL_RETRY_DELAY        seconds between attempts (default 30)
#
# Unix only (macOS, Linux): Windows is checked by scripts/install-check-windows.ps1.
#
# Exit codes: 0 pass; 1 a check failed; 64 usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() {
    local code="$1"
    shift
    echo "::error::install-check-pip: $*" >&2
    exit "$code"
}

usage() {
    die 64 "usage: install-check-pip.sh TAG [--wheel FILE]"
}

[[ $# -ge 1 ]] || usage
tag="$1"
shift
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
    die 64 "TAG must be a release tag such as v0.1.0, not '$tag'"
wheel=""
case "${1:-}" in
    "") ;;
    --wheel)
        [[ $# -eq 2 ]] || usage
        wheel="$2"
        [[ -f "$wheel" ]] || die 64 "no such wheel: $wheel"
        ;;
    *) usage ;;
esac
version="${tag#v}"
pep440="$("$ROOT/scripts/release-version.sh" pep440 "$version")"
attempts="${ROLLCALL_INSTALL_ATTEMPTS:-10}"
delay="${ROLLCALL_RETRY_DELAY:-30}"
base="${ROLLCALL_RELEASE_BASE_URL:-https://github.com/smhasan94/rollcall/releases/download/$tag}"
py="${ROLLCALL_PYTHON:-}"
if [[ -z "$py" ]]; then
    if command -v python3 >/dev/null 2>&1; then py=python3; else py=python; fi
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

work="$(mktemp -d)"
"$py" -m venv "$work/venv" || die 1 "$py -m venv failed"
if [[ -d "$work/venv/Scripts" ]]; then bindir="$work/venv/Scripts"; else bindir="$work/venv/bin"; fi
vpy="$bindir/python"

spec="rollcall==$pep440"
[[ -z "$wheel" ]] || spec="$wheel"
attempt=1
until "$vpy" -m pip install --disable-pip-version-check --no-cache-dir "$spec"; do
    [[ "$attempt" -lt "$attempts" ]] || die 1 "pip install $spec failed $attempts times"
    echo "install-check-pip: attempt $attempt failed; retrying in ${delay}s (index propagation)" >&2
    attempt=$((attempt + 1))
    sleep "$delay"
done

export ROLLCALL_CACHE_DIR="$work/cache"
unset ROLLCALL_BIN
rollcall="$bindir/rollcall"
out="$("$rollcall" --version)" || die 1 "rollcall --version failed through the pip wrapper"
first="$(head -n 1 <<<"$out")"
[[ "$first" == "rollcall $version" ]] ||
    die 1 "rollcall --version printed '$first', not 'rollcall $version'"
"$rollcall" --help >/dev/null || die 1 "rollcall --help failed through the pip wrapper"

info="$("$vpy" -c 'import rollcall
from rollcall import _cli
r = _cli.load_release()
k = _cli.platform_key()
print(rollcall.__version__, r["tag"], k, r["assets"][k]["name"], r["assets"][k]["sha256"])')" ||
    die 1 "cannot read the installed package's release.json"
read -r pkg_version pkg_tag key asset embedded <<<"$info"
[[ "$pkg_version" == "$pep440" ]] || die 1 "the installed package is version $pkg_version, not $pep440"
[[ "$pkg_tag" == "$tag" ]] || die 1 "the installed package is for $pkg_tag, not $tag"

curl -fsSL --retry 3 -o "$work/SHA256SUMS" "$base/SHA256SUMS" || die 1 "cannot download $base/SHA256SUMS"
curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset" || die 1 "cannot download $base/$asset"
published="$(awk -v name="$asset" '$2 == name || $2 == "*" name {print $1}' "$work/SHA256SUMS" | head -n 1)"
[[ -n "$published" ]] || die 1 "SHA256SUMS of $tag does not list $asset"
actual="$(sha256_of "$work/$asset")"
[[ "$embedded" == "$published" ]] ||
    die 1 "the package embeds sha256 $embedded for $asset, but SHA256SUMS of $tag lists $published"
[[ "$actual" == "$published" ]] ||
    die 1 "$asset has sha256 $actual, but SHA256SUMS of $tag lists $published"
exe=rollcall
[[ "$key" != windows-* ]] || exe=rollcall.exe
cached="$ROLLCALL_CACHE_DIR/rollcall/bin/$tag/$key/$exe"
[[ -f "$cached" ]] || die 1 "the wrapper cached no binary at $cached"

echo "$out"
echo "install-check-pip: PASS pip install $spec ($key): $first; sha256 $actual (embedded = SHA256SUMS = downloaded)"
