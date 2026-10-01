#!/usr/bin/env bash
# Checks the identifier database release tarball (scripts/package-identifiers.sh): CI job
# `identifiers-lint` runs it. Offline.
#
#   1. Packages twice; the two SHA-256s must agree (same toolchain and zlib build).
#   2. Unpacks it into a temporary cache directory, as a user installs a release:
#      - as is, the entry is accepted with no warning (it is the embedded version, so the
#        embedded database stays active);
#      - `rollcall --identifiers <unpacked entry> --version` reports its db_version;
#      - the same entry re-labelled as the next MINOR release is picked up from the cache:
#        `rollcall --version` reports `identifiers <next> (cache …)`.
#
# Exit 0 when all hold, 1 otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."

first=$(scripts/package-identifiers.sh 2>/dev/null | tail -n 1)
second=$(scripts/package-identifiers.sh 2>/dev/null | tail -n 1)
echo "run 1: $first"
echo "run 2: $second"
if [[ "$first" != "$second" ]]; then
    echo "check-identifiers-package: the two tarballs differ" >&2
    exit 1
fi
tarball=${first##* }
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/rollcall-identifiers/Cargo.toml | head -n 1)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
root=$tmp/rollcall/identifiers
mkdir -p "$root"
tar -xzf "$tarball" -C "$root"
test -f "$root/$version/identifiers.yaml"

cargo build -q -p rollcall-cli --locked
rollcall() {
    env -u ROLLCALL_IDENTIFIERS -u XDG_CACHE_HOME ROLLCALL_CACHE_DIR="$tmp" \
        cargo run -q -p rollcall-cli --locked -- "$@"
}
fail() {
    echo "check-identifiers-package: $*" >&2
    exit 1
}

# As unpacked: accepted, no warning.
out=$(rollcall --version 2>"$tmp/stderr")
echo "$out"
[[ -s "$tmp/stderr" ]] && fail "warnings for the unpacked entry: $(cat "$tmp/stderr")"
grep -qx "identifiers $version (embedded, minimum 1.0.0)" <<<"$out" ||
    fail "--version does not report the embedded $version"

# Named explicitly.
out=$(rollcall --identifiers "$root/$version" --version)
echo "$out"
grep -qx "identifiers $version (flag $root/$version/identifiers.yaml)" <<<"$out" ||
    fail "--identifiers does not report the unpacked $version"

# As the next release in the cache.
next=$(awk -F. '{print $1 "." $2 + 1 ".0"}' <<<"$version")
mkdir "$root/$next"
sed "s/^db_version: '$version'\$/db_version: '$next'/" "$root/$version/identifiers.yaml" \
    >"$root/$next/identifiers.yaml"
out=$(rollcall --version)
echo "$out"
grep -qx "identifiers $next (cache $root/$next/identifiers.yaml)" <<<"$out" ||
    fail "--version does not report the cached $next"

echo "check-identifiers-package: OK ($tarball)"
