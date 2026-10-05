#!/usr/bin/env bash
# Writes the SHA256SUMS of a release's assets.
#
# Usage: scripts/release-sums.sh DIR [TAG]
#
# Lists every rollcall-*.tar.gz and rollcall-*.zip in DIR, sorted by name (bytewise), as
# `<sha256>  <name>` lines, the format `sha256sum -c` and `shasum -a 256 -c` read, rollcall-action's
# install.sh parses and python/scripts/embed-release.py embeds in the PyPI wrapper. Writes
# DIR/SHA256SUMS and prints it.
#
# With TAG, DIR must hold exactly the four assets of that release (linux-amd64, linux-arm64,
# darwin-universal, windows-amd64): a missing platform or a stray asset fails before anything
# is written.
#
# Exit codes: 0 written; 1 no assets, or not exactly TAG's four; 64 usage error.
set -euo pipefail

die() {
    local code="$1"
    shift
    echo "release-sums: $*" >&2
    exit "$code"
}

[[ $# -eq 1 || $# -eq 2 ]] || die 64 "usage: release-sums.sh DIR [TAG]"
dir="$1" tag="${2:-}"
[[ -d "$dir" ]] || die 64 "no such directory: $dir"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

names=()
while IFS= read -r name; do
    names+=("$name")
done < <(cd "$dir" && find . -maxdepth 1 -type f \( -name 'rollcall-*.tar.gz' -o -name 'rollcall-*.zip' \) |
    sed 's|^\./||' | LC_ALL=C sort)
[[ ${#names[@]} -gt 0 ]] || die 1 "no rollcall-*.tar.gz or rollcall-*.zip in $dir"

if [[ -n "$tag" ]]; then
    want="rollcall-$tag-darwin-universal.tar.gz
rollcall-$tag-linux-amd64.tar.gz
rollcall-$tag-linux-arm64.tar.gz
rollcall-$tag-windows-amd64.zip"
    got="$(printf '%s\n' "${names[@]}")"
    if [[ "$got" != "$want" ]]; then
        echo "release-sums: $dir must hold exactly the four assets of $tag:" >&2
        diff <(echo "$want") <(echo "$got") | sed -n 's/^< /  missing: /p; s/^> /  unexpected: /p' >&2 || true
        exit 1
    fi
fi

tmp="$dir/SHA256SUMS.tmp"
for name in "${names[@]}"; do
    printf '%s  %s\n' "$(sha256_of "$dir/$name")" "$name"
done >"$tmp"
mv "$tmp" "$dir/SHA256SUMS"
cat "$dir/SHA256SUMS"
