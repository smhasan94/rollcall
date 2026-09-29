#!/usr/bin/env bash
# Fetches the official CycloneDX 1.6 JSON schemas at a pinned tag and verifies their sha256
# before writing them to crates/rollcall-core/schema/cyclonedx/.
#
# The files are vendored verbatim; never edit them. To move to a new tag, update TAG, COMMIT
# and the three sha256s below together, re-run this script and update SOURCE.md.
#
# Needs the network, curl and a sha256 tool (sha256sum or shasum).
set -euo pipefail

cd "$(dirname "$0")/.."

TAG="1.6.2"
COMMIT="e833d732337dd33aceb45ff1991f896796f1e5e7"
BASE="https://raw.githubusercontent.com/CycloneDX/specification/${COMMIT}/schema"
DEST="crates/rollcall-core/schema/cyclonedx"

FILES=(bom-1.6.schema.json spdx.schema.json jsf-0.82.schema.json)
SHA256=(
    18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d
    c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6
    8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae
)

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Download and verify everything before touching the destination.
for i in "${!FILES[@]}"; do
    file="${FILES[$i]}"
    want="${SHA256[$i]}"
    curl -fsSL --retry 3 -o "$tmp/$file" "$BASE/$file"
    got=$(sha256_of "$tmp/$file")
    if [[ "$got" != "$want" ]]; then
        echo "vendor-cyclonedx-schema: sha256 mismatch for $file (tag $TAG)" >&2
        echo "  expected $want" >&2
        echo "  got      $got" >&2
        exit 1
    fi
    echo "verified $file $got"
done

mkdir -p "$DEST"
for file in "${FILES[@]}"; do
    cp "$tmp/$file" "$DEST/$file"
done
echo "wrote ${#FILES[@]} schemas to $DEST (CycloneDX/specification $TAG, $COMMIT)"
