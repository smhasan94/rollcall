#!/usr/bin/env bash
# Fetches the official CSAF 2.0 JSON schema (OASIS, CSAF v2.0 OASIS Standard) and the three
# FIRST CVSS schemas it references, verifies their sha256, and only then writes them to
# crates/rollcall-core/schema/csaf/.
#
# The files are vendored verbatim; never edit them. To move to new versions, update the URLs
# and sha256s below together, re-run this script and update SOURCE.md and the *_SHA256
# constants in crates/rollcall-core/src/csaf/schema.rs.
#
# Needs the network, curl and a sha256 tool (sha256sum or shasum).
set -euo pipefail

cd "$(dirname "$0")/.."

DEST="crates/rollcall-core/schema/csaf"

FILES=(csaf_json_schema.json cvss-v2.0.json cvss-v3.0.json cvss-v3.1.json)
URLS=(
    https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json
    https://www.first.org/cvss/cvss-v2.0.json
    https://www.first.org/cvss/cvss-v3.0.json
    https://www.first.org/cvss/cvss-v3.1.json
)
SHA256=(
    29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262
    cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2
    b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919
    77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f
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
    curl -fsSL --retry 3 -o "$tmp/$file" "${URLS[$i]}"
    got=$(sha256_of "$tmp/$file")
    if [[ "$got" != "$want" ]]; then
        echo "vendor-csaf-schema: sha256 mismatch for $file (${URLS[$i]})" >&2
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
echo "wrote ${#FILES[@]} schemas to $DEST"
