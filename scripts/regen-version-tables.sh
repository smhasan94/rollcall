#!/usr/bin/env bash
# Regenerates the fork revision -> upstream version rows of the identifier database
# (crates/rollcall-identifiers/db/identifiers.yaml) and the manifest pin list
# (crates/rollcall-core/tests/data/zephyr-manifest-pins.txt) for the Zephyr releases below,
# then re-runs the identifier tests.
#
# NEEDS THE NETWORK: fetches each release's west.yml and the forks' version files from
# raw.githubusercontent.com, and clones (blobless, commits only) the forks and upstreams whose
# versions come from tags. Everything is cached under .cache/version-tables/.
#
# Usage: scripts/regen-version-tables.sh
#
# Only the rows between the `# BEGIN generated` / `# END generated` markers are rewritten;
# hand-curated rows (outside the markers, each citing its source) are kept. Exits non-zero if
# any pinned revision of a seeded module is left without a version. Review the diff like code.
#
# Environment:
#   GITHUB_TOKEN   optional, for raw.githubusercontent.com rate limits.
set -euo pipefail

cd "$(dirname "$0")/.."

# The pinned release and the releases before it that the tables cover.
ZEPHYR_TAGS=(v4.2.0 v4.2.1 v4.2.2 v4.3.0 v4.3.1 v4.4.0 v4.4.1 v4.4.2)

CACHE=.cache/version-tables
MANIFESTS="$CACHE/manifests"
mkdir -p "$MANIFESTS"

for tool in curl git python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "regen-version-tables: $tool is required" >&2
        exit 2
    }
done

for tag in "${ZEPHYR_TAGS[@]}"; do
    out="$MANIFESTS/west-$tag.yml"
    [[ -s "$out" ]] && continue
    curl -fsSL --retry 3 -o "$out.tmp" \
        "https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/$tag/west.yml"
    mv "$out.tmp" "$out"
done

python3 scripts/version-tables.py \
    --manifests "$MANIFESTS" \
    --db crates/rollcall-identifiers/db/identifiers.yaml \
    --pins crates/rollcall-core/tests/data/zephyr-manifest-pins.txt \
    --cache "$CACHE"

cargo test -p rollcall-core --lib identify::
cargo test -p rollcall-core --test identify

git status --short -- crates/rollcall-identifiers/db crates/rollcall-core/tests/data/zephyr-manifest-pins.txt
git diff --stat -- crates/rollcall-identifiers/db crates/rollcall-core/tests/data/zephyr-manifest-pins.txt
