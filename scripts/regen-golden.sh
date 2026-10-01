#!/usr/bin/env bash
# Regenerates every rollcall-core golden file (the model's internal JSON form, the CycloneDX 1.6
# documents rendered from tests/data/*.model.json, the blob-manifest document rendered from
# tests/data/blobs/, and the Zephyr ingestion goldens under tests/golden/zephyr/ rendered from
# fixtures/zephyr/, including the MCUboot image and the merged sysbuild product), then re-runs
# the golden tests and the reader round trips against them, and the CLI tests that compare
# `rollcall generate` and `rollcall merge` output with them.
#
# Golden files are only ever produced by this script, never edited by hand. Review the
# resulting diff like code.
set -euo pipefail

cd "$(dirname "$0")/.."

# The bless pass skips the golden-inventory tests (`every_committed_*`): they list the golden
# directories, which do not yet hold a golden being blessed for the first time. The second
# pass runs them against the freshly written files.
ROLLCALL_BLESS=1 cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr --test blob --test reader -- --skip every_committed
cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr --test blob --test reader
cargo test -p rollcall-cli --test generate --test generate_zephyr --test merge

git status --short -- crates/rollcall-core/tests/golden
git diff --stat -- crates/rollcall-core/tests/golden
