#!/usr/bin/env bash
# Regenerates every rollcall-core golden file (the model's internal JSON form and the
# CycloneDX 1.6 documents rendered from tests/data/*.model.json), then re-runs the golden
# tests against them, and the CLI tests that compare `rollcall generate` output with them.
#
# Golden files are only ever produced by this script, never edited by hand. Review the
# resulting diff like code.
set -euo pipefail

cd "$(dirname "$0")/.."

ROLLCALL_BLESS=1 cargo test -p rollcall-core --test golden --test cyclonedx
cargo test -p rollcall-core --test golden --test cyclonedx
cargo test -p rollcall-cli --test generate

git diff --stat -- crates/rollcall-core/tests/golden
