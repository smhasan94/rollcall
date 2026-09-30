#!/usr/bin/env bash
# Regenerates every rollcall-core golden file (the model's internal JSON form, the CycloneDX 1.6
# documents rendered from tests/data/*.model.json, and the Zephyr ingestion goldens under
# tests/golden/zephyr/ rendered from fixtures/zephyr/), then re-runs the golden tests against
# them, and the CLI tests that compare `rollcall generate` output with them.
#
# Golden files are only ever produced by this script, never edited by hand. Review the
# resulting diff like code.
set -euo pipefail

cd "$(dirname "$0")/.."

ROLLCALL_BLESS=1 cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr
cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr
cargo test -p rollcall-cli --test generate --test generate_zephyr

git status --short -- crates/rollcall-core/tests/golden
git diff --stat -- crates/rollcall-core/tests/golden
