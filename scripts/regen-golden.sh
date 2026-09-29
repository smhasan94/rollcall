#!/usr/bin/env bash
# Regenerates the rollcall-core model golden files, then re-runs the golden tests against them.
#
# Golden files are only ever produced by this script, never edited by hand. Review the
# resulting diff like code.
set -euo pipefail

cd "$(dirname "$0")/.."

ROLLCALL_BLESS=1 cargo test -p rollcall-core --test golden
cargo test -p rollcall-core --test golden

git diff --stat -- crates/rollcall-core/tests/golden
