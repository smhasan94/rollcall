#!/usr/bin/env bash
# Regenerates every rollcall-core golden file (the model's internal JSON form, the CycloneDX 1.6
# documents rendered from tests/data/*.model.json, the blob-manifest document rendered from
# tests/data/blobs/, and the Zephyr ingestion goldens under tests/golden/zephyr/ rendered from
# fixtures/zephyr/, including the MCUboot image and the merged sysbuild product, and the VEX
# report under tests/golden/vex/ evaluated from tests/data/findings/ and tests/data/vex/,
# with its OpenVEX, CycloneDX VEX and embedded-SBOM renderings, and the validation goldens
# under tests/golden/validate/: the clean document stripped of two components' supplier and
# hashes, and its expected `--profile all` findings), the readiness reports under
# tests/golden/report/ (Markdown and JSON for every model fixture, the blob manifest and every
# real Zephyr build under fixtures/), and the Cargo ingestion goldens under tests/golden/cargo/
# rendered from fixtures/cargo-*/ (SHA-127), then re-runs the golden tests and the reader round
# trips against them, and the CLI tests that compare `rollcall generate`, `rollcall merge`,
# `rollcall vex`, `rollcall validate` and `rollcall report` output with them.
#
# Golden files are only ever produced by this script, never edited by hand. Review the
# resulting diff like code.
set -euo pipefail

cd "$(dirname "$0")/.."

# The bless pass skips the golden-inventory tests (`every_committed_*`): they list the golden
# directories, which do not yet hold a golden being blessed for the first time. The second
# pass runs them against the freshly written files.
ROLLCALL_BLESS=1 cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr --test cargo --test blob --test reader --test vex -- --skip every_committed
# The validation goldens are derived from tests/golden/clean.cdx.json, so they are blessed
# after it.
ROLLCALL_BLESS=1 cargo test -p rollcall-core --test validate
# The report goldens read the VEX goldens (tests/golden/vex/), so they are blessed after them.
ROLLCALL_BLESS=1 cargo test -p rollcall-core --test report
cargo test -p rollcall-core --test golden --test cyclonedx --test zephyr --test cargo --test blob --test reader --test vex --test validate --test report
cargo test -p rollcall-cli --test generate --test generate_zephyr --test generate_cargo --test merge --test vex --test validate_profile --test report

git status --short -- crates/rollcall-core/tests/golden
git diff --stat -- crates/rollcall-core/tests/golden
