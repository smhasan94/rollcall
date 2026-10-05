#!/usr/bin/env bash
# Lints the identifier database: what CI job `identifiers-lint` runs, and the last step of
# adding a module (CONTRIBUTING.md). Offline.
#
# Usage: scripts/lint-identifiers.sh [DB]
#
#   DB  the database file, or a directory holding identifiers.yaml
#       (default: crates/rollcall-identifiers/db/identifiers.yaml)
#
# Runs `rollcall identifiers lint` with:
#   --expect-version  the rollcall-identifiers crate version: db_version must equal it;
#   --fixtures fixtures/zephyr  every module of the E2 fixture builds must resolve to a purl.
# (fixtures/zephyr-old-mbedtls is not linted: its v4.2-era module names are not joined to
# `west list`, issue #12, so two of its modules are unknown by name.)
#
# Findings go to stderr as `<file>:<line>: <rule>: <message>`; the summary to stdout.
# Exit codes: 0 clean, 1 findings, 65/66 unreadable database, anything else a build failure.
set -euo pipefail

cd "$(dirname "$0")/.."

db=${1:-crates/rollcall-identifiers/db/identifiers.yaml}
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/rollcall-identifiers/Cargo.toml | head -n 1)
if [[ -z "$version" ]]; then
    echo "lint-identifiers: no version in crates/rollcall-identifiers/Cargo.toml" >&2
    exit 2
fi

# `cargo run` finds the binary wherever CARGO_TARGET_DIR puts it.
exec cargo run -q -p rollcall --locked -- identifiers lint "$db" \
    --expect-version "$version" \
    --fixtures fixtures/zephyr
