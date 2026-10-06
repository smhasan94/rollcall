#!/usr/bin/env bash
# Checks that a copy of the algorithm catalogue (cbom-infra's) agrees with rollcall's on every
# shared entry (SHA-139). cbom-infra runs it in its CI against the copy it vendors; see
# docs/catalogue.md, "Export contract and sync with cbom-infra". Offline.
#
# Usage: scripts/check-catalogue-sync.sh THEIRS [OURS]
#
#   THEIRS  the copy to check (cbom-infra's algorithms.yaml)
#   OURS    rollcall's catalogue (default: crates/rollcall-assay/db/algorithms.yaml)
#
# Contract: both files are `format: rollcall-algorithms/1` and pass rollcall's loader and lint
# (crates/rollcall-assay/db/algorithms.schema.json is the JSON Schema). An entry is shared when
# its name (ignoring ASCII case) and parameter-set id are in both files. Every field of a shared
# entry must be equal except the prose `source`. Entries in only one file are listed but do not
# fail the check.
#
# Prints the shared count, the entries in one file only and every disagreement
# (`NAME[/ID] FIELD: ours X, theirs Y`) to stdout; errors to stderr.
# Exit codes: 0 agree, 1 disagreements, 64 usage, 65 a file does not load (malformed, wrong
# format or lint findings), 66 a file cannot be read; anything else is a build failure.
# Runs the `catalogue-sync` example of rollcall-assay with `cargo run` (CARGO overrides cargo).
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: scripts/check-catalogue-sync.sh THEIRS [OURS]" >&2
    exit 64
fi

# absolute <path>: <path> made absolute against the directory the script was started in.
absolute() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s\n' "$PWD/$1" ;;
    esac
}

theirs=$(absolute "$1")
root="$(cd "$(dirname "$0")/.." && pwd)"
ours=$(absolute "${2:-$root/crates/rollcall-assay/db/algorithms.yaml}")

cd "$root"
# `cargo run` finds the example wherever CARGO_TARGET_DIR puts it.
exec "${CARGO:-cargo}" run -q -p rollcall-assay --example catalogue-sync --locked -- "$ours" "$theirs"
