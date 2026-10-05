#!/usr/bin/env bash
# Publishes the workspace's crates to crates.io, dependencies first, skipping any version that
# is already there, so re-running a release is safe.
#
# Usage: scripts/publish-crates.sh
#
# Order: rollcall-identifiers, rollcall-core, rollcall-assay, rollcall (the binary). For each
# crate at its version (crates/<crate>/Cargo.toml; `version.workspace = true` means the
# workspace version) it asks the crates.io API:
#
#   HTTP 200   already published: skipped
#   HTTP 404   published with `cargo publish -p <crate> --locked --no-verify` (the release
#              workflow's preflight job has already run `cargo publish --workspace --dry-run`;
#              cargo waits until the new version is in the index before the next crate)
#   other      crates.io cannot say (an outage, rate limiting, no network): asked up to three
#              times, then the script stops without publishing anything more and exits 2
#
# On any stop it prints which crates were published, which were already there, which failed
# and which were not attempted, so a re-run (after fixing the cause) picks up where it left off.
#
# Environment:
#   CARGO_REGISTRY_TOKEN   the token cargo publishes with (the release workflow sets it from
#                          crates.io trusted publishing, or the CARGO_REGISTRY_TOKEN secret)
#   ROLLCALL_CRATES_API    the crates.io API base (default https://crates.io/api/v1; tests)
#   ROLLCALL_RETRY_DELAY   seconds between API attempts (default 10)
#
# Exit codes: 0 every crate is on crates.io; 1 a cargo publish failed; 2 crates.io did not
# answer 200 or 404; 64 usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${ROLLCALL_CRATES_API:-https://crates.io/api/v1}"
DELAY="${ROLLCALL_RETRY_DELAY:-10}"
UA="rollcall-release (github.com/smhasan94/rollcall)"
CRATES=(rollcall-identifiers rollcall-core rollcall-assay rollcall)

[[ $# -eq 0 ]] || {
    echo "publish-crates: usage: publish-crates.sh (no arguments)" >&2
    exit 64
}

published=() skipped=() failed=() pending=()

# toml_version FILE SECTION: the plain `version = "..."` of [SECTION] in FILE.
toml_version() {
    awk -v section="[$2]" '
        /^\[/ { inside = ($0 == section) }
        inside && /^version[ \t]*=[ \t]*"/ {
            v = $0
            sub(/^version[ \t]*=[ \t]*"/, "", v)
            sub(/".*$/, "", v)
            print v
            exit
        }' "$1"
}

# crate_version CRATE: its version as it would be published.
crate_version() {
    local manifest="$ROOT/crates/$1/Cargo.toml" v
    [[ -f "$manifest" ]] || return 1
    if grep -q '^version\.workspace[ \t]*=[ \t]*true' "$manifest"; then
        v="$(toml_version "$ROOT/Cargo.toml" workspace.package)"
    else
        v="$(toml_version "$manifest" package)"
    fi
    [[ -n "$v" ]] || return 1
    echo "$v"
}

list() {
    local label="$1"
    shift
    if [[ $# -gt 0 ]]; then
        echo "publish-crates: $label: $*" >&2
    else
        echo "publish-crates: $label: none" >&2
    fi
}

summary() {
    list "published" ${published[@]+"${published[@]}"}
    list "already on crates.io" ${skipped[@]+"${skipped[@]}"}
    list "failed" ${failed[@]+"${failed[@]}"}
    list "not attempted" ${pending[@]+"${pending[@]}"}
}

# status CRATE VERSION: the crates.io API's HTTP status for that version (000: no answer).
status() {
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' -A "$UA" --max-time 30 \
        "$API/crates/$1/$2" 2>/dev/null)" || true
    [[ "$code" =~ ^[0-9]{3}$ ]] || code=000
    echo "$code"
}

declare -a versions=()
for crate in "${CRATES[@]}"; do
    v="$(crate_version "$crate")" || {
        echo "::error::publish-crates: cannot read the version of $crate (crates/$crate/Cargo.toml)" >&2
        exit 64
    }
    versions+=("$v")
    pending+=("$crate@$v")
done

for i in "${!CRATES[@]}"; do
    crate="${CRATES[$i]}" version="${versions[$i]}"
    pending=("${pending[@]:1}")
    code=000
    for attempt in 1 2 3; do
        code="$(status "$crate" "$version")"
        [[ "$code" == 200 || "$code" == 404 ]] && break
        [[ "$attempt" -lt 3 ]] && sleep "$DELAY"
    done
    case "$code" in
        200)
            echo "publish-crates: skip $crate $version: already on crates.io"
            skipped+=("$crate@$version")
            ;;
        404)
            echo "publish-crates: publishing $crate $version"
            rc=0
            cargo publish -p "$crate" --locked --no-verify || rc=$?
            if [[ "$rc" -ne 0 ]]; then
                failed+=("$crate@$version")
                echo "::error::publish-crates: cargo publish failed for $crate $version (exit $rc); nothing after it was attempted" >&2
                summary
                exit 1
            fi
            published+=("$crate@$version")
            ;;
        *)
            failed+=("$crate@$version")
            echo "::error::publish-crates: crates.io answered HTTP $code for $crate $version (want 200 or 404) after 3 attempts; not publishing it or anything after it" >&2
            summary
            exit 2
            ;;
    esac
done
summary
