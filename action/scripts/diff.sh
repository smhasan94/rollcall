#!/usr/bin/env bash
# rollcall-action step 4: compare this build with the base artifact (if base.sh found one) with
# `rollcall diff`, writing the pull-request comment ($RC_OUT_DIR/comment.md) and the
# rollcall-diff/1 JSON ($RC_OUT_DIR/diff.json).
#
# Inputs (environment): RC_FAIL_ON (critical|high|medium|low|unknown|none), RC_BASE
# (present|absent, from base.sh; absent when unset), RC_OUT_DIR, ROLLCALL_BIN.
#
# Outputs: comment (comment.md's path), diff (diff.json's path), new-findings (how many new
# findings, gated or not), gated-findings (new open ones at or above fail-on), gate
# (clean|findings). The step itself succeeds either way: gate.sh fails the job, after the
# comment and the artifact upload.
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

ROLLCALL="${ROLLCALL_BIN:-rollcall}"

main() {
    local args=(--sbom "$OUT/sbom.cdx.json" --scan "$OUT/scan.json" --report "$OUT/report.json")
    local base="$OUT/base"
    if [[ "${RC_BASE:-absent}" == present && -f "$base/sbom.cdx.json" ]]; then
        args+=(--base-sbom "$base/sbom.cdx.json")
        if [[ -f "$base/scan.json" ]]; then
            args+=(--base-scan "$base/scan.json")
        fi
        if [[ -f "$base/report.json" ]]; then
            args+=(--base-report "$base/report.json")
        fi
    fi
    local fail_on="${RC_FAIL_ON:-high}"
    case "$fail_on" in
        critical | high | medium | low | unknown) args+=(--fail-on "$fail_on") ;;
        none) ;;
        *) die 64 "fail-on must be critical, high, medium, low, unknown or none, not '$fail_on'" ;;
    esac

    local format status gate=""
    for format in md json; do
        local out="$OUT/diff.json"
        [[ "$format" == md ]] && out="$OUT/comment.md"
        status=0
        "$ROLLCALL" diff "${args[@]}" --format "$format" -o "$out" || status=$?
        case "$status" in
            0) gate=clean ;;
            1) gate=findings ;;
            *) die "rollcall diff failed (exit $status)" ;;
        esac
    done
    write_output comment "$OUT/comment.md"
    write_output diff "$OUT/diff.json"
    write_output new-findings "$(jq -r '.findings.new | length' "$OUT/diff.json")"
    write_output gated-findings "$(jq -r '.gate.new_open_at_or_above' "$OUT/diff.json")"
    write_output gate "$gate"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat "$OUT/comment.md" >>"$GITHUB_STEP_SUMMARY"
    fi
    log "gate: $gate"
}

main "$@"
