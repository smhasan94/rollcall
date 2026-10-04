#!/usr/bin/env bash
# rollcall-action step 7 (last, after the comment and the artifact upload): fail the job when
# `rollcall diff` found new open findings at or above fail-on.
#
# Outside a pull request (e.g. a push to main) there is no base, so every open finding of the
# build counts as new; the gate then only notes the outcome and passes, unless
# RC_GATE_ON_PUSH is true. The diff, the artifact and the job summary are unchanged.
#
# Inputs (environment): RC_GATE (clean|findings, from diff.sh), RC_FAIL_ON, RC_GATE_ON_PUSH
# (true|false, default false), GITHUB_EVENT_NAME, RC_OUT_DIR.
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

main() {
    case "${RC_GATE_ON_PUSH:-false}" in
        true | false) ;;
        *) die 64 "gate-on-push must be true or false, not '${RC_GATE_ON_PUSH}'" ;;
    esac
    if [[ "${GITHUB_EVENT_NAME:-}" != pull_request && "${RC_GATE_ON_PUSH:-false}" != true ]]; then
        echo "::notice::rollcall-action: not a pull request (${GITHUB_EVENT_NAME:-no event}): gate outcome '${RC_GATE:-none}' is not enforced (set gate-on-push: true to enforce it)" >&2
        return 0
    fi
    case "${RC_GATE:-}" in
        clean)
            log "gate passed: no new open findings at or above ${RC_FAIL_ON:-high}"
            ;;
        findings)
            local count ids
            count="$(jq -r '.gate.new_open_at_or_above' "$OUT/diff.json" 2>/dev/null || echo '?')"
            ids="$(jq -r --arg t "${RC_FAIL_ON:-high}" '
                ["unknown","low","medium","high","critical"] as $levels
                | ($levels | index($t)) as $min
                | [.findings.new[]
                   | select(.triage != "suppressed")
                   | .severity as $s
                   | select(($levels | index($s)) >= $min)
                   | .id] | unique | join(", ")' "$OUT/diff.json" 2>/dev/null || true)"
            die "$count new open finding(s) at or above ${RC_FAIL_ON:-high}${ids:+: $ids}"
            ;;
        *)
            die "no gate outcome (did the diff step run?)"
            ;;
    esac
}

main "$@"
