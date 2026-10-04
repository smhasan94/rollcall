#!/usr/bin/env bash
# rollcall-action step 3 (pull requests only): fetch the base branch's artifact, the one this
# workflow uploaded on its last completed push run on the base branch, into $RC_OUT_DIR/base.
#
# The workflow is this run's own file (from GITHUB_WORKFLOW_REF), so the base is the same
# job's output on the base branch. Runs are tried newest first (up to five) until one has the
# artifact. Anything going wrong (no such workflow on the base branch yet, no run, an expired
# artifact, the API failing) means "no base": the step never fails the job, and every open
# finding then counts as new.
#
# Inputs (environment): RC_ARTIFACT_NAME, RC_GITHUB_TOKEN, RC_OUT_DIR, GITHUB_REPOSITORY,
# GITHUB_WORKFLOW_REF, GITHUB_BASE_REF, GITHUB_EVENT_NAME. Needs gh and jq.
#
# Outputs: base (present|absent), base-reason (why, when absent), base-run (the run's id).
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

BASE_DIR="$OUT/base"

absent() {
    log "no base artifact: $1"
    echo "::notice::rollcall-action: no base artifact ($1); every open finding counts as new" >&2
    rm -rf "$BASE_DIR"
    write_output base absent
    write_output base-reason "$1"
    exit 0
}

main() {
    case "${GITHUB_EVENT_NAME:-}" in
        pull_request) ;;
        *) absent "not a pull request (${GITHUB_EVENT_NAME:-no event})" ;;
    esac
    local repo="${GITHUB_REPOSITORY:-}" base_ref="${GITHUB_BASE_REF:-}" name="${RC_ARTIFACT_NAME:-rollcall}"
    check_artifact_name "$name"
    [[ -n "$repo" ]] || absent "GITHUB_REPOSITORY is not set"
    [[ -n "$base_ref" ]] || absent "GITHUB_BASE_REF is not set"
    local workflow="${GITHUB_WORKFLOW_REF:-}"
    workflow="${workflow%%@*}"
    workflow="${workflow##*/}"
    [[ -n "$workflow" ]] || absent "GITHUB_WORKFLOW_REF is not set"
    command -v gh >/dev/null 2>&1 || absent "gh is not installed"

    local runs
    # gh encodes the fields (a branch name may hold + % # &); -X GET makes them a query string.
    if ! runs="$(gh_api -X GET "repos/$repo/actions/workflows/$workflow/runs" \
        -f branch="$base_ref" -f event=push -f status=completed -F per_page=5 2>&1)"; then
        absent "no run of $workflow on $base_ref ($(head -c 200 <<<"$runs" | tr '\n' ' '))"
    fi
    local ids
    ids="$(jq -r '.workflow_runs[]?.id // empty' <<<"$runs" 2>/dev/null)" ||
        absent "unreadable runs listing for $workflow on $base_ref"
    [[ -n "$ids" ]] || absent "no completed push run of $workflow on $base_ref yet"

    local id
    for id in $ids; do
        rm -rf "$BASE_DIR"
        mkdir -p "$BASE_DIR"
        if GH_TOKEN="${RC_GITHUB_TOKEN:-${GH_TOKEN:-}}" gh run download "$id" -R "$repo" -n "$name" -D "$BASE_DIR" >&2 &&
            [[ -f "$BASE_DIR/sbom.cdx.json" ]]; then
            log "base artifact '$name' from run $id of $workflow on $base_ref"
            write_output base present
            write_output base-run "$id"
            return 0
        fi
        log "run $id has no usable artifact '$name'"
    done
    absent "no run of $workflow on $base_ref has an artifact '$name' with an SBOM"
}

main "$@"
