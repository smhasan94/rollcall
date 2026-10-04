#!/usr/bin/env bash
# rollcall-action step 5 (pull requests only): post the comment ($RC_OUT_DIR/comment.md), or
# update the one this action posted before, so a re-run never adds a second comment.
#
# The comment starts with a hidden marker, <!-- rollcall-action:ARTIFACT-NAME -->, so two jobs
# with different artifact names keep one comment each. The existing comment is the first one
# on the pull request whose body starts with the marker and whose author is the token's own
# user: `gh api user` names it for a personal access token or an app's user token; the
# workflow token cannot call that endpoint, and then a bot's comment (github-actions[bot])
# is ours. It is PATCHed in place, else a new one is POSTed. A body longer than 64000
# characters is cut at a character boundary (jq slices by code point, so the result is
# always valid UTF-8), with a pointer to the artifact: GitHub's limit is 65536.
#
# On a pull request from a fork (or from a deleted fork: a null head repository) the token is
# read-only: posting fails, and the step says so with a notice and succeeds (the gate still
# applies). Any other failure to post fails the step (usually a missing
# `pull-requests: write` permission).
#
# Inputs (environment): RC_ARTIFACT_NAME, RC_GITHUB_TOKEN, RC_OUT_DIR, GITHUB_REPOSITORY,
# GITHUB_EVENT_PATH. Needs gh and jq.
#
# Outputs: comment-id, comment-action (created|updated|skipped).
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

# What is kept of a longer comment body, in characters (code points), leaving room under
# GitHub's 65536 for the note.
KEEP_CHARS=64000

# The token for one gh call: single attempt (a POST must never be repeated).
gh_once() {
    GH_TOKEN="${RC_GITHUB_TOKEN:-${GH_TOKEN:-}}" gh api "$@"
}

# is_fork: whether the pull request comes from another repository, or from one since deleted
# (its head repository is null).
is_fork() {
    local head
    head="$(jq -r 'if (.pull_request.head | type) == "object" and .pull_request.head.repo == null
                   then "(deleted fork)" else (.pull_request.head.repo.full_name // "") end' \
        "$GITHUB_EVENT_PATH" 2>/dev/null || true)"
    [[ -n "$head" && "$head" != "${GITHUB_REPOSITORY:-}" ]]
}

# cannot_post WHAT DETAIL: a notice and success on a fork, else an error.
cannot_post() {
    if is_fork; then
        echo "::notice::rollcall-action: cannot $1 on a pull request from a fork (the token is read-only); see the job summary and the artifact instead" >&2
        write_output comment-action skipped
        exit 0
    fi
    die "cannot $1: $2 (does the job have 'pull-requests: write'?)"
}

main() {
    local event="${GITHUB_EVENT_PATH:-}"
    local pr=""
    if [[ -n "$event" && -f "$event" ]]; then
        pr="$(jq -r '.pull_request.number // empty' "$event")"
    fi
    if [[ -z "$pr" ]]; then
        log "not a pull request; no comment"
        write_output comment-action skipped
        return 0
    fi
    local repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
    check_artifact_name "${RC_ARTIFACT_NAME:-rollcall}"
    local marker="<!-- rollcall-action:${RC_ARTIFACT_NAME:-rollcall} -->"
    local md="$OUT/comment.md"
    [[ -f "$md" ]] || die "$md does not exist (did the diff step run?)"

    local body="$OUT/comment.body.md" payload="$OUT/comment.payload.json"
    {
        printf '%s\n' "$marker"
        cat "$md"
    } >"$body"
    # jq reads the body as a string and slices it by code point, so a cut never splits a
    # UTF-8 character.
    jq -Rs --argjson keep "$KEEP_CHARS" --arg name "${RC_ARTIFACT_NAME:-rollcall}" '
        if length > $keep
        then .[0:$keep] + "\n\n… The comment was cut at GitHub'"'"'s size limit; the whole diff is in the workflow run'"'"'s artifact `\($name)`.\n"
        else . end
        | {body: .}' <"$body" >"$payload" || die "cannot build the comment payload"

    # Whose comment is ours: the token's own login, when the token may ask (/user).
    local me=""
    me="$(gh_once user 2>/dev/null | jq -r '.login // empty' 2>/dev/null || true)"

    local listing existing
    if ! listing="$(gh_api --paginate "repos/$repo/issues/$pr/comments?per_page=100" 2>&1)"; then
        cannot_post "list the pull request's comments" "$(head -c 300 <<<"$listing")"
    fi
    existing="$(jq -rs --arg m "$marker" --arg me "$me" \
        '[.[] | if type == "array" then .[] else . end
          | select(if $me != "" then (.user.login // "") == $me
                   else (.user.type // "") == "Bot" end)
          | select((.body // "") | startswith($m))
          | .id] | first // empty' <<<"$listing" 2>/dev/null)" ||
        die "unreadable comment listing for pull request $pr"

    local response
    if [[ -n "$existing" ]]; then
        if ! response="$(gh_once -X PATCH "repos/$repo/issues/comments/$existing" --input "$payload" 2>&1)"; then
            cannot_post "update comment $existing" "$(head -c 300 <<<"$response")"
        fi
        log "updated comment $existing on pull request $pr"
        write_output comment-id "$existing"
        write_output comment-action updated
    else
        if ! response="$(gh_once -X POST "repos/$repo/issues/$pr/comments" --input "$payload" 2>&1)"; then
            cannot_post "comment on pull request $pr" "$(head -c 300 <<<"$response")"
        fi
        local id
        id="$(jq -r '.id // empty' <<<"$response" 2>/dev/null || true)"
        log "created comment ${id:-?} on pull request $pr"
        write_output comment-id "$id"
        write_output comment-action created
    fi
}

main "$@"
