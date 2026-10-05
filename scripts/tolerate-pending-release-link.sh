#!/usr/bin/env bash
# Judges a scripts/check-doc-links.sh run on a release tag (SHA-125; ci.yml job docs-links,
# step "Check the release documents' links (release tags)").
#
# Usage: scripts/tolerate-pending-release-link.sh TAG RC REPORT
#
#   TAG     the tag being built (GITHUB_REF_NAME), e.g. v0.1.0
#   RC      check-doc-links.sh's exit code
#   REPORT  its output (the PASS/FAIL/SKIP table)
#
# On a tag's own CI run, release.yml has not created that tag's GitHub Release yet, so
# CHANGELOG.md's link to https://github.com/smhasan94/rollcall/releases/tag/TAG answers 404.
# That one failure, and only it, is tolerated:
#
# - RC 0 passes; an RC other than 0 or 1 (a usage or setup error) fails with that code;
# - with RC 1, every FAIL row must be exactly that URL with the detail `HTTP 404 <that URL>`
#   (no curl error, no redirect); any other failing row (another status, a curl error such as
#   a DNS failure, another tag's release page, another URL, a link inside the repository)
#   fails, and so does a report with no FAIL row at all.
#
# Prints what it tolerated or rejected; exits 0 when the run is acceptable, 1 when not, 2 on a
# usage error.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: scripts/tolerate-pending-release-link.sh TAG RC REPORT" >&2
    exit 2
fi
tag="$1"
rc="$2"
report="$3"
[[ "$tag" =~ ^v[0-9A-Za-z.+-]+$ ]] || {
    echo "tolerate-pending-release-link: '$tag' is not a release tag" >&2
    exit 2
}
[[ "$rc" =~ ^[0-9]+$ ]] || {
    echo "tolerate-pending-release-link: '$rc' is not an exit code" >&2
    exit 2
}
[[ -f "$report" ]] || {
    echo "tolerate-pending-release-link: $report not found" >&2
    exit 2
}

if [[ "$rc" -eq 0 ]]; then
    echo "tolerate-pending-release-link: every link passed"
    exit 0
fi
if [[ "$rc" -ne 1 ]]; then
    echo "tolerate-pending-release-link: check-doc-links.sh exited $rc (not a link failure)" >&2
    exit "$rc"
fi

url="https://github.com/smhasan94/rollcall/releases/tag/$tag"
tolerated=0
rejected=0
# A row is `<file>:<line>  FAIL  <target>  <detail>`; the summary line has no `:<line>`.
while IFS= read -r row; do
    read -r where result target detail <<<"$row" || true
    [[ "$where" =~ :[0-9]+$ && "$result" == FAIL ]] || continue
    if [[ "$target" == "$url" && "$detail" == "HTTP 404 $url" ]]; then
        echo "tolerated (release.yml creates it after this run): $row"
        tolerated=$((tolerated + 1))
    else
        echo "rejected: $row" >&2
        rejected=$((rejected + 1))
    fi
done <"$report"

if [[ "$rejected" -gt 0 ]]; then
    echo "tolerate-pending-release-link: FAIL ($rejected failing link(s) besides $url)" >&2
    exit 1
fi
if [[ "$tolerated" -eq 0 ]]; then
    echo "tolerate-pending-release-link: FAIL (exit 1 but no failing link row in $report)" >&2
    exit 1
fi
echo "tolerate-pending-release-link: PASS (only $url is missing)"
