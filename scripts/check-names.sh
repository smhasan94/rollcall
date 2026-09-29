#!/usr/bin/env bash
# Re-runnable check that every rollcall name is reserved at 0.0.1 and owned by us.
#
# Names: crates.io rollcall, rollcall-core, rollcall-cli, rollcall-assay; PyPI rollcall.
# For each, checks that version 0.0.1 exists (not merely that it is the latest), prints the
# crates.io owner logins, then prints the verbatim `cargo search` and `pip index versions`
# output. Every name is reported even when some fail.
#
# Ownership:
#   - crates.io: set ROLLCALL_CRATES_OWNER to the required owner login. A crate whose
#     owner_user logins do not include it is reported as WRONG-OWNER. If the variable is unset,
#     ownership is not asserted and the script exits 1 even when everything is present,
#     because the acceptance criterion needs ownership proven.
#   - PyPI: its JSON API exposes no owners, so PyPI ownership is recorded manually on the
#     ticket.
#
# Output lines:
#   MISSING <registry>/<name> (...)      not published (HTTP 404) or 0.0.1 absent
#   WRONG-OWNER crates.io/<name> (...)   ROLLCALL_CRATES_OWNER not among the owners
#   UNAVAILABLE <registry>/<name> (...)  network error, HTTP 429, 5xx or other unexpected reply
#
# Exit codes:
#   0  all five present at 0.0.1 and crates.io ownership asserted
#   1  anything missing, wrong owner, or ownership not asserted
#   2  a required tool (curl, jq) is missing, or any registry was unavailable
#      (unavailable wins over missing)
set -euo pipefail

for tool in curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "check-names: $tool is required" >&2
        exit 2
    fi
done

UA="rollcall-check-names (github.com/smhasan94/rollcall)"
WANT="0.0.1"
CRATES=(rollcall rollcall-core rollcall-cli rollcall-assay)
OWNER="${ROLLCALL_CRATES_OWNER:-}"
missing=0
unavailable=0

# fetch <url>: sets BODY, HTTP (status code, "000" if none) and CURL_RC. Never aborts.
fetch() {
    local out
    CURL_RC=0
    out=$(curl -sS -A "$UA" -w '\n%{http_code}' "$1" 2>/dev/null) || CURL_RC=$?
    HTTP="${out##*$'\n'}"
    BODY="${out%$'\n'*}"
    [[ "$HTTP" =~ ^[0-9]{3}$ ]] || HTTP="000"
}

# classify <registry>/<name>: returns 0 if the last fetch was a 200; otherwise reports
# MISSING or UNAVAILABLE, updates the counters and returns 1.
classify() {
    local what="$1"
    if [[ "$CURL_RC" -ne 0 || "$HTTP" == "000" ]]; then
        echo "UNAVAILABLE $what (network error, curl exit $CURL_RC)"
        unavailable=1
    elif [[ "$HTTP" == "200" ]]; then
        return 0
    elif [[ "$HTTP" == "404" ]]; then
        echo "MISSING $what (HTTP 404)"
        missing=1
    else
        # 429, 5xx and anything else unexpected: we cannot tell whether the name is taken.
        echo "UNAVAILABLE $what (HTTP $HTTP)"
        unavailable=1
    fi
    return 1
}

for c in "${CRATES[@]}"; do
    fetch "https://crates.io/api/v1/crates/$c"
    classify "crates.io/$c" || continue
    if ! has=$(jq -r --arg v "$WANT" '[.versions[].num] | index($v) != null' <<<"$BODY" 2>/dev/null); then
        echo "UNAVAILABLE crates.io/$c (unparseable response)"
        unavailable=1
        continue
    fi
    if [[ "$has" == "true" ]]; then
        echo "crates.io/$c has $WANT"
    else
        echo "MISSING crates.io/$c (version $WANT not published)"
        missing=1
    fi

    fetch "https://crates.io/api/v1/crates/$c/owner_user"
    classify "crates.io/$c owners" || continue
    if ! owners=$(jq -r '[.users[].login] | join(",")' <<<"$BODY" 2>/dev/null); then
        echo "UNAVAILABLE crates.io/$c owners (unparseable response)"
        unavailable=1
        continue
    fi
    echo "crates.io/$c owners=$owners"
    if [[ -n "$OWNER" ]] && ! grep -qxF -- "$OWNER" <<<"${owners//,/$'\n'}"; then
        echo "WRONG-OWNER crates.io/$c (owners: ${owners:-<none>})"
        missing=1
    fi
done

fetch "https://pypi.org/pypi/rollcall/json"
if classify "pypi/rollcall"; then
    if ! has=$(jq -r --arg v "$WANT" '.releases | has($v)' <<<"$BODY" 2>/dev/null); then
        echo "UNAVAILABLE pypi/rollcall (unparseable response)"
        unavailable=1
    elif [[ "$has" == "true" ]]; then
        echo "pypi/rollcall has $WANT"
    else
        echo "MISSING pypi/rollcall (version $WANT not published)"
        missing=1
    fi
fi
echo "NOTE: PyPI exposes no owners in its JSON API; PyPI ownership is recorded manually on the ticket."

if [[ -z "$OWNER" ]]; then
    echo "NOTE: ROLLCALL_CRATES_OWNER unset; ownership not asserted"
    missing=1
fi

echo
echo "\$ cargo search rollcall --limit 20"
cargo search rollcall --limit 20 || true
echo
echo "\$ python3 -m pip index versions rollcall"
python3 -m pip index versions rollcall || true

if [[ "$unavailable" -ne 0 ]]; then
    exit 2
fi
exit "$missing"
