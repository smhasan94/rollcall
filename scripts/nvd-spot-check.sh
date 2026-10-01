#!/usr/bin/env bash
# Spot-checks CPEs against the NVD CPE dictionary (the NVD CPE API 2.0).
#
# NEEDS THE NETWORK.
#
# Usage: scripts/nvd-spot-check.sh CPE...
#
# Each argument is a CPE 2.3 formatted string or a prefix of one
# (`cpe:2.3:a:arm:mbed_tls` checks the vendor:product, `cpe:2.3:a:arm:mbed_tls:3.6.4` one
# version). For each, prints
#
#   CPE | totalResults | non-deprecated | first matching cpeName
#
# and exits 1 if any argument has no non-deprecated match.
#
# Environment:
#   NVD_API_KEY   optional; without it requests are spaced 7 s apart (NVD's public limit is
#                 5 requests per 30 s).
set -euo pipefail

for tool in curl jq; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "nvd-spot-check: $tool is required" >&2
        exit 2
    }
done
[[ $# -gt 0 ]] || {
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 2
}

API=https://services.nvd.nist.gov/rest/json/cpes/2.0
headers=()
pause=7
if [[ -n "${NVD_API_KEY:-}" ]]; then
    headers=(-H "apiKey: $NVD_API_KEY")
    pause=1
fi

echo "NVD CPE API, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s | %s | %s | %s\n' CPE totalResults non-deprecated "first cpeName"
failed=0
first=1
for cpe in "$@"; do
    [[ "$first" -eq 1 ]] || sleep "$pause"
    first=0
    body="$(curl -fsS --retry 3 --retry-delay 10 ${headers[@]+"${headers[@]}"} -G "$API" \
        --data-urlencode "cpeMatchString=$cpe" --data-urlencode resultsPerPage=2000)" || {
        printf '%s | ERROR | - | request failed\n' "$cpe"
        failed=1
        continue
    }
    # NVD answers some failures (rate limiting, maintenance) with HTML and a 200.
    if ! jq -e '.totalResults | numbers' >/dev/null 2>&1 <<<"$body"; then
        printf '%s | ERROR | - | not a CPE API JSON answer: %s\n' "$cpe" "$(head -c 80 <<<"$body" | tr '\n' ' ')"
        failed=1
        continue
    fi
    total="$(jq -r '.totalResults' <<<"$body")"
    live="$(jq -r '[.products[] | select(.cpe.deprecated | not)] | length' <<<"$body")"
    name="$(jq -r '[.products[] | select(.cpe.deprecated | not) | .cpe.cpeName][0] // "-"' <<<"$body")"
    printf '%s | %s | %s | %s\n' "$cpe" "$total" "$live" "$name"
    [[ "$live" -gt 0 ]] || failed=1
done
exit "$failed"
