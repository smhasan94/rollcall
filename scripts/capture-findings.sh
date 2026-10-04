#!/usr/bin/env bash
# Captures real scanner output for the VEX evaluator's tests (rollcall vex, SHA-111) into
# crates/rollcall-core/tests/data/findings/. Those files are only ever produced by this
# script, never edited by hand.
#
# NEEDS THE NETWORK for osv-scanner (it queries osv.dev) and for `--install`. grype uses the
# vulnerability database already in $GRYPE_DB_CACHE_DIR and does not update it (set
# GRYPE_DB_AUTO_UPDATE=true to fetch the latest one), so the grype capture is reproducible
# for a given database.
#
# Usage: scripts/capture-findings.sh [--install] [--only NAME] [--bluetooth-cves]
#
#   --install          install the pinned grype and osv-scanner first, by running
#                      scripts/smoke-scan.sh --install (which also smoke-tests them).
#   --only NAME        capture only findings/NAME.json (NAME is one of the captures below,
#                      e.g. old-heapless.grype); the other captures are left exactly as they
#                      are, and CAPTURE.txt keeps their capture dates.
#   --bluetooth-cves   capture nothing; instead print the Bluetooth CVE list of the starter
#                      VEX rule pack's `zephyr-bluetooth-off` rule (see below). Offline
#                      (grype only, cached database).
#
# The Bluetooth list: grype skips CPE matching for components typed `operating-system`,
# which is how rollcall types `zephyr`, so it reports no Zephyr CVEs for rollcall's SBOMs.
# The list is made by rendering the sysbuild SBOMs of fixtures/zephyr/bt (Zephyr v4.4.2,
# cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*) and fixtures/zephyr-old-mbedtls/old-mbedtls
# (v4.2.0, cpe:2.3:o:zephyrproject:zephyr:4.2.0:-:*), retyping that component `library`
# (jq, in the scratch copy only), scanning both with grype, and keeping every vulnerability of
# the `zephyr` component whose description names a file under subsys/bluetooth/; one id per
# line, sorted.
#
# Environment:
#   ROLLCALL_TOOLS_DIR      where the scanners live (default .cache/tools), else PATH
#   GRYPE_DB_CACHE_DIR      grype's database directory (default .cache/grype-db)
#   GRYPE_DB_AUTO_UPDATE    default false (use the cached database as is)
#   ROLLCALL_BIN            the rollcall binary (default: built with `cargo build -p rollcall-cli`)
#
# Captures, each from `rollcall generate --model tests/data/<model>.model.json` rendered with
# the golden timestamp:
#   old-mbedtls.grype.json   grype on old-mbedtls (mbedtls 2.28.0, CPE-matched CVEs)
#   old-mbedtls.osv.json     osv-scanner on old-mbedtls (pkg:github purls; osv-scanner maps
#                            them to "GitHub Actions" and finds nothing)
#   old-heapless.osv.json    osv-scanner on old-heapless (pkg:cargo/heapless@0.5.0, which has
#                            RUSTSEC/GHSA advisories)
#   old-heapless.grype.json  grype on old-heapless (the same advisory by its GHSA id, related
#                            CVE-2020-36464; the grype/osv-scanner overlap `rollcall scan`
#                            is tested on, SHA-117)
#
# and one from a real build, `rollcall generate --zephyr fixtures/zephyr-old-mbedtls/old-mbedtls
# --sysbuild` with its west list and the seed identifier database
# (crates/rollcall-identifiers/db/identifiers.yaml), rendered with the golden timestamp:
#   zephyr-old-mbedtls.grype.json   grype on the Zephyr v4.2.0 build (Mbed TLS 3.6.4 in both
#                                   images, CPE-matched CVEs); the starter VEX rule pack's
#                                   tests and docs/vex-rules.md use it (SHA-115)
#
# Every absolute path in the scanner output (the temporary capture directory, the repository
# root, $HOME) is replaced with a fixed placeholder, so the committed files do not depend on
# the machine. Tool versions, the grype database and each file's capture date are written to
# findings/CAPTURE.txt.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
export TZ=UTC
# Only scrub $HOME when it is a real home directory: replacing a short or root $HOME (e.g.
# `/`) would mangle every path.
SCRUB_HOME="${HOME:-}"
if [[ "${#SCRUB_HOME}" -lt 4 || "$SCRUB_HOME" == "/" ]]; then
    SCRUB_HOME="/nonexistent-home-placeholder"
fi

GRYPE_VERSION=0.119.0
OSV_SCANNER_VERSION=2.6.0
GOLDEN_TIMESTAMP=2026-01-02T03:04:05Z
DATA=crates/rollcall-core/tests/data
OUT_DIR="$DATA/findings"

die() {
    echo "capture-findings: $*" >&2
    exit 2
}

CAPTURES=(old-mbedtls.grype old-mbedtls.osv old-heapless.osv old-heapless.grype zephyr-old-mbedtls.grype)

install=0
bluetooth=0
only=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) install=1 ;;
        --bluetooth-cves) bluetooth=1 ;;
        --only)
            [[ $# -ge 2 ]] || die "--only needs a capture name"
            only="$2"
            shift
            ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
if [[ -n "$only" ]]; then
    case " ${CAPTURES[*]} " in
        *" $only "*) CAPTURES=("$only") ;;
        *) die "unknown capture for --only: $only (one of: ${CAPTURES[*]})" ;;
    esac
fi

command -v jq >/dev/null 2>&1 || die "jq is required"

if [[ "$install" -eq 1 ]]; then
    scripts/smoke-scan.sh --install || die "scripts/smoke-scan.sh --install failed"
fi

TOOLS_DIR="${ROLLCALL_TOOLS_DIR:-.cache/tools}"

# find_tool <name>: the tool in TOOLS_DIR, else on PATH.
find_tool() {
    if [[ -x "$TOOLS_DIR/$1" ]]; then
        echo "$TOOLS_DIR/$1"
    elif command -v "$1" >/dev/null 2>&1; then
        command -v "$1"
    else
        die "$1 not found in $TOOLS_DIR or PATH; run with --install"
    fi
}

GRYPE="$(find_tool grype)"

if ! grype_out="$("$GRYPE" version 2>&1)"; then
    die "refusing $GRYPE: 'grype version' failed"
fi
grype_reported="$(awk '$1 == "Version:" {print $2}' <<<"$grype_out")"
[[ "$grype_reported" == "$GRYPE_VERSION" ]] ||
    die "refusing $GRYPE: version '${grype_reported:-unknown}', pinned $GRYPE_VERSION"
if [[ "$bluetooth" -eq 0 ]]; then
OSV_SCANNER="$(find_tool osv-scanner)"
if ! osv_out="$("$OSV_SCANNER" --version 2>&1)"; then
    die "refusing $OSV_SCANNER: 'osv-scanner --version' failed"
fi
osv_reported="$(awk '/^osv-scanner version:/ {print $3}' <<<"$osv_out")"
[[ "$osv_reported" == "$OSV_SCANNER_VERSION" ]] ||
    die "refusing $OSV_SCANNER: version '${osv_reported:-unknown}', pinned $OSV_SCANNER_VERSION"
fi

if [[ -n "${ROLLCALL_BIN:-}" ]]; then
    ROLLCALL="$ROLLCALL_BIN"
else
    cargo build -q -p rollcall-cli --locked
    ROLLCALL="${CARGO_TARGET_DIR:-target}/debug/rollcall"
fi
[[ -x "$ROLLCALL" ]] || die "rollcall binary not found at $ROLLCALL"

export GRYPE_DB_CACHE_DIR="${GRYPE_DB_CACHE_DIR:-.cache/grype-db}"
export GRYPE_DB_AUTO_UPDATE="${GRYPE_DB_AUTO_UPDATE:-false}"
export GRYPE_CHECK_FOR_APP_UPDATE=false

mkdir -p .cache "$OUT_DIR"
WORK="$(cd "$(mktemp -d .cache/capture.XXXXXX)" && pwd)"
trap 'rm -rf "$WORK"' EXIT

# normalise <raw> <dest>: pretty JSON with every absolute path replaced by a placeholder.
normalise() {
    jq --arg work "$WORK" --arg root "$ROOT" --arg home "$SCRUB_HOME" '
        def scrub: split($work) | join("<capture>")
                 | split($root) | join("<repo>")
                 | split($home) | join("<home>");
        walk(if type == "string" then scrub else . end)
    ' "$1" >"$2"
    if grep -qF -e "$WORK" -e "$ROOT" -e "$SCRUB_HOME" "$2"; then
        die "$2 still contains an absolute path"
    fi
}

# generate <model>: renders tests/data/<model>.model.json to $WORK/<model>.cdx.json.
generate() {
    "$ROLLCALL" generate --model "$DATA/$1.model.json" --timestamp "$GOLDEN_TIMESTAMP" \
        -o "$WORK/$1.cdx.json"
}

# grype_capture <model>
grype_capture() {
    "$GRYPE" "sbom:$WORK/$1.cdx.json" -o json --file "$WORK/$1.grype.raw.json" \
        2>"$WORK/$1.grype.stderr" || die "grype failed on $1: $(head -c 300 "$WORK/$1.grype.stderr")"
    normalise "$WORK/$1.grype.raw.json" "$OUT_DIR/$1.grype.json"
    echo "captured $OUT_DIR/$1.grype.json ($(jq '.matches | length' "$OUT_DIR/$1.grype.json") matches)"
}

# osv_capture <model>: osv-scanner exits 1 when it finds vulnerabilities, which is expected.
osv_capture() {
    local rc=0
    "$OSV_SCANNER" scan source -L "$WORK/$1.cdx.json" --format json --all-packages \
        --output-file "$WORK/$1.osv.raw.json" --verbosity warn 2>"$WORK/$1.osv.stderr" || rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 1 ]] ||
        die "osv-scanner failed on $1 (exit $rc): $(head -c 300 "$WORK/$1.osv.stderr")"
    normalise "$WORK/$1.osv.raw.json" "$OUT_DIR/$1.osv.json"
    echo "captured $OUT_DIR/$1.osv.json ($(jq '[.results[]?.packages[]?.vulnerabilities[]?] | length' "$OUT_DIR/$1.osv.json") vulnerabilities)"
}

# generate_zephyr <name> <variant dir>: renders the real sysbuild build to $WORK/<name>.cdx.json.
generate_zephyr() {
    "$ROLLCALL" generate --zephyr "$2" --sysbuild --west-list "$2/west-list.txt" \
        --identifier-db crates/rollcall-identifiers/db/identifiers.yaml \
        --timestamp "$GOLDEN_TIMESTAMP" -o "$WORK/$1.cdx.json" 2>"$WORK/$1.generate.stderr" ||
        die "rollcall generate failed on $2: $(head -c 300 "$WORK/$1.generate.stderr")"
}

if [[ "$bluetooth" -eq 1 ]]; then
    for variant in fixtures/zephyr/bt fixtures/zephyr-old-mbedtls/old-mbedtls; do
        name="$(basename "$variant")"
        generate_zephyr "$name" "$variant"
        jq '(.. | objects | select(.type? == "operating-system")) .type = "library"' \
            "$WORK/$name.cdx.json" >"$WORK/$name.library.cdx.json"
        "$GRYPE" "sbom:$WORK/$name.library.cdx.json" -o json --file "$WORK/$name.bt.json" \
            2>"$WORK/$name.bt.stderr" || die "grype failed on $name: $(head -c 300 "$WORK/$name.bt.stderr")"
    done
    jq -r '.matches[] | select(.artifact.name == "zephyr")
           | select(.vulnerability.description // "" | contains("subsys/bluetooth/"))
           | .vulnerability.id' "$WORK"/*.bt.json | LC_ALL=C sort -u
    exit 0
fi

generated=" "
grype_ran=0
for capture in "${CAPTURES[@]}"; do
    model="${capture%.*}"
    if [[ "$generated" != *" $model "* ]]; then
        case "$model" in
            zephyr-old-mbedtls) generate_zephyr "$model" fixtures/zephyr-old-mbedtls/old-mbedtls ;;
            *) generate "$model" ;;
        esac
        generated="$generated$model "
    fi
    case "$capture" in
        *.grype)
            grype_capture "$model"
            grype_ran=1
            ;;
        *.osv) osv_capture "$model" ;;
    esac
done

# The capture date of every file: today for the ones captured now, else the date the
# previous CAPTURE.txt records (its per-file line, or the single `captured:` line older
# versions of this script wrote).
OLD_CAPTURE="$OUT_DIR/CAPTURE.txt"
previous_date() {
    [[ -f "$OLD_CAPTURE" ]] || return 0
    local line
    line="$(awk -v f="$1.json:" '$1 == f && $2 == "captured" {print $3}' "$OLD_CAPTURE")"
    if [[ -z "$line" ]]; then
        line="$(awk '$1 == "captured:" && NF == 2 {print $2}' "$OLD_CAPTURE")"
    fi
    echo "${line:-unknown}"
}
today="$(date -u +%Y-%m-%d)"
dates=()
for capture in old-heapless.grype old-heapless.osv old-mbedtls.grype old-mbedtls.osv zephyr-old-mbedtls.grype; do
    case " ${CAPTURES[*]} " in
        *" $capture "*) dates+=("$capture.json: captured $today") ;;
        *) dates+=("$capture.json: captured $(previous_date "$capture")") ;;
    esac
done

# sed_escape <text>: <text> as a literal sed pattern (with `|` as the delimiter).
sed_escape() {
    printf '%s' "$1" | sed -e 's/[]\/$*.^[|]/\\&/g'
}
if [[ "$grype_ran" -eq 1 || ! -f "$OLD_CAPTURE" ]]; then
    db_status="$("$GRYPE" db status 2>/dev/null |
        sed "s|$(sed_escape "$ROOT")|<repo>|g; s|$(sed_escape "$SCRUB_HOME")|<home>|g" |
        sed 's/^/  /' || echo "  unavailable")"
else
    # No grype capture this time: keep the database the grype captures were made with.
    db_status="$(sed -n '/^grype db status:$/,$p' "$OLD_CAPTURE" | sed '1d')"
fi
{
    echo "# Written by scripts/capture-findings.sh; do not edit."
    echo "grype: $GRYPE_VERSION"
    echo "osv-scanner: $OSV_SCANNER_VERSION (queries osv.dev at capture time)"
    printf '%s\n' "${dates[@]}"
    echo "grype db status:"
    echo "$db_status"
} >"$WORK/CAPTURE.txt"
mv "$WORK/CAPTURE.txt" "$OLD_CAPTURE"
echo "wrote $OLD_CAPTURE"
