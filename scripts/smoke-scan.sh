#!/usr/bin/env bash
# Smoke test: pinned grype and osv-scanner load rollcall's CycloneDX 1.6 output without
# warnings, see every component, and report zero findings for the minimal fixture.
#
# NEEDS THE NETWORK: `--install` downloads the pinned scanner releases, grype downloads its
# vulnerability database, and osv-scanner queries osv.dev.
#
# Usage: scripts/smoke-scan.sh [--install]
#
#   --install   download the pinned grype and osv-scanner into $ROLLCALL_TOOLS_DIR
#               (default .cache/tools), verifying each download's SHA-256.
#               Without it, the tools are taken from $ROLLCALL_TOOLS_DIR, then from PATH.
#
# Either way, a tool whose reported version is not the pinned one is refused.
#
# Environment:
#   ROLLCALL_TOOLS_DIR  where the scanners live (default .cache/tools)
#   ROLLCALL_SMOKE_OUT  output directory, emptied first (default .cache/smoke)
#   ROLLCALL_BIN        the rollcall binary (default: built with `cargo build -p rollcall-cli`)
#
# For each fixture (minimal, widget) in crates/rollcall-core/tests/data/:
#   1. rollcall generate with the golden timestamp, byte-compared with the committed golden,
#      then rollcall validate --schema.
#   2. grype: exits 0, no WARN/ERROR in its log, catalogues one package per node except
#      `operating-system` components (see the note at the grype check); for
#      minimal, no matches.
#   3. osv-scanner: exits 0, prints nothing on stderr, scans one package per component that
#      has a purl or cpe; for minimal, no package has a vulnerability.
# Prints a PASS/FAIL table; exits 1 if anything failed, 2 on a setup error.
set -euo pipefail

cd "$(dirname "$0")/.."

GRYPE_VERSION=0.119.0
OSV_SCANNER_VERSION=2.6.0
GOLDEN_TIMESTAMP=2026-01-02T03:04:05Z
FIXTURES=(minimal widget)

# SHA-256 of the grype release tarballs.
grype_sha256() {
    case "$1" in
        linux_amd64) echo 3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b ;;
        linux_arm64) echo 29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8 ;;
        darwin_arm64) echo 500c9b2b6c089d21481815f57a553fabbd441ec7d1e79d95e3aaf40c3bfc7e36 ;;
        darwin_amd64) echo ea106d3ab9573d654871ad9e3e89be2237506ff3f8c170e5aeacb59da4def2b8 ;;
        *) return 1 ;;
    esac
}

# SHA-256 of the osv-scanner release binaries.
osv_sha256() {
    case "$1" in
        linux_amd64) echo ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 ;;
        linux_arm64) echo 2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4 ;;
        darwin_arm64) echo 98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4 ;;
        darwin_amd64) echo 60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca ;;
        *) return 1 ;;
    esac
}

die() {
    echo "smoke-scan: $*" >&2
    exit 2
}

install=0
for arg in "$@"; do
    case "$arg" in
        --install) install=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $arg" ;;
    esac
done

for tool in curl jq cmp tar; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) die "unsupported OS $(uname -s)" ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    arm64 | aarch64) arch=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac
platform="${os}_${arch}"

TOOLS_DIR="${ROLLCALL_TOOLS_DIR:-.cache/tools}"
OUT="${ROLLCALL_SMOKE_OUT:-.cache/smoke}"
mkdir -p "$TOOLS_DIR"
TOOLS_DIR="$(cd "$TOOLS_DIR" && pwd)"

# download <url> <dest> <sha256>: fetches to a temporary file, checks the hash, then moves it.
download() {
    local url="$1" dest="$2" want="$3" tmp got
    tmp="$(mktemp "$TOOLS_DIR/.download.XXXXXX")"
    if ! curl -fsSL --retry 3 -o "$tmp" "$url"; then
        rm -f "$tmp"
        die "download failed: $url"
    fi
    got="$(sha256_of "$tmp")"
    if [[ "$got" != "$want" ]]; then
        rm -f "$tmp"
        die "sha256 mismatch for $url: expected $want, got $got"
    fi
    mv "$tmp" "$dest"
}

if [[ "$install" -eq 1 ]]; then
    want="$(grype_sha256 "$platform")" || die "no pinned grype for $platform"
    tarball="grype_${GRYPE_VERSION}_${platform}.tar.gz"
    download "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${tarball}" \
        "$TOOLS_DIR/$tarball" "$want"
    tar -xzf "$TOOLS_DIR/$tarball" -C "$TOOLS_DIR" grype
    rm -f "$TOOLS_DIR/$tarball"
    chmod +x "$TOOLS_DIR/grype"
    echo "installed grype $GRYPE_VERSION ($platform, sha256 $want)"

    want="$(osv_sha256 "$platform")" || die "no pinned osv-scanner for $platform"
    download "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${platform}" \
        "$TOOLS_DIR/osv-scanner" "$want"
    chmod +x "$TOOLS_DIR/osv-scanner"
    echo "installed osv-scanner $OSV_SCANNER_VERSION ($platform, sha256 $want)"
fi

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
OSV_SCANNER="$(find_tool osv-scanner)"

# The version commands run in `if`, so a tool that fails to run is refused with a message
# instead of `set -e` exiting silently.
if ! grype_out="$("$GRYPE" version 2>&1)"; then
    die "refusing $GRYPE: 'grype version' failed: $(head -c 200 <<<"$grype_out")"
fi
grype_reported="$(awk '$1 == "Version:" {print $2}' <<<"$grype_out")"
[[ "$grype_reported" == "$GRYPE_VERSION" ]] ||
    die "refusing $GRYPE: version '${grype_reported:-unknown}', pinned $GRYPE_VERSION"
if ! osv_out="$("$OSV_SCANNER" --version 2>&1)"; then
    die "refusing $OSV_SCANNER: 'osv-scanner --version' failed: $(head -c 200 <<<"$osv_out")"
fi
osv_reported="$(awk '/^osv-scanner version:/ {print $3}' <<<"$osv_out")"
[[ "$osv_reported" == "$OSV_SCANNER_VERSION" ]] ||
    die "refusing $OSV_SCANNER: version '${osv_reported:-unknown}', pinned $OSV_SCANNER_VERSION"

if [[ -n "${ROLLCALL_BIN:-}" ]]; then
    ROLLCALL="$ROLLCALL_BIN"
else
    cargo build -q -p rollcall-cli --locked
    ROLLCALL="${CARGO_TARGET_DIR:-target}/debug/rollcall"
fi
[[ -x "$ROLLCALL" ]] || die "rollcall binary not found at $ROLLCALL"

export GRYPE_DB_CACHE_DIR="${GRYPE_DB_CACHE_DIR:-.cache/grype-db}"
export GRYPE_CHECK_FOR_APP_UPDATE=false

rm -rf "$OUT"
mkdir -p "$OUT"

echo "grype $GRYPE_VERSION: $GRYPE"
echo "osv-scanner $OSV_SCANNER_VERSION: $OSV_SCANNER"
echo "rollcall: $ROLLCALL"
echo "output: $OUT"
echo

ROWS=()
failed=0

# record <fixture> <check> <PASS|FAIL> <detail>
record() {
    ROWS+=("$1|$2|$3|$4")
    [[ "$3" == PASS ]] || failed=1
}

# check <fixture> <name> <detail> <condition...>: records PASS if the command succeeds.
check() {
    local fixture="$1" name="$2" detail="$3"
    shift 3
    if "$@"; then
        record "$fixture" "$name" PASS "$detail"
    else
        record "$fixture" "$name" FAIL "$detail"
    fi
}

for f in "${FIXTURES[@]}"; do
    sbom="$OUT/$f.cdx.json"
    golden="crates/rollcall-core/tests/golden/$f.cdx.json"

    # 1. Generate, compare with the golden, validate.
    if "$ROLLCALL" generate --model "crates/rollcall-core/tests/data/$f.model.json" \
        --timestamp "$GOLDEN_TIMESTAMP" -o "$sbom" 2>"$OUT/$f.generate.stderr"; then
        record "$f" "rollcall generate" PASS "exit 0"
    else
        record "$f" "rollcall generate" FAIL "exit $? ($(head -c 200 "$OUT/$f.generate.stderr"))"
        continue
    fi
    check "$f" "matches golden" "cmp $golden" cmp -s "$sbom" "$golden"
    if "$ROLLCALL" validate --schema "$sbom" >"$OUT/$f.validate.stdout" 2>&1; then
        record "$f" "rollcall validate --schema" PASS "$(cat "$OUT/$f.validate.stdout")"
    else
        record "$f" "rollcall validate --schema" FAIL "$(head -c 300 "$OUT/$f.validate.stdout")"
    fi

    # Expected package counts, from the document itself.
    nodes="$(jq '[.metadata.component, (.components // [] | .. | objects | select(has("bom-ref")))] | length' "$sbom")"
    os_nodes="$(jq '[.metadata.component, (.components // [] | .. | objects | select(has("bom-ref")))] | map(select(.type == "operating-system")) | length' "$sbom")"
    non_os_nodes=$((nodes - os_nodes))
    # What osv-scanner 2.6.0 lists, verified by editing copies of the minimal document: every
    # component under the top-level `components` tree that has a purl or a cpe (a CPE-only
    # component is still listed; one with neither is dropped), and never `metadata.component`
    # (the product, i.e. the thing being described), even when it has a purl. grype, by
    # contrast, catalogues `metadata.component` as a package too, which is why the grype count
    # above includes it and this one does not.
    identified="$(jq '[.components // [] | .. | objects | select(has("bom-ref")) | select(has("purl") or has("cpe"))] | length' "$sbom")"

    # 2. grype.
    rc=0
    "$GRYPE" "sbom:$sbom" -o json -v --file "$OUT/$f.grype.json" 2>"$OUT/$f.grype.stderr" || rc=$?
    check "$f" "grype exit 0" "exit $rc" test "$rc" -eq 0
    warnings="$(grep -cE '\bWARN\b|\bERROR\b' "$OUT/$f.grype.stderr" || true)"
    check "$f" "grype no WARN/ERROR" "$warnings WARN/ERROR line(s)" test "$warnings" -eq 0
    gathered="$(sed -nE 's/.*gathered packages.*packages=([0-9]+).*/\1/p' "$OUT/$f.grype.stderr" | tail -1)"
    # Known scanner behaviour: grype 0.119.0 silently drops CycloneDX components of type
    # `operating-system` (it treats them as distro information, not packages), so it never
    # scans them for vulnerabilities. Verified: in the widget fixture it catalogues every
    # node except `zephyr`, and with only that component's type changed to `library` it
    # catalogues all of them. The model and writer label RTOS kernels `operating-system` on
    # purpose because that is accurate, so those nodes are excluded from the expected count.
    check "$f" "grype packages = non-OS nodes" \
        "packages=${gathered:-none}, nodes=$nodes ($os_nodes operating-system excluded)" \
        test "${gathered:-x}" = "$non_os_nodes"
    if [[ "$f" == minimal ]]; then
        matches="$(jq '.matches | length' "$OUT/$f.grype.json" 2>/dev/null || echo error)"
        check "$f" "grype zero matches" "matches=$matches" test "$matches" = 0
    fi

    # 3. osv-scanner.
    rc=0
    "$OSV_SCANNER" scan source -L "$sbom" --format json --all-packages \
        --output-file "$OUT/$f.osv.json" --verbosity warn 2>"$OUT/$f.osv.stderr" || rc=$?
    check "$f" "osv-scanner exit 0" "exit $rc" test "$rc" -eq 0
    stderr_bytes="$(wc -c <"$OUT/$f.osv.stderr" | tr -d ' ')"
    check "$f" "osv-scanner empty stderr" "$stderr_bytes byte(s)" test "$stderr_bytes" -eq 0
    scanned="$(jq '[.results[]?.packages[]?] | length' "$OUT/$f.osv.json" 2>/dev/null || echo error)"
    check "$f" "osv packages = purl/cpe nodes" "packages=$scanned, expected=$identified" \
        test "$scanned" = "$identified"
    if [[ "$f" == minimal ]]; then
        vulnerable="$(jq '[.results[]?.packages[]? | select((.vulnerabilities // []) | length > 0)] | length' \
            "$OUT/$f.osv.json" 2>/dev/null || echo error)"
        check "$f" "osv zero vulnerabilities" "vulnerable packages=$vulnerable" \
            test "$vulnerable" = 0
    fi
done

printf '%-8s  %-30s  %-6s  %s\n' FIXTURE CHECK RESULT DETAIL
printf '%-8s  %-30s  %-6s  %s\n' -------- ------------------------------ ------ ------
for row in "${ROWS[@]}"; do
    IFS='|' read -r fixture name result detail <<<"$row"
    printf '%-8s  %-30s  %-6s  %s\n' "$fixture" "$name" "$result" "$detail"
done
echo
if [[ "$failed" -ne 0 ]]; then
    echo "smoke-scan: FAIL (logs in $OUT)"
    exit 1
fi
echo "smoke-scan: PASS"
