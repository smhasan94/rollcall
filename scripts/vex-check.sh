#!/usr/bin/env bash
# VEX conformance check (SHA-113): rollcall's OpenVEX output is accepted by the reference
# OpenVEX tooling (vexctl), its CycloneDX VEX output validates against the CycloneDX 1.6
# schema, and grype honours the OpenVEX document by suppressing the old-mbedTLS findings
# rollcall marks not_affected.
#
# NEEDS THE NETWORK for `--install` (pinned grype and vexctl releases) and for grype's
# vulnerability database on a cache miss.
#
# Usage: scripts/vex-check.sh [--install]
#
#   --install   download the pinned grype and vexctl into $ROLLCALL_TOOLS_DIR (default
#               .cache/tools), verifying each download's SHA-256 (the pins and the download
#               helper follow scripts/smoke-scan.sh). Without it, the tools are taken from
#               $ROLLCALL_TOOLS_DIR, then from PATH.
#
# Either way, a tool whose reported version is not the pinned one is refused.
#
# Environment:
#   ROLLCALL_TOOLS_DIR  where the tools live (default .cache/tools)
#   ROLLCALL_VEX_OUT    output directory, emptied first (default .cache/vex-check)
#   ROLLCALL_BIN        the rollcall binary (default: built with `cargo build -p rollcall-cli`)
#   GRYPE_DB_CACHE_DIR  grype's database directory (default .cache/grype-db); set
#                       GRYPE_DB_AUTO_UPDATE=false to use it offline as it is
#
# Inputs: the hand-written old-mbedTLS model crates/rollcall-core/tests/data/old-mbedtls.model.json
# (Mbed TLS 2.28.0 with its cpe, which grype matches), the captured grype findings
# tests/data/findings/old-mbedtls.grype.json, the rules tests/data/vex/old-mbedtls.rules.yml
# and the real Kconfig of fixtures/zephyr/tls/http_server.
#
# Steps, each a PASS/FAIL row:
#   1. rollcall generate the SBOM (golden timestamp); rollcall validate --schema.
#   2. rollcall vex --format openvex, byte-compared with the committed golden.
#   3. rollcall vex --format cyclonedx, byte-compared with the committed golden, then
#      rollcall validate --schema (CycloneDX 1.6 schema validation of the VEX document).
#   4. vexctl merge loads the OpenVEX document (go-vex parsing) and keeps every statement's
#      vulnerability, product, status and justification.
#   5. vexctl create rebuilds every statement from its fields, which runs go-vex's statement
#      validation (status, justification, impact/action statements); a negative control
#      (not_affected without a justification) must be rejected, proving the check is live.
#   6. grype on the SBOM reports every CVE the OpenVEX document marks not_affected.
#   7. grype --vex with the OpenVEX document: each of those CVEs leaves .matches, appears in
#      .ignoredMatches with a vex/not_affected rule, and the match count drops by exactly
#      their number.
#   8. Steps 6 and 7 on the real Zephyr v4.2.0 build fixtures/zephyr-old-mbedtls/old-mbedtls
#      (Mbed TLS 3.6.4, generated with its west list and the seed identifier database):
#      grype's live findings, the illustrative rules
#      crates/rollcall-core/tests/data/vex/zephyr-old-mbedtls.rules.yml and the build's own
#      .config give an OpenVEX document whose only not_affected CVE (CVE-2026-34873, TLS 1.3
#      compiled out) grype --vex suppresses, and nothing else.
# Prints a PASS/FAIL table; exits 1 if anything failed, 2 on a setup error.
set -euo pipefail

cd "$(dirname "$0")/.."

GRYPE_VERSION=0.119.0
VEXCTL_VERSION=0.4.4
GOLDEN_TIMESTAMP=2026-01-02T03:04:05Z
DATA=crates/rollcall-core/tests/data
GOLDEN=crates/rollcall-core/tests/golden/vex
KCONFIG=fixtures/zephyr/tls/http_server/zephyr/.config
# The real Zephyr v4.2.0 build (Mbed TLS 3.6.4), its illustrative rules, and the one CVE they
# mark not_affected (from the rules file).
REAL_VARIANT=fixtures/zephyr-old-mbedtls/old-mbedtls
REAL_RULES=$DATA/vex/zephyr-old-mbedtls.rules.yml
REAL_EXPECTED=CVE-2026-34873
IDENTIFIER_DB=crates/rollcall-identifiers/db/identifiers.yaml

# SHA-256 of the grype release tarballs (as in scripts/smoke-scan.sh).
grype_sha256() {
    case "$1" in
        linux_amd64) echo 3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b ;;
        linux_arm64) echo 29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8 ;;
        darwin_arm64) echo 500c9b2b6c089d21481815f57a553fabbd441ec7d1e79d95e3aaf40c3bfc7e36 ;;
        darwin_amd64) echo ea106d3ab9573d654871ad9e3e89be2237506ff3f8c170e5aeacb59da4def2b8 ;;
        *) return 1 ;;
    esac
}

# SHA-256 of the vexctl v0.4.4 release binaries, copied from the release's checksum file
# https://github.com/openvex/vexctl/releases/download/v0.4.4/vexctl_checksums.txt
vexctl_sha256() {
    case "$1" in
        linux_amd64) echo d315e2778af88b999ad4bba30a08aa2677ed701638e16c341b6d57b43c1e064d ;;
        linux_arm64) echo 2f37f2d6fd00d3d73dc2c657639d2f3b00060608aef517766fdd0e0dc07abe21 ;;
        darwin_arm64) echo 6d810a5022d7624a7cfe71dbdb973708d4fe4e8210d8f7bd99266f6e282b04f7 ;;
        darwin_amd64) echo 6e9631e7b5020b9e5f42d57fb6670dd5323156d8d68a608aab9a8ebea0544702 ;;
        *) return 1 ;;
    esac
}

die() {
    echo "vex-check: $*" >&2
    exit 2
}

install=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) install=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
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
OUT="${ROLLCALL_VEX_OUT:-.cache/vex-check}"
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

    want="$(vexctl_sha256 "$platform")" || die "no pinned vexctl for $platform"
    download "https://github.com/openvex/vexctl/releases/download/v${VEXCTL_VERSION}/vexctl-${os}-${arch}" \
        "$TOOLS_DIR/vexctl" "$want"
    chmod +x "$TOOLS_DIR/vexctl"
    echo "installed vexctl $VEXCTL_VERSION ($platform, sha256 $want)"
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
VEXCTL="$(find_tool vexctl)"

if ! grype_out="$("$GRYPE" version 2>&1)"; then
    die "refusing $GRYPE: 'grype version' failed: $(head -c 200 <<<"$grype_out")"
fi
grype_reported="$(awk '$1 == "Version:" {print $2}' <<<"$grype_out")"
[[ "$grype_reported" == "$GRYPE_VERSION" ]] ||
    die "refusing $GRYPE: version '${grype_reported:-unknown}', pinned $GRYPE_VERSION"
if ! vexctl_out="$("$VEXCTL" version 2>&1)"; then
    die "refusing $VEXCTL: 'vexctl version' failed: $(head -c 200 <<<"$vexctl_out")"
fi
vexctl_reported="$(awk '$1 == "GitVersion:" {print $2}' <<<"$vexctl_out")"
[[ "$vexctl_reported" == "v$VEXCTL_VERSION" ]] ||
    die "refusing $VEXCTL: version '${vexctl_reported:-unknown}', pinned v$VEXCTL_VERSION"

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
"$GRYPE" db status 2>&1 | sed 's/^/  grype db: /' || true
echo "vexctl $VEXCTL_VERSION: $VEXCTL"
echo "rollcall: $ROLLCALL"
echo "output: $OUT"
echo

ROWS=()
failed=0

# record <check> <PASS|FAIL> <detail>
record() {
    ROWS+=("$1|$2|$3")
    [[ "$2" == PASS ]] || failed=1
}

# check <name> <detail> <condition...>: records PASS if the command succeeds.
check() {
    local name="$1" detail="$2"
    shift 2
    if "$@"; then
        record "$name" PASS "$detail"
    else
        record "$name" FAIL "$detail"
    fi
}

finish() {
    printf '%-40s  %-6s  %s\n' CHECK RESULT DETAIL
    printf '%-40s  %-6s  %s\n' ---------------------------------------- ------ ------
    for row in "${ROWS[@]}"; do
        IFS='|' read -r name result detail <<<"$row"
        printf '%-40s  %-6s  %s\n' "$name" "$result" "$detail"
    done
    echo
    if [[ "$failed" -ne 0 ]]; then
        echo "vex-check: FAIL (logs in $OUT)"
        exit 1
    fi
    echo "vex-check: PASS"
    exit 0
}

SBOM="$OUT/old-mbedtls.cdx.json"
OPENVEX="$OUT/old-mbedtls.openvex.json"
CDXVEX="$OUT/old-mbedtls.vex.cdx.json"

# 1. The SBOM.
if "$ROLLCALL" generate --model "$DATA/old-mbedtls.model.json" \
    --timestamp "$GOLDEN_TIMESTAMP" -o "$SBOM" 2>"$OUT/generate.stderr"; then
    record "rollcall generate" PASS "exit 0"
else
    record "rollcall generate" FAIL "exit $? ($(head -c 200 "$OUT/generate.stderr"))"
    finish
fi
if "$ROLLCALL" validate --schema "$SBOM" >"$OUT/validate-sbom.stdout" 2>&1; then
    record "SBOM validate --schema" PASS "$(cat "$OUT/validate-sbom.stdout")"
else
    record "SBOM validate --schema" FAIL "$(head -c 300 "$OUT/validate-sbom.stdout")"
fi

vex() {
    "$ROLLCALL" vex --sbom "$SBOM" --kconfig "$KCONFIG" \
        --findings "$DATA/findings/old-mbedtls.grype.json" \
        --rules "$DATA/vex/old-mbedtls.rules.yml" --timestamp "$GOLDEN_TIMESTAMP" "$@"
}

# 2. OpenVEX.
if vex --format openvex -o "$OPENVEX" 2>"$OUT/openvex.stderr"; then
    record "rollcall vex --format openvex" PASS "exit 0"
else
    record "rollcall vex --format openvex" FAIL "exit $? ($(head -c 200 "$OUT/openvex.stderr"))"
    finish
fi
check "openvex matches golden" "cmp $GOLDEN/old-mbedtls.openvex.json" \
    cmp -s "$OPENVEX" "$GOLDEN/old-mbedtls.openvex.json"

# 3. CycloneDX VEX.
if vex --format cyclonedx -o "$CDXVEX" 2>"$OUT/cyclonedx.stderr"; then
    record "rollcall vex --format cyclonedx" PASS "exit 0"
else
    record "rollcall vex --format cyclonedx" FAIL "exit $? ($(head -c 200 "$OUT/cyclonedx.stderr"))"
fi
check "cyclonedx vex matches golden" "cmp $GOLDEN/old-mbedtls.vex.cdx.json" \
    cmp -s "$CDXVEX" "$GOLDEN/old-mbedtls.vex.cdx.json"
if "$ROLLCALL" validate --schema "$CDXVEX" >"$OUT/validate-vex.stdout" 2>&1; then
    record "CycloneDX VEX validate --schema" PASS "$(cat "$OUT/validate-vex.stdout")"
else
    record "CycloneDX VEX validate --schema" FAIL "$(head -c 300 "$OUT/validate-vex.stdout")"
fi

# 4. vexctl merge: go-vex loads the document and keeps every statement.
statements="$(jq '.statements | length' "$OPENVEX")"
summary='[.statements[] | {v: .vulnerability.name, p: [.products[]."@id"], s: .status, j: .justification}] | sort'
if "$VEXCTL" merge "$OPENVEX" >"$OUT/vexctl-merge.json" 2>"$OUT/vexctl-merge.stderr"; then
    if [[ "$(jq -c "$summary" "$OUT/vexctl-merge.json")" == "$(jq -c "$summary" "$OPENVEX")" ]]; then
        record "vexctl merge" PASS "exit 0, $statements statement(s) kept"
    else
        record "vexctl merge" FAIL "statements differ after vexctl merge (see $OUT/vexctl-merge.json)"
    fi
else
    record "vexctl merge" FAIL "exit $? ($(head -c 300 "$OUT/vexctl-merge.stderr"))"
fi

# 5. vexctl create: go-vex's statement validation, on every statement's fields.
# create_statement <statement JSON> <log>: rebuilds the statement with vexctl create.
create_statement() {
    local s="$1" log="$2" args=()
    args+=(--vuln "$(jq -r '.vulnerability.name' <<<"$s")")
    args+=(--status "$(jq -r '.status' <<<"$s")")
    while IFS= read -r product; do
        args+=(--product "$product")
    done < <(jq -r '.products[]."@id"' <<<"$s")
    local field flag value
    for field in justification:--justification impact_statement:--impact-statement \
        action_statement:--action-statement status_notes:--status-note; do
        flag="${field#*:}"
        value="$(jq -r --arg k "${field%%:*}" '.[$k] // empty' <<<"$s")"
        if [[ -n "$value" ]]; then
            args+=("$flag" "$value")
        fi
    done
    local aliases
    aliases="$(jq -r '(.vulnerability.aliases // []) | join(",")' <<<"$s")"
    if [[ -n "$aliases" ]]; then
        args+=(--aliases "$aliases")
    fi
    "$VEXCTL" create "${args[@]}" >"$log" 2>&1
}
valid=0
invalid=()
i=0
while IFS= read -r s; do
    i=$((i + 1))
    if create_statement "$s" "$OUT/vexctl-create-$i.log"; then
        valid=$((valid + 1))
    else
        invalid+=("$(jq -r '.vulnerability.name' <<<"$s")")
    fi
done < <(jq -c '.statements[]' "$OPENVEX")
if [[ "$valid" -eq "$statements" && "$statements" -gt 0 ]]; then
    record "vexctl create (statement validation)" PASS "$valid/$statements statement(s) valid"
else
    record "vexctl create (statement validation)" FAIL "$valid/$statements valid; invalid: ${invalid[*]:-}"
fi
negative='{"vulnerability":{"name":"CVE-0000-0000"},"products":[{"@id":"pkg:generic/x@1"}],"status":"not_affected"}'
if create_statement "$negative" "$OUT/vexctl-create-negative.log"; then
    record "vexctl rejects invalid statement" FAIL "not_affected without justification was accepted"
else
    record "vexctl rejects invalid statement" PASS "not_affected without justification rejected"
fi

# grype_vex <prefix> <label> <sbom> <openvex> <baseline grype json>: grype --vex with the
# OpenVEX document must move every CVE it marks not_affected from .matches to .ignoredMatches
# (vex/not_affected) and drop the match count by exactly their number. Writes
# $OUT/<prefix>.not-affected.txt.
grype_vex() {
    local prefix="$1" label="$2" sbom="$3" openvex="$4" baseline="$5" rc cve present still ignored
    jq -r '[.statements[] | select(.status == "not_affected") | .vulnerability.name] | unique | .[]' \
        "$openvex" >"$OUT/$prefix.not-affected.txt"
    local suppressed
    suppressed="$(wc -l <"$OUT/$prefix.not-affected.txt" | tr -d ' ')"
    rc=0
    "$GRYPE" "sbom:$sbom" --vex "$openvex" -o json --file "$OUT/$prefix.grype-vex.json" \
        2>"$OUT/$prefix.grype-vex.stderr" || rc=$?
    check "$label grype --vex exit 0" "exit $rc" test "$rc" -eq 0
    local before after delta=error
    before="$(jq '.matches | length' "$baseline" 2>/dev/null || echo error)"
    after="$(jq '.matches | length' "$OUT/$prefix.grype-vex.json" 2>/dev/null || echo error)"
    check "$label not_affected CVEs" "$suppressed: $(tr '\n' ' ' <"$OUT/$prefix.not-affected.txt")" \
        test "$suppressed" -gt 0
    while IFS= read -r cve; do
        present="$(jq --arg id "$cve" '[.matches[] | select(.vulnerability.id == $id)] | length' "$baseline")"
        check "$label baseline has $cve" "$present match(es) without --vex" test "$present" -gt 0
        still="$(jq --arg id "$cve" '[.matches[] | select(.vulnerability.id == $id)] | length' \
            "$OUT/$prefix.grype-vex.json")"
        ignored="$(jq --arg id "$cve" '[.ignoredMatches[]? | select(.vulnerability.id == $id)
            | select(any(.appliedIgnoreRules[]?; .namespace == "vex" and ."vex-status" == "not_affected"))] | length' \
            "$OUT/$prefix.grype-vex.json")"
        check "$label --vex suppresses $cve" "matches=$still, ignored by vex/not_affected=$ignored" \
            test "$still" -eq 0 -a "$ignored" -gt 0
    done <"$OUT/$prefix.not-affected.txt"
    if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then
        delta=$((before - after))
    fi
    check "$label --vex drops exactly those" "matches $before -> $after (expected -$suppressed)" \
        test "$delta" = "$suppressed"
}

# 6 and 7. grype honours the OpenVEX document (hand-written model).
rc=0
"$GRYPE" "sbom:$SBOM" -o json --file "$OUT/grype.json" 2>"$OUT/grype.stderr" || rc=$?
check "model grype exit 0" "exit $rc" test "$rc" -eq 0
grype_vex model model "$SBOM" "$OPENVEX" "$OUT/grype.json"

# 8. The same on the real Zephyr v4.2.0 build (Mbed TLS 3.6.4), against live grype output:
# exactly the CVE the illustrative rules mark not_affected is suppressed.
REAL_SBOM="$OUT/zephyr-old-mbedtls.cdx.json"
REAL_OPENVEX="$OUT/zephyr-old-mbedtls.openvex.json"
if "$ROLLCALL" generate --zephyr "$REAL_VARIANT/mbedtls" --west-list "$REAL_VARIANT/west-list.txt" \
    --identifier-db "$IDENTIFIER_DB" --timestamp "$GOLDEN_TIMESTAMP" -o "$REAL_SBOM" \
    2>"$OUT/real-generate.stderr"; then
    record "real rollcall generate" PASS "exit 0 ($REAL_VARIANT/mbedtls, seed identifier db)"
else
    record "real rollcall generate" FAIL "exit $? ($(head -c 200 "$OUT/real-generate.stderr"))"
    finish
fi
rc=0
"$GRYPE" "sbom:$REAL_SBOM" -o json --file "$OUT/real.grype.json" 2>"$OUT/real.grype.stderr" || rc=$?
check "real grype exit 0" "exit $rc" test "$rc" -eq 0
if "$ROLLCALL" vex --sbom "$REAL_SBOM" --kconfig "$REAL_VARIANT/mbedtls/zephyr/.config" \
    --findings "$OUT/real.grype.json" --rules "$REAL_RULES" --format openvex \
    --timestamp "$GOLDEN_TIMESTAMP" -o "$REAL_OPENVEX" 2>"$OUT/real-openvex.stderr"; then
    record "real rollcall vex --format openvex" PASS "exit 0"
else
    record "real rollcall vex --format openvex" FAIL "exit $? ($(head -c 200 "$OUT/real-openvex.stderr"))"
    finish
fi
grype_vex real real "$REAL_SBOM" "$REAL_OPENVEX" "$OUT/real.grype.json"
real_suppressed="$(tr '\n' ' ' <"$OUT/real.not-affected.txt")"
check "real suppresses exactly $REAL_EXPECTED" "not_affected: ${real_suppressed% }" \
    test "${real_suppressed% }" = "$REAL_EXPECTED"

finish
