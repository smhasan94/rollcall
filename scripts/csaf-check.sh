#!/usr/bin/env bash
# CSAF conformance check (SHA-132): `rollcall csaf` output for every fixture with captured
# findings passes the official CSAF validator library (@secvisogram/csaf-validator-lib, the
# strict CSAF 2.0 schema test and every mandatory test of CSAF 2.0 section 6.1), as well as
# `rollcall validate --schema` (the vendored schema and rollcall's own mandatory checks).
#
# NEEDS THE NETWORK for `--install` (`npm ci` fetches the pinned validator library and its
# dependencies, each checked against the integrity hash in package-lock.json).
#
# Usage: scripts/csaf-check.sh [--install]
#
#   --install   run `npm ci` in scripts/csaf-validator first. Without it, the validator's
#               node_modules must already be there.
#
# Needs node 20.6 or later (and npm with --install), and jq (scripts/csaf-summary.sh).
#
# Environment:
#   ROLLCALL_CSAF_OUT  output directory, emptied first (default .cache/csaf)
#   ROLLCALL_BIN       the rollcall binary (default: built with `cargo build -p rollcall`)
#
# Fixtures (the inputs with captured scanner findings, crates/rollcall-core/tests/data/findings/):
#   old-mbedtls         tests/data/old-mbedtls.model.json, grype + osv-scanner captures, and the
#                       OpenVEX golden tests/golden/vex/old-mbedtls.openvex.json
#   old-heapless        tests/data/old-heapless.model.json, grype + osv-scanner captures
#   zephyr-old-mbedtls  the real build's SBOM golden tests/golden/zephyr/old-mbedtls.cdx.json
#                       (fixtures/zephyr-old-mbedtls/), its grype capture
#
# Steps, each a PASS/FAIL row:
#   1. rollcall csaf for each fixture (golden timestamp, publisher "Example Devices Ltd" /
#      https://devices.example) into $ROLLCALL_CSAF_OUT/<fixture>.csaf.json; old-mbedtls is
#      byte-compared with the committed golden tests/golden/csaf/old-mbedtls.csaf.json.
#   2. rollcall validate --schema on each.
#   3. The official validator on each: must PASS (optional-test warnings are printed, never
#      fatal).
#   4. Negative control: a copy of the old-mbedtls document with a product status naming an
#      undefined product (mandatory test 6.1.1) must FAIL, proving the validator is live.
#   5. scripts/csaf-summary.sh on the old-mbedtls document prints the expected row for
#      CVE-2022-46392 (mbedtls, as part of the firmware, known_affected).
# Prints a PASS/FAIL table; exits 1 if anything failed, 2 on a setup error.
set -euo pipefail

cd "$(dirname "$0")/.."

GOLDEN_TIMESTAMP=2026-01-02T03:04:05Z
CORE=crates/rollcall-core/tests
VALIDATOR=scripts/csaf-validator
OUT="${ROLLCALL_CSAF_OUT:-.cache/csaf}"

install=0
for arg in "$@"; do
    case "$arg" in
        --install) install=1 ;;
        *)
            echo "usage: scripts/csaf-check.sh [--install]" >&2
            exit 2
            ;;
    esac
done

if ! command -v node >/dev/null 2>&1; then
    echo "csaf-check: node is not installed" >&2
    exit 2
fi
if [[ "$install" == 1 ]]; then
    npm ci --prefix "$VALIDATOR" --ignore-scripts --no-audit --no-fund >&2 || {
        echo "csaf-check: npm ci failed" >&2
        exit 2
    }
fi
if [[ ! -d "$VALIDATOR/node_modules/@secvisogram/csaf-validator-lib" ]]; then
    echo "csaf-check: the validator is not installed; run with --install" >&2
    exit 2
fi

if [[ -z "${ROLLCALL_BIN:-}" ]]; then
    cargo build -p rollcall --locked >&2 || exit 2
    ROLLCALL_BIN=target/debug/rollcall
fi

rm -rf "$OUT"
mkdir -p "$OUT"

rows=()
failed=0
row() {
    rows+=("$(printf '%-4s  %-20s  %s' "$1" "$2" "$3")")
    [[ "$1" == PASS ]] || failed=1
}

# The SBOM, --scan and --vex arguments of a fixture.
fixture_args() {
    local findings="$CORE/data/findings"
    case "$1" in
        old-mbedtls)
            "$ROLLCALL_BIN" generate --model "$CORE/data/old-mbedtls.model.json" \
                --timestamp "$GOLDEN_TIMESTAMP" -o "$OUT/old-mbedtls.cdx.json"
            args=("$OUT/old-mbedtls.cdx.json"
                --scan "$findings/old-mbedtls.grype.json" --scan "$findings/old-mbedtls.osv.json"
                --vex "$CORE/golden/vex/old-mbedtls.openvex.json")
            ;;
        old-heapless)
            "$ROLLCALL_BIN" generate --model "$CORE/data/old-heapless.model.json" \
                --timestamp "$GOLDEN_TIMESTAMP" -o "$OUT/old-heapless.cdx.json"
            args=("$OUT/old-heapless.cdx.json"
                --scan "$findings/old-heapless.grype.json" --scan "$findings/old-heapless.osv.json")
            ;;
        zephyr-old-mbedtls)
            args=("$CORE/golden/zephyr/old-mbedtls.cdx.json"
                --scan "$findings/zephyr-old-mbedtls.grype.json")
            ;;
    esac
}

documents=()
for name in old-mbedtls old-heapless zephyr-old-mbedtls; do
    doc="$OUT/$name.csaf.json"
    fixture_args "$name"
    if "$ROLLCALL_BIN" csaf "${args[@]}" --timestamp "$GOLDEN_TIMESTAMP" \
        --publisher "Example Devices Ltd" --publisher-namespace https://devices.example \
        -o "$doc" 2>"$OUT/$name.csaf.log"; then
        row PASS "$name" "rollcall csaf"
    else
        row FAIL "$name" "rollcall csaf (see $OUT/$name.csaf.log)"
        continue
    fi
    if [[ "$name" == old-mbedtls ]]; then
        if cmp -s "$doc" "$CORE/golden/csaf/old-mbedtls.csaf.json"; then
            row PASS "$name" "byte-identical to tests/golden/csaf/old-mbedtls.csaf.json"
        else
            row FAIL "$name" "differs from tests/golden/csaf/old-mbedtls.csaf.json"
        fi
    fi
    if "$ROLLCALL_BIN" validate --schema "$doc" >"$OUT/$name.validate.log" 2>&1; then
        row PASS "$name" "rollcall validate --schema"
    else
        row FAIL "$name" "rollcall validate --schema (see $OUT/$name.validate.log)"
    fi
    documents+=("$doc")
done

# The official validator, one document at a time (its own log each).
for doc in "${documents[@]}"; do
    name=$(basename "$doc" .csaf.json)
    if node "$VALIDATOR/validate.mjs" "$doc" >"$OUT/$name.validator.log" 2>&1; then
        row PASS "$name" "csaf-validator-lib: $(sed -n 's/^PASS [^:]*: //p' "$OUT/$name.validator.log")"
    else
        row FAIL "$name" "csaf-validator-lib (see $OUT/$name.validator.log)"
        cat "$OUT/$name.validator.log" >&2
    fi
done

# Negative control: a dangling product reference must fail mandatory test 6.1.1.
control="$OUT/negative-control.csaf.json"
if [[ -f "$OUT/old-mbedtls.csaf.json" ]]; then
    node -e '
        const fs = require("fs");
        const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        doc.vulnerabilities[0].product_status = {under_investigation: ["no-such-product"]};
        fs.writeFileSync(process.argv[2], JSON.stringify(doc, null, 2) + "\n");
    ' "$OUT/old-mbedtls.csaf.json" "$control"
    rc=0
    node "$VALIDATOR/validate.mjs" "$control" >"$OUT/negative-control.log" 2>&1 || rc=$?
    if [[ "$rc" == 1 ]] && grep -q 'mandatoryTest_6_1_1' "$OUT/negative-control.log"; then
        row PASS "negative-control" "dangling product id rejected (mandatoryTest_6_1_1)"
    else
        row FAIL "negative-control" "not rejected as expected (exit $rc; see $OUT/negative-control.log)"
    fi
else
    row FAIL "negative-control" "no old-mbedtls document to break"
fi

# The reference rows (docs/cra-clock.md): one known row, exactly.
expected_row=$'CVE-2022-46392\tknown_affected\tcomponent:9404b57b22a8bf72df5b6d6c93f4defd@product:cb91904541becd528b35755f21604693\tpkg:github/mbed-tls/mbedtls@v2.28.0\tcpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*'
if [[ -f "$OUT/old-mbedtls.csaf.json" ]] &&
    scripts/csaf-summary.sh "$OUT/old-mbedtls.csaf.json" >"$OUT/old-mbedtls.summary.tsv" &&
    grep -qxF "$expected_row" "$OUT/old-mbedtls.summary.tsv"; then
    row PASS "old-mbedtls" "csaf-summary.sh: CVE-2022-46392 row as expected"
else
    row FAIL "old-mbedtls" "csaf-summary.sh: CVE-2022-46392 row missing (see $OUT/old-mbedtls.summary.tsv)"
fi

printf '%s\n' "${rows[@]}"
exit "$failed"
