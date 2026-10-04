#!/usr/bin/env bash
# rollcall-action step 2: generate the SBOM, validate it, scan it with grype, write VEX for the
# findings, triage the scan with that VEX, and report on it. Everything lands in $RC_OUT_DIR:
#
#   sbom.cdx.json       rollcall generate
#   validate.json       rollcall validate --profile all --json (recorded, not fatal)
#   grype.json          grype on the SBOM (the findings `rollcall vex` triages)
#   vex.openvex.json    rollcall vex --starter-rules [--rules ...] --format openvex
#   scan.json           rollcall scan --vex vex.openvex.json --json (rollcall-scan/1)
#   report.md / .json   rollcall report --scan scan.json --vex vex.openvex.json
#
# `rollcall validate --schema` failing (the SBOM breaks CycloneDX 1.6) fails the step, as does
# any other command failing; `rollcall scan` exiting 3 (a scanner failed) is fatal too.
#
# Inputs (environment): RC_BUILD_DIR (required), RC_ECOSYSTEM (auto|zephyr|cargo),
# RC_IDENTIFIERS (`embedded` or a directory, from install.sh), RC_VEX_RULES (newline-separated
# paths), RC_STARTER_RULES (true|false), RC_WEST_LIST, RC_SYSBUILD (auto|true|false),
# RC_PRODUCT, RC_ELF, RC_TARGET, RC_SCANNER (grype|auto), RC_TIMESTAMP, RC_OUT_DIR,
# ROLLCALL_BIN (default rollcall on PATH). grype (and osv-scanner) must be on PATH.
#
# Outputs: ecosystem, sbom, vex, scan, report, report-json, score.
set -euo pipefail
# shellcheck source=action/scripts/common.sh
. "$(dirname "$0")/common.sh"

ROLLCALL="${ROLLCALL_BIN:-rollcall}"

# detect_ecosystem DIR CHOICE: zephyr, cargo (a package directory) or cargo-metadata (captured
# `cargo metadata` output); exits 64 when DIR is neither.
detect_ecosystem() {
    local dir="$1" choice="$2"
    case "$choice" in
        auto)
            if [[ -f "$dir/build_info.yml" ]]; then
                echo zephyr
                return
            fi
            ;;
        zephyr)
            [[ -f "$dir/build_info.yml" ]] || die 64 "ecosystem zephyr: $dir has no build_info.yml"
            echo zephyr
            return
            ;;
        cargo) ;;
        *) die 64 "ecosystem must be auto, zephyr or cargo, not '$choice'" ;;
    esac
    if [[ -f "$dir/Cargo.toml" ]]; then
        echo cargo
    elif [[ -f "$dir/cargo-metadata.json" ]]; then
        echo cargo-metadata
    else
        die 64 "cannot tell the ecosystem of $dir: no build_info.yml (Zephyr), Cargo.toml or cargo-metadata.json (Cargo)"
    fi
}

# is_sysbuild DIR: whether the Zephyr build is a sysbuild (RC_SYSBUILD, auto: domains.yaml).
is_sysbuild() {
    case "${RC_SYSBUILD:-auto}" in
        true) return 0 ;;
        false) return 1 ;;
        auto) [[ -f "$1/domains.yaml" ]] ;;
        *) die 64 "sysbuild must be auto, true or false, not '${RC_SYSBUILD}'" ;;
    esac
}

# Arrays every helper appends to (global, so a `die` in a helper stops the script). Expanded
# as ${A[@]+"${A[@]}"}, which bash 3.2 (macOS) accepts for an empty array under `set -u`.
GEN=()
KCONFIG=()
RULES=()
STAMP=()
IDENTIFIERS=()

# generate_args ECOSYSTEM DIR: appends the `rollcall generate` arguments to GEN.
generate_args() {
    local eco="$1" dir="$2"
    case "$eco" in
        zephyr)
            GEN+=(--zephyr "$dir")
            if is_sysbuild "$dir"; then
                GEN+=(--sysbuild)
            fi
            local west="${RC_WEST_LIST:-}"
            if [[ -z "$west" && -f "$dir/west-list.txt" ]]; then
                west="$dir/west-list.txt"
            fi
            if [[ -n "$west" ]]; then
                GEN+=(--west-list "$west")
            fi
            GEN+=(--identify)
            if [[ -n "${RC_PRODUCT:-}" ]]; then
                GEN+=(--product "$RC_PRODUCT")
            fi
            IDENTIFIERS=(--identifiers "${RC_IDENTIFIERS:-embedded}")
            ;;
        cargo)
            GEN+=(--cargo "$dir")
            if [[ -n "${RC_TARGET:-}" ]]; then
                GEN+=(--target "$RC_TARGET")
            fi
            if [[ -n "${RC_ELF:-}" ]]; then
                GEN+=(--elf "$RC_ELF")
            fi
            ;;
        cargo-metadata)
            GEN+=(--cargo-metadata "$dir/cargo-metadata.json")
            if [[ -n "${RC_ELF:-}" ]]; then
                GEN+=(--elf "$RC_ELF")
            fi
            if [[ -n "${RC_TARGET:-}" ]]; then
                echo "::warning::rollcall-action: target is ignored with a captured cargo-metadata.json (it was resolved when captured)" >&2
            fi
            ;;
    esac
    GEN+=(${STAMP[@]+"${STAMP[@]}"})
}

# kconfig_args ECOSYSTEM DIR: appends `rollcall vex --kconfig` arguments to KCONFIG: for a
# sysbuild, IMAGE=DIR/IMAGE/zephyr/.config for each image domains.yaml lists that has one; for
# a single image, DIR/zephyr/.config; for Cargo, none.
kconfig_args() {
    local eco="$1" dir="$2"
    [[ "$eco" == zephyr ]] || return 0
    if is_sysbuild "$dir"; then
        [[ -f "$dir/domains.yaml" ]] || return 0
        local image
        for image in $(sed -n 's/^[[:space:]]*-[[:space:]]*name:[[:space:]]*\([A-Za-z0-9_.-]*\).*$/\1/p' "$dir/domains.yaml" | sort -u); do
            if [[ -f "$dir/$image/zephyr/.config" ]]; then
                KCONFIG+=(--kconfig "$image=$dir/$image/zephyr/.config")
            fi
        done
    elif [[ -f "$dir/zephyr/.config" ]]; then
        KCONFIG+=(--kconfig "$dir/zephyr/.config")
    fi
}

# vex_rule_args: appends --starter-rules and one --rules per non-empty line of RC_VEX_RULES
# to RULES.
vex_rule_args() {
    case "${RC_STARTER_RULES:-true}" in
        true) RULES+=(--starter-rules) ;;
        false) ;;
        *) die 64 "starter-rules must be true or false, not '${RC_STARTER_RULES}'" ;;
    esac
    local line
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        if [[ -n "$line" ]]; then
            [[ -f "$line" ]] || die 66 "vex-rules: $line does not exist"
            RULES+=(--rules "$line")
        fi
    done <<<"${RC_VEX_RULES:-}"
}

main() {
    local dir="${RC_BUILD_DIR:-}"
    [[ -n "$dir" ]] || die 64 "build-dir is required"
    [[ -d "$dir" ]] || die 66 "build-dir $dir is not a directory"
    case "${RC_SCANNER:-grype}" in
        grype | auto) ;;
        *) die 64 "scanner must be grype or auto, not '${RC_SCANNER}'" ;;
    esac
    mkdir -p "$OUT"
    if [[ -n "${RC_TIMESTAMP:-}" ]]; then
        STAMP=(--timestamp "$RC_TIMESTAMP")
    fi

    local eco
    eco="$(detect_ecosystem "$dir" "${RC_ECOSYSTEM:-auto}")"
    log "ecosystem: $eco ($dir)"
    write_output ecosystem "$eco"
    generate_args "$eco" "$dir"
    kconfig_args "$eco" "$dir"
    vex_rule_args

    local sbom="$OUT/sbom.cdx.json" status=0
    log "rollcall ${IDENTIFIERS[*]+${IDENTIFIERS[*]}} generate ${GEN[*]}"
    "$ROLLCALL" ${IDENTIFIERS[@]+"${IDENTIFIERS[@]}"} generate "${GEN[@]}" -o "$sbom" || status=$?
    [[ "$status" -eq 0 ]] || die "rollcall generate failed (exit $status)"
    write_output sbom "$sbom"

    "$ROLLCALL" validate --schema "$sbom" >&2 || status=$?
    [[ "$status" -eq 0 ]] || die "the SBOM is not valid CycloneDX 1.6 (rollcall validate --schema exit $status)"
    "$ROLLCALL" validate --profile all --json "$sbom" >"$OUT/validate.json" || status=$?
    case "$status" in
        0) log "validate --profile all: passed" ;;
        1) log "validate --profile all: findings recorded in $OUT/validate.json (not fatal)" ;;
        *) die "rollcall validate --profile all failed (exit $status)" ;;
    esac

    # grype's own output, for rollcall vex; rollcall scan runs it again with the VEX.
    status=0
    printf '{}\n' >"$OUT/grype.yaml"
    GRYPE_CHECK_FOR_APP_UPDATE=false grype -c "$OUT/grype.yaml" "sbom:$sbom" -o json \
        >"$OUT/grype.json" || status=$?
    [[ "$status" -eq 0 ]] || die "grype failed (exit $status)"

    local vex="$OUT/vex.openvex.json"
    "$ROLLCALL" vex --sbom "$sbom" --findings "$OUT/grype.json" ${RULES[@]+"${RULES[@]}"} \
        ${KCONFIG[@]+"${KCONFIG[@]}"} --format openvex --author rollcall-action \
        ${STAMP[@]+"${STAMP[@]}"} -o "$vex" || status=$?
    [[ "$status" -eq 0 ]] || die "rollcall vex failed (exit $status)"
    write_output vex "$vex"

    "$ROLLCALL" scan "$sbom" --scanner "${RC_SCANNER:-grype}" --vex "$vex" --json \
        >"$OUT/scan.json" || status=$?
    [[ "$status" -ne 3 ]] || die "rollcall scan: a scanner failed (exit 3)"
    [[ "$status" -le 3 ]] || die "rollcall scan failed (exit $status)"
    status=0
    write_output scan "$OUT/scan.json"

    local format
    for format in md json; do
        "$ROLLCALL" report "$sbom" --scan "$OUT/scan.json" --vex "$vex" --format "$format" \
            ${STAMP[@]+"${STAMP[@]}"} -o "$OUT/report.$format" || status=$?
        [[ "$status" -eq 0 ]] || die "rollcall report failed (exit $status)"
    done
    write_output report "$OUT/report.md"
    write_output report-json "$OUT/report.json"
    write_output score "$(jq -r '.score.value' "$OUT/report.json")"
}

main "$@"
