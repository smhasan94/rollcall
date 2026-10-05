# Shared helpers for the rollcall-action scripts. Sourced, not run.
#
# Every script reads its inputs from RC_* environment variables (set by action.yml from the
# action's inputs; never interpolated into the shell source, so no input can inject a
# command) and the usual GITHUB_* variables, and writes step outputs with write_output.
# shellcheck shell=bash

# The action's directory: action.yml sets GITHUB_ACTION_PATH; tests run the scripts in place.
RC_ACTION_DIR="${GITHUB_ACTION_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export RC_ACTION_DIR

# The output directory every step shares.
OUT="${RC_OUT_DIR:-.rollcall-action}"

# log MESSAGE...: a line on stderr, prefixed with the script's name.
log() {
    echo "rollcall-action: $*" >&2
}

# die [CODE] MESSAGE: a workflow error annotation, then exit CODE (default 1).
die() {
    local code=1
    if [[ $# -gt 1 && "$1" =~ ^[0-9]+$ ]]; then
        code="$1"
        shift
    fi
    echo "::error::rollcall-action: $*" >&2
    exit "$code"
}

# check_artifact_name NAME: exits 64 unless NAME is letters, digits, `.`, `_` and `-` only (it
# is embedded in the comment's marker and used as the artifact's name).
check_artifact_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] ||
        die 64 "artifact-name must be letters, digits, '.', '_' and '-' only, not '$1'"
}

# write_output KEY VALUE: a step output (to $GITHUB_OUTPUT, or stdout outside Actions).
# VALUE must be one line.
write_output() {
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

# sha256_of FILE: its SHA-256, lowercase hex.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# sha256_check FILE EXPECTED: exits 1 (removing FILE) unless FILE's SHA-256 is EXPECTED.
sha256_check() {
    local got
    got="$(sha256_of "$1")"
    if [[ "$got" != "$2" ]]; then
        rm -f "$1"
        die "sha256 mismatch for $(basename "$1"): expected $2, got $got"
    fi
}

# gh_api ARGS...: `gh api` with the action's token, retried once on failure (the API is a
# network call). Prints the response on stdout; returns gh's status.
gh_api() {
    local attempt
    for attempt in 1 2; do
        if GH_TOKEN="${RC_GITHUB_TOKEN:-${GH_TOKEN:-}}" gh api "$@"; then
            return 0
        fi
        [[ "$attempt" -eq 1 ]] && sleep "${RC_RETRY_DELAY:-3}"
    done
    return 1
}

# platform: os and arch as the release assets name them (linux|darwin, amd64|arm64).
platform() {
    local os arch
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
    echo "${os}_${arch}"
}

# rollcall_platform: the platform of the rollcall release asset for this machine, as
# platform() spells it, except that both Macs use the one universal binary (darwin_universal).
# The pinned tools (grype, osv-scanner) keep platform(): they ship one asset per architecture.
rollcall_platform() {
    local plat
    plat="$(platform)"
    case "$plat" in
        darwin_*) echo darwin_universal ;;
        *) echo "$plat" ;;
    esac
}
