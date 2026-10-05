#!/usr/bin/env bash
# Runs the worked examples of a Markdown document and checks their output (SHA-115; CI job
# docs-examples). Offline.
#
# Usage: scripts/check-doc-examples.sh [FILE.md ...]     (default: docs/vex-rules.md)
#
# Every ```console block is an example. In it, a line starting with `$ ` is a command (a line
# ending in `\` continues it on the next line); the lines after it, up to the next command or
# the end of the block, are the exact stdout it must print. stderr is not compared (it is
# kept in the log and shown when a command fails).
#
# Each command runs with `bash -euo pipefail`, in one temporary directory per document that
# holds symbolic links to the repository's `fixtures/` and `crates/`, so repository paths in
# the examples work and files they write (an SBOM, say) stay out of the repository and are
# shared by the document's later examples. `rollcall` is first on PATH.
#
# Environment:
#   ROLLCALL_BIN   the rollcall binary (default: built with `cargo build -p rollcall`)
#
# Prints a PASS/FAIL row per command; exits 1 if any output differs or a command fails, 2 on
# a setup error. Needs bash, jq (the examples use it), diff and awk.
set -euo pipefail

die() {
    echo "check-doc-examples: $*" >&2
    exit 2
}

# absolute <path>: <path> made absolute against the directory the script was started in.
absolute() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s\n' "$PWD/$1" ;;
    esac
}

# Arguments and ROLLCALL_BIN are relative to where the script was started, so resolve them
# before moving to the repository root.
docs=()
for arg in "$@"; do
    case "$arg" in
        -h | --help) ;;
        *) docs+=("$(absolute "$arg")") ;;
    esac
done
if [[ -n "${ROLLCALL_BIN:-}" ]]; then
    ROLLCALL_BIN="$(absolute "$ROLLCALL_BIN")"
fi

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

case "${1:-}" in
    -h | --help)
        sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
        exit 0
        ;;
esac

for tool in jq diff awk; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

if [[ ${#docs[@]} -eq 0 ]]; then
    docs=("$ROOT/docs/vex-rules.md")
fi

if [[ -n "${ROLLCALL_BIN:-}" ]]; then
    ROLLCALL="$ROLLCALL_BIN"
else
    cargo build -q -p rollcall --locked || die "cargo build failed"
    ROLLCALL="${CARGO_TARGET_DIR:-target}/debug/rollcall"
fi
[[ -x "$ROLLCALL" ]] || die "rollcall binary not found at $ROLLCALL"
ROLLCALL="$(cd "$(dirname "$ROLLCALL")" && pwd)/$(basename "$ROLLCALL")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# `rollcall` on PATH is the binary under test, whatever its file name.
mkdir "$WORK/bin"
ln -s "$ROLLCALL" "$WORK/bin/rollcall"
# The examples must not depend on the caller's identifier database or cache.
mkdir "$WORK/cache"
unset ROLLCALL_IDENTIFIERS
export ROLLCALL_CACHE_DIR="$WORK/cache"
export XDG_CACHE_HOME="$WORK/cache"

failed=0
total=0
ROWS=()
d=0

for doc in "${docs[@]}"; do
    [[ -f "$doc" ]] || die "$doc not found"
    # Numbered, so two documents with the same file name do not collide.
    d=$((d + 1))
    split="$WORK/split/$d"
    run="$WORK/run/$d"
    shown="${doc#"$ROOT"/}"
    mkdir -p "$split" "$run"
    ln -s "$ROOT/fixtures" "$run/fixtures"
    ln -s "$ROOT/crates" "$run/crates"
    # Split the console blocks into N.cmd (the command), N.exp (its expected stdout) and
    # N.line (its line in the document). A block that does not start with a command, has
    # none, or is not closed cannot be checked, and fails the run.
    awk -v dir="$split" '
        function close_cmd() { if (n > 0) { close(dir "/" n ".cmd"); close(dir "/" n ".exp") } }
        function fail(msg) { err = "line " NR ": " msg; exit 3 }
        /^```console[[:space:]]*$/ && !inblock { inblock = 1; incmds = 0; cont = 0; next }
        /^```[[:space:]]*$/ && inblock {
            if (!incmds) fail("console block without a `$ ` command")
            if (cont) fail("command continues past the end of its block")
            inblock = 0; cont = 0; next
        }
        !inblock { next }
        cont {
            print > (dir "/" n ".cmd")
            cont = ($0 ~ /\\$/)
            next
        }
        /^\$ / {
            close_cmd()
            incmds = 1
            n++
            printf "" > (dir "/" n ".exp")
            print NR > (dir "/" n ".line")
            close(dir "/" n ".line")
            print substr($0, 3) > (dir "/" n ".cmd")
            cont = ($0 ~ /\\$/)
            next
        }
        !incmds { fail("console block line before its first `$ ` command") }
        { print > (dir "/" n ".exp") }
        END {
            if (err == "" && inblock) err = "unterminated console block"
            if (err != "") { print err > "/dev/stderr"; exit 3 }
            print n + 0 > (dir "/count")
        }
    ' "$doc" || die "$shown: cannot check its console blocks"
    count="$(cat "$split/count")"
    [[ "$count" -gt 0 ]] || die "$shown has no console examples"
    for ((i = 1; i <= count; i++)); do
        total=$((total + 1))
        line="$(cat "$split/$i.line")"
        label="$shown:$line"
        rc=0
        (cd "$run" && PATH="$WORK/bin:$PATH" bash -euo pipefail -c "$(cat "$split/$i.cmd")") \
            >"$split/$i.out" 2>"$split/$i.err" || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            ROWS+=("$label|FAIL|exit $rc")
            failed=1
            echo "--- $label: \$ $(head -n 1 "$split/$i.cmd")" >&2
            echo "exit $rc; stderr:" >&2
            sed 's/^/    /' "$split/$i.err" >&2
        elif diff -u "$split/$i.exp" "$split/$i.out" >"$split/$i.diff"; then
            ROWS+=("$label|PASS|$(wc -l <"$split/$i.exp" | tr -d ' ') line(s) of output")
        else
            ROWS+=("$label|FAIL|output differs")
            failed=1
            echo "--- $label: \$ $(head -n 1 "$split/$i.cmd")" >&2
            echo "expected (-) vs actual (+):" >&2
            sed 's/^/    /' "$split/$i.diff" >&2
        fi
    done
done

printf '%-28s  %-6s  %s\n' EXAMPLE RESULT DETAIL
printf '%-28s  %-6s  %s\n' ---------------------------- ------ ------
for row in "${ROWS[@]}"; do
    IFS='|' read -r label result detail <<<"$row"
    printf '%-28s  %-6s  %s\n' "$label" "$result" "$detail"
done
echo
if [[ "$failed" -ne 0 ]]; then
    echo "check-doc-examples: FAIL"
    exit 1
fi
echo "check-doc-examples: PASS ($total command(s))"
