#!/usr/bin/env bash
# The release version: the workspace version, its PEP 440 form for the PyPI wrapper, and the
# check that a release tag and every place the version is written agree.
#
# Usage:
#   scripts/release-version.sh version          the workspace version (Cargo.toml)
#   scripts/release-version.sh pep440 [VERSION]  VERSION (default: the workspace version) in
#                                                PEP 440 form: 0.1.0-rc.1 -> 0.1.0rc1,
#                                                -alpha.N -> aN, -beta.N -> bN
#   scripts/release-version.sh check [TAG]       TAG (default: v<workspace version>) is
#                                                v<workspace version>, and the versions of
#                                                rollcall-core and rollcall-assay in
#                                                [workspace.dependencies], python/pyproject.toml
#                                                and python/src/rollcall/__init__.py
#                                                (__version__ and TAG) all agree with it
#
# `check` prints tag=, version=, pep440= and prerelease=true|false lines, to $GITHUB_OUTPUT
# when it is set (the release workflow's step outputs), else to stdout.
#
# A release version is MAJOR.MINOR.PATCH, optionally followed by -alpha.N, -beta.N or -rc.N:
# the pre-releases that have a PEP 440 form and that cargo and pip both order correctly.
#
# Environment:
#   ROLLCALL_ROOT   the repository root to read (default: this script's repository; tests)
#
# Exit codes: 0 agree; 1 something disagrees (every mismatch is listed); 64 usage error;
# 65 a version or tag that is not a release version; 66 no Cargo.toml.
set -euo pipefail

ROOT="${ROLLCALL_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
SEMVER_RE='^([0-9]+)\.([0-9]+)\.([0-9]+)(-(alpha|beta|rc)\.([0-9]+))?$'

die() {
    local code="$1"
    shift
    echo "release-version: $*" >&2
    exit "$code"
}

usage() {
    die 64 "usage: release-version.sh version | pep440 [VERSION] | check [TAG]"
}

# value_in FILE SECTION KEY: the double-quoted string value of KEY in [SECTION] of a TOML
# file (only the plain `key = "value"` form, which is all the files read here use).
value_in() {
    awk -v section="[$2]" -v key="$3" '
        /^\[/ { inside = ($0 == section) }
        inside && $0 ~ "^" key "[ \t]*=" {
            line = $0
            sub(/^[^=]*=[ \t]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }' "$1"
}

workspace_version() {
    local v
    [[ -f "$ROOT/Cargo.toml" ]] || die 66 "no $ROOT/Cargo.toml"
    v="$(value_in "$ROOT/Cargo.toml" workspace.package version)"
    [[ -n "$v" ]] || die 65 "Cargo.toml has no [workspace.package] version"
    echo "$v"
}

# pep440 VERSION: the PEP 440 spelling of a release version, or exit 65.
pep440() {
    [[ "$1" =~ $SEMVER_RE ]] ||
        die 65 "'$1' is not a release version (MAJOR.MINOR.PATCH, optionally -alpha.N, -beta.N or -rc.N)"
    local base="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}"
    case "${BASH_REMATCH[5]}" in
        "") echo "$base" ;;
        alpha) echo "${base}a${BASH_REMATCH[6]}" ;;
        beta) echo "${base}b${BASH_REMATCH[6]}" ;;
        rc) echo "${base}rc${BASH_REMATCH[6]}" ;;
    esac
}

# dependency_version NAME: the version field of NAME in [workspace.dependencies].
dependency_version() {
    awk -v name="$1" '
        /^\[/ { inside = ($0 == "[workspace.dependencies]") }
        inside && $0 ~ "^" name "[ \t]*=" {
            if (match($0, /version[ \t]*=[ \t]*"[^"]*"/)) {
                v = substr($0, RSTART, RLENGTH)
                sub(/^version[ \t]*=[ \t]*"/, "", v)
                sub(/"$/, "", v)
                print v
            }
            exit
        }' "$ROOT/Cargo.toml"
}

# python_assign FILE NAME: the double-quoted string assigned to NAME at the top level.
python_assign() {
    sed -n "s/^$2 = \"\\(.*\\)\"\$/\\1/p" "$1" | head -n 1
}

emit() {
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

check() {
    local version tag py problems=()
    version="$(workspace_version)"
    tag="${1:-v$version}"
    [[ "$tag" == v* && "${tag#v}" =~ $SEMVER_RE ]] ||
        die 65 "tag '$tag' is not a release tag (v followed by a release version, e.g. v0.1.0 or v0.1.0-rc.1)"
    py="$(pep440 "$version")"
    [[ "$tag" == "v$version" ]] ||
        problems+=("tag $tag does not match the workspace version $version (Cargo.toml [workspace.package]); tag v$version, or bump the version")
    local dep got
    for dep in rollcall-core rollcall-assay; do
        got="$(dependency_version "$dep")"
        [[ "$got" == "$version" ]] ||
            problems+=("Cargo.toml [workspace.dependencies] $dep has version '${got}', not $version")
    done
    local pyproject="$ROOT/python/pyproject.toml" init="$ROOT/python/src/rollcall/__init__.py"
    if [[ -f "$pyproject" ]]; then
        got="$(value_in "$pyproject" project version)"
        [[ "$got" == "$py" ]] || problems+=("python/pyproject.toml version is '${got}', not $py")
    else
        problems+=("python/pyproject.toml is missing")
    fi
    if [[ -f "$init" ]]; then
        got="$(python_assign "$init" __version__)"
        [[ "$got" == "$py" ]] || problems+=("python/src/rollcall/__init__.py __version__ is '${got}', not $py")
        got="$(python_assign "$init" TAG)"
        [[ "$got" == "v$version" ]] || problems+=("python/src/rollcall/__init__.py TAG is '${got}', not v$version")
    else
        problems+=("python/src/rollcall/__init__.py is missing")
    fi
    if [[ ${#problems[@]} -gt 0 ]]; then
        local p
        for p in "${problems[@]}"; do
            echo "::error::release-version: $p" >&2
        done
        exit 1
    fi
    emit tag "$tag"
    emit version "$version"
    emit pep440 "$py"
    if [[ "$version" == *-* ]]; then
        emit prerelease true
    else
        emit prerelease false
    fi
}

[[ $# -ge 1 ]] || usage
case "$1" in
    version)
        [[ $# -eq 1 ]] || usage
        workspace_version
        ;;
    pep440)
        [[ $# -le 2 ]] || usage
        if [[ $# -eq 2 ]]; then
            v="$2"
        else
            v="$(workspace_version)"
        fi
        pep440 "$v"
        ;;
    check)
        [[ $# -le 2 ]] || usage
        check "${2:-}"
        ;;
    *) usage ;;
esac
