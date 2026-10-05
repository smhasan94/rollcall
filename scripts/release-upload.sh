#!/usr/bin/env bash
# The GitHub Release's assets, which are never replaced once published.
#
# Usage:
#   scripts/release-upload.sh adopt TAG DIR     (release workflow, assemble job)
#   scripts/release-upload.sh check TAG DIR     (github-release job, before attesting)
#   scripts/release-upload.sh publish TAG DIR   (github-release job)
#
# DIR holds this run's four assets and their SHA256SUMS (scripts/release-sums.sh DIR TAG).
# A release "has assets" once its SHA256SUMS is uploaded; `publish` uploads it last, so a
# release with a SHA256SUMS has all four assets. The PyPI wrapper embeds the SHA256SUMS it was
# built from and can never be replaced on PyPI, so the published assets must never change:
#
#   adopt    If TAG's release already has assets, download them over DIR (checked against the
#            release's SHA256SUMS) so the wheel built next embeds exactly what is published; a
#            rebuild that differs (MSVC, lipo and LTO builds are not guaranteed reproducible)
#            is discarded with a warning. Otherwise DIR is left as built.
#   check    Prints upload=true when the release does not exist or has no assets yet,
#            upload=false when its SHA256SUMS is identical to DIR's; fails (exit 1) when they
#            differ. Written to $GITHUB_OUTPUT when set, else stdout.
#   publish  As check, then: creates the release if missing (--verify-tag; --prerelease when
#            PRERELEASE=true; notes from docs/releases/TAG.md when present, else generated) and
#            uploads DIR's assets, SHA256SUMS last; or, when identical, uploads nothing.
#
# Environment: GH_TOKEN and GH_REPO for gh; PRERELEASE (true|false) for publish.
#
# Exit codes: 0 done; 1 the release already has different assets, or the published ones do not
# match their SHA256SUMS; 2 gh failed (other than "release not found"); 64 usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

die() {
    local code="$1"
    shift
    echo "::error::release-upload: $*" >&2
    exit "$code"
}

[[ $# -eq 3 ]] || die 64 "usage: release-upload.sh adopt|check|publish TAG DIR"
mode="$1" tag="$2" dir="$3"
case "$mode" in adopt | check | publish) ;; *) die 64 "usage: release-upload.sh adopt|check|publish TAG DIR" ;; esac
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
    die 64 "TAG must be a release tag such as v0.1.0, not '$tag'"
[[ -d "$dir" ]] || die 64 "no such directory: $dir"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# state: sets STATE to missing (no release), empty (a release without SHA256SUMS) or
# published (the release's SHA256SUMS is in $work/published/SHA256SUMS).
state() {
    local err="$work/gh.err" names
    if ! names="$(gh release view "$tag" --json assets --jq '.assets[].name' 2>"$err")"; then
        if grep -qi "release not found" "$err"; then
            STATE=missing
            return
        fi
        cat "$err" >&2
        die 2 "gh release view $tag failed"
    fi
    if ! grep -qx SHA256SUMS <<<"$names"; then
        STATE=empty
        return
    fi
    mkdir -p "$work/published"
    gh release download "$tag" -p SHA256SUMS -D "$work/published" --clobber ||
        die 2 "cannot download SHA256SUMS of $tag"
    STATE=published
}

# same: whether the published SHA256SUMS is byte-identical to DIR's.
same() {
    cmp -s "$work/published/SHA256SUMS" "$dir/SHA256SUMS"
}

differ() {
    diff "$work/published/SHA256SUMS" "$dir/SHA256SUMS" >&2 || true
    die 1 "release $tag already has different assets (SHA256SUMS differ); a changed binary needs a new version. To finish a partial run use \`gh run rerun --failed\`."
}

emit() {
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

[[ -f "$dir/SHA256SUMS" ]] || die 64 "$dir has no SHA256SUMS (scripts/release-sums.sh $dir $tag)"
state

case "$mode" in
    adopt)
        if [[ "$STATE" != published ]]; then
            echo "release-upload: $tag has no assets yet; using this run's"
            exit 0
        fi
        if same; then
            echo "release-upload: this run's assets are identical to the published ones of $tag"
            exit 0
        fi
        echo "::warning::release-upload: the rebuilt assets differ from those published for $tag; using the published ones (the PyPI wrapper must match them)" >&2
        diff "$work/published/SHA256SUMS" "$dir/SHA256SUMS" >&2 || true
        find "$dir" -maxdepth 1 -type f \( -name 'rollcall-*' -o -name SHA256SUMS \) -exec rm -f {} +
        gh release download "$tag" -p 'rollcall-*' -D "$dir" --clobber ||
            die 2 "cannot download the assets of $tag"
        "$ROOT/scripts/release-sums.sh" "$dir" "$tag" >/dev/null ||
            die 1 "the published assets of $tag are not its four assets"
        cmp -s "$work/published/SHA256SUMS" "$dir/SHA256SUMS" ||
            die 1 "the published assets of $tag do not match its SHA256SUMS"
        echo "release-upload: using the published assets of $tag"
        ;;
    check)
        case "$STATE" in
            missing | empty) emit upload true ;;
            published) if same; then emit upload false; else differ; fi ;;
        esac
        ;;
    publish)
        if [[ "$STATE" == published ]]; then
            same || differ
            echo "release-upload: $tag already has these assets (identical SHA256SUMS); nothing uploaded"
            exit 0
        fi
        if [[ "$STATE" == missing ]]; then
            args=(--verify-tag --title "rollcall $tag")
            [[ "${PRERELEASE:-false}" != true ]] || args+=(--prerelease)
            if [[ -f "$ROOT/docs/releases/$tag.md" ]]; then
                args+=(--notes-file "$ROOT/docs/releases/$tag.md")
            else
                args+=(--generate-notes)
            fi
            gh release create "$tag" "${args[@]}" || die 2 "gh release create $tag failed"
        else
            echo "release-upload: $tag exists without assets (an earlier run stopped before SHA256SUMS); uploading"
        fi
        assets=()
        while IFS= read -r f; do assets+=("$f"); done < <(
            find "$dir" -maxdepth 1 -type f \( -name 'rollcall-*.tar.gz' -o -name 'rollcall-*.zip' \) | LC_ALL=C sort
        )
        [[ ${#assets[@]} -gt 0 ]] || die 64 "no assets in $dir"
        gh release upload "$tag" "${assets[@]}" --clobber || die 2 "uploading the assets of $tag failed"
        gh release upload "$tag" "$dir/SHA256SUMS" --clobber || die 2 "uploading SHA256SUMS of $tag failed"
        echo "release-upload: uploaded ${#assets[@]} assets and SHA256SUMS to $tag"
        ;;
esac
