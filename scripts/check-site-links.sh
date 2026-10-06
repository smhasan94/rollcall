#!/usr/bin/env bash
# Checks every link of the built docs site (target/book, from scripts/build-docs.sh) with
# lychee (SHA-125; CI workflow docs.yml, step "Check site links (lychee)").
#
# Usage: scripts/check-site-links.sh [--install] [--offline] [DIR]
#
#   --install   download the pinned lychee into $ROLLCALL_TOOLS_DIR (default .cache/tools),
#               verifying the download's SHA-256. Without it, lychee is taken from
#               $ROLLCALL_TOOLS_DIR, then from PATH. Needs the network.
#   --offline   check only the links inside the site.
#   DIR         the built site (default target/book).
#
# Two passes:
#
# 1. Inside the site, offline: every link between pages and to the site's files resolves,
#    and every #fragment names an element of its page.
# 2. Outside the site, online (skipped with --offline): every http(s) link answers 2xx (429,
#    rate limiting, is accepted), with retries. Three kinds of link are not fetched:
#    - links into this repository's files on GitHub (github.com/smhasan94/rollcall/blob/,
#      tree/ and edit/): scripts/mdbook-repo-links.py writes them only after checking the
#      file exists in the checkout, and they 404 on GitHub until the change is merged;
#    - the patterns in .lycheeignore: pages that exist only once a human step is done (the
#      released tag, the example repository, the live site). Remove each line when it is.
#    - links to the hosts in scripts/link-check-outage-hosts.txt, which are down for everyone
#      (the file gives the date and the evidence); the run prints which hosts it left out.
#      An empty list (comments only) leaves nothing out. $ROLLCALL_OUTAGE_HOSTS_FILE, if set,
#      names another list instead (relative to the repository root); the tests use it.
#    GITHUB_TOKEN, if set, is passed to lychee for github.com links (rate limits).
#    Hosts in scripts/link-check-blocked-hosts.txt (they reject GitHub's CI runners) are
#    checked in a separate lychee run that also accepts HTTP 403, so the two link checkers
#    tolerate the same thing: a 403 from those hosts only. Every other link accepts 2xx and 429.
#    A host on both lists is left out of that run too (lychee's --include beats --exclude).
#    Host names are read lowercased, as scripts/check-doc-links.sh reads them.
#
# Either way, a lychee whose reported version is not the pinned one is refused.
# Exits 1 if a link is broken, 2 on a setup error.
set -euo pipefail

cd "$(dirname "$0")/.."

LYCHEE_VERSION=0.24.2
REPO_FILES='^https://github\.com/smhasan94/rollcall/(blob|tree|edit)/'
OUTAGE_HOSTS="${ROLLCALL_OUTAGE_HOSTS_FILE:-scripts/link-check-outage-hosts.txt}"
BLOCKED_HOSTS=scripts/link-check-blocked-hosts.txt

# SHA-256 of the lychee release tarballs (GitHub release asset digests).
lychee_sha256() {
    case "$1" in
        x86_64-unknown-linux-musl) echo 73657a111819a30c47c08352896796f23d64e4eb2b3ed39b6d32149241566fc5 ;;
        aarch64-unknown-linux-musl) echo 5d0b0e3aeab240f41920c633a6eaf97599be6eedda034b36e858ede7dba5e535 ;;
        aarch64-apple-darwin) echo c9d3740ea2d891854d37116c9fba840f37b6e7c89d330e7db84ac333631c4977 ;;
        x86_64-apple-darwin) echo 887503a9cff667d322b8d0892b40bf49976eb9507af8483220a3706cdad55978 ;;
        *) return 1 ;;
    esac
}

die() {
    echo "check-site-links: $*" >&2
    exit 2
}

install=0
offline=0
site=target/book
for arg in "$@"; do
    case "$arg" in
        --install) install=1 ;;
        --offline) offline=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*) die "unknown option: $arg" ;;
        *) site="$arg" ;;
    esac
done
[[ -f "$site/index.html" ]] || die "$site/index.html not found; run scripts/build-docs.sh first"
site="$(cd "$site" && pwd)"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64 | Linux/amd64) target=x86_64-unknown-linux-musl ;;
    Linux/aarch64 | Linux/arm64) target=aarch64-unknown-linux-musl ;;
    Darwin/arm64 | Darwin/aarch64) target=aarch64-apple-darwin ;;
    Darwin/x86_64) target=x86_64-apple-darwin ;;
    *) die "unsupported host $(uname -s)/$(uname -m)" ;;
esac

TOOLS_DIR="${ROLLCALL_TOOLS_DIR:-.cache/tools}"
mkdir -p "$TOOLS_DIR"
TOOLS_DIR="$(cd "$TOOLS_DIR" && pwd)"

if [[ "$install" -eq 1 ]]; then
    for tool in curl tar; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is required for --install"
    done
    want="$(lychee_sha256 "$target")" || die "no pinned lychee for $target"
    tarball="lychee-${target}.tar.gz"
    tmp="$(mktemp "$TOOLS_DIR/.download.XXXXXX")"
    if ! curl -fsSL --retry 3 -o "$tmp" \
        "https://github.com/lycheeverse/lychee/releases/download/lychee-v${LYCHEE_VERSION}/${tarball}"; then
        rm -f "$tmp"
        die "download failed: $tarball"
    fi
    got="$(sha256_of "$tmp")"
    if [[ "$got" != "$want" ]]; then
        rm -f "$tmp"
        die "sha256 mismatch for $tarball: expected $want, got $got"
    fi
    unpack="$(mktemp -d "$TOOLS_DIR/.unpack.XXXXXX")"
    tar -xzf "$tmp" -C "$unpack"
    rm -f "$tmp"
    bin="$(find "$unpack" -type f -name lychee | head -n 1)"
    [[ -n "$bin" ]] || { rm -rf "$unpack"; die "$tarball holds no lychee binary"; }
    mv "$bin" "$TOOLS_DIR/lychee"
    rm -rf "$unpack"
    chmod +x "$TOOLS_DIR/lychee"
    echo "installed lychee $LYCHEE_VERSION ($target, sha256 $want)"
fi

if [[ -x "$TOOLS_DIR/lychee" ]]; then
    LYCHEE="$TOOLS_DIR/lychee"
elif command -v lychee >/dev/null 2>&1; then
    LYCHEE="$(command -v lychee)"
else
    die "lychee not found in $TOOLS_DIR or PATH; run with --install"
fi
if ! reported="$("$LYCHEE" --version 2>&1)"; then
    die "refusing $LYCHEE: 'lychee --version' failed: $(head -c 200 <<<"$reported")"
fi
[[ "$reported" == "lychee $LYCHEE_VERSION" ]] ||
    die "refusing $LYCHEE: it reports '$reported', pinned lychee $LYCHEE_VERSION"

# The pages, without print.html (every page again on one page, with renamed fragments) and
# 404.html (its links are absolute, under site-url, for whatever path was not found).
pages=()
while IFS= read -r page; do pages+=("$page"); done < <(
    find "$site" -name '*.html' ! -name print.html ! -name 404.html | LC_ALL=C sort
)
[[ ${#pages[@]} -gt 0 ]] || die "no HTML pages under $site"

failed=0
echo "check-site-links: pass 1, inside the site (${#pages[@]} pages, offline, with fragments)"
"$LYCHEE" --no-progress --offline --include-fragments --root-dir "$site" \
    --index-files index.html "${pages[@]}" || failed=1

if [[ "$offline" -eq 0 ]]; then
    echo "check-site-links: pass 2, outside the site (online)"
    args=(--no-progress --max-retries 3 --retry-wait-time 5 --timeout 30
        --exclude "$REPO_FILES" --scheme https --scheme http)
    # lychee reads .lycheeignore from the current directory (the repository root) itself.
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        args+=(--github-token "$GITHUB_TOKEN")
    fi
    # The host names of a host list (one per line, `#` comments), lowercased, one per line;
    # nothing for a list of comments only.
    list_hosts() {
        awk '{ sub(/#.*/, ""); gsub(/[[:space:]]/, ""); if ($0 != "") print tolower($0) }' "$1"
    }
    # Host names (one per line) as one regular expression for a URL on any of them.
    hosts_regex() {
        printf '^https?://(%s)(:[0-9]+)?(/|$)' "$(sed 's/\./\\./g' | paste -sd '|' -)"
    }
    [[ -f "$OUTAGE_HOSTS" ]] || die "$OUTAGE_HOSTS not found"
    [[ -f "$BLOCKED_HOSTS" ]] || die "$BLOCKED_HOSTS not found"
    # Hosts that are down for everyone are left out of both runs below.
    outage="$(list_hosts "$OUTAGE_HOSTS")"
    if [[ -n "$outage" ]]; then
        echo "check-site-links: not fetched, hosts listed as having an outage ($OUTAGE_HOSTS):" \
            "${outage//$'\n'/ }"
        args+=(--exclude "$(hosts_regex <<<"$outage")")
    fi
    # The hosts that block CI runners, without those listed as having an outage (none: no
    # second run).
    blocked=""
    while IFS= read -r host; do
        if [[ -n "$outage" ]] && grep -qxF -- "$host" <<<"$outage"; then
            continue
        fi
        blocked+="$host"$'\n'
    done < <(list_hosts "$BLOCKED_HOSTS")
    blocked="${blocked%$'\n'}"
    if [[ -n "$blocked" ]]; then
        hosts="$(hosts_regex <<<"$blocked")"
        "$LYCHEE" "${args[@]}" --accept '200..=299,429' --exclude "$hosts" "${pages[@]}" || failed=1
        echo "check-site-links: pass 2, hosts that block CI runners (403 accepted):" \
            "${blocked//$'\n'/ }"
        "$LYCHEE" "${args[@]}" --accept '200..=299,403,429' --exclude '.*' --include "$hosts" \
            "${pages[@]}" || failed=1
    else
        "$LYCHEE" "${args[@]}" --accept '200..=299,429' "${pages[@]}" || failed=1
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    echo "check-site-links: FAIL"
    exit 1
fi
echo "check-site-links: PASS"
