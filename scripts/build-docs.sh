#!/usr/bin/env bash
# Builds the docs site (book.toml: the Markdown under docs/) with mdBook (SHA-125; CI workflow
# docs.yml). Offline once mdBook is installed.
#
# Usage: scripts/build-docs.sh [--install] [--serve]
#
#   --install   download the pinned mdBook into $ROLLCALL_TOOLS_DIR (default .cache/tools),
#               verifying the download's SHA-256. Without it, mdBook is taken from
#               $ROLLCALL_TOOLS_DIR, then from PATH. Needs the network.
#   --serve     run `mdbook serve` (live reload on http://localhost:3000) instead of building.
#
# Either way, an mdBook whose reported version is not the pinned one is refused.
#
# The book is written to target/book/ (book.toml `build-dir`). The source of the quickstart
# page is copied next to its HTML (target/book/quickstart.md), so that
# scripts/quickstart-clean.sh can follow the published page's exact commands.
#
# Needs bash, curl and tar (for --install), and python3 (the link preprocessor,
# scripts/mdbook-repo-links.py). Exits 1 if the build fails, 2 on a setup error.
set -euo pipefail

cd "$(dirname "$0")/.."

MDBOOK_VERSION=0.5.4
OUT=target/book

# SHA-256 of the mdBook release tarballs (GitHub release asset digests).
mdbook_sha256() {
    case "$1" in
        x86_64-unknown-linux-musl) echo 5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89 ;;
        aarch64-unknown-linux-musl) echo 753e5c5c363ee8a56972344dcf91466f005a51db84a7aeffe427ae3ef83d6d44 ;;
        aarch64-apple-darwin) echo 03e8a6d8b13a2971e0b3280affd03b388373c1485e26f73407c3a76b0b1838df ;;
        x86_64-apple-darwin) echo a47d7bf0d5d670cff9ee6cce95537cbeb62dc10704d9e7131ffbd13e2b59a5de ;;
        *) return 1 ;;
    esac
}

die() {
    echo "build-docs: $*" >&2
    exit 2
}

install=0
serve=0
for arg in "$@"; do
    case "$arg" in
        --install) install=1 ;;
        --serve) serve=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $arg" ;;
    esac
done

command -v python3 >/dev/null 2>&1 || die "python3 is required (scripts/mdbook-repo-links.py)"

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
    want="$(mdbook_sha256 "$target")" || die "no pinned mdBook for $target"
    tarball="mdbook-v${MDBOOK_VERSION}-${target}.tar.gz"
    tmp="$(mktemp "$TOOLS_DIR/.download.XXXXXX")"
    if ! curl -fsSL --retry 3 -o "$tmp" \
        "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/${tarball}"; then
        rm -f "$tmp"
        die "download failed: $tarball"
    fi
    got="$(sha256_of "$tmp")"
    if [[ "$got" != "$want" ]]; then
        rm -f "$tmp"
        die "sha256 mismatch for $tarball: expected $want, got $got"
    fi
    tar -xzf "$tmp" -C "$TOOLS_DIR" mdbook
    rm -f "$tmp"
    chmod +x "$TOOLS_DIR/mdbook"
    echo "installed mdBook $MDBOOK_VERSION ($target, sha256 $want)"
fi

if [[ -x "$TOOLS_DIR/mdbook" ]]; then
    MDBOOK="$TOOLS_DIR/mdbook"
elif command -v mdbook >/dev/null 2>&1; then
    MDBOOK="$(command -v mdbook)"
else
    die "mdbook not found in $TOOLS_DIR or PATH; run with --install"
fi
if ! reported="$("$MDBOOK" --version 2>&1)"; then
    die "refusing $MDBOOK: 'mdbook --version' failed: $(head -c 200 <<<"$reported")"
fi
[[ "$reported" == "mdbook v$MDBOOK_VERSION" ]] ||
    die "refusing $MDBOOK: it reports '$reported', pinned mdbook v$MDBOOK_VERSION"

if [[ "$serve" -eq 1 ]]; then
    exec "$MDBOOK" serve
fi

rm -rf "$OUT"
"$MDBOOK" build || {
    echo "build-docs: mdbook build failed" >&2
    exit 1
}
[[ -f "$OUT/index.html" && -f "$OUT/quickstart.html" ]] ||
    { echo "build-docs: $OUT lacks index.html or quickstart.html" >&2; exit 1; }
cp docs/quickstart.md "$OUT/quickstart.md"
echo "build-docs: built $OUT ($(find "$OUT" -name '*.html' | wc -l | tr -d ' ') HTML pages)"
