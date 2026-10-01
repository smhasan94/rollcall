#!/usr/bin/env bash
# Checks crates/rollcall-core/db/subsystems.yaml against the pinned Zephyr tree: every
# source path exists, every Kconfig symbol is defined, `size` claims hold, and the tree is
# the release the table is pinned to.
#
# MAY NEED THE NETWORK: if the tree is missing, the pinned tag is shallow-cloned (one retry).
#
# Usage: scripts/verify-subsystems.sh
#
# Environment:
#   ROLLCALL_ZEPHYR_TREE       the zephyr repository checkout
#                              (default $ROLLCALL_ZEPHYR_WORKSPACE/zephyr)
#   ROLLCALL_ZEPHYR_WORKSPACE  west workspace (default .cache/zephyr-workspace, as used by
#                              scripts/regen-fixtures.sh)
#
# The pinned tag and commit come from fixtures/zephyr/MANIFEST.json. An existing checkout at
# any other commit is refused, never modified. Then runs, with ROLLCALL_ZEPHYR_TREE set:
#   cargo test -p rollcall-core --test subsystems --locked -- --include-ignored
# Exits 0 on success, 1 if the tests fail, 2 on a setup error.
set -euo pipefail

die() {
    echo "verify-subsystems: $*" >&2
    exit 2
}

cd "$(dirname "$0")/.."

for tool in git python3 cargo; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

manifest=fixtures/zephyr/MANIFEST.json
[[ -f "$manifest" ]] || die "$manifest is missing"
read -r tag commit url < <(python3 - "$manifest" <<'PY'
import json, sys
z = json.load(open(sys.argv[1]))["zephyr"]
print(z["tag"], z["commit"], z["url"])
PY
) || die "cannot read the zephyr pin from $manifest"
[[ -n "$tag" && -n "$commit" && -n "$url" ]] || die "incomplete zephyr pin in $manifest"

ws="${ROLLCALL_ZEPHYR_WORKSPACE:-.cache/zephyr-workspace}"
tree="${ROLLCALL_ZEPHYR_TREE:-$ws/zephyr}"

if [[ ! -e "$tree" ]]; then
    echo "verify-subsystems: cloning $url $tag into $tree"
    mkdir -p "$(dirname "$tree")"
    # One retry: the clone is the only network call. A failed attempt leaves no checkout.
    git clone --quiet --depth 1 --branch "$tag" "$url" "$tree" || {
        echo "verify-subsystems: clone failed; retrying once" >&2
        rm -rf "$tree"
        git clone --quiet --depth 1 --branch "$tag" "$url" "$tree"
    } || die "cannot clone $url at $tag"
fi
[[ -f "$tree/VERSION" ]] || die "$tree is not a zephyr checkout (no VERSION)"
head="$(git -C "$tree" rev-parse HEAD)" || die "cannot read HEAD of $tree"
[[ "$head" == "$commit" ]] ||
    die "$tree is at $head, not the pinned $tag ($commit)"

echo "verify-subsystems: $tree at $tag ($commit)"
tree_abs="$(cd "$tree" && pwd)"
ROLLCALL_ZEPHYR_TREE="$tree_abs" \
    cargo test -p rollcall-core --test subsystems --locked -- --include-ignored || exit 1
