#!/usr/bin/env bash
# Re-runnable check that every rollcall name is reserved at 0.0.1 on crates.io and PyPI.
# Prints each registry's version and owners, then the verbatim `cargo search` and
# `pip index versions` output. Exits 1 (after reporting every name) if any is missing.
set -euo pipefail

UA="rollcall-check-names (github.com/smhasan94/rollcall)"
WANT="0.0.1"
CRATES=(rollcall rollcall-core rollcall-cli rollcall-assay)
missing=0

fetch() {
    # Prints the body on success; returns non-zero (without aborting) on HTTP/network failure.
    curl -sf -A "$UA" "$1" || return 1
}

for c in "${CRATES[@]}"; do
    if body=$(fetch "https://crates.io/api/v1/crates/$c"); then
        version=$(jq -r '.crate.max_version // empty' <<<"$body")
        echo "crates.io/$c max_version=${version:-<none>}"
        if owners=$(fetch "https://crates.io/api/v1/crates/$c/owner_user"); then
            echo "crates.io/$c owners=$(jq -r '[.users[].login] | join(",")' <<<"$owners")"
        else
            echo "crates.io/$c owners=<unavailable>"
        fi
        if [[ "$version" != "$WANT" ]]; then
            echo "MISSING crates.io/$c (want $WANT, found ${version:-<none>})"
            missing=1
        fi
    else
        echo "MISSING crates.io/$c"
        missing=1
    fi
done

if body=$(fetch "https://pypi.org/pypi/rollcall/json"); then
    version=$(jq -r '.info.version // empty' <<<"$body")
    echo "pypi/rollcall version=${version:-<none>}"
    if [[ "$version" != "$WANT" ]]; then
        echo "MISSING pypi/rollcall (want $WANT, found ${version:-<none>})"
        missing=1
    fi
else
    echo "MISSING pypi/rollcall"
    missing=1
fi

echo
echo "\$ cargo search rollcall --limit 20"
cargo search rollcall --limit 20 || true
echo
echo "\$ python3 -m pip index versions rollcall"
python3 -m pip index versions rollcall || true

exit "$missing"
