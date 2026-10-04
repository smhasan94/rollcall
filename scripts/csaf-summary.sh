#!/usr/bin/env bash
# Prints the findings of a rollcall CSAF document as sorted, tab-separated rows:
#
#   vulnerability  status  product_id  purl  cpe
#
# one per product named in a vulnerability's product_status. The product_id is what the
# status is about: a relationship product "component as part of the firmware"
# (`<component bom-ref>@<product bom-ref>`), or the product itself. The purl and CPE are the
# component's (`-` when missing). It is the reference a CSAF consumer's view is compared
# against (docs/cra-clock.md): the same vulnerabilities, statuses and product identifiers must
# show up there.
#
# Usage: scripts/csaf-summary.sh FILE
# Needs jq.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: scripts/csaf-summary.sh FILE" >&2
    exit 2
fi

jq -r '
  # product_id -> identification helper, for the product and every component.
  def helpers:
    [ (.product_tree.branches // [] | .. | objects | select(has("product")) | .product),
      (.product_tree.full_product_names // [])[] ]
    | map({key: .product_id, value: .product_identification_helper})
    | from_entries;
  # relationship product_id -> the component it is about.
  def components:
    (.product_tree.relationships // [])
    | map({key: .full_product_name.product_id, value: .product_reference})
    | from_entries;
  helpers as $h
  | components as $c
  | .vulnerabilities[]
  | (.cve // ([.ids[]?.text] | first) // "-") as $id
  | .product_status | to_entries[] | .key as $status | .value[]
  | ($c[.] // .) as $component
  | [$id, $status, ., ($h[$component].purl // "-"), ($h[$component].cpe // "-")]
  | @tsv
' "$1" | LC_ALL=C sort
