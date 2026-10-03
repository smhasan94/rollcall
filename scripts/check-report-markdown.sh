#!/usr/bin/env bash
# Renders every readiness-report Markdown golden (crates/rollcall-core/tests/golden/report/*.md)
# with GitHub's own Markdown renderer (POST https://api.github.com/markdown, mode gfm) and
# checks the HTML: exactly one <h1>, the eight section <h2>s in order, as many <table>s as
# the Markdown has pipe tables, no pipe-table line left as a paragraph, and no raw HTML from
# the inputs (every `<` in the Markdown is escaped, so the HTML has no tag GitHub did not
# make). Needs the network; GITHUB_TOKEN, if set, avoids the anonymous rate limit.
#
# Usage: scripts/check-report-markdown.sh [FILE.md...]   (default: every report golden)
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
  set -- crates/rollcall-core/tests/golden/report/*.md
fi

out="${ROLLCALL_REPORT_MD_OUT:-.cache/report-markdown}"
mkdir -p "$out"

render() {
  # $1: Markdown file, $2: HTML output. One retry: it is a network call.
  local body
  body="$(python3 -c 'import json, sys; print(json.dumps({"text": open(sys.argv[1], encoding="utf-8").read(), "mode": "gfm"}))' "$1")"
  local auth=()
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  for attempt in 1 2; do
    if curl -fsS -X POST https://api.github.com/markdown \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "${auth[@]}" \
        --data "$body" -o "$2"; then
      return 0
    fi
    echo "render of $1 failed (attempt $attempt)" >&2
    sleep 5
  done
  return 1
}

status=0
for md in "$@"; do
  html="$out/$(basename "$md" .md).html"
  render "$md" "$html"
  if ! python3 - "$md" "$html" <<'PY'
import re, sys
md = open(sys.argv[1], encoding="utf-8").read()
html = open(sys.argv[2], encoding="utf-8").read()
problems = []
sections = ["Score", "Coverage", "Components", "Unresolved modules", "Findings",
            "VEX coverage", "Validation", "Warnings"]
h1 = re.findall(r"<h1[ >]", html)
if len(h1) != 1:
    problems.append(f"{len(h1)} <h1>, expected 1")
h2 = [re.sub(r"<[^>]+>", "", t).strip() for t in re.findall(r"<h2[^>]*>(.*?)</h2>", html, re.S)]
if h2 != sections:
    problems.append(f"<h2>s {h2}, expected {sections}")
tables_md = sum(1 for line in md.splitlines() if re.match(r"^\| (---|:?-+:?) ", line))
tables_html = html.count("<table")
if tables_md != tables_html:
    problems.append(f"{tables_html} <table>s, expected {tables_md}")
if re.search(r"<p>\s*\|", html):
    problems.append("a pipe-table line rendered as a paragraph")
allowed = {"h1", "h2", "p", "strong", "em", "code", "pre", "table", "thead", "tbody", "tr",
           "th", "td", "ul", "li", "div", "span", "a", "svg", "path", "markdown-accessiblity-table"}
tags = {t.lower() for t in re.findall(r"</?([A-Za-z][A-Za-z0-9-]*)", html)}
unexpected = sorted(tags - allowed)
if unexpected:
    problems.append(f"unexpected HTML tags {unexpected}")
if problems:
    print(f"{sys.argv[1]}:", *problems, sep="\n  ")
    sys.exit(1)
print(f"{sys.argv[1]}: OK ({tables_html} tables)")
PY
  then
    status=1
  fi
done
exit "$status"
