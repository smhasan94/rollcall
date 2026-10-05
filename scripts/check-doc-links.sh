#!/usr/bin/env bash
# Checks that every link in Markdown documents resolves (SHA-134; CI job docs-links).
#
# Usage: scripts/check-doc-links.sh [--offline] FILE.md...
#
# Links are inline `[text](target)` links (images included), autolinks `<scheme:...>` and
# reference definitions `[label]: target`. Links inside fenced code blocks and inline code
# are ignored.
#
# - A relative target must exist, relative to the document's directory, with every path
#   component spelled in exactly the case on disk (so a check on a case-insensitive file
#   system, such as macOS's default, catches what would break on Linux). A `#anchor` on a
#   Markdown target (or a bare `#anchor`, meaning the document itself) must match one of
#   its headings, slugged the way GitHub does it.
# - An http(s) target is fetched with curl: a HEAD request, then a GET if HEAD fails,
#   following redirects, with a 20 s timeout and two retries. It passes when curl succeeds,
#   the final status is 2xx or 3xx, and the final URL is not a proper prefix of the one
#   asked for (a missing GitHub wiki page, say, redirects up to the wiki's home page and
#   answers 200; that fails). Redirects to another host or a longer path pass. The final
#   URL is shown in DETAIL. GITHUB_TOKEN, if set, is sent to api.github.com only (it avoids
#   the anonymous API rate limit; github.com pages do not use it). Anchors on http(s)
#   targets are not checked.
# - Hosts in scripts/link-check-blocked-hosts.txt reject GitHub's CI runners: for those
#   hosts, and only for an HTTP 403 (curl succeeded, no redirect up to a parent page), the
#   link is listed as SKIP ("HTTP 403 from a host that blocks CI runners"). Any other result
#   from them (404, 5xx, a curl error, a redirect to a parent page) still fails. The file says
#   why and when each host was added.
# - --offline skips http(s) targets (they are listed as SKIP) and checks the rest.
# - mailto: and other schemes are listed as SKIP.
#
# Prints a PASS/FAIL/SKIP row per link and a summary of links checked and skipped; exits 1
# if any link fails, 2 on a usage error.
# Needs bash, python3 and, without --offline, curl.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

offline=0
files=()
for arg in "$@"; do
    case "$arg" in
        -h | --help)
            usage
            exit 0
            ;;
        --offline) offline=1 ;;
        -*)
            echo "check-doc-links: unknown option $arg" >&2
            exit 2
            ;;
        *) files+=("$arg") ;;
    esac
done
if [[ ${#files[@]} -eq 0 ]]; then
    echo "check-doc-links: no files given" >&2
    usage >&2
    exit 2
fi
command -v python3 >/dev/null 2>&1 || {
    echo "check-doc-links: python3 is required" >&2
    exit 2
}
if [[ "$offline" -eq 0 ]]; then
    command -v curl >/dev/null 2>&1 || {
        echo "check-doc-links: curl is required (or pass --offline)" >&2
        exit 2
    }
fi

BLOCKED_HOSTS="$(dirname "$0")/link-check-blocked-hosts.txt"
[[ -f "$BLOCKED_HOSTS" ]] || {
    echo "check-doc-links: $BLOCKED_HOSTS not found" >&2
    exit 2
}

exec python3 - "$offline" "$BLOCKED_HOSTS" "${files[@]}" <<'PY'
import os
import re
import subprocess
import sys
import urllib.parse

offline = sys.argv[1] == "1"
blocked_file = sys.argv[2]
files = sys.argv[3:]


def read_blocked(path):
    """The host names in the blocked-hosts file: one per line, `#` comments."""
    hosts = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                hosts.add(line.lower())
    return hosts


BLOCKED = read_blocked(blocked_file)
BLOCKED_NOTE = "HTTP 403 from a host that blocks CI runners (listed in scripts/link-check-blocked-hosts.txt)"

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`+[^`]*`+")
# [text](target "title") and ![alt](target); the target has no spaces or parentheses
# unless they are balanced one level deep.
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?((?:[^()\s<>]|\([^()\s]*\))+)>?(?:\s+\"[^\"]*\")?\s*\)")
AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^>\s]+)>")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+\"[^\"]*\")?\s*$")


def links(path):
    """(line number, target) for every link in the Markdown file at path."""
    out = []
    in_fence = False
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            m = REFDEF.match(line)
            if m:
                out.append((n, m.group(1)))
                continue
            text = INLINE_CODE.sub("", line)
            for m in INLINE.finditer(text):
                out.append((n, m.group(1)))
            for m in AUTOLINK.finditer(text):
                out.append((n, m.group(1)))
    return out


def slug(heading):
    """GitHub's anchor for a heading's text."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links keep their text
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(path):
    found = set()
    seen = {}
    in_fence = False
    with open(path, encoding="utf-8") as f:
        for line in f:
            if FENCE.match(line):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
            if not m:
                continue
            base = slug(m.group(1))
            count = seen.get(base, 0)
            seen[base] = count + 1
            found.add(base if count == 0 else f"{base}-{count}")
    return found


def check_local(doc, target):
    path, _, frag = target.partition("#")
    path = urllib.parse.unquote(path)
    full = os.path.normpath(os.path.join(os.path.dirname(doc), path)) if path else doc
    if not os.path.exists(full):
        return "FAIL", f"{full} does not exist"
    # The exact case of each component, whatever the file system.
    here = os.path.dirname(doc) or "."
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            here = os.path.dirname(os.path.abspath(here))
            continue
        if part not in os.listdir(here):
            return "FAIL", f"{part!r} is not spelled as on disk in {here}"
        here = os.path.join(here, part)
    if frag:
        if not full.endswith(".md"):
            return "FAIL", f"anchor #{frag} on a non-Markdown file"
        if os.path.isdir(full):
            return "FAIL", f"anchor #{frag} on a directory"
        if frag.lower() not in anchors(full):
            return "FAIL", f"no heading for #{frag} in {full}"
    return "PASS", "exists" + (f", #{frag} found" if frag else "")


_http_cache = {}


def curl_status(url, method):
    """(curl exit code, final HTTP status, final URL, stderr) of fetching url."""
    host = urllib.parse.urlsplit(url).hostname or ""
    cmd = ["curl", "-sS", "-o", os.devnull, "-w", "%{http_code} %{url_effective}", "-L",
           "--max-time", "20", "--retry", "2", "--retry-delay", "2",
           "-A", "rollcall-check-doc-links/1"]
    if method == "HEAD":
        cmd.append("-I")
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and host == "api.github.com":
        cmd += ["-H", f"Authorization: Bearer {token}"]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return -1, 0, "", "timed out"
    code, _, effective = r.stdout.strip().partition(" ")
    try:
        status = int(code)
    except ValueError:
        status = 0
    return r.returncode, status, effective, r.stderr.strip()


def strip_url(url):
    """url without its fragment and trailing slashes, for comparing redirects."""
    return urllib.parse.urldefrag(url)[0].rstrip("/")


def judge(url, rc, status, effective, err):
    """(result, detail) for one fetch."""
    detail = f"HTTP {status} {effective}".rstrip()
    if rc != 0:
        return "FAIL", f"{detail} (curl exit {rc}{': ' + err if err else ''})"
    if not 200 <= status < 400:
        return "FAIL", detail
    asked, got = strip_url(url), strip_url(effective)
    if got != asked and asked.startswith(got):
        return "FAIL", f"{detail} (redirected up to a parent page)"
    return "PASS", detail


def blocked_403(url, rc, status, effective):
    """True when a fetch is a plain 403 from a host listed as blocking CI runners: curl
    succeeded, the asked and final hosts are both listed, and it was not redirected up to a
    parent page."""
    if rc != 0 or status != 403:
        return False
    hosts = {(urllib.parse.urlsplit(u).hostname or "").lower() for u in (url, effective or url)}
    if not hosts <= BLOCKED:
        return False
    asked, got = strip_url(url), strip_url(effective or url)
    return not (got != asked and asked.startswith(got))


def check_http(url):
    if url in _http_cache:
        return _http_cache[url]
    fetch = curl_status(url, "HEAD")
    result = judge(url, *fetch)
    if result[0] == "FAIL":
        fetch = curl_status(url, "GET")
        result = judge(url, *fetch)
    if result[0] == "FAIL" and blocked_403(url, *fetch[:3]):
        result = ("SKIP", BLOCKED_NOTE)
    _http_cache[url] = result
    return result


rows = []
failed = False
for doc in files:
    if not os.path.isfile(doc):
        print(f"check-doc-links: {doc} not found", file=sys.stderr)
        sys.exit(2)
    for n, target in links(doc):
        scheme = urllib.parse.urlsplit(target).scheme.lower()
        if scheme in ("http", "https"):
            if offline:
                result, detail = "SKIP", "offline"
            else:
                result, detail = check_http(target)
        elif scheme:
            result, detail = "SKIP", f"{scheme}: link"
        else:
            result, detail = check_local(doc, target)
        if result == "FAIL":
            failed = True
        rows.append((f"{doc}:{n}", result, target, detail))

width = max([len(r[0]) for r in rows] + [len("LINK")])
print(f"{'LINK':<{width}}  RESULT  TARGET  DETAIL")
for where, result, target, detail in rows:
    print(f"{where:<{width}}  {result:<6}  {target}  {detail}")
print()
if failed:
    print("check-doc-links: FAIL")
    sys.exit(1)
skipped = sum(1 for r in rows if r[1] == "SKIP")
print(f"check-doc-links: PASS ({len(rows) - skipped} checked, {skipped} skipped)")
PY
