#!/usr/bin/env bash
# Follows the quickstart as published on the docs site, on the machine it runs on (SHA-125;
# workflow quickstart-clean.yml runs it in a fresh ubuntu:24.04 container). It never reads the
# repository: the page, the install and the example build all come from the network.
#
# Usage: scripts/quickstart-clean.sh --method tarball|cargo|pip|path [--site URL]
#                                    [--workdir DIR] [--print]
#
#   --method M   which install of step 1 to follow: tarball (the release binary), cargo or
#                pip; or path, to skip step 1 and use the `rollcall` already on PATH (for a
#                dry run before a release exists).
#   --site URL   the docs site (default https://smhasan94.github.io/rollcall). A file:// URL
#                of a local build (target/book) works too.
#   --workdir D  where to work (default: a new temporary directory). Must be empty.
#   --print      print the script that would run, and run nothing.
#
# What it does:
#
# 1. Fetches SITE/quickstart.html (the page) and SITE/quickstart.md (its source, published
#    beside it by scripts/build-docs.sh), and checks that every command it is about to run
#    appears on the HTML page, so what runs is what a reader sees.
# 2. Runs, in one bash session (`set -euo pipefail`) in the work directory: the ```sh block of
#    the chosen install subsection of "1. Install rollcall" (with TARGET set to this machine's
#    release target, and on macOS `shasum -a 256 --check` for `sha256sum --check`, as the page
#    says; the archive's layout, `rollcall-<tag>-<target>/rollcall`, is the page's), the ```sh
#    block of "No build at hand: the example build", then every
#    `$ ` command of the ```console blocks of steps 3 to 5.
# 3. Compares each console command's stdout with the output the page shows.
#
# Prerequisites are the page's own: curl and tar, plus a Rust toolchain for cargo and Python
# 3.9+ with venv for pip; and python3 for this script. Prints a PASS/FAIL row per command and
# the elapsed time; exits 1 if a command fails or its output differs, 2 on a setup error.
set -euo pipefail

die() {
    echo "quickstart-clean: $*" >&2
    exit 2
}

method=""
site="https://smhasan94.github.io/rollcall"
workdir=""
print=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --method)
            [[ $# -ge 2 ]] || die "--method needs a value"
            method="$2"
            shift
            ;;
        --site)
            [[ $# -ge 2 ]] || die "--site needs a value"
            site="${2%/}"
            shift
            ;;
        --workdir)
            [[ $# -ge 2 ]] || die "--workdir needs a value"
            workdir="$2"
            shift
            ;;
        --print) print=1 ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done
case "$method" in
    tarball | cargo | pip | path) ;;
    "") die "--method is required (tarball, cargo, pip or path)" ;;
    *) die "unknown --method $method (tarball, cargo, pip or path)" ;;
esac
for tool in curl python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64 | Linux/amd64) target=linux-amd64 ;;
    Linux/aarch64 | Linux/arm64) target=linux-arm64 ;;
    Darwin/*) target=darwin-universal ;;
    *) die "no release binary for $(uname -s)/$(uname -m)" ;;
esac

if [[ -z "$workdir" ]]; then
    workdir="$(mktemp -d)"
else
    mkdir -p "$workdir"
    [[ -z "$(ls -A "$workdir")" ]] || die "$workdir is not empty"
fi
workdir="$(cd "$workdir" && pwd)"
meta="$workdir/.quickstart-clean"
mkdir -p "$meta"

curl -fsSL --retry 3 -o "$meta/quickstart.md" "$site/quickstart.md" ||
    die "cannot fetch $site/quickstart.md"
curl -fsSL --retry 3 -o "$meta/quickstart.html" "$site/quickstart.html" ||
    die "cannot fetch $site/quickstart.html"

# Extract the steps into $meta: script.sh (what runs), N.exp (each console command's expected
# stdout) and commands.tsv (N, line, command).
python3 - "$meta" "$method" "$target" <<'PY' || die "cannot follow $site/quickstart.md (above)"
import html
import os
import re
import sys

meta, method, target = sys.argv[1:4]
md = open(os.path.join(meta, "quickstart.md"), encoding="utf-8").read().split("\n")
page = open(os.path.join(meta, "quickstart.html"), encoding="utf-8").read()
# The page's text: tags dropped, entities decoded, whitespace runs as one space.
text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", page)))

INSTALL = {"tarball": "### Release binary", "cargo": "### cargo", "pip": "### pip"}


def fail(msg):
    print(f"quickstart-clean: {msg}", file=sys.stderr)
    sys.exit(1)


def blocks(start, lang):
    """The ```lang blocks (line number, lines) after the heading that starts with `start`,
    up to the next heading of the same or a higher level."""
    found = [i for i, l in enumerate(md) if l.startswith(start)]
    if len(found) != 1:
        fail(f"expected one heading starting {start!r}, found {len(found)}")
    level = len(start.split(" ")[0])
    out, i = [], found[0] + 1
    while i < len(md):
        line = md[i]
        hashes = len(line) - len(line.lstrip("#"))
        if 0 < hashes <= level and line[hashes:hashes + 1] == " ":
            break
        if line == "```" + lang:
            body, j = [], i + 1
            while j < len(md) and md[j] != "```":
                body.append(md[j])
                j += 1
            if j == len(md):
                fail(f"unterminated block at line {i + 1}")
            out.append((i + 1, body))
            i = j
        i += 1
    return out


def on_page(line):
    want = re.sub(r"\s+", " ", line.strip())
    if want and want not in text:
        fail(f"{want!r} is in quickstart.md but not on quickstart.html: not the published page")


script = ["set -euo pipefail"]
if method != "path":
    install = blocks(INSTALL[method], "sh")
    if len(install) != 1:
        fail(f"expected one sh block under {INSTALL[method]!r}, found {len(install)}")
    script.append(f"# step 1, {INSTALL[method][4:]} (quickstart.md line {install[0][0]})")
    for line in install[0][1]:
        on_page(line)
        if method == "tarball" and re.fullmatch(r"TARGET=\S+", line.strip()):
            line = f"TARGET={target}"
        if method == "tarball" and target == "darwin-universal":
            # The page: "On macOS, `sha256sum --check` is `shasum -a 256 --check`."
            line = line.replace("| sha256sum --check", "| shasum -a 256 --check")
        script.append(line)
prepare = blocks("### No build at hand", "sh")
if len(prepare) != 1:
    fail(f"expected one sh block under the example build, found {len(prepare)}")
script.append(f"# step 2, the example build (quickstart.md line {prepare[0][0]})")
for line in prepare[0][1]:
    on_page(line)
    script.append(line)

rows = []
n = 0
for step in ("## 3.", "## 4.", "## 5."):
    for start, body in blocks(step, "console"):
        cmd = None
        for k, line in enumerate(body):
            if line.startswith("$ "):
                n += 1
                cmd = line[2:]
                on_page(cmd)
                rows.append((n, start + 1 + k, cmd))
                open(os.path.join(meta, f"{n}.exp"), "w", encoding="utf-8").close()
                script.append(f"{{ {cmd}\n}} > {meta}/{n}.out")
            elif cmd is None:
                fail(f"console block at line {start} does not start with a command")
            else:
                with open(os.path.join(meta, f"{n}.exp"), "a", encoding="utf-8") as f:
                    f.write(line + "\n")
if n == 0:
    fail("no console commands in steps 3 to 5")
with open(os.path.join(meta, "script.sh"), "w", encoding="utf-8") as f:
    f.write("\n".join(script) + "\n")
with open(os.path.join(meta, "commands.tsv"), "w", encoding="utf-8") as f:
    for row in rows:
        f.write("\t".join(map(str, row)) + "\n")
PY

if [[ "$print" -eq 1 ]]; then
    cat "$meta/script.sh"
    exit 0
fi

echo "quickstart-clean: following $site/quickstart.html (method $method, in $workdir)"
start="$(date +%s)"
rc=0
(cd "$workdir" && bash "$meta/script.sh") || rc=$?
elapsed=$(($(date +%s) - start))

failed=0
printf '%-8s  %-6s  %s\n' LINE RESULT COMMAND
while IFS=$'\t' read -r n line cmd; do
    if [[ ! -f "$meta/$n.out" ]]; then
        result="NOT RUN"
        failed=1
    elif diff -u "$meta/$n.exp" "$meta/$n.out" >"$meta/$n.diff"; then
        result=PASS
    else
        result=FAIL
        failed=1
        sed 's/^/    /' "$meta/$n.diff" >&2
    fi
    printf '%-8s  %-6s  %s\n' "$line" "$result" "$cmd"
done <"$meta/commands.tsv"
echo
echo "elapsed: $((elapsed / 60))m$((elapsed % 60))s"
if [[ "$rc" -ne 0 || "$failed" -ne 0 ]]; then
    echo "quickstart-clean: FAIL (script exit $rc)"
    exit 1
fi
echo "quickstart-clean: PASS"
