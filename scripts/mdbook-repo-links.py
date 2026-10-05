#!/usr/bin/env python3
"""mdBook preprocessor: links that leave the book's source directory become GitHub links.

The docs site (book.toml, `src = "docs"`) is built from the same Markdown files GitHub shows,
and those link freely into the rest of the repository (`../README.md#zephyr-ingestion`,
`../crates/rollcall-core/profiles/cra.yaml`, ...). On the site such a link would point at a
file the site does not have. This preprocessor rewrites them at build time only, so the
source files stay correct on GitHub:

- a relative link to a page of the book (a chapter in SUMMARY.md), or to another file in the
  source directory (mdBook copies those to the site), stays relative; a link to a `README.md`
  page becomes `index.md`, the name mdBook gives that page;
- a relative link to anything else in the repository (a file outside the source directory, a
  Markdown file there that is not a chapter, such as SUMMARY.md, or a directory) becomes
  `<repository>/blob/<branch>/<path>` (`tree/` for a directory), keeping its `#fragment`;
- a relative link whose target does not exist fails the build, naming the chapter;
- absolute URLs, `mailto:` links and bare `#fragment` links are left alone, as is anything
  inside fenced code blocks or inline code.

Text pulled in with `{{#include}}` from outside the source directory (the identifier-database
guide from CONTRIBUTING.md, say) carries links relative to its own file. Wrap the include in

    <!-- repo-links: base=../CONTRIBUTING.md -->
    {{#include ../CONTRIBUTING.md:identifier-db}}
    <!-- repo-links: end -->

and links between the markers are resolved against the named file's directory instead of the
chapter's. The preprocessor must therefore run after mdBook's `links` preprocessor (book.toml:
`after = ["links"]`).

Configuration (book.toml, all optional):

    [preprocessor.repo-links]
    repository = "https://github.com/smhasan94/rollcall"   # default: output.html.git-repository-url
    branch = "main"

Python 3 standard library only.

    mdbook-repo-links.py supports RENDERER   # exit 0: every renderer is supported
    mdbook-repo-links.py < [context, book]   # the mdBook preprocessor protocol
    mdbook-repo-links.py --self-test         # offline checks; prints PASS or fails
"""

import json
import os
import posixpath
import re
import sys
import tempfile

DEFAULT_BRANCH = "main"

FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
# A closing fence: the same character, at least as long as the opening one, and nothing after.
CLOSING_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*$")
# Four columns of indentation: an indented code block, after a blank line outside a list.
INDENTED = re.compile(r"^(?: {4}| {0,3}\t)")
LIST_ITEM = re.compile(r"^\s{0,3}(?:[-*+]|\d{1,9}[.)])(?:\s|$)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
# [text](target "title") and ![alt](target); the target has no spaces, or is in <...>.
INLINE_LINK = re.compile(
    r"(?P<head>!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*)"
    r"(?P<target><[^<>\n]*>|(?:[^()\s<>]|\([^()\s]*\))+)"
    r"(?P<tail>(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\))"
)
REFDEF = re.compile(r"^(?P<head>\s{0,3}\[[^\]]+\]:\s*)(?P<target><[^<>]*>|\S+)(?P<tail>.*)$")
REGION_START = re.compile(r"^\s*<!--\s*repo-links:\s*base=(?P<base>\S+)\s*-->\s*$")
REGION_END = re.compile(r"^\s*<!--\s*repo-links:\s*end\s*-->\s*$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class LinkError(Exception):
    """A relative link that names no file, or a malformed region marker."""


class Rewriter:
    """Rewrites the links of chapters of a book whose source directory is `src_dir` (a path
    relative to the repository root `root`)."""

    def __init__(self, root, src_dir, repository, branch, pages=None):
        self.root = os.path.abspath(root)
        self.src = posixpath.normpath(src_dir.replace(os.sep, "/"))
        self.repository = repository.rstrip("/")
        self.branch = branch
        # The chapters' source files, relative to the root; None means every Markdown file in
        # the source directory is a page.
        self.pages = None if pages is None else {posixpath.normpath(p) for p in pages}

    def _is_page(self, rel):
        if self._is_dir(rel):
            return False
        if not rel.endswith(".md"):
            return True  # mdBook copies the source directory's other files to the site
        return self.pages is None or rel in self.pages

    def _exists(self, rel):
        return os.path.exists(os.path.join(self.root, *rel.split("/")))

    def _is_dir(self, rel):
        return os.path.isdir(os.path.join(self.root, *rel.split("/")))

    def _inside_src(self, rel):
        return self.src == "." or rel == self.src or rel.startswith(self.src + "/")

    def rewrite_target(self, target, chapter, base_dir):
        """The new link target for `target`, written in the chapter at `chapter` (relative to
        the repository root), resolved against `base_dir` (relative to the root)."""
        bracketed = target.startswith("<") and target.endswith(">")
        raw = target[1:-1] if bracketed else target
        if not raw or raw.startswith("#") or raw.startswith("/") or SCHEME.match(raw):
            return target
        if "{{" in raw:
            return target
        path, sep, frag = raw.partition("#")
        resolved = posixpath.normpath(posixpath.join(base_dir, path)) if path else chapter
        if resolved.startswith("../") or resolved == "..":
            raise LinkError(f"{chapter}: link {raw!r} leaves the repository")
        if not self._exists(resolved):
            raise LinkError(f"{chapter}: link {raw!r} names {resolved}, which does not exist")
        if self._inside_src(resolved) and self._is_page(resolved):
            if posixpath.basename(resolved) == "README.md":
                resolved = posixpath.join(posixpath.dirname(resolved), "index.md")
            chapter_dir = posixpath.dirname(chapter) or "."
            new = posixpath.relpath(resolved, chapter_dir) if path else ""
            if path and new == path and not bracketed:
                return target
        else:
            kind = "tree" if self._is_dir(resolved) else "blob"
            new = f"{self.repository}/{kind}/{self.branch}/{resolved}"
        out = new + (sep + frag if sep else "")
        return f"<{out}>" if bracketed else out

    def rewrite_chapter(self, content, chapter):
        """`content` (the Markdown of the chapter whose source is `chapter`, relative to the
        repository root) with its links rewritten."""
        chapter = posixpath.normpath(chapter.replace(os.sep, "/"))
        chapter_dir = posixpath.dirname(chapter)
        base_dir = chapter_dir
        region = False
        fence = None
        # Indented code blocks: one starts after a blank line (or at the top), outside a list,
        # and runs while lines stay indented four columns or are blank.
        indented_code = False
        prev_blank = True
        in_list = False
        out = []
        for n, line in enumerate(content.split("\n"), 1):
            if fence is not None:
                close = CLOSING_FENCE.match(line)
                if close and close.group(1)[0] == fence[0] and len(close.group(1)) >= len(fence):
                    fence = None
                out.append(line)
                continue
            if not line.strip():
                prev_blank = True
                out.append(line)
                continue
            if indented_code and INDENTED.match(line):
                out.append(line)
                continue
            indented_code = False
            if prev_blank and not in_list and INDENTED.match(line):
                indented_code = True
                prev_blank = False
                out.append(line)
                continue
            if LIST_ITEM.match(line):
                in_list = True
            elif prev_blank and not INDENTED.match(line):
                in_list = False
            prev_blank = False
            m = FENCE.match(line)
            if m:
                fence = m.group(1)
                out.append(line)
                continue
            start = REGION_START.match(line)
            if start:
                if region:
                    raise LinkError(f"{chapter}:{n}: repo-links region opened twice")
                base = posixpath.normpath(posixpath.join(chapter_dir, start.group("base")))
                if not self._exists(base):
                    raise LinkError(f"{chapter}:{n}: repo-links base {base} does not exist")
                base_dir = posixpath.dirname(base)
                region = True
                out.append(line)
                continue
            if REGION_END.match(line):
                if not region:
                    raise LinkError(f"{chapter}:{n}: repo-links end without a start")
                base_dir = chapter_dir
                region = False
                out.append(line)
                continue
            out.append(self._rewrite_line(line, chapter, base_dir))
        if region:
            raise LinkError(f"{chapter}: repo-links region is never closed")
        return "\n".join(out)

    def _rewrite_line(self, line, chapter, base_dir):
        m = REFDEF.match(line)
        if m:
            return m.group("head") + self.rewrite_target(m.group("target"), chapter, base_dir) + m.group("tail")
        # A link that starts inside an inline code span is code, not a link. (Code inside a
        # link's text, as in [`x`](y), starts after the link does.)
        spans = [(c.start(), c.end()) for c in INLINE_CODE.finditer(line)]

        def sub(match):
            if any(a <= match.start() < b for a, b in spans):
                return match.group(0)
            new = self.rewrite_target(match.group("target"), chapter, base_dir)
            return match.group("head") + new + match.group("tail")

        return INLINE_LINK.sub(sub, line)


def chapters(node):
    """Every Chapter object in an mdBook book (any version's JSON shape), depth first."""
    if isinstance(node, dict):
        chapter = node.get("Chapter")
        if isinstance(chapter, dict):
            yield chapter
        for value in node.values():
            yield from chapters(value)
    elif isinstance(node, list):
        for value in node:
            yield from chapters(value)


def process(raw):
    """The book JSON to print for the preprocessor input `raw` (the text of `[context, book]`).
    Raises ValueError for input of the wrong shape and LinkError for a broken link."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"input is not JSON: {e}") from None
    except RecursionError:
        raise ValueError("input is nested too deeply") from None
    if not (isinstance(data, list) and len(data) == 2 and all(isinstance(x, dict) for x in data)):
        raise ValueError("input is not a [context, book] pair")
    context, book = data
    root = context.get("root")
    config = context.get("config")
    if not isinstance(root, str) or not isinstance(config, dict):
        raise ValueError("context lacks root or config")
    book_cfg = config.get("book") if isinstance(config.get("book"), dict) else {}
    src = book_cfg.get("src", "src")
    pre = config.get("preprocessor", {})
    own = pre.get("repo-links", {}) if isinstance(pre, dict) else {}
    own = own if isinstance(own, dict) else {}
    html = config.get("output", {}).get("html", {}) if isinstance(config.get("output"), dict) else {}
    html = html if isinstance(html, dict) else {}
    repository = own.get("repository") or html.get("git-repository-url")
    branch = own.get("branch", DEFAULT_BRANCH)
    if not isinstance(src, str) or not isinstance(repository, str) or not isinstance(branch, str):
        raise ValueError("book.src, the repository URL and the branch must be strings")
    pages = []
    for chapter in chapters(book):
        source = chapter.get("source_path") or chapter.get("path")
        if isinstance(source, str):
            pages.append(posixpath.join(src, source))
    rewriter = Rewriter(root, src, repository, branch, pages)
    for chapter in list(chapters(book)):
        content = chapter.get("content")
        source = chapter.get("source_path") or chapter.get("path")
        if not isinstance(content, str) or not isinstance(source, str):
            continue
        chapter["content"] = rewriter.rewrite_chapter(content, posixpath.join(src, source))
    return json.dumps(book)


def self_test():
    failures = []

    def check(name, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    def raises(name, exc, fn):
        try:
            fn()
        except exc:
            return
        except Exception as e:  # noqa: BLE001 - any other exception is the failure
            failures.append(f"{name}: raised {type(e).__name__}: {e}")
            return
        failures.append(f"{name}: did not raise {exc.__name__}")

    with tempfile.TemporaryDirectory() as root:
        for rel in ["README.md", "CONTRIBUTING.md", "crates/x/src/lib.rs", "docs/README.md",
                    "docs/a.md", "docs/sub/b.md", "docs/schema.json"]:
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("# x\n")
        r = Rewriter(root, "docs", "https://github.com/o/r/", "main")
        rw = r.rewrite_chapter
        check("inside stays", rw("[a](sub/b.md#x)", "docs/a.md"), "[a](sub/b.md#x)")
        check("non-md inside stays", rw("[s](schema.json)", "docs/a.md"), "[s](schema.json)")
        check("up and back in", rw("[a](../a.md)", "docs/sub/b.md"), "[a](../a.md)")
        check("readme is index", rw("[i](README.md#e)", "docs/a.md"), "[i](index.md#e)")
        check("outside file", rw("[r](../README.md#zephyr-ingestion)", "docs/a.md"),
              "[r](https://github.com/o/r/blob/main/README.md#zephyr-ingestion)")
        check("outside dir", rw("[c](../crates/x)", "docs/a.md"),
              "[c](https://github.com/o/r/tree/main/crates/x)")
        check("image", rw("![i](../crates/x/src/lib.rs)", "docs/a.md"),
              "![i](https://github.com/o/r/blob/main/crates/x/src/lib.rs)")
        check("title kept", rw('[r](../README.md "T")', "docs/a.md"),
              '[r](https://github.com/o/r/blob/main/README.md "T")')
        check("bracketed", rw("[r](<../README.md>)", "docs/a.md"),
              "[r](<https://github.com/o/r/blob/main/README.md>)")
        check("refdef", rw("[r]: ../README.md", "docs/a.md"),
              "[r]: https://github.com/o/r/blob/main/README.md")
        check("absolute untouched", rw("[u](https://x.org/a.md) <https://x.org>", "docs/a.md"),
              "[u](https://x.org/a.md) <https://x.org>")
        check("mailto untouched", rw("[m](mailto:a@b.c)", "docs/a.md"), "[m](mailto:a@b.c)")
        check("fragment untouched", rw("[f](#here)", "docs/a.md"), "[f](#here)")
        check("inline code untouched", rw("`[r](../nope.md)` and [r](../README.md)", "docs/a.md"),
              "`[r](../nope.md)` and [r](https://github.com/o/r/blob/main/README.md)")
        check("code in link text", rw("[`README.md`](../README.md)", "docs/a.md"),
              "[`README.md`](https://github.com/o/r/blob/main/README.md)")
        check("dir inside src", rw("[s](sub/)", "docs/a.md"),
              "[s](https://github.com/o/r/tree/main/docs/sub)")
        paged = Rewriter(root, "docs", "https://github.com/o/r", "main",
                         ["docs/README.md", "docs/a.md"]).rewrite_chapter
        check("md not a page", paged("[b](sub/b.md) [a](a.md) [s](schema.json)", "docs/a.md"),
              "[b](https://github.com/o/r/blob/main/docs/sub/b.md) [a](a.md) [s](schema.json)")
        fenced = "```sh\n[r](../nope.md)\n```\n~~~~\n[r](../nope.md)\n~~~~"
        check("fences untouched", rw(fenced, "docs/a.md"), fenced)
        region = ("<!-- repo-links: base=../../CONTRIBUTING.md -->\n"
                  "[i](docs/a.md#x) [r](README.md) [c](crates/x/src/lib.rs)\n"
                  "<!-- repo-links: end -->\n[after](../a.md)")
        check("region", rw(region, "docs/sub/b.md"),
              "<!-- repo-links: base=../../CONTRIBUTING.md -->\n"
              "[i](../a.md#x) [r](https://github.com/o/r/blob/main/README.md) "
              "[c](https://github.com/o/r/blob/main/crates/x/src/lib.rs)\n"
              "<!-- repo-links: end -->\n[after](../a.md)")
        raises("missing target", LinkError, lambda: rw("[x](nope.md)", "docs/a.md"))
        raises("leaves repository", LinkError, lambda: rw("[x](../../etc)", "docs/a.md"))
        raises("unclosed region", LinkError,
               lambda: rw("<!-- repo-links: base=../README.md -->\n", "docs/a.md"))
        raises("end without start", LinkError, lambda: rw("<!-- repo-links: end -->", "docs/a.md"))
        raises("region twice", LinkError, lambda: rw(
            "<!-- repo-links: base=../README.md -->\n<!-- repo-links: base=../README.md -->",
            "docs/a.md"))
        raises("missing base", LinkError,
               lambda: rw("<!-- repo-links: base=../NOPE.md -->", "docs/a.md"))

        # The protocol, in both JSON shapes mdBook has used (`items`, `sections`).
        def context(**html):
            return {"root": root, "renderer": "html", "mdbook_version": "0.5.4",
                    "config": {"book": {"src": "docs"}, "output": {"html": html},
                               "preprocessor": {"repo-links": {"branch": "v1"}}}}

        for key in ["items", "sections"]:
            book = {key: [{"Chapter": {"name": "A", "content": "[r](../README.md)",
                                       "path": "a.md", "source_path": "a.md",
                                       "sub_items": [{"Chapter": {
                                           "name": "B", "content": "[a](../a.md)",
                                           "path": "sub/b.md", "source_path": "sub/b.md",
                                           "sub_items": []}}]}},
                          {"PartTitle": "P"}, "Separator"]}
            out = json.loads(process(json.dumps([context(**{"git-repository-url": "https://g/o/r"}), book])))
            check(f"protocol {key} top", out[key][0]["Chapter"]["content"],
                  "[r](https://g/o/r/blob/v1/README.md)")
            check(f"protocol {key} nested", out[key][0]["Chapter"]["sub_items"][0]["Chapter"]["content"],
                  "[a](../a.md)")
            check(f"protocol {key} rest", out[key][1:], [{"PartTitle": "P"}, "Separator"])

        # Malformed input is an error, never a traceback.
        for name, raw in [("empty", ""), ("truncated", '[{"root": "'), ("not a pair", "[1, 2]"),
                          ("object", "{}"), ("one element", "[{}]"),
                          ("no root", json.dumps([{"config": {}}, {}])),
                          ("config not a map", json.dumps([{"root": root, "config": []}, {}])),
                          ("no repository", json.dumps([context(), {"items": []}])),
                          ("src not a string", json.dumps([{"root": root, "config": {
                              "book": {"src": 3}, "output": {"html": {"git-repository-url": "u"}}}}, {}]))]:
            raises(f"malformed: {name}", ValueError, lambda raw=raw: process(raw))
        raises("malformed: too deep", ValueError, lambda: process("[" * 200000 + "]" * 200000))
        # The command-line path: every malformed input is exit 1 with a one-line message.
        for name, raw in [("cli empty", b""), ("cli not UTF-8", b"\xff\xfe["),
                          ("cli truncated", b'[{"root": "'), ("cli too deep", b"[" * 200000),
                          ("cli wrong shape", b'{"a": 1}')]:
            code, out, err = run(raw)
            check(name, (code, out, err.startswith("mdbook-repo-links: ") and "\n" not in err),
                  (1, "", True))

        # Code blocks: indented ones are code (outside lists), and a fence closes only on a
        # bare fence line.
        indented = "Text:\n\n    [r](../nope.md)\n\n    still code [r](../nope.md)\n\n[r](../README.md)"
        check("indented code untouched", rw(indented, "docs/a.md"),
              indented.replace("[r](../README.md)",
                               "[r](https://github.com/o/r/blob/main/README.md)"))
        in_list = "- item\n\n    [r](../README.md)"
        check("indented list continuation rewritten", rw(in_list, "docs/a.md"),
              "- item\n\n    [r](https://github.com/o/r/blob/main/README.md)")
        check("paragraph continuation is not code", rw("Text\n    [r](../README.md)", "docs/a.md"),
              "Text\n    [r](https://github.com/o/r/blob/main/README.md)")
        info = "```sh\n```not-a-close\n[r](../nope.md)\n```\n[r](../README.md)"
        check("closing fence has no info string", rw(info, "docs/a.md"),
              info.replace("[r](../README.md)", "[r](https://github.com/o/r/blob/main/README.md)"))

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"mdbook-repo-links self-test: FAIL ({len(failures)} case(s))", file=sys.stderr)
        return 1
    print("mdbook-repo-links self-test: PASS")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "supports":
        return 0
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 1:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    code, out, err = run(sys.stdin.buffer.read())
    sys.stdout.write(out)
    if err:
        print(err, file=sys.stderr)
    return code


def run(raw_bytes):
    """(exit code, stdout, stderr message) of the preprocessor on the bytes `raw_bytes`: any
    malformed input is a one-line error and exit 1, never a traceback."""
    try:
        return 0, process(raw_bytes.decode("utf-8")), ""
    except UnicodeDecodeError as e:
        return 1, "", f"mdbook-repo-links: input is not UTF-8: {e}"
    except json.JSONDecodeError as e:
        return 1, "", f"mdbook-repo-links: input is not JSON: {e}"
    except RecursionError:
        return 1, "", "mdbook-repo-links: input is nested too deeply"
    except (ValueError, LinkError) as e:
        return 1, "", f"mdbook-repo-links: {e}"


if __name__ == "__main__":
    sys.exit(main(sys.argv))
