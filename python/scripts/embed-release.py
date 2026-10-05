#!/usr/bin/env python3
"""Records a release's SHA-256s in the wrapper package before it is built.

Usage:
    python/scripts/embed-release.py --sums SHA256SUMS [--tag TAG] [--tamper] [--out FILE]

Reads the release's SHA256SUMS (scripts/release-sums.sh writes it), checks that it lists every
platform's asset for TAG (default: rollcall.TAG from python/src/rollcall/__init__.py, which
must equal TAG), and writes python/src/rollcall/release.json (or FILE), which the wrapper
verifies every download against. The file is generated and gitignored: a package built
without it is not a release build and refuses to download anything.

--tamper flips one hex digit of every digest: the wheel built from it must refuse every real
download (the release workflow's and install-check's tamper test).

Exit codes: 0 written; 64 usage error; 65 a malformed SHA256SUMS, a missing asset or a tag
that is not this package's; 66 SHA256SUMS cannot be read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PYTHON_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PYTHON_DIR / "src"))

from rollcall import TAG  # noqa: E402
from rollcall import _cli  # noqa: E402

LINE = re.compile(r"^([0-9a-f]{64}) [ *]([^\s/\\]+)$")


class Failure(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def parse_sums(text: str, source: str) -> dict:
    """``{asset name: sha256}`` from sha256sum-format text."""
    sums = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = LINE.match(line)
        if m is None:
            raise Failure(
                65, "{}:{}: not a `<sha256>  <file>` line: {!r}".format(source, number, line)
            )
        digest, name = m.groups()
        if name in sums:
            raise Failure(65, "{}:{}: {} is listed twice".format(source, number, name))
        sums[name] = digest
    return sums


def tamper(digest: str) -> str:
    return "{:x}".format(int(digest[0], 16) ^ 1) + digest[1:]


def build(sums: dict, tag: str, tampered: bool, source: str) -> dict:
    assets = {}
    for key in _cli.KEYS:
        name = _cli.asset_name(tag, key)
        if name not in sums:
            raise Failure(65, "{} does not list {}".format(source, name))
        digest = sums[name]
        assets[key] = {"name": name, "sha256": tamper(digest) if tampered else digest}
    release = {"tag": tag, "assets": assets}
    try:
        _cli.parse_release(release, "release.json")
    except _cli.WrapperError as e:
        raise Failure(65, e.message) from None
    return release


def run(argv: list) -> int:
    parser = argparse.ArgumentParser(prog="embed-release.py", description=__doc__.split("\n")[0])
    parser.add_argument("--sums", required=True, type=Path, help="the release's SHA256SUMS")
    parser.add_argument("--tag", default=TAG, help="the release tag (default: %(default)s)")
    parser.add_argument("--tamper", action="store_true", help="flip a digit of every digest")
    parser.add_argument(
        "--out",
        type=Path,
        default=PYTHON_DIR / "src" / "rollcall" / "release.json",
        help="where to write release.json",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    if args.tag != TAG:
        raise Failure(
            65,
            "tag {} is not this package's ({} in python/src/rollcall/__init__.py; "
            "scripts/release-version.sh check)".format(args.tag, TAG),
        )
    try:
        text = args.sums.read_bytes().decode("utf-8")
    except OSError as e:
        raise Failure(66, "cannot read {}: {}".format(args.sums, e)) from None
    except UnicodeDecodeError as e:
        raise Failure(65, "{}: not UTF-8: {}".format(args.sums, e)) from None
    release = build(parse_sums(text, str(args.sums)), args.tag, args.tamper, str(args.sums))
    # The same bytes on every platform (no \r\n on Windows).
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(release, indent=2, sort_keys=True) + "\n")
    note = " (TAMPERED: every digest has one digit flipped)" if args.tamper else ""
    print("embed-release: wrote {} for {}{}".format(args.out, args.tag, note), file=sys.stderr)
    return 0


def main() -> int:
    try:
        return run(sys.argv[1:])
    except Failure as e:
        print("embed-release: " + e.message, file=sys.stderr)
        return e.code


if __name__ == "__main__":
    sys.exit(main())
