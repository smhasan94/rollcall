"""Test helpers: the wrapper imported from python/src, release archives, a local HTTP server."""

from __future__ import annotations

import functools
import hashlib
import http.server
import io
import json
import shutil
import socketserver
import sys
import tarfile
import threading
import zipfile
from pathlib import Path
from typing import Dict, List

import pytest

PYTHON_DIR = Path(__file__).resolve().parent.parent
REPO = PYTHON_DIR.parent
sys.path.insert(0, str(PYTHON_DIR / "src"))

import rollcall  # noqa: E402
from rollcall import _cli  # noqa: E402

#: The fake binary every test archive holds: prints a version line like rollcall's, then its
#: arguments, and exits 3 when asked to (`fail`).
FAKE_BINARY = (
    "#!/bin/sh\n"
    'echo "rollcall {version}"\n'
    'echo "args: $*"\n'
    '[ "$1" = fail ] && exit 3\n'
    "exit 0\n"
).format(version=rollcall.TAG[1:])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_archive(key: str, tag: str = rollcall.TAG, payload: bytes = None) -> bytes:
    """A release asset as scripts/package-release.sh lays it out."""
    payload = FAKE_BINARY.encode() if payload is None else payload
    prefix = "rollcall-{}-{}".format(tag, key)
    files = [
        (_cli.binary_name(key), payload, 0o755),
        ("LICENSE", b"Apache-2.0\n", 0o644),
        ("README.md", b"# rollcall\n", 0o644),
    ]
    out = io.BytesIO()
    if key.startswith("windows-"):
        with zipfile.ZipFile(out, "w") as z:
            for name, data, mode in files:
                info = zipfile.ZipInfo(prefix + "/" + name)
                info.external_attr = (0o100000 | mode) << 16
                z.writestr(info, data)
    else:
        with tarfile.open(fileobj=out, mode="w:gz") as t:
            for name, data, mode in files:
                info = tarfile.TarInfo(prefix + "/" + name)
                info.size = len(data)
                info.mode = mode
                t.addfile(info, io.BytesIO(data))
    return out.getvalue()


def release_json(sums: Dict[str, str], tag: str = rollcall.TAG) -> dict:
    return {
        "tag": tag,
        "assets": {
            key: {"name": _cli.asset_name(tag, key), "sha256": sums[key]} for key in _cli.KEYS
        },
    }


class _HTTPServer(http.server.ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer.server_bind looks up the host's FQDN, which can take seconds; skip it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Server:
    """Serves a directory on 127.0.0.1, logging every request path."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.requests: List[str] = []
        log = self.requests

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args) -> None:  # quiet
                pass

            def do_GET(self) -> None:
                log.append(self.path)
                super().do_GET()

        handler = functools.partial(Handler, directory=str(root))
        self.httpd = _HTTPServer(("127.0.0.1", 0), handler)
        self.url = "http://127.0.0.1:{}".format(self.httpd.server_address[1])
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class Release:
    """A fake release: every platform's asset served locally, plus SHA256SUMS."""

    def __init__(self, tmp: Path) -> None:
        self.assets = tmp / "assets"
        self.assets.mkdir()
        self.sums: Dict[str, str] = {}
        lines = []
        for key in _cli.KEYS:
            data = make_archive(key)
            name = _cli.asset_name(rollcall.TAG, key)
            (self.assets / name).write_bytes(data)
            self.sums[key] = sha256(data)
            lines.append("{}  {}\n".format(self.sums[key], name))
        (self.assets / "SHA256SUMS").write_text("".join(sorted(lines, key=lambda l: l[66:])))
        self.server = Server(self.assets)
        self.url = self.server.url

    def replace_asset(self, key: str, data: bytes) -> None:
        (self.assets / _cli.asset_name(rollcall.TAG, key)).write_bytes(data)


@pytest.fixture
def release(tmp_path):
    r = Release(tmp_path)
    yield r
    r.server.close()


@pytest.fixture
def package(tmp_path):
    """A copy of the wrapper package (to give it a release.json): returns its parent dir."""
    dest = tmp_path / "pkg"
    shutil.copytree(
        str(PYTHON_DIR / "src" / "rollcall"),
        str(dest / "rollcall"),
        ignore=shutil.ignore_patterns("__pycache__", "release.json"),
    )
    return dest


def write_release(package_dir: Path, data) -> Path:
    path = package_dir / "rollcall" / "release.json"
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path
