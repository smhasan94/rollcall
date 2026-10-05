"""The ``rollcall`` console script: find, or download and verify, the release binary and run it.

On first run for a release the wrapper downloads ``rollcall-<tag>-<platform>.tar.gz`` (``.zip``
on Windows) from the GitHub release, checks its SHA-256 against the digest recorded in this
package's ``release.json`` (written at release time from the release's ``SHA256SUMS``, so it
is as trustworthy as the wheel pip verified), extracts only the ``rollcall`` binary into the
cache and runs it. Later runs use the cached binary without touching the network.

A wrong checksum aborts with exit 65 and deletes the download; a platform without a binary, a
package built outside a release (no ``release.json``), or an unreachable download exits 69.
Every wrapper message starts with ``rollcall: ``; anything else on stderr is rollcall's own.

Environment:

- ``ROLLCALL_BIN``: run this binary instead (no download, no checksum).
- ``ROLLCALL_CACHE_DIR``: the cache root, as for rollcall's identifier cache: else
  ``XDG_CACHE_HOME``, else ``$HOME/.cache`` (``%LOCALAPPDATA%`` on Windows). Relative values are
  ignored. Binaries go to ``<root>/rollcall/bin/<tag>/<platform>/``.
- ``ROLLCALL_RELEASE_BASE_URL``: where the release assets are downloaded from, instead of
  ``https://github.com/smhasan94/rollcall/releases/download/<tag>`` (mirrors, tests).

Standard library only, Python 3.9 or newer.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from . import TAG, __version__

EX_DATAERR = 65
EX_UNAVAILABLE = 69

#: The release platforms, as the asset names spell them.
KEYS = ("darwin-universal", "linux-amd64", "linux-arm64", "windows-amd64")
DEFAULT_BASE_URL = "https://github.com/smhasan94/rollcall/releases/download/{tag}"
DOWNLOAD_TIMEOUT = 60
#: No release archive is anywhere near this; a bigger download is not one.
MAX_DOWNLOAD = 256 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")
#: Where to turn when no verified binary can be had through this package.
FALLBACK = (
    "install rollcall another way: `cargo install rollcall`, or download the archive for "
    "your platform and SHA256SUMS from https://github.com/smhasan94/rollcall/releases and "
    "check it with `sha256sum -c`"
)


class WrapperError(Exception):
    """A failure the wrapper reports as ``rollcall: <message>`` and exits ``code`` with."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def platform_key(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    """The release platform for ``system``/``machine`` (default: this machine)."""
    system = platform.system() if system is None else system
    machine = (platform.machine() if machine is None else machine).lower()
    if system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "linux-amd64"
        if machine in ("aarch64", "arm64"):
            return "linux-arm64"
    elif system == "Darwin":
        if machine in ("x86_64", "arm64"):
            return "darwin-universal"
    elif system == "Windows":
        if machine in ("amd64", "x86_64"):
            return "windows-amd64"
    raise WrapperError(
        EX_UNAVAILABLE,
        "no rollcall binary for this platform ({} {}); release {} has {}. "
        "Install with `cargo install rollcall` instead".format(
            system or "unknown OS", machine or "unknown architecture", TAG, ", ".join(KEYS)
        ),
    )


def binary_name(key: str) -> str:
    """The binary's file name on platform ``key``."""
    return "rollcall.exe" if key.startswith("windows-") else "rollcall"


def asset_name(tag: str, key: str) -> str:
    """The release asset for ``key``: what the release workflow uploads."""
    ext = "zip" if key.startswith("windows-") else "tar.gz"
    return "rollcall-{}-{}.{}".format(tag, key, ext)


def archive_member(tag: str, key: str) -> str:
    """The binary's path inside the asset (scripts/package-release.sh writes it)."""
    return "rollcall-{}-{}/{}".format(tag, key, binary_name(key))


def cache_dir(env: Optional[Mapping[str, str]] = None, windows: Optional[bool] = None) -> Path:
    """``<cache>/rollcall``, by the same rules as rollcall's identifier cache."""
    env = os.environ if env is None else env
    windows = (os.name == "nt") if windows is None else windows

    def var(name: str) -> Optional[Path]:
        value = env.get(name, "")
        if not value:
            return None
        path = Path(value)
        # A cache that moves with the working directory is not a cache.
        return path if path.is_absolute() else None

    base = var("ROLLCALL_CACHE_DIR")
    if base is None:
        if windows:
            base = var("LOCALAPPDATA")
        else:
            base = var("XDG_CACHE_HOME")
            if base is None:
                home = var("HOME")
                base = home / ".cache" if home is not None else None
    if base is None:
        raise WrapperError(
            EX_UNAVAILABLE,
            "no cache directory for the rollcall binary: set ROLLCALL_CACHE_DIR to an absolute path",
        )
    return base / "rollcall"


def parse_release(data: Any, source: str) -> Dict[str, Any]:
    """Checks a decoded ``release.json``; raises ``WrapperError`` (65) naming what is wrong."""

    def bad(what: str) -> WrapperError:
        return WrapperError(EX_DATAERR, "{}: {}".format(source, what))

    if not isinstance(data, dict):
        raise bad("expected a JSON object")
    tag = data.get("tag")
    if not isinstance(tag, str):
        raise bad("`tag` must be a string")
    if tag != TAG:
        raise bad("`tag` is {!r}, but this package is for {}".format(tag, TAG))
    assets = data.get("assets")
    if not isinstance(assets, dict):
        raise bad("`assets` must be an object")
    if sorted(assets) != sorted(KEYS):
        raise bad("`assets` must list exactly {}".format(", ".join(KEYS)))
    out: Dict[str, Dict[str, str]] = {}
    for key in KEYS:
        entry = assets[key]
        if not isinstance(entry, dict):
            raise bad("`assets.{}` must be an object".format(key))
        name, sha256 = entry.get("name"), entry.get("sha256")
        if name != asset_name(tag, key):
            raise bad("`assets.{}.name` must be {!r}".format(key, asset_name(tag, key)))
        if not (isinstance(sha256, str) and len(sha256) == 64 and set(sha256) <= _HEX):
            raise bad("`assets.{}.sha256` must be 64 lowercase hex digits".format(key))
        out[key] = {"name": name, "sha256": sha256}
    return {"tag": tag, "assets": out}


def _release_path() -> Path:
    return Path(__file__).with_name("release.json")


def load_release(path: Optional[Path] = None) -> Dict[str, Any]:
    """The release this package was built for, from its ``release.json``."""
    path = _release_path() if path is None else path
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise WrapperError(
            EX_UNAVAILABLE,
            "this rollcall package is not a release build (it has no release.json, so it "
            "cannot download and verify a binary); install a release from PyPI, or set "
            "ROLLCALL_BIN to a rollcall binary",
        ) from None
    except OSError as e:
        raise WrapperError(EX_UNAVAILABLE, "cannot read {}: {}".format(path, e)) from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise WrapperError(EX_DATAERR, "{}: not valid JSON: {}".format(path, e)) from None
    return parse_release(data, str(path))


def download(url: str, dest: Path, timeout: float = DOWNLOAD_TIMEOUT) -> None:
    """Fetches ``url`` to ``dest``; raises ``WrapperError`` (69) on any failure."""
    request = urllib.request.Request(url, headers={"User-Agent": "rollcall-pip/" + __version__})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, open(dest, "wb") as out:
            total = 0
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD:
                    raise WrapperError(
                        EX_UNAVAILABLE,
                        "cannot download {}: larger than {} bytes".format(url, MAX_DOWNLOAD),
                    )
                out.write(chunk)
    except urllib.error.HTTPError as e:
        raise WrapperError(
            EX_UNAVAILABLE, "cannot download {}: HTTP {} {}".format(url, e.code, e.reason)
        ) from None
    except urllib.error.URLError as e:
        raise _download_error(url, e.reason) from None
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise _download_error(url, e) from None


def _download_error(url: str, reason: object) -> WrapperError:
    """The error for a failed download; a TLS failure (an intercepting proxy, missing CA
    certificates) says so and names the other ways to install. Verification is never skipped."""
    if isinstance(reason, ssl.SSLError):
        return WrapperError(
            EX_UNAVAILABLE,
            "cannot download {}: TLS failed ({}); fix the system's CA certificates or proxy, "
            "or {}".format(url, reason, FALLBACK),
        )
    return WrapperError(EX_UNAVAILABLE, "cannot download {}: {}".format(url, reason))


def sha256_file(path: Path) -> str:
    """The SHA-256 of ``path``, lowercase hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected: str, name: str) -> None:
    """Raises ``WrapperError`` (65), deleting ``path``, unless its SHA-256 is ``expected``."""
    got = sha256_file(path)
    if got != expected:
        try:
            os.remove(path)
        except OSError:
            pass
        raise WrapperError(
            EX_DATAERR,
            "checksum mismatch for {}: expected {}, got {}; the download was discarded".format(
                name, expected, got
            ),
        )


def _copy_member(archive: Path, member: str, zipped: bool, out: Any) -> None:
    """Copies the regular file ``member`` of ``archive`` to the open file ``out``."""
    if zipped:
        with zipfile.ZipFile(archive) as z:
            try:
                info = z.getinfo(member)
            except KeyError:
                raise WrapperError(
                    EX_DATAERR, "{} has no {}".format(archive.name, member)
                ) from None
            if info.is_dir():
                raise WrapperError(
                    EX_DATAERR, "{} in {} is not a regular file".format(member, archive.name)
                )
            with z.open(info) as src:
                shutil.copyfileobj(src, out)
        return
    with tarfile.open(archive, "r:gz") as t:
        try:
            info = t.getmember(member)
        except KeyError:
            raise WrapperError(EX_DATAERR, "{} has no {}".format(archive.name, member)) from None
        src = t.extractfile(info) if info.isfile() else None
        if src is None:
            raise WrapperError(
                EX_DATAERR, "{} in {} is not a regular file".format(member, archive.name)
            )
        with src:
            shutil.copyfileobj(src, out)


def extract(archive: Path, tag: str, key: str, dest: Path) -> None:
    """Extracts only the binary from ``archive`` to ``dest`` (mode 0755), atomically."""
    member = archive_member(tag, key)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".rollcall-", dir=str(dest.parent))
    except OSError as e:
        raise WrapperError(
            EX_UNAVAILABLE, "cannot write to {}: {}".format(dest.parent, e)
        ) from None
    try:
        with os.fdopen(fd, "wb") as out:
            _copy_member(archive, member, key.startswith("windows-"), out)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except (
        tarfile.TarError,
        zipfile.BadZipFile,
        zlib.error,
        EOFError,
        OSError,
        RuntimeError,
        NotImplementedError,
    ) as e:
        raise WrapperError(
            EX_DATAERR, "cannot extract {} from {}: {}".format(member, archive.name, e)
        ) from None
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def ensure_binary(env: Optional[Mapping[str, str]] = None) -> Path:
    """The binary to run: ``ROLLCALL_BIN``, the cached one, or a fresh verified download."""
    env = os.environ if env is None else env
    override = env.get("ROLLCALL_BIN", "")
    if override:
        path = Path(override)
        if not path.is_file():
            raise WrapperError(EX_UNAVAILABLE, "ROLLCALL_BIN={} is not a file".format(override))
        return path
    release = load_release()
    key = platform_key()
    tag = release["tag"]
    asset = release["assets"][key]
    binary = cache_dir(env) / "bin" / tag / key / binary_name(key)
    if binary.is_file():
        return binary
    base = env.get("ROLLCALL_RELEASE_BASE_URL", "") or DEFAULT_BASE_URL.format(tag=tag)
    url = base.rstrip("/") + "/" + asset["name"]
    try:
        binary.parent.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix=".download-", dir=str(binary.parent)))
    except OSError as e:
        raise WrapperError(
            EX_UNAVAILABLE, "cannot create the cache directory {}: {}".format(binary.parent, e)
        ) from None
    print("rollcall: downloading rollcall {} ({}) from {}".format(tag, key, url), file=sys.stderr)
    try:
        archive = work / asset["name"]
        download(url, archive)
        verify_sha256(archive, asset["sha256"], asset["name"])
        extract(archive, tag, key, binary)
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
    print(
        "rollcall: sha256 {} verified; installed {}".format(asset["sha256"], binary),
        file=sys.stderr,
    )
    return binary


def main(argv: Optional[Sequence[str]] = None) -> int:
    """The console script: runs rollcall with ``argv`` (default: this process's arguments)."""
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        binary = ensure_binary()
    except WrapperError as e:
        print("rollcall: " + e.message, file=sys.stderr)
        return e.code
    command = [str(binary)] + args
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        if os.name == "nt":
            try:
                return subprocess.run(command).returncode
            except KeyboardInterrupt:
                return 130
        os.execv(command[0], command)
    except OSError as e:
        print("rollcall: cannot run {}: {}".format(binary, e), file=sys.stderr)
        return EX_UNAVAILABLE
    return 0  # not reached: execv does not return
