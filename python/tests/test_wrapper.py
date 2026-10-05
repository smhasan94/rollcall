"""The PyPI wrapper (python/src/rollcall/_cli.py) and python/scripts/embed-release.py.

Downloads come from a local HTTP server serving fake release assets (a shell script standing in
for the binary), so the tests are offline. The tests that run the binary need a POSIX shell and
are skipped on Windows; everything up to running it (download, checksum, extraction, errors)
runs everywhere.
"""

from __future__ import annotations

import io
import json
import os
import re
import ssl
import stat
import subprocess
import urllib.error
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import rollcall
from rollcall import _cli

from conftest import (
    FAKE_BINARY,
    PYTHON_DIR,
    REPO,
    make_archive,
    release_json,
    sha256,
    write_release,
)

POSIX = os.name == "posix"
EMBED = PYTHON_DIR / "scripts" / "embed-release.py"
VERSION = rollcall.TAG[1:]


def host_key():
    try:
        return _cli.platform_key()
    except _cli.WrapperError:
        pytest.skip("no rollcall release binary for this platform")


def run_wrapper(package, tmp_path, args, base_url, extra_env=None):
    """Runs the console script's main() in a fresh interpreter, as pip's script does."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROLLCALL_")}
    env["PYTHONPATH"] = str(package)
    env["ROLLCALL_CACHE_DIR"] = str(tmp_path / "cache")
    env["ROLLCALL_RELEASE_BASE_URL"] = base_url
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-c", "import sys; from rollcall._cli import main; sys.exit(main())"]
        + list(args),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def cache_files(tmp_path):
    root = tmp_path / "cache"
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()) if root.exists() else []


def cached_binary(tmp_path, key):
    return tmp_path / "cache" / "rollcall" / "bin" / rollcall.TAG / key / _cli.binary_name(key)


# --- platform_key, cache_dir -----------------------------------------------------------------


@pytest.mark.parametrize(
    "system, machine, key",
    [
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "AMD64", "linux-amd64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Linux", "arm64", "linux-arm64"),
        ("Darwin", "arm64", "darwin-universal"),
        ("Darwin", "x86_64", "darwin-universal"),
        ("Windows", "AMD64", "windows-amd64"),
    ],
)
def test_platform_key_maps_supported_platforms(system, machine, key):
    assert _cli.platform_key(system, machine) == key
    assert key in _cli.KEYS


@pytest.mark.parametrize(
    "system, machine",
    [("Linux", "riscv64"), ("Linux", "armv7l"), ("Windows", "ARM64"), ("FreeBSD", "amd64"), ("", "")],
)
def test_platform_key_rejects_unsupported_platforms(system, machine):
    with pytest.raises(_cli.WrapperError) as e:
        _cli.platform_key(system, machine)
    assert e.value.code == 69
    assert "no rollcall binary for this platform" in e.value.message
    assert "cargo install rollcall" in e.value.message


@pytest.mark.skipif(not POSIX, reason="POSIX absolute paths")
def test_cache_dir_follows_the_identifier_cache_rules():
    # The same precedence as rollcall-core's identify::source::cache_root.
    cases = [
        ({"ROLLCALL_CACHE_DIR": "/r", "XDG_CACHE_HOME": "/x", "HOME": "/h"}, False, "/r"),
        ({"XDG_CACHE_HOME": "/x", "HOME": "/h"}, False, "/x"),
        ({"HOME": "/h"}, False, "/h/.cache"),
        ({"ROLLCALL_CACHE_DIR": "rel", "XDG_CACHE_HOME": "rel2", "HOME": "/h"}, False, "/h/.cache"),
        ({"ROLLCALL_CACHE_DIR": "", "HOME": "/h"}, False, "/h/.cache"),
        ({"LOCALAPPDATA": "/l", "XDG_CACHE_HOME": "/x", "HOME": "/h"}, True, "/l"),
        ({"ROLLCALL_CACHE_DIR": "/r", "LOCALAPPDATA": "/l"}, True, "/r"),
    ]
    for env, windows, base in cases:
        assert _cli.cache_dir(env, windows) == Path(base) / "rollcall", env


def test_cache_dir_without_a_usable_variable_exits_69():
    for env, windows in [({}, False), ({"HOME": "relative"}, False), ({"HOME": "/h"}, True)]:
        with pytest.raises(_cli.WrapperError) as e:
            _cli.cache_dir(env, windows)
        assert e.value.code == 69
        assert "ROLLCALL_CACHE_DIR" in e.value.message


# --- release.json ----------------------------------------------------------------------------

GOOD_SUMS = {key: "{:064x}".format(i + 1) for i, key in enumerate(_cli.KEYS)}


def test_load_release_without_release_json_is_not_a_release_build(tmp_path):
    with pytest.raises(_cli.WrapperError) as e:
        _cli.load_release(tmp_path / "release.json")
    assert e.value.code == 69
    assert "not a release build" in e.value.message
    assert "ROLLCALL_BIN" in e.value.message


def test_load_release_accepts_a_well_formed_file(tmp_path):
    path = tmp_path / "release.json"
    path.write_text(json.dumps(release_json(GOOD_SUMS)))
    release = _cli.load_release(path)
    assert release["tag"] == rollcall.TAG
    assert release["assets"]["linux-amd64"] == {
        "name": "rollcall-{}-linux-amd64.tar.gz".format(rollcall.TAG),
        "sha256": GOOD_SUMS["linux-amd64"],
    }
    assert release["assets"]["windows-amd64"]["name"].endswith("-windows-amd64.zip")


def _mutated(mutate):
    data = release_json(GOOD_SUMS)
    mutate(data)
    return json.dumps(data).encode()


MALFORMED = {
    "empty": (b"", "not valid JSON"),
    "truncated": (json.dumps(release_json(GOOD_SUMS)).encode()[:40], "not valid JSON"),
    "not utf-8": (b"\xff\xfe{}", "not valid JSON"),
    "a list": (b"[]", "expected a JSON object"),
    "tag not a string": (_mutated(lambda d: d.update(tag=1)), "`tag` must be a string"),
    "another tag": (_mutated(lambda d: d.update(tag="v9.9.9")), "this package is for"),
    "assets not an object": (_mutated(lambda d: d.update(assets=[])), "`assets` must be an object"),
    "missing platform": (_mutated(lambda d: d["assets"].pop("linux-arm64")), "must list exactly"),
    "extra platform": (_mutated(lambda d: d["assets"].update(x={})), "must list exactly"),
    "entry not an object": (
        _mutated(lambda d: d["assets"].update({"linux-amd64": "x"})),
        "`assets.linux-amd64` must be an object",
    ),
    "wrong name": (
        _mutated(lambda d: d["assets"]["linux-amd64"].update(name="../../evil")),
        "`assets.linux-amd64.name` must be",
    ),
    "short digest": (
        _mutated(lambda d: d["assets"]["darwin-universal"].update(sha256="abc")),
        "64 lowercase hex digits",
    ),
    "uppercase digest": (
        _mutated(lambda d: d["assets"]["darwin-universal"].update(sha256="A" * 64)),
        "64 lowercase hex digits",
    ),
    "digest not a string": (
        _mutated(lambda d: d["assets"]["darwin-universal"].update(sha256=None)),
        "64 lowercase hex digits",
    ),
}


@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_load_release_rejects_malformed_files(tmp_path, case):
    raw, needle = MALFORMED[case]
    path = tmp_path / "release.json"
    path.write_bytes(raw)
    with pytest.raises(_cli.WrapperError) as e:
        _cli.load_release(path)
    assert e.value.code == 65, case
    assert needle in e.value.message, (case, e.value.message)
    assert str(path) in e.value.message


# --- extract ---------------------------------------------------------------------------------


def _extract(tmp_path, data, key="linux-amd64"):
    archive = tmp_path / _cli.asset_name(rollcall.TAG, key)
    archive.write_bytes(data)
    dest_dir = tmp_path / "bin"
    dest_dir.mkdir(exist_ok=True)
    dest = dest_dir / _cli.binary_name(key)
    _cli.extract(archive, rollcall.TAG, key, dest)
    return dest


@pytest.mark.parametrize("key", ["linux-amd64", "windows-amd64"])
def test_extract_writes_only_the_binary_executable(tmp_path, key):
    dest = _extract(tmp_path, make_archive(key, payload=b"BINARY"), key)
    assert dest.read_bytes() == b"BINARY"
    assert sorted(p.name for p in dest.parent.iterdir()) == [dest.name]
    if POSIX:
        assert stat.S_IMODE(dest.stat().st_mode) == 0o755


def _tar(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as t:
        for info, data in entries:
            t.addfile(info, io.BytesIO(data) if data is not None else None)
    return out.getvalue()


def _member(kind, name="rollcall-{}-linux-amd64/rollcall".format(rollcall.TAG)):
    info = tarfile.TarInfo(name)
    if kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = "/bin/sh"
    elif kind == "dir":
        info.type = tarfile.DIRTYPE
    return info


GOOD_TAR = make_archive("linux-amd64")
MALFORMED_ARCHIVES = {
    "empty": (b"", "linux-amd64", "cannot extract"),
    "not gzip": (b"this is not an archive", "linux-amd64", "cannot extract"),
    "truncated": (GOOD_TAR[: len(GOOD_TAR) // 2], "linux-amd64", "cannot extract"),
    "no binary": (_tar([(tarfile.TarInfo("rollcall-x/README.md"), None)]), "linux-amd64", "has no"),
    "binary at the top level": (_tar([(tarfile.TarInfo("rollcall"), None)]), "linux-amd64", "has no"),
    "symlink binary": (_tar([(_member("symlink"), None)]), "linux-amd64", "not a regular file"),
    "directory binary": (_tar([(_member("dir"), None)]), "linux-amd64", "not a regular file"),
    "zip empty": (b"", "windows-amd64", "cannot extract"),
    "zip truncated": (make_archive("windows-amd64")[:30], "windows-amd64", "cannot extract"),
    "zip no binary": (make_archive("linux-amd64"), "windows-amd64", "cannot extract"),
}


@pytest.mark.parametrize("case", sorted(MALFORMED_ARCHIVES))
def test_extract_rejects_malformed_archives(tmp_path, case):
    data, key, needle = MALFORMED_ARCHIVES[case]
    with pytest.raises(_cli.WrapperError) as e:
        _extract(tmp_path, data, key)
    assert e.value.code == 65, case
    assert needle in e.value.message, (case, e.value.message)
    # Nothing written: no binary, no temporary file.
    assert list((tmp_path / "bin").iterdir()) == []


def test_zip_without_the_binary_member_names_it(tmp_path):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("rollcall-{}-windows-amd64/README.md".format(rollcall.TAG), b"x")
    with pytest.raises(_cli.WrapperError) as e:
        _extract(tmp_path, out.getvalue(), "windows-amd64")
    assert e.value.code == 65
    assert "has no rollcall-{}-windows-amd64/rollcall.exe".format(rollcall.TAG) in e.value.message


# --- the console script, end to end ----------------------------------------------------------


@pytest.mark.skipif(not POSIX, reason="the fake binary is a shell script")
def test_first_run_downloads_verifies_and_caches(tmp_path, package, release):
    key = host_key()
    write_release(package, release_json(release.sums))
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 0, out
    assert out.stdout == "rollcall {}\nargs: --version\n".format(VERSION)
    asset = _cli.asset_name(rollcall.TAG, key)
    assert "rollcall: downloading rollcall {} ({}) from {}/{}".format(
        rollcall.TAG, key, release.url, asset
    ) in out.stderr
    assert "rollcall: sha256 {} verified".format(release.sums[key]) in out.stderr
    assert release.server.requests == ["/" + asset]
    binary = cached_binary(tmp_path, key)
    assert binary.read_bytes() == FAKE_BINARY.encode()
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    # Only the binary is kept: no archive, no temporary directory.
    assert cache_files(tmp_path) == [str(binary.relative_to(tmp_path / "cache"))]


@pytest.mark.skipif(not POSIX, reason="the fake binary is a shell script")
def test_second_run_uses_the_cache_without_the_network(tmp_path, package, release):
    host_key()
    write_release(package, release_json(release.sums))
    assert run_wrapper(package, tmp_path, ["--version"], release.url).returncode == 0
    release.server.close()
    out = run_wrapper(package, tmp_path, ["--help"], release.url)
    assert out.returncode == 0, out
    assert out.stdout == "rollcall {}\nargs: --help\n".format(VERSION)
    assert out.stderr == ""
    assert len(release.server.requests) == 1


@pytest.mark.skipif(not POSIX, reason="the fake binary is a shell script")
def test_main_passes_arguments_and_exit_code_through(tmp_path, package, release):
    host_key()
    write_release(package, release_json(release.sums))
    out = run_wrapper(package, tmp_path, ["fail", "--x", "a b"], release.url)
    assert out.returncode == 3, out
    assert out.stdout.endswith("args: fail --x a b\n")


def embed(sums_file, out, *extra):
    return subprocess.run(
        [sys.executable, str(EMBED), "--sums", str(sums_file), "--out", str(out)] + list(extra),
        capture_output=True,
        text=True,
    )


def test_tampered_checksum_aborts_install(tmp_path, package, release):
    key = host_key()
    # The release's real SHA256SUMS, embedded with --tamper, as the release workflow and
    # install-check's pip-tamper job build the tampered wheel.
    result = embed(release.assets / "SHA256SUMS", package / "rollcall" / "release.json", "--tamper")
    assert result.returncode == 0, result
    assert "TAMPERED" in result.stderr
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 65, out
    assert out.stdout == ""
    asset = _cli.asset_name(rollcall.TAG, key)
    got = release.sums[key]
    expected = "{:x}".format(int(got[0], 16) ^ 1) + got[1:]
    assert (
        "rollcall: checksum mismatch for {}: expected {}, got {}; the download was discarded\n".format(
            asset, expected, got
        )
        in out.stderr
    )
    assert release.server.requests == ["/" + asset]
    assert cache_files(tmp_path) == [], "the bad download or a binary was kept"


def test_tampered_download_aborts_install(tmp_path, package, release):
    key = host_key()
    write_release(package, release_json(release.sums))
    evil = make_archive(key, payload=b"#!/bin/sh\necho pwned\n")
    release.replace_asset(key, evil)
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 65, out
    assert out.stdout == ""
    assert re.search(
        r"^rollcall: checksum mismatch for \S+: expected {}, got {}; the download was discarded$".format(
            release.sums[key], sha256(evil)
        ),
        out.stderr,
        re.M,
    ), out.stderr
    assert cache_files(tmp_path) == []


def test_download_failure_exits_69(tmp_path, package, release):
    key = host_key()
    write_release(package, release_json(release.sums))
    (release.assets / _cli.asset_name(rollcall.TAG, key)).unlink()
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 69, out
    assert "rollcall: cannot download {}/".format(release.url) in out.stderr
    assert "HTTP 404" in out.stderr
    release.server.close()
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 69, out
    assert "rollcall: cannot download" in out.stderr
    assert cache_files(tmp_path) == []


def test_not_a_release_build_exits_69_with_a_clear_message(tmp_path, package, release):
    out = run_wrapper(package, tmp_path, ["--version"], release.url)
    assert out.returncode == 69, out
    assert out.stderr.startswith("rollcall: this rollcall package is not a release build")
    assert release.server.requests == []


@pytest.mark.skipif(not POSIX, reason="the fake binary is a shell script")
def test_rollcall_bin_override_skips_the_download(tmp_path, package, release):
    fake = tmp_path / "my-rollcall"
    fake.write_text("#!/bin/sh\necho custom $*\n")
    fake.chmod(0o755)
    out = run_wrapper(package, tmp_path, ["--version"], release.url, {"ROLLCALL_BIN": str(fake)})
    assert out.returncode == 0, out
    assert out.stdout == "custom --version\n"
    assert release.server.requests == []
    out = run_wrapper(
        package, tmp_path, ["--version"], release.url, {"ROLLCALL_BIN": str(tmp_path / "nope")}
    )
    assert out.returncode == 69
    assert "rollcall: ROLLCALL_BIN=" in out.stderr


def test_unsupported_platform_exits_69(monkeypatch, tmp_path, capsys):
    path = tmp_path / "release.json"
    path.write_text(json.dumps(release_json(GOOD_SUMS)))
    monkeypatch.setattr(_cli, "_release_path", lambda: path)
    monkeypatch.setattr(_cli.platform, "system", lambda: "Plan9")
    monkeypatch.delenv("ROLLCALL_BIN", raising=False)
    assert _cli.main(["--version"]) == 69
    assert capsys.readouterr().err.startswith("rollcall: no rollcall binary for this platform")


# --- embed-release.py ------------------------------------------------------------------------


def write_sums(path, sums, tag=rollcall.TAG):
    lines = ["{}  {}\n".format(sums[k], _cli.asset_name(tag, k)) for k in _cli.KEYS]
    path.write_text("".join(lines))
    return path


def test_embed_release_writes_the_release_json(tmp_path):
    sums = write_sums(tmp_path / "SHA256SUMS", GOOD_SUMS)
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert embed(sums, a).returncode == 0
    assert embed(sums, b).returncode == 0
    assert a.read_bytes() == b.read_bytes(), "not deterministic"
    assert json.loads(a.read_text()) == release_json(GOOD_SUMS)
    assert a.read_bytes().endswith(b"}\n") and b"\r" not in a.read_bytes()
    assert _cli.load_release(a)["assets"]["linux-arm64"]["sha256"] == GOOD_SUMS["linux-arm64"]


def test_embed_release_tamper_flips_every_digest(tmp_path):
    sums = write_sums(tmp_path / "SHA256SUMS", GOOD_SUMS)
    out = tmp_path / "release.json"
    assert embed(sums, out, "--tamper").returncode == 0
    release = _cli.load_release(out)
    for key in _cli.KEYS:
        got, want = release["assets"][key]["sha256"], GOOD_SUMS[key]
        assert got != want and got[1:] == want[1:], key


def test_embed_release_rejects_malformed_sums(tmp_path):
    good = "".join(
        "{}  {}\n".format(GOOD_SUMS[k], _cli.asset_name(rollcall.TAG, k)) for k in _cli.KEYS
    )
    cases = [
        ("empty", b"", 65, "does not list"),
        ("missing asset", good.splitlines(True)[1:], 65, "does not list"),
        ("malformed line", good + "nonsense\n", 65, "not a `<sha256>  <file>` line"),
        ("short digest", "abc  x.tar.gz\n", 65, "not a `<sha256>  <file>` line"),
        ("path in name", "{}  ../x.tar.gz\n".format("0" * 64), 65, "not a `<sha256>  <file>` line"),
        ("duplicate", good + good.splitlines(True)[0], 65, "listed twice"),
        ("not utf-8", b"\xff\xfe", 65, "not UTF-8"),
    ]
    for name, content, code, needle in cases:
        sums = tmp_path / "SHA256SUMS"
        if isinstance(content, list):
            content = "".join(content)
        sums.write_bytes(content if isinstance(content, bytes) else content.encode())
        out = tmp_path / (name + ".json")
        result = embed(sums, out)
        assert result.returncode == code, (name, result)
        assert needle in result.stderr, (name, result.stderr)
        assert not out.exists(), name
    result = embed(tmp_path / "missing", tmp_path / "x.json")
    assert result.returncode == 66 and "cannot read" in result.stderr
    write_sums(tmp_path / "SHA256SUMS", GOOD_SUMS)
    result = embed(tmp_path / "SHA256SUMS", tmp_path / "x.json", "--tag", "v9.9.9")
    assert result.returncode == 65 and "is not this package's" in result.stderr
    result = embed(tmp_path / "SHA256SUMS", tmp_path / "x.json", "--bogus")
    assert result.returncode == 64


# --- versions --------------------------------------------------------------------------------


def test_versions_match_the_cargo_workspace():
    cargo = (REPO / "Cargo.toml").read_text()
    section = cargo.split("[workspace.package]", 1)[1]
    version = re.search(r'^version = "([^"]+)"', section, re.M).group(1)
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-(alpha|beta|rc)\.(\d+))?", version)
    assert m, version
    pep440 = m.group(1) + ({"alpha": "a", "beta": "b", "rc": "rc"}[m.group(2)] + m.group(3) if m.group(2) else "")
    assert rollcall.__version__ == pep440
    assert rollcall.TAG == "v" + version
    pyproject = (PYTHON_DIR / "pyproject.toml").read_text()
    assert re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1) == pep440


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed")),
        ssl.SSLError(1, "wrong version number"),
    ],
)
def test_tls_failure_names_the_other_ways_to_install(monkeypatch, tmp_path, error):
    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(_cli.urllib.request, "urlopen", fail)
    with pytest.raises(_cli.WrapperError) as e:
        _cli.download("https://example.invalid/x.tar.gz", tmp_path / "x")
    assert e.value.code == 69
    assert "TLS failed" in e.value.message
    assert "cargo install rollcall" in e.value.message
    assert "https://github.com/smhasan94/rollcall/releases" in e.value.message
    assert not (tmp_path / "x").exists() or (tmp_path / "x").stat().st_size == 0


@pytest.mark.skipif(os.name != "nt", reason="runs a real Windows executable")
def test_windows_exe_is_extracted_and_run_with_arguments_and_exit_code(tmp_path, package, release):
    # A real PE executable as the binary: cmd.exe renamed rollcall.exe inside the zip, as
    # scripts/package-release.sh lays out the windows-amd64 asset.
    key = host_key()
    assert key == "windows-amd64"
    cmd = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
    archive = make_archive(key, payload=cmd.read_bytes())
    release.replace_asset(key, archive)
    sums = dict(release.sums, **{key: sha256(archive)})
    write_release(package, release_json(sums))
    out = run_wrapper(
        package, tmp_path, ["/c", "echo", "rollcall-through-the-wrapper", "&", "exit", "7"], release.url
    )
    assert out.returncode == 7, out
    assert "rollcall-through-the-wrapper" in out.stdout
    assert "rollcall: sha256 {} verified".format(sums[key]) in out.stderr
    binary = cached_binary(tmp_path, key)
    assert binary.name == "rollcall.exe"
    assert binary.read_bytes() == cmd.read_bytes()
    # The second run starts the cached .exe without downloading.
    out = run_wrapper(package, tmp_path, ["/c", "exit", "3"], release.url)
    assert out.returncode == 3, out
    assert "downloading" not in out.stderr
    assert len(release.server.requests) == 1
