#!/usr/bin/env bash
# Packages a rollcall binary as a release asset, deterministically.
#
# Usage: scripts/package-release.sh BINARY TAG PLATFORM OUTDIR
#
#   BINARY     the built binary (target/<triple>/dist/rollcall, or rollcall.exe)
#   TAG        the release tag, e.g. v0.1.0 or v0.1.0-rc.1
#   PLATFORM   linux-amd64, linux-arm64, darwin-universal or windows-amd64
#   OUTDIR     where the asset goes (created if missing)
#
# Writes OUTDIR/rollcall-TAG-PLATFORM.tar.gz (.zip for windows-amd64) holding one directory,
# rollcall-TAG-PLATFORM/, with the binary (rollcall, or rollcall.exe; mode 0755), LICENSE and
# README.md (mode 0644), and prints the asset's path. This is the layout rollcall-action's
# install.sh and the PyPI wrapper (python/src/rollcall/_cli.py) unpack.
#
# The same inputs give byte-identical assets: entries in a fixed order, owner 0/0 with no
# names, every mtime (and the gzip header's) set to $SOURCE_DATE_EPOCH (default 315532800,
# 1980-01-01, the earliest time a zip can hold), no gzip file name.
#
# Environment:
#   SOURCE_DATE_EPOCH   the timestamp to record (the release workflow uses the tag's commit
#                       time)
#   PYTHON              the Python 3 to run (default: python3, else python)
#
# Exit codes: 0 written; 64 usage error; 66 BINARY, LICENSE or README.md missing; 1 anything
# else.
set -euo pipefail

# On Windows (Git Bash) the Windows form of the path (pwd -W), which Python can open.
ROOT="$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })"

die() {
    local code="$1"
    shift
    echo "package-release: $*" >&2
    exit "$code"
}

[[ $# -eq 4 ]] || die 64 "usage: package-release.sh BINARY TAG PLATFORM OUTDIR"
binary="$1" tag="$2" plat="$3" outdir="$4"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] ||
    die 64 "TAG must be a release tag such as v0.1.0 or v0.1.0-rc.1, not '$tag'"
case "$plat" in
    linux-amd64 | linux-arm64 | darwin-universal) ext=tar.gz exe=rollcall ;;
    windows-amd64) ext=zip exe=rollcall.exe ;;
    *) die 64 "PLATFORM must be linux-amd64, linux-arm64, darwin-universal or windows-amd64, not '$plat'" ;;
esac
epoch="${SOURCE_DATE_EPOCH:-315532800}"
[[ "$epoch" =~ ^[0-9]+$ && "$epoch" -ge 315532800 ]] ||
    die 64 "SOURCE_DATE_EPOCH must be a Unix time no earlier than 315532800 (1980-01-01), not '$epoch'"
[[ -f "$binary" ]] || die 66 "no such binary: $binary"
for f in LICENSE README.md; do
    [[ -f "$ROOT/$f" ]] || die 66 "no $ROOT/$f"
done

py="${PYTHON:-}"
if [[ -z "$py" ]]; then
    if command -v python3 >/dev/null 2>&1; then py=python3; else py=python; fi
fi

mkdir -p "$outdir"
asset="$outdir/rollcall-$tag-$plat.$ext"
"$py" - "$asset" "rollcall-$tag-$plat" "$epoch" \
    "$exe=$binary" "LICENSE=$ROOT/LICENSE" "README.md=$ROOT/README.md" <<'PY'
import gzip
import io
import os
import sys
import tarfile
import time
import zipfile

asset, prefix, epoch = sys.argv[1], sys.argv[2], int(sys.argv[3])
files = sorted(a.split("=", 1) for a in sys.argv[4:])
tmp = asset + ".tmp"


def mode(name):
    return 0o755 if name.startswith("rollcall") else 0o644


if asset.endswith(".zip"):
    stamp = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(tmp, "w") as z:
        for name, path in files:
            info = zipfile.ZipInfo(prefix + "/" + name, date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # Unix, so the mode below is honoured
            info.external_attr = (0o100000 | mode(name)) << 16
            with open(path, "rb") as f:
                z.writestr(info, f.read(), compresslevel=9)
else:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, path in files:
            info = tarfile.TarInfo(prefix + "/" + name)
            with open(path, "rb") as f:
                data = f.read()
            info.size = len(data)
            info.mtime = epoch
            info.mode = mode(name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            t.addfile(info, io.BytesIO(data))
    with open(tmp, "wb") as out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=epoch, compresslevel=9) as g:
            g.write(raw.getvalue())
os.replace(tmp, asset)
PY
echo "$asset"
