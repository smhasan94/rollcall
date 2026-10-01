#!/usr/bin/env bash
# Packages the identifier database as a release tarball, byte-identical on every run:
#
#   ${CARGO_TARGET_DIR:-target}/identifiers/rollcall-identifiers-<db_version>.tar.gz
#     <db_version>/identifiers.yaml
#
# The layout is the cache layout, so installing a database without a rollcall release is
#
#   mkdir -p ~/.cache/rollcall/identifiers
#   tar -xzf rollcall-identifiers-<db_version>.tar.gz -C ~/.cache/rollcall/identifiers
#
# (or $ROLLCALL_CACHE_DIR/rollcall/identifiers, $XDG_CACHE_HOME/rollcall/identifiers). Check
# with `rollcall --version`.
#
# Refuses (exit 1) when scripts/lint-identifiers.sh finds anything, which includes a
# db_version that differs from the rollcall-identifiers crate version. Prints the tarball's
# path and SHA-256 (the last line of output). Offline; needs python3 (for a tar/gzip with
# fixed metadata on any OS). "Byte-identical" holds for a given python3/zlib build: another
# zlib may compress the same tar stream differently. scripts/check-identifiers-package.sh
# (CI job identifiers-lint) checks two runs agree and that rollcall reads the result.
set -euo pipefail

cd "$(dirname "$0")/.."

scripts/lint-identifiers.sh >&2 || {
    echo "package-identifiers: the database does not lint; not packaging" >&2
    exit 1
}
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' crates/rollcall-identifiers/Cargo.toml | head -n 1)
out_dir=${CARGO_TARGET_DIR:-target}/identifiers
out=$out_dir/rollcall-identifiers-$version.tar.gz
mkdir -p "$out_dir"

python3 - "$version" "$out" <<'PY'
import gzip, io, sys, tarfile

version, out = sys.argv[1], sys.argv[2]
with open("crates/rollcall-identifiers/db/identifiers.yaml", "rb") as f:
    data = f.read()
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
    for name, is_dir in ((version, True), (f"{version}/identifiers.yaml", False)):
        info = tarfile.TarInfo(name)
        info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
        if is_dir:
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
        else:
            info.mode, info.size = 0o644, len(data)
            tar.addfile(info, io.BytesIO(data))
with open(out, "wb") as f:
    with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
        gz.write(buf.getvalue())
PY

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$out"
else
    shasum -a 256 "$out"
fi
