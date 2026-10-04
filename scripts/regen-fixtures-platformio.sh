#!/usr/bin/env bash
# Regenerate the PlatformIO build fixture under fixtures/platformio/ from a real `pio run` of
# the hand-written Arduino-ESP32 project in scripts/fixture-src/platformio/ (SHA-131), in the
# pinned python image with PlatformIO Core installed from hash-pinned wheels. See
# docs/platformio.md (Fixtures) and docs/fixtures.md. The fixtures are never edited by hand.
# `scripts/regen-fixtures.sh --variant platformio[-…]` runs this script.
#
# NEEDS DOCKER AND THE NETWORK: pulls the python image by digest, installs PlatformIO Core
# from PyPI (every wheel pinned by SHA-256 in scripts/fixture-src/platformio/requirements.txt),
# and `pio run` downloads the platform, framework, toolchain and the three libraries from the
# PlatformIO registry.
#
# Usage:
#   scripts/regen-fixtures-platformio.sh [--check-stable] [--remove-image]
#
#   --check-stable   build twice, in fresh containers, and require byte-identical trees;
#                    fails without touching the output if not.
#   --remove-image   `docker image rm` the pinned image when done, to free disk.
#
# The one variant, fixtures/platformio/arduino-mqtt/, holds only metadata (no sources,
# toolchains or build output):
#   platformio.ini                                   the project file, as written
#   .pio/libdeps/<env>/<library>/library.json        each installed library's manifest
#   .pio/libdeps/<env>/<library>/.piopm              PlatformIO's install record for it
#   pio-core/platforms/<platform>/platform.json      the development platform's manifest
#   pio-core/platforms/<platform>/.piopm
#   pio-core/packages/<framework package>/package.json   the framework package's manifest
#   pio-core/packages/<framework package>/.piopm
# (`pio-core/` is a copy of those files from the build's PLATFORMIO_CORE_DIR, for
# `rollcall generate --pio-core`), and fixtures/platformio/MANIFEST.json records the pins, the
# build command and the size and SHA-256 of every file.
#
# Every pin below is asserted after the build: the installed PlatformIO Core, platform,
# framework package and library versions must be exactly the pinned ones, and exactly the
# three pinned libraries must be installed.
#
# Paths: the build runs in the container at /project/arduino-mqtt with PLATFORMIO_CORE_DIR
# /pio-core; the copied files hold no absolute path (the run fails if a host path reaches
# them).
#
# The staged result must pass `cargo test -p rollcall-core --test fixtures_platformio` (run
# with ROLLCALL_PLATFORMIO_FIXTURES_DIR pointing at it) before it replaces the output.
#
# Logs go to .cache/platformio-fixtures-logs/; with --check-stable the staged trees stay in
# .cache/platformio-fixtures-staging/.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

# --- Pins -----------------------------------------------------------------------------------
PY_IMAGE=python
PY_TAG=3.12-slim-bookworm
# The linux/amd64 manifest digest of python:3.12-slim-bookworm (Python 3.12.15).
PY_IMAGE_DIGEST=sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4
PY_PLATFORM=linux/amd64
PLATFORMIO_VERSION=6.1.18
ENV_NAME=esp32dev
PLATFORM_NAME=espressif32
PLATFORM_VERSION=6.10.0
FRAMEWORK_PACKAGE=framework-arduinoespressif32
FRAMEWORK_VERSION=3.20017.241212
# The Arduino-ESP32 release that framework package is (rollcall's db/platformio.yaml).
ARDUINO_ESP32_VERSION=2.0.17
# owner/name@version, as in platformio.ini's lib_deps.
LIB_PINS="bblanchon/ArduinoJson@7.2.1 knolleary/PubSubClient@2.8 mathertel/OneButton@2.6.1"
VARIANT=arduino-mqtt
CONTAINER_PROJECT=/project
CONTAINER_CORE=/pio-core

log() { echo "regen-fixtures-platformio: $*" >&2; }
die() {
    echo "regen-fixtures-platformio: error: $*" >&2
    exit 1
}

CHECK_STABLE=0
REMOVE_IMAGE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check-stable) CHECK_STABLE=1 && shift ;;
        --remove-image) REMOVE_IMAGE=1 && shift ;;
        --variant)
            # From scripts/regen-fixtures.sh: platformio, platformio-arduino-mqtt.
            [[ $# -ge 2 ]] || die "--variant needs a value"
            case "$2" in
                platformio | "platformio-$VARIANT" | "$VARIANT") ;;
                *) die "unknown variant '$2' (known: $VARIANT)" ;;
            esac
            shift 2
            ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

for tool in docker python3 cargo diff git; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
IMAGE_REF="$PY_IMAGE@$PY_IMAGE_DIGEST"
SRC="$REPO_ROOT/scripts/fixture-src/platformio"
[[ -f "$SRC/$VARIANT/platformio.ini" ]] || die "$SRC/$VARIANT/platformio.ini is missing"
[[ -f "$SRC/requirements.txt" ]] || die "$SRC/requirements.txt is missing"

CACHE="$REPO_ROOT/.cache"
STAGING="$CACHE/platformio-fixtures-staging"
LOGS="$CACHE/platformio-fixtures-logs"
OUT="$REPO_ROOT/fixtures/platformio"

# --- The image, by digest only --------------------------------------------------------------
if ! docker image inspect "$IMAGE_REF" >/dev/null 2>&1; then
    log "pulling $IMAGE_REF ($PY_IMAGE:$PY_TAG, $PY_PLATFORM)"
    docker pull --platform "$PY_PLATFORM" "$IMAGE_REF" >&2
fi
PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE_REF")"
[[ "$PLATFORM" == "$PY_PLATFORM" ]] || die "$IMAGE_REF is $PLATFORM, not $PY_PLATFORM"

# The script run in the container: install PlatformIO Core from the hash-pinned wheels, build
# the project, and copy the metadata the fixture keeps into /out/<variant>. Every file is then
# given to the host user (on Linux the container writes as root).
CONTAINER_SCRIPT='
set -euo pipefail
variant="$1" env_name="$2" platform="$3" framework_package="$4" pio_version="$5" uid="$6" gid="$7"
pip install --no-cache-dir -q --disable-pip-version-check --require-hashes -r /src/requirements.txt
got="$(pio --version)"
[[ "$got" == "PlatformIO Core, version $pio_version" ]] || { echo "pio is $got, not $pio_version" >&2; exit 1; }
export PLATFORMIO_CORE_DIR=/pio-core
export PLATFORMIO_SETTING_ENABLE_TELEMETRY=no
export PLATFORMIO_SETTING_CHECK_PLATFORMIO_INTERVAL=36500
export PLATFORMIO_SETTING_CHECK_PRUNE_SYSTEM_THRESHOLD=0
mkdir -p /project
cp -R "/src/$variant" "/project/$variant"
# A .pio/ left in the source (an earlier local build) must not seed this one.
rm -rf "/project/$variant/.pio"
cd "/project/$variant"
pio run -e "$env_name"
out="/out/$variant"
mkdir -p "$out"
cp platformio.ini "$out/platformio.ini"
for lib in .pio/libdeps/"$env_name"/*/; do
    lib="${lib%/}"
    mkdir -p "$out/$lib"
    for f in library.json .piopm; do
        [[ ! -f "$lib/$f" ]] || cp "$lib/$f" "$out/$lib/$f"
    done
done
mkdir -p "$out/pio-core/platforms/$platform" "$out/pio-core/packages/$framework_package"
for f in platform.json .piopm; do
    cp "/pio-core/platforms/$platform/$f" "$out/pio-core/platforms/$platform/$f"
done
for f in package.json .piopm; do
    cp "/pio-core/packages/$framework_package/$f" "$out/pio-core/packages/$framework_package/$f"
done
chown -R "$uid:$gid" /out
'

# build <run>: builds the variant in a fresh container and collects it into $STAGING/run<run>.
build() {
    local run="$1" out log
    out="$STAGING/run$run"
    log="$LOGS/run$run-$VARIANT.log"
    mkdir -p "$out"
    docker run --rm --platform "$PY_PLATFORM" -v "$SRC:/src:ro" -v "$out:/out" "$IMAGE_REF" \
        bash -c "$CONTAINER_SCRIPT" container \
        "$VARIANT" "$ENV_NAME" "$PLATFORM_NAME" "$FRAMEWORK_PACKAGE" "$PLATFORMIO_VERSION" \
        "$(id -u)" "$(id -g)" >"$log" 2>&1 ||
        die "run $run: build failed (log: $log)"
    check_pins "$out/$VARIANT" || die "run $run: a pin does not hold (see above)"
    check_no_host_paths "$out" || die "run $run: build-machine paths left in $out"
}

# check_pins <variant dir>: the installed platform, framework package and libraries are
# exactly the pinned ones, and the project file is the source's.
check_pins() {
    python3 - "$1" "$SRC/$VARIANT/platformio.ini" "$ENV_NAME" "$PLATFORM_NAME" \
        "$PLATFORM_VERSION" "$FRAMEWORK_PACKAGE" "$FRAMEWORK_VERSION" "$LIB_PINS" <<'EOF'
import json, os, sys
root, ini, env, platform, platform_version, fw, fw_version, lib_pins = sys.argv[1:9]
bad = []
def load(rel):
    with open(os.path.join(root, rel), encoding="utf-8") as f:
        return json.load(f)
if open(os.path.join(root, "platformio.ini"), "rb").read() != open(ini, "rb").read():
    bad.append("platformio.ini differs from the source")
p = load(f"pio-core/platforms/{platform}/.piopm")
if p.get("version") != platform_version:
    bad.append(f"platform {platform} is {p.get('version')}, not {platform_version}")
if load(f"pio-core/platforms/{platform}/platform.json").get("version") != platform_version:
    bad.append(f"platform.json is not {platform_version}")
f = load(f"pio-core/packages/{fw}/.piopm")
if f.get("version", "").split("+")[0] != fw_version:
    bad.append(f"{fw} is {f.get('version')}, not {fw_version}")
if load(f"pio-core/packages/{fw}/package.json").get("version", "").split("+")[0] != fw_version:
    bad.append(f"{fw} package.json is not {fw_version}")
libdeps = os.path.join(root, ".pio/libdeps", env)
installed = {}
for name in sorted(os.listdir(libdeps)):
    piopm = os.path.join(libdeps, name, ".piopm")
    if not os.path.isfile(piopm):
        bad.append(f"{name}: no .piopm")
        continue
    with open(piopm, encoding="utf-8") as fh:
        spec = json.load(fh)
    if not os.path.isfile(os.path.join(libdeps, name, "library.json")):
        bad.append(f"{name}: no library.json")
    installed[f"{spec['spec']['owner']}/{spec['name']}"] = spec["version"]
expected = {}
for pin in lib_pins.split():
    lib, version = pin.rsplit("@", 1)
    expected[lib] = version
if sorted(installed) != sorted(expected):
    bad.append(f"installed libraries {sorted(installed)}, expected {sorted(expected)}")
for lib, version in expected.items():
    got = installed.get(lib)
    # PlatformIO records a two-part version as semver (2.8 -> 2.8.0).
    if got is not None and got not in (version, version + ".0"):
        bad.append(f"{lib} is {got}, not {version}")
    manifest = os.path.join(libdeps, lib.split("/", 1)[1], "library.json")
    if os.path.isfile(manifest):
        with open(manifest, encoding="utf-8") as fh:
            data = json.load(fh)
        if str(data.get("version")) != version:
            bad.append(f"{lib} library.json is {data.get('version')}, not {version}")
        repo = data.get("repository")
        if not (isinstance(repo, dict) and repo.get("url")):
            bad.append(f"{lib} library.json has no repository url")
if bad:
    print("pins do not hold:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
EOF
}

# check_no_host_paths <dir>: fails if any file holds a host path.
check_no_host_paths() {
    python3 - "$1" "$REPO_ROOT" "${HOME:-/nonexistent-home}" <<'EOF'
import os, sys
root = sys.argv[1]
needles = set(sys.argv[2:]) | {"/Users/", "/home/", "/private/", "/var/folders/", "/tmp/", "C:\\", "/project/", "/pio-core"}
bad = []
for dirpath, _, files in os.walk(root):
    for name in files:
        p = os.path.join(dirpath, name)
        with open(p, "rb") as f:
            data = f.read()
        bad += [f"{os.path.relpath(p, root)}: {n}" for n in sorted(needles) if n and n.encode() in data]
if bad:
    print("absolute paths left:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
EOF
}

# write_manifest <dir>: MANIFEST.json for the tree.
write_manifest() {
    python3 - "$1" "$PY_IMAGE" "$PY_TAG" "$PY_IMAGE_DIGEST" "$PY_PLATFORM" "$PLATFORMIO_VERSION" \
        "$VARIANT" "$ENV_NAME" "$PLATFORM_NAME" "$PLATFORM_VERSION" "$FRAMEWORK_PACKAGE" \
        "$FRAMEWORK_VERSION" "$ARDUINO_ESP32_VERSION" "$LIB_PINS" <<'EOF'
import hashlib, json, os, platform, sys
(root, image, tag, digest, image_platform, pio_version, variant, env, platform_name,
 platform_version, fw, fw_version, upstream, lib_pins) = sys.argv[1:15]
files = []
for dirpath, dirs, names in os.walk(root):
    dirs.sort()
    for name in sorted(names):
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        if rel == "MANIFEST.json":
            continue
        with open(p, "rb") as f:
            data = f.read()
        files.append({"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
files.sort(key=lambda e: e["path"])
libraries = []
for pin in lib_pins.split():
    lib, version = pin.rsplit("@", 1)
    owner, name = lib.split("/", 1)
    libraries.append({"owner": owner, "name": name, "version": version})
manifest = {
    "format": "rollcall-fixtures/1",
    "generator": "scripts/regen-fixtures-platformio.sh",
    "ecosystem": "platformio",
    "platformio": {
        "core_version": pio_version,
        "image": image, "tag": tag, "digest": digest, "image_platform": image_platform,
        "requirements": "scripts/fixture-src/platformio/requirements.txt",
        "container_core_dir": "/pio-core",
    },
    "variants": {
        variant: {
            "source": f"scripts/fixture-src/platformio/{variant}",
            "container_project_dir": f"/project/{variant}",
            "env": env,
            "build_command": [["pio", "run", "-e", env]],
            "platform": {"name": platform_name, "version": platform_version},
            "framework": {"package": fw, "version": fw_version, "upstream": upstream},
            "libraries": libraries,
        }
    },
    "host": {"os": platform.system().lower(), "arch": platform.machine().lower()},
    "files": files,
    "total_bytes": sum(e["bytes"] for e in files),
}
with open(os.path.join(root, "MANIFEST.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
EOF
}

# --- Main -----------------------------------------------------------------------------------
t0=$SECONDS
# Fresh staging and log directories (moved aside, then removed).
for d in "$STAGING" "$LOGS"; do
    if [[ -e "$d" ]]; then
        mv "$d" "$d.old.$$"
        rm -r "$d.old.$$"
    fi
done
mkdir -p "$STAGING" "$LOGS"
runs=(1)
[[ "$CHECK_STABLE" -eq 0 ]] || runs=(1 2)
for run in "${runs[@]}"; do
    log "run $run: building $VARIANT (pio run -e $ENV_NAME) in $IMAGE_REF"
    build "$run"
    write_manifest "$STAGING/run$run"
done
if [[ "$CHECK_STABLE" -eq 1 ]]; then
    log "comparing run 1 with run 2"
    if ! diff -r "$STAGING/run1" "$STAGING/run2" >"$STAGING/compare-stable.txt" 2>&1; then
        cat "$STAGING/compare-stable.txt" >&2
        die "the two runs differ (see $STAGING/compare-stable.txt); output left unchanged"
    fi
    log "compare: PASS (byte-identical)"
fi

log "running cargo test -p rollcall-core --test fixtures_platformio on the staged tree"
if ! ROLLCALL_PLATFORMIO_FIXTURES_DIR="$STAGING/run1" cargo test -q -p rollcall-core \
    --test fixtures_platformio --locked >&2; then
    die "the staged tree fails the fixture tests; fixtures/platformio left unchanged (staged: $STAGING/run1)"
fi

if [[ -e "$OUT" ]]; then
    mv "$OUT" "$OUT.old"
fi
if ! cp -R "$STAGING/run1" "$OUT"; then
    [[ ! -e "$OUT" ]] || rm -r "$OUT"
    [[ ! -e "$OUT.old" ]] || mv "$OUT.old" "$OUT"
    die "could not install fixtures/platformio; the previous tree is restored"
fi
[[ ! -e "$OUT.old" ]] || rm -r "$OUT.old"
[[ "$CHECK_STABLE" -eq 1 ]] || rm -r "$STAGING"

# Hidden files (.pio/, .piopm) must reach git: no ignore rule may drop any of them.
ignored="$(cd "$OUT" && find . -type f | sed 's|^\./|fixtures/platformio/|' | git -C "$REPO_ROOT" check-ignore --no-index --stdin || true)"
[[ -z "$ignored" ]] || die "git ignores fixture files (check your global excludes):
$ignored"

if [[ "$REMOVE_IMAGE" -eq 1 ]]; then
    docker image rm "$IMAGE_REF" >&2 || log "could not remove $IMAGE_REF"
fi
log "fixtures/platformio written ($(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total_bytes"])' "$OUT/MANIFEST.json") bytes) in $((SECONDS - t0))s"
git status --short -- fixtures/platformio
