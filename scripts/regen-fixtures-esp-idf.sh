#!/usr/bin/env bash
# Regenerate the ESP-IDF build fixtures under fixtures/esp-idf/ from real builds of two
# vanilla ESP-IDF examples in the pinned espressif/idf Docker image (SHA-129). See
# docs/esp-idf.md (Fixtures) and docs/fixtures.md. The fixtures are never edited by hand.
# `scripts/regen-fixtures.sh --variant esp-idf[-…]` runs this script.
#
# NEEDS DOCKER AND THE NETWORK on first run: pulls espressif/idf by digest (about 4 GB
# compressed, 12 GB unpacked). The builds themselves need no network (neither example
# depends on a registry component).
#
# Usage:
#   scripts/regen-fixtures-esp-idf.sh [--variant V]... [--check-stable] [--remove-image]
#
#   --variant V      build only V; repeatable (an `esp-idf-` prefix is accepted). Default: all of
#                      hello-world  examples/get-started/hello_world
#                      wifi-tls     examples/protocols/https_request (Wi-Fi + HTTPS over
#                                   mbedTLS and lwIP)
#                    Unselected variants already in fixtures/esp-idf/ are carried over unchanged.
#   --check-stable   build everything twice, in fresh containers and work directories, and
#                    require byte-identical trees; fails without touching the output if not.
#   --remove-image   `docker image rm` the pinned image when done, to free disk.
#
# Each variant tree, fixtures/esp-idf/<variant>/, holds:
#   sdkconfig                     the project's sdkconfig
#   dependencies.lock             the component manager's lock (when it writes one)
#   main/idf_component.yml        the project's component manifest (when the example has one)
#   managed_components/*/idf_component.yml   each downloaded component's manifest (if any)
#   build/project_description.json
#   build/<project>.map           the GNU ld map, without its `Cross Reference Table`
#                                 (transform `strip-cref`: everything from that header on)
#   idf/components/esp_common/include/esp_idf_version.h   the ESP-IDF version file
#   idf/<path>                    every Espressif prebuilt library (blob) the map lists as an
#                                 archive member, at its path in the ESP-IDF tree
# and fixtures/esp-idf/MANIFEST.json records the pins, the build commands and the size and
# SHA-256 of every file.
#
# Paths: the builds run in the container at /project/<variant> with ESP-IDF at /opt/esp/idf;
# those container paths are the only absolute paths in the fixtures (no host path is
# rewritten, because none reaches them; the run fails if one does).
#
# The staged result must pass `cargo test -p rollcall-core --test fixtures_esp_idf` (run with
# ROLLCALL_ESP_IDF_FIXTURES_DIR pointing at it) before it replaces the output.
#
# Logs go to .cache/esp-idf-fixtures-logs/; with --check-stable the staged trees stay in
# .cache/esp-idf-fixtures-staging/. The work directories (the full builds, about 170 MB per
# run) are deleted.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd -P)"

# --- Pins -----------------------------------------------------------------------------------
IDF_IMAGE=espressif/idf
IDF_TAG=v5.5.1
# The multi-arch index digest of espressif/idf:v5.5.1 (linux/amd64 and linux/arm64).
IDF_IMAGE_DIGEST=sha256:dfa2d076c796769c07c155eba6c672b9f395aec943b2ba3701b73379b5f9e884
TARGET=esp32
ALL_VARIANTS=(hello-world wifi-tls)
CONTAINER_IDF=/opt/esp/idf
CONTAINER_WORK=/project

# variant_sample <v>: the example, relative to the ESP-IDF tree.
variant_sample() {
    case "$1" in
        hello-world) echo examples/get-started/hello_world ;;
        wifi-tls) echo examples/protocols/https_request ;;
        *) return 1 ;;
    esac
}

# variant_project <v>: the CMake project name (the map is build/<project>.map).
variant_project() {
    case "$1" in
        hello-world) echo hello_world ;;
        wifi-tls) echo https_request ;;
        *) return 1 ;;
    esac
}

log() { echo "regen-fixtures-esp-idf: $*" >&2; }
die() {
    echo "regen-fixtures-esp-idf: error: $*" >&2
    exit 1
}

SELECTED=()
CHECK_STABLE=0
REMOVE_IMAGE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant)
            [[ $# -ge 2 ]] || die "--variant needs a value"
            v="${2#esp-idf-}"
            if [[ "$v" == esp-idf ]]; then
                SELECTED+=("${ALL_VARIANTS[@]}")
            else
                variant_sample "$v" >/dev/null || die "unknown variant '$2' (known: ${ALL_VARIANTS[*]})"
                SELECTED+=("$v")
            fi
            shift 2
            ;;
        --check-stable) CHECK_STABLE=1 && shift ;;
        --remove-image) REMOVE_IMAGE=1 && shift ;;
        -h | --help)
            sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ ${#SELECTED[@]} -gt 0 ]] || SELECTED=("${ALL_VARIANTS[@]}")

for tool in docker python3 cargo diff; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
IMAGE_REF="$IDF_IMAGE@$IDF_IMAGE_DIGEST"

CACHE="$REPO_ROOT/.cache"
STAGING="$CACHE/esp-idf-fixtures-staging"
LOGS="$CACHE/esp-idf-fixtures-logs"
WORK_ROOT="$CACHE/esp-idf-fixtures-work"
OUT="$REPO_ROOT/fixtures/esp-idf"
IMAGE_PRESENT=0

# remove_work: deletes the work directories. A build that fails before its final `chown`
# leaves root-owned files on Linux, which the host user cannot delete; those are removed as
# root in the container (when the image is there), and a leftover is reported, not fatal.
remove_work() {
    [[ -e "$WORK_ROOT" ]] || return 0
    rm -rf "$WORK_ROOT" 2>/dev/null && return 0
    if [[ "$IMAGE_PRESENT" -eq 1 ]]; then
        docker run --rm -v "$WORK_ROOT:/work" --entrypoint sh "$IMAGE_REF" -c 'rm -rf /work/* /work/.[!.]*' >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_ROOT" 2>/dev/null || echo "regen-fixtures-esp-idf: warning: could not remove $WORK_ROOT" >&2
}
trap remove_work EXIT

# --- The image, by digest only --------------------------------------------------------------
if ! docker image inspect "$IMAGE_REF" >/dev/null 2>&1; then
    log "pulling $IMAGE_REF ($IDF_IMAGE:$IDF_TAG)"
    docker pull "$IMAGE_REF" >&2
fi
IDF_DESCRIBE="$(docker run --rm --entrypoint git "$IMAGE_REF" -C "$CONTAINER_IDF" describe --tags --exact-match 2>/dev/null)" ||
    die "$IMAGE_REF: $CONTAINER_IDF is not at a tag"
[[ "$IDF_DESCRIBE" == "$IDF_TAG" ]] || die "$IMAGE_REF holds ESP-IDF $IDF_DESCRIBE, not $IDF_TAG"
IMAGE_PRESENT=1
PLATFORM="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE_REF")"

# The script run in the container for one variant: copy the example, build it for $TARGET,
# collect the ESP-IDF files the fixture needs into /project/<v>.idf, and give every file to
# the host user (on Linux the container writes as root).
CONTAINER_SCRIPT='
set -euo pipefail
v="$1" sample="$2" project="$3" target="$4" uid="$5" gid="$6"
cd /project
cp -R "$IDF_PATH/$sample" "/project/$v"
cd "/project/$v"
idf.py set-target "$target"
idf.py build
python3 - "$IDF_PATH" "build/$project.map" "/project/$v.idf" <<"EOF"
import os, re, shutil, sys
idf, map_path, out = sys.argv[1:4]
dirs = ("components/bt/controller/", "components/esp_coex/lib/", "components/esp_phy/lib/", "components/esp_wifi/lib/")
blobs = set()
with open(map_path, encoding="utf-8") as f:
    for line in f:
        if line.startswith(("Discarded input sections", "Memory Configuration")):
            break
        m = re.match(r"(/\S+\.a)\(", line)
        if m and m.group(1).startswith(idf + "/"):
            rel = m.group(1)[len(idf) + 1:]
            if rel.startswith(dirs):
                blobs.add(rel)
for rel in sorted(blobs) + ["components/esp_common/include/esp_idf_version.h"]:
    dst = os.path.join(out, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(os.path.join(idf, rel), dst)
EOF
chown -R "$uid:$gid" /project
'

# build_variant <v> <run>: builds the variant and collects its tree into $STAGING/run<run>/<v>.
build_variant() {
    local v="$1" run="$2" sample project work out log
    sample="$(variant_sample "$v")"
    project="$(variant_project "$v")"
    work="$WORK_ROOT/run$run/$v"
    out="$STAGING/run$run/$v"
    log="$LOGS/run$run-$v.log"
    rm -rf "$work" "$out"
    mkdir -p "$work" "$out"
    docker run --rm -v "$work:$CONTAINER_WORK" -e IDF_COMPONENT_CHECK_NEW_VERSION=0 "$IMAGE_REF" \
        bash -c "$CONTAINER_SCRIPT" container \
        "$v" "$sample" "$project" "$TARGET" "$(id -u)" "$(id -g)" >"$log" 2>&1 ||
        die "$v: build failed (log: $log)"
    python3 - "$work/$v" "$work/$v.idf" "$out" "$project" <<'EOF'
import os, shutil, sys
src, idf, out, project = sys.argv[1:5]
def copy(rel, dst_rel=None):
    s = os.path.join(src, rel)
    if os.path.isfile(s):
        d = os.path.join(out, dst_rel or rel)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(s, d)
for rel in ("sdkconfig", "dependencies.lock", "main/idf_component.yml", "build/project_description.json"):
    copy(rel)
managed = os.path.join(src, "managed_components")
if os.path.isdir(managed):
    for name in sorted(os.listdir(managed)):
        copy(f"managed_components/{name}/idf_component.yml")
# The map, cut at the Cross Reference Table (rollcall does not read it; it is most of the size).
with open(os.path.join(src, f"build/{project}.map"), "rb") as f:
    data = f.read()
cut = data.find(b"\nCross Reference Table\n")
if cut >= 0:
    data = data[: cut + 1]
os.makedirs(os.path.join(out, "build"), exist_ok=True)
with open(os.path.join(out, f"build/{project}.map"), "wb") as f:
    f.write(data)
for dirpath, _, files in os.walk(idf):
    for name in files:
        p = os.path.join(dirpath, name)
        d = os.path.join(out, "idf", os.path.relpath(p, idf))
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(p, d)
EOF
    check_no_host_paths "$out" || die "$v: build-machine paths left in $out"
    rm -rf "$work"
}

# check_no_host_paths <dir>: fails if any text file holds a host path.
check_no_host_paths() {
    python3 - "$1" "$REPO_ROOT" "${HOME:-/nonexistent-home}" "$WORK_ROOT" <<'EOF'
import os, sys
root = sys.argv[1]
needles = set(sys.argv[2:]) | {"/Users/", "/home/", "/private/", "/var/folders/", "/tmp/", "C:\\"}
bad = []
for dirpath, _, files in os.walk(root):
    for name in files:
        if name.endswith(".a"):
            continue
        p = os.path.join(dirpath, name)
        with open(p, "rb") as f:
            data = f.read()
        bad += [f"{os.path.relpath(p, root)}: {n}" for n in sorted(needles) if n and n.encode() in data]
if bad:
    print("host paths left:\n  " + "\n  ".join(bad), file=sys.stderr)
    sys.exit(1)
EOF
}

# write_manifest <dir>: MANIFEST.json for the whole tree (every variant directory in it).
write_manifest() {
    python3 - "$1" "$IDF_IMAGE" "$IDF_TAG" "$IDF_IMAGE_DIGEST" "$TARGET" "$PLATFORM" \
        "$(variant_sample hello-world)" "$(variant_sample wifi-tls)" <<'EOF'
import hashlib, json, os, platform, sys
root, image, tag, digest, target, image_platform, hello, wifi = sys.argv[1:9]
samples = {"hello-world": (hello, "hello_world"), "wifi-tls": (wifi, "https_request")}
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
        entry = {"path": rel, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if rel.endswith(".map"):
            entry["transform"] = "strip-cref"
        files.append(entry)
files.sort(key=lambda e: e["path"])
variants = {}
for v in sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))):
    sample, project = samples[v]
    lock = os.path.join(root, v, "dependencies.lock")
    variants[v] = {
        "sample": sample,
        "project": project,
        "container_project_dir": f"/project/{v}",
        "build_command": [["idf.py", "set-target", target], ["idf.py", "build"]],
        "lock": "dependencies.lock" if os.path.isfile(lock) else None,
        "blobs": sorted(e["path"][len(v) + len("/idf/"):] for e in files
                        if e["path"].startswith(f"{v}/idf/") and e["path"].endswith(".a")),
    }
manifest = {
    "format": "rollcall-fixtures/1",
    "generator": "scripts/regen-fixtures-esp-idf.sh",
    "ecosystem": "esp-idf",
    "esp_idf": {"image": image, "tag": tag, "digest": digest, "target": target,
                "image_platform": image_platform, "container_idf_path": "/opt/esp/idf"},
    "build_env": {"IDF_COMPONENT_CHECK_NEW_VERSION": "0"},
    "variants": variants,
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
remove_work
rm -rf "$STAGING" "$LOGS"
mkdir -p "$STAGING" "$LOGS" "$WORK_ROOT"
runs=(1)
[[ "$CHECK_STABLE" -eq 0 ]] || runs=(1 2)
for run in "${runs[@]}"; do
    mkdir -p "$STAGING/run$run"
    # Carry over the variants not being rebuilt.
    if [[ -d "$OUT" ]]; then
        for d in "$OUT"/*/; do
            [[ -d "$d" ]] || continue
            name="$(basename "$d")"
            [[ " ${SELECTED[*]} " == *" $name "* ]] || cp -R "$d" "$STAGING/run$run/$name"
        done
    fi
    for v in "${SELECTED[@]}"; do
        log "run $run: building $v ($(variant_sample "$v")) in $IMAGE_REF"
        build_variant "$v" "$run"
    done
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

log "running cargo test -p rollcall-core --test fixtures_esp_idf on the staged tree"
if ! ROLLCALL_ESP_IDF_FIXTURES_DIR="$STAGING/run1" cargo test -q -p rollcall-core \
    --test fixtures_esp_idf --locked >&2; then
    die "the staged tree fails the fixture tests; fixtures/esp-idf left unchanged (staged: $STAGING/run1)"
fi

rm -rf "$OUT.old"
[[ ! -e "$OUT" ]] || mv "$OUT" "$OUT.old"
if ! cp -R "$STAGING/run1" "$OUT"; then
    rm -rf "$OUT"
    [[ ! -e "$OUT.old" ]] || mv "$OUT.old" "$OUT"
    die "could not install fixtures/esp-idf; the previous tree is restored"
fi
rm -rf "$OUT.old"
[[ "$CHECK_STABLE" -eq 1 ]] || rm -rf "$STAGING"
if [[ "$REMOVE_IMAGE" -eq 1 ]]; then
    docker image rm "$IMAGE_REF" >&2 || log "could not remove $IMAGE_REF"
fi
log "fixtures/esp-idf written ($(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["total_bytes"])' "$OUT/MANIFEST.json") bytes) in $((SECONDS - t0))s"
git status --short -- fixtures/esp-idf
