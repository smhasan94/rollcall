//! Checks on the PlatformIO build fixture, `fixtures/platformio/` (see `docs/platformio.md`,
//! *Fixtures*): `arduino-mqtt`, a real `pio run` of the hand-written Arduino-ESP32 project in
//! `scripts/fixture-src/platformio/arduino-mqtt/` (three registry `lib_deps`), built in the
//! pinned python image with PlatformIO Core installed from hash-pinned wheels.
//!
//! The fixture is produced only by `scripts/regen-fixtures-platformio.sh`; these tests check
//! that the committed tree is what its `MANIFEST.json` says, that it records the script's pins
//! and the project file's, that the script runs the image by digest and installs PlatformIO by
//! hash, that exactly the three pinned libraries are installed, and that no build-machine
//! path is in it.
//!
//! `ROLLCALL_PLATFORMIO_FIXTURES_DIR` points the tests at another tree; the script uses it to
//! test a staged tree before installing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const VARIANT: &str = "arduino-mqtt";
const ENV: &str = "esp32dev";
const PLATFORM: &str = "espressif32";
const FRAMEWORK_PACKAGE: &str = "framework-arduinoespressif32";
/// (owner, name, version) of the three `lib_deps`.
const LIBRARIES: [(&str, &str, &str); 3] = [
    ("bblanchon", "ArduinoJson", "7.2.1"),
    ("knolleary", "PubSubClient", "2.8"),
    ("mathertel", "OneButton", "2.6.1"),
];

/// The fixture tree is kept under this size.
const MAX_TREE_BYTES: u64 = 200_000;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn root() -> PathBuf {
    match std::env::var_os("ROLLCALL_PLATFORMIO_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => repo_root().join("fixtures/platformio"),
    }
}

fn manifest() -> Value {
    let path = root().join("MANIFEST.json");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read(rel: &str) -> Vec<u8> {
    let path = root().join(rel);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn json(rel: &str) -> Value {
    serde_json::from_slice(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every file under the tree (hidden ones included), relative, sorted.
fn files_on_disk() -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy();
                out.push(rel.replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root(), &root(), &mut out);
    out.sort();
    out
}

fn script() -> String {
    fs::read_to_string(repo_root().join("scripts/regen-fixtures-platformio.sh")).unwrap()
}

/// A `NAME=value` assignment in `scripts/regen-fixtures-platformio.sh`.
fn script_pin(name: &str) -> String {
    script()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name}= in regen-fixtures-platformio.sh"))
        .trim()
        .trim_matches('"')
        .to_owned()
}

/// The source project file the script builds.
fn source_ini() -> String {
    fs::read_to_string(repo_root().join(format!(
        "scripts/fixture-src/platformio/{VARIANT}/platformio.ini"
    )))
    .unwrap()
}

#[test]
fn manifest_pins_match_the_script_and_ini() {
    let m = manifest();
    assert_eq!(m["format"], "rollcall-fixtures/1");
    assert_eq!(m["generator"], "scripts/regen-fixtures-platformio.sh");
    assert_eq!(m["ecosystem"], "platformio");
    let pio = &m["platformio"];
    for (key, pin) in [
        ("core_version", "PLATFORMIO_VERSION"),
        ("image", "PY_IMAGE"),
        ("tag", "PY_TAG"),
        ("digest", "PY_IMAGE_DIGEST"),
        ("image_platform", "PY_PLATFORM"),
    ] {
        assert_eq!(pio[key].as_str(), Some(script_pin(pin).as_str()), "{key}");
    }
    assert_eq!(pio["core_version"], "6.1.18");
    assert_eq!(pio["image_platform"], "linux/amd64");
    let digest = pio["digest"].as_str().unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();
    assert!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "{digest}"
    );

    let variants = m["variants"].as_object().unwrap();
    assert_eq!(variants.keys().collect::<Vec<_>>(), [VARIANT]);
    let v = &variants[VARIANT];
    assert_eq!(v["env"], script_pin("ENV_NAME"));
    assert_eq!(v["env"], ENV);
    assert_eq!(v["platform"]["name"], script_pin("PLATFORM_NAME"));
    assert_eq!(v["platform"]["version"], script_pin("PLATFORM_VERSION"));
    assert_eq!(v["platform"]["version"], "6.10.0");
    assert_eq!(v["framework"]["package"], script_pin("FRAMEWORK_PACKAGE"));
    assert_eq!(v["framework"]["version"], script_pin("FRAMEWORK_VERSION"));
    assert_eq!(v["framework"]["version"], "3.20017.241212");
    assert_eq!(
        v["framework"]["upstream"],
        script_pin("ARDUINO_ESP32_VERSION")
    );
    assert_eq!(v["framework"]["upstream"], "2.0.17");
    let libs: Vec<(String, String, String)> = v["libraries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["owner"].as_str().unwrap().to_owned(),
                l["name"].as_str().unwrap().to_owned(),
                l["version"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected: Vec<(String, String, String)> = LIBRARIES
        .iter()
        .map(|(o, n, v)| ((*o).to_owned(), (*n).to_owned(), (*v).to_owned()))
        .collect();
    assert_eq!(libs, expected);
    let pins: Vec<String> = LIBRARIES
        .iter()
        .map(|(o, n, v)| format!("{o}/{n}@{v}"))
        .collect();
    assert_eq!(script_pin("LIB_PINS"), pins.join(" "));

    // The project file pins the same versions, exactly, and the fixture holds it unchanged.
    let ini = source_ini();
    for needle in [
        format!("platform = {PLATFORM} @ 6.10.0"),
        format!("platformio/{FRAMEWORK_PACKAGE} @ 3.20017.241212"),
        format!("[env:{ENV}]"),
        format!("default_envs = {ENV}"),
    ] {
        assert!(ini.contains(&needle), "platformio.ini lacks {needle:?}");
    }
    for (owner, name, version) in LIBRARIES {
        let needle = format!("{owner}/{name} @ {version}");
        assert!(ini.contains(&needle), "platformio.ini lacks {needle:?}");
    }
    assert_eq!(
        read(&format!("{VARIANT}/platformio.ini")),
        ini.as_bytes(),
        "the fixture's platformio.ini is not the source's"
    );
}

#[test]
fn script_runs_the_image_by_digest_only_and_installs_platformio_by_hash() {
    let script = script();
    assert!(script.contains("IMAGE_REF=\"$PY_IMAGE@$PY_IMAGE_DIGEST\""));
    assert!(script.contains("--require-hashes -r /src/requirements.txt"));
    for line in script.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("docker run") || line.starts_with("docker pull") {
            assert!(line.contains("\"$IMAGE_REF\""), "not by digest: {line}");
            assert!(line.contains("--platform \"$PY_PLATFORM\""), "{line}");
        }
        assert!(
            !line.contains("python:3") && !line.contains(":latest"),
            "image by tag: {line}"
        );
    }
    // Every requirement is pinned exactly and carries a hash; PlatformIO Core is the pin.
    let requirements =
        fs::read_to_string(repo_root().join("scripts/fixture-src/platformio/requirements.txt"))
            .unwrap();
    let mut pinned = 0;
    let mut lines = requirements
        .lines()
        .filter(|l| !l.starts_with('#'))
        .peekable();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        let (name, version) = line
            .trim_end_matches(" \\")
            .split_once("==")
            .unwrap_or_else(|| panic!("not pinned: {line}"));
        let hash = lines.next().unwrap_or_default().trim();
        assert!(
            hash.strip_prefix("--hash=sha256:")
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
            "{name}: no sha256 hash"
        );
        if name == "platformio" {
            assert_eq!(version, script_pin("PLATFORMIO_VERSION"));
        }
        pinned += 1;
    }
    assert!(pinned >= 10, "only {pinned} requirements");
    assert!(requirements.contains("platformio==6.1.18"));
}

#[test]
fn tree_holds_exactly_the_expected_files() {
    let mut expected: BTreeSet<String> = BTreeSet::from([
        "MANIFEST.json".to_owned(),
        format!("{VARIANT}/platformio.ini"),
        format!("{VARIANT}/pio-core/platforms/{PLATFORM}/platform.json"),
        format!("{VARIANT}/pio-core/platforms/{PLATFORM}/.piopm"),
        format!("{VARIANT}/pio-core/packages/{FRAMEWORK_PACKAGE}/package.json"),
        format!("{VARIANT}/pio-core/packages/{FRAMEWORK_PACKAGE}/.piopm"),
    ]);
    for (_, name, _) in LIBRARIES {
        for file in ["library.json", ".piopm"] {
            expected.insert(format!("{VARIANT}/.pio/libdeps/{ENV}/{name}/{file}"));
        }
    }
    let on_disk: BTreeSet<String> = files_on_disk().into_iter().collect();
    assert_eq!(on_disk, expected);
}

#[test]
fn manifest_lists_every_file_with_its_size_and_sha256() {
    let m = manifest();
    let files = m["files"].as_array().unwrap();
    let listed: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    let expected: Vec<String> = files_on_disk()
        .into_iter()
        .filter(|f| f != "MANIFEST.json")
        .collect();
    assert_eq!(listed, expected);
    let mut total = 0;
    for f in files {
        let rel = f["path"].as_str().unwrap();
        let bytes = read(rel);
        assert_eq!(f["sha256"].as_str(), Some(sha256(&bytes).as_str()), "{rel}");
        assert_eq!(f["bytes"].as_u64(), Some(bytes.len() as u64), "{rel}");
        total += bytes.len() as u64;
    }
    assert_eq!(m["total_bytes"].as_u64(), Some(total));
    assert!(total <= MAX_TREE_BYTES, "the tree is {total} bytes");
}

#[test]
fn no_build_machine_path_is_left_in_any_file() {
    let needles = [
        "/Users/",
        "/home/",
        "/private/",
        "/var/folders/",
        "/tmp/",
        "C:\\",
        "/project/",
        "/pio-core",
    ];
    for rel in files_on_disk() {
        if rel == "MANIFEST.json" {
            continue;
        }
        let bytes = read(&rel);
        for needle in needles {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{rel} contains {needle:?}"
            );
        }
    }
}

#[test]
fn installed_packages_are_exactly_the_pinned_ones() {
    let base = format!("{VARIANT}/.pio/libdeps/{ENV}");
    for (owner, name, version) in LIBRARIES {
        let piopm = json(&format!("{base}/{name}/.piopm"));
        assert_eq!(piopm["type"], "library", "{name}");
        assert_eq!(piopm["name"], name);
        assert_eq!(piopm["spec"]["owner"], owner, "{name}");
        // PlatformIO records a two-part version as semver (2.8 -> 2.8.0).
        let installed = piopm["version"].as_str().unwrap();
        assert!(
            installed == version || installed == format!("{version}.0"),
            "{name}: {installed}"
        );
        let manifest = json(&format!("{base}/{name}/library.json"));
        assert_eq!(manifest["name"], name);
        assert_eq!(manifest["version"], version, "{name}");
        assert!(
            manifest["repository"]["url"]
                .as_str()
                .is_some_and(|u| u.starts_with("https://github.com/")),
            "{name}: no repository url"
        );
    }
    let platform = format!("{VARIANT}/pio-core/platforms/{PLATFORM}");
    assert_eq!(json(&format!("{platform}/.piopm"))["version"], "6.10.0");
    assert_eq!(
        json(&format!("{platform}/platform.json"))["version"],
        "6.10.0"
    );
    assert_eq!(
        json(&format!("{platform}/platform.json"))["frameworks"]["arduino"]["package"],
        FRAMEWORK_PACKAGE
    );
    let framework = format!("{VARIANT}/pio-core/packages/{FRAMEWORK_PACKAGE}");
    for file in [".piopm", "package.json"] {
        let version = json(&format!("{framework}/{file}"))["version"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(version.starts_with("3.20017.241212"), "{file}: {version}");
    }
}

/// The CI job that builds the canonical fixture runs this script and uploads the tree with its
/// hidden files (`.pio/`, `.piopm`), which `actions/upload-artifact` drops by default.
#[test]
fn regen_workflow_builds_with_the_script_and_uploads_hidden_files() {
    let text =
        fs::read_to_string(repo_root().join(".github/workflows/regen-fixtures.yml")).unwrap();
    let workflow: Value = yaml_serde::from_str(&text).unwrap();
    let job = &workflow["jobs"]["regen-platformio"];
    let steps = job["steps"].as_array().expect("a regen-platformio job");
    assert!(
        steps.iter().any(|s| s["run"]
            .as_str()
            .is_some_and(|r| r.contains("scripts/regen-fixtures-platformio.sh"))),
        "the job does not run the script"
    );
    let upload = steps
        .iter()
        .find(|s| s["with"]["name"] == "platformio-fixtures")
        .expect("an upload of platformio-fixtures");
    assert_eq!(upload["with"]["path"], "fixtures/platformio");
    assert_eq!(upload["with"]["include-hidden-files"], true);
    let paths = workflow["on"]["pull_request"]["paths"].as_array().unwrap();
    assert!(
        paths
            .iter()
            .any(|p| p == "scripts/regen-fixtures-platformio.sh")
    );
}
