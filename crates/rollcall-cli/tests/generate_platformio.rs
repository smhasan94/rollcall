//! End-to-end tests for `rollcall generate --platformio` on the real PlatformIO build fixture
//! in `fixtures/platformio/` (SHA-131).
//!
//! The expected documents are `crates/rollcall-core/tests/golden/platformio/*.cdx.json`,
//! generated only by `scripts/regen-golden.sh`. `fixtures/` is never modified: error cases
//! copy files into a temporary directory first. `PLATFORMIO_CORE_DIR` is removed from every
//! command's environment so the developer's own PlatformIO install never reaches the output.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rollcall"));
    c.env_remove("PLATFORMIO_CORE_DIR");
    c
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/platformio/arduino-mqtt")
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden/platformio")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn generate(args: &[&std::ffi::OsStr]) -> Output {
    rollcall()
        .arg("generate")
        .args(args)
        .arg("--timestamp")
        .arg(GOLDEN_TIMESTAMP)
        .output()
        .unwrap()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn assert_exit(out: &Output, code: i32, needles: &[&str]) -> String {
    let stderr = stderr_of(out);
    assert_eq!(out.status.code(), Some(code), "stderr: {stderr}");
    assert!(out.stdout.is_empty(), "stdout not empty");
    assert!(!stderr.contains("panicked"), "{stderr}");
    for needle in needles {
        assert!(stderr.contains(needle), "{stderr:?} lacks {needle:?}");
    }
    stderr
}

fn validate_schema(text: &str) {
    let dir = tempfile::tempdir().unwrap();
    let sbom = dir.path().join("sbom.cdx.json");
    fs::write(&sbom, text).unwrap();
    let out = rollcall()
        .arg("validate")
        .arg("--schema")
        .arg(&sbom)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout_of(&out),
        stderr_of(&out)
    );
}

fn os(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let to = dst.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_tree(&path, &to);
        } else {
            fs::copy(&path, &to).unwrap();
        }
    }
}

/// AC1 end to end: the CLI's output is the golden, byte for byte, and `rollcall validate
/// --schema` accepts it; with and without the core directory, every library is listed.
#[test]
fn generate_platformio_fixture_matches_golden_and_validates() {
    let core = fixture().join("pio-core");
    let out = generate(&[
        os("--platformio"),
        fixture().as_os_str(),
        os("--pio-core"),
        core.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    // Only the two libraries that publish no licence are warned about.
    assert_eq!(
        stderr_of(&out),
        "rollcall generate: warning: .pio/libdeps/esp32dev/ArduinoJson/library.json: bblanchon/ArduinoJson: no license in library.json; the component has no licence\n\
         rollcall generate: warning: .pio/libdeps/esp32dev/PubSubClient/library.json: knolleary/PubSubClient: no license in library.json; the component has no licence\n"
    );
    let text = stdout_of(&out);
    assert!(
        text == golden("arduino-mqtt.cdx.json"),
        "differs from the golden"
    );
    validate_schema(&text);
    let doc: Value = serde_json::from_str(&text).unwrap();
    let names: Vec<&str> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "arduino-esp32",
            "bblanchon/ArduinoJson",
            "knolleary/PubSubClient",
            "mathertel/OneButton",
            "espressif32"
        ]
    );

    let out = generate(&[os("--platformio"), fixture().as_os_str()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stdout_of(&out) == golden("arduino-mqtt.no-core.cdx.json"));
    validate_schema(&stdout_of(&out));
}

/// `$PLATFORMIO_CORE_DIR` stands in for `--pio-core`, and is named on stderr.
#[test]
fn generate_platformio_reads_the_core_directory_from_the_environment_with_a_note() {
    let core = fixture().join("pio-core");
    let out = rollcall()
        .env("PLATFORMIO_CORE_DIR", &core)
        .arg("generate")
        .arg("--platformio")
        .arg(fixture())
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stdout_of(&out) == golden("arduino-mqtt.cdx.json"));
    assert!(
        stderr_of(&out).contains("note: no --pio-core; reading the platform and framework packages from $PLATFORMIO_CORE_DIR"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn generate_platformio_errors_exit_64_65_66_and_never_panic() {
    // A wrong --env is a usage error listing the environments.
    let out = generate(&[
        os("--platformio"),
        fixture().as_os_str(),
        os("--env"),
        os("nope"),
    ]);
    assert_exit(
        &out,
        64,
        &["no environment \"nope\" (environments: esp32dev)"],
    );
    // Missing directory or project file: 66.
    let dir = tempfile::tempdir().unwrap();
    let out = generate(&[os("--platformio"), dir.path().as_os_str()]);
    assert_exit(&out, 66, &["platformio.ini"]);
    // Malformed inputs: 65, naming the file.
    for (file, contents, needle) in [
        (
            "platformio.ini",
            "[env:esp32dev\n",
            "platformio.ini: line 1: malformed section header",
        ),
        (
            ".pio/libdeps/esp32dev/OneButton/library.json",
            "{\"license\": 7}",
            "library.json: license: expected a string",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("arduino-mqtt");
        copy_tree(&fixture(), &project);
        fs::write(project.join(file), contents).unwrap();
        let out = generate(&[os("--platformio"), project.as_os_str()]);
        assert_exit(&out, 65, &[needle]);
    }
    // Two environments, no default: 64, listing them.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("platformio.ini"), "[env:a]\n[env:b]\n").unwrap();
    let out = generate(&[os("--platformio"), dir.path().as_os_str()]);
    assert_exit(&out, 64, &["choose one with --env: a, b"]);
    // Another ecosystem's flag, or a PlatformIO flag without PlatformIO input: 64.
    for extra in [
        vec!["--west-list", "x"],
        vec!["--idf-path", "x"],
        vec!["--target", "x"],
        vec!["--verbose"],
    ] {
        let mut args = vec![
            std::ffi::OsString::from("--platformio"),
            fixture().into_os_string(),
        ];
        args.extend(extra.iter().map(std::ffi::OsString::from));
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let out = generate(&refs);
        assert_eq!(
            out.status.code(),
            Some(64),
            "{extra:?}: {}",
            stderr_of(&out)
        );
    }
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    for extra in [["--env", "a"], ["--pio-core", "x"]] {
        let out = generate(&[os("--model"), model.as_os_str(), os(extra[0]), os(extra[1])]);
        assert_exit(&out, 64, &["cannot be used with"]);
    }
}

/// `--product` (now for every ingester) gives exactly `generate` then `merge --product`.
#[test]
fn generate_platformio_product_equals_generate_plus_merge_product() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.cdx.json");
    let out = generate(&[
        os("--platformio"),
        fixture().as_os_str(),
        os("-o"),
        plain.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let merged = rollcall()
        .arg("merge")
        .arg(&plain)
        .args([
            "--product",
            "button-box@1.2.0",
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ])
        .output()
        .unwrap();
    assert_eq!(merged.status.code(), Some(0), "{}", stderr_of(&merged));
    let direct = generate(&[
        os("--platformio"),
        fixture().as_os_str(),
        os("--product"),
        os("button-box@1.2.0"),
    ]);
    assert_eq!(direct.status.code(), Some(0), "{}", stderr_of(&direct));
    assert!(stdout_of(&direct) == stdout_of(&merged));
    let doc: Value = serde_json::from_str(&stdout_of(&direct)).unwrap();
    assert_eq!(doc["metadata"]["component"]["name"], "button-box");
}
