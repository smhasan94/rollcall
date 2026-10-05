//! End-to-end tests for `rollcall generate --esp-idf` on the real ESP-IDF build fixtures in
//! `fixtures/esp-idf/` (SHA-129).
//!
//! The expected documents are `crates/rollcall-core/tests/golden/esp-idf/*.cdx.json`,
//! generated only by `scripts/regen-golden.sh`. `fixtures/` is never modified: error cases
//! copy files into a temporary directory first. `IDF_PATH` is removed from every command's
//! environment so the developer's own ESP-IDF install never reaches the output.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rollcall"));
    c.env_remove("IDF_PATH");
    c
}

fn fixture(variant: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/esp-idf")
        .join(variant)
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden/esp-idf")
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

#[test]
fn generate_esp_idf_fixtures_match_goldens_and_validate() {
    for variant in ["hello-world", "wifi-tls"] {
        let dir = fixture(variant);
        let out = generate(&[
            "--esp-idf".as_ref(),
            dir.as_os_str(),
            "--idf-path".as_ref(),
            dir.join("idf").as_os_str(),
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        assert_eq!(stderr_of(&out), "", "{variant}: no warnings");
        let text = stdout_of(&out);
        assert!(
            text == golden(&format!("{variant}.cdx.json")),
            "{variant} differs from the golden"
        );
        validate_schema(&text);
    }
}

#[test]
fn idf_path_falls_back_to_the_environment_and_without_it_blobs_have_no_hash() {
    let dir = fixture("wifi-tls");
    let out = generate(&["--esp-idf".as_ref(), dir.as_os_str()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stdout_of(&out) == golden("wifi-tls.no-idf-path.cdx.json"));
    assert!(
        stderr_of(&out).contains("rollcall generate: warning: build/https_request.map: 6 linked blob(s) without SHA-256: pass --idf-path"),
        "{}",
        stderr_of(&out)
    );
    // $IDF_PATH stands in for --idf-path.
    let out = rollcall()
        .env("IDF_PATH", dir.join("idf"))
        .args(["generate", "--esp-idf"])
        .arg(&dir)
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stdout_of(&out) == golden("wifi-tls.cdx.json"));
    assert_eq!(
        stderr_of(&out),
        format!(
            "rollcall generate: note: no --idf-path; reading blobs and the version file from $IDF_PATH ({})\n",
            dir.join("idf").display()
        )
    );
}

#[test]
fn build_dir_and_verbose_notes_work_with_esp_idf() {
    let tmp = tempfile::tempdir().unwrap();
    let src = fixture("hello-world");
    for rel in [
        "sdkconfig",
        "build/project_description.json",
        "build/hello_world.map",
    ] {
        let to = tmp.path().join(rel.replace("build/", "out/"));
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(src.join(rel), to).unwrap();
    }
    let out = generate(&[
        "--esp-idf".as_ref(),
        tmp.path().as_os_str(),
        "--build".as_ref(),
        tmp.path().join("out").as_os_str(),
        "--verbose".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    // hello_world enables mbedTLS but links only ESP-IDF's SHA port files.
    assert!(
        stderr_of(&out).contains("rollcall generate: note: out/hello_world.map: subsystem mbedtls is enabled by CONFIG_MBEDTLS_TLS_ENABLED but nothing from"),
        "{}",
        stderr_of(&out)
    );
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    assert_eq!(doc["metadata"]["component"]["name"], "hello_world");
}

#[test]
fn generate_esp_idf_errors_have_exit_codes_and_never_panic() {
    // Missing project or required file: 66.
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-project");
    assert_exit(
        &generate(&["--esp-idf".as_ref(), missing.as_os_str()]),
        66,
        &["project_description.json"],
    );
    // Malformed input: 65, naming the file.
    let tmp = tempfile::tempdir().unwrap();
    let src = fixture("wifi-tls");
    for rel in [
        "sdkconfig",
        "dependencies.lock",
        "main/idf_component.yml",
        "build/project_description.json",
    ] {
        let to = tmp.path().join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(src.join(rel), to).unwrap();
    }
    fs::write(tmp.path().join("dependencies.lock"), "dependencies: [\n").unwrap();
    assert_exit(
        &generate(&["--esp-idf".as_ref(), tmp.path().as_os_str()]),
        65,
        &["dependencies.lock", "not valid YAML"],
    );
    // Flags that need --esp-idf, or conflict with another input: a usage error, 64.
    for args in [
        vec!["--model", "m.json", "--idf-path", "x"],
        vec!["--zephyr", "d", "--build", "x"],
        vec!["--esp-idf", "d", "--zephyr", "d"],
        vec!["--cargo-metadata", "m.json", "--verbose"],
    ] {
        let out = rollcall().arg("generate").args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty());
        assert!(!stderr_of(&out).contains("panicked"));
    }
}
