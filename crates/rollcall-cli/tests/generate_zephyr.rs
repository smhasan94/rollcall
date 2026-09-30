//! End-to-end tests for `rollcall generate --zephyr` on the real build fixtures.
//!
//! The expected documents are `crates/rollcall-core/tests/golden/zephyr/*.cdx.json`, generated
//! only by `scripts/regen-golden.sh`. Negative tests copy a build directory into a temporary
//! directory; `fixtures/` is never modified.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const APP_BUILDS: [(&str, &str); 3] = [
    ("baseline", "with_mcuboot"),
    ("bt", "beacon"),
    ("tls", "http_server"),
];

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr")
}

fn fixture_build(variant: &str, image: &str) -> PathBuf {
    fixtures_root().join(variant).join(image)
}

fn west_list(variant: &str) -> PathBuf {
    fixtures_root().join(variant).join("west-list.txt")
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden/zephyr")
        .join(format!("{name}.cdx.json"));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn generate_zephyr(dir: &Path, extra: &[&str]) -> Output {
    rollcall()
        .arg("generate")
        .arg("--zephyr")
        .arg(dir)
        .args(extra)
        .output()
        .unwrap()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// Asserts a failure: the exit code, empty stdout, no panic, and stderr starting with
/// `rollcall generate: <path>` and containing every `needle`.
fn assert_fails(out: &Output, code: i32, path: &Path, needles: &[&str]) -> String {
    let stderr = stderr_of(out);
    assert_eq!(out.status.code(), Some(code), "stderr: {stderr}");
    assert!(out.stdout.is_empty());
    assert!(!stderr.contains("panicked"), "{stderr}");
    let prefix = format!("rollcall generate: {}", path.display());
    assert!(
        stderr.starts_with(&prefix),
        "{stderr:?} does not start with {prefix:?}"
    );
    for needle in needles {
        assert!(stderr.contains(needle), "{stderr:?} lacks {needle:?}");
    }
    stderr
}

/// Copies a build directory's inputs (not its binaries) into a temporary directory.
fn copy_build(variant: &str, image: &str) -> tempfile::TempDir {
    let from = fixture_build(variant, image);
    let dir = tempfile::tempdir().unwrap();
    for rel in [
        "build_info.yml",
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "spdx/zephyr.spdx",
        "zephyr/.config",
    ] {
        let to = dir.path().join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(from.join(rel), &to).unwrap();
    }
    dir
}

fn components(doc: &Value) -> Vec<&Value> {
    doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .collect()
}

#[test]
fn generate_zephyr_output_validates_with_rollcall_validate() {
    let dir = tempfile::tempdir().unwrap();
    for (variant, image) in APP_BUILDS {
        let out_path = dir.path().join(format!("{variant}.cdx.json"));
        rollcall()
            .arg("generate")
            .arg("--zephyr")
            .arg(fixture_build(variant, image))
            .arg("--west-list")
            .arg(west_list(variant))
            .arg("-o")
            .arg(&out_path)
            .assert()
            .code(0)
            .stdout("")
            .stderr("");
        let out = rollcall()
            .args(["validate", "--schema"])
            .arg(&out_path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert_eq!(
            stdout,
            format!("{}: valid CycloneDX 1.6\n", out_path.display())
        );
    }
}

#[test]
fn generate_zephyr_matches_golden_bytes() {
    for (variant, image) in APP_BUILDS {
        let west_list = west_list(variant);
        let out = generate_zephyr(
            &fixture_build(variant, image),
            &[
                "--west-list",
                west_list.to_str().unwrap(),
                "--timestamp",
                GOLDEN_TIMESTAMP,
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        assert_eq!(stderr_of(&out), "");
        assert_eq!(String::from_utf8(out.stdout).unwrap(), golden(variant));
    }
    let west_list = west_list("baseline");
    let out = generate_zephyr(
        &fixture_build("baseline", "with_mcuboot"),
        &[
            "--west-list",
            west_list.to_str().unwrap(),
            "--include-sdk",
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        golden("baseline.include-sdk")
    );
}

#[test]
fn generate_zephyr_include_sdk_adds_toolchain_component() {
    let build = fixture_build("bt", "beacon");
    let without: Value = serde_json::from_slice(&generate_zephyr(&build, &[]).stdout).unwrap();
    let with: Value =
        serde_json::from_slice(&generate_zephyr(&build, &["--include-sdk"]).stdout).unwrap();
    let names = |doc: &Value| -> Vec<String> {
        components(doc)
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert!(!names(&without).contains(&"zephyr-sdk".to_owned()));
    let sdk = components(&with)
        .into_iter()
        .find(|c| c["name"] == "zephyr-sdk")
        .unwrap();
    assert_eq!(sdk["type"], "application");
    assert_eq!(sdk["version"], "1.0");
    assert_eq!(names(&with).len(), names(&without).len() + 1);
}

#[test]
fn generate_zephyr_warns_on_missing_optional_files_exit_0() {
    let dir = copy_build("baseline", "with_mcuboot");
    for rel in [
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "zephyr/.config",
    ] {
        fs::remove_file(dir.path().join(rel)).unwrap();
    }
    let out = generate_zephyr(dir.path(), &["--timestamp", GOLDEN_TIMESTAMP]);
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 5, "{stderr}");
    for (line, location) in lines.iter().zip([
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "zephyr/.config",
        "west list",
    ]) {
        assert!(
            line.starts_with(&format!("rollcall generate: warning: {location}: ")),
            "{line}"
        );
    }
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(rollcall_core::cyclonedx::validate_cyclonedx_1_6(&doc).is_ok());
    // Without --west-list alone, only that warning.
    let out = generate_zephyr(&fixture_build("tls", "http_server"), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stderr_of(&out),
        "rollcall generate: warning: west list: not given (--west-list); module revisions come \
         from spdx/zephyr.spdx only\n"
    );
}

#[test]
fn generate_zephyr_missing_build_dir_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("no-such-build");
    let out = generate_zephyr(&absent, &[]);
    assert_fails(&out, 66, &absent, &["build_info.yml"]);
}

#[test]
fn generate_zephyr_missing_build_info_exit_66_names_file() {
    let dir = copy_build("bt", "beacon");
    fs::remove_file(dir.path().join("build_info.yml")).unwrap();
    let out = generate_zephyr(dir.path(), &[]);
    assert_fails(&out, 66, &dir.path().join("build_info.yml"), &[]);
}

#[test]
fn generate_zephyr_truncated_spdx_exit_65_names_file_no_panic() {
    let dir = copy_build("tls", "http_server");
    let path = dir.path().join("spdx/zephyr.spdx");
    let text = fs::read_to_string(&path).unwrap();
    // Cut inside the first <text> block, and just after a PackageName line.
    let in_text = text.find("<text>\n").unwrap() + "<text>\n".len();
    let package = text.find("PackageName: ").unwrap();
    let after_package = package + text[package..].find('\n').unwrap() + 1;
    for (cut, needle) in [(in_text, "<text>"), (after_package, "SPDXID")] {
        fs::write(&path, &text[..cut]).unwrap();
        let out = generate_zephyr(dir.path(), &[]);
        assert_fails(&out, 65, &path, &["line ", needle]);
    }
}

#[test]
fn generate_zephyr_bad_config_exit_65_names_file() {
    let dir = copy_build("baseline", "with_mcuboot");
    let path = dir.path().join("zephyr/.config");
    let text = fs::read_to_string(&path).unwrap();
    let line = text.lines().count() + 1;
    fs::write(&path, format!("{text}CONFIG_FOO\n")).unwrap();
    let out = generate_zephyr(dir.path(), &[]);
    assert_fails(
        &out,
        65,
        &path,
        &[&format!("line {line}"), "unknown syntax"],
    );
}

#[test]
fn generate_zephyr_missing_named_west_list_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("west-list.txt");
    let out = generate_zephyr(
        &fixture_build("baseline", "with_mcuboot"),
        &["--west-list", absent.to_str().unwrap()],
    );
    assert_fails(&out, 66, &absent, &[]);
}

#[test]
fn generate_zephyr_sysbuild_top_dir_exit_65_names_image_dir() {
    for (variant, image) in APP_BUILDS {
        let top = fixtures_root().join(variant);
        let out = generate_zephyr(&top, &[]);
        assert_fails(
            &out,
            65,
            &top.join("build_info.yml"),
            &["sysbuild", &format!("{image}/")],
        );
    }
}

#[test]
fn generate_requires_exactly_one_of_model_or_zephyr_exit_64() {
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    let out = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(&model)
        .arg("--zephyr")
        .arg(fixture_build("bt", "beacon"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert!(
        stderr_of(&out).contains("cannot be used with"),
        "{}",
        stderr_of(&out)
    );
    let out = rollcall().arg("generate").output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("--model <FILE>") && stderr.contains("--zephyr <DIR>"),
        "{stderr}"
    );
}

#[test]
fn generate_west_list_and_include_sdk_require_zephyr_exit_64() {
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    for extra in [
        vec![
            "--west-list".to_owned(),
            west_list("bt").display().to_string(),
        ],
        vec!["--include-sdk".to_owned()],
    ] {
        let out = rollcall()
            .arg("generate")
            .arg("--model")
            .arg(&model)
            .args(&extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{extra:?}");
        assert!(out.stdout.is_empty());
        let stderr = stderr_of(&out);
        assert!(
            stderr.contains("cannot be used with")
                && stderr.contains(&format!("'{}", extra[0]))
                && stderr.contains("'--model <FILE>'"),
            "{stderr}"
        );
    }
    // And with no input at all, the missing --zephyr is reported.
    for flag in ["--include-sdk", "--west-list=x"] {
        let out = rollcall().args(["generate", flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(64));
        assert!(
            stderr_of(&out).contains("--zephyr <DIR>"),
            "{}",
            stderr_of(&out)
        );
    }
}

#[test]
fn generate_zephyr_t2_west_list_keeps_one_zephyr_and_warns_on_unmatched_row() {
    // A T2 workspace: the application is the manifest repository and Zephyr is a project,
    // plus a project (bsim) that is not a module of this build.
    let dir = copy_build("baseline", "with_mcuboot");
    let sha = "dccb09599635bdff17633fa7e9dab014b91dce90";
    let original = fs::read_to_string(west_list("baseline")).unwrap();
    let t2 = original.replace(
        "manifest zephyr HEAD N/A\n",
        &format!(
            "manifest with_mcuboot HEAD N/A\nzephyr zephyr {sha} https://github.com/zephyrproject-rtos/zephyr\n"
        ),
    ) + "bsim tools/bsim 0123456789012345678901234567890123456789 https://github.com/zephyrproject-rtos/babblesim-manifest\n";
    let list = dir.path().join("west-list.txt");
    fs::write(&list, &t2).unwrap();
    let bsim_line = t2.lines().count();

    let out = generate_zephyr(dir.path(), &["--west-list", list.to_str().unwrap()]);
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(
        stderr,
        format!(
            "rollcall generate: warning: west-list.txt:{bsim_line}: west list project bsim is not \
             a module of this build (no bsim-sources package in spdx/zephyr.spdx); ignored\n"
        )
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let zephyrs: Vec<&Value> = components(&doc)
        .into_iter()
        .filter(|c| c["name"] == "zephyr")
        .collect();
    assert_eq!(zephyrs.len(), 1);
    assert_eq!(zephyrs[0]["type"], "operating-system");
    assert_eq!(zephyrs[0]["version"], "4.4.2");
    let version_methods = zephyrs[0]["evidence"]["identity"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["field"] == "version")
        .unwrap()["methods"]
        .as_array()
        .unwrap()
        .clone();
    assert!(
        version_methods.iter().any(|m| m["value"] == sha),
        "{version_methods:?}"
    );
    assert!(components(&doc).iter().all(|c| c["name"] != "bsim"));
    // The six real modules are still there, once each.
    let libraries = components(&doc)
        .iter()
        .filter(|c| c["type"] == "library")
        .count();
    assert_eq!(libraries, 6);
}
