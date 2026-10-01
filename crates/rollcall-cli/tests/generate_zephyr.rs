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

/// `(variant, application image)` paired with the bootloader image of the same variant.
const MCUBOOT_BUILDS: [(&str, &str); 3] = [
    ("baseline", "mcuboot"),
    ("bt", "mcuboot"),
    ("tls", "mcuboot"),
];

#[test]
fn generate_sysbuild_equals_manual_generate_plus_merge_bytes() {
    let dir = tempfile::tempdir().unwrap();
    for ((variant, app), (_, boot)) in APP_BUILDS.into_iter().zip(MCUBOOT_BUILDS) {
        for extra in [&["--west-list"][..], &["--include-sdk"][..]] {
            let with = |cmd: &mut Command| {
                if extra == ["--west-list"] {
                    cmd.arg("--west-list").arg(west_list(variant));
                } else {
                    cmd.arg("--include-sdk");
                }
            };
            let mut manual_inputs = Vec::new();
            for image in [app, boot] {
                let path = dir.path().join(format!("{variant}-{image}.cdx.json"));
                let mut cmd = rollcall();
                cmd.arg("generate")
                    .arg("--zephyr")
                    .arg(fixture_build(variant, image))
                    .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
                    .arg(&path);
                with(&mut cmd);
                cmd.assert().code(0);
                manual_inputs.push(path);
            }
            let manual = rollcall()
                .arg("merge")
                .args(&manual_inputs)
                .args(["--product", app, "--timestamp", GOLDEN_TIMESTAMP])
                .output()
                .unwrap();
            assert_eq!(manual.status.code(), Some(0));

            let mut cmd = rollcall();
            cmd.arg("generate")
                .arg("--zephyr")
                .arg(fixtures_root().join(variant))
                .args(["--sysbuild", "--timestamp", GOLDEN_TIMESTAMP]);
            with(&mut cmd);
            let sysbuild = cmd.output().unwrap();
            assert_eq!(sysbuild.status.code(), Some(0), "{}", stderr_of(&sysbuild));
            assert!(
                sysbuild.stdout == manual.stdout,
                "{variant} {extra:?}: --sysbuild differs from generate + merge"
            );
        }
    }
    // The baseline one is the committed golden document.
    let out = generate_zephyr(
        &fixtures_root().join("baseline"),
        &[
            "--sysbuild",
            "--west-list",
            west_list("baseline").to_str().unwrap(),
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout == golden("baseline.sysbuild").as_bytes());
}

#[test]
fn generate_sysbuild_warnings_name_the_image() {
    let out = generate_zephyr(
        &fixtures_root().join("baseline"),
        &["--sysbuild", "--timestamp", GOLDEN_TIMESTAMP],
    );
    assert_eq!(out.status.code(), Some(0));
    let stderr = stderr_of(&out);
    for image in ["with_mcuboot", "mcuboot"] {
        assert!(
            stderr.contains(&format!("rollcall generate: warning: {image}: west list")),
            "{stderr}"
        );
    }
}

#[test]
fn generate_sysbuild_on_image_dir_exit_65() {
    let dir = fixture_build("baseline", "with_mcuboot");
    let out = generate_zephyr(&dir, &["--sysbuild"]);
    assert_fails(
        &out,
        65,
        &dir.join("build_info.yml"),
        &["not a sysbuild top-level build directory"],
    );
    // --sysbuild needs --zephyr.
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    let out = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(&model)
        .arg("--sysbuild")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    // A sysbuild directory whose image directory is missing is a missing input.
    let tmp = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures_root().join("baseline/build_info.yml"),
        tmp.path().join("build_info.yml"),
    )
    .unwrap();
    let out = generate_zephyr(tmp.path(), &["--sysbuild"]);
    assert_eq!(out.status.code(), Some(66), "{}", stderr_of(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn generate_sysbuild_two_images_with_the_same_identity_exit_65_names_both_dirs() {
    // A second MCUboot build (`s1_image`) next to `mcuboot`: both become `bootloader:mcuboot`.
    // Laid out in a temporary directory from copies; `fixtures/` is never touched.
    let top = tempfile::tempdir().unwrap();
    fs::write(
        top.path().join("build_info.yml"),
        "cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images:\n   \
         - name: with_mcuboot\n     type: MAIN\n   - name: mcuboot\n     type: BOOTLOADER\n   \
         - name: s1_image\n     type: BOOTLOADER\n",
    )
    .unwrap();
    for (image, from) in [
        ("with_mcuboot", "with_mcuboot"),
        ("mcuboot", "mcuboot"),
        ("s1_image", "mcuboot"),
    ] {
        let from = fixture_build("baseline", from);
        let to = top.path().join(image);
        for rel in [
            "build_info.yml",
            "spdx/app.spdx",
            "spdx/build.spdx",
            "spdx/modules-deps.spdx",
            "spdx/zephyr.spdx",
            "zephyr/.config",
        ] {
            fs::create_dir_all(to.join(rel).parent().unwrap()).unwrap();
            fs::copy(from.join(rel), to.join(rel)).unwrap();
        }
    }
    let out = generate_zephyr(top.path(), &["--sysbuild"]);
    assert_fails(
        &out,
        65,
        &top.path().join("build_info.yml"),
        &[
            &top.path().join("mcuboot").display().to_string(),
            &top.path().join("s1_image").display().to_string(),
            "bootloader:mcuboot",
        ],
    );
}

#[test]
fn generate_zephyr_mcuboot_dir_yields_bootloader_image_named_mcuboot() {
    for (variant, image) in MCUBOOT_BUILDS {
        let out = generate_zephyr(
            &fixture_build(variant, image),
            &["--west-list", west_list(variant).to_str().unwrap()],
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(doc["metadata"]["component"]["name"], "mcuboot");
        let images = doc["components"].as_array().unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0]["name"], "mcuboot");
        assert!(images[0].get("version").is_none());
        assert!(
            images[0]["properties"].as_array().unwrap().contains(
                &serde_json::json!({"name": "rollcall:image-kind", "value": "bootloader"})
            )
        );
    }
    let out = generate_zephyr(
        &fixture_build("baseline", "mcuboot"),
        &[
            "--west-list",
            west_list("baseline").to_str().unwrap(),
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ],
    );
    assert!(out.stdout == golden("baseline.mcuboot").as_bytes());
}

/// `crates/rollcall-core/tests/data/identifiers-stub.yaml`: maps cmsis, mbedtls and
/// tf-psa-crypto; the fixtures' cmsis_6, hal_nordic and mcuboot are left out on purpose.
fn stub_db() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/identifiers-stub.yaml")
}

const UNMAPPED: [&str; 3] = ["cmsis_6", "hal_nordic", "mcuboot"];

#[test]
fn generate_zephyr_identifier_db_prints_one_warning_and_stub_per_unknown_module() {
    let dir = tempfile::tempdir().unwrap();
    let mut runs: Vec<(String, Vec<String>)> = APP_BUILDS
        .iter()
        .map(|(variant, image)| {
            (
                format!("{variant}/{image}"),
                vec![
                    "--zephyr".to_owned(),
                    fixture_build(variant, image).display().to_string(),
                    "--west-list".to_owned(),
                    west_list(variant).display().to_string(),
                ],
            )
        })
        .collect();
    // With --sysbuild the rule holds across both images of the run.
    for (variant, _) in APP_BUILDS {
        runs.push((
            format!("{variant} --sysbuild"),
            vec![
                "--zephyr".to_owned(),
                fixtures_root().join(variant).display().to_string(),
                "--sysbuild".to_owned(),
                "--west-list".to_owned(),
                west_list(variant).display().to_string(),
            ],
        ));
    }
    for (what, args) in runs {
        let out_path = dir.path().join("out.cdx.json");
        let out = rollcall()
            .arg("generate")
            .args(&args)
            .arg("--identifier-db")
            .arg(stub_db())
            .arg("-o")
            .arg(&out_path)
            .output()
            .unwrap();
        let stderr = stderr_of(&out);
        assert_eq!(out.status.code(), Some(0), "{what}: {stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
        // One warning per unmapped module, and no other module is reported unknown.
        let unknown: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("rollcall generate: warning: "))
            .filter_map(|l| l.strip_suffix(" is not in identifiers-stub.yaml; stub entry printed"))
            .filter_map(|l| l.rsplit_once("module ").map(|(_, m)| m))
            .collect();
        assert_eq!(unknown, UNMAPPED, "{what}: {stderr}");
        // Then the header and one stub per module, after every warning.
        let header =
            "rollcall generate: 3 module(s) not in identifiers-stub.yaml; paste and fill in:\n";
        let (before, stubs) = stderr
            .split_once(header)
            .unwrap_or_else(|| panic!("{what}: no stub header in {stderr}"));
        assert!(
            before
                .lines()
                .all(|l| l.starts_with("rollcall generate: warning: "))
        );
        let keys: Vec<&str> = stubs
            .lines()
            .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
            .collect();
        assert_eq!(
            keys,
            ["  cmsis_6:", "  hal_nordic:", "  mcuboot:"],
            "{what}"
        );
        assert!(
            stubs.contains("pkg:github/zephyrproject-rtos/hal_nordic@v{version}"),
            "{stubs}"
        );
        assert!(
            stubs.contains("\"44fd3d44b15cb75f80a25b4679f91d2787e28664\": \"\""),
            "{stubs}"
        );

        // Pasted under modules: and filled in, the stubs load and nothing is unknown any more.
        let filled = stubs
            .replace("name: \"\"", "name: \"Upstream\"")
            .replace("homepage: \"\"", "homepage: \"https://example.com/\"")
            .replace("supplier: \"\"", "supplier: \"Example\"")
            .replace("<vendor>", "example")
            .replace("<product>", "product")
            .replace(": \"\"    # the upstream", ": \"1.0.0\"    # the upstream");
        let db = dir.path().join("identifiers.yaml");
        fs::write(
            &db,
            format!("{}{filled}", fs::read_to_string(stub_db()).unwrap()),
        )
        .unwrap();
        let out = rollcall()
            .arg("generate")
            .args(&args)
            .arg("--identifier-db")
            .arg(&db)
            .arg("-o")
            .arg(&out_path)
            .output()
            .unwrap();
        let stderr = stderr_of(&out);
        assert_eq!(out.status.code(), Some(0), "{what}: {stderr}");
        assert!(
            !stderr.contains("not in identifiers.yaml"),
            "{what}: {stderr}"
        );
        assert!(!stderr.contains("paste and fill in"), "{what}: {stderr}");
        let validated = rollcall()
            .args(["validate", "--schema"])
            .arg(&out_path)
            .output()
            .unwrap();
        assert_eq!(
            validated.status.code(),
            Some(0),
            "{}",
            stderr_of(&validated)
        );
        // The filled-in upstream identity is in the document.
        let doc: Value = serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
        let text = doc.to_string();
        assert!(
            text.contains("pkg:github/zephyrproject-rtos/hal_nordic@v1.0.0"),
            "{what}"
        );
    }
}

#[test]
fn generate_zephyr_bad_identifier_db_exit_65_names_file_and_line() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("identifiers.yaml");
    let text = fs::read_to_string(stub_db()).unwrap().replace(
        "purl: pkg:github/Mbed-TLS/mbedtls@v{version}",
        "purl: pkg:github/Mbed-TLS/mbedtls@v{ver}",
    );
    fs::write(&db, text).unwrap();
    for extra in [&[][..], &["--sysbuild"][..]] {
        let build = if extra.is_empty() {
            fixture_build("baseline", "with_mcuboot")
        } else {
            fixtures_root().join("baseline")
        };
        let mut args = extra.to_vec();
        args.extend(["--identifier-db", db.to_str().unwrap()]);
        let out = generate_zephyr(&build, &args);
        let stderr = assert_fails(
            &out,
            65,
            &db,
            &["unknown placeholder {ver}", "modules.mbedtls.purl"],
        );
        assert!(
            stderr.starts_with(&format!("rollcall generate: {}:20:11: ", db.display())),
            "{stderr}"
        );
    }
    // A missing database is "no input".
    let absent = dir.path().join("absent.yaml");
    let out = generate_zephyr(
        &fixture_build("baseline", "with_mcuboot"),
        &["--identifier-db", absent.to_str().unwrap()],
    );
    assert_fails(&out, 66, &absent, &[]);
}

#[test]
fn generate_identifier_db_and_workspace_flags_need_their_inputs_exit_64() {
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    let db = stub_db();
    let out = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(&model)
        .arg("--identifier-db")
        .arg(&db)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert!(
        stderr_of(&out).contains("cannot be used with"),
        "{}",
        stderr_of(&out)
    );
    // --workspace needs both an identifier database and a west list (module paths come from
    // the west list); missing either is a usage error, never silently ignored.
    let db_arg = db.display().to_string();
    let west = west_list("baseline").display().to_string();
    for (extra, missing) in [
        (vec!["--workspace", "."], "--identifier-db <FILE>"),
        (
            vec!["--workspace", ".", "--identifier-db", db_arg.as_str()],
            "--west-list <FILE>",
        ),
        (
            vec!["--workspace", ".", "--west-list", west.as_str()],
            "--identifier-db <FILE>",
        ),
    ] {
        let out = generate_zephyr(&fixture_build("baseline", "with_mcuboot"), &extra);
        assert_eq!(
            out.status.code(),
            Some(64),
            "{extra:?}: {}",
            stderr_of(&out)
        );
        assert!(out.stdout.is_empty());
        assert!(
            stderr_of(&out).contains(missing),
            "{extra:?}: {}",
            stderr_of(&out)
        );
    }
    // With both, it is accepted.
    let ws = tempfile::tempdir().unwrap();
    let out = generate_zephyr(
        &fixture_build("baseline", "with_mcuboot"),
        &[
            "--workspace",
            ws.path().to_str().unwrap(),
            "--identifier-db",
            &db_arg,
            "--west-list",
            &west,
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
}

#[test]
fn generate_sysbuild_product_names_and_versions_the_root_and_validates() {
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("widget.cdx.json");
    rollcall()
        .arg("generate")
        .arg("--zephyr")
        .arg(fixtures_root().join("baseline"))
        .arg("--west-list")
        .arg(west_list("baseline"))
        .args([
            "--sysbuild",
            "--product",
            "widget@1.2.3",
            "--timestamp",
            GOLDEN_TIMESTAMP,
            "-o",
        ])
        .arg(&out_path)
        .assert()
        .code(0)
        .stdout("");
    let doc: Value = serde_json::from_slice(&fs::read(&out_path).unwrap()).unwrap();
    let root = &doc["metadata"]["component"];
    assert_eq!(root["name"], "widget", "{root}");
    assert_eq!(root["version"], "1.2.3", "{root}");
    // Both sysbuild images are still there, under the new root.
    let mut images: Vec<&str> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    images.sort_unstable();
    assert_eq!(images, ["mcuboot", "with_mcuboot"]);
    let out = rollcall()
        .args(["validate", "--schema"])
        .arg(&out_path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}: valid CycloneDX 1.6\n", out_path.display())
    );
}

#[test]
fn generate_product_equals_generate_plus_merge_product_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let west = west_list("baseline").display().to_string();
    let db = stub_db().display().to_string();
    let inputs: [(&str, PathBuf, &[&str]); 2] = [
        (
            "sysbuild",
            fixtures_root().join("baseline"),
            &["--sysbuild"],
        ),
        ("single", fixture_build("baseline", "with_mcuboot"), &[]),
    ];
    let options: [Vec<&str>; 2] = [
        vec!["--west-list", &west],
        vec!["--west-list", &west, "--identifier-db", &db],
    ];
    for (label, input, mode) in &inputs {
        for opts in &options {
            for spec in ["widget@1.2.3", "widget", "@scope/widget@1.0.0"] {
                let context = format!("{label} {opts:?} --product {spec}");
                let mut extra: Vec<&str> = mode.to_vec();
                extra.extend(opts.iter().copied());
                extra.extend(["--timestamp", GOLDEN_TIMESTAMP]);

                // The manual pipeline: generate, then merge --product.
                let generated = dir.path().join("generated.cdx.json");
                let mut plain_args = extra.clone();
                plain_args.push("-o");
                let plain = rollcall()
                    .arg("generate")
                    .arg("--zephyr")
                    .arg(input)
                    .args(&plain_args)
                    .arg(&generated)
                    .output()
                    .unwrap();
                assert_eq!(
                    plain.status.code(),
                    Some(0),
                    "{context}: {}",
                    stderr_of(&plain)
                );
                let manual = rollcall()
                    .arg("merge")
                    .arg(&generated)
                    .args(["--product", spec, "--timestamp", GOLDEN_TIMESTAMP])
                    .output()
                    .unwrap();
                assert_eq!(
                    manual.status.code(),
                    Some(0),
                    "{context}: {}",
                    stderr_of(&manual)
                );

                // One step.
                let mut one_step = extra.clone();
                one_step.extend(["--product", spec]);
                let direct = generate_zephyr(input, &one_step);
                assert_eq!(
                    direct.status.code(),
                    Some(0),
                    "{context}: {}",
                    stderr_of(&direct)
                );
                assert!(
                    direct.stdout == manual.stdout,
                    "{context}: generate --product differs from generate + merge --product"
                );
                // Warnings and identifier-database stubs are unchanged by --product.
                assert_eq!(stderr_of(&direct), stderr_of(&plain), "{context}");
                if opts.len() > 2 {
                    assert!(
                        stderr_of(&direct).contains("paste and fill in"),
                        "{context}: {}",
                        stderr_of(&direct)
                    );
                }
            }
        }
    }
}

#[test]
fn generate_invalid_product_spec_exit_64() {
    for spec in ["", "@scope/widget", "@1.2.3", "widget@"] {
        for mode in [&["--sysbuild"][..], &[][..]] {
            let input = if mode.is_empty() {
                fixture_build("baseline", "with_mcuboot")
            } else {
                fixtures_root().join("baseline")
            };
            let mut extra = mode.to_vec();
            extra.extend(["--product", spec]);
            let out = generate_zephyr(&input, &extra);
            let stderr = stderr_of(&out);
            assert_eq!(out.status.code(), Some(64), "{spec:?} {mode:?}: {stderr}");
            assert!(out.stdout.is_empty(), "{spec:?} {mode:?}");
            assert!(!stderr.contains("panicked"), "{stderr}");
            assert!(
                stderr.contains("--product <NAME[@VERSION]>"),
                "{spec:?} {mode:?}: {stderr}"
            );
        }
    }
}

#[test]
fn generate_product_requires_zephyr_exit_64() {
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    let out = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(&model)
        .args(["--product", "widget@1.2.3"])
        .output()
        .unwrap();
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(64), "{stderr}");
    assert!(out.stdout.is_empty());
    assert!(
        stderr.contains("cannot be used with")
            && stderr.contains("'--product <NAME[@VERSION]>'")
            && stderr.contains("'--model <FILE>'"),
        "{stderr}"
    );
    // With no input at all, the missing --zephyr is reported.
    let out = rollcall()
        .args(["generate", "--product", "widget"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(
        stderr_of(&out).contains("--zephyr <DIR>"),
        "{}",
        stderr_of(&out)
    );
}

/// The real Zephyr v4.2.0 old-mbedTLS build (`fixtures/zephyr-old-mbedtls/`) with the seed
/// identifier database: the same bytes as
/// `crates/rollcall-core/tests/golden/zephyr/old-mbedtls.cdx.json`, which
/// `scripts/smoke-scan.sh --only old-mbedtls` scans with grype.
#[test]
fn old_mbedtls_fixture_cli_output_matches_golden() {
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core");
    let variant = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zephyr-old-mbedtls/old-mbedtls");
    let dir = variant.join("mbedtls");
    let west_list = variant.join("west-list.txt");
    let db = core.join("../rollcall-identifiers/db/identifiers.yaml");
    let out = generate_zephyr(
        &dir,
        &[
            "--west-list",
            west_list.to_str().unwrap(),
            "--identifier-db",
            db.to_str().unwrap(),
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ],
    );
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("module mbedtls is not in"), "{stderr}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout, golden("old-mbedtls"));
    // The build's own cpe is primary; the seed database's is a syft:cpe23 property.
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    let mbedtls = doc["components"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["components"].as_array().into_iter().flatten())
        .find(|c| c["type"] == "library" && c["name"] == "mbedtls")
        .expect("mbedtls component");
    assert_eq!(mbedtls["cpe"], "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*");
    let syft: Vec<&str> = mbedtls["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["name"] == "syft:cpe23")
        .filter_map(|p| p["value"].as_str())
        .collect();
    assert_eq!(
        syft,
        ["cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"]
    );
}

/// `generate --sysbuild` on the `tls` fixture with the seed identifier database: Zephyr's own
/// mbedtls purl and cpe and the database's name the same project (same GitHub repository; the
/// SPDX cpe `arm:mbed_tls` is one of the database's `cpe_aliases`), so nothing "differs" for
/// mbedtls, and no purl differs for tf-psa-crypto either. tf-psa-crypto's SPDX cpe
/// `arm:tf-psa-crypto` is not in the NVD CPE dictionary, so it cannot be an alias: that genuinely
/// different cpe is still a warning, once per image.
#[test]
fn sysbuild_tls_with_seed_db_warns_only_about_genuinely_different_identifiers() {
    let db = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-identifiers/db/identifiers.yaml");
    let west_list = west_list("tls");
    let out = generate_zephyr(
        &fixtures_root().join("tls"),
        &[
            "--sysbuild",
            "--west-list",
            west_list.to_str().unwrap(),
            "--identifier-db",
            db.to_str().unwrap(),
            "--timestamp",
            GOLDEN_TIMESTAMP,
        ],
    );
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let differs: Vec<&str> = stderr.lines().filter(|l| l.contains("differs")).collect();
    assert!(
        !differs.iter().any(|l| l.contains("module mbedtls:")),
        "{differs:#?}"
    );
    assert!(
        !differs.iter().any(|l| l.contains(" purl ")),
        "{differs:#?}"
    );
    assert_eq!(
        differs,
        ["http_server", "mcuboot"].map(|image| format!(
            "rollcall generate: warning: {image}: identifiers.yaml: module tf-psa-crypto: \
             identifiers.yaml cpe cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:* \
             differs from spdx/modules-deps.spdx cpe cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*; \
             using cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*, with \
             cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:* as an additional CPE"
        )),
        "{stderr}"
    );
}
