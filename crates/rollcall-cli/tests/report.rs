//! End-to-end tests for `rollcall report` (SHA-120). The expected outputs are the
//! rollcall-core report goldens (`crates/rollcall-core/tests/golden/report/`), written only by
//! `scripts/regen-golden.sh`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

const TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

/// `rollcall generate --model tests/data/<model>.model.json` into `dir/sbom.cdx.json`, as the
/// core report tests render it.
fn sbom(dir: &Path, model: &str) -> PathBuf {
    let out = dir.join("sbom.cdx.json");
    rollcall()
        .args(["generate", "--timestamp", TIMESTAMP, "--model"])
        .arg(core_dir().join(format!("data/{model}.model.json")))
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    out
}

fn golden(name: &str) -> String {
    let path = core_dir().join("golden/report").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    })
}

/// The old-mbedTLS report's arguments: both captured scans and the CycloneDX VEX golden.
fn old_mbedtls_inputs() -> Vec<PathBuf> {
    vec![
        core_dir().join("data/findings/old-mbedtls.grype.json"),
        core_dir().join("data/findings/old-mbedtls.osv.json"),
        core_dir().join("golden/vex/old-mbedtls.vex.cdx.json"),
    ]
}

fn report(sbom: &Path, format: &str) -> Command {
    let mut cmd = rollcall();
    cmd.arg("report")
        .arg(sbom)
        .args(["--format", format, "--timestamp", TIMESTAMP]);
    cmd
}

#[test]
fn clean_report_cli_scores_100_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "clean");
    let out = report(&sbom, "json").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["schema"], "rollcall-report/1");
    assert_eq!(value["score"]["value"], 100);
    assert_eq!(value["warnings"], Value::Array(Vec::new()));
    // A low score is still exit 0: the report was produced.
    let low = sbom_for(dir.path(), "widget");
    report(&low, "md").assert().code(0);
}

fn sbom_for(dir: &Path, model: &str) -> PathBuf {
    let sub = dir.join(model);
    std::fs::create_dir_all(&sub).unwrap();
    sbom(&sub, model)
}

/// `rollcall report` writes exactly the core goldens, for an SBOM alone and with scans and
/// VEX, in both formats.
#[test]
fn cli_md_and_json_match_core_goldens() {
    let dir = tempfile::tempdir().unwrap();
    for (model, extra) in [("clean", Vec::new()), ("old-mbedtls", old_mbedtls_inputs())] {
        let sbom = sbom_for(dir.path(), model);
        for (format, ext) in [("md", "md"), ("json", "json")] {
            let mut cmd = report(&sbom, format);
            for path in &extra {
                let flag = if path.to_string_lossy().contains("/findings/") {
                    "--scan"
                } else {
                    "--vex"
                };
                cmd.arg(flag).arg(path);
            }
            let out = cmd.output().unwrap();
            assert_eq!(out.status.code(), Some(0), "{model} {format}");
            assert!(
                out.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                String::from_utf8(out.stdout).unwrap(),
                golden(&format!("{model}.report.{ext}")),
                "{model} {format}"
            );
        }
    }
}

#[test]
fn missing_input_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "minimal");
    let missing = dir.path().join("nope.json");
    for args in [
        vec![missing.clone()],
        vec![sbom.clone(), "--scan".into(), missing.clone()],
        vec![sbom.clone(), "--vex".into(), missing.clone()],
    ] {
        let out = rollcall()
            .arg("report")
            .args(&args)
            .args(["--format", "md"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(66), "{args:?}: {stderr}");
        assert!(stderr.starts_with("rollcall report: "), "{stderr}");
        assert!(stderr.contains("nope.json"), "{stderr}");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn malformed_sbom_scan_or_vex_exit_65_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "minimal");
    let text = std::fs::read(&sbom).unwrap();
    let bad: [(&str, &[u8]); 6] = [
        ("empty.json", b""),
        ("truncated.json", &text[..text.len() / 2]),
        ("latin1.json", &[0xff, 0xfe, b'{', b'}']),
        ("array.json", b"[]"),
        ("number.json", b"42"),
        ("unknown.json", br#"{"hello": "world"}"#),
    ];
    for (name, bytes) in bad {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        for args in [
            vec![path.clone()],
            vec![sbom.clone(), "--scan".into(), path.clone()],
            vec![sbom.clone(), "--vex".into(), path.clone()],
        ] {
            let out = rollcall()
                .arg("report")
                .args(&args)
                .args(["--format", "json"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(65), "{args:?}: {stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
            assert!(stderr.contains(name), "{stderr}");
            assert!(out.stdout.is_empty());
        }
    }
}

#[test]
fn output_flag_writes_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "minimal");
    let stdout = report(&sbom, "md").output().unwrap().stdout;
    let target = dir.path().join("report.md");
    std::fs::write(&target, "old contents").unwrap();
    report(&sbom, "md")
        .arg("-o")
        .arg(&target)
        .assert()
        .code(0)
        .stdout("");
    assert_eq!(std::fs::read(&target).unwrap(), stdout);
    // Nothing else is left in the directory (no temporary file).
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["report.md", "sbom.cdx.json"]);
    // An unwritable destination: exit 74, nothing written.
    let nowhere = dir.path().join("no/such/dir/report.md");
    let out = report(&sbom, "json")
        .arg("-o")
        .arg(&nowhere)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(74));
    assert!(!nowhere.exists());
    // A malformed input never touches an existing output.
    let empty = dir.path().join("empty.json");
    std::fs::write(&empty, "").unwrap();
    rollcall()
        .arg("report")
        .arg(&empty)
        .args(["--format", "md", "-o"])
        .arg(&target)
        .assert()
        .code(65);
    assert_eq!(std::fs::read(&target).unwrap(), stdout);
}

/// A pipe whose read end is already closed, so every write to it fails with EPIPE.
fn closed_pipe() -> std::process::Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

#[test]
fn closed_stdout_exits_74_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "minimal");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"))
        .arg("report")
        .arg(&sbom)
        .args(["--format", "md"])
        .stdout(closed_pipe())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(74), "{:?}: {stderr}", out.status);
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn report_usage_errors_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = sbom(dir.path(), "minimal");
    // No --format, an unknown format, a bad timestamp, no SBOM.
    rollcall().arg("report").arg(&sbom).assert().code(64);
    rollcall()
        .arg("report")
        .arg(&sbom)
        .args(["--format", "html"])
        .assert()
        .code(64);
    rollcall()
        .arg("report")
        .arg(&sbom)
        .args(["--format", "md", "--timestamp", "yesterday"])
        .assert()
        .code(64);
    rollcall()
        .args(["report", "--format", "md"])
        .assert()
        .code(64);
}
