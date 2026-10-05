//! End-to-end tests for `rollcall generate`.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

fn model(name: &str) -> PathBuf {
    core_dir().join("data").join(format!("{name}.model.json"))
}

fn golden(name: &str) -> String {
    let path = core_dir().join("golden").join(format!("{name}.cdx.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn generate(name: &str, extra: &[&str]) -> std::process::Output {
    rollcall()
        .arg("generate")
        .arg("--model")
        .arg(model(name))
        .args(extra)
        .output()
        .unwrap()
}

fn stdout_of(output: &std::process::Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout.clone()).unwrap()
}

/// Lines of `a` not equal to the line at the same position in `b`, pairwise.
fn differing_lines(a: &str, b: &str) -> Vec<(String, String)> {
    assert_eq!(a.lines().count(), b.lines().count());
    a.lines()
        .zip(b.lines())
        .filter(|(x, y)| x != y)
        .map(|(x, y)| (x.to_owned(), y.to_owned()))
        .collect()
}

#[test]
fn generate_minimal_matches_golden_bytes() {
    let out = generate("minimal", &["--timestamp", GOLDEN_TIMESTAMP]);
    assert_eq!(stdout_of(&out), golden("minimal"));
}

#[test]
fn generate_widget_matches_golden_bytes() {
    let out = generate("widget", &["--timestamp", GOLDEN_TIMESTAMP]);
    assert_eq!(stdout_of(&out), golden("widget"));
}

#[test]
fn generate_output_file_equals_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.cdx.json");
    for flag in ["-o", "--output"] {
        rollcall()
            .arg("generate")
            .arg("--model")
            .arg(model("widget"))
            .args(["--timestamp", GOLDEN_TIMESTAMP, flag])
            .arg(&path)
            .assert()
            .code(0)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::is_empty());
        let written = std::fs::read_to_string(&path).unwrap();
        let stdout = stdout_of(&generate("widget", &["--timestamp", GOLDEN_TIMESTAMP]));
        assert_eq!(written, stdout);
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn generate_timestamp_override_changes_only_timestamp_line() {
    for name in ["minimal", "widget"] {
        let a = stdout_of(&generate(name, &["--timestamp", GOLDEN_TIMESTAMP]));
        // A non-UTC offset is normalised to UTC.
        let b = stdout_of(&generate(
            name,
            &["--timestamp", "2031-07-08T11:10:11+02:00"],
        ));
        assert_eq!(
            differing_lines(&a, &b),
            [(
                format!("    \"timestamp\": \"{GOLDEN_TIMESTAMP}\","),
                "    \"timestamp\": \"2031-07-08T09:10:11Z\",".to_owned()
            )],
            "{name}"
        );
    }
    // Without --timestamp, the current time is used and nothing else changes.
    let a = stdout_of(&generate("minimal", &["--timestamp", GOLDEN_TIMESTAMP]));
    let now = stdout_of(&generate("minimal", &[]));
    let diff = differing_lines(&a, &now);
    assert!(diff.len() <= 1, "{diff:#?}");
    for (_, line) in diff {
        assert!(
            line.trim_start().starts_with("\"timestamp\": \"20"),
            "{line}"
        );
    }
}

#[test]
fn generate_serial_number_override_is_used() {
    let serial = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
    let a = stdout_of(&generate("minimal", &["--timestamp", GOLDEN_TIMESTAMP]));
    let b = stdout_of(&generate(
        "minimal",
        &["--timestamp", GOLDEN_TIMESTAMP, "--serial-number", serial],
    ));
    let diff = differing_lines(&a, &b);
    assert_eq!(diff.len(), 1, "{diff:#?}");
    assert_eq!(diff[0].1, format!("  \"serialNumber\": \"{serial}\","));
}

/// SPDX export is deferred (rollcall#37): `--format spdx` is not a value at all, so clap
/// rejects it as a usage error naming the only format, and `--help` says why.
#[test]
fn generate_format_spdx_is_rejected_exit_64() {
    let out = generate("minimal", &["--format", "spdx"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("invalid value 'spdx' for '--format <FORMAT>'"),
        "{stderr}"
    );
    assert!(stderr.contains("[possible values: cyclonedx]"), "{stderr}");
    let help = Command::new(env!("CARGO_BIN_EXE_rollcall"))
        .args(["generate", "--help"])
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(
        help.contains("SPDX export is deferred")
            && help.contains("https://github.com/smhasan94/rollcall/issues/37"),
        "{help}"
    );
    assert!(!help.contains("- spdx"), "{help}");
    // The default and explicit cyclonedx format agree.
    let a = stdout_of(&generate("minimal", &["--timestamp", GOLDEN_TIMESTAMP]));
    let b = stdout_of(&generate(
        "minimal",
        &["--timestamp", GOLDEN_TIMESTAMP, "--format", "cyclonedx"],
    ));
    assert_eq!(a, b);
    let bogus = generate("minimal", &["--format", "xml"]);
    assert_eq!(bogus.status.code(), Some(64));
}

#[test]
fn generate_rejects_bad_timestamp_exit_64() {
    for bad in [
        "yesterday",
        "2026-01-02",
        "2026-01-02T03:04:05",
        "2026-02-30T00:00:00Z",
        "",
    ] {
        let out = generate("minimal", &["--timestamp", bad]);
        assert_eq!(out.status.code(), Some(64), "{bad:?}");
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("--timestamp"), "{bad:?}: {stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}

#[test]
fn generate_rejects_bad_serial_number_exit_64() {
    for bad in [
        "urn:uuid:NOPE",
        "3e671687-395b-41f5-a30f-a58921a69b79",
        "urn:uuid:3E671687-395B-41F5-A30F-A58921A69B79",
        "",
    ] {
        let out = generate("minimal", &["--serial-number", bad]);
        assert_eq!(out.status.code(), Some(64), "{bad:?}");
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.contains("--serial-number"), "{bad:?}: {stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
}

#[test]
fn generate_missing_model_file_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    for path in [dir.path().join("absent.model.json"), dir.path().to_owned()] {
        let out = rollcall()
            .arg("generate")
            .arg("--model")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(66), "{}", path.display());
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(
            stderr.starts_with(&format!("rollcall generate: {}: ", path.display())),
            "{stderr}"
        );
    }
}

#[test]
fn generate_malformed_model_exit_65_no_panic() {
    let widget = std::fs::read_to_string(model("widget")).unwrap();
    let wrong_schema = widget.replace("rollcall-model/1", "rollcall-model/2");
    assert_ne!(wrong_schema, widget);
    let mut dangling: serde_json::Value = serde_json::from_str(&widget).unwrap();
    dangling["dependencies"][format!("component:{}", "0".repeat(32))] = serde_json::json!([]);
    let mut invalid_utf8 = widget.clone().into_bytes();
    let at = invalid_utf8
        .windows(6)
        .position(|w| w == b"widget")
        .unwrap();
    invalid_utf8.insert(at + 1, 0xff);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", b"{not json".to_vec()),
        ("empty", Vec::new()),
        ("deeply nested", "[".repeat(200_000).into_bytes()),
        ("invalid utf-8", invalid_utf8),
        ("empty object", b"{}".to_vec()),
        ("wrong schema tag", wrong_schema.into_bytes()),
        (
            "dangling dependency",
            serde_json::to_vec(&dangling).unwrap(),
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    for (what, bytes) in cases {
        let path = dir.path().join("bad.model.json");
        std::fs::write(&path, bytes).unwrap();
        let out = rollcall()
            .arg("generate")
            .arg("--model")
            .arg(&path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{what}: {stderr}");
        assert!(out.stdout.is_empty(), "{what}");
        assert!(
            stderr.starts_with("rollcall generate: "),
            "{what}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{what}: {stderr}");
    }
}

#[test]
fn generate_output_unwritable_exit_74() {
    let dir = tempfile::tempdir().unwrap();
    let out = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(model("minimal"))
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(74));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!("rollcall generate: {}: ", dir.path().display())),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// Names of the entries in `dir`, sorted.
fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A failure part-way through writing cannot be injected portably, so this covers the
/// observable guarantees of the write-to-temp-then-rename approach instead:
/// - a generate that fails before writing (malformed model) leaves an existing `-o` file
///   byte-for-byte untouched;
/// - a failure in the write step itself (the final rename onto a directory fails) exits 74,
///   leaves the target as it was, and leaves no temporary file behind;
/// - a successful generate replaces the file completely, keeps its permissions on Unix, and
///   leaves no temporary file behind.
#[test]
fn generate_failed_write_keeps_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.cdx.json");
    let previous = b"previous contents that must survive\n".repeat(1000);
    std::fs::write(&out, &previous).unwrap();
    let bad_model = dir.path().join("bad.model.json");
    std::fs::write(&bad_model, b"{not json").unwrap();

    rollcall()
        .arg("generate")
        .arg("--model")
        .arg(&bad_model)
        .arg("-o")
        .arg(&out)
        .assert()
        .code(65);
    assert_eq!(std::fs::read(&out).unwrap(), previous);
    assert_eq!(listing(dir.path()), ["bad.model.json", "out.cdx.json"]);

    // The rename itself fails: the target is a non-empty directory.
    let target_dir = dir.path().join("occupied");
    std::fs::create_dir(&target_dir).unwrap();
    std::fs::write(target_dir.join("keep"), b"keep").unwrap();
    let result = rollcall()
        .arg("generate")
        .arg("--model")
        .arg(model("minimal"))
        .arg("-o")
        .arg(&target_dir)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(74));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
    assert_eq!(listing(&target_dir), ["keep"]);
    assert_eq!(
        listing(dir.path()),
        ["bad.model.json", "occupied", "out.cdx.json"]
    );

    // Success replaces the whole file and keeps its permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    rollcall()
        .arg("generate")
        .arg("--model")
        .arg(model("minimal"))
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&out)
        .assert()
        .code(0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), golden("minimal"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }
    assert_eq!(
        listing(dir.path()),
        ["bad.model.json", "occupied", "out.cdx.json"]
    );
}
