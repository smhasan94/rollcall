//! End-to-end tests for `rollcall validate --schema`.

use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

fn validate(path: &Path) -> std::process::Output {
    rollcall()
        .args(["validate", "--schema"])
        .arg(path)
        .output()
        .unwrap()
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn validate_schema_accepts_generated_documents() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["minimal", "widget"] {
        let model = core_dir().join("data").join(format!("{name}.model.json"));
        let out_path = dir.path().join(format!("{name}.cdx.json"));
        rollcall()
            .arg("generate")
            .arg("--model")
            .arg(&model)
            .arg("-o")
            .arg(&out_path)
            .assert()
            .code(0);
        // Both a freshly generated document (current timestamp) and the committed golden.
        let golden = core_dir().join("golden").join(format!("{name}.cdx.json"));
        for path in [&out_path, &golden] {
            let out = validate(path);
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(out.stderr.is_empty());
            assert_eq!(
                String::from_utf8(out.stdout).unwrap(),
                format!("{}: valid CycloneDX 1.6\n", path.display())
            );
        }
    }
}

#[test]
fn validate_schema_rejects_invalid_document_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(
        dir.path(),
        "bad.cdx.json",
        br#"{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:NOPE","metadata":{"timestamp":"yesterday"},"components":[{"type":"widget","name":3}]}"#,
    );
    let out = validate(&path);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let mut lines = stderr.lines();
    assert_eq!(
        lines.next().unwrap(),
        format!("{}: 4 schema violation(s)", path.display())
    );
    let paths: Vec<&str> = lines
        .map(|l| {
            let l = l.strip_prefix("  ").unwrap_or_else(|| panic!("{l:?}"));
            l.split(": ").next().unwrap()
        })
        .collect();
    assert_eq!(
        paths,
        [
            "/components/0/name",
            "/components/0/type",
            "/metadata/timestamp",
            "/serialNumber"
        ],
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"));
}

#[test]
fn validate_schema_rejects_spec_version_1_5_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let golden = std::fs::read_to_string(core_dir().join("golden/minimal.cdx.json")).unwrap();
    let text = golden.replace("\"specVersion\": \"1.6\"", "\"specVersion\": \"1.5\"");
    assert_ne!(text, golden);
    let path = write_file(dir.path(), "old.cdx.json", text.as_bytes());
    let out = validate(&path);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        stderr,
        format!(
            "{}: 1 schema violation(s)\n  /specVersion: expected \"1.6\", found \"1.5\"\n",
            path.display()
        )
    );
}

#[test]
fn validate_malformed_input_exit_65_no_panic() {
    let dir = tempfile::tempdir().unwrap();
    let golden = std::fs::read(core_dir().join("golden/minimal.cdx.json")).unwrap();
    let mut invalid_utf8 = golden.clone();
    let at = invalid_utf8
        .windows(9)
        .position(|w| w == b"CycloneDX")
        .unwrap();
    invalid_utf8.insert(at + 1, 0xff);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", golden[..golden.len() / 2].to_vec()),
        ("not json", b"{not json".to_vec()),
        ("empty", Vec::new()),
        ("whitespace", b" \n".to_vec()),
        ("deeply nested", "[".repeat(200_000).into_bytes()),
        ("invalid utf-8", invalid_utf8),
        ("trailing garbage", [golden.as_slice(), b"x"].concat()),
    ];
    for (what, bytes) in cases {
        let path = write_file(dir.path(), "bad.json", &bytes);
        let out = validate(&path);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{what}: {stderr}");
        assert!(out.stdout.is_empty(), "{what}");
        assert!(
            stderr.starts_with(&format!(
                "rollcall validate: {}: not valid JSON: ",
                path.display()
            )),
            "{what}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{what}: {stderr}");
    }
    // Valid JSON that is not a CycloneDX object is a schema failure, not a parse failure.
    for (what, bytes) in [
        ("array", b"[]".as_slice()),
        ("null", b"null"),
        ("empty object", b"{}"),
    ] {
        let path = write_file(dir.path(), "odd.json", bytes);
        let out = validate(&path);
        assert_eq!(out.status.code(), Some(1), "{what}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
    }
}

#[test]
fn validate_missing_file_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.cdx.json");
    let out = validate(&path);
    assert_eq!(out.status.code(), Some(66));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!("rollcall validate: {}: ", path.display())),
        "{stderr}"
    );
}

#[test]
fn validate_directory_as_file_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let out = validate(dir.path());
    assert_eq!(out.status.code(), Some(66));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!("rollcall validate: {}: ", dir.path().display())),
        "{stderr}"
    );
}

#[test]
fn validate_output_is_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(
        dir.path(),
        "bad.cdx.json",
        br#"{"bomFormat":"CycloneDX","specVersion":"1.6","version":0,"serialNumber":"x","metadata":{"timestamp":"t","component":{"name":1}},"components":[{"type":"widget","name":3},{"name":"n"},{"type":"library","name":"m","hashes":[{"alg":"MD4","content":"zz"}]}],"dependencies":[{"dependsOn":[1]}]}"#,
    );
    let first = validate(&path);
    assert_eq!(first.status.code(), Some(1));
    for _ in 0..5 {
        let again = validate(&path);
        assert_eq!(again.status.code(), Some(1));
        assert_eq!(again.stdout, first.stdout);
        assert_eq!(again.stderr, first.stderr);
    }
    let stderr = String::from_utf8(first.stderr).unwrap();
    let paths: Vec<String> = stderr
        .lines()
        .skip(1)
        .map(|l| l.trim_start().split(": ").next().unwrap().to_owned())
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "{stderr}");
    assert!(paths.len() >= 8, "{stderr}");
}

/// A pipe whose read end is already closed, so every write to it fails with EPIPE.
fn closed_pipe() -> std::process::Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

#[test]
fn validate_closed_output_pipe_exits_without_panic() {
    let golden = core_dir().join("golden/minimal.cdx.json");

    // Like `rollcall validate --schema f | head -0`, with the reader gone before the write,
    // so the failure is deterministic: exit 74 (EX_IOERR), no panic, not killed by a signal.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"))
        .args(["validate", "--schema"])
        .arg(&golden)
        .stdout(closed_pipe())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(74),
        "status {:?}: {stderr}",
        out.status
    );
    assert!(!stderr.contains("panicked"), "{stderr}");

    // A closed stderr while reporting violations: the exit code still says invalid (1); a
    // panic would exit 101.
    let dir = tempfile::tempdir().unwrap();
    let bad = write_file(
        dir.path(),
        "bad.cdx.json",
        br#"{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:NOPE"}"#,
    );
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"))
        .args(["validate", "--schema"])
        .arg(&bad)
        .stdout(std::process::Stdio::null())
        .stderr(closed_pipe())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "{status:?}");

    // The same for a missing file and for malformed JSON.
    for (path, code) in [
        (dir.path().join("absent.json"), 66),
        (write_file(dir.path(), "x.json", b"{"), 65),
    ] {
        let status = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"))
            .args(["validate", "--schema"])
            .arg(&path)
            .stderr(closed_pipe())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(code), "{}: {status:?}", path.display());
    }
}

/// SHA-132: `--schema` detects a CSAF document by content and checks it against the vendored
/// CSAF 2.0 schema and the CSAF mandatory tests rollcall implements: the committed golden
/// passes; a broken copy fails both.
#[test]
fn validate_schema_detects_csaf_and_reports_violations() {
    let golden = core_dir().join("golden/csaf/old-mbedtls.csaf.json");
    let out = validate(&golden);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        format!("{}: valid CSAF 2.0\n", golden.display())
    );

    let dir = tempfile::tempdir().unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&golden).unwrap()).unwrap();
    // A schema violation.
    doc["document"]["tracking"]["status"] = serde_json::json!("done");
    let path = write_file(
        dir.path(),
        "bad-schema.csaf.json",
        doc.to_string().as_bytes(),
    );
    let out = validate(&path);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("/document/tracking/status"), "{stderr}");

    // Schema-valid, but a product status names an undefined product (mandatory test 6.1.1).
    doc["document"]["tracking"]["status"] = serde_json::json!("final");
    doc["vulnerabilities"][0]["product_status"]["under_investigation"] =
        serde_json::json!(["no-such-product"]);
    let path = write_file(dir.path(), "bad-ref.csaf.json", doc.to_string().as_bytes());
    let out = validate(&path);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("CSAF 6.1.1"), "{stderr}");
}
