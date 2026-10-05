//! End-to-end tests for `rollcall validate --profile` (and its combination with `--schema`
//! and `--json`). The clean and stripped documents are goldens of `rollcall-core`, written
//! only by `scripts/regen-golden.sh`.

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn golden(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden")
        .join(name)
}

fn validate(args: &[&str], path: &Path) -> Output {
    rollcall()
        .arg("validate")
        .args(args)
        .arg(path)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn write_json(dir: &Path, name: &str, value: &Value) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    path
}

/// The finding lines of a failing text report (every stderr line after the summary).
fn finding_lines(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|l| l.starts_with("  ")).collect()
}

#[test]
fn clean_golden_passes_all_profiles_exit_0() {
    let clean = golden("clean.cdx.json");
    let out = validate(&["--profile", "all", "--schema"], &clean);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let file = clean.display();
    assert_eq!(
        text(&out.stdout),
        format!(
            "{file}: valid CycloneDX 1.6\n{file}: passes cisa-2026, cra (12 checks, 0 warnings)\n"
        )
    );
    for (profile, checks) in [("cisa-2026", 10), ("cra", 12)] {
        let out = validate(&["--profile", profile], &clean);
        assert_eq!(out.status.code(), Some(0), "{profile}");
        assert!(out.stderr.is_empty(), "{profile}: {}", text(&out.stderr));
        assert_eq!(
            text(&out.stdout),
            format!("{file}: passes {profile} ({checks} checks, 0 warnings)\n")
        );
    }
}

#[test]
fn stripped_document_fails_naming_both_components() {
    let stripped = golden("validate/clean.stripped.cdx.json");
    let doc = read_json(&stripped);
    // The bom-refs of the two stripped components, from the document itself.
    let mut refs = Vec::new();
    for image in doc["components"].as_array().unwrap() {
        for c in image["components"].as_array().into_iter().flatten() {
            if c["name"] == "mbedtls" || c["name"] == "littlefs" {
                assert!(c.get("supplier").is_none() && c.get("hashes").is_none());
                refs.push((
                    c["name"].as_str().unwrap().to_owned(),
                    c["bom-ref"].as_str().unwrap().to_owned(),
                ));
            }
        }
    }
    assert_eq!(refs.len(), 2);

    let out = validate(&["--profile", "all"], &stripped);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert_eq!(
        stderr.lines().next().unwrap(),
        format!(
            "{}: 4 error(s), 0 warning(s) against cisa-2026, cra",
            stripped.display()
        )
    );
    let lines = finding_lines(&stderr);
    assert_eq!(lines.len(), 4, "{stderr}");
    // One line pinned byte for byte: severity padded to 7 columns, then two spaces.
    let littlefs = &refs.iter().find(|(n, _)| n == "littlefs").unwrap().1;
    assert_eq!(
        lines[0],
        format!(
            "  error    component.supplier  {littlefs}  littlefs@2.9.0: no supplier \
             (manufacturer.name and supplier.name missing). Fix: set manufacturer.name or \
             supplier.name to the organisation that supplies this component. [cisa-2026: Data \
             Fields, Component Data: Component Producer (p. 10); cra: section 5.2.2, Table 3: \
             Component creator (lenient: name accepted, see profile header)]"
        )
    );
    // docs/validate.md shows this exact line as its example.
    let docs = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/validate.md"),
    )
    .unwrap();
    assert!(
        docs.lines().any(|l| l == lines[0]),
        "docs/validate.md example differs from {:?}",
        lines[0]
    );
    for (name, bom_ref) in &refs {
        for check in ["component.supplier", "component.hash"] {
            let matching: Vec<_> = lines
                .iter()
                .filter(|l| l.contains(check) && l.contains(bom_ref.as_str()))
                .collect();
            assert_eq!(matching.len(), 1, "{name} {check}: {stderr}");
            let line = matching[0];
            assert!(line.contains(&format!("{name}@")), "{line}");
            assert!(line.trim_start().starts_with("error"), "{line}");
            assert!(line.contains(". Fix: "), "{line}");
            assert!(
                line.contains("[cisa-2026: ") && line.contains("; cra: "),
                "{line}"
            );
        }
    }
    assert!(!stderr.contains("panicked"));
}

#[test]
fn stripped_document_json_matches_golden() {
    let stripped = golden("validate/clean.stripped.cdx.json");
    let out = validate(&["--profile", "all", "--json"], &stripped);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["file"], stripped.display().to_string());
    assert_eq!(value["rollcall-validate"], 1);
    assert_eq!(
        value["schema"],
        serde_json::json!({"checked": false, "violations": []})
    );
    let expected = read_json(&golden("validate/clean.stripped.findings.json"));
    assert_eq!(value["profile"], expected);
    // Byte-identical across runs.
    let again = validate(&["--profile", "all", "--json"], &stripped);
    assert_eq!(again.stdout, out.stdout);
}

#[test]
fn orphan_component_exit_1_names_ref() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = read_json(&golden("clean.cdx.json"));
    let root = doc["metadata"]["component"]["bom-ref"]
        .as_str()
        .unwrap()
        .to_owned();
    // An extra top-level component that nothing depends on.
    doc["components"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "firmware",
            "bom-ref": "orphan-image",
            "name": "orphan",
            "version": "1.0.0",
            "supplier": {"name": "Example Devices Ltd"},
            "purl": "pkg:generic/orphan@1.0.0",
            "hashes": [{"alg": "SHA-256", "content": "00".repeat(32)}],
        }));
    let path = write_json(dir.path(), "orphan.cdx.json", &doc);
    let out = validate(&["--profile", "cisa-2026"], &path);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    let lines = finding_lines(&stderr);
    assert_eq!(lines.len(), 1, "{stderr}");
    let line = lines[0];
    assert!(line.contains("graph.reachable"), "{line}");
    assert!(line.contains("orphan-image  orphan@1.0.0: "), "{line}");
    assert!(
        line.contains(&format!("not reachable from the root {root}")),
        "{line}"
    );
    assert!(
        line.contains("Fix: add orphan-image to the dependsOn"),
        "{line}"
    );
}

#[test]
fn schema_and_profile_compose() {
    let dir = tempfile::tempdir().unwrap();
    // Schema-invalid (specVersion 1.5) and missing a supplier: both are reported, exit 1.
    let mut doc = read_json(&golden("validate/clean.stripped.cdx.json"));
    doc["specVersion"] = "1.5".into();
    let path = write_json(dir.path(), "both.cdx.json", &doc);
    let out = validate(&["--schema", "--profile", "cra"], &path);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    let file = path.display();
    assert!(
        stderr.starts_with(&format!(
            "{file}: 1 schema violation(s)\n  /specVersion: expected \"1.6\", found \"1.5\"\n{file}: 4 error(s), 0 warning(s) against cra\n"
        )),
        "{stderr}"
    );
    // Schema-valid but failing the profile: the schema pass is on stdout, exit still 1.
    let out = validate(
        &["--schema", "--profile", "cra"],
        &golden("validate/clean.stripped.cdx.json"),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).ends_with(": valid CycloneDX 1.6\n"));
    // Both in JSON.
    let out = validate(&["--schema", "--profile", "cra", "--json"], &path);
    assert_eq!(out.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["schema"]["checked"], true);
    assert_eq!(value["schema"]["violations"][0]["path"], "/specVersion");
    assert_eq!(value["profile"]["errors"], 4);
}

#[test]
fn warnings_alone_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = read_json(&golden("clean.cdx.json"));
    // A top-level component that is neither type firmware nor marked with an image kind.
    let mcuboot = doc["components"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|c| c["name"] == "mcuboot")
        .unwrap();
    mcuboot["type"] = "library".into();
    mcuboot.as_object_mut().unwrap().remove("properties");
    let path = write_json(dir.path(), "warn.cdx.json", &doc);
    let out = validate(&["--profile", "cra"], &path);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!("{}: passes cra (12 checks, 1 warning)\n", path.display())
    );
    let stderr = text(&out.stderr);
    let lines = finding_lines(&stderr);
    assert_eq!(lines.len(), 1, "{stderr}");
    assert!(
        lines[0]
            .trim_start()
            .starts_with("warning  image.represented"),
        "{stderr}"
    );
}

#[test]
fn unknown_profile_exit_64() {
    let out = validate(&["--profile", "nist"], &golden("clean.cdx.json"));
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert_eq!(
        text(&out.stderr),
        "rollcall validate: unknown profile \"nist\": use cisa-2026, cra, all, or the path of a profile YAML file\n"
    );
}

#[test]
fn validate_without_schema_or_profile_is_usage_error_exit_64() {
    let out = validate(&["--json"], &golden("clean.cdx.json"));
    assert_eq!(out.status.code(), Some(64));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("--schema") && stderr.contains("--profile"),
        "{stderr}"
    );
}

#[test]
fn profile_path_missing_exit_66_and_malformed_exit_65() {
    let dir = tempfile::tempdir().unwrap();
    let clean = golden("clean.cdx.json");
    let missing = dir.path().join("absent.yaml");
    let out = validate(&["--profile", missing.to_str().unwrap()], &clean);
    assert_eq!(out.status.code(), Some(66));
    assert!(
        text(&out.stderr).starts_with(&format!("rollcall validate: {}: ", missing.display())),
        "{}",
        text(&out.stderr)
    );
    for (name, body) in [
        ("empty.yaml", ""),
        (
            "truncated.yaml",
            "format: rollcall-profile/1\nid: x\nchecks: [ {id: ",
        ),
        ("list.yaml", "- a\n- b\n"),
        (
            "unknown-check.yaml",
            "format: rollcall-profile/1\nid: x\ntitle: X\nsources: [{key: s, document: D}]\nchecks: [{id: nope, severity: error, cite: {source: s, clause: c}}]\n",
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        let out = validate(&["--profile", path.to_str().unwrap()], &clean);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{name}: {stderr}");
        assert!(out.stdout.is_empty(), "{name}");
        assert!(!stderr.contains("panicked"), "{name}: {stderr}");
    }
}

#[test]
fn profile_path_runs_a_custom_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("strict.yaml");
    std::fs::write(
        &path,
        "format: rollcall-profile/1\nid: strict-hash\ntitle: SHA-512 only\nsources: [{key: s, document: Internal policy}]\nchecks:\n  - id: component.hash\n    severity: warning\n    cite: {source: s, clause: \"§1\"}\n    params: {algorithms: [SHA3-512]}\n",
    )
    .unwrap();
    let clean = golden("clean.cdx.json");
    let out = validate(&["--profile", path.to_str().unwrap()], &clean);
    // The clean document has SHA-256 and SHA-512 but no SHA3-512: warnings for all 8 nodes.
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).ends_with("passes strict-hash (1 check, 8 warnings)\n"));
    assert_eq!(finding_lines(&text(&out.stderr)).len(), 8);
}

#[test]
fn json_output_is_only_stdout() {
    let out = validate(
        &["--profile", "all", "--json", "--schema"],
        &golden("clean.cdx.json"),
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["profile"]["findings"], serde_json::json!([]));
    assert_eq!(value["profile"]["checks_run"], 12);
    assert_eq!(value["schema"]["checked"], true);
    // Without --profile, "profile" is null.
    let out = validate(&["--schema", "--json"], &golden("clean.cdx.json"));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["profile"], Value::Null);
}

#[test]
fn malformed_documents_with_profile_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let golden_text = std::fs::read(golden("clean.cdx.json")).unwrap();
    for (name, bytes, code) in [
        (
            "truncated",
            golden_text[..golden_text.len() / 2].to_vec(),
            65,
        ),
        ("empty", Vec::new(), 65),
        ("invalid-utf8", vec![b'{', 0xff, b'}'], 65),
        ("null", b"null".to_vec(), 1),
        ("array", b"[]".to_vec(), 1),
        (
            "wrong types",
            br#"{"metadata":3,"components":{"a":1},"dependencies":"x"}"#.to_vec(),
            1,
        ),
    ] {
        let path = dir.path().join(format!("{}.json", name.replace(' ', "-")));
        std::fs::write(&path, bytes).unwrap();
        for json in [false, true] {
            let mut args = vec!["--profile", "all"];
            if json {
                args.push("--json");
            }
            let out = validate(&args, &path);
            let stderr = text(&out.stderr);
            assert_eq!(out.status.code(), Some(code), "{name}: {stderr}");
            assert!(!stderr.contains("panicked"), "{name}: {stderr}");
        }
    }
}

/// A pipe whose read end is already closed, so every write to it fails with EPIPE.
fn closed_pipe() -> std::process::Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

#[test]
fn validate_profile_closed_output_pipe_exits_without_panic() {
    // A pass with stdout closed: exit 74, no panic.
    for json in [false, true] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"));
        cmd.args(["validate", "--profile", "all"]);
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .arg(golden("clean.cdx.json"))
            .stdout(closed_pipe())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(74), "json={json}: {stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
    }
    // A failure with stderr closed: still exit 1.
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"))
        .args(["validate", "--profile", "all"])
        .arg(golden("validate/clean.stripped.cdx.json"))
        .stdout(std::process::Stdio::null())
        .stderr(closed_pipe())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1), "{status:?}");
}
