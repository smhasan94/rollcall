//! End-to-end tests for `rollcall vex` on the captured scanner output in
//! `crates/rollcall-core/tests/data/findings/` (from `scripts/capture-findings.sh`), the
//! hand-written rules and old-mbedTLS model in `crates/rollcall-core/tests/data/`, and the
//! real Kconfig of `fixtures/zephyr/tls/http_server`.
//!
//! The expected report `crates/rollcall-core/tests/golden/vex/old-mbedtls.vex.json` is
//! generated only by `scripts/regen-golden.sh`. Outputs go to temporary directories;
//! `fixtures/` is never modified.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core")
        .join(path)
}

fn data(path: &str) -> String {
    core("tests/data").join(path).display().to_string()
}

/// The TLS build directory.
fn tls_build() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr/tls/http_server")
}

fn tls_config() -> String {
    tls_build().join("zephyr/.config").display().to_string()
}

fn golden() -> String {
    let path = core("tests/golden/vex/old-mbedtls.vex.json");
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    })
}

/// `rollcall vex` on the old-mbedTLS inputs, with `input` naming the product and the TLS
/// build's `.config` given by its absolute path.
fn vex_old_mbedtls(input: &[&str], rules: &str) -> Command {
    let mut cmd = rollcall();
    cmd.arg("vex")
        .args(input)
        .args(["--kconfig", &tls_config()])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .args(["--rules", &data(rules)]);
    cmd
}

#[test]
fn vex_old_mbedtls_matches_golden() {
    let model = data("old-mbedtls.model.json");
    let output = vex_old_mbedtls(&["--model", &model], "vex/old-mbedtls.rules.yml")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout == golden(), "stdout differs from the golden report");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "rollcall vex: warning: 1 of 23 finding(s) unresolved; see `unresolved` in the report \
         for a rule template for each\n"
    );
}

#[test]
fn vex_from_generated_sbom_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = dir.path().join("old-mbedtls.cdx.json");
    rollcall()
        .args(["generate", "--model", &data("old-mbedtls.model.json")])
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&sbom)
        .assert()
        .code(0);
    let report = dir.path().join("report.json");
    let sbom = sbom.display().to_string();
    vex_old_mbedtls(&["--sbom", &sbom], "vex/old-mbedtls.rules.yml")
        .arg("-o")
        .arg(&report)
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
    assert!(std::fs::read_to_string(&report).unwrap() == golden());
}

#[test]
fn warning_names_both_rules_on_stderr() {
    let model = data("old-mbedtls.model.json");
    let output = vex_old_mbedtls(&["--model", &model], "vex/conflict.rules.yml")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    let line = stderr
        .lines()
        .find(|l| l.contains("conflicting rules"))
        .unwrap_or_else(|| panic!("no conflict warning in {stderr}"));
    assert!(
        line.starts_with(
            "rollcall vex: warning: CVE-2022-35409 on mbedtls@2.28.0 (component:9404b57b22a8bf72df5b6d6c93f4defd): "
        ),
        "{line}"
    );
    assert!(line.contains("`dtls-says-affected` (affected)"), "{line}");
    assert!(
        line.contains("`dtls-says-not-affected` (not_affected, code_not_present)"),
        "{line}"
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let conflict = report["unresolved"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["vulnerability"] == "CVE-2022-35409")
        .unwrap();
    assert_eq!(conflict["reason"]["kind"], "conflict");
    assert!(
        conflict["template"]
            .as_str()
            .unwrap()
            .contains("CVE-2022-35409")
    );
    assert_eq!(report["warnings"].as_array().unwrap().len(), 1);
}

#[test]
fn unresolved_findings_are_listed_with_a_template() {
    let output = rollcall()
        .arg("vex")
        .args(["--model", &data("old-heapless.model.json")])
        .args(["--findings", &data("findings/old-heapless.osv.json")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let unresolved = report["unresolved"].as_array().unwrap();
    assert!(!unresolved.is_empty());
    for u in unresolved {
        assert_eq!(u["reason"]["kind"], "no_rule");
        let template = u["template"].as_str().unwrap();
        assert!(template.contains("pkg:cargo/heapless@0.5.0"), "{template}");
        assert!(
            template.contains("status: under_investigation"),
            "{template}"
        );
    }
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unresolved")
    );
}

#[test]
fn malformed_rules_exit_65_with_line() {
    let rules = data("vex/bad-status.rules.yml");
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .args(["--rules", &rules])
        .assert()
        .code(65)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(format!(
            "rollcall vex: {rules}:7:"
        )))
        .stderr(predicate::str::contains("unknown variant `probably_fine`"));
}

#[test]
fn malformed_findings_exit_65_and_missing_files_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let truncated = dir.path().join("truncated.json");
    std::fs::write(&truncated, "{\"matches\": [").unwrap();
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .arg("--findings")
        .arg(&truncated)
        .assert()
        .code(65)
        .stderr(predicate::str::contains("invalid JSON"));
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .arg("--findings")
        .arg(dir.path().join("missing.json"))
        .assert()
        .code(66);
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .arg("--kconfig")
        .arg(&truncated)
        .assert()
        .code(65);
}

#[test]
fn unwritable_output_exits_74() {
    let dir = tempfile::tempdir().unwrap();
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .arg("-o")
        .arg(dir.path().join("no/such/dir/report.json"))
        .assert()
        .code(74);
}

#[test]
fn kconfig_path_does_not_leak_into_report() {
    let model = data("old-mbedtls.model.json");
    let run = |dir: &std::path::Path, kconfig: &str| {
        let output = rollcall()
            .current_dir(dir)
            .arg("vex")
            .args(["--model", &model, "--kconfig", kconfig])
            .args(["--findings", &data("findings/old-mbedtls.grype.json")])
            .args(["--rules", &data("vex/old-mbedtls.rules.yml")])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        output.stdout
    };
    let absolute = run(&std::env::temp_dir(), &tls_config());
    let relative = run(&tls_build(), "zephyr/.config");
    let named = run(&tls_build(), "old-tls-app=zephyr/.config");
    assert!(absolute == relative && relative == named);
    let text = String::from_utf8(absolute).unwrap();
    assert!(
        text.contains(
            "\"old-tls-app/zephyr/.config:403: CONFIG_MBEDTLS_SSL_PROTO_DTLS is not set\""
        )
    );
    assert!(!text.contains(&tls_build().display().to_string()));
    assert!(text == golden());
}

fn sysbuild_model() -> String {
    core("tests/golden/zephyr/baseline.sysbuild.model.json")
        .display()
        .to_string()
}

fn baseline_config(image: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zephyr/baseline")
        .join(image)
        .join("zephyr/.config")
        .display()
        .to_string()
}

#[test]
fn unqualified_kconfig_on_multi_image_product_exits_64() {
    rollcall()
        .arg("vex")
        .args(["--model", &sysbuild_model()])
        .args(["--kconfig", &baseline_config("with_mcuboot")])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "the product has 2 images (mcuboot, with_mcuboot)",
        ))
        .stderr(predicate::str::contains("--kconfig IMAGE="));
}

#[test]
fn kconfig_for_unknown_or_repeated_image_exits_64() {
    rollcall()
        .arg("vex")
        .args(["--model", &sysbuild_model()])
        .args(["--kconfig", &format!("nope={}", baseline_config("mcuboot"))])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("no image \"nope\""));
    rollcall()
        .arg("vex")
        .args(["--model", &sysbuild_model()])
        .args([
            "--kconfig",
            &format!("mcuboot={}", baseline_config("mcuboot")),
        ])
        .args([
            "--kconfig",
            &format!("mcuboot={}", baseline_config("with_mcuboot")),
        ])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("more than once"));
}

#[test]
fn sysbuild_kconfig_is_scoped_to_each_image() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules.yml");
    std::fs::write(
        &rules,
        "version: 1\nrules:\n  - id: mbedtls-off\n    match: {name: mbedtls}\n    when: [{kconfig_off: CONFIG_MBEDTLS}]\n    status: not_affected\n    justification: code_not_present\n",
    )
    .unwrap();
    let findings = dir.path().join("grype.json");
    std::fs::write(
        &findings,
        r#"{"descriptor": {"name": "grype"}, "matches": [{"vulnerability": {"id": "CVE-2099-0001"}, "artifact": {"name": "mbedtls", "purl": "pkg:github/mbed-tls/mbedtls@v4.1.0"}}]}"#,
    )
    .unwrap();
    let run = |kconfigs: &[String]| -> Value {
        let mut cmd = rollcall();
        cmd.arg("vex").args(["--model", &sysbuild_model()]);
        for k in kconfigs {
            cmd.args(["--kconfig", k]);
        }
        let output = cmd
            .arg("--findings")
            .arg(&findings)
            .arg("--rules")
            .arg(&rules)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        serde_json::from_slice(&output.stdout).unwrap()
    };
    let both = run(&[
        format!("mcuboot={}", baseline_config("mcuboot")),
        format!("with_mcuboot={}", baseline_config("with_mcuboot")),
    ]);
    let statements = both["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 1, "{both}");
    assert_eq!(
        statements[0]["evidence"][0],
        "with_mcuboot/zephyr/.config:262: CONFIG_MBEDTLS is not set"
    );
    // MCUboot's mbedtls (CONFIG_MBEDTLS=y) is not claimed not_affected.
    assert_eq!(both["unresolved"][0]["reason"]["kind"], "no_rule");

    let app_only = run(&[format!("with_mcuboot={}", baseline_config("with_mcuboot"))]);
    assert_eq!(app_only["statements"].as_array().unwrap().len(), 1);
    assert_eq!(
        app_only["unresolved"][0]["reason"]["kind"],
        "needs_evidence"
    );
}

/// Renames every `bom-ref` in a CycloneDX document (and the references to it) to
/// `foreign-<n>`, as another tool might have written them.
fn reref(document: &mut Value) -> std::collections::BTreeMap<String, String> {
    fn collect(v: &Value, out: &mut std::collections::BTreeMap<String, String>) {
        match v {
            Value::Object(map) => {
                if let Some(Value::String(r)) = map.get("bom-ref") {
                    let n = out.len();
                    out.entry(r.clone())
                        .or_insert_with(|| format!("foreign-{n}"));
                }
                map.values().for_each(|c| collect(c, out));
            }
            Value::Array(items) => items.iter().for_each(|c| collect(c, out)),
            _ => {}
        }
    }
    fn rewrite(v: &mut Value, map: &std::collections::BTreeMap<String, String>) {
        match v {
            Value::String(s) => {
                if let Some(new) = map.get(s.as_str()) {
                    *s = new.clone();
                }
            }
            Value::Object(m) => m.values_mut().for_each(|c| rewrite(c, map)),
            Value::Array(items) => items.iter_mut().for_each(|c| rewrite(c, map)),
            _ => {}
        }
    }
    let mut map = std::collections::BTreeMap::new();
    collect(document, &mut map);
    rewrite(document, &map);
    map
}

#[test]
fn sbom_statements_cite_the_documents_own_bom_refs() {
    let dir = tempfile::tempdir().unwrap();
    let generated = dir.path().join("generated.cdx.json");
    rollcall()
        .args(["generate", "--model", &data("old-mbedtls.model.json")])
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&generated)
        .assert()
        .code(0);
    let mut document: Value =
        serde_json::from_str(&std::fs::read_to_string(&generated).unwrap()).unwrap();
    let renamed = reref(&mut document);
    let foreign = dir.path().join("foreign.cdx.json");
    std::fs::write(&foreign, serde_json::to_string_pretty(&document).unwrap()).unwrap();

    let output = vex_old_mbedtls(
        &["--sbom", &foreign.display().to_string()],
        "vex/old-mbedtls.rules.yml",
    )
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let golden: Value = serde_json::from_str(&golden()).unwrap();
    let derived = golden["statements"][0]["component"]["bom-ref"]
        .as_str()
        .unwrap();
    let expected = &renamed[derived];
    assert!(expected.starts_with("foreign-"));
    for entry in report["statements"]
        .as_array()
        .unwrap()
        .iter()
        .chain(report["unresolved"].as_array().unwrap())
    {
        assert_eq!(&entry["component"]["bom-ref"], expected, "{entry}");
    }
    // Apart from the refs (and the templates, whose ids hash the ref), the outcomes are
    // the golden ones.
    let outcomes = |r: &Value| -> Vec<(Value, Value, Value)> {
        r["statements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["vulnerability"].clone(),
                    s["status"].clone(),
                    s["rules"].clone(),
                )
            })
            .collect()
    };
    assert_eq!(outcomes(&report), outcomes(&golden));
    assert_eq!(
        report["unresolved"].as_array().unwrap().len(),
        golden["unresolved"].as_array().unwrap().len()
    );
}

// ---------------------------------------------------------------------------------------
// --format cyclonedx|openvex and --embed (SHA-113). Expected documents are the goldens
// `crates/rollcall-core/tests/golden/vex/old-mbedtls.{openvex,vex.cdx,embed.cdx}.json`,
// generated only by scripts/regen-golden.sh.

fn vex_golden(name: &str) -> String {
    let path = core("tests/golden/vex").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    })
}

/// Generates the old-mbedTLS SBOM into `dir`, returning its path.
fn generate_sbom(dir: &std::path::Path) -> PathBuf {
    let sbom = dir.join("old-mbedtls.cdx.json");
    rollcall()
        .args(["generate", "--model", &data("old-mbedtls.model.json")])
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&sbom)
        .assert()
        .code(0);
    sbom
}

fn vex_document(sbom: &std::path::Path, format: &str) -> Command {
    let sbom = sbom.display().to_string();
    let mut cmd = vex_old_mbedtls(&["--sbom", &sbom], "vex/old-mbedtls.rules.yml");
    cmd.args(["--format", format]);
    cmd
}

#[test]
fn vex_openvex_output_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let output = vex_document(&sbom, "openvex")
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(String::from_utf8(output.stdout).unwrap() == vex_golden("old-mbedtls.openvex.json"));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "rollcall vex: warning: 1 of 23 finding(s) unresolved and not in the VEX document; run \
         with --format rollcall for a rule template for each\n\
         rollcall vex: warning: OpenVEX author: no --author and no supplier on the SBOM's \
         product, so the document's author is \"rollcall\"; name the party responsible for \
         these statements with --author\n"
    );
}

#[test]
fn vex_cyclonedx_output_passes_rollcall_validate_schema() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let out = dir.path().join("old-mbedtls.vex.cdx.json");
    vex_document(&sbom, "cyclonedx")
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
    assert!(std::fs::read_to_string(&out).unwrap() == vex_golden("old-mbedtls.vex.cdx.json"));
    rollcall()
        .args(["validate", "--schema"])
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("valid CycloneDX 1.6"));
}

#[test]
fn vex_embed_output_matches_golden_and_validates() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let before = std::fs::read(&sbom).unwrap();
    let out = dir.path().join("embedded.cdx.json");
    vex_document(&sbom, "cyclonedx")
        .arg("--embed")
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    assert!(std::fs::read_to_string(&out).unwrap() == vex_golden("old-mbedtls.embed.cdx.json"));
    assert_eq!(
        std::fs::read(&sbom).unwrap(),
        before,
        "the input SBOM was modified"
    );
    rollcall()
        .args(["validate", "--schema"])
        .arg(&out)
        .assert()
        .code(0);
}

#[test]
fn vex_default_leaves_sbom_file_untouched_and_output_has_no_components() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let before = std::fs::read(&sbom).unwrap();
    for format in ["cyclonedx", "openvex", "rollcall"] {
        let output = vex_document(&sbom, format).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{format}: {output:?}");
        let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(doc.get("components").is_none(), "{format}");
        assert_eq!(
            std::fs::read(&sbom).unwrap(),
            before,
            "{format} modified the SBOM"
        );
    }
    let sbom_doc: Value = serde_json::from_slice(&before).unwrap();
    assert!(sbom_doc.get("vulnerabilities").is_none());
}

#[test]
fn vex_openvex_from_model_uses_purls() {
    let model = data("old-mbedtls.model.json");
    let output = vex_old_mbedtls(&["--model", &model], "vex/old-mbedtls.rules.yml")
        .args(["--format", "openvex", "--timestamp", GOLDEN_TIMESTAMP])
        .args(["--author", "Example Devices Ltd"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(doc["author"], "Example Devices Ltd");
    assert_eq!(doc["timestamp"], GOLDEN_TIMESTAMP);
    for s in doc["statements"].as_array().unwrap() {
        assert_eq!(
            s["products"][0]["@id"],
            "pkg:github/mbed-tls/mbedtls@v2.28.0"
        );
    }
}

#[test]
fn vex_id_override_is_used_by_both_formats() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let id = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79";
    let mut derived = Vec::new();
    for (format, key) in [("openvex", "@id"), ("cyclonedx", "serialNumber")] {
        let output = vex_document(&sbom, format)
            .args(["--id", id])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(doc[key], id, "{format}");
        // Without --id each format derives its own id.
        let output = vex_document(&sbom, format).output().unwrap();
        let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
        derived.push(doc[key].as_str().unwrap().to_owned());
    }
    assert_ne!(
        derived[0], derived[1],
        "OpenVEX and CycloneDX VEX share a derived id"
    );
    vex_document(&sbom, "openvex")
        .args(["--id", "urn:uuid:NOT-A-UUID"])
        .assert()
        .code(64);
}

#[test]
fn vex_embed_requires_cyclonedx_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    for format in ["openvex", "rollcall"] {
        vex_document(&sbom, format)
            .arg("--embed")
            .assert()
            .code(64)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(
                "--embed writes CycloneDX: use it with --format cyclonedx",
            ));
    }
    // --embed needs an SBOM to embed into.
    let model = data("old-mbedtls.model.json");
    vex_old_mbedtls(&["--model", &model], "vex/old-mbedtls.rules.yml")
        .args(["--format", "cyclonedx", "--embed"])
        .assert()
        .code(64);
}

#[test]
fn vex_flag_combinations_are_usage_errors_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let model = data("old-mbedtls.model.json");
    vex_old_mbedtls(&["--model", &model], "vex/old-mbedtls.rules.yml")
        .args(["--format", "cyclonedx"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("--format cyclonedx needs --sbom"));
    vex_document(&sbom, "rollcall")
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .assert()
        .code(64)
        .stderr(predicate::str::contains(
            "--timestamp and --id apply to a VEX document",
        ));
    vex_document(&sbom, "cyclonedx")
        .args(["--embed", "--timestamp", GOLDEN_TIMESTAMP])
        .assert()
        .code(64);
    vex_document(&sbom, "cyclonedx")
        .args(["--author", "x"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains(
            "--author applies to --format openvex",
        ));
    vex_document(&sbom, "spdx").assert().code(64);
}

#[test]
fn vex_missing_input_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    vex_document(&dir.path().join("missing.cdx.json"), "cyclonedx")
        .assert()
        .code(66)
        .stdout(predicate::str::is_empty());
}

/// `text` with its serialNumber's UUID in upper case (the schema requires lower case).
fn uppercase_serial(text: &str) -> String {
    let doc: Value = serde_json::from_str(text).unwrap();
    let serial = doc["serialNumber"].as_str().unwrap();
    let upper = format!(
        "urn:uuid:{}",
        serial.trim_start_matches("urn:uuid:").to_uppercase()
    );
    assert_ne!(upper, serial);
    text.replacen(serial, &upper, 1)
}

#[test]
fn vex_embed_increments_the_sbom_version() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let out = dir.path().join("embedded.cdx.json");
    vex_document(&sbom, "cyclonedx")
        .arg("--embed")
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    let before: Value = serde_json::from_slice(&std::fs::read(&sbom).unwrap()).unwrap();
    let after: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(before["version"], 1);
    assert_eq!(after["version"], 2);
    assert_eq!(after["serialNumber"], before["serialNumber"]);
}

#[test]
fn vex_bom_link_inputs_version_0_and_uppercase_uuid_exit_65() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let text = std::fs::read_to_string(&sbom).unwrap();
    for (name, bytes, needle) in [
        (
            "version-0",
            text.replacen("\"version\": 1,", "\"version\": 0,", 1),
            "version 0 is not an integer of at least 1",
        ),
        (
            "uppercase-uuid",
            uppercase_serial(&text),
            "is not a lowercase urn:uuid:",
        ),
    ] {
        let path = dir.path().join(format!("{name}.cdx.json"));
        std::fs::write(&path, bytes).unwrap();
        for format in ["cyclonedx", "openvex"] {
            let output = vex_document(&path, format).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(65),
                "{name} {format}: {output:?}"
            );
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(needle), "{name} {format}: {stderr}");
        }
    }
}

#[test]
fn vex_malformed_inputs_exit_65_no_panic() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = generate_sbom(dir.path());
    let text = std::fs::read_to_string(&sbom).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("truncated", text.as_bytes()[..text.len() / 2].to_vec()),
        ("not-utf8", b"\xff\xfe{}".to_vec()),
        ("wrong-type", b"[\"CycloneDX\"]".to_vec()),
        (
            "no-serial",
            text.replacen("\"serialNumber\"", "\"x-serialNumber\"", 1)
                .into_bytes(),
        ),
        (
            "version-0",
            text.replacen("\"version\": 1,", "\"version\": 0,", 1)
                .into_bytes(),
        ),
        ("uppercase-uuid", uppercase_serial(&text).into_bytes()),
    ];
    for (name, bytes) in cases {
        let path = dir.path().join(format!("{name}.cdx.json"));
        std::fs::write(&path, bytes).unwrap();
        let output = vex_document(&path, "cyclonedx").output().unwrap();
        assert_eq!(output.status.code(), Some(65), "{name}: {output:?}");
        assert!(output.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("panicked"), "{name}: {stderr}");
        assert!(stderr.starts_with("rollcall vex: "), "{name}: {stderr}");
    }
    // An SBOM that already carries vulnerabilities is not embedded into twice.
    let embedded = dir.path().join("embedded.cdx.json");
    vex_document(&sbom, "cyclonedx")
        .arg("--embed")
        .arg("-o")
        .arg(&embedded)
        .assert()
        .code(0);
    vex_document(&embedded, "cyclonedx")
        .arg("--embed")
        .assert()
        .code(65)
        .stderr(predicate::str::contains(
            "already has a `vulnerabilities` array",
        ));
}

#[test]
fn vex_unresolved_findings_are_warned() {
    let output = rollcall()
        .arg("vex")
        .args(["--model", &data("old-heapless.model.json")])
        .args(["--findings", &data("findings/old-heapless.osv.json")])
        .args(["--format", "openvex", "--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let doc: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(doc["statements"].as_array().unwrap().is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unresolved and not in the VEX document"),
        "{stderr}"
    );
}
