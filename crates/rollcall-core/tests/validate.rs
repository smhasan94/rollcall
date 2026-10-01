//! Profile validation (`rollcall validate --profile`) against the clean fixture, a stripped
//! copy of it, and the Zephyr goldens.
//!
//! `tests/golden/clean.cdx.json` is rendered from the hand-written model
//! `tests/data/clean.model.json` (see `tests/data/README.md`). The stripped document and its
//! expected findings under `tests/golden/validate/` are written only by
//! `scripts/regen-golden.sh` (`ROLLCALL_BLESS=1`), never by hand.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use rollcall_core::validate::{Profile, Report, Severity, builtin_profiles, validate_profiles};
use serde_json::Value;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn read_json(path: &std::path::Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

/// The clean document: `tests/golden/clean.cdx.json`.
fn clean_document() -> Value {
    read_json(&golden_dir().join("clean.cdx.json"))
}

/// Names of the two components the stripped document loses `supplier` and `hashes` from.
const STRIPPED: [&str; 2] = ["littlefs", "mbedtls"];

/// The clean document with `supplier` and `hashes` removed from `mbedtls` and `littlefs`.
fn stripped_document() -> Value {
    let mut doc = clean_document();
    let mut stripped = BTreeSet::new();
    let images = doc["components"].as_array_mut().unwrap();
    for image in images {
        // `get_mut`, not indexing: `image["components"]` would insert a null into images
        // without components.
        let Some(children) = image.get_mut("components").and_then(Value::as_array_mut) else {
            continue;
        };
        for c in children {
            let name = c["name"].as_str().unwrap().to_owned();
            if STRIPPED.contains(&name.as_str()) {
                let object = c.as_object_mut().unwrap();
                assert!(
                    object.remove("supplier").is_some(),
                    "{name} had no supplier"
                );
                assert!(object.remove("hashes").is_some(), "{name} had no hashes");
                stripped.insert(name);
            }
        }
    }
    assert_eq!(stripped.len(), 2, "both components found: {stripped:?}");
    // Still a schema-valid document: only the profile checks fail.
    assert_eq!(rollcall_core::validate_cyclonedx_1_6(&doc), Ok(()));
    doc
}

fn all() -> Vec<Profile> {
    builtin_profiles()
}

fn report_json(report: &Report) -> String {
    serde_json::to_string_pretty(report).unwrap() + "\n"
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join("validate").join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        common::bless(&path, actual);
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} differs; if the change is intended, run scripts/regen-golden.sh and review the \
         diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

#[test]
fn clean_fixture_passes_cisa_2026_and_cra_with_zero_warnings() {
    let doc = clean_document();
    assert_eq!(rollcall_core::validate_cyclonedx_1_6(&doc), Ok(()));
    let profiles = all();
    let ids: Vec<&str> = profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cisa-2026", "cra"]);
    for profile in &profiles {
        let report = validate_profiles(&doc, std::slice::from_ref(profile));
        assert!(
            report.findings.is_empty(),
            "{}: {:#?}",
            profile.id,
            report.findings
        );
        assert_eq!((report.errors, report.warnings), (0, 0));
        assert!(report.passed());
        assert_eq!(report.checks_run, profile.checks.len());
    }
    let report = validate_profiles(&doc, &profiles);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    assert!(report.passed());
    // Every check in the catalogue ran against it (cra uses all of them).
    let ran: BTreeSet<&str> = profiles
        .iter()
        .flat_map(|p| p.checks.iter().map(|c| c.id.as_str()))
        .collect();
    let catalogue: BTreeSet<&str> = rollcall_core::validate::CHECKS
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(ran, catalogue);
}

#[test]
fn stripped_fixture_matches_golden_failure_list() {
    let doc = stripped_document();
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    check_golden("clean.stripped.cdx.json", &text);
    let report = validate_profiles(&doc, &all());
    check_golden("clean.stripped.findings.json", &report_json(&report));

    // What the golden holds: exactly a supplier and a hash finding for each stripped
    // component, required by both profiles, and nothing else.
    assert!(!report.passed());
    let got: Vec<(String, String)> = report
        .findings
        .iter()
        .map(|f| (f.name.clone().unwrap(), f.check.clone()))
        .collect();
    assert_eq!(
        got,
        [
            ("littlefs".to_owned(), "component.supplier".to_owned()),
            ("littlefs".to_owned(), "component.hash".to_owned()),
            ("mbedtls".to_owned(), "component.supplier".to_owned()),
            ("mbedtls".to_owned(), "component.hash".to_owned()),
        ]
    );
    for f in &report.findings {
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(f.profiles, ["cisa-2026", "cra"]);
        assert!(f.r#ref.as_deref().unwrap().starts_with("component:"));
        assert!(!f.fix.is_empty());
        assert_eq!(f.citations.len(), 2);
    }
}

#[test]
fn stripped_golden_document_is_the_stripped_clean_document() {
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        return;
    }
    let committed = read_json(&golden_dir().join("validate/clean.stripped.cdx.json"));
    assert_eq!(committed, stripped_document());
    let findings = read_json(&golden_dir().join("validate/clean.stripped.findings.json"));
    let report = validate_profiles(&committed, &all());
    assert_eq!(findings, serde_json::to_value(&report).unwrap());
}

#[test]
fn stripped_findings_are_deterministic() {
    let doc = stripped_document();
    let first = report_json(&validate_profiles(&doc, &all()));
    for _ in 0..5 {
        assert_eq!(report_json(&validate_profiles(&doc, &all())), first);
    }
    // Profile order changes only the profile list, not which findings there are.
    let mut reversed = all();
    reversed.reverse();
    let other = validate_profiles(&doc, &reversed);
    assert_eq!(other.findings.len(), 4);
    assert_eq!(other.profiles, ["cra", "cisa-2026"]);
}

#[test]
fn orphan_component_is_reported_with_ref_and_fix() {
    let mut doc = clean_document();
    let mcuboot = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "mcuboot")
        .and_then(|c| c["bom-ref"].as_str())
        .unwrap()
        .to_owned();
    let root = doc["metadata"]["component"]["bom-ref"]
        .as_str()
        .unwrap()
        .to_owned();
    for dep in doc["dependencies"].as_array_mut().unwrap() {
        if dep["ref"] == root.as_str() {
            dep["dependsOn"]
                .as_array_mut()
                .unwrap()
                .retain(|t| t != mcuboot.as_str());
        }
    }
    let report = validate_profiles(&doc, &all());
    let reachable: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.check == "graph.reachable")
        .collect();
    assert_eq!(reachable.len(), 1, "{:#?}", report.findings);
    let orphan = reachable[0];
    assert_eq!(orphan.r#ref.as_deref(), Some(mcuboot.as_str()));
    assert_eq!(orphan.name.as_deref(), Some("mcuboot"));
    assert!(orphan.message.contains(&root), "{}", orphan.message);
    assert!(orphan.fix.contains(&mcuboot), "{}", orphan.fix);
    assert_eq!(orphan.profiles, ["cisa-2026", "cra"]);
    // The CRA's top-level completeness check reports the same image.
    let top: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.check == "graph.top-level-complete")
        .map(|f| f.r#ref.as_deref().unwrap())
        .collect();
    assert_eq!(top, [mcuboot.as_str()]);
    assert_eq!(report.findings.len(), 2);
}

/// rollcall's own Zephyr output fails exactly the per-component field checks today (no hashes
/// on sources or images, images without version, supplier or identifier) and passes every
/// document and graph check. The gap is tracked as
/// <https://github.com/smhasan94/rollcall/issues/14>; tighten or delete this test when it is
/// closed.
#[test]
fn zephyr_goldens_fail_only_component_fields_until_issue_14() {
    let dir = golden_dir().join("zephyr");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".cdx.json"))
        .collect();
    names.sort();
    assert!(names.len() >= 7, "{names:?}");
    let expected: BTreeSet<&str> = [
        "component.hash",
        "component.identifier",
        "component.supplier",
        "component.version",
    ]
    .into();
    for name in names {
        let report = validate_profiles(&read_json(&dir.join(&name)), &all());
        let failing: BTreeSet<&str> = report.findings.iter().map(|f| f.check.as_str()).collect();
        assert_eq!(failing, expected, "{name}");
        assert_eq!(report.warnings, 0, "{name}");
    }
}

/// CycloneDX 1.6 `dependencies` may name `services[]` (at any depth). A service named by the
/// root's dependencies is a valid target, need not be reachable itself, and its own edges
/// count; a ref naming nothing still fails.
#[test]
fn services_as_dependency_targets_pass_and_dangling_refs_still_fail() {
    let mut doc = clean_document();
    let root = doc["metadata"]["component"]["bom-ref"]
        .as_str()
        .unwrap()
        .to_owned();
    doc["services"] = serde_json::json!([{
        "bom-ref": "service:ota",
        "name": "ota-backend",
        "services": [{"bom-ref": "service:ota-auth", "name": "ota-auth"}]
    }, {"bom-ref": "service:unused", "name": "telemetry"}]);
    let deps = doc["dependencies"].as_array_mut().unwrap();
    for dep in deps.iter_mut() {
        if dep["ref"] == root.as_str() {
            dep["dependsOn"]
                .as_array_mut()
                .unwrap()
                .push("service:ota".into());
        }
    }
    deps.push(serde_json::json!({"ref": "service:ota", "dependsOn": ["service:ota-auth"]}));
    assert_eq!(rollcall_core::validate_cyclonedx_1_6(&doc), Ok(()));
    let report = validate_profiles(&doc, &all());
    assert!(report.findings.is_empty(), "{:#?}", report.findings);

    // A dangling ref next to the services still fails graph.refs-resolve.
    doc["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"ref": "service:ota-auth", "dependsOn": ["service:ghost"]}));
    let report = validate_profiles(&doc, &all());
    let failing: Vec<(&str, &str)> = report
        .findings
        .iter()
        .map(|f| (f.check.as_str(), f.path.as_str()))
        .collect();
    let last = doc["dependencies"].as_array().unwrap().len() - 1;
    assert_eq!(
        failing,
        [(
            "graph.refs-resolve",
            format!("/dependencies/{last}/dependsOn/0").as_str()
        )]
    );
    assert!(report.findings[0].message.contains("service:ghost"));
}

#[test]
fn malformed_documents_never_panic() {
    let text = std::fs::read_to_string(golden_dir().join("clean.cdx.json")).unwrap();
    let doc = clean_document();
    for value in [
        Value::Null,
        Value::Array(Vec::new()),
        serde_json::json!({"components": "x", "dependencies": [1, {"ref": 2}]}),
        doc["components"].clone(),
        doc["metadata"].clone(),
    ] {
        let report = validate_profiles(&value, &all());
        assert!(!report.passed());
    }
    for cut in (1..text.len()).step_by(97) {
        if let Ok(v) = serde_json::from_str::<Value>(text.get(..cut).unwrap_or("")) {
            let _ = validate_profiles(&v, &all());
        }
    }
}
