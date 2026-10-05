//! End-to-end tests for `rollcall csaf` (SHA-132). The expected output is the rollcall-core
//! golden `crates/rollcall-core/tests/golden/csaf/old-mbedtls.csaf.json`, written only by
//! `scripts/regen-golden.sh`.
//!
//! The fixtures are the three inputs with captured scanner findings (see
//! `crates/rollcall-core/tests/csaf.rs`): the `old-mbedtls` and `old-heapless` model SBOMs
//! and the real Zephyr old-mbedTLS build's SBOM golden.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

const TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const PUBLISHER: [&str; 4] = [
    "--publisher",
    "Example Devices Ltd",
    "--publisher-namespace",
    "https://devices.example",
];

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

/// `rollcall generate --model tests/data/<model>.model.json` into `dir/<model>.cdx.json`.
fn model_sbom(dir: &Path, model: &str) -> PathBuf {
    let out = dir.join(format!("{model}.cdx.json"));
    rollcall()
        .args(["generate", "--timestamp", TIMESTAMP, "--model"])
        .arg(core_dir().join(format!("data/{model}.model.json")))
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    out
}

/// A fixture's SBOM, `--scan` files and `--vex` files.
fn fixture(dir: &Path, name: &str) -> (PathBuf, Vec<PathBuf>, Vec<PathBuf>) {
    let findings = core_dir().join("data/findings");
    match name {
        "old-mbedtls" => (
            model_sbom(dir, "old-mbedtls"),
            vec![
                findings.join("old-mbedtls.grype.json"),
                findings.join("old-mbedtls.osv.json"),
            ],
            vec![core_dir().join("golden/vex/old-mbedtls.openvex.json")],
        ),
        "old-heapless" => (
            model_sbom(dir, "old-heapless"),
            vec![
                findings.join("old-heapless.grype.json"),
                findings.join("old-heapless.osv.json"),
            ],
            Vec::new(),
        ),
        "zephyr-old-mbedtls" => (
            core_dir().join("golden/zephyr/old-mbedtls.cdx.json"),
            vec![findings.join("zephyr-old-mbedtls.grype.json")],
            Vec::new(),
        ),
        other => panic!("no fixture {other}"),
    }
}

const FIXTURES: [&str; 3] = ["old-mbedtls", "old-heapless", "zephyr-old-mbedtls"];

fn csaf_cmd(sbom: &Path, scans: &[PathBuf], vex: &[PathBuf]) -> Command {
    let mut cmd = rollcall();
    cmd.arg("csaf").arg(sbom);
    for s in scans {
        cmd.arg("--scan").arg(s);
    }
    for v in vex {
        cmd.arg("--vex").arg(v);
    }
    cmd.args(["--timestamp", TIMESTAMP]).args(PUBLISHER);
    cmd
}

fn run_fixture(dir: &Path, name: &str) -> std::process::Output {
    let (sbom, scans, vex) = fixture(dir, name);
    csaf_cmd(&sbom, &scans, &vex).output().unwrap()
}

/// TP3: `rollcall csaf` on the old-mbedTLS fixture writes the golden byte for byte, to
/// stdout and with `-o`.
#[test]
fn csaf_output_matches_golden() {
    let dir = tempfile::tempdir().unwrap();
    let golden_path = core_dir().join("golden/csaf/old-mbedtls.csaf.json");
    let golden = std::fs::read_to_string(&golden_path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            golden_path.display()
        )
    });
    let out = run_fixture(dir.path(), "old-mbedtls");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8(out.stdout).unwrap(), golden);

    let (sbom, scans, vex) = fixture(dir.path(), "old-mbedtls");
    let path = dir.path().join("out.csaf.json");
    csaf_cmd(&sbom, &scans, &vex)
        .arg("-o")
        .arg(&path)
        .assert()
        .code(0)
        .stdout("");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), golden);
}

/// TP1 (end to end): every fixture's `rollcall csaf` output passes `rollcall validate
/// --schema`, which detects CSAF by content and checks the CSAF 2.0 schema and the
/// mandatory tests.
#[test]
fn csaf_output_validates_for_every_fixture() {
    let dir = tempfile::tempdir().unwrap();
    for name in FIXTURES {
        let out = run_fixture(dir.path(), name);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let path = dir.path().join(format!("{name}.csaf.json"));
        std::fs::write(&path, &out.stdout).unwrap();
        let validated = rollcall()
            .args(["validate", "--schema"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(
            validated.status.code(),
            Some(0),
            "{name}: {}",
            String::from_utf8_lossy(&validated.stderr)
        );
        assert_eq!(
            String::from_utf8(validated.stdout).unwrap(),
            format!("{}: valid CSAF 2.0\n", path.display())
        );
    }
}

/// AC3: every product the CSAF tree names is one of the SBOM's own bom-refs with its purl
/// and CPE unchanged; every relationship is a named component as part of the SBOM's product,
/// with id `<component bom-ref>@<product bom-ref>`; and every status, flag, threat and
/// remediation names such a relationship product (or the product itself), never a bare
/// component.
#[test]
fn csaf_product_ids_are_the_sbom_bom_refs() {
    let dir = tempfile::tempdir().unwrap();
    for name in FIXTURES {
        let (sbom_path, _, _) = fixture(dir.path(), name);
        let sbom: Value = serde_json::from_slice(&std::fs::read(&sbom_path).unwrap()).unwrap();
        let out = run_fixture(dir.path(), name);
        assert_eq!(out.status.code(), Some(0), "{name}");
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();

        type Ids = BTreeMap<String, (Option<String>, Option<String>)>;
        fn walk(v: &Value, out: &mut Ids) {
            if let Some(r) = v["bom-ref"].as_str() {
                let s = |k: &str| v[k].as_str().map(str::to_owned);
                out.insert(r.to_owned(), (s("purl"), s("cpe")));
            }
            for c in v["components"].as_array().into_iter().flatten() {
                walk(c, out);
            }
        }
        let mut refs = Ids::new();
        walk(&sbom["metadata"]["component"], &mut refs);
        for c in sbom["components"].as_array().into_iter().flatten() {
            walk(c, &mut refs);
        }
        let product = sbom["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            doc["product_tree"]["branches"]
                .to_string()
                .contains(&format!("\"product_id\":\"{product}\"")),
            "{name}: the product is not in the branches"
        );

        let fpns = doc["product_tree"]["full_product_names"]
            .as_array()
            .unwrap();
        assert!(!fpns.is_empty(), "{name}");
        for f in fpns {
            let id = f["product_id"].as_str().unwrap();
            let (purl, cpe) = refs
                .get(id)
                .unwrap_or_else(|| panic!("{name}: {id} is not an SBOM bom-ref"));
            let pih = &f["product_identification_helper"];
            assert_eq!(pih["purl"].as_str(), purl.as_deref(), "{name}: {id}");
            assert_eq!(pih["cpe"].as_str(), cpe.as_deref(), "{name}: {id}");
        }
        let mut relationship_ids = BTreeSet::new();
        for rel in doc["product_tree"]["relationships"].as_array().unwrap() {
            let a = rel["product_reference"].as_str().unwrap();
            let b = rel["relates_to_product_reference"].as_str().unwrap();
            assert!(fpns.iter().any(|f| f["product_id"] == a), "{name}: {rel}");
            assert_eq!(b, product, "{name}: {rel}");
            assert_eq!(rel["full_product_name"]["product_id"], format!("{a}@{b}"));
            relationship_ids.insert(format!("{a}@{b}"));
        }
        assert_eq!(relationship_ids.len(), fpns.len(), "{name}");
        let mut used = BTreeSet::new();
        for v in doc["vulnerabilities"].as_array().unwrap() {
            let mut ids: Vec<&Value> = Vec::new();
            for list in v["product_status"].as_object().unwrap().values() {
                ids.extend(list.as_array().unwrap());
            }
            for key in ["flags", "threats", "remediations"] {
                for item in v[key].as_array().into_iter().flatten() {
                    ids.extend(item["product_ids"].as_array().unwrap());
                }
            }
            for id in ids {
                let id = id.as_str().unwrap();
                assert!(
                    relationship_ids.contains(id) || id == product,
                    "{name}: {id} is not a relationship product"
                );
                used.insert(id.to_owned());
            }
        }
        // Every relationship product is used (no unused product ids).
        assert!(relationship_ids.is_subset(&used), "{name}");
    }
}

/// Accepted choice: an export with nothing in it exits 1 and writes nothing.
#[test]
fn csaf_empty_export_exits_1_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = model_sbom(dir.path(), "minimal");
    let empty = dir.path().join("grype.json");
    std::fs::write(&empty, b"{\"matches\": []}").unwrap();
    let path = dir.path().join("out.csaf.json");
    let out = csaf_cmd(&sbom, &[empty], &[])
        .arg("-o")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nothing to export"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!path.exists());
}

#[test]
fn csaf_without_publisher_exits_64() {
    let dir = tempfile::tempdir().unwrap();
    let (sbom, scans, _) = fixture(dir.path(), "old-heapless");
    let mut cmd = rollcall();
    cmd.arg("csaf").arg(&sbom);
    for s in &scans {
        cmd.arg("--scan").arg(s);
    }
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("rollcall csaf: no publisher"));

    // A namespace that is not a URI is a usage error too.
    let out = rollcall()
        .arg("csaf")
        .arg(&sbom)
        .arg("--scan")
        .arg(&scans[0])
        .args(["--publisher", "x", "--publisher-namespace", "not a uri"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn csaf_requires_scan_and_valid_flags() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = model_sbom(dir.path(), "minimal");
    for args in [
        vec!["csaf".to_owned()],
        vec!["csaf".to_owned(), sbom.display().to_string()],
        vec![
            "csaf".to_owned(),
            sbom.display().to_string(),
            "--scan".to_owned(),
            "x.json".to_owned(),
            "--id".to_owned(),
            " padded".to_owned(),
        ],
        vec![
            "csaf".to_owned(),
            sbom.display().to_string(),
            "--scan".to_owned(),
            "x.json".to_owned(),
            "--timestamp".to_owned(),
            "yesterday".to_owned(),
        ],
        vec![
            "csaf".to_owned(),
            sbom.display().to_string(),
            "--scan".to_owned(),
            "x.json".to_owned(),
            "--tlp".to_owned(),
            "purple".to_owned(),
        ],
    ] {
        let out = rollcall().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn csaf_missing_input_exits_66() {
    let dir = tempfile::tempdir().unwrap();
    let (sbom, scans, _) = fixture(dir.path(), "old-heapless");
    let missing = dir.path().join("missing.json");
    for (s, scan, vex) in [
        (missing.clone(), scans[0].clone(), None),
        (sbom.clone(), missing.clone(), None),
        (sbom.clone(), scans[0].clone(), Some(missing.clone())),
    ] {
        let out = csaf_cmd(&s, &[scan], vex.as_slice()).output().unwrap();
        assert_eq!(out.status.code(), Some(66));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("missing.json"));
    }
}

/// Malformed inputs (empty, truncated, not UTF-8, wrong types) exit 65 with a message and
/// never panic.
#[test]
fn csaf_malformed_input_exits_65_without_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (sbom, scans, _) = fixture(dir.path(), "old-heapless");
    let bad: [&[u8]; 5] = [
        b"",
        b"{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\"",
        b"\xff\xfe\xfd",
        b"[1, 2]",
        b"{\"statements\": 5, \"@context\": \"https://openvex.dev/ns/v0.2.0\"}",
    ];
    for (i, bytes) in bad.iter().enumerate() {
        let path = dir.path().join(format!("bad{i}.json"));
        std::fs::write(&path, bytes).unwrap();
        for (s, scan, vex) in [
            (path.clone(), scans[0].clone(), None),
            (sbom.clone(), path.clone(), None),
            (sbom.clone(), scans[0].clone(), Some(path.clone())),
        ] {
            let out = csaf_cmd(&s, &[scan], vex.as_slice()).output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(65), "{i}: {stderr}");
            assert!(out.stdout.is_empty());
            assert!(stderr.starts_with("rollcall csaf: "), "{stderr}");
            assert!(!stderr.contains("panicked"), "{stderr}");
        }
    }
}

/// `--id`, `--title`, `--tlp` and `--publisher-category` reach the document; no TLP is
/// written unless asked for.
#[test]
fn csaf_options_reach_the_document() {
    let dir = tempfile::tempdir().unwrap();
    let (sbom, scans, vex) = fixture(dir.path(), "old-mbedtls");
    let out = csaf_cmd(&sbom, &scans, &vex)
        .args(["--id", "ACME-VEX-2026-001", "--title", "Custom title"])
        .args(["--tlp", "amber", "--publisher-category", "coordinator"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["document"]["tracking"]["id"], "ACME-VEX-2026-001");
    assert_eq!(doc["document"]["title"], "Custom title");
    assert_eq!(doc["document"]["distribution"]["tlp"]["label"], "AMBER");
    assert_eq!(doc["document"]["publisher"]["category"], "coordinator");

    let out = run_fixture(dir.path(), "old-mbedtls");
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(doc["document"].get("distribution").is_none());
}

/// S4: when nothing is written, the warnings still say why: they come before the error.
#[test]
fn csaf_empty_export_prints_why_before_the_error() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = model_sbom(dir.path(), "old-heapless");
    let ghost = dir.path().join("ghost.scan.json");
    std::fs::write(
        &ghost,
        br#"{"schema": "rollcall-scan/1", "scanners": [],
             "findings": [{"id": "CVE-2020-0001", "component": null,
                           "package": {"name": "ghost", "version": "1.0"},
                           "severity": "high",
                           "sources": [{"scanner": "grype", "id": "CVE-2020-0001"}]}]}"#,
    )
    .unwrap();
    let out = csaf_cmd(&sbom, &[ghost], &[]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(
        lines,
        [
            "rollcall csaf: warning: CVE-2020-0001 on ghost: the package is not in the SBOM, so \
             it has no CSAF product; left out",
            "rollcall csaf: no finding about a component of the SBOM's product, so there is \
             nothing to export",
        ],
        "{stderr}"
    );
}
