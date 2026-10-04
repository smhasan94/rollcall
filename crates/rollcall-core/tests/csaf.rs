//! `rollcall csaf`'s core: CSAF 2.0 VEX export of scan and VEX results.
//!
//! The fixtures are the three inputs with captured scanner findings
//! (`tests/data/findings/`, written only by `scripts/capture-findings.sh`):
//!
//! - `old-mbedtls`: the SBOM `rollcall generate --model tests/data/old-mbedtls.model.json
//!   --timestamp 2026-01-02T03:04:05Z` writes, the grype and osv-scanner captures, and the
//!   OpenVEX golden `tests/golden/vex/old-mbedtls.openvex.json`;
//! - `old-heapless`: the same for `old-heapless.model.json`, without VEX;
//! - `zephyr-old-mbedtls`: the real build's SBOM golden `tests/golden/zephyr/old-mbedtls.cdx.json`
//!   (from `fixtures/zephyr-old-mbedtls/`) with its grype capture, without VEX.
//!
//! The golden `tests/golden/csaf/old-mbedtls.csaf.json` is written only by
//! `scripts/regen-golden.sh` (this test with `ROLLCALL_BLESS=1`). Never edit it by hand.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use common::{GOLDEN_TIMESTAMP, bless, load_fixture};
use proptest::prelude::*;
use rollcall_core::csaf::{
    self, CsafError, CsafOptions, Export, TrackingId, read_tree, validate, validate_csaf_2_0,
};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions};
use rollcall_core::report::Input;
use rollcall_core::scan::{self, ScannerRun, ScannerStatus, Triage, parse_vex};
use rollcall_core::vex::{Scanner, parse_findings};
use serde_json::{Value, json};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    let path = manifest_dir().join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One fixture's inputs: (name, bytes) each.
struct Case {
    sbom: Vec<u8>,
    scans: Vec<(String, Vec<u8>)>,
    vex: Vec<(String, Vec<u8>)>,
}

fn named(path: &str) -> (String, Vec<u8>) {
    let name = path.rsplit('/').next().unwrap_or(path).to_owned();
    (name, read(path))
}

/// The SBOM `rollcall generate --model tests/data/<model>.model.json` writes.
fn model_sbom(model: &str) -> Vec<u8> {
    let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    cyclonedx::write(&load_fixture(model), &options)
        .unwrap()
        .into_bytes()
}

/// The three fixtures with captured findings.
const FIXTURES: [&str; 3] = ["old-mbedtls", "old-heapless", "zephyr-old-mbedtls"];

fn case(name: &str) -> Case {
    match name {
        "old-mbedtls" => Case {
            sbom: model_sbom("old-mbedtls"),
            scans: vec![
                named("tests/data/findings/old-mbedtls.grype.json"),
                named("tests/data/findings/old-mbedtls.osv.json"),
            ],
            vex: vec![named("tests/golden/vex/old-mbedtls.openvex.json")],
        },
        "old-heapless" => Case {
            sbom: model_sbom("old-heapless"),
            scans: vec![
                named("tests/data/findings/old-heapless.grype.json"),
                named("tests/data/findings/old-heapless.osv.json"),
            ],
            vex: Vec::new(),
        },
        "zephyr-old-mbedtls" => Case {
            sbom: read("tests/golden/zephyr/old-mbedtls.cdx.json"),
            scans: vec![named("tests/data/findings/zephyr-old-mbedtls.grype.json")],
            vex: Vec::new(),
        },
        other => panic!("no fixture {other}"),
    }
}

fn inputs(list: &[(String, Vec<u8>)]) -> Vec<Input<'_>> {
    list.iter()
        .map(|(name, bytes)| Input {
            name: name.as_str(),
            bytes: bytes.as_slice(),
        })
        .collect()
}

/// The options the golden and the CLI tests use.
fn options() -> CsafOptions {
    let mut options = CsafOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    options.publisher_name = Some("Example Devices Ltd".to_owned());
    options.publisher_namespace = Some("https://devices.example".to_owned());
    options
}

fn export_with(c: &Case, options: &CsafOptions) -> Result<Export, CsafError> {
    csaf::build(
        Input {
            name: "sbom.cdx.json",
            bytes: &c.sbom,
        },
        &inputs(&c.scans),
        &inputs(&c.vex),
        options,
    )
}

fn export(name: &str) -> Export {
    export_with(&case(name), &options()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn text(name: &str) -> String {
    csaf::to_json(&export(name).csaf).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn value(name: &str) -> Value {
    serde_json::from_str(&text(name)).unwrap()
}

/// Every SBOM node with a bom-ref: bom-ref → (purl, cpe), as written.
fn sbom_identifiers(sbom: &[u8]) -> BTreeMap<String, (Option<String>, Option<String>)> {
    fn walk(v: &Value, out: &mut BTreeMap<String, (Option<String>, Option<String>)>) {
        if let Some(r) = v.get("bom-ref").and_then(Value::as_str) {
            let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
            out.insert(r.to_owned(), (s("purl"), s("cpe")));
        }
        for c in v
            .get("components")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(c, out);
        }
    }
    let doc: Value = serde_json::from_slice(sbom).unwrap();
    let mut out = BTreeMap::new();
    walk(&doc["metadata"]["component"], &mut out);
    for c in doc["components"].as_array().into_iter().flatten() {
        walk(c, &mut out);
    }
    out
}

/// Every CSAF product the tree defines with a name: product_id → (purl, cpe).
fn csaf_identifiers(doc: &Value) -> BTreeMap<String, (Option<String>, Option<String>)> {
    fn pih(f: &Value) -> (Option<String>, Option<String>) {
        let s = |k: &str| {
            f["product_identification_helper"][k]
                .as_str()
                .map(str::to_owned)
        };
        (s("purl"), s("cpe"))
    }
    fn branches(items: &Value, out: &mut BTreeMap<String, (Option<String>, Option<String>)>) {
        for b in items.as_array().into_iter().flatten() {
            if let Some(id) = b["product"]["product_id"].as_str() {
                out.insert(id.to_owned(), pih(&b["product"]));
            }
            branches(&b["branches"], out);
        }
    }
    let mut out = BTreeMap::new();
    branches(&doc["product_tree"]["branches"], &mut out);
    for f in doc["product_tree"]["full_product_names"]
        .as_array()
        .into_iter()
        .flatten()
    {
        out.insert(f["product_id"].as_str().unwrap().to_owned(), pih(f));
    }
    out
}

/// The product's `product_id` (the product in the branches).
fn product_ref(doc: &Value) -> String {
    fn find(items: &Value) -> Option<String> {
        items.as_array().into_iter().flatten().find_map(|b| {
            b["product"]["product_id"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| find(&b["branches"]))
        })
    }
    find(&doc["product_tree"]["branches"]).expect("a product in the branches")
}

/// The relationship products: product_id → (component bom-ref, product bom-ref).
fn relationships(doc: &Value) -> BTreeMap<String, (String, String)> {
    doc["product_tree"]["relationships"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            (
                r["full_product_name"]["product_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                (
                    r["product_reference"].as_str().unwrap().to_owned(),
                    r["relates_to_product_reference"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
            )
        })
        .collect()
}

/// The SBOM `bom-ref` a vulnerability's product id is about: the product itself, or the
/// component of a relationship product "component as part of the product".
fn component_of(doc: &Value, product_id: &str) -> String {
    let product = product_ref(doc);
    if product_id == product {
        return product;
    }
    let (component, parent) = relationships(doc)
        .remove(product_id)
        .unwrap_or_else(|| panic!("{product_id} is neither the product nor a relationship"));
    assert_eq!(parent, product, "{product_id} is not part of the product");
    component
}

/// Every product id a vulnerability's statuses name, in the document.
fn status_ids(doc: &Value) -> BTreeSet<String> {
    doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["product_status"].as_object().unwrap().values())
        .flat_map(|l| l.as_array().unwrap().iter())
        .map(|i| i.as_str().unwrap().to_owned())
        .collect()
}

// --- AC1 / TP1: schema validation ------------------------------------------------------------

/// AC1, TP1: every fixture's CSAF validates against the vendored CSAF 2.0 schema (with the
/// CVSS schemas it references) and passes the mandatory tests rollcall checks. CI runs this
/// test on its own as the `CSAF schema` step.
#[test]
fn csaf_validates_against_schema_for_every_fixture() {
    for name in FIXTURES {
        let doc = value(name);
        assert_eq!(validate_csaf_2_0(&doc), Ok(()), "{name}");
        assert_eq!(validate(&doc), Ok(()), "{name}");
        assert_eq!(doc["document"]["category"], "csaf_vex", "{name}");
        assert!(
            !doc["vulnerabilities"].as_array().unwrap().is_empty(),
            "{name}"
        );
    }
}

/// AC1: every committed CSAF golden validates.
#[test]
fn every_committed_csaf_golden_validates_against_schema() {
    let dir = manifest_dir().join("tests/golden/csaf");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let doc: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(validate(&doc), Ok(()), "{}", path.display());
        seen += 1;
    }
    assert!(seen >= 1, "no CSAF golden in {}", dir.display());
}

/// AC1: the self-check refuses an invalid document instead of writing it: an SBOM CPE that
/// the CycloneDX reader accepts but CSAF's stricter pattern does not.
#[test]
fn to_json_refuses_a_document_that_fails_the_schema() {
    let mut c = case("old-mbedtls");
    let mut sbom: Value = serde_json::from_slice(&c.sbom).unwrap();
    let mut patched = false;
    for image in sbom["components"].as_array_mut().unwrap() {
        for comp in image["components"].as_array_mut().into_iter().flatten() {
            if comp["name"] == "mbedtls" {
                comp["cpe"] = json!("cpe:/badpart:x");
                patched = true;
            }
        }
    }
    assert!(patched);
    c.sbom = serde_json::to_vec(&sbom).unwrap();
    let export = export_with(&c, &options()).unwrap();
    match csaf::to_json(&export.csaf) {
        Err(CsafError::Invalid(violations)) => assert!(
            violations
                .iter()
                .any(|v| v.path.ends_with("product_identification_helper/cpe")),
            "{violations:?}"
        ),
        other => panic!("{other:?}"),
    }
}

// --- AC2 (rollcall's side) ------------------------------------------------------------------

/// Every finding's CSAF product status is the triage `rollcall scan` gives it on the same
/// inputs (the rollcall side of the cra-clock comparison in docs/cra-clock.md).
#[test]
fn product_status_matches_scan_triage_for_every_fixture() {
    for name in FIXTURES {
        let c = case(name);
        let doc = value(name);
        // `rollcall scan` on the same inputs.
        let sbom = scan::Sbom::from_bytes(&c.sbom).unwrap();
        let mut findings = Vec::new();
        for (_, bytes) in &c.scans {
            findings.extend(parse_findings(bytes).unwrap().findings);
        }
        let documents: Vec<_> = c
            .vex
            .iter()
            .map(|(n, b)| (n.clone(), parse_vex(b).unwrap()))
            .collect();
        let runs = vec![ScannerRun {
            scanner: Scanner::Grype,
            version: None,
            status: ScannerStatus::Ok,
            offline: false,
        }];
        let report = scan::scan(&sbom, runs, &findings, &documents, Vec::new());
        let product_ref = product_ref(&doc);
        let mut compared = 0;
        for f in &report.findings {
            let Some(bom_ref) = f.finding.bom_ref() else {
                continue;
            };
            // The status is about the component as part of the product.
            let product = if bom_ref == product_ref {
                bom_ref.to_owned()
            } else {
                csaf::product_id_of(bom_ref, &product_ref)
            };
            assert_eq!(component_of(&doc, &product), bom_ref);
            let vuln = doc["vulnerabilities"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    v["cve"] == f.finding.id.as_str()
                        || v["ids"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .any(|i| i["text"] == f.finding.id.as_str())
                })
                .unwrap_or_else(|| panic!("{name}: no vulnerability {}", f.finding.id));
            let lists: Vec<&str> = [
                "fixed",
                "known_affected",
                "known_not_affected",
                "under_investigation",
            ]
            .into_iter()
            .filter(|l| {
                vuln["product_status"][l]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|p| p == product.as_str())
            })
            .collect();
            let want = match f.triage {
                Triage::Affected => "known_affected",
                Triage::Unresolved => "under_investigation",
                Triage::Suppressed => match f.vex[0].status.as_str() {
                    "fixed" => "fixed",
                    _ => "known_not_affected",
                },
            };
            assert_eq!(lists, [want], "{name}: {} on {product}", f.finding.id);
            compared += 1;
        }
        assert!(compared > 0, "{name}");
    }
}

/// The old-mbedTLS fixture covers every status the VEX golden gives: affected (with its
/// action statement as the remediation), not affected (flag and impact statement) and under
/// investigation.
#[test]
fn old_mbedtls_maps_statuses_flags_threats_and_remediations() {
    let doc = value("old-mbedtls");
    let vuln = |cve: &str| {
        doc["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["cve"] == cve)
            .unwrap_or_else(|| panic!("no {cve}"))
            .clone()
    };
    let affected = vuln("CVE-2022-46392");
    let product = affected["product_status"]["known_affected"][0].clone();
    // The OpenVEX statement gives no response, and the scanners know an upstream fix: a
    // fixed firmware is not available yet (none_available), with the statement's action text.
    assert_eq!(
        affected["remediations"],
        json!([{"category": "none_available", "details": "Upgrade Mbed TLS to 2.28.2 or later.",
                "product_ids": [product.clone()]}])
    );
    // The product id is mbedtls as part of the firmware, not mbedtls itself.
    let product_id = product.as_str().unwrap();
    assert!(product_id.contains('@'), "{product_id}");
    let component = component_of(&doc, product_id);
    assert_eq!(
        csaf_identifiers(&doc)[&component].0.as_deref(),
        Some("pkg:github/mbed-tls/mbedtls@v2.28.0")
    );
    let not_affected = vuln("CVE-2022-35409");
    assert_eq!(
        not_affected["product_status"],
        json!({"known_not_affected": [product.clone()]})
    );
    assert_eq!(
        not_affected["flags"],
        json!([{"label": "vulnerable_code_not_present", "product_ids": [product.clone()]}])
    );
    assert_eq!(
        not_affected["threats"][0]["details"],
        "DTLS support (MBEDTLS_SSL_PROTO_DTLS) is not compiled in."
    );
    let open = vuln("CVE-2021-43666");
    assert_eq!(
        open["product_status"],
        json!({"under_investigation": [product]})
    );
    assert!(open.get("remediations").is_none());
    assert_eq!(open["notes"][0]["category"], "summary");
}

// --- AC3: identifiers round-trip ------------------------------------------------------------

/// AC3: the purl and CPE of every SBOM component a vulnerability names reach the CSAF
/// product whose `product_id` is its `bom-ref` byte for byte; every status names that
/// component as part of the SBOM's product; and every product a VEX statement names (by purl
/// in OpenVEX, by BOM-Link `bom-ref` in CycloneDX VEX) is the component with exactly that
/// purl or `bom-ref`.
#[test]
fn purl_and_cpe_round_trip_unchanged_sbom_vex_csaf() {
    for name in FIXTURES {
        let c = case(name);
        let doc = value(name);
        let sbom = sbom_identifiers(&c.sbom);
        let csaf = csaf_identifiers(&doc);
        // Every product the tree names is an SBOM node with the SBOM's own strings.
        for (id, identifiers) in &csaf {
            assert_eq!(sbom.get(id), Some(identifiers), "{name}: {id}");
        }
        // The tree names exactly the product and the components the statuses are about.
        let named: BTreeSet<String> = status_ids(&doc)
            .iter()
            .map(|id| component_of(&doc, id))
            .chain([product_ref(&doc)])
            .collect();
        assert_eq!(
            csaf.keys().cloned().collect::<BTreeSet<_>>(),
            named,
            "{name}"
        );
        // And those are the components the scan's findings are about.
        let export = export(name);
        let found: BTreeSet<String> = export
            .findings
            .iter()
            .filter_map(|f| f.finding.bom_ref().map(str::to_owned))
            .chain([product_ref(&doc)])
            .collect();
        assert_eq!(named, found, "{name}");
        assert!(
            csaf.values().any(|(p, _)| p.is_some()),
            "{name}: no purl to compare"
        );
    }

    // VEX (OpenVEX, by purl) → CSAF: the component a statement names has that purl.
    let doc = value("old-mbedtls");
    let csaf = csaf_identifiers(&doc);
    let openvex: Value =
        serde_json::from_slice(&read("tests/golden/vex/old-mbedtls.openvex.json")).unwrap();
    let mut checked = 0;
    for statement in openvex["statements"].as_array().unwrap() {
        let cve = statement["vulnerability"]["name"].as_str().unwrap();
        let purl = statement["products"][0]["identifiers"]["purl"]
            .as_str()
            .unwrap();
        let Some(vuln) = doc["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["cve"] == cve)
        else {
            continue;
        };
        for list in vuln["product_status"].as_object().unwrap().values() {
            for id in list.as_array().unwrap() {
                let component = component_of(&doc, id.as_str().unwrap());
                let (p, _) = &csaf[&component];
                assert_eq!(p.as_deref(), Some(purl), "{cve}");
                checked += 1;
            }
        }
    }
    assert!(checked > 0);

    // VEX (CycloneDX, by BOM-Link) → CSAF: the bom-ref fragment is the component.
    let mut c = case("old-mbedtls");
    c.vex = vec![named("tests/golden/vex/old-mbedtls.vex.cdx.json")];
    let doc: Value =
        serde_json::from_str(&csaf::to_json(&export_with(&c, &options()).unwrap().csaf).unwrap())
            .unwrap();
    let cdx: Value =
        serde_json::from_slice(&read("tests/golden/vex/old-mbedtls.vex.cdx.json")).unwrap();
    let mut checked = 0;
    for v in cdx["vulnerabilities"].as_array().unwrap() {
        let cve = v["id"].as_str().unwrap();
        let reference = v["affects"][0]["ref"].as_str().unwrap();
        let bom_ref = reference.rsplit('#').next().unwrap();
        if let Some(vuln) = doc["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["cve"] == cve)
        {
            let ids: BTreeSet<String> = vuln["product_status"]
                .as_object()
                .unwrap()
                .values()
                .flat_map(|l| l.as_array().unwrap().iter())
                .map(|i| component_of(&doc, i.as_str().unwrap()))
                .collect();
            assert_eq!(ids, BTreeSet::from([bom_ref.to_owned()]), "{cve}");
            checked += 1;
        }
    }
    assert!(checked > 0);
}

/// AC3: a purl spelled other than rollcall would (upper-case type, unsorted qualifiers) is
/// carried verbatim, not canonicalised.
#[test]
fn non_canonical_purl_spelling_is_kept_verbatim() {
    let sbom = json!({
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"component": {"type": "firmware", "bom-ref": "p", "name": "dev"}},
        "components": [{"type": "library", "bom-ref": "c", "name": "lib", "version": "1.0",
            "purl": "pkg:GitHub/Mbed-TLS/mbedtls@v2.28.0?b=2&a=1",
            "cpe": "cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*"}]
    });
    let tree = csaf::read_tree(&sbom).unwrap();
    let tree = serde_json::to_value(build_tree(&tree, &all_components(&tree))).unwrap();
    let ids = csaf_identifiers(&json!({ "product_tree": tree }));
    assert_eq!(
        ids["c"],
        (
            Some("pkg:GitHub/Mbed-TLS/mbedtls@v2.28.0?b=2&a=1".to_owned()),
            Some("cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*".to_owned())
        )
    );
}

fn build_tree(tree: &csaf::SbomTree, components: &BTreeSet<String>) -> csaf::ProductTree {
    csaf::build_product_tree(tree, components)
}

/// Every component of the tree, as if each had a finding.
fn all_components(tree: &csaf::SbomTree) -> BTreeSet<String> {
    tree.children
        .iter()
        .map(|c| c.node.bom_ref.clone())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// AC3 (property): for any product rollcall can render, with a finding on every
    /// component, the CSAF product tree defines exactly the SBOM's bom-refs (less the
    /// components of scope `excluded`), each with the SBOM's purl and CPE strings, and one
    /// relationship product per component, as part of the product.
    #[test]
    fn product_tree_identifiers_equal_sbom_identifiers(entries in common::arb_entries()) {
        let product = common::build(&entries);
        let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
        let text = cyclonedx::write(&product, &options).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        let read = read_tree(&doc).unwrap();
        let tree = build_tree(&read, &all_components(&read));
        let value = json!({"product_tree": serde_json::to_value(&tree).unwrap()});
        let ids = csaf_identifiers(&value);
        let excluded: BTreeSet<&str> = read
            .children
            .iter()
            .filter(|c| c.scope.as_deref() == Some("excluded"))
            .map(|c| c.node.bom_ref.as_str())
            .collect();
        let mut want = sbom_identifiers(text.as_bytes());
        want.retain(|r, _| !excluded.contains(r.as_str()));
        prop_assert_eq!(&ids, &want);
        let rels = relationships(&value);
        prop_assert_eq!(rels.len(), want.len() - 1);
        for (id, (component, product)) in rels {
            prop_assert_eq!(&product, &read.product.bom_ref);
            prop_assert_eq!(id, csaf::product_id_of(&component, &product));
        }
    }
}

// --- TP3: golden and diff test ---------------------------------------------------------------

fn check_golden(name: &str, actual: &str) {
    let path = manifest_dir().join("tests/golden/csaf").join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        bless(&path, actual);
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    if expected != actual {
        let (removed, added) = common::line_diff(&expected, actual);
        panic!(
            "{} differs from the CSAF output; if the change is intended, run \
             scripts/regen-golden.sh and review the diff\n--- golden\n{}\n+++ actual\n{}",
            path.display(),
            removed.join("\n"),
            added.join("\n")
        );
    }
}

/// TP3: the old-mbedTLS CSAF document is byte-identical to its golden.
#[test]
fn old_mbedtls_csaf_matches_golden() {
    check_golden("old-mbedtls.csaf.json", &text("old-mbedtls"));
}

/// TP3: the diff test catches a change, and only where it is: with the tracking id pinned,
/// one more VEX statement changes only that vulnerability's lines; the default (content-
/// derived) tracking id changes with it.
#[test]
fn one_more_vex_statement_changes_only_its_vulnerability() {
    let mut pinned = options();
    pinned.id = Some(TrackingId::parse("pinned").unwrap());
    let base_export = export_with(&case("old-mbedtls"), &pinned).unwrap();
    let base = csaf::to_json(&base_export.csaf).unwrap();
    let mut c = case("old-mbedtls");
    let extra = json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:uuid:00000000-0000-8000-8000-000000000001",
        "author": "test", "timestamp": GOLDEN_TIMESTAMP, "version": 1,
        "statements": [{
            "vulnerability": {"name": "CVE-2021-43666"},
            "products": [{"@id": "pkg:github/mbed-tls/mbedtls@v2.28.0"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path"
        }]
    });
    c.vex.push((
        "extra.openvex.json".to_owned(),
        serde_json::to_vec(&extra).unwrap(),
    ));
    let changed_export = export_with(&c, &pinned).unwrap();
    let changed = csaf::to_json(&changed_export.csaf).unwrap();

    // Textually: one contiguous change, inside one vulnerability.
    let (removed, added) = common::line_diff(&base, &changed);
    let all = removed.iter().chain(&added).cloned().collect::<Vec<_>>();
    assert!(!removed.is_empty() && !added.is_empty(), "{all:?}");
    assert!(
        all.iter().any(|l| l.contains("\"known_not_affected\"")),
        "{all:?}"
    );
    assert!(
        all.iter()
            .any(|l| l.contains("vulnerable_code_not_in_execute_path")),
        "{all:?}"
    );
    for line in &all {
        assert!(
            !line.contains("\"cve\"")
                && !line.contains("\"product_id\"")
                && !line.contains("\"id\""),
            "unrelated line changed: {line}"
        );
    }

    // Structurally: only that vulnerability differs.
    let a = &base_export.csaf;
    let b = &changed_export.csaf;
    assert_eq!(a.document, b.document);
    assert_eq!(a.product_tree, b.product_tree);
    assert_eq!(a.vulnerabilities.len(), b.vulnerabilities.len());
    for (x, y) in a.vulnerabilities.iter().zip(&b.vulnerabilities) {
        if x.cve.as_deref() == Some("CVE-2021-43666") {
            assert_ne!(x, y);
        } else {
            assert_eq!(x, y);
        }
    }

    // The default id is derived from the content, so it changes too.
    let default_base = export("old-mbedtls").csaf.document.tracking.id;
    let default_changed = export_with(&c, &options())
        .unwrap()
        .csaf
        .document
        .tracking
        .id;
    assert_ne!(default_base, default_changed);
}

// --- Determinism ------------------------------------------------------------------------------

#[test]
fn export_is_byte_identical_across_runs_and_input_order() {
    for name in FIXTURES {
        let first = text(name);
        assert_eq!(first, text(name), "{name}");
        let mut c = case(name);
        c.scans.reverse();
        let reversed = csaf::to_json(&export_with(&c, &options()).unwrap().csaf).unwrap();
        assert_eq!(first, reversed, "{name}");
    }
}

#[test]
fn default_id_is_content_derived_and_timestamp_independent() {
    let a = export("old-mbedtls").csaf;
    let mut later = options();
    later.timestamp = Timestamp::parse("2030-06-07T08:09:10Z").unwrap();
    let b = export_with(&case("old-mbedtls"), &later).unwrap().csaf;
    assert_eq!(a.document.tracking.id, b.document.tracking.id);
    assert!(a.document.tracking.id.starts_with("rollcall-csaf-"));
    assert_eq!(a.document.tracking.id.len(), "rollcall-csaf-".len() + 16);
    assert_eq!(
        b.document.tracking.initial_release_date,
        "2030-06-07T08:09:10Z"
    );
    assert_ne!(
        a.document.tracking.id,
        export("old-heapless").csaf.document.tracking.id
    );

    let mut fixed = options();
    fixed.id = Some(TrackingId::parse("ACME-VEX-2026-001").unwrap());
    fixed.title = Some("Custom".to_owned());
    fixed.tlp = Some(csaf::Tlp::Green);
    let doc: Value = serde_json::from_str(
        &csaf::to_json(&export_with(&case("old-mbedtls"), &fixed).unwrap().csaf).unwrap(),
    )
    .unwrap();
    assert_eq!(doc["document"]["tracking"]["id"], "ACME-VEX-2026-001");
    assert_eq!(doc["document"]["title"], "Custom");
    assert_eq!(
        doc["document"]["distribution"],
        json!({"tlp": {"label": "GREEN"}})
    );
    // No TLP unless asked for.
    assert!(
        value("old-mbedtls")["document"]
            .get("distribution")
            .is_none()
    );
}

/// A `rollcall scan --json` report is an input like raw scanner output: the same document.
#[test]
fn scan_report_input_gives_the_same_document() {
    let c = case("old-mbedtls");
    let sbom = scan::Sbom::from_bytes(&c.sbom).unwrap();
    let mut findings = Vec::new();
    for (_, bytes) in &c.scans {
        findings.extend(parse_findings(bytes).unwrap().findings);
    }
    let report = scan::scan(&sbom, Vec::new(), &findings, &[], Vec::new());
    let mut from_report = case("old-mbedtls");
    from_report.scans = vec![(
        "scan.json".to_owned(),
        report.to_json().unwrap().into_bytes(),
    )];
    let a = export("old-mbedtls").csaf;
    let b = export_with(&from_report, &options()).unwrap().csaf;
    assert_eq!(a.product_tree, b.product_tree);
    let statuses = |c: &csaf::Csaf| -> Vec<_> {
        c.vulnerabilities
            .iter()
            .map(|v| (v.cve.clone(), v.product_status.clone()))
            .collect()
    };
    assert_eq!(statuses(&a), statuses(&b));
}

// --- Errors: empty export, publisher, malformed inputs ---------------------------------------

#[test]
fn no_findings_is_an_error() {
    let mut c = case("old-mbedtls");
    c.scans = vec![("grype.json".to_owned(), b"{\"matches\": []}".to_vec())];
    assert!(matches!(
        export_with(&c, &options()),
        Err(CsafError::NoFindings(_))
    ));
}

#[test]
fn findings_not_in_the_sbom_are_left_out_with_a_warning() {
    let ghost = json!({
        "schema": "rollcall-scan/1", "scanners": [],
        "findings": [{"id": "CVE-2020-0001", "component": null,
            "package": {"name": "ghost", "version": "1.0"},
            "severity": "high", "sources": [{"scanner": "grype", "id": "CVE-2020-0001"}]}]
    });
    let mut c = case("old-mbedtls");
    c.scans = vec![("ghost.json".to_owned(), serde_json::to_vec(&ghost).unwrap())];
    // With nothing left, the error still carries the warning that says why.
    match export_with(&c, &options()) {
        Err(CsafError::NoFindings(warnings)) => assert!(
            warnings
                .iter()
                .any(|w| w.location == "CVE-2020-0001 on ghost"),
            "{warnings:?}"
        ),
        other => panic!("{other:?}"),
    }
    let mut c = case("old-mbedtls");
    c.scans
        .push(("ghost.json".to_owned(), serde_json::to_vec(&ghost).unwrap()));
    let export = export_with(&c, &options()).unwrap();
    assert!(
        export
            .warnings
            .iter()
            .any(|w| w.location == "CVE-2020-0001 on ghost"),
        "{:?}",
        export.warnings
    );
    assert!(
        export
            .csaf
            .vulnerabilities
            .iter()
            .all(|v| v.cve.as_deref() != Some("CVE-2020-0001"))
    );
}

#[test]
fn publisher_comes_from_options_or_the_sbom_supplier() {
    let c = case("old-mbedtls");
    let none = CsafOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    assert!(matches!(
        export_with(&c, &none),
        Err(CsafError::Publisher(_))
    ));
    let mut name_only = none.clone();
    name_only.publisher_name = Some("Example".to_owned());
    assert!(matches!(
        export_with(&c, &name_only),
        Err(CsafError::Publisher(m)) if m.contains("--publisher-namespace")
    ));
    let mut bad = options();
    bad.publisher_namespace = Some("not a uri".to_owned());
    assert!(matches!(
        export_with(&c, &bad),
        Err(CsafError::Publisher(_))
    ));

    // From the SBOM's product supplier.
    let mut sbom: Value = serde_json::from_slice(&c.sbom).unwrap();
    sbom["metadata"]["component"]["supplier"] =
        json!({"name": "Supplier Ltd", "url": ["https://supplier.example"]});
    let with_supplier = Case {
        sbom: serde_json::to_vec(&sbom).unwrap(),
        scans: c.scans.clone(),
        vex: c.vex.clone(),
    };
    let csaf = export_with(&with_supplier, &none).unwrap().csaf;
    assert_eq!(csaf.document.publisher.name, "Supplier Ltd");
    assert_eq!(
        csaf.document.publisher.namespace,
        "https://supplier.example"
    );
    assert_eq!(csaf.product_tree.branches[0].category, "vendor");
    assert_eq!(csaf.product_tree.branches[0].name, "Supplier Ltd");
}

#[test]
fn malformed_inputs_are_errors_never_panics() {
    let good = case("old-mbedtls");
    let bad_sboms: [&[u8]; 6] = [
        b"",
        b"{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\"",
        b"\xff\xfe\x00",
        b"[]",
        b"{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\", \"components\": 7}",
        b"{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.6\", \"metadata\": {\"component\": {\"type\": \"firmware\", \"name\": 5}}}",
    ];
    for bytes in bad_sboms {
        let c = Case {
            sbom: bytes.to_vec(),
            scans: good.scans.clone(),
            vex: good.vex.clone(),
        };
        assert!(
            matches!(export_with(&c, &options()), Err(CsafError::Sbom { .. })),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
    let bad_scans: [&[u8]; 4] = [
        b"",
        b"{\"matches\": [",
        b"{\"matches\": 5}",
        b"{\"schema\": \"rollcall-scan/1\", \"findings\": [{\"id\": 3}]}",
    ];
    for bytes in bad_scans {
        let c = Case {
            sbom: good.sbom.clone(),
            scans: vec![("bad.json".to_owned(), bytes.to_vec())],
            vex: Vec::new(),
        };
        match export_with(&c, &options()) {
            Err(CsafError::Scan { name, .. }) => assert_eq!(name, "bad.json"),
            other => panic!("{}: {other:?}", String::from_utf8_lossy(bytes)),
        }
    }
    let bad_vex: [&[u8]; 4] = [
        b"",
        b"{\"@context\": \"https://openvex.dev/ns/v0.2.0\", \"statements\": [{",
        b"{\"@context\": \"https://openvex.dev/ns/v0.2.0\", \"statements\": [{\"vulnerability\": 1}]}",
        b"{\"hello\": 1}",
    ];
    for bytes in bad_vex {
        let c = Case {
            sbom: good.sbom.clone(),
            scans: good.scans.clone(),
            vex: vec![("bad.vex.json".to_owned(), bytes.to_vec())],
        };
        match export_with(&c, &options()) {
            Err(CsafError::Vex { name, .. }) => assert_eq!(name, "bad.vex.json"),
            other => panic!("{}: {other:?}", String::from_utf8_lossy(bytes)),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary bytes as any input never panic.
    #[test]
    fn build_never_panics_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let good = case("old-heapless");
        for c in [
            Case { sbom: bytes.clone(), scans: good.scans.clone(), vex: Vec::new() },
            Case { sbom: good.sbom.clone(), scans: vec![("x".to_owned(), bytes.clone())], vex: Vec::new() },
            Case { sbom: good.sbom.clone(), scans: good.scans.clone(), vex: vec![("x".to_owned(), bytes.clone())] },
        ] {
            let _ = export_with(&c, &options());
        }
    }
}

/// The old-mbedTLS SBOM with mbedtls given CycloneDX `scope`.
fn with_mbedtls_scope(scope: &str) -> Case {
    let mut c = case("old-mbedtls");
    let mut sbom: Value = serde_json::from_slice(&c.sbom).unwrap();
    let mut patched = false;
    for image in sbom["components"].as_array_mut().unwrap() {
        for comp in image["components"].as_array_mut().into_iter().flatten() {
            if comp["name"] == "mbedtls" {
                comp["scope"] = json!(scope);
                patched = true;
            }
        }
    }
    assert!(patched);
    c.sbom = serde_json::to_vec(&sbom).unwrap();
    c
}

/// S1: a component of scope `excluded` is not part of the product: its findings are left
/// out with a warning each (here, all of them, so there is nothing to export), and it is not
/// in the product tree. An `optional` one is an `optional_component_of` the product.
#[test]
fn excluded_components_are_left_out_and_optional_ones_are_optional() {
    match export_with(&with_mbedtls_scope("excluded"), &options()) {
        Err(CsafError::NoFindings(warnings)) => {
            let excluded: Vec<_> = warnings
                .iter()
                .filter(|w| w.message.contains("scope excluded"))
                .collect();
            assert_eq!(excluded.len(), 23, "{warnings:?}");
            assert!(
                excluded[0].location.contains("mbedtls 2.28.0"),
                "{excluded:?}"
            );
        }
        other => panic!("{other:?}"),
    }

    let doc: Value = serde_json::from_str(
        &csaf::to_json(
            &export_with(&with_mbedtls_scope("optional"), &options())
                .unwrap()
                .csaf,
        )
        .unwrap(),
    )
    .unwrap();
    let rels = doc["product_tree"]["relationships"].as_array().unwrap();
    assert_eq!(rels.len(), 1);
    assert_eq!(rels[0]["category"], "optional_component_of");
}

/// The old-mbedTLS case with the CycloneDX VEX golden, CVE-2022-46392's analysis given
/// `response` (None: none).
fn remediation_with_response(response: Option<Value>) -> Value {
    let mut cdx: Value =
        serde_json::from_slice(&read("tests/golden/vex/old-mbedtls.vex.cdx.json")).unwrap();
    let mut patched = false;
    for v in cdx["vulnerabilities"].as_array_mut().unwrap() {
        if v["id"] == "CVE-2022-46392" {
            assert_eq!(v["analysis"]["state"], "exploitable");
            if let Some(r) = &response {
                v["analysis"]["response"] = r.clone();
            }
            patched = true;
        }
    }
    assert!(patched);
    let mut c = case("old-mbedtls");
    c.vex = vec![("vex.cdx.json".to_owned(), serde_json::to_vec(&cdx).unwrap())];
    let doc: Value =
        serde_json::from_str(&csaf::to_json(&export_with(&c, &options()).unwrap().csaf).unwrap())
            .unwrap();
    doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"] == "CVE-2022-46392")
        .unwrap()["remediations"]
        .clone()
}

/// S2: the remediation category comes from the claim's CycloneDX `analysis.response`; with
/// none, `none_available` even with an upstream fixed version (never `mitigation`). The
/// claim's detail is the text.
#[test]
fn remediation_category_comes_from_the_claim_response() {
    for (response, want) in [
        (Some(json!(["update"])), "vendor_fix"),
        (Some(json!(["rollback"])), "vendor_fix"),
        (Some(json!(["workaround_available"])), "workaround"),
        (Some(json!(["will_not_fix"])), "no_fix_planned"),
        (Some(json!(["can_not_fix"])), "no_fix_planned"),
        (Some(json!(["will_not_fix", "update"])), "vendor_fix"),
        (None, "none_available"),
    ] {
        let remediations = remediation_with_response(response.clone());
        assert_eq!(remediations.as_array().unwrap().len(), 1, "{response:?}");
        assert_eq!(remediations[0]["category"], want, "{response:?}");
        assert_eq!(
            remediations[0]["details"], "Upgrade Mbed TLS to 2.28.2 or later.",
            "{response:?}"
        );
    }
}

/// S2: an affected finding the scanners know no fixed version for, with no response, is
/// `none_available`; without an action statement the text is generated.
#[test]
fn affected_without_a_fixed_version_has_none_available() {
    let mut c = case("old-mbedtls");
    let extra = json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "urn:uuid:00000000-0000-8000-8000-000000000002",
        "author": "test", "timestamp": GOLDEN_TIMESTAMP, "version": 1,
        "statements": [{
            "vulnerability": {"name": "CVE-2021-43666"},
            "products": [{"@id": "pkg:github/mbed-tls/mbedtls@v2.28.0"}],
            "status": "affected",
            "impact_statement": "not an action statement"
        }]
    });
    c.vex = vec![(
        "x.openvex.json".to_owned(),
        serde_json::to_vec(&extra).unwrap(),
    )];
    let doc: Value =
        serde_json::from_str(&csaf::to_json(&export_with(&c, &options()).unwrap().csaf).unwrap())
            .unwrap();
    let vuln = doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["cve"] == "CVE-2021-43666")
        .unwrap()
        .clone();
    assert_eq!(vuln["remediations"][0]["category"], "none_available");
    assert_eq!(
        vuln["remediations"][0]["details"],
        "No fixed version of mbedtls is known."
    );
}
