//! `rollcall scan`'s core: normalising captured grype and osv-scanner output, applying VEX
//! documents, the report and the exit-code gate.
//!
//! - SBOMs are rendered from the hand-written `tests/data/old-*.model.json` exactly as
//!   `rollcall generate --model … --timestamp 2026-01-02T03:04:05Z` writes them.
//! - Findings are the captures in `tests/data/findings/`, written only by
//!   `scripts/capture-findings.sh`.
//! - VEX documents are the committed `tests/golden/vex/` renderings of `rollcall vex`, or are
//!   built in the test from the captures.
//!
//! The goldens under `tests/golden/scan/` are written only by `scripts/regen-golden.sh`
//! (this test with `ROLLCALL_BLESS=1`). Never edit them by hand.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{GOLDEN_TIMESTAMP, bless, load_fixture};
use proptest::prelude::*;
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions};
use rollcall_core::scan::{
    self, Gate, LabelledVex, NormalisedFinding, Outcome, Sbom, ScanFinding, ScanReport, ScannerRun,
    ScannerStatus, Triage, normalise, normalise_scanner, overlap, parse_vex,
};
use rollcall_core::severity::Severity;
use rollcall_core::vex::{Finding, Package, Scanner, parse_findings};
use serde_json::{Value, json};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The SBOM `rollcall generate --model tests/data/<model>.model.json` writes.
fn sbom_text(model: &str) -> String {
    let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    cyclonedx::write(&load_fixture(model), &options).unwrap()
}

fn sbom(model: &str) -> Sbom {
    Sbom::from_bytes(sbom_text(model).as_bytes()).unwrap()
}

fn capture_bytes(file: &str) -> Vec<u8> {
    std::fs::read(manifest_dir().join("tests/data/findings").join(file)).unwrap()
}

fn findings(file: &str) -> Vec<Finding> {
    let parsed = parse_findings(&capture_bytes(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert!(parsed.warnings.is_empty(), "{file}: {:?}", parsed.warnings);
    parsed.findings
}

fn both(model: &str) -> Vec<Finding> {
    let mut all = findings(&format!("{model}.grype.json"));
    all.extend(findings(&format!("{model}.osv.json")));
    all
}

/// The scanner versions the captures were made with (`tests/data/findings/CAPTURE.txt`).
fn captured_runs() -> Vec<ScannerRun> {
    vec![
        ScannerRun {
            scanner: Scanner::Grype,
            version: Some("0.119.0".to_owned()),
            status: ScannerStatus::Ok,
            offline: false,
        },
        ScannerRun {
            scanner: Scanner::Osv,
            version: Some("2.6.0".to_owned()),
            status: ScannerStatus::Ok,
            offline: false,
        },
    ]
}

fn golden_vex(file: &str) -> LabelledVex {
    let bytes = std::fs::read(manifest_dir().join("tests/golden/vex").join(file)).unwrap();
    (file.to_owned(), parse_vex(&bytes).unwrap())
}

fn vex_value(label: &str, value: &Value) -> LabelledVex {
    (
        label.to_owned(),
        parse_vex(&serde_json::to_vec(value).unwrap()).unwrap(),
    )
}

fn report(model: &str, documents: &[LabelledVex]) -> ScanReport {
    scan::scan(
        &sbom(model),
        captured_runs(),
        &both(model),
        documents,
        Vec::new(),
    )
}

fn check_golden(name: &str, actual: &str) {
    let path = manifest_dir().join("tests/golden/scan").join(name);
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
    assert!(
        expected == actual,
        "{} differs from the scan output; if the change is intended, run \
         scripts/regen-golden.sh and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

fn bom_ref_of(sbom_text: &str, name: &str) -> String {
    let doc: Value = serde_json::from_str(sbom_text).unwrap();
    doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| std::iter::once(c).chain(c["components"].as_array().into_iter().flatten()))
        .find(|c| c["name"] == name)
        .and_then(|c| c["bom-ref"].as_str())
        .unwrap_or_else(|| panic!("no component {name}"))
        .to_owned()
}

/// Asserts the AC: every vulnerability both scanners report on the same component
/// normalises to the same id and component. Returns the pairs.
/// What a finding is about: its component's bom-ref, else the reported package's name and
/// version.
fn target_key(f: &NormalisedFinding) -> String {
    match f.bom_ref() {
        Some(r) => r.to_owned(),
        None => format!(
            "package {}@{}",
            f.package.name,
            f.package.version.as_deref().unwrap_or("")
        ),
    }
}

/// Every way two scanners' normalised findings disagree about a vulnerability both report
/// (paired by shared id or alias only, whatever the target): a different id or target in a
/// pair, or, for an id both report, different sets of (id, target).
fn overlap_mismatches(grype: &[NormalisedFinding], osv: &[NormalisedFinding]) -> Vec<String> {
    let mut problems = Vec::new();
    for (g, o) in overlap(grype, osv) {
        if g.id != o.id || target_key(g) != target_key(o) || g.component != o.component {
            problems.push(format!(
                "{} on {} (grype) / {} on {} (osv-scanner)",
                g.id,
                target_key(g),
                o.id,
                target_key(o)
            ));
        }
    }
    let by_id = |findings: &[NormalisedFinding]| {
        let mut map: std::collections::BTreeMap<String, BTreeSet<(String, String)>> =
            std::collections::BTreeMap::new();
        for f in findings {
            for id in f.ids() {
                map.entry(id)
                    .or_default()
                    .insert((f.id.clone(), target_key(f)));
            }
        }
        map
    };
    let (g, o) = (by_id(grype), by_id(osv));
    for (id, g_targets) in &g {
        if let Some(o_targets) = o.get(id)
            && g_targets != o_targets
        {
            problems.push(format!(
                "{id}: grype {g_targets:?}, osv-scanner {o_targets:?}"
            ));
        }
    }
    problems
}

/// Asserts the AC: every vulnerability both scanners report normalises to the same id and
/// component. Returns the overlapping pairs.
fn assert_overlap_identical(model: &str) -> Vec<(NormalisedFinding, NormalisedFinding)> {
    let sbom = sbom(model);
    let all = both(model);
    let grype = normalise_scanner(&sbom, &all, Scanner::Grype).findings;
    let osv = normalise_scanner(&sbom, &all, Scanner::Osv).findings;
    let problems = overlap_mismatches(&grype, &osv);
    assert!(problems.is_empty(), "{model}: {problems:#?}");
    overlap(&grype, &osv)
        .into_iter()
        .map(|(a, b)| (a.clone(), b.clone()))
        .collect()
}

#[test]
fn overlap_check_catches_a_component_or_id_mismatch() {
    let sbom = sbom("old-heapless");
    let all = both("old-heapless");
    let grype = normalise_scanner(&sbom, &all, Scanner::Grype).findings;
    let osv = normalise_scanner(&sbom, &all, Scanner::Osv).findings;
    assert!(overlap_mismatches(&grype, &osv).is_empty());

    let mut moved = osv.clone();
    moved[0].component.as_mut().unwrap().bom_ref = "component:elsewhere".to_owned();
    assert!(!overlap_mismatches(&grype, &moved).is_empty(), "component");
    let mut unlisted = osv.clone();
    unlisted[0].component = None;
    assert!(
        !overlap_mismatches(&grype, &unlisted).is_empty(),
        "not in SBOM"
    );
    let mut renamed = osv.clone();
    renamed[0].id = "GHSA-qgwf-r2jj-2ccv".to_owned();
    renamed[0].aliases.remove("GHSA-qgwf-r2jj-2ccv");
    renamed[0].aliases.insert("CVE-2020-36464".to_owned());
    assert!(!overlap_mismatches(&grype, &renamed).is_empty(), "id");
}

#[test]
fn overlapping_findings_identical_between_grype_and_osv_old_heapless() {
    let pairs = assert_overlap_identical("old-heapless");
    let heapless = bom_ref_of(&sbom_text("old-heapless"), "heapless");
    let [(grype, osv)] = pairs.as_slice() else {
        panic!("expected exactly one overlapping finding, got {pairs:?}")
    };
    assert_eq!(grype.id, "CVE-2020-36464");
    assert_eq!(grype.bom_ref(), Some(heapless.as_str()));
    assert_eq!(osv.bom_ref(), Some(heapless.as_str()));
    assert_eq!(grype.severity, Severity::High);
    assert_eq!(osv.severity, Severity::High);
    assert_eq!(grype.fixed_versions, osv.fixed_versions);
    // grype names it by its GHSA id, osv-scanner by RUSTSEC and GHSA; both alias the CVE.
    assert!(grype.aliases.contains("GHSA-qgwf-r2jj-2ccv"), "{grype:?}");
    assert!(osv.aliases.contains("RUSTSEC-2020-0145"), "{osv:?}");

    // Together, they are one finding reported by both scanners.
    let merged = normalise(&sbom("old-heapless"), &both("old-heapless")).findings;
    let [one] = merged.as_slice() else {
        panic!("{merged:?}")
    };
    assert_eq!(one.id, "CVE-2020-36464");
    let scanners: BTreeSet<Scanner> = one.sources.iter().map(|s| s.scanner).collect();
    assert_eq!(scanners, BTreeSet::from([Scanner::Grype, Scanner::Osv]));
}

#[test]
fn overlapping_findings_identical_old_mbedtls_captures() {
    // osv-scanner maps pkg:github purls to "GitHub Actions" and finds nothing for mbedtls,
    // so the overlap is empty: the property holds trivially (see docs/scan.md).
    let pairs = assert_overlap_identical("old-mbedtls");
    assert!(pairs.is_empty(), "{pairs:?}");
    let sbom = sbom("old-mbedtls");
    assert_eq!(
        normalise_scanner(&sbom, &both("old-mbedtls"), Scanner::Grype)
            .findings
            .len(),
        23
    );
}

#[test]
fn scan_golden_old_mbedtls() {
    let report = report("old-mbedtls", &[]);
    check_golden("old-mbedtls.scan.json", &report.to_json().unwrap());
    check_golden("old-mbedtls.scan.txt", &report.to_table());
}

#[test]
fn scan_golden_old_heapless() {
    let report = report("old-heapless", &[]);
    check_golden("old-heapless.scan.json", &report.to_json().unwrap());
    check_golden("old-heapless.scan.txt", &report.to_table());
}

#[test]
fn scan_golden_old_mbedtls_with_openvex() {
    let report = report("old-mbedtls", &[golden_vex("old-mbedtls.openvex.json")]);
    check_golden("old-mbedtls.openvex.scan.json", &report.to_json().unwrap());
    check_golden("old-mbedtls.openvex.scan.txt", &report.to_table());
    let summary = report.summary();
    assert_eq!(
        (
            summary.total,
            summary.suppressed,
            summary.affected,
            summary.unresolved
        ),
        (23, 3, 1, 19)
    );
}

#[test]
fn every_vex_format_triages_alike() {
    let triage = |doc: &str| -> Vec<(String, Triage)> {
        report("old-mbedtls", &[golden_vex(doc)])
            .findings
            .iter()
            .map(|f| (f.finding.id.clone(), f.triage))
            .collect()
    };
    let openvex = triage("old-mbedtls.openvex.json");
    assert_eq!(triage("old-mbedtls.vex.cdx.json"), openvex, "CycloneDX VEX");
    assert_eq!(triage("old-mbedtls.vex.json"), openvex, "rollcall-vex/1");
    assert_eq!(triage("old-mbedtls.embed.cdx.json"), openvex, "embedded");
}

#[test]
fn scanning_twice_is_byte_identical() {
    let docs = [golden_vex("old-mbedtls.openvex.json")];
    let a = report("old-mbedtls", &docs);
    let b = report("old-mbedtls", &docs);
    assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    assert_eq!(a.to_table(), b.to_table());
}

/// An OpenVEX document marking `status` every captured old-mbedTLS grype finding whose
/// severity is in `severities`.
fn openvex_for(severities: &[&str], status: &str) -> Value {
    let capture: Value = serde_json::from_slice(&capture_bytes("old-mbedtls.grype.json")).unwrap();
    let statements: Vec<Value> = capture["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| severities.contains(&m["vulnerability"]["severity"].as_str().unwrap()))
        .map(|m| {
            let mut s = json!({
                "vulnerability": {"name": m["vulnerability"]["id"]},
                "products": [{"@id": m["artifact"]["purl"]}],
                "status": status,
            });
            if status == "not_affected" {
                s["justification"] = json!("vulnerable_code_not_present");
            }
            s
        })
        .collect();
    json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": statements})
}

#[test]
fn suppressed_findings_listed_and_excluded_from_gate() {
    let gate = Gate {
        fail_on: Some(Severity::Critical),
        fail_on_unresolved: false,
    };
    let plain = report("old-mbedtls", &[]);
    assert_eq!(gate.decide(&plain), Outcome::Findings);

    let docs = [vex_value(
        "criticals.openvex.json",
        &openvex_for(&["Critical"], "not_affected"),
    )];
    let triaged = report("old-mbedtls", &docs);
    // Listed, not hidden: the same 23 findings, the 5 criticals suppressed.
    assert_eq!(triaged.findings.len(), plain.findings.len());
    let suppressed: Vec<&ScanFinding> = triaged
        .findings
        .iter()
        .filter(|f| f.triage == Triage::Suppressed)
        .collect();
    assert_eq!(suppressed.len(), 5);
    assert!(
        suppressed
            .iter()
            .all(|f| f.finding.severity == Severity::Critical)
    );
    let table = triaged.to_table();
    for f in &suppressed {
        let row = table
            .lines()
            .find(|l| l.contains(&f.finding.id))
            .unwrap_or_else(|| panic!("{} missing from the table", f.finding.id));
        assert!(
            row.contains("suppressed") && row.contains("not_affected"),
            "{row}"
        );
    }
    let json: Value = serde_json::from_str(&triaged.to_json().unwrap()).unwrap();
    assert_eq!(json["summary"]["suppressed"], 5);
    assert_eq!(json["summary"]["open_by_severity"]["critical"], 0);
    // Not counted toward --fail-on.
    assert_eq!(gate.decide(&triaged), Outcome::Clean);
    let high = Gate {
        fail_on: Some(Severity::High),
        ..gate
    };
    assert_eq!(high.decide(&triaged), Outcome::Findings);
}

fn finding(id: &str, severity: Severity, triage: Triage) -> ScanFinding {
    ScanFinding {
        finding: NormalisedFinding {
            id: id.to_owned(),
            aliases: BTreeSet::new(),
            component: None,
            package: Package {
                name: "p".to_owned(),
                version: None,
                purl: None,
            },
            severity,
            fixed_versions: BTreeSet::new(),
            sources: BTreeSet::new(),
        },
        triage,
        vex: Vec::new(),
    }
}

fn run(scanner: Scanner, status: ScannerStatus) -> ScannerRun {
    ScannerRun {
        scanner,
        version: None,
        status,
        offline: false,
    }
}

#[test]
fn gate_decide_matrix() {
    let index = sbom("old-mbedtls").index;
    let ok = || vec![run(Scanner::Grype, ScannerStatus::Ok)];
    let make = |runs: Vec<ScannerRun>, findings: Vec<ScanFinding>| {
        ScanReport::new(&index, runs, findings, Vec::new())
    };
    let gates = |fail_on: Option<Severity>, unresolved: bool| Gate {
        fail_on,
        fail_on_unresolved: unresolved,
    };

    // No findings: clean whatever the gate.
    for level in Severity::ALL.map(Some).into_iter().chain([None]) {
        for unresolved in [false, true] {
            assert_eq!(
                gates(level, unresolved).decide(&make(ok(), vec![])),
                Outcome::Clean
            );
        }
    }

    // One open finding of each severity × each --fail-on level.
    for severity in Severity::ALL {
        for triage in [Triage::Affected, Triage::Unresolved] {
            for level in Severity::ALL {
                let report = make(ok(), vec![finding("CVE-1", severity, triage)]);
                let want = if severity >= level {
                    Outcome::Findings
                } else {
                    Outcome::Clean
                };
                assert_eq!(
                    gates(Some(level), false).decide(&report),
                    want,
                    "{severity} {triage:?} --fail-on {level}"
                );
            }
            // Without --fail-on, findings never fail exit 1.
            let report = make(ok(), vec![finding("CVE-1", severity, triage)]);
            assert_eq!(gates(None, false).decide(&report), Outcome::Clean);
        }
        // Suppressed never fails, even --fail-on unknown or --fail-on-unresolved.
        let report = make(ok(), vec![finding("CVE-1", severity, Triage::Suppressed)]);
        assert_eq!(
            gates(Some(Severity::Unknown), true).decide(&report),
            Outcome::Clean
        );
    }

    // --fail-on-unresolved: unresolved fails 2, affected does not.
    let unresolved = make(
        ok(),
        vec![finding("CVE-1", Severity::Low, Triage::Unresolved)],
    );
    let affected = make(
        ok(),
        vec![finding("CVE-1", Severity::Low, Triage::Affected)],
    );
    assert_eq!(gates(None, true).decide(&unresolved), Outcome::Unresolved);
    assert_eq!(gates(None, true).decide(&affected), Outcome::Clean);
    // 1 wins over 2.
    assert_eq!(
        gates(Some(Severity::Low), true).decide(&unresolved),
        Outcome::Findings
    );
    assert_eq!(
        gates(Some(Severity::High), true).decide(&unresolved),
        Outcome::Unresolved
    );

    // 3 wins over everything: a failed scanner, or none that ran.
    let failing = [
        vec![
            run(Scanner::Grype, ScannerStatus::Ok),
            run(Scanner::Osv, ScannerStatus::Failed),
        ],
        vec![run(Scanner::Grype, ScannerStatus::Skipped)],
        vec![],
    ];
    for runs in failing {
        let report = make(
            runs.clone(),
            vec![finding("CVE-1", Severity::Critical, Triage::Unresolved)],
        );
        for gate in [gates(Some(Severity::Low), true), gates(None, false)] {
            assert_eq!(gate.decide(&report), Outcome::ScannerFailed, "{runs:?}");
        }
    }
    // One skipped, one ok: not a failure.
    let report = make(
        vec![
            run(Scanner::Grype, ScannerStatus::Skipped),
            run(Scanner::Osv, ScannerStatus::Ok),
        ],
        vec![],
    );
    assert_eq!(gates(None, true).decide(&report), Outcome::Clean);

    assert_eq!(
        [
            Outcome::Clean,
            Outcome::Findings,
            Outcome::Unresolved,
            Outcome::ScannerFailed
        ]
        .map(Outcome::code),
        [0, 1, 2, 3]
    );
}

/// The old-mbedTLS CycloneDX VEX golden with its BOM-Links rewritten.
fn cdx_vex_with_links(from: &str, to: &str) -> LabelledVex {
    let path = manifest_dir().join("tests/golden/vex/old-mbedtls.vex.cdx.json");
    let text = std::fs::read_to_string(path).unwrap().replace(from, to);
    (
        "relinked.vex.cdx.json".to_owned(),
        parse_vex(text.as_bytes()).unwrap(),
    )
}

#[test]
fn bom_link_for_other_sbom_is_warned_not_applied() {
    let sbom_serial = sbom("old-mbedtls")
        .index
        .serial_number
        .unwrap()
        .as_str()
        .to_owned();
    let uuid = sbom_serial.strip_prefix("urn:uuid:").unwrap();
    let link = format!("urn:cdx:{uuid}/1#");

    // Into this SBOM: applied, no warning.
    let same = report("old-mbedtls", &[cdx_vex_with_links(&link, &link)]);
    assert_eq!(same.summary().suppressed, 3);
    assert!(same.warnings.is_empty(), "{:?}", same.warnings);

    // Into another SBOM: not applied, one warning per claim and finding.
    let other = "urn:cdx:00000000-0000-4000-8000-000000000000/1#";
    let report_other = report("old-mbedtls", &[cdx_vex_with_links(&link, other)]);
    let summary = report_other.summary();
    assert_eq!((summary.suppressed, summary.affected), (0, 0));
    assert_eq!(summary.unresolved, 23);
    assert!(report_other.findings.iter().all(|f| f.vex.is_empty()));
    assert_eq!(
        report_other.warnings.len(),
        22,
        "{:?}",
        report_other.warnings
    );
    assert!(
        report_other
            .warnings
            .iter()
            .all(|w| w.message.contains("another SBOM") && w.message.contains("not applied")),
        "{:?}",
        report_other.warnings
    );

    // Into another version of this SBOM: applied, with a warning.
    let v2 = format!("urn:cdx:{uuid}/2#");
    let report_v2 = report("old-mbedtls", &[cdx_vex_with_links(&link, &v2)]);
    assert_eq!(report_v2.summary().suppressed, 3);
    assert!(!report_v2.warnings.is_empty());
    assert!(
        report_v2
            .warnings
            .iter()
            .all(|w| w.message.contains("version 2") && w.message.contains("applied"))
    );
}

#[test]
fn conflicting_vex_claims_stay_unresolved() {
    let docs = [
        golden_vex("old-mbedtls.openvex.json"),
        vex_value(
            "second-opinion.openvex.json",
            &json!({
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [{
                    "vulnerability": {"name": "CVE-2022-35409"},
                    "products": [{"@id": "pkg:github/mbed-tls/mbedtls@v2.28.0"}],
                    "status": "affected"
                }]
            }),
        ),
    ];
    let report = report("old-mbedtls", &docs);
    let f = report
        .findings
        .iter()
        .find(|f| f.finding.id == "CVE-2022-35409")
        .unwrap();
    assert_eq!(f.triage, Triage::Unresolved);
    assert_eq!(f.vex.len(), 2, "{:?}", f.vex);
    let [warning] = report.warnings.as_slice() else {
        panic!("{:?}", report.warnings)
    };
    assert!(
        warning.location.starts_with("CVE-2022-35409 on mbedtls"),
        "{warning}"
    );
    assert!(
        warning.message.contains("conflicting VEX claims")
            && warning
                .message
                .contains("not_affected (old-mbedtls.openvex.json)")
            && warning
                .message
                .contains("affected (second-opinion.openvex.json)"),
        "{warning}"
    );
    // The other suppressions still apply.
    assert_eq!(report.summary().suppressed, 2);
    assert_eq!(
        Gate {
            fail_on: None,
            fail_on_unresolved: true
        }
        .decide(&report),
        Outcome::Unresolved
    );
}

const MBEDTLS_PURL: &str = "pkg:github/mbed-tls/mbedtls@v2.28.0";

fn openvex_statement(id: &str, status: &str, time: Option<&str>) -> Value {
    let mut s = json!({
        "vulnerability": {"name": id},
        "products": [{"@id": MBEDTLS_PURL}],
        "status": status,
    });
    if status == "not_affected" {
        s["justification"] = json!("vulnerable_code_not_present");
    }
    if let Some(t) = time {
        s["timestamp"] = json!(t);
    }
    s
}

fn openvex_doc(timestamp: &str, statements: Vec<Value>) -> Value {
    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "timestamp": timestamp,
        "statements": statements,
    })
}

fn triage_of<'a>(report: &'a ScanReport, id: &str) -> &'a ScanFinding {
    report
        .findings
        .iter()
        .find(|f| f.finding.id == id)
        .unwrap_or_else(|| panic!("no finding {id}"))
}

#[test]
fn openvex_later_statement_supersedes_earlier_in_one_document() {
    let id = "CVE-2022-35409";
    // under_investigation (statement time), then not_affected a day later.
    let doc = openvex_doc(
        "2026-01-01T00:00:00Z",
        vec![
            openvex_statement(id, "not_affected", Some("2026-01-03T00:00:00Z")),
            openvex_statement(id, "under_investigation", Some("2026-01-02T00:00:00Z")),
        ],
    );
    let r = report("old-mbedtls", &[vex_value("timeline.openvex.json", &doc)]);
    let f = triage_of(&r, id);
    assert_eq!(f.triage, Triage::Suppressed, "{f:?}");
    assert_eq!(f.vex.len(), 1, "{:?}", f.vex);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);

    // last_updated beats timestamp; a statement without a time takes the document's.
    let mut later = openvex_statement(id, "affected", Some("2026-01-01T00:00:00Z"));
    later["last_updated"] = json!("2026-02-01T00:00:00Z");
    let doc = openvex_doc(
        "2026-01-15T00:00:00Z",
        vec![openvex_statement(id, "not_affected", None), later],
    );
    let r = report("old-mbedtls", &[vex_value("updated.openvex.json", &doc)]);
    assert_eq!(triage_of(&r, id).triage, Triage::Affected);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn openvex_statements_at_the_same_time_or_in_different_documents_conflict() {
    let id = "CVE-2022-35409";
    let same_time = openvex_doc(
        "2026-01-01T00:00:00Z",
        vec![
            openvex_statement(id, "not_affected", None),
            openvex_statement(id, "affected", None),
        ],
    );
    let r = report("old-mbedtls", &[vex_value("same.openvex.json", &same_time)]);
    assert_eq!(triage_of(&r, id).triage, Triage::Unresolved);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.message.contains("conflicting VEX claims")),
        "{:?}",
        r.warnings
    );

    // Different documents conflict whatever their times.
    let older = openvex_doc(
        "2026-01-01T00:00:00Z",
        vec![openvex_statement(id, "affected", None)],
    );
    let newer = openvex_doc(
        "2026-06-01T00:00:00Z",
        vec![openvex_statement(id, "not_affected", None)],
    );
    let r = report(
        "old-mbedtls",
        &[
            vex_value("older.openvex.json", &older),
            vex_value("newer.openvex.json", &newer),
        ],
    );
    assert_eq!(triage_of(&r, id).triage, Triage::Unresolved);
}

#[test]
fn cyclonedx_plain_refs_are_bom_links_into_their_own_document() {
    let text = sbom_text("old-mbedtls");
    let mbedtls = bom_ref_of(&text, "mbedtls");
    let sbom_doc: Value = serde_json::from_str(&text).unwrap();
    let vex = |serial: Option<&str>, version: u64| {
        let mut doc = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": version,
            "vulnerabilities": [{
                "id": "CVE-2022-35409",
                "analysis": {"state": "not_affected", "justification": "code_not_present"},
                "affects": [{"ref": mbedtls}]
            }]
        });
        if let Some(serial) = serial {
            doc["serialNumber"] = json!(serial);
        }
        vex_value("plain.vex.cdx.json", &doc)
    };
    let ours = sbom_doc["serialNumber"].as_str().unwrap();

    // The scanned SBOM's own serial number (an SBOM with embedded VEX): applied.
    let r = report("old-mbedtls", &[vex(Some(ours), 1)]);
    assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Suppressed);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    // A later version of it: applied, with a warning.
    let r = report("old-mbedtls", &[vex(Some(ours), 2)]);
    assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Suppressed);
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    // Another document (a standalone VEX BOM's own serial): not applied, with a warning.
    let other = "urn:uuid:00000000-0000-4000-8000-000000000000";
    let r = report("old-mbedtls", &[vex(Some(other), 1)]);
    assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Unresolved);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.message.contains("another SBOM")),
        "{:?}",
        r.warnings
    );
    // No serial number at all: a bare bom-ref of the scanned SBOM.
    let r = report("old-mbedtls", &[vex(None, 1)]);
    assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Suppressed);
}

#[test]
fn openvex_subcomponents_of_another_product_warn() {
    let text = sbom_text("old-mbedtls");
    let doc: Value = serde_json::from_str(&text).unwrap();
    let product_purl = doc["metadata"]["component"]["purl"].as_str();
    let product_ref = doc["metadata"]["component"]["bom-ref"].as_str().unwrap();
    let statement = |product: &str| {
        json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{
                "vulnerability": {"name": "CVE-2022-35409"},
                "products": [{"@id": product, "subcomponents": [{"@id": MBEDTLS_PURL}]}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_present"
            }]
        })
    };
    for ours in [Some(product_ref), product_purl].into_iter().flatten() {
        let r = report(
            "old-mbedtls",
            &[vex_value("sub.openvex.json", &statement(ours))],
        );
        assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Suppressed);
        assert!(r.warnings.is_empty(), "{ours}: {:?}", r.warnings);
    }
    let r = report(
        "old-mbedtls",
        &[vex_value(
            "sub.openvex.json",
            &statement("pkg:generic/someone-else@1"),
        )],
    );
    assert_eq!(triage_of(&r, "CVE-2022-35409").triage, Triage::Suppressed);
    let [w] = r.warnings.as_slice() else {
        panic!("{:?}", r.warnings)
    };
    assert!(w.message.contains("not this SBOM's"), "{w}");
}

#[test]
fn unknown_severity_is_counted_and_lowest() {
    let mut f = findings("old-heapless.grype.json");
    f[0].severity = None;
    let report = scan::scan(&sbom("old-heapless"), captured_runs(), &f, &[], Vec::new());
    assert_eq!(report.findings[0].finding.severity, Severity::Unknown);
    assert_eq!(report.open_unknown_severity(), 1);
    let gate = |level| Gate {
        fail_on: Some(level),
        fail_on_unresolved: false,
    };
    assert_eq!(gate(Severity::Low).decide(&report), Outcome::Clean);
    assert_eq!(gate(Severity::Unknown).decide(&report), Outcome::Findings);
}

#[test]
fn malformed_sbom_is_an_error_never_a_panic() {
    let text = sbom_text("old-mbedtls");
    for bytes in [
        &b""[..],
        b"{",
        b"[]",
        b"\xff\xfe{}",
        b"{\"bomFormat\":\"SPDX\"}",
        b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":{}}",
        &text.as_bytes()[..text.len() / 2],
    ] {
        assert!(
            Sbom::from_bytes(bytes).is_err(),
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn normalise_is_order_independent(seed in any::<u64>()) {
        let sbom = sbom("old-heapless");
        let mut all = both("old-heapless");
        all.extend(both("old-mbedtls"));
        let expected = normalise(&sbom, &all);
        // A permutation of 0..all.len() from the seed (Fisher-Yates with an LCG).
        let mut order: Vec<usize> = (0..all.len()).collect();
        let mut state = seed;
        for i in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = usize::try_from((state >> 33) % (i as u64 + 1)).unwrap();
            order.swap(i, j);
        }
        let shuffled: Vec<Finding> = order.iter().map(|i| all[*i].clone()).collect();
        prop_assert_eq!(shuffled.len(), all.len());
        prop_assert_eq!(normalise(&sbom, &shuffled), expected);
    }
}
