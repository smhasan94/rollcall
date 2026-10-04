//! `rollcall diff`'s core: components and findings compared between a base and a head build,
//! the gate, the `rollcall-diff/1` JSON and the pull-request Markdown.
//!
//! - SBOMs are the committed Zephyr goldens `tests/golden/zephyr/tls.cdx.json` (the base: Zephyr
//!   v4.4.2, a current Mbed TLS) and `tests/golden/zephyr/old-mbedtls.cdx.json` (the head:
//!   Zephyr v4.2.0, Mbed TLS 3.6.4).
//! - Scans are built with [`scan::scan`] from the real grype capture
//!   `tests/data/findings/zephyr-old-mbedtls.grype.json` (written only by
//!   `scripts/capture-findings.sh`) for the head and an empty grype result for the base,
//!   exactly as `rollcall scan --scanner grype --json` renders them.
//! - Readiness reports are built with [`report::build`] from those SBOMs and scans.
//! - The few scans written in this file (to exercise matching, the gate and malformed input)
//!   are hand-written test inputs, not real-build fixtures.
//!
//! The goldens under `tests/golden/diff/` are written only by `scripts/regen-golden.sh` (this
//! test with `ROLLCALL_BLESS=1`). Never edit them by hand.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{GOLDEN_TIMESTAMP, bless};
use proptest::prelude::*;
use rollcall_core::cyclonedx::Timestamp;
use rollcall_core::diff::{
    self, DiffError, GateOutcome, MAX_ROWS, REASON_NO_BASE, REASON_NO_BASE_SCAN, Side,
    read_report_summary, read_scan_rows,
};
use rollcall_core::report::{self, Input};
use rollcall_core::scan::{self, Sbom, ScannerRun, ScannerStatus};
use rollcall_core::severity::Severity;
use rollcall_core::vex::{Scanner, parse_findings};
use serde_json::{Value, json};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    let path = manifest_dir().join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The two builds the goldens compare.
const BASE_SBOM: &str = "tests/golden/zephyr/tls.cdx.json";
const HEAD_SBOM: &str = "tests/golden/zephyr/old-mbedtls.cdx.json";
const HEAD_GRYPE: &str = "tests/data/findings/zephyr-old-mbedtls.grype.json";

/// One build's inputs to `rollcall diff`, as bytes.
struct Build {
    sbom: Vec<u8>,
    scan: Vec<u8>,
    report: Vec<u8>,
}

impl Build {
    /// The build's SBOM with `grype` output (`None`: grype found nothing), scanned and
    /// reported as `rollcall scan --scanner grype --json` and `rollcall report --format json`
    /// do.
    fn new(sbom: Vec<u8>, grype: Option<&str>) -> Self {
        let grype_bytes = grype.map_or_else(|| b"{\"matches\": []}".to_vec(), read);
        let parsed = parse_findings(&grype_bytes).unwrap();
        let runs = vec![ScannerRun {
            scanner: Scanner::Grype,
            version: Some("0.119.0".to_owned()),
            status: ScannerStatus::Ok,
            offline: false,
        }];
        let index = Sbom::from_bytes(&sbom).unwrap();
        let scan = scan::scan(&index, runs, &parsed.findings, &[], parsed.warnings)
            .to_json()
            .unwrap()
            .into_bytes();
        Self::with_scan(sbom, scan)
    }

    /// The build with this `rollcall-scan/1` report.
    fn with_scan(sbom: Vec<u8>, scan: Vec<u8>) -> Self {
        let report = {
            let built = report::build(
                Input {
                    name: "sbom.cdx.json",
                    bytes: &sbom,
                },
                &[Input {
                    name: "scan.json",
                    bytes: &scan,
                }],
                &[],
                &Timestamp::parse(GOLDEN_TIMESTAMP).unwrap(),
            )
            .unwrap();
            report::to_json(&built).unwrap().into_bytes()
        };
        Self { sbom, scan, report }
    }

    fn side(&self) -> Side<'_> {
        Side {
            sbom: Input {
                name: "sbom.cdx.json",
                bytes: &self.sbom,
            },
            scan: Some(Input {
                name: "scan.json",
                bytes: &self.scan,
            }),
            report: Some(Input {
                name: "report.json",
                bytes: &self.report,
            }),
        }
    }
}

fn base_build() -> Build {
    Build::new(read(BASE_SBOM), None)
}

fn head_build() -> Build {
    Build::new(read(HEAD_SBOM), Some(HEAD_GRYPE))
}

fn blessing() -> bool {
    std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1")
}

fn golden_dir() -> PathBuf {
    manifest_dir().join("tests/golden/diff")
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if blessing() {
        std::fs::create_dir_all(golden_dir()).unwrap();
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
        "{} differs from the diff; if the change is intended, run scripts/regen-golden.sh \
         and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

/// The diffs the goldens hold: name, head, base, `--fail-on`.
fn golden_cases() -> Vec<(&'static str, diff::Diff)> {
    let base = base_build();
    let head = head_build();
    let bumped = Build::new(bumped_sbom("3.6.6"), None);
    let high = Some(Severity::High);
    vec![
        (
            "tls-to-old-mbedtls",
            diff::build(head.side(), Some(base.side()), high).unwrap(),
        ),
        (
            "old-mbedtls-no-base",
            diff::build(head.side(), None, high).unwrap(),
        ),
        (
            "identical",
            diff::build(head.side(), Some(head.side()), high).unwrap(),
        ),
        // The old-mbedTLS build (base) with its application's mbedtls bumped to 3.6.6 and
        // rescanned clean (head): one changed component, every finding fixed.
        (
            "old-mbedtls-to-bumped",
            diff::build(bumped.side(), Some(head.side()), high).unwrap(),
        ),
    ]
}

fn check_case_goldens(name: &str, d: &diff::Diff) {
    check_golden(&format!("{name}.diff.json"), &diff::to_json(d).unwrap());
    check_golden(&format!("{name}.diff.md"), &diff::to_markdown(d));
}

/// The expected new CVEs: every CVE the head's grype capture reports, at its severity.
fn head_cves() -> Vec<(String, Severity)> {
    let rows = read_scan_rows(Input {
        name: "scan.json",
        bytes: &head_build().scan,
    })
    .unwrap();
    let mut out: Vec<(String, Severity)> = rows.into_iter().map(|r| (r.id, r.severity)).collect();
    out.sort();
    out.dedup();
    out
}

// --- Goldens ----------------------------------------------------------------------------------

/// AC2: introducing an old Mbed TLS (head) over a current one (base) fails a `high` gate,
/// naming every new CVE at or above `high`; the comment lists them, the JSON and Markdown
/// match the goldens.
#[test]
fn diff_golden_tls_to_old_mbedtls() {
    let cases = golden_cases();
    let (_, d) = &cases[0];
    assert_eq!(d.gate.outcome, GateOutcome::Findings);
    assert_eq!(d.gate.fail_on, Some(Severity::High));
    assert!(d.base.present);
    assert_eq!(d.base.reason, None);
    let cves = head_cves();
    let at_or_above_high: Vec<&str> = cves
        .iter()
        .filter(|(_, s)| *s >= Severity::High)
        .map(|(id, _)| id.as_str())
        .collect();
    assert_eq!(d.gate.new_open_at_or_above, at_or_above_high.len() as u64);
    for named in ["CVE-2026-34872", "CVE-2026-34875", "CVE-2026-34877"] {
        assert!(at_or_above_high.contains(&named), "{named}: {cves:?}");
    }
    let md = diff::to_markdown(d);
    assert!(md.contains("❌"), "{md}");
    for id in &at_or_above_high {
        assert!(md.contains(&format!("| {id} |")), "{id} not in\n{md}");
    }
    assert!(!md.contains('\r'));
    for (name, d) in &cases {
        check_case_goldens(name, d);
    }
}

/// Every golden under `tests/golden/diff/` is one this test produces, and vice versa.
#[test]
fn every_committed_diff_golden_is_produced() {
    let mut expected: Vec<String> = golden_cases()
        .iter()
        .flat_map(|(n, _)| [format!("{n}.diff.json"), format!("{n}.diff.md")])
        .collect();
    expected.sort();
    let mut on_disk: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    assert_eq!(on_disk, expected);
}

// --- Findings and the gate --------------------------------------------------------------------

/// Without a base, every head finding (and so every open one) is new, and the reason says
/// so; with a base SBOM but no base scan, the same, with its own reason.
#[test]
fn base_absent_marks_every_open_finding_new() {
    let head = head_build();
    let d = diff::build(head.side(), None, Some(Severity::Critical)).unwrap();
    assert!(!d.base.present);
    assert_eq!(d.base.reason.as_deref(), Some(REASON_NO_BASE));
    assert!(d.findings.head_open > 0);
    assert_eq!(d.findings.new.len() as u64, d.findings.head_total);
    let open_new = d.findings.new.iter().filter(|f| f.triage != "suppressed");
    assert_eq!(open_new.count() as u64, d.findings.head_open);
    assert!(d.findings.fixed.is_empty() && d.findings.changed.is_empty());
    assert!(d.components.added.is_empty() && d.components.removed.is_empty());
    let md = diff::to_markdown(&d);
    assert!(md.contains("every open finding counts as new"), "{md}");

    let base = base_build();
    let no_scan = Side {
        scan: None,
        ..base.side()
    };
    let d = diff::build(head.side(), Some(no_scan), Some(Severity::High)).unwrap();
    assert!(d.base.present);
    assert_eq!(d.base.reason.as_deref(), Some(REASON_NO_BASE_SCAN));
    assert_eq!(d.findings.new.len() as u64, d.findings.head_total);
}

/// The head scan with every finding's triage set to `triage`.
fn retriaged(scan: &[u8], triage: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(scan).unwrap();
    for f in value["findings"].as_array_mut().unwrap() {
        f["triage"] = json!(triage);
    }
    serde_json::to_vec(&value).unwrap()
}

/// A VEX-suppressed finding is listed as new but never counts toward the gate, even at
/// `--fail-on unknown`; when the base had it open, it is a triage change, not new or fixed.
#[test]
fn suppressed_findings_never_fail_the_gate() {
    let head = head_build();
    let suppressed = Build::with_scan(head.sbom.clone(), retriaged(&head.scan, "suppressed"));
    for level in Severity::ALL {
        let d = diff::build(suppressed.side(), None, Some(level)).unwrap();
        assert_eq!(d.gate.new_open_at_or_above, 0, "{level}");
        assert_eq!(d.gate.outcome, GateOutcome::Clean, "{level}");
        assert_eq!(d.findings.new.len() as u64, d.findings.head_total);
        assert!(d.findings.new.iter().all(|f| f.triage == "suppressed"));
        assert_eq!(d.findings.head_open, 0);
    }
    let d = diff::build(
        suppressed.side(),
        Some(head.side()),
        Some(Severity::Unknown),
    )
    .unwrap();
    assert!(d.findings.new.is_empty() && d.findings.fixed.is_empty());
    assert_eq!(d.findings.changed.len() as u64, d.findings.head_total);
    assert!(
        d.findings
            .changed
            .iter()
            .all(|c| c.base_triage == "unresolved" && c.head_triage == "suppressed")
    );
    let md = diff::to_markdown(&d);
    assert!(md.contains("### Triage changes\n\n| Severity |"), "{md}");
}

/// TP3: the gate counts exactly the new open findings at or above the threshold:
/// `critical` lets the `high` ones pass (exit 0) while the diff still lists them; findings
/// the base already had are never counted.
#[test]
fn gate_counts_only_new_open_findings_at_or_above_threshold() {
    let head = head_build();
    let cves = head_cves();
    for level in Severity::ALL {
        let d = diff::build(head.side(), None, Some(level)).unwrap();
        let expected = d
            .findings
            .new
            .iter()
            .filter(|f| f.severity >= level)
            .count() as u64;
        assert_eq!(d.gate.new_open_at_or_above, expected, "{level}");
        assert_eq!(
            d.gate.outcome == GateOutcome::Findings,
            expected > 0,
            "{level}"
        );
    }
    // fail-on critical: the high findings pass but are listed, in the JSON and the comment.
    let critical = diff::build(head.side(), None, Some(Severity::Critical)).unwrap();
    let high: Vec<&str> = cves
        .iter()
        .filter(|(_, s)| *s == Severity::High)
        .map(|(id, _)| id.as_str())
        .collect();
    assert!(!high.is_empty());
    let criticals = cves
        .iter()
        .filter(|(_, s)| *s == Severity::Critical)
        .count();
    assert_eq!(critical.gate.new_open_at_or_above, criticals as u64);
    let md = diff::to_markdown(&critical);
    for id in &high {
        assert!(critical.findings.new.iter().any(|f| f.id == *id), "{id}");
        assert!(md.contains(&format!("| high | {id} |")), "{id}\n{md}");
    }
    // A head with only high findings passes a critical gate (TP3), and lists them.
    let mut value: Value = serde_json::from_slice(&head.scan).unwrap();
    value["findings"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["severity"] == "high");
    let only_high = Build::with_scan(head.sbom.clone(), serde_json::to_vec(&value).unwrap());
    let d = diff::build(only_high.side(), None, Some(Severity::Critical)).unwrap();
    assert_eq!(d.gate.outcome, GateOutcome::Clean);
    assert_eq!(d.gate.new_open_at_or_above, 0);
    assert!(!d.findings.new.is_empty());
    assert!(d.findings.new.iter().all(|f| f.severity == Severity::High));
    let md = diff::to_markdown(&d);
    assert!(
        md.contains("✅ **No new open findings at or above critical.**"),
        "{md}"
    );
    assert!(md.contains("| high | CVE-"), "{md}");
    // No gate: nothing counted.
    let d = diff::build(head.side(), None, None).unwrap();
    assert_eq!(d.gate.new_open_at_or_above, 0);
    assert_eq!(d.gate.outcome, GateOutcome::Clean);
    assert_eq!(d.gate.fail_on, None);
    // Findings the base already has are not new, so they never count.
    let d = diff::build(head.side(), Some(head.side()), Some(Severity::Unknown)).unwrap();
    assert!(d.findings.new.is_empty());
    assert_eq!(d.gate.outcome, GateOutcome::Clean);
}

/// The head SBOM with the application's mbedtls component bumped to `version`.
fn bumped_sbom(version: &str) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&read(HEAD_SBOM)).unwrap();
    let mut bumped = 0;
    fn walk(v: &mut Value, version: &str, bumped: &mut usize) {
        if let Some(components) = v.get_mut("components").and_then(Value::as_array_mut) {
            for c in components {
                if c["name"] == "mbedtls" && c["type"] == "library" {
                    c["version"] = json!(version);
                    *bumped += 1;
                }
                walk(c, version, bumped);
            }
        }
    }
    walk(&mut value, version, &mut bumped);
    assert_eq!(bumped, 1, "one mbedtls component in {HEAD_SBOM}");
    serde_json::to_vec_pretty(&value).unwrap()
}

/// A version bump keeps the component's path, so it is one changed row, not an added and a
/// removed one; nothing else changes.
#[test]
fn component_version_bump_is_changed_not_added_and_removed() {
    let base = read(HEAD_SBOM);
    let head = bumped_sbom("3.6.6");
    let side = |bytes| Side {
        sbom: Input {
            name: "sbom.cdx.json",
            bytes,
        },
        scan: None,
        report: None,
    };
    let d = diff::build(side(&head), Some(side(&base)), None).unwrap();
    assert!(d.components.added.is_empty(), "{:?}", d.components.added);
    assert!(
        d.components.removed.is_empty(),
        "{:?}",
        d.components.removed
    );
    let [change] = d.components.changed.as_slice() else {
        panic!("{:?}", d.components.changed)
    };
    assert_eq!(change.path, "mbedtls / mbedtls");
    assert_eq!(change.level, "component");
    assert_eq!(change.head_version.as_deref(), Some("3.6.6"));
    assert_eq!(
        change.base_version.as_deref(),
        Some("85440ef5fffa95d0e9971e9163719189cf34d979")
    );
    let md = diff::to_markdown(&d);
    assert!(md.contains("0 added, 0 removed, 1 changed."), "{md}");
    assert!(
        md.contains(
            "| changed | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 |"
        ),
        "{md}"
    );
    // The golden case: bumped and rescanned clean, every base finding is fixed.
    let (_, golden) = golden_cases()
        .into_iter()
        .find(|(n, _)| *n == "old-mbedtls-to-bumped")
        .unwrap();
    assert_eq!(golden.components.changed.len(), 1);
    assert!(golden.findings.new.is_empty());
    assert_eq!(golden.findings.fixed.len(), head_cves().len());
    assert_eq!(golden.gate.outcome, GateOutcome::Clean);
    // The same SBOM on both sides: no change at all.
    let d = diff::build(side(&base), Some(side(&base)), None).unwrap();
    assert_eq!(d.components, diff::ComponentDiff::default());
    assert!(diff::to_markdown(&d).contains("### Components\n\nNo changes.\n"));
}

/// A hand-written `rollcall-scan/1` report with these findings.
fn scan_doc(findings: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "rollcall-scan/1",
        "sbom": {"serialNumber": null, "version": 1},
        "scanners": [],
        "findings": findings,
        "summary": {},
        "warnings": []
    }))
    .unwrap()
}

fn finding(id: &str, aliases: &[&str], bom_ref: &str, name: &str, severity: &str) -> Value {
    json!({
        "id": id, "aliases": aliases,
        "component": {"bom-ref": bom_ref, "name": name, "version": "1.0", "purl": null},
        "package": {"name": name, "version": "1.0", "purl": null},
        "severity": severity, "fixed_versions": ["1.1"], "sources": [],
        "triage": "unresolved", "vex": []
    })
}

fn scan_side<'a>(sbom: &'a [u8], scan: &'a [u8]) -> Side<'a> {
    Side {
        sbom: Input {
            name: "sbom.cdx.json",
            bytes: sbom,
        },
        scan: Some(Input {
            name: "scan.json",
            bytes: scan,
        }),
        report: None,
    }
}

/// A finding is matched by any shared id or alias on a component of the same name, so a
/// changed `bom-ref` (e.g. from a version bump) or a different primary id does not make it
/// new; the same id on a different component is new.
#[test]
fn finding_keyed_by_alias_survives_bom_ref_change() {
    let sbom = read(HEAD_SBOM);
    let base = scan_doc(json!([
        finding(
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2026-0001"],
            "ref-old",
            "mbedtls",
            "high"
        ),
        finding("CVE-2026-0002", &[], "ref-old", "mbedtls", "medium"),
    ]));
    let head = scan_doc(json!([
        finding(
            "CVE-2026-0001",
            &["GHSA-aaaa-bbbb-cccc"],
            "ref-new",
            "mbedtls",
            "high"
        ),
        finding("CVE-2026-0001", &[], "ref-x", "zlib", "high"),
    ]));
    let d = diff::build(
        scan_side(&sbom, &head),
        Some(scan_side(&sbom, &base)),
        Some(Severity::High),
    )
    .unwrap();
    let new: Vec<(&str, &str)> = d
        .findings
        .new
        .iter()
        .map(|f| (f.id.as_str(), f.name.as_str()))
        .collect();
    assert_eq!(new, [("CVE-2026-0001", "zlib")]);
    let fixed: Vec<&str> = d.findings.fixed.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(fixed, ["CVE-2026-0002"]);
    assert!(d.findings.changed.is_empty());
    assert_eq!(d.gate.new_open_at_or_above, 1);
    // Two base findings of one id on two copies of a component match two head findings, one
    // each: neither is new.
    let two = scan_doc(json!([
        finding("CVE-2026-0003", &[], "a", "mbedtls", "low"),
        finding("CVE-2026-0003", &[], "b", "mbedtls", "low"),
    ]));
    let d = diff::build(scan_side(&sbom, &two), Some(scan_side(&sbom, &two)), None).unwrap();
    assert!(d.findings.new.is_empty() && d.findings.fixed.is_empty());
}

// --- Markdown ---------------------------------------------------------------------------------

/// Each table shows at most `MAX_ROWS` rows and counts the rest; every input value is
/// escaped, so a hostile component name cannot inject HTML or break the table; LF only.
#[test]
fn markdown_caps_rows_and_escapes_values() {
    let sbom = read(HEAD_SBOM);
    let total = MAX_ROWS + 10;
    let findings: Vec<Value> = (0..total)
        .map(|i| {
            finding(
                &format!("CVE-2026-{i:04}"),
                &[],
                "r",
                "evil|<script>alert(1)</script>*_`#",
                "critical",
            )
        })
        .collect();
    let scan = scan_doc(Value::Array(findings));
    let d = diff::build(scan_side(&sbom, &scan), None, Some(Severity::High)).unwrap();
    assert_eq!(d.findings.new.len(), total);
    let md = diff::to_markdown(&d);
    let section: String = md
        .split("### New findings")
        .nth(1)
        .unwrap()
        .split("###")
        .next()
        .unwrap()
        .to_owned();
    let rows = section
        .lines()
        .filter(|l| l.starts_with("| critical |"))
        .count();
    assert_eq!(rows, MAX_ROWS, "{section}");
    assert!(
        section.contains("… and 10 more in the artifact."),
        "{section}"
    );
    assert!(!md.contains("<script>"), "{md}");
    assert!(
        md.contains(r"evil\|\<script\>alert(1)\</script\>\*\_\`\#"),
        "{md}"
    );
    assert!(!md.contains('\r'));
    assert!(md.ends_with('\n'));
    // Every table line has the same number of unescaped pipes as its header.
    for line in section.lines().filter(|l| l.starts_with('|')) {
        let pipes = line.replace("\\|", "").matches('|').count();
        assert_eq!(pipes, 7, "{line}");
    }
}

// --- Malformed input ----------------------------------------------------------------------------

/// A scan with a field of the wrong type, or a required one missing, is a shape error naming
/// its path; nothing panics.
#[test]
fn scan_rows_rejects_wrong_types_without_panicking() {
    let good = || finding("CVE-1", &["GHSA-1"], "r", "mbedtls", "high");
    let with = |key: &str, v: Value| {
        let mut f = good();
        f[key] = v;
        scan_doc(json!([f]))
    };
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            serde_json::to_vec(&json!({"schema": "rollcall-scan/1"})).unwrap(),
            "$.findings",
        ),
        (
            serde_json::to_vec(&json!({"schema": "rollcall-scan/1", "findings": {}})).unwrap(),
            "$.findings",
        ),
        (serde_json::to_vec(&json!([1])).unwrap(), "$"),
        (scan_doc(json!([1])), "findings[0]"),
        (with("id", json!(1)), "findings[0].id"),
        (with("id", Value::Null), "findings[0].id"),
        (with("aliases", json!("x")), "findings[0].aliases"),
        (with("aliases", json!([2])), "findings[0].aliases[0]"),
        (with("severity", json!("severe")), "findings[0].severity"),
        (with("severity", json!(3)), "findings[0].severity"),
        (with("triage", json!("maybe")), "findings[0].triage"),
        (with("triage", json!(true)), "findings[0].triage"),
        (
            with("fixed_versions", json!({})),
            "findings[0].fixed_versions",
        ),
        (with("component", json!(5)), "findings[0].component"),
        (
            with("component", json!({"bom-ref": 1, "name": "x"})),
            "findings[0].component.bom-ref",
        ),
        (
            with("component", json!({"bom-ref": "r"})),
            "findings[0].component.name",
        ),
        (
            with("component", json!({"name": "x", "version": 1.5})),
            "findings[0].component.version",
        ),
    ];
    for (bytes, want) in cases {
        let text = String::from_utf8_lossy(&bytes).into_owned();
        match read_scan_rows(Input {
            name: "scan.json",
            bytes: &bytes,
        }) {
            Err(DiffError::Shape { path, name, .. }) => {
                assert_eq!(path, want, "{text}");
                assert_eq!(name, "scan.json");
            }
            other => panic!("{text}: {other:?}"),
        }
    }
    // No component and no package.
    let mut f = good();
    f["component"] = Value::Null;
    f["package"] = Value::Null;
    assert!(matches!(
        read_scan_rows(Input {
            name: "s",
            bytes: &scan_doc(json!([f]))
        }),
        Err(DiffError::Shape { .. })
    ));
    // The wrong document altogether: a grype capture, a readiness report.
    for bytes in [read(HEAD_GRYPE), head_build().report] {
        assert!(matches!(
            read_scan_rows(Input {
                name: "s",
                bytes: &bytes
            }),
            Err(DiffError::Schema { .. })
        ));
    }
    // And through build, as the CLI sees it.
    let sbom = read(HEAD_SBOM);
    let bad = with("severity", json!([]));
    assert!(matches!(
        diff::build(scan_side(&sbom, &bad), None, None),
        Err(DiffError::Shape { .. })
    ));
}

/// A readiness report is read only for its score and summary: when either is missing or of
/// the wrong type it is `None`; a document that is not a readiness report is an error.
#[test]
fn report_summary_missing_fields_is_none() {
    let read_summary = |value: Value| {
        read_report_summary(Input {
            name: "report.json",
            bytes: &serde_json::to_vec(&value).unwrap(),
        })
    };
    let empty = read_summary(json!({"schema": "rollcall-report/1"})).unwrap();
    assert_eq!(empty.score, None);
    assert_eq!(empty.summary, None);
    let mistyped = read_summary(json!({
        "schema": "rollcall-report/1", "score": {"value": "high"}, "summary": 7
    }))
    .unwrap();
    assert_eq!((mistyped.score, mistyped.summary), (None, None));
    let out_of_range =
        read_summary(json!({"schema": "rollcall-report/1", "score": {"value": 101}})).unwrap();
    assert_eq!(out_of_range.score, None);
    let real = read_report_summary(Input {
        name: "report.json",
        bytes: &head_build().report,
    })
    .unwrap();
    assert!(real.score.is_some_and(|s| s <= 100));
    assert!(real.summary.is_some_and(|s| s.contains("mbedtls")));
    for bad in [
        json!({"schema": "rollcall-scan/1"}),
        json!({"score": {"value": 3}}),
        json!([]),
        json!("rollcall-report/1"),
    ] {
        assert!(
            matches!(
                read_summary(bad.clone()),
                Err(DiffError::Schema { .. } | DiffError::Shape { .. })
            ),
            "{bad}"
        );
    }
    // A diff built with a summary-less report still renders, without the summary or score.
    let head = head_build();
    let bare = serde_json::to_vec(&json!({"schema": "rollcall-report/1"})).unwrap();
    let side = Side {
        report: Some(Input {
            name: "report.json",
            bytes: &bare,
        }),
        ..head.side()
    };
    let d = diff::build(side, None, None).unwrap();
    assert_eq!(d.summary, None);
    assert_eq!(d.score.head, None);
    assert!(!diff::to_markdown(&d).contains("Readiness score"));
}

/// Empty, truncated and non-UTF-8 inputs are errors on every side and in every slot, never a
/// panic.
#[test]
fn truncated_and_empty_inputs_are_errors() {
    let head = head_build();
    let full: [&[u8]; 3] = [&head.sbom, &head.scan, &head.report];
    let broken: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"{".to_vec(),
        vec![0xff, 0xfe, 0x00],
        b"null".to_vec(),
    ];
    for slot in 0..3 {
        let mut variants: Vec<Vec<u8>> = broken.clone();
        let original = full[slot];
        variants.push(original[..original.len() / 2].to_vec());
        for bad in variants {
            let mut parts: Vec<&[u8]> = full.to_vec();
            parts[slot] = &bad;
            let side = Side {
                sbom: Input {
                    name: "sbom.cdx.json",
                    bytes: parts[0],
                },
                scan: Some(Input {
                    name: "scan.json",
                    bytes: parts[1],
                }),
                report: Some(Input {
                    name: "report.json",
                    bytes: parts[2],
                }),
            };
            assert!(
                diff::build(side, None, None).is_err(),
                "slot {slot}: {:?}",
                String::from_utf8_lossy(&bad)
            );
            assert!(
                diff::build(head.side(), Some(side), None).is_err(),
                "base slot {slot}"
            );
        }
    }
}

proptest! {
    /// Arbitrary bytes after a valid prefix never make the scan reader panic.
    #[test]
    fn scan_reader_never_panics(tail in r#"[\[\]\{\}",:a-z0-9_ -]{0,80}"#) {
        for prefix in [
            r#"{"schema":"rollcall-scan/1","findings":"#,
            r#"{"schema":"rollcall-scan/1","findings":[{"id":"C","severity":"high","triage":"unresolved","#,
            r#"{"schema":"rollcall-report/1","score":"#,
        ] {
            let text = format!("{prefix}{tail}");
            let input = Input { name: "x", bytes: text.as_bytes() };
            let _ = read_scan_rows(input);
            let _ = read_report_summary(input);
        }
    }
}

// --- Schema -----------------------------------------------------------------------------------

fn schema() -> Value {
    serde_json::from_slice(&read("../../docs/diff-schema.json")).unwrap()
}

/// Every diff the goldens hold validates against `docs/diff-schema.json`, which is valid draft
/// 2020-12, closed, and rejects a diff with a missing or extra field, a wrong type or an
/// unknown gate outcome.
#[test]
fn diff_json_validates_against_schema() {
    let schema = schema();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    assert_eq!(schema["title"], diff::DIFF_SCHEMA);
    assert_eq!(schema["properties"]["schema"]["const"], diff::DIFF_SCHEMA);
    assert_eq!(schema["additionalProperties"], false);
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&schema)
        .unwrap();
    let mut seen = BTreeSet::new();
    for (name, d) in golden_cases() {
        let value: Value = serde_json::from_str(&diff::to_json(&d).unwrap()).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:#?}");
        seen.insert(name);
    }
    assert_eq!(seen.len(), 4);
    let (_, d) = golden_cases().remove(0);
    let good: Value = serde_json::from_str(&diff::to_json(&d).unwrap()).unwrap();
    type Mutation = fn(&mut Value);
    let mutations: [(&str, Mutation); 5] = [
        ("missing gate", |v| {
            v.as_object_mut().unwrap().remove("gate");
        }),
        ("extra field", |v| {
            v["extra"] = json!(1);
        }),
        ("wrong schema", |v| {
            v["schema"] = json!("rollcall-diff/2");
        }),
        ("bad outcome", |v| {
            v["gate"]["outcome"] = json!("maybe");
        }),
        ("severity typo", |v| {
            v["findings"]["new"][0]["severity"] = json!("severe");
        }),
    ];
    for (what, mutate) in mutations {
        let mut bad = good.clone();
        mutate(&mut bad);
        assert!(!validator.is_valid(&bad), "{what}");
    }
}
