//! The readiness report (`rollcall report`): how ready an SBOM is to hand over, as Markdown
//! for people and versioned JSON (`rollcall-report/1`, schema `docs/report-schema.json`) for
//! machines.
//!
//! [`build`] reads a CycloneDX 1.6 SBOM, optional scanner output and optional VEX documents,
//! and returns a [`ReadinessReport`]; [`to_json`] and [`to_markdown`] render it. Both
//! renderings start with the same plain-language summary.
//!
//! # Inputs
//!
//! - **SBOM**: a CycloneDX 1.6 JSON document, read with [`cyclonedx::read_bytes`] (documents
//!   rollcall did not write are read leniently; the reader's warnings become report
//!   warnings).
//! - **Scans** (`--scan`, repeatable): grype `-o json`, osv-scanner `--format json` or
//!   `rollcall scan --json` (`rollcall-scan/1`, by its `schema`), told apart by content
//!   ([`vex::parse_findings`]). A `rollcall-scan/1` finding is read as one scanner finding on
//!   the component it was joined to; its VEX triage is not used (only `--vex` closes
//!   findings), with a warning when the scan suppressed any. Findings are joined to components exactly as
//!   `rollcall vex` joins them (by purl, then CPE, then name and version) and merged across
//!   scanners; a finding for a package that is not in the SBOM is counted as `not-in-sbom`.
//!   Severities are normalised with [`normalise_severity`](crate::severity::normalise_severity).
//! - **VEX** (`--vex`, repeatable): rollcall's `rollcall-vex/1` report, an OpenVEX document,
//!   a CycloneDX VEX BOM (whose `affects` are BOM-Links) or an SBOM with embedded
//!   `vulnerabilities` (`rollcall vex --embed`), told apart by content. A statement matches
//!   a finding when one of its ids is the finding's id or alias and it names the finding's
//!   component by `bom-ref` (bare or as a BOM-Link fragment) or purl. A BOM-Link into
//!   another SBOM (a different serial number) is warned about and not applied. A finding is
//!   **closed** when at least one statement matches it and every matching statement is
//!   `not_affected` or `fixed` (CycloneDX: `not_affected`, `false_positive`, `resolved`,
//!   `resolved_with_pedigree`); otherwise it is **open**.
//!
//! # Score
//!
//! The score is out of 100, computed in integer basis points and rounded down, so only a
//! perfect result scores 100. "Items" are every node of the SBOM: the product, each image and
//! every component at any depth (subsystems included).
//!
//! | Category | Weight | Earned by |
//! |----------|-------:|-----------|
//! | `identified` | 25 | share of items with a purl or a CPE |
//! | `hashed` | 15 | share of items with at least one hash |
//! | `licensed` | 15 | share of items with a licence |
//! | `validation` | 25 | share of items with no `cisa-2026` or `cra` profile finding (a document-level finding counts against the product); 0 if the SBOM breaks the CycloneDX 1.6 schema |
//! | `modules` | 10 | share of Zephyr modules the identifier database resolved (full marks when there are none) |
//! | `vulnerabilities` | 10 | share of findings in the SBOM that are closed (full marks when there are none) |
//!
//! Each category earns `weight × 10000 × numerator / denominator` (rounded down) units of
//! 1/10000 point; the score in basis points is the sum divided by the total weight of the
//! assessed categories, rounded down, and the score is that divided by 100, rounded down.
//! Without `--scan` the `vulnerabilities` category is not assessed and is left out of the
//! total weight (90), and the summary says so. CPE coverage is reported but not scored on
//! its own.
//!
//! # Unresolved modules
//!
//! A component is a **Zephyr module** when its evidence comes from `west list`, or Kconfig
//! names it with a `CONFIG_ZEPHYR_<MODULE>_MODULE` symbol. A module is unresolved when the
//! identifier database did not resolve it (it has no `identifier-db` evidence: ingest with
//! `rollcall generate --identify` or `--identifier-db`). Any other component with neither a
//! purl nor a CPE is listed too. Each entry carries a paste-ready identifier-database stub
//! ([`identify::stub`](crate::identify::stub())), prefilled from the module's GitHub purl and version.
//!
//! # Determinism
//!
//! The report depends only on the inputs' contents and the timestamp: rows follow the
//! model's sorted walk (product, each image, its components depth-first), and unresolved
//! entries, findings, statements and warnings are sorted. Profile findings are sorted too:
//! document-level ones first, then by node in walk order (not the document's array order),
//! then by check, message and pointer. The SBOM's own `serialNumber` and
//! `timestamp`, and the input file paths, are not in the report, so it diffs cleanly between
//! builds. Rows are identified by path (names from the image down, no versions), so a
//! dependency bump changes only that component's row and the totals. The JSON is
//! two-space-indented with keys in a fixed order and every field present; the Markdown uses
//! LF line endings and escapes every input value ([`md_cell`]).

mod coverage;
mod findings;
mod markdown;
mod model;
mod scan_input;
mod score;
mod summary;
mod unresolved;
mod vex_input;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub use markdown::{md_cell, to_markdown};
pub use model::{
    BySeverity, Category, ComponentRow, Coverage, FindingItem, FindingsSection, ProductInfo,
    ProfileFinding, ProfileResult, ReadinessReport, ReportWarning, SchemaResult,
    SchemaViolationEntry, Score, Share, Tool, UnresolvedEntry, Validation, VexCoverage,
};
pub use vex_input::{SbomIdentity, VexInput, VexInputError, VexStatement, VexStatus, parse_vex};

use crate::cyclonedx::{self, ReadError, Timestamp, validate_cyclonedx_1_6};
use crate::model::{ModelError, to_canonical_json};
use crate::validate::{self, builtin_profiles, validate_profiles};
use crate::vex;

/// The `schema` of a [`ReadinessReport`].
pub const REPORT_SCHEMA: &str = "rollcall-report/1";

/// One input file: a name for messages and warnings (e.g. its file name) and its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// How the report names it.
    pub name: &'a str,
    /// Its contents.
    pub bytes: &'a [u8],
}

/// Why a report could not be built. Every variant is a malformed input.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReportError {
    /// The SBOM is not JSON.
    #[error("{name}: not valid JSON: {message}")]
    SbomJson {
        /// The SBOM's name.
        name: String,
        /// Why.
        message: String,
    },
    /// The SBOM cannot be read as CycloneDX 1.6.
    #[error("{name}: {source}")]
    Sbom {
        /// The SBOM's name.
        name: String,
        /// Why.
        source: Box<ReadError>,
    },
    /// A scan cannot be read.
    #[error("{name}: {source}")]
    Scan {
        /// The scan's name.
        name: String,
        /// Why.
        source: vex::FindingsError,
    },
    /// A VEX document cannot be read.
    #[error("{name}: {source}")]
    Vex {
        /// The VEX document's name.
        name: String,
        /// Why.
        source: VexInputError,
    },
}

/// Builds the readiness report for `sbom`, with `scans` (none: vulnerabilities not assessed)
/// and `vex` documents, made at `timestamp`. Never panics; any malformed input is a
/// [`ReportError`].
pub fn build(
    sbom: Input<'_>,
    scans: &[Input<'_>],
    vex: &[Input<'_>],
    timestamp: &Timestamp,
) -> Result<ReadinessReport, ReportError> {
    let document: Value =
        serde_json::from_slice(sbom.bytes).map_err(|e| ReportError::SbomJson {
            name: sbom.name.to_owned(),
            message: e.to_string(),
        })?;
    let read = cyclonedx::read(&document).map_err(|source| ReportError::Sbom {
        name: sbom.name.to_owned(),
        source: Box::new(source),
    })?;
    let mut warnings: Vec<ReportWarning> = read
        .warnings
        .iter()
        .map(|w| ReportWarning {
            location: sbom.name.to_owned(),
            message: format!("{}: {}", w.location, w.message),
        })
        .collect();

    let product_type = document
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("firmware");
    let nodes = coverage::nodes(&read, product_type);
    let components = coverage::rows(&nodes);
    let coverage = coverage::totals(&components);
    let unresolved = unresolved::unresolved(&nodes);

    // Scans.
    let mut findings_all = Vec::new();
    for scan in scans {
        let parsed = match serde_json::from_slice::<Value>(scan.bytes) {
            Ok(value) if scan_input::is_scan_report(&value) => {
                scan_input::parse_scan_report(&value)
            }
            _ => vex::parse_findings(scan.bytes).map(|f| (f.findings, f.warnings)),
        };
        let (found, found_warnings) = parsed.map_err(|source| ReportError::Scan {
            name: scan.name.to_owned(),
            source,
        })?;
        warnings.extend(found_warnings.iter().map(|w| ReportWarning {
            location: scan.name.to_owned(),
            message: format!("{}: {}", w.location, w.message),
        }));
        findings_all.extend(found);
    }

    // VEX.
    let serial = document.get("serialNumber").and_then(Value::as_str);
    let identity = SbomIdentity {
        serial_number: serial,
    };
    let mut statements: BTreeSet<VexStatement> = BTreeSet::new();
    for input in vex {
        let parsed =
            parse_vex(input.bytes, input.name, &identity).map_err(|source| ReportError::Vex {
                name: input.name.to_owned(),
                source,
            })?;
        warnings.extend(parsed.warnings);
        statements.extend(parsed.statements);
    }
    let statements: Vec<VexStatement> = statements.into_iter().collect();
    let statements = (!vex.is_empty()).then_some(statements.as_slice());

    let (findings, vex_coverage) = if scans.is_empty() {
        let coverage = statements.map(|s| VexCoverage {
            statements: s.len() as u64,
            unmatched_statements: s.len() as u64,
            findings_covered: None,
        });
        (None, coverage)
    } else {
        let joined = findings::join(&read, &nodes, sbom.name, &findings_all, statements);
        warnings.extend(joined.warnings);
        (Some(joined.section), joined.vex)
    };

    // Validation.
    let violations = validate_cyclonedx_1_6(&document).err().unwrap_or_default();
    let profiles = validate_profiles(&document, &builtin_profiles());
    // Each node's index by its bom-ref; a finding that names no node counts against the
    // product (index 0).
    let index: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| n.doc_ref.as_deref().map(|r| (r, i)))
        .collect();
    let mut flagged: BTreeSet<usize> = BTreeSet::new();
    let mut profile_findings: Vec<(Option<usize>, ProfileFinding)> = profiles
        .findings
        .iter()
        .map(|f| {
            let node = f.r#ref.as_deref().and_then(|r| index.get(r).copied());
            flagged.insert(node.unwrap_or(0));
            let finding = ProfileFinding {
                check: f.check.clone(),
                severity: match f.severity {
                    validate::Severity::Error => "error",
                    validate::Severity::Warning => "warning",
                },
                profiles: f.profiles.clone(),
                component: node.and_then(|i| nodes.get(i)).map(|n| n.label.clone()),
                level: node.and_then(|i| nodes.get(i)).map(|n| n.level),
                pointer: node.is_none().then(|| f.path.clone()),
                message: f.message.clone(),
            };
            (node, finding)
        })
        .collect();
    // Document-level findings first, then by node in walk order (which follows content, not
    // the document's array order), then by check, message and pointer.
    profile_findings.sort_by(|(na, a), (nb, b)| {
        (na, &a.check, &a.message, &a.pointer, &a.profiles).cmp(&(
            nb,
            &b.check,
            &b.message,
            &b.pointer,
            &b.profiles,
        ))
    });
    let profile_findings: Vec<ProfileFinding> =
        profile_findings.into_iter().map(|(_, f)| f).collect();
    let flagged_nodes = flagged.len() as u64;
    let validation = Validation {
        schema: SchemaResult {
            valid: violations.is_empty(),
            violations: violations
                .iter()
                .map(|v| SchemaViolationEntry {
                    path: v.path.clone(),
                    message: v.message.clone(),
                })
                .collect(),
        },
        profiles: ProfileResult {
            profiles: profiles.profiles.clone(),
            passed: profiles.passed(),
            errors: profiles.errors as u64,
            warnings: profiles.warnings as u64,
            findings: profile_findings,
        },
    };

    // Score.
    let modules: Vec<_> = nodes.iter().filter(|n| unresolved::is_module(n)).collect();
    let counts = score::Counts {
        nodes: coverage.nodes,
        identified: coverage.identified.count,
        hashed: coverage.hash.count,
        licensed: coverage.licence.count,
        validated: coverage.nodes.saturating_sub(flagged_nodes),
        schema_valid: validation.schema.valid,
        modules: modules.len() as u64,
        modules_resolved: modules
            .iter()
            .filter(|n| unresolved::is_resolved(n))
            .count() as u64,
        vulnerabilities: findings.as_ref().map(|f| (f.closed, f.in_sbom)),
    };
    let score = score::score(&counts);

    warnings.sort();
    warnings.dedup();
    let mut report = ReadinessReport {
        schema: REPORT_SCHEMA,
        generated: timestamp.to_string(),
        tool: Tool {
            name: "rollcall",
            version: env!("CARGO_PKG_VERSION"),
        },
        product: ProductInfo {
            name: read.product.name.clone(),
            version: read.product.version.clone(),
        },
        summary: String::new(),
        score,
        coverage,
        components,
        unresolved,
        findings,
        vex: vex_coverage,
        validation,
        warnings,
    };
    report.summary = summary::summary(&report);
    Ok(report)
}

/// The report's component rows for `sbom` alone: one [`ComponentRow`] per node, the product
/// first, in the report's walk order (see the [module docs](self)). `rollcall diff` compares
/// two builds with them. Never panics; a malformed SBOM is a [`ReportError`].
pub fn component_rows(sbom: Input<'_>) -> Result<Vec<ComponentRow>, ReportError> {
    let document: Value =
        serde_json::from_slice(sbom.bytes).map_err(|e| ReportError::SbomJson {
            name: sbom.name.to_owned(),
            message: e.to_string(),
        })?;
    let read = cyclonedx::read(&document).map_err(|source| ReportError::Sbom {
        name: sbom.name.to_owned(),
        source: Box::new(source),
    })?;
    let product_type = document
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("firmware");
    Ok(coverage::rows(&coverage::nodes(&read, product_type)))
}

/// The report as canonical `rollcall-report/1` JSON: two-space-indented, keys in a fixed
/// order, ending in a newline.
pub fn to_json(report: &ReadinessReport) -> Result<String, ModelError> {
    to_canonical_json(report)
}
