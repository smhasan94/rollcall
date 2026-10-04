//! `rollcall diff`: what a pull request changes in a product's SBOM and findings, against its
//! base branch's build, and whether it may merge. `rollcall-action` posts the Markdown as
//! its pull-request comment and gates the check on the outcome.
//!
//! [`build`] reads each side's SBOM, `rollcall scan --json` report (`rollcall-scan/1`) and
//! `rollcall report --format json` report (`rollcall-report/1`), and returns a [`Diff`];
//! [`to_json`] renders it as `rollcall-diff/1` JSON (schema `docs/diff-schema.json`) and
//! [`to_markdown`] as the comment.
//!
//! # Inputs
//!
//! - **Head** (required SBOM; optional scan and report): the pull request's build.
//! - **Base** (all optional): the base branch's build, from its last workflow artifact. With
//!   no base SBOM there is nothing to compare with, and every head finding is **new**; a
//!   base SBOM without a base scan compares components but, again, makes every head finding
//!   new. [`BaseInfo::reason`] says which.
//!
//! The SBOMs are read with [`report::component_rows`]; a scan's findings are joined to their
//! component paths through the `bom-ref`s of the same side's SBOM. The reports are read only
//! for their `score.value` and `summary`.
//!
//! # Components
//!
//! Rows are keyed by path (names from the image down, no versions): a version bump is one
//! **changed** row, not an added and a removed one. See [`components`] for the rules.
//!
//! # Findings
//!
//! A head finding is the same as a base finding when both are on a component (or package)
//! of the same name and share an id or alias, whatever their `bom-ref`s and versions. Head
//! findings with no match are **new**; base findings with no match are **fixed**; matched
//! findings whose VEX triage changed (`suppressed`, `affected`, `unresolved`) are listed as
//! **triage changes**.
//!
//! # Gate
//!
//! With `--fail-on SEVERITY`, the gate counts the new findings that are open (VEX did not
//! suppress them) and at or above that severity (`unknown` is the lowest). Any such finding
//! makes the outcome `findings` and `rollcall diff` exit 1; findings below the threshold are
//! still listed. Without `--fail-on` nothing is gated.
//!
//! # Determinism
//!
//! The diff depends only on the inputs' contents: findings are sorted most severe first,
//! then by id, component and version; components by path then version. It carries no
//! timestamp and no file path. The JSON is two-space-indented with keys in a fixed order and
//! every field present; the Markdown uses LF line endings, escapes every input value
//! ([`md_cell`](crate::report::md_cell)) and shows at most [`MAX_ROWS`] rows per table.

pub mod components;
pub mod findings;
mod markdown;
mod model;
pub mod scan_rows;

use std::collections::BTreeMap;

pub use markdown::{MAX_ROWS, to_markdown};
pub use model::{
    BaseInfo, ComponentChange, ComponentDiff, ComponentEntry, Diff, FindingDiff, FindingEntry,
    Gate, GateOutcome, ScoreChange, TriageChange,
};
pub use scan_rows::{ReportSummary, ScanRow, read_report_summary, read_scan_rows};

use crate::model::{ModelError, to_canonical_json};
use crate::report::{self, ComponentRow, Input, ProductInfo, ReportError};
use crate::severity::Severity;

/// The `schema` of a [`Diff`].
pub const DIFF_SCHEMA: &str = "rollcall-diff/1";

/// [`BaseInfo::reason`] when no base SBOM was supplied.
pub const REASON_NO_BASE: &str = "No base artifact was found for this pull request's base branch";
/// [`BaseInfo::reason`] when the base has an SBOM but no scan.
pub const REASON_NO_BASE_SCAN: &str = "The base artifact has no scan";

/// One side of the diff: its SBOM, and optionally its scan and readiness report.
#[derive(Debug, Clone, Copy)]
pub struct Side<'a> {
    /// The CycloneDX 1.6 SBOM.
    pub sbom: Input<'a>,
    /// `rollcall scan --json` output for it.
    pub scan: Option<Input<'a>>,
    /// `rollcall report --format json` output for it.
    pub report: Option<Input<'a>>,
}

/// Why a diff could not be built. Every variant is a malformed input.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiffError {
    /// An SBOM cannot be read.
    #[error(transparent)]
    Sbom(#[from] ReportError),
    /// A scan or report is not JSON.
    #[error("{name}: not valid JSON: {message}")]
    Json {
        /// The input's name.
        name: String,
        /// Why.
        message: String,
    },
    /// A scan or report has the wrong `schema`.
    #[error("{name}: expected a {expected} document, found schema {found:?}")]
    Schema {
        /// The input's name.
        name: String,
        /// The schema it should have.
        expected: &'static str,
        /// The schema it has.
        found: Option<String>,
    },
    /// A field of a scan has the wrong type or is missing.
    #[error("{name}: {path}: expected {expected}")]
    Shape {
        /// The input's name.
        name: String,
        /// The field's path.
        path: String,
        /// What it should be.
        expected: &'static str,
    },
}

/// One side, read.
struct ReadSide {
    rows: Vec<ComponentRow>,
    scan: Option<findings::Located>,
    report: Option<ReportSummary>,
}

fn read_side(side: Side<'_>) -> Result<ReadSide, DiffError> {
    let rows = report::component_rows(side.sbom)?;
    let paths: BTreeMap<String, String> = rows
        .iter()
        .filter_map(|r| r.bom_ref.clone().map(|b| (b, r.path.clone())))
        .collect();
    let scan = match side.scan {
        Some(input) => Some(findings::Located::new(read_scan_rows(input)?, &paths)),
        None => None,
    };
    let report = side.report.map(read_report_summary).transpose()?;
    Ok(ReadSide { rows, scan, report })
}

fn product(rows: &[ComponentRow]) -> ProductInfo {
    match rows.iter().find(|r| r.level == "product") {
        Some(r) => ProductInfo {
            name: r.name.clone(),
            version: r.version.clone(),
        },
        None => ProductInfo {
            name: String::new(),
            version: None,
        },
    }
}

/// Builds the diff of `head` against `base` (none: no base artifact), gated at `fail_on`
/// (none: not gated). Never panics; any malformed input is a [`DiffError`].
pub fn build(
    head: Side<'_>,
    base: Option<Side<'_>>,
    fail_on: Option<Severity>,
) -> Result<Diff, DiffError> {
    let head = read_side(head)?;
    let base = base.map(read_side).transpose()?;

    let components = match &base {
        Some(b) => components::diff_components(&b.rows, &head.rows),
        None => ComponentDiff::default(),
    };
    let reason = match &base {
        None => Some(REASON_NO_BASE.to_owned()),
        Some(b) if b.scan.is_none() && head.scan.is_some() => Some(REASON_NO_BASE_SCAN.to_owned()),
        Some(_) => None,
    };
    let findings = match &head.scan {
        Some(h) => findings::diff_findings(base.as_ref().and_then(|b| b.scan.as_ref()), h),
        None => FindingDiff::default(),
    };
    let gate = findings::gate(&findings.new, fail_on);
    Ok(Diff {
        schema: DIFF_SCHEMA,
        product: product(&head.rows),
        base: BaseInfo {
            present: base.is_some(),
            product: base.as_ref().map(|b| product(&b.rows)),
            reason,
        },
        summary: head.report.as_ref().and_then(|r| r.summary.clone()),
        score: ScoreChange {
            head: head.report.as_ref().and_then(|r| r.score),
            base: base
                .as_ref()
                .and_then(|b| b.report.as_ref())
                .and_then(|r| r.score),
        },
        components,
        findings,
        gate,
    })
}

/// The diff as canonical `rollcall-diff/1` JSON: two-space-indented, keys in a fixed order,
/// ending in a newline.
pub fn to_json(diff: &Diff) -> Result<String, ModelError> {
    to_canonical_json(diff)
}
