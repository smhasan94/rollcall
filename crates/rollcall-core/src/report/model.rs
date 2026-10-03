//! The readiness report's data, serialised as `rollcall-report/1` JSON
//! (`docs/report-schema.json`). Every field is always present (absent values are `null`),
//! keys are written in declaration order and every list is sorted, so the JSON is stable.

use serde::Serialize;

/// A readiness report for one SBOM. Built by [`build`](super::build).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessReport {
    /// Always [`REPORT_SCHEMA`](super::REPORT_SCHEMA).
    pub schema: &'static str,
    /// When the report was made (`--timestamp`, else the current time), RFC 3339 UTC.
    pub generated: String,
    /// The tool that made it.
    pub tool: Tool,
    /// The product the SBOM describes.
    pub product: ProductInfo,
    /// The plain-language summary for a non-engineer reader.
    pub summary: String,
    /// The readiness score and how it was earned.
    pub score: Score,
    /// Coverage totals over every node.
    pub coverage: Coverage,
    /// One row per node: the product, each image, each component at any depth.
    pub components: Vec<ComponentRow>,
    /// Modules the identifier database did not resolve and components with no identifier.
    pub unresolved: Vec<UnresolvedEntry>,
    /// The scanner findings, or `null` when no scan was supplied.
    pub findings: Option<FindingsSection>,
    /// VEX coverage, or `null` when no VEX document was supplied.
    pub vex: Option<VexCoverage>,
    /// Schema and regulator-profile validation of the SBOM.
    pub validation: Validation,
    /// Problems with the inputs, sorted.
    pub warnings: Vec<ReportWarning>,
}

/// The tool that made a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tool {
    /// `rollcall`.
    pub name: &'static str,
    /// rollcall's version.
    pub version: &'static str,
}

/// The product the SBOM describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductInfo {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: Option<String>,
}

/// The readiness score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Score {
    /// The score out of 100: `basis_points / 100`, rounded down.
    pub value: u32,
    /// The score in basis points (0 to 10000), rounded down.
    pub basis_points: u32,
    /// The total weight of the assessed categories (100, or 90 without a scan).
    pub weight_assessed: u32,
    /// Whether a vulnerability scan was supplied (and so the vulnerabilities category
    /// assessed).
    pub scan_supplied: bool,
    /// Each category, in a fixed order.
    pub categories: Vec<Category>,
}

/// One category of the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Category {
    /// A stable id: `identified`, `hashed`, `licensed`, `validation`, `modules`,
    /// `vulnerabilities`.
    pub id: &'static str,
    /// Its weight (points out of 100).
    pub weight: u32,
    /// Whether it was assessed (only `vulnerabilities` can be unassessed: no scan).
    pub assessed: bool,
    /// How many of `denominator` meet it.
    pub numerator: u64,
    /// How many were counted.
    pub denominator: u64,
    /// The points earned, in basis points of a point (`weight × 10000 × numerator /
    /// denominator`, rounded down; the full weight when the denominator is 0; 0 when not
    /// assessed).
    pub earned: u64,
}

/// A count and its share of the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Share {
    /// How many.
    pub count: u64,
    /// `count / total` in basis points, rounded down (0 when the total is 0).
    pub basis_points: u32,
}

/// Coverage totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Coverage {
    /// Every node: the product, the images and every component at any depth.
    pub nodes: u64,
    /// Nodes with a purl.
    pub purl: Share,
    /// Nodes with a CPE.
    pub cpe: Share,
    /// Nodes with a purl or a CPE.
    pub identified: Share,
    /// Nodes with at least one hash.
    pub hash: Share,
    /// Nodes with a licence.
    pub licence: Share,
}

/// One node of the SBOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentRow {
    /// `product`, `image` or `component`.
    pub level: &'static str,
    /// The names from the image down, joined with ` / ` (the product's own name for the
    /// product). Versions are left out, so a version bump keeps a row's path.
    pub path: String,
    /// The CycloneDX `type` (e.g. `firmware`, `library`, `operating-system`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: Option<String>,
    /// Its `bom-ref` in the SBOM.
    pub bom_ref: Option<String>,
    /// Whether it has a purl.
    pub purl: bool,
    /// Whether it has a CPE.
    pub cpe: bool,
    /// Whether it has at least one hash.
    pub hash: bool,
    /// Whether it has a licence.
    pub licence: bool,
}

/// A module the identifier database did not resolve, or a component with no identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UnresolvedEntry {
    /// The node's path (see [`ComponentRow::path`]).
    pub path: String,
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: Option<String>,
    /// `module-not-in-identifier-db` or `no-identifier`.
    pub reason: &'static str,
    /// A paste-ready identifier-database entry to fill in (see
    /// [`identify::stub`](crate::identify::stub())).
    pub hint: String,
}

/// The scanner findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingsSection {
    /// Every finding, merged across scanners (one per vulnerability and component or
    /// package).
    pub total: u64,
    /// Findings joined to a component of the SBOM.
    pub in_sbom: u64,
    /// Findings for packages that are not components of the SBOM.
    pub not_in_sbom: u64,
    /// Joined findings that are still open.
    pub open: u64,
    /// Joined findings a VEX statement closes (`not_affected` or `fixed`).
    pub closed: u64,
    /// The open findings by severity.
    pub open_by_severity: BySeverity,
    /// Every finding, most severe first.
    pub items: Vec<FindingItem>,
}

/// Counts per normalised severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct BySeverity {
    /// Critical.
    pub critical: u64,
    /// High.
    pub high: u64,
    /// Medium (or moderate).
    pub medium: u64,
    /// Low (or negligible).
    pub low: u64,
    /// No severity or an unrecognised one.
    pub unknown: u64,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingItem {
    /// The vulnerability id (the lowest `CVE-` id of its aliases, else the lowest id).
    pub id: String,
    /// Its other ids, sorted.
    pub aliases: Vec<String>,
    /// The normalised severity: `critical`, `high`, `medium`, `low` or `unknown`.
    pub severity: &'static str,
    /// The severity as the scanner wrote it.
    pub scanner_severity: Option<String>,
    /// The component's path, when the finding is joined to one.
    pub component: Option<String>,
    /// The component's `bom-ref` in the SBOM, when joined.
    pub bom_ref: Option<String>,
    /// The package the scanner reported: `name@version` or its purl.
    pub package: String,
    /// `open`, `closed` or `not-in-sbom`.
    pub status: &'static str,
    /// The VEX status that decides it (`not_affected`, `affected`, `fixed`,
    /// `under_investigation`), or `null` when no statement matches.
    pub vex_status: Option<&'static str>,
}

/// VEX coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VexCoverage {
    /// Statements read: one per vulnerability and product (an OpenVEX product, a CycloneDX
    /// `affects` entry).
    pub statements: u64,
    /// Statements that match no finding (or every statement, without a scan).
    pub unmatched_statements: u64,
    /// Joined findings with at least one matching statement, with their share of the joined
    /// findings; `null` without a scan.
    pub findings_covered: Option<Share>,
}

/// Validation results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Validation {
    /// The CycloneDX 1.6 schema check.
    pub schema: SchemaResult,
    /// The built-in regulator profiles.
    pub profiles: ProfileResult,
}

/// The CycloneDX 1.6 schema check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SchemaResult {
    /// Whether the SBOM is valid.
    pub valid: bool,
    /// Every violation, sorted.
    pub violations: Vec<SchemaViolationEntry>,
}

/// One schema violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SchemaViolationEntry {
    /// The JSON pointer.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

/// The regulator-profile checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileResult {
    /// The profiles run.
    pub profiles: Vec<String>,
    /// Whether no finding is an error.
    pub passed: bool,
    /// Error findings.
    pub errors: u64,
    /// Warning findings.
    pub warnings: u64,
    /// Every finding: document-level ones first, then by node in walk order (by content, not
    /// the document's array order), then by check, message and pointer.
    pub findings: Vec<ProfileFinding>,
}

/// One profile finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileFinding {
    /// The check id.
    pub check: String,
    /// `error` or `warning`.
    pub severity: &'static str,
    /// The profiles requiring it.
    pub profiles: Vec<String>,
    /// The node's path, or `null` for a document-level finding.
    pub component: Option<String>,
    /// The node's level (`product`, `image` or `component`), or `null` for a
    /// document-level finding.
    pub level: Option<&'static str>,
    /// The JSON pointer of a document-level finding; `null` for a finding about a node
    /// (whose pointer is positional, and would change when a sibling is added).
    pub pointer: Option<String>,
    /// What is wrong.
    pub message: String,
}

/// A problem with an input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ReportWarning {
    /// The input it is about (the SBOM, or a scan or VEX file by name).
    pub location: String,
    /// What is wrong.
    pub message: String,
}
