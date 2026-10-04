//! The diff's data, serialised as `rollcall-diff/1` JSON (`docs/diff-schema.json`). Every
//! field is always present (absent values are `null`), keys are written in declaration order
//! and every list is sorted, so the JSON is stable.

use serde::Serialize;

use crate::report::ProductInfo;
use crate::severity::Severity;

/// The difference between a pull request's build (the head) and its base branch's build.
/// Built by [`build`](super::build).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// Always [`DIFF_SCHEMA`](super::DIFF_SCHEMA).
    pub schema: &'static str,
    /// The product the head SBOM describes.
    pub product: ProductInfo,
    /// What the head was compared with.
    pub base: BaseInfo,
    /// The head readiness report's plain-language summary, or `null` without `--report`.
    pub summary: Option<String>,
    /// The readiness scores.
    pub score: ScoreChange,
    /// Components added, removed and changed.
    pub components: ComponentDiff,
    /// Findings new, fixed and re-triaged.
    pub findings: FindingDiff,
    /// The gate: whether new open findings reach `--fail-on`.
    pub gate: Gate,
}

/// What the head was compared with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaseInfo {
    /// Whether a base SBOM was supplied.
    pub present: bool,
    /// The product the base SBOM describes, or `null` without one.
    pub product: Option<ProductInfo>,
    /// Why findings could not be compared with the base (no base, or a base without a scan),
    /// so every head finding counts as new; `null` when they were compared.
    pub reason: Option<String>,
}

/// The readiness scores (`score.value` of each `rollcall-report/1`), `null` where no report
/// was supplied (or it had no score).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScoreChange {
    /// The head's score.
    pub head: Option<u32>,
    /// The base's score.
    pub base: Option<u32>,
}

/// Components added, removed and changed, keyed by path (see
/// [`ComponentRow::path`](crate::report::ComponentRow::path)) and level.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ComponentDiff {
    /// Nodes only in the head, sorted by path, level, then version.
    pub added: Vec<ComponentEntry>,
    /// Nodes only in the base, sorted by path, level, then version.
    pub removed: Vec<ComponentEntry>,
    /// Nodes at the same path and level whose version or identifiers changed, sorted by
    /// path then level.
    pub changed: Vec<ComponentChange>,
}

/// A node added or removed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ComponentEntry {
    /// Its path.
    pub path: String,
    /// `product`, `image` or `component`.
    pub level: &'static str,
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: Option<String>,
    /// Whether it has a purl.
    pub purl: bool,
    /// Whether it has a CPE.
    pub cpe: bool,
}

/// A node whose version, purl or CPE changed between the base and the head.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ComponentChange {
    /// Its path.
    pub path: String,
    /// `product`, `image` or `component`.
    pub level: &'static str,
    /// Its name.
    pub name: String,
    /// Its version in the base.
    pub base_version: Option<String>,
    /// Its version in the head.
    pub head_version: Option<String>,
    /// Whether it had a purl in the base.
    pub base_purl: bool,
    /// Whether it has a purl in the head.
    pub head_purl: bool,
    /// Whether it had a CPE in the base.
    pub base_cpe: bool,
    /// Whether it has a CPE in the head.
    pub head_cpe: bool,
}

/// Findings new, fixed and re-triaged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FindingDiff {
    /// Whether a head scan was supplied (without one nothing is compared).
    pub scanned: bool,
    /// Every finding of the head scan.
    pub head_total: u64,
    /// The head scan's open (not suppressed) findings.
    pub head_open: u64,
    /// Head findings the base does not have (every head finding without a base scan), most
    /// severe first.
    pub new: Vec<FindingEntry>,
    /// Base findings the head no longer has, most severe first.
    pub fixed: Vec<FindingEntry>,
    /// Findings in both whose VEX triage changed, most severe first.
    pub changed: Vec<TriageChange>,
}

/// One finding of a `rollcall-scan/1` report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingEntry {
    /// The vulnerability id.
    pub id: String,
    /// Its other ids, sorted.
    pub aliases: Vec<String>,
    /// The normalised severity.
    pub severity: Severity,
    /// The component's path in its SBOM, or the reported package's name when the SBOM does
    /// not list it.
    pub component: String,
    /// The component's (or package's) name.
    pub name: String,
    /// Whether the finding is on a component of the SBOM.
    pub in_sbom: bool,
    /// The component's (or package's) version.
    pub version: Option<String>,
    /// The versions that fix it, sorted.
    pub fixed_versions: Vec<String>,
    /// `suppressed`, `affected` or `unresolved` (see `rollcall scan`).
    pub triage: String,
}

/// A finding in both scans whose VEX triage changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TriageChange {
    /// The head finding's id.
    pub id: String,
    /// The head finding's severity.
    pub severity: Severity,
    /// The head finding's component (see [`FindingEntry::component`]).
    pub component: String,
    /// The head finding's version.
    pub version: Option<String>,
    /// The triage in the base.
    pub base_triage: String,
    /// The triage in the head.
    pub head_triage: String,
}

/// The gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Gate {
    /// The `--fail-on` threshold, or `null` when nothing is gated.
    pub fail_on: Option<Severity>,
    /// New findings that are open (not suppressed by VEX) and at or above `fail_on` (0
    /// without a threshold).
    pub new_open_at_or_above: u64,
    /// `findings` when `new_open_at_or_above` is above 0 (`rollcall diff` exits 1), else
    /// `clean`.
    pub outcome: GateOutcome,
}

/// The gate's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateOutcome {
    /// No new open finding at or above the threshold.
    Clean,
    /// At least one.
    Findings,
}

impl GateOutcome {
    /// `clean` or `findings`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Findings => "findings",
        }
    }
}
