//! `rollcall scan`: normalised scanner findings for an SBOM, triaged with VEX documents, and
//! the exit code a CI gate gets.
//!
//! The CLI runs the scanners (grype, osv-scanner) and hands their JSON output to this module,
//! which does everything else without touching the process environment:
//!
//! 1. **Parse** each scanner's output with [`vex::parse_findings`](crate::vex::parse_findings).
//! 2. **Normalise** ([`normalise`]): join every finding to the SBOM's components and merge
//!    the reports of one vulnerability on one component, across scanners, exactly as
//!    `rollcall vex` does ([`vex::evaluate_document`](crate::vex::evaluate_document) with no
//!    rules). Each [`NormalisedFinding`] has an id (the lowest `CVE-` id among the merged ids
//!    and aliases, else the lowest id), the component's `bom-ref` (or none, for a package the
//!    SBOM does not list), a [`Severity`](crate::severity::Severity) (the highest any scanner
//!    gave, see [`crate::severity`]), the fixed versions, and the [`Source`]s that reported
//!    it.
//! 3. **Apply VEX** ([`apply`]): every claim in the `--vex` documents ([`parse_vex`]: OpenVEX,
//!    CycloneDX VEX standalone or embedded in an SBOM, or `rollcall-vex/1`) about the
//!    finding's vulnerability (by id or alias) and component (by `bom-ref`, BOM-Link into this
//!    SBOM, or purl) decides its [`Triage`]:
//!    - `not_affected`, `fixed` or `false_positive`: **suppressed**. The finding stays in the
//!      report, marked suppressed; it never counts toward `--fail-on`.
//!    - `affected`: **affected**. Resolved (someone has decided) but open: it counts toward
//!      `--fail-on`.
//!    - `under_investigation` (CycloneDX `in_triage`), no claim at all, or claims that
//!      disagree on the status (any two different statuses, even two suppressing ones; a
//!      warning names them): **unresolved**. Open, and counted by `--fail-on-unresolved`.
//!      Without `--vex` every finding is unresolved.
//!
//!    Within one OpenVEX document only the latest statements per vulnerability and product
//!    count (see [`parse_vex`]), so only statements with the same time, or from different
//!    documents, can disagree. A BOM-Link into a different SBOM (another serial number) is
//!    not applied, with a warning; one into another version of this SBOM is applied, with a
//!    warning. A CycloneDX document's plain `affects[].ref`s are BOM-Links into that
//!    document when it has a `serialNumber`.
//! 4. **Report** ([`ScanReport`]): `rollcall-scan/1` JSON ([`ScanReport::to_json`]) or a
//!    table ([`ScanReport::to_table`]); suppressed findings are listed in both.
//! 5. **Gate** ([`Gate::decide`]): the [`Outcome`] and its exit code.
//!
//! # Exit codes
//!
//! | Exit | Outcome | Meaning |
//! |------|---------|---------|
//! | 0 | [`Outcome::Clean`] | no gate failed |
//! | 1 | [`Outcome::Findings`] | an open (not suppressed) finding at or above `--fail-on` |
//! | 2 | [`Outcome::Unresolved`] | an unresolved finding, with `--fail-on-unresolved` |
//! | 3 | [`Outcome::ScannerFailed`] | a scanner was missing or failed, or its output was unreadable |
//!
//! 3 wins over 1, and 1 over 2. Severity `unknown` is the lowest level, so it fails only
//! `--fail-on unknown`.
//!
//! # `rollcall-scan/1`
//!
//! ```json
//! {
//!   "schema": "rollcall-scan/1",
//!   "sbom": {"serialNumber": "urn:uuid:…", "version": 1},
//!   "scanners": [{"name": "grype", "version": "0.119.0", "status": "ok", "offline": false}],
//!   "findings": [{
//!     "id": "CVE-2020-36464", "aliases": ["GHSA-qgwf-r2jj-2ccv"],
//!     "component": {"bom-ref": "…", "name": "heapless", "version": "0.5.0", "purl": "…"},
//!     "package": {"name": "heapless", "version": "0.5.0", "purl": "…"},
//!     "severity": "high", "fixed_versions": ["0.6.1"],
//!     "sources": [{"scanner": "grype", "id": "GHSA-qgwf-r2jj-2ccv", "severity": "High"}],
//!     "triage": "unresolved", "vex": []
//!   }],
//!   "summary": {"total": 1, "suppressed": 0, "affected": 0, "unresolved": 1,
//!               "open_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0}},
//!   "warnings": []
//! }
//! ```
//!
//! `scanners[].status` is `ok`, `skipped` (not installed, with `--scanner auto`) or
//! `failed`; `offline` is true with `--db-path`. `component` is `null` for a package that is
//! not in the SBOM. `vex` lists the claims that matched (`document`, `status`,
//! `justification`), `document` being the VEX file's name without its directory.
//!
//! # Determinism
//!
//! The report depends only on the contents of the inputs: findings are sorted by severity
//! (highest first), then id, then `bom-ref`; every list is sorted. It carries no timestamp
//! and no host path, so two runs on the same inputs and scanner database diff cleanly.

mod apply;
mod normalise;
mod report;
mod vexdoc;

pub use apply::{Applied, AppliedClaim, ScanFinding, Triage, apply};
pub use normalise::{
    Normalised, NormalisedFinding, Sbom, Source, normalise, normalise_scanner, overlap,
};
pub use report::{
    Gate, OpenBySeverity, Outcome, SCAN_SCHEMA, ScanReport, ScannerRun, ScannerStatus, Summary,
};
pub use vexdoc::{Claim, ClaimStatus, ClaimTarget, VexDocError, VexDocument, VexFormat, parse_vex};

use crate::vex::Finding;
use crate::warning::Warning;

/// Why a scan input could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The SBOM is not a readable CycloneDX document.
    #[error("{0}")]
    Sbom(String),
}

/// A labelled VEX document: the label (the file's name) is what the report cites.
pub type LabelledVex = (String, VexDocument);

/// Runs steps 2–4 of the [module docs](self): normalises `findings` (from every scanner that
/// ran) against `sbom`, applies the VEX `documents`, and builds the report with the scanner
/// runs and any further `warnings` (e.g. the scanner parsers').
pub fn scan(
    sbom: &Sbom,
    scanners: Vec<ScannerRun>,
    findings: &[Finding],
    documents: &[LabelledVex],
    warnings: Vec<Warning>,
) -> ScanReport {
    let normalised = normalise(sbom, findings);
    let applied = apply(normalised.findings, documents, sbom);
    let mut all = warnings;
    all.extend(sbom.warnings.iter().cloned());
    all.extend(normalised.warnings);
    all.extend(applied.warnings);
    ScanReport::new(&sbom.index, scanners, applied.findings, all)
}
