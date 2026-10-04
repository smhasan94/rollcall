//! Normalising scanner findings: one entry per vulnerability per SBOM component, whichever
//! scanners reported it and under whichever ids.
//!
//! Joining a finding to components and merging connected ids is `rollcall vex`'s evaluator
//! run with no rules ([`vex::evaluate_document`]), so `scan` and `vex` agree on what a
//! finding is about and what it is called. This module adds what the evaluator does not
//! keep: which scanner reported each merged entry, and the highest severity among them.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::ScanError;
use crate::cyclonedx;
use crate::model::{NodePath, Product};
use crate::severity::{Severity, normalise_severity};
use crate::vex::{
    self, BuildEvidence, ComponentRef, Finding, Package, RuleSet, SbomIndex, Scanner, Unresolved,
};
use crate::warning::Warning;

/// The SBOM being scanned: its product, its own `bom-ref`s and its identity.
#[derive(Debug, Clone)]
pub struct Sbom {
    /// The product the SBOM describes.
    pub product: Product,
    /// The document's `bom-ref` → node path table.
    pub refs: BTreeMap<String, NodePath>,
    /// The serial number, version and purls as written.
    pub index: SbomIndex,
    /// What the reader could not represent.
    pub warnings: Vec<Warning>,
}

impl Sbom {
    /// Reads a CycloneDX JSON SBOM. Never panics; a malformed document is a
    /// [`ScanError::Sbom`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScanError> {
        let read = cyclonedx::read_bytes(bytes).map_err(|e| ScanError::Sbom(e.to_string()))?;
        let index = SbomIndex::from_bytes(bytes).map_err(|e| ScanError::Sbom(e.to_string()))?;
        Ok(Self {
            product: read.product,
            refs: read.refs,
            index,
            warnings: read.warnings,
        })
    }
}

/// One scanner's report of a vulnerability that went into a [`NormalisedFinding`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Source {
    /// The scanner.
    pub scanner: Scanner,
    /// The id it reported.
    pub id: String,
    /// Its severity, as it wrote it.
    pub severity: Option<String>,
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("Source", 3)?;
        st.serialize_field("scanner", &self.scanner.to_string())?;
        st.serialize_field("id", &self.id)?;
        if let Some(severity) = &self.severity {
            st.serialize_field("severity", severity)?;
        } else {
            st.skip_field("severity")?;
        }
        st.end()
    }
}

/// One vulnerability on one component (or one package the SBOM does not list), merged
/// across scanners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NormalisedFinding {
    /// The id: the lowest `CVE-` id among the merged ids and aliases, else the lowest id.
    pub id: String,
    /// Every other id of the vulnerability.
    pub aliases: BTreeSet<String>,
    /// The SBOM component, or `None` when the reported package is not in the SBOM.
    pub component: Option<ComponentRef>,
    /// The package as (the first) scanner reported it.
    pub package: Package,
    /// The highest severity any scanner gave.
    pub severity: Severity,
    /// Versions it is fixed in, from every scanner.
    pub fixed_versions: BTreeSet<String>,
    /// The scanners' reports.
    pub sources: BTreeSet<Source>,
}

/// What a finding is about: an SBOM component (by `bom-ref`) or an unlisted package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Component(String),
    Package(Package),
}

fn target_of(component: Option<&ComponentRef>, package: &Package) -> Target {
    match component {
        Some(c) => Target::Component(c.bom_ref.clone()),
        None => Target::Package(package.clone()),
    }
}

fn upper_ids<'a>(id: &'a str, aliases: impl IntoIterator<Item = &'a String>) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = aliases
        .into_iter()
        .map(|a| a.to_ascii_uppercase())
        .collect();
    ids.insert(id.to_ascii_uppercase());
    ids
}

impl NormalisedFinding {
    /// The id and every alias, in ASCII upper case (how ids are compared).
    pub fn ids(&self) -> BTreeSet<String> {
        upper_ids(&self.id, &self.aliases)
    }

    /// The component's `bom-ref`, if the finding is about an SBOM component.
    pub fn bom_ref(&self) -> Option<&str> {
        self.component.as_ref().map(|c| c.bom_ref.as_str())
    }

    fn target(&self) -> Target {
        target_of(self.component.as_ref(), &self.package)
    }

    /// Sort key: severity (highest first), then id, then `bom-ref`, then package.
    pub(super) fn sort_key(&self) -> (Reverse<Severity>, &str, Option<&str>, &Package) {
        (
            Reverse(self.severity),
            self.id.as_str(),
            self.bom_ref(),
            &self.package,
        )
    }
}

/// The result of [`normalise`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalised {
    /// The findings, sorted (see [`NormalisedFinding`]'s order in the module docs).
    pub findings: Vec<NormalisedFinding>,
    /// Components the SBOM gave no `bom-ref`.
    pub warnings: Vec<Warning>,
}

fn join_only(sbom: &Sbom, findings: &[Finding]) -> vex::Report {
    vex::evaluate_document(
        &sbom.product,
        &sbom.refs,
        &BuildEvidence::new(),
        findings,
        &RuleSet::default(),
    )
}

fn base(entry: &Unresolved) -> NormalisedFinding {
    NormalisedFinding {
        id: entry.vulnerability.clone(),
        aliases: entry.aliases.clone(),
        component: entry.component.clone(),
        package: entry.package.clone(),
        severity: Severity::Unknown,
        fixed_versions: entry.fixed_in.clone(),
        sources: BTreeSet::new(),
    }
}

/// Normalises `findings` (from any number of scanners) against `sbom`. Deterministic: the
/// result does not depend on the order of `findings`.
pub fn normalise(sbom: &Sbom, findings: &[Finding]) -> Normalised {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort();
    sorted.dedup();

    // Where each raw finding lands, joined on its own.
    let mut landed: Vec<(Target, BTreeSet<String>, &Finding)> = Vec::new();
    for finding in &sorted {
        let alone = join_only(sbom, std::slice::from_ref(*finding));
        let ids = upper_ids(&finding.id, &finding.aliases);
        for entry in &alone.unresolved {
            landed.push((
                target_of(entry.component.as_ref(), &entry.package),
                ids.clone(),
                finding,
            ));
        }
    }

    let owned: Vec<Finding> = sorted.into_iter().cloned().collect();
    let merged = join_only(sbom, &owned);
    let mut out: Vec<NormalisedFinding> = merged
        .unresolved
        .iter()
        .map(|entry| {
            let mut finding = base(entry);
            let target = finding.target();
            let ids = finding.ids();
            for (t, raw_ids, raw) in &landed {
                if *t == target && !raw_ids.is_disjoint(&ids) {
                    finding.severity = finding
                        .severity
                        .max(normalise_severity(raw.severity.as_deref()));
                    finding.sources.insert(Source {
                        scanner: raw.scanner,
                        id: raw.id.clone(),
                        severity: raw.severity.clone(),
                    });
                }
            }
            finding
        })
        .collect();
    out.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Normalised {
        findings: out,
        warnings: merged.warnings,
    }
}

/// [`normalise`] of only `scanner`'s findings: what that scanner alone reports.
pub fn normalise_scanner(sbom: &Sbom, findings: &[Finding], scanner: Scanner) -> Normalised {
    let own: Vec<Finding> = findings
        .iter()
        .filter(|f| f.scanner == scanner)
        .cloned()
        .collect();
    normalise(sbom, &own)
}

/// The findings two scanners both report: every pair whose ids and aliases intersect,
/// whatever their targets, so a caller can check the two scanners agree on the component
/// and the id. Sorted as `a` is.
pub fn overlap<'a>(
    a: &'a [NormalisedFinding],
    b: &'a [NormalisedFinding],
) -> Vec<(&'a NormalisedFinding, &'a NormalisedFinding)> {
    let mut pairs = Vec::new();
    for x in a {
        let ids = x.ids();
        for y in b {
            if !y.ids().is_disjoint(&ids) {
                pairs.push((x, y));
            }
        }
    }
    pairs
}
