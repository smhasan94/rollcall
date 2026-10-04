//! Applying VEX claims to normalised findings. See the [module docs](super) for the rules.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Serialize, Serializer};

use super::LabelledVex;
use super::normalise::{NormalisedFinding, Sbom};
use super::vexdoc::{Claim, ClaimStatus, ClaimTarget};
use crate::model::Purl;
use crate::vex::SbomIndex;
use crate::warning::Warning;

/// What the VEX documents make of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Triage {
    /// `not_affected`, `fixed` or `false_positive`: shown, but never fails a gate.
    Suppressed,
    /// `affected`: resolved, still open.
    Affected,
    /// No claim, `under_investigation`, or conflicting claims: open and unresolved.
    Unresolved,
}

impl Triage {
    /// The name used in reports: `suppressed`, `affected` or `unresolved`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suppressed => "suppressed",
            Self::Affected => "affected",
            Self::Unresolved => "unresolved",
        }
    }

    /// Whether the finding is open (counts toward `--fail-on`): not suppressed.
    pub fn is_open(self) -> bool {
        self != Self::Suppressed
    }
}

impl Serialize for Triage {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A claim that matched a finding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AppliedClaim {
    /// The VEX document's label (its file name).
    pub document: String,
    /// The claimed status.
    pub status: ClaimStatus,
    /// The claimed justification, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// The claim's free-text detail ([`Claim::detail`]). Not part of `rollcall-scan/1`:
    /// never serialised, and claims that differ only in it (or in `response`) are reported
    /// once, so the scan report is unchanged by them.
    #[serde(skip)]
    pub detail: Option<String>,
    /// The claim's CycloneDX `analysis.response` ([`Claim::response`]). Not serialised, as
    /// `detail`.
    #[serde(skip)]
    pub response: Vec<String>,
}

/// A normalised finding with its triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanFinding {
    /// The finding.
    #[serde(flatten)]
    pub finding: NormalisedFinding,
    /// What the VEX documents make of it.
    pub triage: Triage,
    /// The claims that matched it, sorted.
    pub vex: Vec<AppliedClaim>,
}

/// The result of [`apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The findings, in the order given.
    pub findings: Vec<ScanFinding>,
    /// The documents' own warnings (prefixed with their label), BOM-Links into other SBOMs,
    /// and conflicting claims.
    pub warnings: Vec<Warning>,
}

fn same_purl(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    match (Purl::new(a), Purl::new(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Whether `target` names `finding`'s component (or, for a package the SBOM does not list,
/// its purl).
fn names(
    target: &ClaimTarget,
    finding: &NormalisedFinding,
    sbom: &SbomIndex,
    label: &str,
    warnings: &mut BTreeSet<Warning>,
) -> bool {
    let bom_ref = finding.bom_ref();
    match target {
        ClaimTarget::BomRef(r) => bom_ref == Some(r.as_str()),
        ClaimTarget::Purl(p) => {
            let sbom_spelling = bom_ref.and_then(|r| sbom.purl_of(r));
            let component = finding.component.as_ref().and_then(|c| c.purl.as_ref());
            let package = finding.package.purl.as_ref();
            sbom_spelling.is_some_and(|s| same_purl(s, p))
                || component.is_some_and(|c| same_purl(c.as_str(), p))
                || (finding.component.is_none()
                    && package.is_some_and(|c| same_purl(c.as_str(), p)))
        }
        ClaimTarget::BomLink {
            serial_number,
            version,
            bom_ref: linked,
        } => {
            if bom_ref != Some(linked.as_str()) {
                return false;
            }
            let ours = sbom.serial_number.as_ref().map(|s| s.as_str());
            if ours != Some(serial_number.as_str()) {
                warnings.insert(Warning::new(
                    format!("{label}: {} on {linked}", finding.id),
                    format!(
                        "the claim's BOM-Link is into another SBOM ({serial_number}, this one \
                         is {}); not applied",
                        ours.unwrap_or("without a serialNumber")
                    ),
                ));
                return false;
            }
            if *version != sbom.version {
                warnings.insert(Warning::new(
                    format!("{label}: {} on {linked}", finding.id),
                    format!(
                        "the claim's BOM-Link is into version {version} of this SBOM, which is \
                         version {}; applied",
                        sbom.version
                    ),
                ));
            }
            true
        }
    }
}

fn about_vulnerability(claim: &Claim, ids: &BTreeSet<String>) -> bool {
    std::iter::once(&claim.vulnerability)
        .chain(&claim.aliases)
        .any(|id| ids.contains(&id.to_ascii_uppercase()))
}

/// Applies every claim of `documents` to `findings` (see the [module docs](super)).
pub fn apply(
    findings: Vec<NormalisedFinding>,
    documents: &[LabelledVex],
    scanned: &Sbom,
) -> Applied {
    let sbom = &scanned.index;
    let root = scanned.product.path();
    let product_ref = scanned
        .refs
        .iter()
        .find(|(_, path)| **path == root)
        .map(|(r, _)| r.as_str());
    let product_purl = sbom
        .product
        .as_ref()
        .and_then(|p| p.get("purl"))
        .and_then(|p| p.as_str());
    let names_product = |t: &ClaimTarget| match t {
        ClaimTarget::BomRef(r) => product_ref == Some(r.as_str()),
        ClaimTarget::BomLink {
            serial_number,
            bom_ref,
            ..
        } => {
            product_ref == Some(bom_ref.as_str())
                && sbom.serial_number.as_ref().map(|s| s.as_str()) == Some(serial_number.as_str())
        }
        ClaimTarget::Purl(p) => product_purl.is_some_and(|ours| same_purl(ours, p)),
    };
    let mut warnings: BTreeSet<Warning> = BTreeSet::new();
    for (label, document) in documents {
        for w in &document.warnings {
            warnings.insert(Warning::new(
                format!("{label}: {}", w.location),
                w.message.clone(),
            ));
        }
        for claim in &document.claims {
            if !claim.products.is_empty() && !claim.products.iter().any(names_product) {
                warnings.insert(Warning::new(
                    format!("{label}: {}", claim.vulnerability),
                    "the statement's product (with subcomponents) is not this SBOM's \
                     metadata.component; its subcomponents are matched anyway",
                ));
            }
        }
    }
    let mut out = Vec::with_capacity(findings.len());
    for finding in findings {
        let ids = finding.ids();
        let mut matched: BTreeSet<AppliedClaim> = BTreeSet::new();
        for (label, document) in documents {
            for claim in &document.claims {
                if !about_vulnerability(claim, &ids) {
                    continue;
                }
                let mut hit = false;
                for target in &claim.targets {
                    // Every target is checked, so that a BOM-Link into another SBOM is
                    // reported even when another target matches.
                    hit |= names(target, &finding, sbom, label, &mut warnings);
                }
                if hit {
                    matched.insert(AppliedClaim {
                        document: label.clone(),
                        status: claim.status,
                        justification: claim.justification.clone(),
                        detail: claim.detail.clone(),
                        response: claim.response.clone(),
                    });
                }
            }
        }
        // Claims that differ only in their detail or response are one claim to the report.
        // The detail kept is the lexicographically greatest (a detail always beats none):
        // arbitrary, but deterministic. The responses are the union of all of them, so none
        // is lost.
        let mut merged: BTreeMap<(String, ClaimStatus, Option<String>), AppliedClaim> =
            BTreeMap::new();
        for claim in matched {
            let key = (
                claim.document.clone(),
                claim.status,
                claim.justification.clone(),
            );
            // `matched` is sorted, so a later claim has the greater detail.
            let mut claim = claim;
            if let Some(earlier) = merged.remove(&key) {
                let union: BTreeSet<String> =
                    earlier.response.into_iter().chain(claim.response).collect();
                claim.response = union.into_iter().collect();
            }
            merged.insert(key, claim);
        }
        let matched = merged;
        let statuses: BTreeSet<ClaimStatus> = matched.values().map(|c| c.status).collect();
        let triage = match statuses.iter().collect::<Vec<_>>().as_slice() {
            [] => Triage::Unresolved,
            [one] => match one {
                ClaimStatus::NotAffected | ClaimStatus::Fixed | ClaimStatus::FalsePositive => {
                    Triage::Suppressed
                }
                ClaimStatus::Affected => Triage::Affected,
                ClaimStatus::UnderInvestigation => Triage::Unresolved,
            },
            _ => {
                let described: Vec<String> = matched
                    .values()
                    .map(|c| format!("{} ({})", c.status, c.document))
                    .collect();
                let component = finding.component.as_ref().map_or_else(
                    || finding.package.name.clone(),
                    |c| format!("{} ({})", c.name, c.bom_ref),
                );
                warnings.insert(Warning::new(
                    format!("{} on {component}", finding.id),
                    format!(
                        "conflicting VEX claims: {}; finding left unresolved",
                        described.join(", ")
                    ),
                ));
                Triage::Unresolved
            }
        };
        out.push(ScanFinding {
            finding,
            triage,
            vex: matched.into_values().collect(),
        });
    }
    Applied {
        findings: out,
        warnings: warnings.into_iter().collect(),
    }
}
