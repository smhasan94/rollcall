//! Scanner findings joined to the SBOM's components, and closed or kept open by VEX.

use std::collections::{BTreeMap, BTreeSet};

use super::coverage::{Node, share};
use super::model::{BySeverity, FindingItem, FindingsSection, ReportWarning, VexCoverage};
use super::vex_input::{VexStatement, VexStatus};
use crate::cyclonedx::Read;
use crate::model::Purl;
use crate::severity::{Severity, normalise_severity};
use crate::vex::{self, BuildEvidence, Finding, RuleSet};

/// A purl in canonical form, or as written if it does not parse.
fn canonical(purl: &str) -> String {
    Purl::new(purl).map_or_else(|_| purl.to_owned(), |p| p.as_str().to_owned())
}

/// The findings section, the VEX coverage (when `statements` is given) and warnings.
pub(super) struct Joined {
    pub section: FindingsSection,
    pub vex: Option<VexCoverage>,
    pub warnings: Vec<ReportWarning>,
}

/// Joins `findings` to the SBOM's components (as `rollcall vex` does: by purl, then cpe, then
/// name and version; merged across scanners) and decides each joined finding's status from
/// `statements`: closed when at least one statement matches it and every matching statement
/// is `not_affected` or `fixed`, else open. A statement matches a finding when one of its ids
/// is the finding's id or an alias, and it names the finding's component by `bom-ref` or
/// purl.
pub(super) fn join(
    read: &Read,
    nodes: &[Node<'_>],
    sbom_name: &str,
    findings: &[Finding],
    statements: Option<&[VexStatement]>,
) -> Joined {
    let report = vex::evaluate_document(
        &read.product,
        &read.refs,
        &BuildEvidence::new(),
        findings,
        &RuleSet::default(),
    );
    let warnings = report
        .warnings
        .iter()
        .map(|w| ReportWarning {
            location: sbom_name.to_owned(),
            message: format!("{}: {}", w.location, w.message),
        })
        .collect();
    let labels: BTreeMap<&str, &str> = nodes
        .iter()
        .filter_map(|n| n.doc_ref.as_deref().map(|r| (r, n.label.as_str())))
        .collect();
    let canonical_statements: Vec<(&VexStatement, Option<String>)> = statements
        .unwrap_or_default()
        .iter()
        .map(|s| (s, s.purl.as_deref().map(canonical)))
        .collect();
    let mut matched: BTreeSet<usize> = BTreeSet::new();
    let mut covered = 0u64;
    let mut items: Vec<(Severity, FindingItem)> = Vec::new();
    for finding in &report.unresolved {
        let severity = normalise_severity(finding.severity.as_deref());
        let package = match &finding.package.purl {
            Some(p) => p.as_str().to_owned(),
            None => match &finding.package.version {
                Some(v) => format!("{}@{v}", finding.package.name),
                None => finding.package.name.clone(),
            },
        };
        let mut aliases: Vec<String> = finding.aliases.iter().cloned().collect();
        aliases.sort();
        let (status, vex_status, component, bom_ref) = match &finding.component {
            None => ("not-in-sbom", None, None, None),
            Some(component) => {
                let mut ids: BTreeSet<&str> = finding.aliases.iter().map(String::as_str).collect();
                ids.insert(&finding.vulnerability);
                let purl = component.purl.as_ref().map(Purl::as_str);
                let statuses: BTreeSet<VexStatus> = canonical_statements
                    .iter()
                    .enumerate()
                    .filter(|(_, (s, s_purl))| {
                        s.ids.iter().any(|id| ids.contains(id.as_str()))
                            && (s.bom_ref.as_deref() == Some(component.bom_ref.as_str())
                                || (s_purl.is_some() && s_purl.as_deref() == purl))
                    })
                    .map(|(i, (s, _))| {
                        matched.insert(i);
                        s.status
                    })
                    .collect();
                if !statuses.is_empty() {
                    covered += 1;
                }
                let open = statuses.iter().find(|s| !s.closes()).copied();
                let (status, decided) = match (open, statuses.iter().next()) {
                    (Some(open), _) => ("open", Some(open)),
                    (None, Some(first)) => ("closed", Some(*first)),
                    (None, None) => ("open", None),
                };
                (
                    status,
                    decided.map(VexStatus::as_str),
                    Some(
                        labels
                            .get(component.bom_ref.as_str())
                            .map_or_else(|| component.name.clone(), |l| (*l).to_owned()),
                    ),
                    Some(component.bom_ref.clone()),
                )
            }
        };
        items.push((
            severity,
            FindingItem {
                id: finding.vulnerability.clone(),
                aliases,
                severity: severity.as_str(),
                scanner_severity: finding.severity.clone(),
                component,
                bom_ref,
                package,
                status,
                vex_status,
            },
        ));
    }
    items.sort_by(|(sa, a), (sb, b)| {
        sb.cmp(sa)
            .then_with(|| a.id.cmp(&b.id))
            .then_with(|| a.component.cmp(&b.component))
            .then_with(|| a.bom_ref.cmp(&b.bom_ref))
            .then_with(|| a.package.cmp(&b.package))
    });
    let mut open_by_severity = BySeverity::default();
    for (severity, item) in &items {
        if item.status == "open" {
            let slot = match severity {
                Severity::Critical => &mut open_by_severity.critical,
                Severity::High => &mut open_by_severity.high,
                Severity::Medium => &mut open_by_severity.medium,
                Severity::Low => &mut open_by_severity.low,
                Severity::Unknown => &mut open_by_severity.unknown,
            };
            *slot += 1;
        }
    }
    let count = |status: &str| items.iter().filter(|(_, i)| i.status == status).count() as u64;
    let (open, closed, not_in_sbom) = (count("open"), count("closed"), count("not-in-sbom"));
    let in_sbom = open + closed;
    let mut warnings: Vec<ReportWarning> = warnings;
    if in_sbom == 0 && not_in_sbom > 0 {
        warnings.push(ReportWarning {
            location: sbom_name.to_owned(),
            message: format!(
                "none of the scan's {not_in_sbom} finding(s) is for a component of this SBOM; \
                 was the scan run on another SBOM or build?"
            ),
        });
    }
    let vex = statements.map(|s| VexCoverage {
        statements: s.len() as u64,
        unmatched_statements: (s.len() - matched.len()) as u64,
        findings_covered: Some(share(covered, in_sbom)),
    });
    Joined {
        section: FindingsSection {
            total: items.len() as u64,
            in_sbom,
            not_in_sbom,
            open,
            closed,
            open_by_severity,
            items: items.into_iter().map(|(_, i)| i).collect(),
        },
        vex,
        warnings,
    }
}
