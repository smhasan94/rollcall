//! CSAF `vulnerabilities[]` from triaged scan findings. See the [module docs](super) for the
//! mapping.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::product_tree::SbomTree;
use crate::scan::{AppliedClaim, ClaimStatus, ScanFinding, Triage};
use crate::severity::Severity;
use crate::warning::Warning;

/// A `notes_t` item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Note {
    /// `summary`.
    pub category: &'static str,
    /// The text.
    pub text: String,
}

/// An `ids` item: a non-CVE id of the vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Id {
    /// The id's database (`GHSA`, `RUSTSEC`, …: the id's prefix).
    pub system_name: String,
    /// The id.
    pub text: String,
}

/// `product_status`: product ids by status, sorted; empty lists are left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProductStatus {
    /// Fixed (VEX `fixed`).
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub fixed: BTreeSet<String>,
    /// Affected (VEX `affected`).
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub known_affected: BTreeSet<String>,
    /// Not affected (VEX `not_affected`, CycloneDX `false_positive`).
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub known_not_affected: BTreeSet<String>,
    /// No claim, `under_investigation`, or conflicting claims.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub under_investigation: BTreeSet<String>,
}

/// A `flags` item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flag {
    /// The CSAF flag label.
    pub label: &'static str,
    /// The products it is about.
    pub product_ids: BTreeSet<String>,
}

/// A `threats` item (always category `impact`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Threat {
    /// `impact`.
    pub category: &'static str,
    /// The impact statement.
    pub details: String,
    /// The products it is about.
    pub product_ids: BTreeSet<String>,
}

/// A `remediations` item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Remediation {
    /// `vendor_fix`, `workaround` or `no_fix_planned` (from the claim's response), else
    /// `none_available` (the text naming any upstream fix).
    pub category: &'static str,
    /// The action statement.
    pub details: String,
    /// The products it is about.
    pub product_ids: BTreeSet<String>,
}

/// One `vulnerabilities[]` item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vulnerability {
    /// The CVE id, when the finding's id is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve: Option<String>,
    /// Justifications of `known_not_affected` products.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<Flag>,
    /// Every other id, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<Id>,
    /// One summary note.
    pub notes: Vec<Note>,
    /// The products by status.
    pub product_status: ProductStatus,
    /// Action statements of `known_affected` products.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub remediations: Vec<Remediation>,
    /// Impact statements of `known_not_affected` products.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub threats: Vec<Threat>,
}

/// Why the findings cannot be exported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{vulnerability} on {product}: the findings give it two statuses ({first}, {second})")]
pub struct ConflictingStatus {
    /// The vulnerability.
    pub vulnerability: String,
    /// The product id.
    pub product: String,
    /// One status.
    pub first: &'static str,
    /// The other.
    pub second: &'static str,
}

/// Whether `id` matches the CSAF `cve` pattern `^CVE-[0-9]{4}-[0-9]{4,}$`.
pub fn is_cve(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && number.len() >= 4
        && number.bytes().all(|b| b.is_ascii_digit())
}

/// The `system_name` of a non-CVE id: its prefix before the first `-` (`GHSA`, `RUSTSEC`,
/// `PYSEC`, …), else `other`.
pub fn system_name(id: &str) -> String {
    match id.split_once('-') {
        Some((prefix, _)) if !prefix.is_empty() => prefix.to_owned(),
        _ => "other".to_owned(),
    }
}

/// The CSAF flag for a VEX justification, in OpenVEX's words (which are CSAF's) or
/// CycloneDX's. `None` for anything else.
pub fn flag_of(justification: &str) -> Option<&'static str> {
    Some(match justification {
        "component_not_present" => "component_not_present",
        "vulnerable_code_not_present" | "code_not_present" => "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path" | "code_not_reachable" => {
            "vulnerable_code_not_in_execute_path"
        }
        "vulnerable_code_cannot_be_controlled_by_adversary"
        | "requires_configuration"
        | "requires_dependency"
        | "requires_environment" => "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist"
        | "protected_by_compiler"
        | "protected_at_runtime"
        | "protected_at_perimeter"
        | "protected_by_mitigating_control" => "inline_mitigations_already_exist",
        _ => return None,
    })
}

/// The CSAF `product_status` list a triaged finding goes in.
pub fn status_of(finding: &ScanFinding) -> &'static str {
    match finding.triage {
        Triage::Affected => "known_affected",
        Triage::Unresolved => "under_investigation",
        // Suppressed: every matching claim has the same status.
        Triage::Suppressed => match finding.vex.first().map(|c| c.status) {
            Some(ClaimStatus::Fixed) => "fixed",
            _ => "known_not_affected",
        },
    }
}

/// The claims of `finding` with `status`, in their sorted order.
fn claims_with<'a>(
    finding: &'a ScanFinding,
    status: &'a [ClaimStatus],
) -> impl Iterator<Item = &'a AppliedClaim> {
    finding.vex.iter().filter(|c| status.contains(&c.status))
}

struct Group<'a> {
    aliases: BTreeSet<String>,
    severity: Severity,
    scanners: BTreeSet<String>,
    findings: Vec<(&'a ScanFinding, String)>,
}

fn summary(id: &str, group: &Group<'_>) -> String {
    let mut text = String::new();
    let aliases: Vec<&str> = group
        .aliases
        .iter()
        .map(String::as_str)
        .filter(|a| *a != id)
        .collect();
    text.push_str(id);
    if !aliases.is_empty() {
        text.push_str(&format!(" (also {})", aliases.join(", ")));
    }
    let components: BTreeSet<String> = group
        .findings
        .iter()
        .filter_map(|(f, _)| f.finding.component.as_ref())
        .map(|c| match &c.version {
            Some(v) => format!("{} {v}", c.name),
            None => c.name.clone(),
        })
        .collect();
    let components: Vec<&str> = components.iter().map(String::as_str).collect();
    let scanners: Vec<&str> = group.scanners.iter().map(String::as_str).collect();
    text.push_str(&format!(
        " was reported for {} by {}. Highest severity reported: {}.",
        components.join(", "),
        if scanners.is_empty() {
            "the scan".to_owned()
        } else {
            scanners.join(", ")
        },
        group.severity.as_str()
    ));
    text
}

/// The product id a vulnerability names for SBOM component `component` of product
/// `product` (both `bom-ref`s): the relationship product "component as part of the
/// product", `<component bom-ref>@<product bom-ref>`. Content-derived and deterministic.
pub fn product_id_of(component: &str, product: &str) -> String {
    format!("{component}@{product}")
}

/// The CSAF remediation category for a claim's CycloneDX `analysis.response` values:
/// `update` or `rollback` → `vendor_fix`, else `workaround_available` → `workaround`, else
/// `will_not_fix` or `can_not_fix` → `no_fix_planned`. `None` when none of them is given.
pub fn remediation_of(response: &[String]) -> Option<&'static str> {
    let has = |words: &[&str]| response.iter().any(|r| words.contains(&r.as_str()));
    if has(&["update", "rollback"]) {
        Some("vendor_fix")
    } else if has(&["workaround_available"]) {
        Some("workaround")
    } else if has(&["will_not_fix", "can_not_fix"]) {
        Some("no_fix_planned")
    } else {
        None
    }
}

/// What the vulnerabilities of a CSAF document are built into (see [`crate::csaf`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// One item per finding id, sorted by id.
    pub vulnerabilities: Vec<Vulnerability>,
    /// The `bom-ref`s of the SBOM components (not the product) the vulnerabilities name: the
    /// product tree defines exactly these.
    pub components: BTreeSet<String>,
}

/// Builds one `vulnerabilities[]` item per finding id (see the [module docs](super)). Every
/// product id is the product's own `bom-ref` (for a finding on the product) or a relationship
/// product ([`product_id_of`]). Findings with no such product are left out, with a warning
/// each: a package the SBOM does not list, a component outside the SBOM's product tree, and a
/// component of CycloneDX scope `excluded` (not part of the product).
pub fn build(
    findings: &[ScanFinding],
    tree: &SbomTree,
    warnings: &mut Vec<Warning>,
) -> Result<Built, ConflictingStatus> {
    let product_ref = tree.product.bom_ref.as_str();
    let mut components: BTreeSet<String> = BTreeSet::new();
    let mut groups: BTreeMap<&str, Group<'_>> = BTreeMap::new();
    for f in findings {
        let Some(bom_ref) = f.finding.bom_ref() else {
            let p = &f.finding.package;
            warnings.push(Warning::new(
                format!("{} on {}", f.finding.id, p.name),
                "the package is not in the SBOM, so it has no CSAF product; left out",
            ));
            continue;
        };
        let product_id = if bom_ref == product_ref {
            bom_ref.to_owned()
        } else {
            match tree.children.iter().find(|c| c.node.bom_ref == bom_ref) {
                None => {
                    warnings.push(Warning::new(
                        format!("{} on {bom_ref}", f.finding.id),
                        "the component is not in the SBOM's product tree; left out",
                    ));
                    continue;
                }
                Some(c) if c.scope.as_deref() == Some("excluded") => {
                    warnings.push(Warning::new(
                        format!("{} on {} ({bom_ref})", f.finding.id, c.node.label()),
                        "the component has scope excluded, so it is not part of the product; \
                         left out",
                    ));
                    continue;
                }
                Some(_) => {
                    components.insert(bom_ref.to_owned());
                    product_id_of(bom_ref, product_ref)
                }
            }
        };
        let group = groups
            .entry(f.finding.id.as_str())
            .or_insert_with(|| Group {
                aliases: BTreeSet::new(),
                severity: Severity::Unknown,
                scanners: BTreeSet::new(),
                findings: Vec::new(),
            });
        group.aliases.extend(f.finding.aliases.iter().cloned());
        group.severity = group.severity.max(f.finding.severity);
        group
            .scanners
            .extend(f.finding.sources.iter().map(|s| s.scanner.to_string()));
        group.findings.push((f, product_id));
    }

    let mut out = Vec::with_capacity(groups.len());
    for (id, group) in &groups {
        let (cve, mut ids) = if is_cve(id) {
            (Some((*id).to_owned()), Vec::new())
        } else {
            (
                None,
                vec![Id {
                    system_name: system_name(id),
                    text: (*id).to_owned(),
                }],
            )
        };
        ids.extend(
            group
                .aliases
                .iter()
                .filter(|a| a.as_str() != *id)
                .map(|a| Id {
                    system_name: system_name(a),
                    text: a.clone(),
                }),
        );
        ids.sort();
        ids.dedup();

        let mut status = ProductStatus::default();
        let mut placed: BTreeMap<&str, &'static str> = BTreeMap::new();
        let mut flags: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        let mut threats: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut remediations: BTreeMap<(&'static str, String), BTreeSet<String>> = BTreeMap::new();
        for (f, product) in &group.findings {
            let product = product.as_str();
            let bucket = status_of(f);
            if let Some(first) = placed.insert(product, bucket)
                && first != bucket
            {
                return Err(ConflictingStatus {
                    vulnerability: (*id).to_owned(),
                    product: product.to_owned(),
                    first,
                    second: bucket,
                });
            }
            let list = match bucket {
                "fixed" => &mut status.fixed,
                "known_affected" => &mut status.known_affected,
                "known_not_affected" => &mut status.known_not_affected,
                _ => &mut status.under_investigation,
            };
            list.insert(product.to_owned());

            let name = f
                .finding
                .component
                .as_ref()
                .map_or(f.finding.package.name.as_str(), |c| c.name.as_str());
            match bucket {
                "known_not_affected" => {
                    let suppressing = [ClaimStatus::NotAffected, ClaimStatus::FalsePositive];
                    let flag = claims_with(f, &suppressing)
                        .filter_map(|c| c.justification.as_deref().and_then(flag_of))
                        .next();
                    let detail = claims_with(f, &suppressing).find_map(|c| c.detail.clone());
                    if let Some(label) = flag {
                        flags.entry(label).or_default().insert(product.to_owned());
                    }
                    // An impact statement: the claim's own, else (with no flag to say why)
                    // a generated one.
                    let details = detail.or_else(|| {
                        if flag.is_some() {
                            return None;
                        }
                        let claim = claims_with(f, &suppressing).next();
                        let document = claim.map_or("a VEX document", |c| c.document.as_str());
                        Some(match claim.map(|c| c.status) {
                            Some(ClaimStatus::FalsePositive) => format!(
                                "The finding is a false positive, per the VEX statement in \
                                 {document}."
                            ),
                            _ => format!(
                                "The product is not affected, per the VEX statement in \
                                 {document}."
                            ),
                        })
                    });
                    if let Some(details) = details {
                        threats
                            .entry(details)
                            .or_default()
                            .insert(product.to_owned());
                    }
                }
                "known_affected" => {
                    let affected = [ClaimStatus::Affected];
                    let detail = claims_with(f, &affected).find_map(|c| c.detail.clone());
                    let from_response =
                        claims_with(f, &affected).find_map(|c| remediation_of(&c.response));
                    let document = claims_with(f, &affected)
                        .next()
                        .map_or("a VEX document", |c| c.document.as_str());
                    let fixed: Vec<&str> = f
                        .finding
                        .fixed_versions
                        .iter()
                        .map(String::as_str)
                        .collect();
                    let (category, generated) = match from_response {
                        Some("vendor_fix") if fixed.is_empty() => {
                            ("vendor_fix", format!("Update {name} to a fixed version."))
                        }
                        Some("vendor_fix") => (
                            "vendor_fix",
                            format!("Update {name} to a fixed version: {}.", fixed.join(", ")),
                        ),
                        Some("workaround") => (
                            "workaround",
                            format!(
                                "A workaround is available, per the VEX statement in {document}."
                            ),
                        ),
                        Some(other) => (
                            other,
                            format!(
                                "No fix is planned for {name}, per the VEX statement in \
                                 {document}."
                            ),
                        ),
                        // No claimed response: an upstream fix is not a fixed firmware (and
                        // not a mitigation, which does not resolve the vulnerability: CSAF 2.0
                        // 3.2.3.12.1), so none is available yet; the text names the fix.
                        None if !fixed.is_empty() => (
                            "none_available",
                            format!(
                                "Upgrade {name} to a version fixed upstream: {}.",
                                fixed.join(", ")
                            ),
                        ),
                        None => (
                            "none_available",
                            format!("No fixed version of {name} is known."),
                        ),
                    };
                    remediations
                        .entry((category, detail.unwrap_or(generated)))
                        .or_default()
                        .insert(product.to_owned());
                }
                _ => {}
            }
        }

        out.push(Vulnerability {
            cve,
            ids,
            notes: vec![Note {
                category: "summary",
                text: summary(id, group),
            }],
            product_status: status,
            flags: flags
                .into_iter()
                .map(|(label, product_ids)| Flag { label, product_ids })
                .collect(),
            threats: threats
                .into_iter()
                .map(|(details, product_ids)| Threat {
                    category: "impact",
                    details,
                    product_ids,
                })
                .collect(),
            remediations: remediations
                .into_iter()
                .map(|((category, details), product_ids)| Remediation {
                    category,
                    details,
                    product_ids,
                })
                .collect(),
        });
    }
    Ok(Built {
        vulnerabilities: out,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_pattern_and_system_names() {
        for good in ["CVE-2024-23170", "CVE-1999-0001", "CVE-2026-1234567"] {
            assert!(is_cve(good), "{good}");
        }
        for bad in [
            "cve-2024-23170",
            "CVE-24-23170",
            "CVE-2024-123",
            "CVE-2024-12a4",
            "CVE-2024",
            "GHSA-qgwf-r2jj-2ccv",
            "",
        ] {
            assert!(!is_cve(bad), "{bad}");
        }
        assert_eq!(system_name("GHSA-qgwf-r2jj-2ccv"), "GHSA");
        assert_eq!(system_name("RUSTSEC-2020-0145"), "RUSTSEC");
        assert_eq!(system_name("nodash"), "other");
        assert_eq!(system_name("-x"), "other");
    }

    #[test]
    fn responses_map_to_remediation_categories() {
        let r = |words: &[&str]| {
            remediation_of(&words.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(r(&["update"]), Some("vendor_fix"));
        assert_eq!(r(&["rollback"]), Some("vendor_fix"));
        assert_eq!(r(&["workaround_available"]), Some("workaround"));
        assert_eq!(r(&["will_not_fix"]), Some("no_fix_planned"));
        assert_eq!(r(&["can_not_fix"]), Some("no_fix_planned"));
        // The most actionable response wins.
        assert_eq!(
            r(&["will_not_fix", "workaround_available"]),
            Some("workaround")
        );
        assert_eq!(r(&["workaround_available", "update"]), Some("vendor_fix"));
        assert_eq!(r(&[]), None);
        assert_eq!(r(&["bogus"]), None);
        assert_eq!(
            product_id_of("component:1", "product:2"),
            "component:1@product:2"
        );
    }

    #[test]
    fn every_justification_maps_to_a_csaf_flag() {
        for (justification, flag) in [
            ("component_not_present", "component_not_present"),
            ("vulnerable_code_not_present", "vulnerable_code_not_present"),
            ("code_not_present", "vulnerable_code_not_present"),
            (
                "vulnerable_code_not_in_execute_path",
                "vulnerable_code_not_in_execute_path",
            ),
            ("code_not_reachable", "vulnerable_code_not_in_execute_path"),
            (
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "requires_configuration",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "requires_dependency",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "requires_environment",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "inline_mitigations_already_exist",
                "inline_mitigations_already_exist",
            ),
            ("protected_by_compiler", "inline_mitigations_already_exist"),
            ("protected_at_runtime", "inline_mitigations_already_exist"),
            ("protected_at_perimeter", "inline_mitigations_already_exist"),
            (
                "protected_by_mitigating_control",
                "inline_mitigations_already_exist",
            ),
        ] {
            assert_eq!(flag_of(justification), Some(flag), "{justification}");
        }
        assert_eq!(flag_of("because"), None);
        assert_eq!(flag_of(""), None);
    }
}
