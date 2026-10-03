//! The plain-language summary at the top of a report, for a reader who is not an engineer.
//! It is built from counts only (never names or versions), so a dependency bump that keeps
//! every count leaves it unchanged.

use super::model::ReadinessReport;

/// `1 thing`, `2 things`.
fn count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The summary paragraph for `report` (whose `summary` is ignored).
pub(super) fn summary(report: &ReadinessReport) -> String {
    let c = &report.coverage;
    let images = report
        .components
        .iter()
        .filter(|r| r.level == "image")
        .count() as u64;
    let components = report
        .components
        .iter()
        .filter(|r| r.level == "component")
        .count() as u64;
    let mut out = Vec::new();
    out.push(format!(
        "This report checks how ready the software bill of materials (SBOM) of {} is to hand \
         to a customer or regulator. Its readiness score is {} out of 100.",
        match &report.product.version {
            Some(v) => format!("{} {v}", report.product.name),
            None => report.product.name.clone(),
        },
        report.score.value
    ));
    out.push(format!(
        "The SBOM lists {} in total: the product, {} and {}. {} of them carry an identifier \
         (a PURL or CPE) that vulnerability databases can match, {} a file hash that proves \
         exactly which file was shipped, and {} a licence.",
        count(c.nodes, "item", "items"),
        count(images, "firmware image", "firmware images"),
        count(components, "software component", "software components"),
        c.identified.count,
        c.hash.count,
        c.licence.count
    ));
    let by_reason = |reason: &str| {
        report
            .unresolved
            .iter()
            .filter(|u| u.reason == reason)
            .count() as u64
    };
    let (not_in_db, no_identifier) = (
        by_reason(super::unresolved::NOT_IN_DB),
        by_reason(super::unresolved::NO_IDENTIFIER),
    );
    if not_in_db == 0 && no_identifier == 0 {
        out.push("No unresolved modules.".to_owned());
    }
    if not_in_db > 0 {
        out.push(format!(
            "{} not in rollcall's identifier database, so {} identity may be incomplete (see \
             Unresolved modules).",
            if not_in_db == 1 {
                "1 module is".to_owned()
            } else {
                format!("{not_in_db} modules are")
            },
            if not_in_db == 1 { "its" } else { "their" }
        ));
    }
    if no_identifier > 0 {
        out.push(format!(
            "{} no PURL or CPE, so scanners cannot match {} (see Unresolved modules).",
            if no_identifier == 1 {
                "1 component has".to_owned()
            } else {
                format!("{no_identifier} components have")
            },
            if no_identifier == 1 { "it" } else { "them" }
        ));
    }
    let profiles = &report.validation.profiles;
    match (
        report.validation.schema.valid,
        profiles.errors,
        profiles.warnings,
    ) {
        (true, 0, 0) => out.push(
            "The SBOM is valid CycloneDX 1.6 and meets every CISA 2026 and EU Cyber \
             Resilience Act minimum element rollcall checks."
                .to_owned(),
        ),
        (true, errors, warnings) => out.push(format!(
            "The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act \
             checks found {} to fix and {}.",
            count(errors, "problem", "problems"),
            count(warnings, "recommendation", "recommendations")
        )),
        (false, errors, warnings) => out.push(format!(
            "The SBOM is not valid CycloneDX 1.6, which must be fixed first; the CISA 2026 \
             and EU Cyber Resilience Act checks found {} to fix and {}.",
            count(errors, "problem", "problems"),
            count(warnings, "recommendation", "recommendations")
        )),
    }
    match &report.findings {
        None => out.push(
            "No vulnerability scan was supplied, so known vulnerabilities were not checked \
             and are not part of the score."
                .to_owned(),
        ),
        Some(f) => {
            let mut text = format!(
                "A vulnerability scan was supplied: {} this product's components; {} \
                 still open ({} critical, {} high) and {} closed by VEX statements (not \
                 affected or fixed).",
                if f.in_sbom == 1 {
                    "1 known vulnerability affects".to_owned()
                } else {
                    format!("{} known vulnerabilities affect", f.in_sbom)
                },
                if f.open == 1 {
                    "1 is".to_owned()
                } else {
                    format!("{} are", f.open)
                },
                f.open_by_severity.critical,
                f.open_by_severity.high,
                f.closed
            );
            if f.not_in_sbom > 0 {
                text.push_str(&format!(
                    " The scan also reported {} for packages this SBOM does not list.",
                    count(f.not_in_sbom, "finding", "findings")
                ));
            }
            out.push(text);
        }
    }
    if !report.warnings.is_empty() {
        out.push(format!(
            "rollcall noted {} about the inputs (see Warnings).",
            count(report.warnings.len() as u64, "problem", "problems")
        ));
    }
    out.join(" ")
}
