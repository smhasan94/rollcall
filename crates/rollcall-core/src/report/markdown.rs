//! The report as GitHub-flavoured Markdown: LF line endings, one table row per item, every
//! value from the inputs escaped with [`md_cell`].

use std::collections::BTreeMap;

use super::model::{Category, ReadinessReport, Share};

/// Escapes `text` for a Markdown table cell or heading: ASCII punctuation Markdown gives a
/// meaning to (`\`, `` ` ``, `*`, `_`, `[`, `]`, `<`, `>`, `|`, `#`, `~`, `&`, and `$`,
/// which GitHub renders as math) is
/// backslash-escaped, and line breaks and other control characters become spaces, so a
/// value can neither end its cell or row, nor start a link, emphasis, code span or raw
/// HTML.
pub fn md_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '~' | '&' | '$' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// `12.34%`.
fn percent(basis_points: u32) -> String {
    format!("{}.{:02}%", basis_points / 100, basis_points % 100)
}

fn share(s: &Share, total: u64) -> String {
    format!("{} of {total} ({})", s.count, percent(s.basis_points))
}

fn yes(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn opt(v: &Option<String>) -> String {
    v.as_deref().map_or_else(|| "—".to_owned(), md_cell)
}

/// Points earned, from units of 1/10000 point: `12.34`.
fn points(earned: u64) -> String {
    format!("{}.{:02}", earned / 10_000, (earned % 10_000) / 100)
}

fn category_name(c: &Category) -> &'static str {
    match c.id {
        "identified" => "Identified (PURL or CPE)",
        "hashed" => "Hashed",
        "licensed" => "Licensed",
        "validation" => "Validation (CISA 2026, CRA)",
        "modules" => "Modules resolved",
        "vulnerabilities" => "Vulnerabilities closed",
        other => other,
    }
}

fn category_result(c: &Category, schema_valid: bool) -> String {
    if !c.assessed {
        return "not assessed (no scan supplied)".to_owned();
    }
    if c.denominator == 0 {
        return match c.id {
            "modules" => "no modules (full marks)".to_owned(),
            "vulnerabilities" => "no findings in the SBOM (full marks)".to_owned(),
            _ => "nothing to count (full marks)".to_owned(),
        };
    }
    let base = format!("{} of {}", c.numerator, c.denominator);
    if c.id == "validation" && !schema_valid {
        return format!("{base}; 0 because the SBOM is not valid CycloneDX 1.6");
    }
    base
}

/// The report as Markdown.
pub fn to_markdown(report: &ReadinessReport) -> String {
    let mut out: Vec<String> = Vec::new();
    let product = match &report.product.version {
        Some(v) => format!("{} {}", md_cell(&report.product.name), md_cell(v)),
        None => md_cell(&report.product.name),
    };
    out.push(format!("# Readiness report: {product}"));
    out.push(String::new());
    out.push(md_cell(&report.summary));
    out.push(String::new());
    out.push(format!(
        "Generated {} by {} {}. Report schema `{}`; see `docs/report.md` for how the score is \
         calculated.",
        md_cell(&report.generated),
        report.tool.name,
        md_cell(report.tool.version),
        report.schema
    ));

    // Score.
    let schema_valid = report.validation.schema.valid;
    out.push(String::new());
    out.push("## Score".to_owned());
    out.push(String::new());
    out.push(format!("**{} / 100**", report.score.value));
    out.push(String::new());
    out.push("| Category | Weight | Result | Points |".to_owned());
    out.push("| --- | ---: | --- | ---: |".to_owned());
    for c in &report.score.categories {
        out.push(format!(
            "| {} | {} | {} | {} |",
            category_name(c),
            c.weight,
            category_result(c, schema_valid),
            if c.assessed {
                points(c.earned)
            } else {
                "—".to_owned()
            }
        ));
    }
    out.push(format!(
        "| **Total** | {} | {} | **{}.{:02}** |",
        report.score.weight_assessed,
        if report.score.scan_supplied {
            "scan supplied"
        } else {
            "no scan supplied; out of 90, scaled to 100"
        },
        report.score.basis_points / 100,
        report.score.basis_points % 100
    ));

    // Coverage.
    let c = &report.coverage;
    out.push(String::new());
    out.push("## Coverage".to_owned());
    out.push(String::new());
    out.push(format!(
        "Over {} (the product, its images and every component).",
        if c.nodes == 1 {
            "1 item".to_owned()
        } else {
            format!("{} items", c.nodes)
        }
    ));
    out.push(String::new());
    out.push("| Measure | Items |".to_owned());
    out.push("| --- | --- |".to_owned());
    for (name, s) in [
        ("PURL", &c.purl),
        ("CPE", &c.cpe),
        ("PURL or CPE", &c.identified),
        ("Hash", &c.hash),
        ("Licence", &c.licence),
    ] {
        out.push(format!("| {name} | {} |", share(s, c.nodes)));
    }

    // Components.
    out.push(String::new());
    out.push("## Components".to_owned());
    out.push(String::new());
    out.push("| Item | Version | Type | PURL | CPE | Hash | Licence |".to_owned());
    out.push("| --- | --- | --- | --- | --- | --- | --- |".to_owned());
    for r in &report.components {
        let item = match r.level {
            "product" => format!("{} (product)", md_cell(&r.path)),
            "image" => format!("{} (image)", md_cell(&r.path)),
            _ => md_cell(&r.path),
        };
        out.push(format!(
            "| {item} | {} | {} | {} | {} | {} | {} |",
            opt(&r.version),
            md_cell(&r.kind),
            yes(r.purl),
            yes(r.cpe),
            yes(r.hash),
            yes(r.licence)
        ));
    }

    // Unresolved modules.
    out.push(String::new());
    out.push("## Unresolved modules".to_owned());
    out.push(String::new());
    if report.unresolved.is_empty() {
        out.push("None: every module is in the identifier database and every component has a PURL or CPE.".to_owned());
    } else {
        out.push("| Item | Version | Why |".to_owned());
        out.push("| --- | --- | --- |".to_owned());
        for u in &report.unresolved {
            let why = match u.reason {
                super::unresolved::NOT_IN_DB => "module not in the identifier database",
                _ => "no PURL or CPE",
            };
            out.push(format!(
                "| {} | {} | {why} |",
                md_cell(&u.path),
                opt(&u.version)
            ));
        }
        out.push(String::new());
        out.push(
            "Identifier database entries to fill in and add under `modules:` (one per name):"
                .to_owned(),
        );
        // One stub per name: a module in several images needs one entry.
        let mut stubs: BTreeMap<&str, &str> = BTreeMap::new();
        for u in &report.unresolved {
            stubs.entry(&u.name).or_insert(&u.hint);
        }
        for hint in stubs.values() {
            out.push(String::new());
            out.push("```yaml".to_owned());
            // A stub is YAML text from rollcall; a fence inside it cannot occur, but guard
            // anyway so it can never end the block.
            for line in hint.lines() {
                out.push(line.replace("```", "'''"));
            }
            out.push("```".to_owned());
        }
    }

    // Findings.
    out.push(String::new());
    out.push("## Findings".to_owned());
    out.push(String::new());
    match &report.findings {
        None => out.push(
            "No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed."
                .to_owned(),
        ),
        Some(f) => {
            out.push(format!(
                "{} finding(s): {} in the SBOM ({} open, {} closed by VEX), {} for packages not in the SBOM.",
                f.total, f.in_sbom, f.open, f.closed, f.not_in_sbom
            ));
            out.push(String::new());
            out.push("| Open, by severity | Count |".to_owned());
            out.push("| --- | ---: |".to_owned());
            let s = &f.open_by_severity;
            for (name, n) in [
                ("Critical", s.critical),
                ("High", s.high),
                ("Medium", s.medium),
                ("Low", s.low),
                ("Unknown", s.unknown),
            ] {
                out.push(format!("| {name} | {n} |"));
            }
            if !f.items.is_empty() {
                out.push(String::new());
                out.push("| Vulnerability | Severity | Item | Package | Status | VEX |".to_owned());
                out.push("| --- | --- | --- | --- | --- | --- |".to_owned());
                for i in &f.items {
                    out.push(format!(
                        "| {} | {} | {} | {} | {} | {} |",
                        md_cell(&i.id),
                        i.severity,
                        opt(&i.component),
                        md_cell(&i.package),
                        i.status,
                        i.vex_status.unwrap_or("—").replace('_', "\\_")
                    ));
                }
            }
        }
    }

    // VEX coverage.
    out.push(String::new());
    out.push("## VEX coverage".to_owned());
    out.push(String::new());
    match &report.vex {
        None => out.push("No VEX document was supplied (`--vex`).".to_owned()),
        Some(v) => {
            let covered = match &v.findings_covered {
                Some(s) => format!(
                    "; {} of the findings in the SBOM have a statement ({})",
                    s.count,
                    percent(s.basis_points)
                ),
                None => "; no scan was supplied to match them against".to_owned(),
            };
            out.push(format!(
                "{} statement(s), {} matching no finding{covered}.",
                v.statements, v.unmatched_statements
            ));
        }
    }

    // Validation.
    let v = &report.validation;
    out.push(String::new());
    out.push("## Validation".to_owned());
    out.push(String::new());
    if v.schema.valid {
        out.push("- CycloneDX 1.6 schema: valid.".to_owned());
    } else {
        out.push(format!(
            "- CycloneDX 1.6 schema: {} violation(s).",
            v.schema.violations.len()
        ));
    }
    out.push(format!(
        "- Profiles {}: {}, {} error(s), {} warning(s).",
        v.profiles
            .profiles
            .iter()
            .map(|p| format!("`{}`", p.replace('`', "'")))
            .collect::<Vec<_>>()
            .join(", "),
        if v.profiles.passed {
            "passed"
        } else {
            "failed"
        },
        v.profiles.errors,
        v.profiles.warnings
    ));
    if !v.schema.violations.is_empty() {
        out.push(String::new());
        out.push("| Schema path | Violation |".to_owned());
        out.push("| --- | --- |".to_owned());
        for s in &v.schema.violations {
            let path = if s.path.is_empty() { "/" } else { &s.path };
            out.push(format!("| {} | {} |", md_cell(path), md_cell(&s.message)));
        }
    }
    if !v.profiles.findings.is_empty() {
        out.push(String::new());
        out.push("| Severity | Check | Item | Problem |".to_owned());
        out.push("| --- | --- | --- | --- |".to_owned());
        for f in &v.profiles.findings {
            let item = match (&f.component, f.level) {
                (Some(c), Some(level @ ("product" | "image"))) => {
                    format!("{} ({level})", md_cell(c))
                }
                (Some(c), _) => md_cell(c),
                (None, _) => format!(
                    "document {}",
                    md_cell(f.pointer.as_deref().unwrap_or_default())
                ),
            };
            out.push(format!(
                "| {} | {} | {item} | {} |",
                f.severity,
                md_cell(&f.check),
                md_cell(&f.message)
            ));
        }
    }

    // Warnings.
    out.push(String::new());
    out.push("## Warnings".to_owned());
    out.push(String::new());
    if report.warnings.is_empty() {
        out.push("None.".to_owned());
    } else {
        for w in &report.warnings {
            out.push(format!(
                "- {}: {}",
                md_cell(&w.location),
                md_cell(&w.message)
            ));
        }
    }

    let mut text = out.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn points_and_percent() {
        assert_eq!(points(250_000), "25.00");
        assert_eq!(points(123_456), "12.34");
        assert_eq!(percent(10_000), "100.00%");
        assert_eq!(percent(5), "0.05%");
    }
}
