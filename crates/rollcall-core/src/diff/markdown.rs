//! The diff as GitHub-flavoured Markdown: the pull-request comment `rollcall-action` posts.

use std::fmt::Write as _;

use super::DIFF_SCHEMA;
use super::model::{ComponentEntry, Diff, FindingEntry, GateOutcome};
use crate::report::md_cell;

/// The most rows any one table shows; the rest are counted and left to the JSON artifact.
pub const MAX_ROWS: usize = 50;

fn opt(v: Option<&str>) -> String {
    v.map_or_else(|| "—".to_owned(), md_cell)
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        "—".to_owned()
    } else {
        items
            .iter()
            .map(|s| md_cell(s))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Appends a table with `header` and at most [`MAX_ROWS`] of `rows`, then a line counting
/// the rows left out.
fn table(out: &mut String, header: &[&str], rows: &[Vec<String>]) {
    let _ = writeln!(out, "| {} |", header.join(" | "));
    let _ = writeln!(
        out,
        "|{}",
        header.iter().map(|_| " --- |").collect::<String>()
    );
    for row in rows.iter().take(MAX_ROWS) {
        let _ = writeln!(out, "| {} |", row.join(" | "));
    }
    if rows.len() > MAX_ROWS {
        let _ = writeln!(
            out,
            "\n… and {} more in the artifact.",
            rows.len() - MAX_ROWS
        );
    }
}

fn component(f: &FindingEntry) -> String {
    if f.in_sbom {
        md_cell(&f.component)
    } else {
        format!("{} (not in SBOM)", md_cell(&f.component))
    }
}

/// A node's path, marked `(product)` or `(image)` as in the readiness report.
fn label(path: &str, level: &str) -> String {
    match level {
        "component" => md_cell(path),
        other => format!("{} ({other})", md_cell(path)),
    }
}

fn component_row(change: &str, c: &ComponentEntry) -> Vec<String> {
    let version = opt(c.version.as_deref());
    let (base, head) = if change == "added" {
        ("—".to_owned(), version)
    } else {
        (version, "—".to_owned())
    };
    vec![change.to_owned(), label(&c.path, c.level), base, head]
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Renders `diff` as Markdown (LF line endings; every input value escaped with [`md_cell`]).
pub fn to_markdown(diff: &Diff) -> String {
    let mut out = String::new();
    let product = match &diff.product.version {
        Some(v) => format!("{} {}", md_cell(&diff.product.name), md_cell(v)),
        None => md_cell(&diff.product.name),
    };
    let _ = writeln!(out, "## rollcall: {product}\n");

    // The verdict.
    let findings = &diff.findings;
    let gate = &diff.gate;
    let new = findings.new.len();
    let verdict = if !findings.scanned {
        "✅ **No scan supplied**: findings were not compared.".to_owned()
    } else {
        match (gate.fail_on, gate.outcome) {
            (Some(sev), GateOutcome::Findings) => format!(
                "❌ **{} at or above {sev}**: the check fails.",
                plural(
                    usize::try_from(gate.new_open_at_or_above).unwrap_or(usize::MAX),
                    "new open finding",
                    "new open findings"
                )
            ),
            (Some(sev), GateOutcome::Clean) if new > 0 => format!(
                "✅ **No new open findings at or above {sev}.** {} below the threshold or \
                 suppressed by VEX {} listed below.",
                plural(new, "new finding", "new findings"),
                if new == 1 { "is" } else { "are" }
            ),
            (Some(sev), GateOutcome::Clean) => {
                format!("✅ **No new open findings at or above {sev}.**")
            }
            (None, _) => format!(
                "✅ **Not gated** (fail-on: none): {}.",
                plural(new, "new finding", "new findings")
            ),
        }
    };
    let _ = writeln!(out, "{verdict}\n");

    if let Some(summary) = &diff.summary {
        let _ = writeln!(out, "{}\n", md_cell(summary));
    }
    if let Some(head) = diff.score.head {
        let base = match diff.score.base {
            Some(b) => format!("base: {b} / 100"),
            None => "no base score".to_owned(),
        };
        let _ = writeln!(out, "Readiness score: **{head} / 100** ({base}).\n");
    }

    // Findings.
    let _ = writeln!(out, "### New findings\n");
    if !findings.scanned {
        let _ = writeln!(out, "No scan supplied.\n");
    } else if findings.new.is_empty() {
        let _ = writeln!(out, "None.\n");
    } else {
        let rows: Vec<Vec<String>> = findings
            .new
            .iter()
            .map(|f| {
                vec![
                    f.severity.to_string(),
                    md_cell(&f.id),
                    component(f),
                    opt(f.version.as_deref()),
                    list(&f.fixed_versions),
                    md_cell(&f.triage),
                ]
            })
            .collect();
        table(
            &mut out,
            &[
                "Severity",
                "ID",
                "Component",
                "Version",
                "Fixed in",
                "Triage",
            ],
            &rows,
        );
        out.push('\n');
    }

    let _ = writeln!(out, "### Fixed findings\n");
    if findings.fixed.is_empty() {
        let _ = writeln!(out, "None.\n");
    } else {
        let rows: Vec<Vec<String>> = findings
            .fixed
            .iter()
            .map(|f| {
                vec![
                    f.severity.to_string(),
                    md_cell(&f.id),
                    component(f),
                    opt(f.version.as_deref()),
                ]
            })
            .collect();
        table(&mut out, &["Severity", "ID", "Component", "Version"], &rows);
        out.push('\n');
    }

    let _ = writeln!(out, "### Triage changes\n");
    if findings.changed.is_empty() {
        let _ = writeln!(out, "None.\n");
    } else {
        let rows: Vec<Vec<String>> = findings
            .changed
            .iter()
            .map(|c| {
                vec![
                    c.severity.to_string(),
                    md_cell(&c.id),
                    md_cell(&c.component),
                    md_cell(&c.base_triage),
                    md_cell(&c.head_triage),
                ]
            })
            .collect();
        table(
            &mut out,
            &["Severity", "ID", "Component", "Base", "Head"],
            &rows,
        );
        out.push('\n');
    }

    // Components.
    let components = &diff.components;
    let _ = writeln!(out, "### Components\n");
    if !diff.base.present {
        let _ = writeln!(out, "No base SBOM to compare with.\n");
    } else if components.added.is_empty()
        && components.removed.is_empty()
        && components.changed.is_empty()
    {
        let _ = writeln!(out, "No changes.\n");
    } else {
        let _ = writeln!(
            out,
            "{} added, {} removed, {} changed.\n",
            components.added.len(),
            components.removed.len(),
            components.changed.len()
        );
        let mut rows: Vec<Vec<String>> = Vec::new();
        rows.extend(components.added.iter().map(|c| component_row("added", c)));
        rows.extend(
            components
                .removed
                .iter()
                .map(|c| component_row("removed", c)),
        );
        rows.extend(components.changed.iter().map(|c| {
            vec![
                "changed".to_owned(),
                label(&c.path, c.level),
                opt(c.base_version.as_deref()),
                opt(c.head_version.as_deref()),
            ]
        }));
        table(
            &mut out,
            &["Change", "Component", "Base version", "Head version"],
            &rows,
        );
        out.push('\n');
    }

    // Base.
    let _ = writeln!(out, "### Base\n");
    match (&diff.base.product, &diff.base.reason) {
        (Some(p), None) => {
            let _ = writeln!(
                out,
                "Compared with the base branch's build of {}{}.\n",
                md_cell(&p.name),
                p.version
                    .as_deref()
                    .map(|v| format!(" {}", md_cell(v)))
                    .unwrap_or_default()
            );
        }
        (_, Some(reason)) => {
            let _ = writeln!(
                out,
                "{}: every open finding counts as new.\n",
                md_cell(reason)
            );
        }
        (None, None) => {
            let _ = writeln!(out, "No base.\n");
        }
    }
    let _ = writeln!(
        out,
        "Diff schema `{DIFF_SCHEMA}`; the SBOM, VEX, scan, report and diff JSON are in the \
         workflow run's artifact."
    );
    out
}
