//! Findings new, fixed and re-triaged between two scans, and the gate.
//!
//! A head finding and a base finding are the same finding when they are on a component (or
//! package) of the same name and share an id or alias. The match ignores `bom-ref`s and
//! versions, so bumping a component (which changes its `bom-ref`) does not make an old
//! vulnerability it still has "new". Head findings are matched in order (most severe first),
//! each first to a base finding at the same component path, then to one at any path, and
//! each base finding is matched at most once.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use super::model::{FindingDiff, FindingEntry, Gate, GateOutcome, TriageChange};
use super::scan_rows::ScanRow;
use crate::severity::Severity;

/// A scan's rows with each row's component path (from its `bom-ref` in the same SBOM).
pub struct Located {
    rows: Vec<(ScanRow, Option<String>)>,
}

impl Located {
    /// Locates `rows` with `paths` (`bom-ref` → path) and sorts them most severe first.
    pub fn new(rows: Vec<ScanRow>, paths: &BTreeMap<String, String>) -> Self {
        let mut rows: Vec<(ScanRow, Option<String>)> = rows
            .into_iter()
            .map(|row| {
                let path = row.bom_ref.as_ref().and_then(|r| paths.get(r)).cloned();
                (row, path)
            })
            .collect();
        rows.sort_by(|(a, pa), (b, pb)| sort_key(a, pa).cmp(&sort_key(b, pb)));
        Self { rows }
    }
}

type SortKey<'a> = (
    Reverse<Severity>,
    &'a str,
    Option<&'a str>,
    &'a str,
    Option<&'a str>,
    &'a str,
);

fn sort_key<'a>(row: &'a ScanRow, path: &'a Option<String>) -> SortKey<'a> {
    (
        Reverse(row.severity),
        row.id.as_str(),
        path.as_deref(),
        row.component_name.as_str(),
        row.version.as_deref(),
        row.triage.as_str(),
    )
}

fn entry(row: &ScanRow, path: &Option<String>) -> FindingEntry {
    FindingEntry {
        id: row.id.clone(),
        aliases: row.aliases.iter().cloned().collect(),
        severity: row.severity,
        component: path.clone().unwrap_or_else(|| row.component_name.clone()),
        name: row.component_name.clone(),
        in_sbom: path.is_some() || row.bom_ref.is_some(),
        version: row.version.clone(),
        fixed_versions: row.fixed_versions.iter().cloned().collect(),
        triage: row.triage.clone(),
    }
}

fn same_vulnerability(a: &ScanRow, b: &ScanRow) -> bool {
    a.component_name == b.component_name && !a.ids().is_disjoint(&b.ids())
}

/// The finding diff of `head` against `base` (see the [module docs](self)). Without a base
/// scan every head finding is new.
pub fn diff_findings(base: Option<&Located>, head: &Located) -> FindingDiff {
    let mut out = FindingDiff {
        scanned: true,
        head_total: head.rows.len() as u64,
        head_open: head.rows.iter().filter(|(r, _)| !r.is_suppressed()).count() as u64,
        ..FindingDiff::default()
    };
    let Some(base) = base else {
        out.new = head.rows.iter().map(|(r, p)| entry(r, p)).collect();
        return out;
    };
    let mut taken = vec![false; base.rows.len()];
    let mut matched: Vec<Option<usize>> = vec![None; head.rows.len()];
    // Pass 1: same path; pass 2: any path.
    for same_path in [true, false] {
        for (h, (row, path)) in head.rows.iter().enumerate() {
            if matched.get(h).copied().flatten().is_some() {
                continue;
            }
            let found = base
                .rows
                .iter()
                .enumerate()
                .position(|(b, (other, opath))| {
                    !taken.get(b).copied().unwrap_or(true)
                        && (!same_path || path == opath)
                        && same_vulnerability(row, other)
                });
            if let Some(b) = found {
                if let Some(t) = taken.get_mut(b) {
                    *t = true;
                }
                if let Some(m) = matched.get_mut(h) {
                    *m = Some(b);
                }
            }
        }
    }
    for ((row, path), m) in head.rows.iter().zip(&matched) {
        match m.and_then(|b| base.rows.get(b)) {
            None => out.new.push(entry(row, path)),
            Some((old, _)) if old.triage != row.triage => out.changed.push(TriageChange {
                id: row.id.clone(),
                severity: row.severity,
                component: path.clone().unwrap_or_else(|| row.component_name.clone()),
                version: row.version.clone(),
                base_triage: old.triage.clone(),
                head_triage: row.triage.clone(),
            }),
            Some(_) => {}
        }
    }
    out.fixed = base
        .rows
        .iter()
        .zip(&taken)
        .filter(|(_, t)| !**t)
        .map(|((r, p), _)| entry(r, p))
        .collect();
    out
}

/// The gate over the new findings: how many are open (not suppressed) and at or above
/// `fail_on`. Without a threshold nothing is gated.
pub fn gate(new: &[FindingEntry], fail_on: Option<Severity>) -> Gate {
    let count = match fail_on {
        None => 0,
        Some(threshold) => new
            .iter()
            .filter(|f| f.triage != "suppressed" && f.severity >= threshold)
            .count() as u64,
    };
    Gate {
        fail_on,
        new_open_at_or_above: count,
        outcome: if count > 0 {
            GateOutcome::Findings
        } else {
            GateOutcome::Clean
        },
    }
}
