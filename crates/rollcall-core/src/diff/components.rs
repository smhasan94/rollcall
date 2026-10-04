//! Components added, removed and changed between two SBOMs' report rows.
//!
//! Rows are keyed by path (names from the image down, no versions) and level (the product
//! and its application image can share a name), so a version bump keeps its key. At each
//! key, rows identical in version, purl and CPE presence cancel out; if exactly one row is
//! left on each side it is **changed**, otherwise what is left in the head is **added** and
//! what is left in the base **removed** (a key can hold several rows, e.g. two versions of
//! one crate).

use std::collections::BTreeMap;

use super::model::{ComponentChange, ComponentDiff, ComponentEntry};
use crate::report::ComponentRow;

fn entry(row: &ComponentRow) -> ComponentEntry {
    ComponentEntry {
        path: row.path.clone(),
        level: row.level,
        name: row.name.clone(),
        version: row.version.clone(),
        purl: row.purl,
        cpe: row.cpe,
    }
}

type Key<'a> = (&'a str, &'static str);

fn group(rows: &[ComponentRow]) -> BTreeMap<Key<'_>, Vec<&ComponentRow>> {
    let mut out: BTreeMap<Key<'_>, Vec<&ComponentRow>> = BTreeMap::new();
    for row in rows {
        out.entry((row.path.as_str(), row.level))
            .or_default()
            .push(row);
    }
    out
}

fn same(a: &ComponentRow, b: &ComponentRow) -> bool {
    a.version == b.version && a.purl == b.purl && a.cpe == b.cpe
}

/// The component diff of `head` against `base` (see the [module docs](self)).
pub fn diff_components(base: &[ComponentRow], head: &[ComponentRow]) -> ComponentDiff {
    let base = group(base);
    let head = group(head);
    let mut keys: Vec<Key<'_>> = base.keys().chain(head.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();

    let mut out = ComponentDiff::default();
    for key @ (path, level) in keys {
        let mut b: Vec<&ComponentRow> = base.get(&key).cloned().unwrap_or_default();
        let mut h: Vec<&ComponentRow> = head.get(&key).cloned().unwrap_or_default();
        // Cancel identical rows.
        h.retain(|row| match b.iter().position(|other| same(row, other)) {
            Some(i) => {
                b.remove(i);
                false
            }
            None => true,
        });
        match (b.as_slice(), h.as_slice()) {
            ([old], [new]) => out.changed.push(ComponentChange {
                path: path.to_owned(),
                level,
                name: new.name.clone(),
                base_version: old.version.clone(),
                head_version: new.version.clone(),
                base_purl: old.purl,
                head_purl: new.purl,
                base_cpe: old.cpe,
                head_cpe: new.cpe,
            }),
            _ => {
                out.added.extend(h.iter().map(|r| entry(r)));
                out.removed.extend(b.iter().map(|r| entry(r)));
            }
        }
    }
    out.added.sort();
    out.removed.sort();
    out.changed.sort();
    out
}
