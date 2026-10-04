//! Joins the `.dep-v0` crate list with `cargo metadata` packages.
//!
//! The join key is (name, version, source class): `.dep-v0` records the kind of source
//! (`crates.io`, `git`, `local`, `registry`) but not its URL or revision, so that is all the
//! two can be matched on. Two metadata packages with the same key cannot be told apart and
//! are an error ([`MatchError::Ambiguous`]); a `.dep-v0` package with no metadata package is
//! returned in [`Linked::unmatched`] for the caller to warn about.

use std::collections::{BTreeMap, BTreeSet};

use super::auditable::{DepPackage, DepV0};
use super::metadata::Metadata;

/// Why `.dep-v0` and the metadata could not be joined.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MatchError {
    /// Two metadata packages share a name, version and source class.
    #[error(
        "{name}@{version} ({class}) is two different packages in cargo metadata; rollcall cannot tell which one the binary links"
    )]
    Ambiguous {
        /// The crate name.
        name: String,
        /// The crate version.
        version: String,
        /// The source class.
        class: String,
    },
}

/// The result of [`match_linked`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Linked {
    /// Each `.dep-v0` package index matched to a metadata package id.
    pub matched: BTreeMap<usize, String>,
    /// The `.dep-v0` package indices with no metadata package, in section order.
    pub unmatched: Vec<usize>,
}

impl Linked {
    /// The metadata ids of every matched package.
    pub fn ids(&self) -> BTreeSet<&str> {
        self.matched.values().map(String::as_str).collect()
    }
}

type Key<'a> = (&'a str, &'a str, &'a str);

fn dep_key(p: &DepPackage) -> Key<'_> {
    (&p.name, &p.version, p.source.class())
}

/// Matches every `.dep-v0` package to the metadata package with the same name, version and
/// source class.
pub fn match_linked(metadata: &Metadata, dep_v0: &DepV0) -> Result<Linked, MatchError> {
    let mut by_key: BTreeMap<Key<'_>, &str> = BTreeMap::new();
    let mut ambiguous: BTreeSet<Key<'_>> = BTreeSet::new();
    for (id, p) in &metadata.packages {
        let key = (p.name.as_str(), p.version.as_str(), p.source.class());
        if by_key.insert(key, id).is_some() {
            ambiguous.insert(key);
        }
    }
    let mut linked = Linked::default();
    for (index, p) in dep_v0.packages.iter().enumerate() {
        let key = dep_key(p);
        if ambiguous.contains(&key) {
            return Err(MatchError::Ambiguous {
                name: p.name.clone(),
                version: p.version.clone(),
                class: p.source.class().to_owned(),
            });
        }
        match by_key.get(&key) {
            Some(id) => {
                linked.matched.insert(index, (*id).to_owned());
            }
            None => linked.unmatched.push(index),
        }
    }
    Ok(linked)
}

#[cfg(test)]
mod tests {
    use super::super::{auditable, metadata};
    use super::*;

    const CRATES: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn meta(extra: &str) -> Metadata {
        metadata::parse(&format!(
            r#"{{"version": 1, "packages": [
                {{"id": "r", "name": "app", "version": "0.1.0", "source": null}},
                {{"id": "a", "name": "a", "version": "1.0.0", "source": "{CRATES}"}}{extra}
            ], "resolve": {{"root": "r", "nodes": []}}}}"#
        ))
        .unwrap()
    }

    fn dep(json: &str) -> DepV0 {
        auditable::parse_json(json).unwrap()
    }

    #[test]
    fn matches_by_name_version_and_class() {
        let d = dep(
            r#"{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"},
            {"name":"app","version":"0.1.0","source":"local","root":true},
            {"name":"ghost","version":"9.9.9","source":"crates.io"},
            {"name":"a","version":"1.0.0","source":"git"}]}"#,
        );
        let linked = match_linked(&meta(""), &d).unwrap();
        assert_eq!(
            linked.matched,
            BTreeMap::from([(0, "a".to_owned()), (1, "r".to_owned())])
        );
        assert_eq!(linked.unmatched, vec![2, 3]);
    }

    #[test]
    fn same_key_twice_in_metadata_is_ambiguous() {
        let m = meta(
            r#", {"id": "a2", "name": "a", "version": "1.0.0", "source": "sparse+https://index.crates.io/"}"#,
        );
        let d = dep(
            r#"{"packages":[{"name":"a","version":"1.0.0","source":"crates.io"},
            {"name":"app","version":"0.1.0","source":"local","root":true}]}"#,
        );
        assert!(matches!(
            match_linked(&m, &d),
            Err(MatchError::Ambiguous { .. })
        ));
    }
}
