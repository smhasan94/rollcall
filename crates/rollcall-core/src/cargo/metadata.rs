//! A panic-free reader for `cargo metadata --format-version 1` JSON.
//!
//! Only the subset rollcall needs is read: each package's id, name, version, source and
//! licence, and the `resolve` graph (nodes, their dependencies with `dep_kinds`, and their
//! enabled features). Unknown fields are ignored, so newer Cargo output still reads; a wrong
//! type, a missing required field, a `version` other than 1, a missing `resolve`, a duplicate
//! package id or a dependency on an id that is not a package is a [`MetadataError`].
//!
//! Package ids are treated as opaque strings: they are matched against each other and never
//! written to the output (a path package's id holds a build-machine path).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Deserialize;

/// Why `cargo metadata` output could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MetadataError {
    /// Not JSON, truncated, or a field has the wrong type.
    #[error("not cargo metadata JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// `version` is not 1 (`cargo metadata --format-version 1`).
    #[error("unsupported cargo metadata format version {0} (rollcall reads --format-version 1)")]
    FormatVersion(u64),
    /// There is no `resolve` section (`cargo metadata --no-deps` was used).
    #[error("no resolve section: run cargo metadata without --no-deps")]
    NoResolve,
    /// Two packages share an id.
    #[error("package id {0:?} is listed twice")]
    DuplicatePackage(String),
    /// A resolve node, dependency or the root names an id that is not a package.
    #[error("resolve refers to unknown package id {0:?}")]
    UnknownPackage(String),
    /// A dependency kind is not `null` (normal), `"build"` or `"dev"`.
    #[error("unknown dependency kind {0:?}")]
    UnknownDepKind(String),
    /// A package source is not a registry, sparse registry or git URL.
    #[error("package {package}: unrecognised source {source_url:?}")]
    UnknownSource {
        /// The package, `name@version`.
        package: String,
        /// The source as given.
        source_url: String,
    },
}

/// The parsed metadata: packages by id and the resolve graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// Every package, keyed by its (opaque) id.
    pub packages: BTreeMap<String, Package>,
    /// The resolve graph, keyed by package id.
    pub nodes: BTreeMap<String, Node>,
    /// The root package's id (`resolve.root`), `None` for a virtual workspace.
    pub root: Option<String>,
}

/// One package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The crate name.
    pub name: String,
    /// The crate version.
    pub version: String,
    /// Where it comes from.
    pub source: SourceKind,
    /// The `license` field, as written in its manifest.
    pub license: Option<String>,
}

impl Package {
    /// `name@version`, for messages.
    pub fn label(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// A package's source, from its `source` field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceKind {
    /// crates.io (`registry+https://github.com/rust-lang/crates.io-index` or
    /// `sparse+https://index.crates.io/`).
    CratesIo,
    /// Another registry, by index URL (without the `registry+`/`sparse+` prefix).
    Registry(String),
    /// A git repository: its URL (without `git+`, query or fragment) and the exact commit.
    Git {
        /// The repository URL.
        url: String,
        /// The full commit sha Cargo resolved (the `#` fragment, else a `rev` query value),
        /// only when it is 40 hex digits.
        commit: Option<String>,
        /// The revision as written when it is not a full commit sha (e.g. a branch, tag or
        /// short sha), for the warning that the purl carries no revision.
        reference: Option<String>,
    },
    /// A path dependency, or the root package (no `source`).
    Path,
}

impl SourceKind {
    /// The class `cargo auditable` records in `.dep-v0`: `crates.io`, `registry`, `git` or
    /// `local`.
    pub fn class(&self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Registry(_) => "registry",
            Self::Git { .. } => "git",
            Self::Path => "local",
        }
    }
}

/// One resolve node: a package and what it depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Its dependencies: target package id → the kinds of the edge.
    pub deps: BTreeMap<String, BTreeSet<DepKind>>,
    /// The features enabled on it, sorted.
    pub features: BTreeSet<String>,
}

/// The kind of a dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DepKind {
    /// `[dependencies]` (`kind: null`).
    Normal,
    /// `[build-dependencies]`.
    Build,
    /// `[dev-dependencies]`: never linked into the binary.
    Dev,
}

/// How a package is reached from the root (see [`Metadata::reach`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reach {
    /// Through normal and build edges only: built for the binary.
    Linked,
    /// Only through a dev-dependency of the root: never in the binary.
    DevOnly,
}

#[derive(Deserialize)]
struct RawMetadata {
    version: u64,
    packages: Vec<RawPackage>,
    #[serde(default)]
    resolve: Option<RawResolve>,
}

#[derive(Deserialize)]
struct RawPackage {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    license: Option<String>,
}

#[derive(Deserialize)]
struct RawResolve {
    nodes: Vec<RawNode>,
    #[serde(default)]
    root: Option<String>,
}

#[derive(Deserialize)]
struct RawNode {
    id: String,
    #[serde(default)]
    deps: Vec<RawDep>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Deserialize)]
struct RawDep {
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<RawDepKind>,
}

#[derive(Deserialize)]
struct RawDepKind {
    #[serde(default)]
    kind: Option<String>,
}

/// crates.io's index URLs, as they appear after the `registry+` / `sparse+` prefix.
const CRATES_IO: [&str; 2] = [
    "https://github.com/rust-lang/crates.io-index",
    "https://index.crates.io/",
];

/// Parses a package `source` (`None` for a path package).
pub fn parse_source(source: Option<&str>, package: &str) -> Result<SourceKind, MetadataError> {
    let Some(source) = source else {
        return Ok(SourceKind::Path);
    };
    let unknown = || MetadataError::UnknownSource {
        package: package.to_owned(),
        source_url: source.to_owned(),
    };
    if let Some(index) = source
        .strip_prefix("registry+")
        .or_else(|| source.strip_prefix("sparse+"))
    {
        if index.is_empty() {
            return Err(unknown());
        }
        return Ok(if CRATES_IO.contains(&index) {
            SourceKind::CratesIo
        } else {
            SourceKind::Registry(index.to_owned())
        });
    }
    if let Some(rest) = source.strip_prefix("git+") {
        let (before_fragment, fragment) = match rest.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (rest, None),
        };
        let (url, query) = match before_fragment.split_once('?') {
            Some((u, q)) => (u, Some(q)),
            None => (before_fragment, None),
        };
        let from_query = query.and_then(|q| {
            ["rev", "tag", "branch"].iter().find_map(|key| {
                q.split('&')
                    .find_map(|pair| pair.strip_prefix(*key)?.strip_prefix('='))
            })
        });
        let rev = fragment.filter(|f| !f.is_empty()).or(from_query);
        return match rev {
            Some(rev) if !url.is_empty() => {
                let full = rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit());
                Ok(SourceKind::Git {
                    url: url.to_owned(),
                    commit: full.then(|| rev.to_ascii_lowercase()),
                    reference: (!full).then(|| rev.to_owned()),
                })
            }
            _ => Err(unknown()),
        };
    }
    if source.starts_with("path+") {
        return Ok(SourceKind::Path);
    }
    Err(unknown())
}

/// Parses `cargo metadata --format-version 1` output.
pub fn parse(text: &str) -> Result<Metadata, MetadataError> {
    let raw: RawMetadata = serde_json::from_str(text)?;
    if raw.version != 1 {
        return Err(MetadataError::FormatVersion(raw.version));
    }
    let resolve = raw.resolve.ok_or(MetadataError::NoResolve)?;
    let mut packages = BTreeMap::new();
    for p in raw.packages {
        let label = format!("{}@{}", p.name, p.version);
        let source = parse_source(p.source.as_deref(), &label)?;
        let package = Package {
            name: p.name,
            version: p.version,
            source,
            license: p.license,
        };
        if packages.insert(p.id.clone(), package).is_some() {
            return Err(MetadataError::DuplicatePackage(p.id));
        }
    }
    let known = |id: &str| -> Result<(), MetadataError> {
        if packages.contains_key(id) {
            Ok(())
        } else {
            Err(MetadataError::UnknownPackage(id.to_owned()))
        }
    };
    let mut nodes = BTreeMap::new();
    for n in resolve.nodes {
        known(&n.id)?;
        let mut deps: BTreeMap<String, BTreeSet<DepKind>> = BTreeMap::new();
        for d in n.deps {
            known(&d.pkg)?;
            let kinds = deps.entry(d.pkg).or_default();
            if d.dep_kinds.is_empty() {
                // Cargo before 1.41 wrote no dep_kinds: every edge was a normal one.
                kinds.insert(DepKind::Normal);
            }
            for k in d.dep_kinds {
                kinds.insert(match k.kind.as_deref() {
                    None => DepKind::Normal,
                    Some("build") => DepKind::Build,
                    Some("dev") => DepKind::Dev,
                    Some(other) => return Err(MetadataError::UnknownDepKind(other.to_owned())),
                });
            }
        }
        let node = Node {
            deps,
            features: n.features.into_iter().collect(),
        };
        if nodes.insert(n.id.clone(), node).is_some() {
            return Err(MetadataError::DuplicatePackage(n.id));
        }
    }
    if let Some(root) = &resolve.root {
        known(root)?;
    }
    Ok(Metadata {
        packages,
        nodes,
        root: resolve.root,
    })
}

impl Metadata {
    /// How each package is reached from `root`: [`Reach::Linked`] through normal and build
    /// edges, [`Reach::DevOnly`] only through one of the root's dev-dependencies. Packages
    /// not reached at all are absent. `root` itself is not included.
    ///
    /// Dev edges count at the root only: Cargo resolves dev-dependencies for workspace
    /// members, never for their dependencies.
    pub fn reach(&self, root: &str) -> BTreeMap<String, Reach> {
        let linked = self.closure(root, |_, kinds| {
            kinds
                .iter()
                .any(|k| matches!(k, DepKind::Normal | DepKind::Build))
        });
        let mut out: BTreeMap<String, Reach> = BTreeMap::new();
        for id in &linked {
            out.insert(id.clone(), Reach::Linked);
        }
        let with_dev = self.closure(root, |from, kinds| {
            kinds
                .iter()
                .any(|k| matches!(k, DepKind::Normal | DepKind::Build))
                || (from == root && kinds.contains(&DepKind::Dev))
        });
        for id in with_dev {
            out.entry(id).or_insert(Reach::DevOnly);
        }
        out.remove(root);
        out
    }

    /// Every id reachable from `root` (excluding `root` unless it is on a cycle) through the
    /// edges `follow` accepts. Iterative, so depth never threatens the stack.
    fn closure(
        &self,
        root: &str,
        follow: impl Fn(&str, &BTreeSet<DepKind>) -> bool,
    ) -> BTreeSet<String> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<&str> = VecDeque::from([root]);
        while let Some(id) = queue.pop_front() {
            let Some(node) = self.nodes.get(id) else {
                continue;
            };
            for (dep, kinds) in &node.deps {
                if follow(id, kinds) && seen.insert(dep.clone()) {
                    queue.push_back(dep);
                }
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRATES: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn sample() -> String {
        format!(
            r#"{{
  "version": 1,
  "workspace_root": "/x",
  "packages": [
    {{"id": "path+file:///x#app@0.1.0", "name": "app", "version": "0.1.0", "source": null, "license": "MIT", "manifest_path": "/x/Cargo.toml"}},
    {{"id": "{CRATES}#a@1.0.0", "name": "a", "version": "1.0.0", "source": "{CRATES}", "license": "MIT/Apache-2.0"}},
    {{"id": "{CRATES}#b@2.0.0", "name": "b", "version": "2.0.0", "source": "{CRATES}"}},
    {{"id": "{CRATES}#dev@3.0.0", "name": "dev", "version": "3.0.0", "source": "{CRATES}"}},
    {{"id": "git+https://github.com/o/g?rev=abc#0123456789abcdef0123456789abcdef01234567", "name": "g", "version": "0.2.0", "source": "git+https://github.com/o/g?rev=abc#0123456789abcdef0123456789abcdef01234567"}}
  ],
  "resolve": {{
    "root": "path+file:///x#app@0.1.0",
    "nodes": [
      {{"id": "path+file:///x#app@0.1.0", "deps": [
        {{"name": "a", "pkg": "{CRATES}#a@1.0.0", "dep_kinds": [{{"kind": null, "target": null}}]}},
        {{"name": "g", "pkg": "git+https://github.com/o/g?rev=abc#0123456789abcdef0123456789abcdef01234567", "dep_kinds": [{{"kind": "build", "target": null}}]}},
        {{"name": "dev", "pkg": "{CRATES}#dev@3.0.0", "dep_kinds": [{{"kind": "dev", "target": null}}]}}
      ], "features": ["default", "std"]}},
      {{"id": "{CRATES}#a@1.0.0", "deps": [{{"name": "b", "pkg": "{CRATES}#b@2.0.0", "dep_kinds": [{{"kind": null}}]}}], "features": []}},
      {{"id": "{CRATES}#b@2.0.0", "deps": [], "features": []}},
      {{"id": "{CRATES}#dev@3.0.0", "deps": [{{"name": "b", "pkg": "{CRATES}#b@2.0.0", "dep_kinds": [{{"kind": null}}]}}], "features": []}},
      {{"id": "git+https://github.com/o/g?rev=abc#0123456789abcdef0123456789abcdef01234567", "deps": [], "features": []}}
    ]
  }},
  "target_directory": "/x/target",
  "metadata": null
}}"#
        )
    }

    #[test]
    fn parses_a_real_shaped_document() {
        let m = parse(&sample()).unwrap();
        assert_eq!(m.packages.len(), 5);
        let root = m.root.clone().unwrap();
        assert_eq!(m.packages[&root].name, "app");
        assert_eq!(
            m.nodes[&root].features,
            BTreeSet::from(["default".to_owned(), "std".to_owned()])
        );
        let reach = m.reach(&root);
        let names: BTreeMap<&str, Reach> = reach
            .iter()
            .map(|(id, r)| (m.packages[id].name.as_str(), *r))
            .collect();
        // b is reached both through a (linked) and through dev: linked wins.
        assert_eq!(
            names,
            BTreeMap::from([
                ("a", Reach::Linked),
                ("b", Reach::Linked),
                ("dev", Reach::DevOnly),
                ("g", Reach::Linked),
            ])
        );
    }

    #[test]
    fn source_forms() {
        assert_eq!(parse_source(None, "p").unwrap(), SourceKind::Path);
        assert_eq!(
            parse_source(Some(CRATES), "p").unwrap(),
            SourceKind::CratesIo
        );
        assert_eq!(
            parse_source(Some("sparse+https://index.crates.io/"), "p").unwrap(),
            SourceKind::CratesIo
        );
        assert_eq!(
            parse_source(Some("sparse+https://my.reg/index/"), "p").unwrap(),
            SourceKind::Registry("https://my.reg/index/".to_owned())
        );
        let sha = "0123456789abcdef0123456789ABCDEF01234567";
        assert_eq!(
            parse_source(
                Some(&format!("git+https://github.com/o/r?rev=abc#{sha}")),
                "p"
            )
            .unwrap(),
            SourceKind::Git {
                url: "https://github.com/o/r".to_owned(),
                commit: Some(sha.to_ascii_lowercase()),
                reference: None,
            }
        );
        // A short sha or a branch is not a commit: kept only for the warning.
        assert_eq!(
            parse_source(Some("git+https://github.com/o/r?rev=abc#deadbeef"), "p").unwrap(),
            SourceKind::Git {
                url: "https://github.com/o/r".to_owned(),
                commit: None,
                reference: Some("deadbeef".to_owned()),
            }
        );
        assert_eq!(
            parse_source(Some("git+https://github.com/o/r?branch=main"), "p").unwrap(),
            SourceKind::Git {
                url: "https://github.com/o/r".to_owned(),
                commit: None,
                reference: Some("main".to_owned()),
            }
        );
        for bad in [
            "git+https://github.com/o/r",
            "git+#abc",
            "registry+",
            "svn+https://x",
            "",
        ] {
            assert!(
                matches!(
                    parse_source(Some(bad), "p"),
                    Err(MetadataError::UnknownSource { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn malformed_input_is_an_error_never_a_panic() {
        let good = sample();
        let cases: Vec<String> = vec![
            String::new(),
            "not json".to_owned(),
            "[]".to_owned(),
            "{}".to_owned(),
            r#"{"version": 2, "packages": [], "resolve": {"nodes": []}}"#.to_owned(),
            r#"{"version": "1", "packages": [], "resolve": {"nodes": []}}"#.to_owned(),
            r#"{"version": 1, "packages": []}"#.to_owned(),
            r#"{"version": 1, "packages": {}, "resolve": {"nodes": []}}"#.to_owned(),
            r#"{"version": 1, "packages": [{"id": 1, "name": "a", "version": "1"}], "resolve": {"nodes": []}}"#.to_owned(),
            r#"{"version": 1, "packages": [], "resolve": {"nodes": [{"id": "ghost"}]}}"#.to_owned(),
            r#"{"version": 1, "packages": [], "resolve": {"nodes": [], "root": "ghost"}}"#.to_owned(),
            r#"{"version": 1, "packages": [{"id": "a", "name": "a", "version": "1"}, {"id": "a", "name": "a", "version": "1"}], "resolve": {"nodes": []}}"#.to_owned(),
            r#"{"version": 1, "packages": [{"id": "a", "name": "a", "version": "1"}], "resolve": {"nodes": [{"id": "a", "deps": [{"pkg": "ghost"}]}]}}"#.to_owned(),
            r#"{"version": 1, "packages": [{"id": "a", "name": "a", "version": "1"}], "resolve": {"nodes": [{"id": "a", "deps": [{"pkg": "a", "dep_kinds": [{"kind": "weird"}]}]}]}}"#.to_owned(),
            r#"{"version": 1, "packages": [{"id": "a", "name": "a", "version": "1", "source": "svn+x"}], "resolve": {"nodes": []}}"#.to_owned(),
            good.get(..good.len() / 2).unwrap().to_owned(),
            good.replace("\"deps\": []", "\"deps\": 7"),
        ];
        for case in cases {
            assert!(parse(&case).is_err(), "accepted: {case:.80}");
        }
        assert!(parse(&good).is_ok());
    }

    #[test]
    fn virtual_workspace_has_no_root() {
        let m = parse(r#"{"version": 1, "packages": [], "resolve": {"nodes": [], "root": null}}"#)
            .unwrap();
        assert_eq!(m.root, None);
    }

    #[test]
    fn missing_dep_kinds_mean_normal() {
        let m = parse(
            r#"{"version": 1, "packages": [{"id": "r", "name": "r", "version": "1"}, {"id": "a", "name": "a", "version": "1"}],
                "resolve": {"root": "r", "nodes": [{"id": "r", "deps": [{"pkg": "a"}]}, {"id": "a"}]}}"#,
        )
        .unwrap();
        assert_eq!(
            m.reach("r"),
            BTreeMap::from([("a".to_owned(), Reach::Linked)])
        );
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_text_never_panics(text in ".{0,400}") {
                let _ = parse(&text);
            }

            #[test]
            fn arbitrary_bytes_of_the_sample_never_panic(cut in 0usize..4000, byte in any::<u8>()) {
                let mut bytes = super::sample().into_bytes();
                if let Some(b) = bytes.get_mut(cut) {
                    *b = byte;
                }
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    let _ = parse(text);
                }
            }

            #[test]
            fn arbitrary_sources_never_panic(source in ".{0,80}") {
                let _ = parse_source(Some(&source), "p");
            }
        }
    }
}
