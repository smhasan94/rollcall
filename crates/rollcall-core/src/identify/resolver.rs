//! Resolving one module against the database.

use std::collections::BTreeSet;
use std::path::Path;

use super::rules::{FsTree, SourceTree, derive_version};
use super::stub::{Stub, stub};
use super::{IdentifierDb, Level};
use crate::model::{Cpe, Purl, Supplier};

/// What is known about a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query<'a> {
    /// The west module name.
    pub module: &'a str,
    /// The git revision the build used.
    pub revision: Option<&'a str>,
    /// The module's source directory, if available.
    pub path: Option<&'a Path>,
}

/// A module the database lists, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The upstream version, if derived.
    pub version: Option<String>,
    /// How sure the version (and so the purl and cpe) is.
    pub level: Level,
    /// The upstream purl, rendered only when a version was derived.
    pub purl: Option<Purl>,
    /// The upstream cpe, rendered only when a version was derived and the entry has one.
    pub cpe: Option<Cpe>,
    /// The upstream supplier.
    pub supplier: Option<Supplier>,
    /// The upstream project's name.
    pub upstream_name: String,
    /// The version rule's kind (`git_tag`, `file_regex`, `manual`).
    pub rule: &'static str,
    /// Why there is no version, or a template could not be rendered.
    pub note: Option<String>,
}

/// The result of [`Resolver::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The database lists the module.
    Identified(Identity),
    /// The database does not list the module. `stub` is `Some` only the first time this
    /// resolver sees the module, so callers warn exactly once per module.
    Unknown {
        /// A ready-to-paste entry, the first time.
        stub: Option<Stub>,
    },
}

/// Resolves modules against one database, remembering which unknown modules it has already
/// reported.
#[derive(Debug, Clone)]
pub struct Resolver<'db> {
    db: &'db IdentifierDb,
    warned: BTreeSet<String>,
}

impl<'db> Resolver<'db> {
    /// A resolver over `db` that has reported nothing yet.
    pub fn new(db: &'db IdentifierDb) -> Self {
        Self {
            db,
            warned: BTreeSet::new(),
        }
    }

    /// The database.
    pub fn db(&self) -> &'db IdentifierDb {
        self.db
    }

    /// The unknown modules seen so far, sorted.
    pub fn unknown_modules(&self) -> impl Iterator<Item = &str> {
        self.warned.iter().map(String::as_str)
    }

    /// Resolves `query`, reading the module's sources at `query.path` if given. `url` (the
    /// module's repository) only prefills the stub of an unknown module.
    pub fn resolve(&mut self, query: &Query<'_>, url: Option<&str>) -> Outcome {
        let tree = query.path.map(FsTree::new);
        self.resolve_in(query, url, tree.as_ref().map(|t| t as &dyn SourceTree))
    }

    /// [`Resolver::resolve`] with an explicit source tree.
    pub fn resolve_in(
        &mut self,
        query: &Query<'_>,
        url: Option<&str>,
        tree: Option<&dyn SourceTree>,
    ) -> Outcome {
        let Some(entry) = self.db.get(query.module) else {
            let first = self.warned.insert(query.module.to_owned());
            return Outcome::Unknown {
                stub: first.then(|| stub(query.module, url, query.revision)),
            };
        };
        let derived = derive_version(&entry.version_rule, query.revision, tree);
        // Only problems are noted (not, say, which tag gave the version).
        let mut notes: Vec<String> = match derived.version {
            None => derived.note.into_iter().collect(),
            Some(_) => Vec::new(),
        };
        let (purl, cpe) = match &derived.version {
            Some(version) => {
                let purl = entry
                    .purl
                    .render(version)
                    .map_err(|e| notes.push(format!("purl not rendered: {e}")))
                    .ok();
                let cpe = entry.cpe.as_ref().and_then(|t| {
                    t.render(version)
                        .map_err(|e| notes.push(format!("cpe not rendered: {e}")))
                        .ok()
                });
                (purl, cpe)
            }
            None => (None, None),
        };
        let supplier = entry
            .upstream
            .supplier
            .as_deref()
            .and_then(|s| Supplier::new(s.trim()).ok());
        Outcome::Identified(Identity {
            version: derived.version,
            level: derived.level,
            purl,
            cpe,
            supplier,
            upstream_name: entry.upstream.name.clone(),
            rule: entry.version_rule.kind(),
            note: (!notes.is_empty()).then(|| notes.join("; ")),
        })
    }
}

impl Identity {
    /// Whether the version came from reading source text (a `file_regex` rule).
    pub fn from_source(&self) -> bool {
        self.rule == "file_regex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identify::load_str;
    use crate::identify::rules::MemTree;

    const DB: &str = "schema: 1
modules:
  mbedtls:
    upstream:
      name: Mbed TLS
      supplier: Arm
    purl: pkg:github/Mbed-TLS/mbedtls@v{version}
    cpe: cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*
    version_rule:
      kind: manual
      table:
        a3e190fe44c78d1ba67f55979e1257328cc7d0d8: 4.1.0
  lib:
    upstream:
      name: Lib
    purl: pkg:generic/lib@{version}
    version_rule:
      kind: file_regex
      file: VERSION
      pattern: '(?P<version>\\S+)'
";
    const SHA: &str = "a3e190fe44c78d1ba67f55979e1257328cc7d0d8";

    #[test]
    fn known_module_resolves_purl_cpe_supplier() {
        let db = load_str("identifiers.yaml", DB).unwrap();
        let mut resolver = Resolver::new(&db);
        let query = Query {
            module: "mbedtls",
            revision: Some(SHA),
            path: None,
        };
        let Outcome::Identified(id) = resolver.resolve(&query, None) else {
            panic!("unknown");
        };
        assert_eq!(id.version.as_deref(), Some("4.1.0"));
        assert_eq!(id.level, Level::High);
        assert_eq!(
            id.purl.as_ref().unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        assert_eq!(
            id.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*"
        );
        assert_eq!(id.supplier.as_ref().unwrap().name(), "Arm");
        assert_eq!(id.upstream_name, "Mbed TLS");
        assert!(!id.from_source());
        // An unlisted fork revision: low, and no purl or cpe from a commit hash.
        let query = Query {
            revision: Some("ffff"),
            ..query
        };
        let Outcome::Identified(id) = resolver.resolve(&query, None) else {
            panic!("unknown");
        };
        assert_eq!(
            (id.version, id.level, id.purl, id.cpe),
            (None, Level::Low, None, None)
        );
        assert_eq!(
            id.note.as_deref(),
            Some("revision ffff is not in the manual table")
        );
        // A file_regex module through a tree.
        let tree = MemTree {
            files: [("VERSION".to_owned(), "2.0.1\n".to_owned())].into(),
            ..MemTree::default()
        };
        let query = Query {
            module: "lib",
            revision: Some(SHA),
            path: None,
        };
        let Outcome::Identified(id) = resolver.resolve_in(&query, None, Some(&tree)) else {
            panic!("unknown");
        };
        assert_eq!(id.level, Level::Medium);
        assert_eq!(id.purl.as_ref().unwrap().as_str(), "pkg:generic/lib@2.0.1");
        assert!(id.from_source());
        assert_eq!(resolver.unknown_modules().count(), 0);
    }

    #[test]
    fn unknown_module_warns_once_and_yields_stub() {
        let db = load_str("identifiers.yaml", DB).unwrap();
        let mut resolver = Resolver::new(&db);
        let query = |module| Query {
            module,
            revision: Some(SHA),
            path: None,
        };
        let url = Some("https://github.com/zephyrproject-rtos/hal_nordic");
        let first = resolver.resolve(&query("hal_nordic"), url);
        let Outcome::Unknown { stub: Some(stub) } = first else {
            panic!("expected a stub, got {first:?}");
        };
        assert_eq!(stub.module(), "hal_nordic");
        assert!(stub.to_string().starts_with("  hal_nordic:\n"), "{stub}");
        // The second and later queries, for any revision, give no stub.
        for _ in 0..3 {
            assert_eq!(
                resolver.resolve(&query("hal_nordic"), url),
                Outcome::Unknown { stub: None }
            );
        }
        let Outcome::Unknown { stub: Some(_) } = resolver.resolve(&query("cmsis_6"), None) else {
            panic!("cmsis_6 should get its own stub");
        };
        assert_eq!(
            resolver.unknown_modules().collect::<Vec<_>>(),
            ["cmsis_6", "hal_nordic"]
        );
    }
}
