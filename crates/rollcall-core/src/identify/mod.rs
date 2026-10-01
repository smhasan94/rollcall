//! The identifier database: Zephyr module → upstream project, purl, cpe and version.
//!
//! A Zephyr module is built from a fork (`zephyrproject-rtos/mbedtls` at some commit), but
//! vulnerability scanners match the *upstream* project and release (`pkg:github/mbed-tls/
//! mbedtls@v4.1.0`, `cpe:2.3:a:arm:mbed_tls:4.1.0:…`). The identifier database says, for each
//! module, which upstream project it is and how to find the upstream version of the revision
//! the build used. [`Resolver`] answers that for one module at a time.
//!
//! # Schema
//!
//! ```yaml
//! schema: 1
//! db_version: '1.0.0'                     # optional here; required by the lint and the cache
//! modules:
//!   mbedtls:                              # the west module name, [A-Za-z0-9_.+-]+
//!     upstream:
//!       name: Mbed TLS                    # required
//!       homepage: https://www.trustedfirmware.org/projects/mbed-tls/   # optional
//!       supplier: Arm                     # optional; becomes the component's supplier
//!     purl: pkg:github/Mbed-TLS/mbedtls@v{version}                     # required
//!     cpe: cpe:2.3:a:trustedfirmware:mbed_tls:{version}:*:*:*:*:*:*:*  # optional
//!     cpe_aliases:                        # optional; other vendor:products NVD files under
//!       - cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*
//!     version_rule:                       # required, exactly one kind
//!       kind: manual
//!       table:
//!         a3e190fe44c78d1ba67f55979e1257328cc7d0d8: 4.1.0
//! ```
//!
//! Unknown keys, a duplicate module, a duplicate revision in a `manual` table, a module name
//! outside `[A-Za-z0-9_.+-]+`, and a `schema` other than `1` are rejected. Every rejection names the file, and, when the YAML parser can
//! place it, the line and column (`identifiers.yaml:7:11: modules.mbedtls.purl: …`). A
//! duplicate module is reported at the start of the `modules:` mapping; problems only visible after
//! parsing (an empty manual table or version, an unusable homepage, `cpe_aliases` without a
//! `cpe` or repeating a template) name the module instead.
//!
//! # Templates
//!
//! `purl`, `cpe` and each of `cpe_aliases` are templates in which `{version}` is the derived
//! upstream version; see [`template`]. All are checked at load time: a template that does not render to a valid
//! purl (by the `packageurl` crate) or CPE 2.3 formatted string ([`cpe::parse`]) is rejected
//! with its line.
//!
//! # Version rules
//!
//! | `kind` | Keys | Upstream version |
//! |--------|------|------------------|
//! | `git_tag` | `pattern` | the `version` group of `pattern` matched against the revision itself (a tag-like revision such as `v2.9.0`), else against the tags pointing at that commit in the module's `.git` (packed and loose refs) |
//! | `file_regex` | `file`, `pattern` | the `version` group of the first match of `pattern` in `file`, relative to the module's source directory (e.g. `include/version.h`) |
//! | `manual` | `table` | `table[revision]` (an exact, case-sensitive match of the full revision), for forks whose commits do not map to an upstream tag |
//!
//! Patterns are Rust regular expressions with a named group `(?P<version>…)`. A `git_tag`
//! pattern is never matched against a revision that looks like a commit id (7 to 64 hex
//! digits); only tags pointing at that commit are.
//!
//! # Confidence
//!
//! | [`Level`] | Basis points | When |
//! |-----------|--------------|------|
//! | `High` | 9000 | a `git_tag` match or a `manual` table hit |
//! | `Medium` | 8000 | a `file_regex` match (source text, not release metadata) |
//! | `Low` | 3000 | no version: no revision, no source tree, no match, or a fork revision missing from the manual table |
//!
//! A purl or cpe is only rendered when a version was derived, since a template filled with a
//! commit hash would name a release that does not exist.
//!
//! # Unknown modules
//!
//! A module the database does not list resolves to [`Outcome::Unknown`]. The first time a
//! [`Resolver`] sees it, the outcome carries a [`Stub`]: a ready-to-paste entry for the
//! `modules:` mapping, prefilled from the module's URL and revision, whose blanks (`""`,
//! `<vendor>`, `<product>`) the user fills in. Later queries for the same module carry no
//! stub, so one resolver gives one warning per module however many images use it.
//!
//! # Versions, sources and lint
//!
//! The seed database lives in the `rollcall-identifiers` crate, whose version is the
//! database's `db_version`, so it is released (and picked up) without a rollcall release.
//! [`version`] holds the pin ([`MIN_DB_VERSION`], [`SUPPORTED_DB_MAJOR`]); [`source`] selects
//! the active database (explicit path, `$ROLLCALL_IDENTIFIERS`, the cache directory, or the
//! embedded one) and loads it next to the embedded one; [`lint`] is
//! `rollcall identifiers lint`.

pub mod cpe;
pub mod db;
pub mod lint;
pub mod resolver;
pub mod rules;
#[cfg(test)]
mod seed;
pub mod source;
pub mod stub;
pub mod template;
pub mod version;

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};

pub use db::{LoadError, load, load_str};
pub use resolver::{Identity, Outcome, Query, Resolver};
pub use rules::{Derived, FsTree, SourceTree, derive_version};
pub use source::{
    DbSource, LoadedDbs, PROP_DB_VERSION, PROP_SOURCE, PROVENANCE_PROPERTIES, SourceError,
    provenance, select,
};
pub use stub::{Stub, stub};
pub use template::{CpeTemplate, Pattern, PurlTemplate, RelPath};
pub use version::{
    DbVersion, DbVersionError, Incompatible, MIN_DB_VERSION, SUPPORTED_DB_MAJOR, check_compatible,
};

/// The seed database shipped with rollcall: the `rollcall-identifiers` crate's
/// `db/identifiers.yaml`, embedded at build time.
pub(crate) const BUILTIN: &str = rollcall_identifiers::IDENTIFIERS_YAML;
/// The name the seed database is cited by.
pub const BUILTIN_NAME: &str = rollcall_identifiers::FILE_NAME;
/// The embedded database's `db_version` (the `rollcall-identifiers` crate version).
pub const BUILTIN_DB_VERSION: &str = rollcall_identifiers::DB_VERSION;

/// A loaded identifier database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifierDb {
    pub(crate) schema: u32,
    pub(crate) db_version: Option<DbVersion>,
    pub(crate) modules: BTreeMap<String, Entry>,
    pub(crate) name: String,
}

impl IdentifierDb {
    /// The file name the database is cited by in warnings and evidence.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The schema version (always 1).
    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// The database's release (`db_version`), if it declares one.
    pub fn db_version(&self) -> Option<&DbVersion> {
        self.db_version.as_ref()
    }

    /// The entry for `module`, if listed.
    pub fn get(&self, module: &str) -> Option<&Entry> {
        self.modules.get(module)
    }

    /// Every module and its entry, sorted by name.
    pub fn modules(&self) -> impl Iterator<Item = (&str, &Entry)> {
        self.modules.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// One module's entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The upstream project.
    pub upstream: Upstream,
    /// The purl template.
    pub purl: PurlTemplate,
    /// The cpe template, if the project has a CPE.
    #[serde(default)]
    pub cpe: Option<CpeTemplate>,
    /// Further cpe templates for the same project: other NVD vendor:product pairs its
    /// vulnerabilities are filed under. Requires `cpe`; none may repeat it or each other.
    #[serde(default)]
    pub cpe_aliases: Vec<CpeTemplate>,
    /// How to find the upstream version.
    pub version_rule: VersionRule,
}

/// The upstream project of a module.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The project's name.
    pub name: String,
    /// Its homepage.
    #[serde(default)]
    pub homepage: Option<String>,
    /// Who supplies it upstream.
    #[serde(default)]
    pub supplier: Option<String>,
}

/// How the upstream version of a revision is found.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VersionRule {
    /// Match a tag: the revision itself, or a tag pointing at it.
    GitTag {
        /// The pattern, with a `version` group.
        pattern: Pattern,
    },
    /// Search a source file.
    FileRegex {
        /// The file, relative to the module.
        file: RelPath,
        /// The pattern, with a `version` group.
        pattern: Pattern,
    },
    /// Look the revision up.
    Manual {
        /// Revision → upstream version.
        table: ManualTable,
    },
}

/// A `manual` rule's table: revision → upstream version, rejecting a revision listed twice
/// (a plain map would silently keep the last one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManualTable(BTreeMap<String, String>);

impl ManualTable {
    /// The upstream version of exactly `revision`, if listed.
    pub fn get(&self, revision: &str) -> Option<&String> {
        self.0.get(revision)
    }

    /// Every revision and version, sorted by revision.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    /// Whether the table lists nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<BTreeMap<String, String>> for ManualTable {
    fn from(map: BTreeMap<String, String>) -> Self {
        Self(map)
    }
}

impl<'de> Deserialize<'de> for ManualTable {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct TableVisitor;
        impl<'de> Visitor<'de> for TableVisitor {
            type Value = ManualTable;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a mapping of revision to upstream version")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ManualTable, A::Error> {
                let mut table = BTreeMap::new();
                while let Some(revision) = map.next_key::<String>()? {
                    if table.contains_key(&revision) {
                        return Err(de::Error::custom(format!(
                            "revision {revision} is listed twice in the manual table"
                        )));
                    }
                    let version: String = map.next_value()?;
                    table.insert(revision, version);
                }
                Ok(ManualTable(table))
            }
        }
        d.deserialize_map(TableVisitor)
    }
}

impl VersionRule {
    /// The rule's `kind`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::GitTag { .. } => "git_tag",
            Self::FileRegex { .. } => "file_regex",
            Self::Manual { .. } => "manual",
        }
    }
}

/// How sure a derived version is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// From a tag or the manual table.
    High,
    /// From a source file.
    Medium,
    /// Nothing derived.
    Low,
}

impl Level {
    /// The level as a [`Confidence`](crate::model::Confidence) in basis points.
    pub fn basis_points(self) -> u16 {
        match self {
            Self::High => 9000,
            Self::Medium => 8000,
            Self::Low => 3000,
        }
    }
}

/// The seed database shipped with rollcall (the `rollcall-identifiers` crate).
pub fn builtin() -> Result<IdentifierDb, LoadError> {
    load_str(BUILTIN_NAME, BUILTIN)
}

/// `https://github.com/<owner>/<repo>[.git][/]` → `(owner, repo)`.
pub(crate) fn github_repo(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, repo) = rest.split_once('/')?;
    (!owner.is_empty() && !repo.is_empty() && !repo.contains('/')).then_some((owner, repo))
}
