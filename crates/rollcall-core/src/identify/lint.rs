//! The identifier database lint (`rollcall identifiers lint`, CI job `identifiers-lint`).
//!
//! [`lint_text`] checks a database's text; [`lint_fixtures`] checks that it resolves every
//! module of real Zephyr builds. Both return [`Finding`]s, sorted, and never panic: a database
//! that does not even parse is one finding, not a crash.
//!
//! | Rule | Finding |
//! |------|---------|
//! | `schema` | the YAML is malformed or does not match the schema (unknown key, missing field, bad module name, `schema` other than 1, …) |
//! | `purl` | a `purl` template that does not render to a valid purl |
//! | `cpe` | a `cpe` or `cpe_aliases` template that does not render to a CPE 2.3 name, or a repeated alias |
//! | `duplicate` | a module listed twice (both lines named) |
//! | `unsorted` | modules not in name order |
//! | `db-version` | no `db_version`, one that is not semver, or one this rollcall does not accept |
//! | `version-mismatch` | `db_version` differs from the expected version (the `rollcall-identifiers` crate version) |
//! | `self-resolve` | a `manual` table row that does not resolve to a purl (and cpe, if the entry has one) |
//! | `fixture-resolve` | a module of a fixture build that the database does not list, or that gets no purl from it |
//!
//! The loader stops at its first error, so when a database does not load each module entry
//! is also loaded on its own, and every bad entry is reported. Those entries, and the
//! `duplicate` and `unsorted` findings, come from a line scan of the `modules:` mapping
//! (block style, one module per key line, as the shipped database is written).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::version::{DbVersion, check_compatible};
use super::{IdentifierDb, LoadError, Outcome, Query, Resolver, VersionRule, load_str};
use crate::model::{ComponentKind, EvidenceField};
use crate::zephyr::{self, IngestOptions};

/// What a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Rule {
    /// Malformed YAML or a schema violation.
    Schema,
    /// A bad purl template.
    Purl,
    /// A bad cpe or cpe alias template.
    Cpe,
    /// A module listed twice.
    Duplicate,
    /// Modules not sorted by name.
    Unsorted,
    /// A missing, malformed or unaccepted `db_version`.
    DbVersion,
    /// `db_version` is not the expected version.
    VersionMismatch,
    /// A manual-table row that does not resolve.
    SelfResolve,
    /// A fixture module that does not resolve.
    FixtureResolve,
}

impl Rule {
    /// The rule's name in findings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Purl => "purl",
            Self::Cpe => "cpe",
            Self::Duplicate => "duplicate",
            Self::Unsorted => "unsorted",
            Self::DbVersion => "db-version",
            Self::VersionMismatch => "version-mismatch",
            Self::SelfResolve => "self-resolve",
            Self::FixtureResolve => "fixture-resolve",
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One problem: `<file>:<line>: <rule>: <message>` (no `:<line>` when it has none).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Finding {
    /// The database file, as cited.
    pub file: String,
    /// The 1-based line, if known.
    pub line: Option<u32>,
    /// The rule.
    pub rule: Rule,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}: {}", self.file, self.rule, self.message),
            None => write!(f, "{}: {}: {}", self.file, self.rule, self.message),
        }
    }
}

/// The result of [`lint_text`].
#[derive(Debug, Clone)]
pub struct TextLint {
    /// The database, if it loads.
    pub db: Option<IdentifierDb>,
    /// Every finding, sorted.
    pub findings: Vec<Finding>,
}

/// One module's lines in the `modules:` mapping: `start` is its key line, `end` the first
/// line after it (both 1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleBlock {
    /// The module name.
    pub name: String,
    /// The key line.
    pub start: u32,
    /// The first line after the block.
    pub end: u32,
}

/// Each module of the `modules:` mapping, in file order. Only block style is seen (a
/// flow-style mapping yields nothing; the loader still checks it).
pub fn module_blocks(text: &str) -> Vec<ModuleBlock> {
    let mut blocks: Vec<ModuleBlock> = Vec::new();
    let mut in_modules = false;
    let mut indent: Option<usize> = None;
    let mut last_line = 0;
    for (n, line) in text.lines().enumerate() {
        let line_no = u32::try_from(n + 1).unwrap_or(u32::MAX);
        last_line = line_no;
        let content = line.trim_start_matches(' ');
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let depth = line.len() - content.len();
        if depth == 0 {
            if in_modules && let Some(open) = blocks.last_mut().filter(|b| b.end == 0) {
                open.end = line_no;
            }
            in_modules = content.trim_end() == "modules:"
                || content
                    .strip_prefix("modules:")
                    .is_some_and(|rest| rest.trim_start().starts_with('#'));
            indent = None;
            continue;
        }
        if !in_modules || content.starts_with('-') {
            continue;
        }
        let depth_of_keys = *indent.get_or_insert(depth);
        if depth != depth_of_keys {
            continue;
        }
        if let Some(key) = key_of(content) {
            if let Some(open) = blocks.last_mut().filter(|b| b.end == 0) {
                open.end = line_no;
            }
            blocks.push(ModuleBlock {
                name: key,
                start: line_no,
                end: 0,
            });
        }
    }
    if let Some(open) = blocks.last_mut().filter(|b| b.end == 0) {
        open.end = last_line.saturating_add(1);
    }
    blocks
}

/// Each module key of the `modules:` mapping and its 1-based line, in file order
/// ([`module_blocks`]).
pub fn module_keys(text: &str) -> Vec<(String, u32)> {
    module_blocks(text)
        .into_iter()
        .map(|b| (b.name, b.start))
        .collect()
}

/// Loads each module block on its own, so that every bad entry is reported, not only the
/// first the loader meets. Lines are mapped back to `text`.
fn per_entry_findings(file: &str, text: &str, blocks: &[ModuleBlock]) -> Vec<Finding> {
    const HEADER: &str = "schema: 1\nmodules:\n";
    let lines: Vec<&str> = text.lines().collect();
    let mut findings = Vec::new();
    for block in blocks {
        let from = usize::try_from(block.start)
            .unwrap_or(usize::MAX)
            .saturating_sub(1);
        let to = usize::try_from(block.end)
            .unwrap_or(usize::MAX)
            .saturating_sub(1)
            .min(lines.len());
        let Some(body) = lines.get(from..to) else {
            continue;
        };
        let snippet = format!("{HEADER}{}\n", body.join("\n"));
        let Err(e) = load_str(file, &snippet) else {
            continue;
        };
        let mut f = from_load_error(&e, file, &snippet, &|_| Some(block.start));
        f.line = match &e {
            // The block's first line is line 3 of the snippet.
            LoadError::Yaml { line: Some(n), .. } if *n >= 3 => {
                Some(block.start.saturating_add(n - 3))
            }
            _ => Some(block.start),
        };
        findings.push(f);
    }
    findings
}

/// The key of a `key:` line (plain, `'single'` or `"double"` quoted), if it is one.
fn key_of(content: &str) -> Option<String> {
    let (key, rest) = match content.chars().next()? {
        quote @ ('\'' | '"') => {
            let inner = &content[1..];
            let end = inner.find(quote)?;
            (inner[..end].to_owned(), &inner[end + 1..])
        }
        _ => {
            let end = content.find(':')?;
            (content[..end].trim_end().to_owned(), &content[end..])
        }
    };
    let after = rest.strip_prefix(':')?;
    (after.is_empty() || after.starts_with(' ')).then_some(key)
}

/// The 1-based line of the first top-level `<key>:` line.
fn top_level_line(text: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key}:");
    text.lines()
        .position(|l| l.starts_with(&prefix))
        .and_then(|n| u32::try_from(n + 1).ok())
}

/// Lints the database text `text`, cited as `file`. With `expected`, `db_version` must equal
/// it (the shipped database's `db_version` is the `rollcall-identifiers` crate version).
pub fn lint_text(file: &str, text: &str, expected: Option<&DbVersion>) -> TextLint {
    let mut findings = Vec::new();
    let finding = |line: Option<u32>, rule: Rule, message: String| Finding {
        file: file.to_owned(),
        line,
        rule,
        message,
    };

    // Duplicates and order, from the key lines.
    let blocks = module_blocks(text);
    let keys: Vec<(String, u32)> = blocks.iter().map(|b| (b.name.clone(), b.start)).collect();
    let mut first_line: BTreeMap<&str, u32> = BTreeMap::new();
    let mut previous: Option<(&str, u32)> = None;
    for (name, line) in &keys {
        if let Some(first) = first_line.get(name.as_str()) {
            findings.push(finding(
                Some(*line),
                Rule::Duplicate,
                format!("module {name} is listed twice (lines {first} and {line})"),
            ));
            continue;
        }
        first_line.insert(name, *line);
        if let Some((prev, prev_line)) = previous
            && name.as_str() < prev
        {
            findings.push(finding(
                Some(*line),
                Rule::Unsorted,
                format!(
                    "module {name} comes after {prev} (line {prev_line}); keep modules sorted by name"
                ),
            ));
        }
        previous = Some((name, *line));
    }
    let has_duplicates = findings.iter().any(|f| f.rule == Rule::Duplicate);
    let module_line = |module: &str| first_line.get(module).copied();

    // Everything the loader checks: schema, templates, duplicates it alone can see.
    let db = match load_str(file, text) {
        Ok(db) => Some(db),
        Err(e) => {
            // The loader stops at its first error; each entry on its own shows the others.
            let whole = from_load_error(&e, file, text, &module_line);
            let per_entry = per_entry_findings(file, text, &blocks);
            let in_a_block = whole
                .line
                .is_some_and(|l| blocks.iter().any(|b| l >= b.start && l < b.end));
            let explained = (has_duplicates && whole.rule == Rule::Duplicate)
                || (in_a_block && !per_entry.is_empty());
            if !explained {
                findings.push(whole);
            }
            findings.extend(per_entry);
            None
        }
    };

    if let Some(db) = &db {
        let version_line = top_level_line(text, "db_version");
        match db.db_version() {
            None => findings.push(finding(
                top_level_line(text, "schema"),
                Rule::DbVersion,
                "no db_version; add `db_version: 'X.Y.Z'` after `schema: 1`".to_owned(),
            )),
            Some(version) => {
                if let Err(e) = check_compatible(version) {
                    findings.push(finding(version_line, Rule::DbVersion, e.to_string()));
                }
                if let Some(expected) = expected
                    && version != expected
                {
                    findings.push(finding(
                        version_line,
                        Rule::VersionMismatch,
                        format!(
                            "db_version {version} differs from the expected {expected} (the rollcall-identifiers crate version); bump both together"
                        ),
                    ));
                }
            }
        }
        findings.extend(self_resolve(db, file, &module_line));
    }
    findings.sort();
    findings.dedup();
    TextLint { db, findings }
}

/// A load error as a finding.
fn from_load_error(
    e: &LoadError,
    file: &str,
    text: &str,
    module_line: &dyn Fn(&str) -> Option<u32>,
) -> Finding {
    let (line, rule, message) = match e {
        LoadError::Yaml { line, message, .. } => {
            let rule = if message.contains("is listed twice") && message.starts_with("modules") {
                Rule::Duplicate
            } else if yaml_path_has(message, "purl") {
                Rule::Purl
            } else if yaml_path_has(message, "cpe") || yaml_path_has(message, "cpe_aliases") {
                Rule::Cpe
            } else if yaml_path_has(message, "db_version") {
                Rule::DbVersion
            } else {
                Rule::Schema
            };
            (*line, rule, message.clone())
        }
        LoadError::UnsupportedSchema { found, .. } => (
            top_level_line(text, "schema"),
            Rule::Schema,
            format!(
                "unsupported schema {found}; this rollcall reads schema {}",
                super::db::SCHEMA
            ),
        ),
        LoadError::Invalid { module, reason, .. } => {
            let rule = if reason.contains("cpe") {
                Rule::Cpe
            } else {
                Rule::Schema
            };
            (
                module_line(module),
                rule,
                format!("module {module}: {reason}"),
            )
        }
        LoadError::Empty { .. } => (None, Rule::Schema, "empty identifier database".to_owned()),
        other => (None, Rule::Schema, other.to_string()),
    };
    Finding {
        file: file.to_owned(),
        line,
        rule,
        message,
    }
}

/// Whether the YAML path a loader message starts with (`modules.a.purl: …`) ends in `field`.
fn yaml_path_has(message: &str, field: &str) -> bool {
    message
        .split_once(": ")
        .is_some_and(|(path, _)| path.rsplit('.').next() == Some(field) || path == field)
}

/// Every `manual` table row must resolve to a purl, and to a cpe when the entry has one.
fn self_resolve(
    db: &IdentifierDb,
    file: &str,
    module_line: &dyn Fn(&str) -> Option<u32>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut resolver = Resolver::new(db);
    for (module, entry) in db.modules() {
        let VersionRule::Manual { table } = &entry.version_rule else {
            continue;
        };
        for (revision, _) in table.iter() {
            let query = Query {
                module,
                revision: Some(revision),
                path: None,
            };
            let problem = match resolver.resolve_in(&query, None, None) {
                Outcome::Identified(id) if id.purl.is_none() => Some(format!(
                    "no purl ({})",
                    id.note.as_deref().unwrap_or("not rendered")
                )),
                Outcome::Identified(id) if entry.cpe.is_some() && id.cpe.is_none() => Some(
                    format!("no cpe ({})", id.note.as_deref().unwrap_or("not rendered")),
                ),
                Outcome::Identified(_) => None,
                Outcome::Unknown { .. } => Some("not found".to_owned()),
            };
            if let Some(problem) = problem {
                findings.push(Finding {
                    file: file.to_owned(),
                    line: module_line(module),
                    rule: Rule::SelfResolve,
                    message: format!("module {module} revision {revision}: {problem}"),
                });
            }
        }
    }
    findings
}

/// What [`lint_fixtures`] checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixtureLint {
    /// The sysbuild build directories ingested, sorted.
    pub builds: Vec<PathBuf>,
    /// Module components checked across them.
    pub modules: usize,
    /// Every finding, sorted.
    pub findings: Vec<Finding>,
}

/// The sysbuild build directories under `root`: `root` itself, or its immediate
/// subdirectories, that hold both `build_info.yml` and `west-list.txt` (as every
/// `fixtures/zephyr/<variant>/` does). Sorted.
pub fn fixture_builds(root: &Path) -> Vec<PathBuf> {
    let is_build =
        |dir: &Path| dir.join("build_info.yml").is_file() && dir.join("west-list.txt").is_file();
    if is_build(root) {
        return vec![root.to_owned()];
    }
    let mut builds: Vec<PathBuf> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| is_build(p))
        .collect();
    builds.sort();
    builds
}

/// Ingests every build under `root` ([`fixture_builds`], with `--sysbuild` and its
/// `west-list.txt`) with `db`, cited as `file`, and reports each module the database does not
/// list or gives no purl.
pub fn lint_fixtures(db: &IdentifierDb, file: &str, root: &Path) -> FixtureLint {
    let mut lint = FixtureLint {
        builds: fixture_builds(root),
        ..FixtureLint::default()
    };
    let finding = |line: Option<u32>, message: String| Finding {
        file: file.to_owned(),
        line,
        rule: Rule::FixtureResolve,
        message,
    };
    if lint.builds.is_empty() {
        lint.findings.push(finding(
            None,
            format!(
                "no fixture builds (a directory with build_info.yml and west-list.txt) in {}",
                root.display()
            ),
        ));
        return lint;
    }
    for build in &lint.builds {
        let options = IngestOptions::new(build)
            .with_sysbuild(true)
            .with_west_list(build.join("west-list.txt"));
        let ingest = match zephyr::ingest_with_db(&options, Some(db)) {
            Ok(ingest) => ingest,
            Err(e) => {
                lint.findings.push(finding(
                    None,
                    format!("{}: cannot ingest: {e}", build.display()),
                ));
                continue;
            }
        };
        for unknown in &ingest.unknown_modules {
            lint.findings.push(finding(
                None,
                format!(
                    "{}: module {} is not in the database",
                    build.display(),
                    unknown.name
                ),
            ));
        }
        for image in &ingest.product.images {
            for c in image
                .components
                .iter()
                .filter(|c| c.kind == ComponentKind::Library)
            {
                lint.modules += 1;
                let from_db = c
                    .evidence
                    .iter()
                    .any(|e| e.field == EvidenceField::Purl && e.source() == "identifier-db");
                let unknown = ingest.unknown_modules.iter().any(|u| u.name == c.name);
                if !from_db && !unknown {
                    lint.findings.push(finding(
                        None,
                        format!(
                            "{}: image {}: module {} gets no purl from the database",
                            build.display(),
                            image.name,
                            c.name
                        ),
                    ));
                }
            }
        }
    }
    lint.findings.sort();
    lint
}
