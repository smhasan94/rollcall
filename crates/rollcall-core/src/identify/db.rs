//! Loading an identifier database from YAML. See the [module docs](super) for the schema.
//!
//! The loader never panics: every problem is a [`LoadError`] naming the file, and the line
//! and column where the YAML parser can place it.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};

use super::{Entry, IdentifierDb, VersionRule};
use crate::model::check_iri_reference_chars;

/// The schema version this rollcall reads.
pub const SCHEMA: u32 = 1;

/// Why an identifier database could not be loaded. Every variant names the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file could not be read.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// The file is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// The file is empty (or only whitespace and comments).
    #[error("{}: empty identifier database", path.display())]
    Empty {
        /// The file.
        path: PathBuf,
    },
    /// The YAML is malformed or does not match the schema.
    #[error("{}: {message}", Located(path, *line, *column))]
    Yaml {
        /// The file.
        path: PathBuf,
        /// The 1-based line, if known.
        line: Option<u32>,
        /// The 1-based column, if known.
        column: Option<u32>,
        /// What is wrong, with the YAML path (e.g. `modules.mbedtls.purl`).
        message: String,
    },
    /// `schema` is not a version this rollcall reads.
    #[error("{}: unsupported schema {found}; this rollcall reads schema {SCHEMA}", path.display())]
    UnsupportedSchema {
        /// The file.
        path: PathBuf,
        /// The `schema` value.
        found: u32,
    },
    /// An entry is well-formed YAML but unusable.
    #[error("{}: module {module}: {reason}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// The module.
        module: String,
        /// What is wrong.
        reason: String,
    },
}

impl LoadError {
    /// True when the file could not be read (missing, a directory, no permission, …).
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Read { .. })
    }
}

/// `path`, `path:line` or `path:line:column`.
struct Located<'a>(&'a Path, Option<u32>, Option<u32>);

impl fmt::Display for Located<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())?;
        if let Some(line) = self.1 {
            write!(f, ":{line}")?;
            if let Some(column) = self.2 {
                write!(f, ":{column}")?;
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDb {
    schema: u32,
    modules: Modules,
}

/// The `modules:` mapping, rejecting duplicate and malformed module names (a plain map would
/// silently keep the last duplicate). Such an error is located at the start of the `modules:`
/// mapping (its first key), not at the offending key.
struct Modules(BTreeMap<String, Entry>);

/// Whether `name` is a usable module name: `[A-Za-z0-9_.+-]+`.
fn is_module_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

impl<'de> Deserialize<'de> for Modules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ModulesVisitor;
        impl<'de> Visitor<'de> for ModulesVisitor {
            type Value = Modules;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a mapping of module name to entry")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Modules, A::Error> {
                let mut modules = BTreeMap::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !is_module_name(&name) {
                        return Err(de::Error::custom(format!(
                            "module name {name:?} must match [A-Za-z0-9_.+-]+"
                        )));
                    }
                    if modules.contains_key(&name) {
                        return Err(de::Error::custom(format!("module {name} is listed twice")));
                    }
                    let entry: Entry = map.next_value()?;
                    modules.insert(name, entry);
                }
                Ok(Modules(modules))
            }
        }
        d.deserialize_map(ModulesVisitor)
    }
}

/// Reads and loads the database at `path`. It is cited (in warnings and evidence) by its file
/// name.
pub fn load(path: &Path) -> Result<IdentifierDb, LoadError> {
    let bytes = std::fs::read(path).map_err(|source| LoadError::Read {
        path: path.to_owned(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| LoadError::NotUtf8 {
        path: path.to_owned(),
    })?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "identifier-db".to_owned());
    parse(path, &name, &text)
}

/// Loads a database from text, citing it as `name` in errors, warnings and evidence.
pub fn load_str(name: &str, text: &str) -> Result<IdentifierDb, LoadError> {
    parse(Path::new(name), name, text)
}

/// `message` without a trailing ` at line N column M` that repeats the error's own location
/// (already printed as `path:N:M:`). Any other trailing location is kept.
fn without_location(message: &str, line: Option<u32>, column: Option<u32>) -> &str {
    match (line, column) {
        (Some(line), Some(column)) => message
            .strip_suffix(&format!(" at line {line} column {column}"))
            .unwrap_or(message),
        _ => message,
    }
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn parse(path: &Path, name: &str, text: &str) -> Result<IdentifierDb, LoadError> {
    if text.trim().is_empty() {
        return Err(LoadError::Empty {
            path: path.to_owned(),
        });
    }
    let raw: Option<RawDb> = yaml_serde::from_str(text).map_err(|e| {
        let location = e.location();
        let line = location.as_ref().map(|l| to_u32(l.line()));
        let column = location.as_ref().map(|l| to_u32(l.column()));
        LoadError::Yaml {
            path: path.to_owned(),
            line,
            column,
            message: without_location(&e.to_string(), line, column).to_owned(),
        }
    })?;
    let Some(raw) = raw else {
        return Err(LoadError::Empty {
            path: path.to_owned(),
        });
    };
    if raw.schema != SCHEMA {
        return Err(LoadError::UnsupportedSchema {
            path: path.to_owned(),
            found: raw.schema,
        });
    }
    for (module, entry) in &raw.modules.0 {
        validate(entry).map_err(|reason| LoadError::Invalid {
            path: path.to_owned(),
            module: module.clone(),
            reason,
        })?;
    }
    Ok(IdentifierDb {
        schema: raw.schema,
        modules: raw.modules.0,
        name: name.to_owned(),
    })
}

/// Checks what the deserialiser cannot see.
fn validate(entry: &Entry) -> Result<(), String> {
    let upstream = &entry.upstream;
    if upstream.name.trim().is_empty() {
        return Err("upstream.name must not be empty".to_owned());
    }
    if upstream
        .supplier
        .as_deref()
        .is_some_and(|s| s.trim().is_empty())
    {
        return Err("upstream.supplier must not be empty when given".to_owned());
    }
    if let Some(homepage) = &upstream.homepage {
        if homepage.is_empty() {
            return Err("upstream.homepage must not be empty when given".to_owned());
        }
        check_iri_reference_chars(homepage)
            .map_err(|reason| format!("upstream.homepage {homepage:?}: {reason}"))?;
    }
    if !entry.cpe_aliases.is_empty() {
        let Some(cpe) = &entry.cpe else {
            return Err("cpe_aliases needs a cpe (the primary CPE)".to_owned());
        };
        let mut seen = std::collections::BTreeSet::from([cpe.as_str()]);
        for alias in &entry.cpe_aliases {
            if !seen.insert(alias.as_str()) {
                return Err(format!(
                    "cpe_aliases repeats {} (already the cpe or an alias)",
                    alias.as_str()
                ));
            }
        }
    }
    if let VersionRule::Manual { table } = &entry.version_rule {
        if table.is_empty() {
            return Err("version_rule.table must list at least one revision".to_owned());
        }
        for (revision, version) in table.iter() {
            if revision.trim().is_empty() || revision.chars().any(char::is_whitespace) {
                return Err(format!(
                    "version_rule.table revision {revision:?} must be non-empty without whitespace"
                ));
            }
            if version.trim().is_empty() {
                return Err(format!(
                    "version_rule.table[{revision}] must not be an empty version"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const GOOD: &str = "schema: 1
modules:
  a:
    upstream:
      name: A
    purl: pkg:generic/a@{version}
    cpe: cpe:2.3:a:a:a:{version}:*:*:*:*:*:*:*
    version_rule:
      kind: manual
      table:
        abc: 1.0.0
";

    fn yaml_location(e: &LoadError) -> (Option<u32>, Option<u32>) {
        match e {
            LoadError::Yaml { line, column, .. } => (*line, *column),
            other => panic!("not a YAML error: {other}"),
        }
    }

    #[test]
    fn good_database_loads() {
        let db = load_str("identifiers.yaml", GOOD).unwrap();
        assert_eq!(db.name(), "identifiers.yaml");
        assert_eq!(db.schema(), 1);
        let entry = db.get("a").unwrap();
        assert_eq!(entry.purl.as_str(), "pkg:generic/a@{version}");
        assert_eq!(entry.version_rule.kind(), "manual");
    }

    #[test]
    fn invalid_purl_template_is_rejected_with_file_and_line() {
        let text = GOOD.replace("pkg:generic/a@{version}", "pkg:x{version}");
        let e = load_str("identifiers.yaml", &text).unwrap_err();
        // `purl:` is on line 6; the scalar starts at column 11.
        assert_eq!(yaml_location(&e), (Some(6), Some(11)), "{e}");
        let shown = e.to_string();
        assert!(shown.starts_with("identifiers.yaml:6:11: "), "{shown}");
        assert!(shown.contains("modules.a.purl"), "{shown}");
        assert!(shown.contains("purl"), "{shown}");
    }

    #[test]
    fn invalid_cpe_template_is_rejected_with_file_and_line() {
        for bad in [
            "cpe:2.3:a:a:a:{version}:*:*:*:*:*:*",
            "cpe:2.3:a:a a:a:{version}:*:*:*:*:*:*:*",
            "cpe:/a:a:a:{version}",
            "cpe:2.3:a:a:a:1.0:*:*:*:*:*:*:*",
        ] {
            let text = GOOD.replace("cpe:2.3:a:a:a:{version}:*:*:*:*:*:*:*", bad);
            let e = load_str("identifiers.yaml", &text).unwrap_err();
            assert_eq!(yaml_location(&e), (Some(7), Some(10)), "{bad}: {e}");
            let shown = e.to_string();
            assert!(shown.starts_with("identifiers.yaml:7:10: "), "{shown}");
            assert!(shown.contains("modules.a.cpe"), "{shown}");
        }
    }

    #[test]
    fn yaml_error_prints_its_location_once() {
        let text = GOOD.replace("pkg:generic/a@{version}", "pkg:generic/a@{ver}");
        let e = load_str("identifiers.yaml", &text).unwrap_err();
        assert_eq!(
            e.to_string(),
            "identifiers.yaml:6:11: modules.a.purl: unknown placeholder {ver}; the only placeholder is {version}"
        );
        // A trailing location that is not the error's own is kept.
        let e = load_str(
            "identifiers.yaml",
            "schema: 1\nmodules: {a: {upstream: {name: A",
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "identifiers.yaml:3:1: did not find expected ',' or '}' at line 3 column 1, while parsing a flow mapping at line 2 column 25"
        );
        assert_eq!(
            without_location("m at line 1 column 2", Some(1), Some(2)),
            "m"
        );
        assert_eq!(
            without_location("m at line 1 column 2", Some(1), Some(3)),
            "m at line 1 column 2"
        );
        assert_eq!(
            without_location("m at line 1 column 2", None, None),
            "m at line 1 column 2"
        );
    }

    #[test]
    fn duplicate_module_is_rejected() {
        let text = format!(
            "{GOOD}  a:\n    upstream: {{name: A2}}\n    purl: pkg:generic/a@{{version}}\n    version_rule: {{kind: manual, table: {{x: '1'}}}}\n"
        );
        let e = load_str("identifiers.yaml", &text).unwrap_err();
        let shown = e.to_string();
        assert!(shown.contains("module a is listed twice"), "{shown}");
        assert!(yaml_location(&e).0.is_some(), "{shown}");
    }

    /// A malformed database: the text and a fragment the error must contain.
    fn malformed_cases() -> Vec<(String, String, &'static str)> {
        let entry = |purl: &str, rule: &str| {
            format!(
                "schema: 1\nmodules:\n  a:\n    upstream:\n      name: A\n    purl: {purl}\n    version_rule:\n{rule}"
            )
        };
        let manual = "      kind: manual\n      table:\n        abc: 1.0.0\n";
        let p = "pkg:generic/a@{version}";
        // Inside version_rule, which serde buffers whole, so every level is actually visited.
        let deep = entry(
            p,
            &format!(
                "      kind: manual\n      table: {{abc: {}{}}}\n",
                "[".repeat(200),
                "]".repeat(200)
            ),
        );
        let deeper = entry(
            p,
            &format!(
                "      kind: manual\n      table: {{abc: {}",
                "[".repeat(10_000)
            ),
        );
        vec![
            ("empty".into(), String::new(), "empty"),
            ("whitespace only".into(), " \n\t\n".into(), "empty"),
            ("comments only".into(), "# nothing\n".into(), "empty"),
            (
                "truncated flow".into(),
                "schema: 1\nmodules: {a: {upstream: {name: A".into(),
                "did not find expected ',' or '}'",
            ),
            (
                "tab indentation".into(),
                "schema: 1\nmodules:\n\ta: 1\n".into(),
                "found character that cannot start any token",
            ),
            (
                "NUL byte".into(),
                "schema: 1\u{0}\nmodules: {}\n".into(),
                "control characters are not allowed",
            ),
            (
                "not a mapping".into(),
                "- 1\n- 2\n".into(),
                "invalid type: sequence, expected struct RawDb",
            ),
            (
                "modules as list".into(),
                "schema: 1\nmodules: [a, b]\n".into(),
                "modules",
            ),
            (
                "entry as scalar".into(),
                "schema: 1\nmodules:\n  a: hello\n".into(),
                "modules.a",
            ),
            ("missing modules".into(), "schema: 1\n".into(), "modules"),
            ("missing schema".into(), "modules: {}\n".into(), "schema"),
            (
                "schema as string".into(),
                "schema: one\nmodules: {}\n".into(),
                "schema",
            ),
            (
                "schema 2".into(),
                "schema: 2\nmodules: {}\n".into(),
                "unsupported schema 2",
            ),
            (
                "unknown top-level field".into(),
                "schema: 1\nmodules: {}\nextra: 1\n".into(),
                "extra",
            ),
            (
                "unknown entry field".into(),
                entry(p, manual).replace("    purl:", "    homepage: x\n    purl:"),
                "homepage",
            ),
            (
                "unknown upstream field".into(),
                entry(p, manual).replace("      name: A", "      name: A\n      url: x"),
                "url",
            ),
            (
                "missing purl".into(),
                entry(p, manual).replace(&format!("    purl: {p}\n"), ""),
                "purl",
            ),
            (
                "missing version_rule".into(),
                entry(p, "").replace("    version_rule:\n", ""),
                "version_rule",
            ),
            (
                "missing upstream name".into(),
                entry(p, manual).replace("      name: A\n", "      supplier: X\n"),
                "name",
            ),
            (
                "version_rule as scalar".into(),
                entry(p, "      manual\n"),
                "version_rule",
            ),
            (
                "unknown kind".into(),
                entry(p, "      kind: semver\n      pattern: x\n"),
                "semver",
            ),
            (
                "missing kind".into(),
                entry(p, "      table: {abc: '1'}\n"),
                "kind",
            ),
            (
                "rule missing pattern".into(),
                entry(p, "      kind: git_tag\n"),
                "pattern",
            ),
            (
                "rule unknown field".into(),
                entry(
                    p,
                    "      kind: git_tag\n      pattern: '(?P<version>.*)'\n      file: x\n",
                ),
                "file",
            ),
            (
                "invalid regex".into(),
                entry(p, "      kind: git_tag\n      pattern: '(?P<version>'\n"),
                "regular expression",
            ),
            (
                "regex without version group".into(),
                entry(p, "      kind: git_tag\n      pattern: 'v(\\d+)'\n"),
                "version",
            ),
            (
                "file_regex absolute file".into(),
                entry(
                    p,
                    "      kind: file_regex\n      file: /etc/version.h\n      pattern: '(?P<version>.*)'\n",
                ),
                "file",
            ),
            (
                "file_regex escaping file".into(),
                entry(
                    p,
                    "      kind: file_regex\n      file: ../version.h\n      pattern: '(?P<version>.*)'\n",
                ),
                "file",
            ),
            (
                "template without {version}".into(),
                entry("pkg:generic/a@1.0", manual),
                "no {version}",
            ),
            (
                "{ver} placeholder".into(),
                entry("pkg:generic/a@{ver}", manual),
                "unknown placeholder {ver}",
            ),
            (
                "unbalanced brace".into(),
                entry("'pkg:generic/a@{version'", manual),
                "unbalanced",
            ),
            ("purl as number".into(), entry("12", manual), "purl"),
            (
                "cpe_aliases without cpe".into(),
                entry(p, manual).replace(
                    "    version_rule:",
                    "    cpe_aliases: ['cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*']\n    version_rule:",
                ),
                "cpe_aliases needs a cpe",
            ),
            (
                "cpe alias repeats cpe".into(),
                entry(p, manual).replace(
                    "    version_rule:",
                    "    cpe: 'cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*'\n    cpe_aliases: ['cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*']\n    version_rule:",
                ),
                "cpe_aliases repeats",
            ),
            (
                "duplicate cpe alias".into(),
                entry(p, manual).replace(
                    "    version_rule:",
                    "    cpe: 'cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*'\n    cpe_aliases: ['cpe:2.3:a:z:y:{version}:*:*:*:*:*:*:*', 'cpe:2.3:a:z:y:{version}:*:*:*:*:*:*:*']\n    version_rule:",
                ),
                "cpe_aliases repeats",
            ),
            (
                "invalid cpe alias".into(),
                entry(p, manual).replace(
                    "    version_rule:",
                    "    cpe: 'cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*'\n    cpe_aliases: ['cpe:2.3:a:z:{version}']\n    version_rule:",
                ),
                "cpe_aliases",
            ),
            (
                "cpe_aliases as scalar".into(),
                entry(p, manual).replace(
                    "    version_rule:",
                    "    cpe: 'cpe:2.3:a:x:y:{version}:*:*:*:*:*:*:*'\n    cpe_aliases: 'cpe:2.3:a:z:y:{version}:*:*:*:*:*:*:*'\n    version_rule:",
                ),
                "cpe_aliases",
            ),
            (
                "empty manual table".into(),
                entry(p, "      kind: manual\n      table: {}\n"),
                "at least one revision",
            ),
            (
                "empty version".into(),
                entry(p, "      kind: manual\n      table:\n        abc: ''\n"),
                "empty version",
            ),
            (
                "manual table as list".into(),
                entry(p, "      kind: manual\n      table: [a]\n"),
                "sequence",
            ),
            (
                "empty upstream name".into(),
                entry(p, manual).replace("name: A", "name: ''"),
                "upstream.name",
            ),
            (
                "bad homepage".into(),
                entry(p, manual).replace(
                    "      name: A",
                    "      name: A\n      homepage: 'https://x/<y>'",
                ),
                "homepage",
            ),
            (
                "bad module name".into(),
                entry(p, manual).replace("  a:\n", "  'a b':\n"),
                "must match",
            ),
            (
                "empty module name".into(),
                entry(p, manual).replace("  a:\n", "  '':\n"),
                "must match",
            ),
            ("200-deep nesting".into(), deep, "recursion limit exceeded"),
            (
                "10000-deep unterminated nesting".into(),
                deeper,
                "recursion limit exceeded",
            ),
            (
                "anchor bomb".into(),
                entry(
                    p,
                    "      kind: manual\n      a: &a [x,x,x,x,x,x,x,x,x]\n      b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n      c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n      d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n      e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n      f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n      g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n      table: {abc: *g}\n",
                ),
                "repetition limit exceeded",
            ),
            (
                "duplicate revision".into(),
                entry(
                    p,
                    "      kind: manual\n      table:\n        abc: 1.0.0\n        abc: 2.0.0\n",
                ),
                "revision abc is listed twice in the manual table",
            ),
        ]
    }

    #[test]
    fn malformed_entries_are_rejected_never_panic() {
        for (what, text, needle) in malformed_cases() {
            let result = std::panic::catch_unwind(|| load_str("identifiers.yaml", &text));
            let Ok(result) = result else {
                panic!("{what}: panicked");
            };
            let e = match result {
                Ok(_) => panic!("{what}: accepted"),
                Err(e) => e,
            };
            let shown = e.to_string();
            assert!(shown.starts_with("identifiers.yaml"), "{what}: {shown}");
            assert!(shown.contains(needle), "{what}: {shown:?} lacks {needle:?}");
        }
    }

    #[test]
    fn non_utf8_and_unreadable_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identifiers.yaml");
        std::fs::write(&path, b"schema: 1\nmodules: {}\n\xff\xfe").unwrap();
        assert!(matches!(load(&path), Err(LoadError::NotUtf8 { .. })));
        let missing = dir.path().join("missing.yaml");
        let e = load(&missing).unwrap_err();
        assert!(e.is_read_error());
        assert!(e.to_string().starts_with(&missing.display().to_string()));
        assert!(load(dir.path()).unwrap_err().is_read_error());
        // A loaded file is cited by its file name.
        std::fs::write(&path, GOOD).unwrap();
        assert_eq!(load(&path).unwrap().name(), "identifiers.yaml");
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
            let _ = load_str("identifiers.yaml", &text);
        }

        #[test]
        fn mutated_database_never_panics(cut in 0usize..GOOD.len(), insert in "[ :{}\\[\\]'\"#&*!|>\\-\\n\\t]{0,4}") {
            let mut text = GOOD.get(..cut).unwrap_or(GOOD).to_owned();
            text.push_str(&insert);
            text.push_str(GOOD.get(cut..).unwrap_or(""));
            let _ = load_str("identifiers.yaml", &text);
        }
    }
}
