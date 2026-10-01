//! Validation profiles: which checks to run, at what severity, with which parameters, and
//! which clause of which source document each check encodes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use super::checks::{self, ParamKind, ParamValue, Params};
use super::report::Severity;

/// The `format` tag of a profile file.
pub const FORMAT: &str = "rollcall-profile/1";

/// The built-in profiles, by id, embedded from `profiles/<id>.yaml` in this crate. Adding a
/// profile is one YAML file plus one line here; [`builtin_profiles`] and the CLI pick it up.
const BUILTIN: &[(&str, &str)] = &[
    ("cisa-2026", include_str!("../../profiles/cisa-2026.yaml")),
    ("cra", include_str!("../../profiles/cra.yaml")),
];

/// Where the built-in profiles live, relative to the `rollcall-core` crate.
pub const BUILTIN_DIR: &str = "profiles";

/// Why a profile could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The file could not be read.
    #[error("{path}: {message}")]
    Io {
        /// The file.
        path: String,
        /// The I/O error.
        message: String,
    },
    /// The YAML does not parse, or does not have the profile's shape.
    #[error("not a valid profile: {0}")]
    Yaml(String),
    /// The file is empty.
    #[error("empty profile")]
    Empty,
    /// `format` is not [`FORMAT`].
    #[error("format must be {FORMAT:?}, found {0:?}")]
    Format(String),
    /// `id` is empty, `all`, or not `[a-z0-9][a-z0-9.-]*`.
    #[error("invalid profile id {0:?}: use lowercase letters, digits, '.' and '-', not \"all\"")]
    BadId(String),
    /// A required text field is empty.
    #[error("{0} must not be empty")]
    EmptyField(String),
    /// Two sources share a key.
    #[error("source key {0:?} is defined twice")]
    DuplicateSource(String),
    /// The profile lists no checks.
    #[error("the profile lists no checks")]
    NoChecks,
    /// A check id that is not in the catalogue.
    #[error("unknown check {0:?}")]
    UnknownCheck(String),
    /// A check listed twice.
    #[error("check {0:?} is listed twice")]
    DuplicateCheck(String),
    /// A citation naming a source key the profile does not define.
    #[error("check {check:?} cites unknown source {source_key:?}")]
    UnknownSource {
        /// The check.
        check: String,
        /// The source key.
        source_key: String,
    },
    /// A parameter the check does not take.
    #[error("check {check:?} has no parameter {param:?}")]
    UnknownParam {
        /// The check.
        check: String,
        /// The parameter.
        param: String,
    },
    /// A parameter of the wrong type or with a value not allowed.
    #[error("check {check:?} parameter {param:?}: expected {expected}")]
    BadParam {
        /// The check.
        check: String,
        /// The parameter.
        param: String,
        /// What it should be.
        expected: String,
    },
}

/// A source document a profile cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The key checks cite it by.
    pub key: String,
    /// Its full title (and date).
    pub document: String,
    /// Where to read it.
    pub url: Option<String>,
}

/// The clause a profile check encodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cite {
    /// The cited source's [`Source::document`].
    pub document: String,
    /// The source's URL.
    pub url: Option<String>,
    /// The clause, e.g. `Annex I, Part II, point (1)`.
    pub clause: String,
}

/// One check a profile runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCheck {
    /// The check id (in [`checks::CHECKS`]).
    pub id: String,
    /// The severity of its findings.
    pub severity: Severity,
    /// What it encodes.
    pub cite: Cite,
    /// Its parameters.
    pub params: Params,
}

/// A loaded, validated profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The id, e.g. `cra`.
    pub id: String,
    /// A one-line title.
    pub title: String,
    /// The documents it cites.
    pub sources: Vec<Source>,
    /// The checks, in file order.
    pub checks: Vec<ProfileCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    format: String,
    id: String,
    title: String,
    sources: Vec<RawSource>,
    checks: Vec<RawCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    key: String,
    document: String,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCheck {
    id: String,
    severity: Severity,
    cite: RawCite,
    #[serde(default)]
    params: BTreeMap<String, yaml_serde::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCite {
    source: String,
    clause: String,
}

fn non_empty(field: &str, value: &str) -> Result<(), ProfileError> {
    if value.trim().is_empty() {
        Err(ProfileError::EmptyField(field.to_owned()))
    } else {
        Ok(())
    }
}

fn valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && id != "all"
}

fn parse_params(
    check: &checks::CheckDef,
    raw: BTreeMap<String, yaml_serde::Value>,
) -> Result<Params, ProfileError> {
    let mut params = Params::new();
    for (name, value) in raw {
        let Some(def) = check.params.iter().find(|p| p.name == name) else {
            return Err(ProfileError::UnknownParam {
                check: check.id.to_owned(),
                param: name,
            });
        };
        let bad = |expected: String| ProfileError::BadParam {
            check: check.id.to_owned(),
            param: name.clone(),
            expected,
        };
        let parsed = match (def.kind, value) {
            (ParamKind::Bool, yaml_serde::Value::Bool(b)) => ParamValue::Bool(b),
            (ParamKind::Bool, _) => return Err(bad("true or false".to_owned())),
            (ParamKind::Choices(allowed), yaml_serde::Value::Sequence(items)) => {
                let mut list = Vec::new();
                for item in items {
                    match item {
                        yaml_serde::Value::String(s) if allowed.contains(&s.as_str()) => {
                            list.push(s);
                        }
                        _ => return Err(bad(format!("a list of {}", allowed.join(", ")))),
                    }
                }
                if list.is_empty() {
                    return Err(bad(format!("a non-empty list of {}", allowed.join(", "))));
                }
                ParamValue::List(list)
            }
            (ParamKind::Choices(allowed), _) => {
                return Err(bad(format!("a list of {}", allowed.join(", "))));
            }
        };
        params = params.with(&name, parsed);
    }
    // Explicit defaults are dropped, so they group with omitted parameters.
    Ok(params.normalized(check))
}

impl Profile {
    /// Parses and validates a profile. Never panics.
    pub fn from_yaml(text: &str) -> Result<Profile, ProfileError> {
        if text.trim().is_empty() {
            return Err(ProfileError::Empty);
        }
        let raw: Option<RawProfile> =
            yaml_serde::from_str(text).map_err(|e| ProfileError::Yaml(e.to_string()))?;
        let raw = raw.ok_or(ProfileError::Empty)?;
        if raw.format != FORMAT {
            return Err(ProfileError::Format(raw.format));
        }
        if !valid_id(&raw.id) {
            return Err(ProfileError::BadId(raw.id));
        }
        non_empty("title", &raw.title)?;
        let mut sources: Vec<Source> = Vec::new();
        for s in raw.sources {
            non_empty("sources[].key", &s.key)?;
            non_empty("sources[].document", &s.document)?;
            if sources.iter().any(|x| x.key == s.key) {
                return Err(ProfileError::DuplicateSource(s.key));
            }
            sources.push(Source {
                key: s.key,
                document: s.document,
                url: s.url.filter(|u| !u.trim().is_empty()),
            });
        }
        if raw.checks.is_empty() {
            return Err(ProfileError::NoChecks);
        }
        let mut seen = BTreeSet::new();
        let mut checks = Vec::new();
        for c in raw.checks {
            let Some(def) = checks::check(&c.id) else {
                return Err(ProfileError::UnknownCheck(c.id));
            };
            if !seen.insert(c.id.clone()) {
                return Err(ProfileError::DuplicateCheck(c.id));
            }
            non_empty(&format!("checks[{}].cite.clause", c.id), &c.cite.clause)?;
            let Some(source) = sources.iter().find(|s| s.key == c.cite.source) else {
                return Err(ProfileError::UnknownSource {
                    check: c.id,
                    source_key: c.cite.source,
                });
            };
            checks.push(ProfileCheck {
                params: parse_params(def, c.params)?,
                id: c.id,
                severity: c.severity,
                cite: Cite {
                    document: source.document.clone(),
                    url: source.url.clone(),
                    clause: c.cite.clause,
                },
            });
        }
        Ok(Profile {
            id: raw.id,
            title: raw.title,
            sources,
            checks,
        })
    }

    /// Reads and parses a profile file.
    pub fn from_path(path: &Path) -> Result<Profile, ProfileError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::InvalidData {
                ProfileError::Yaml(format!("{}: not UTF-8", path.display()))
            } else {
                ProfileError::Io {
                    path: path.display().to_string(),
                    message: e.to_string(),
                }
            }
        })?;
        Profile::from_yaml(&text)
    }

    /// The built-in profile with this id (`cisa-2026`, `cra`).
    pub fn builtin(id: &str) -> Option<Profile> {
        BUILTIN
            .iter()
            .find(|(name, _)| *name == id)
            .and_then(|(_, text)| Profile::from_yaml(text).ok())
    }
}

/// The ids of the built-in profiles, in a fixed order.
pub fn builtin_ids() -> Vec<&'static str> {
    BUILTIN.iter().map(|(id, _)| *id).collect()
}

/// Every built-in profile, in [`builtin_ids`] order. (Each is checked to parse by the tests,
/// so none is ever left out in practice.)
pub fn builtin_profiles() -> Vec<Profile> {
    BUILTIN
        .iter()
        .filter_map(|(_, text)| Profile::from_yaml(text).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "format: rollcall-profile/1
id: test
title: Test
sources:
  - key: s
    document: A document
checks:
  - id: component.hash
    severity: error
    cite: { source: s, clause: \"§1\" }
    params: { algorithms: [SHA-512, SHA-256], include_root: false }
";

    #[test]
    fn minimal_profile_loads() {
        let p = Profile::from_yaml(MINIMAL).unwrap();
        assert_eq!(p.id, "test");
        assert_eq!(p.checks.len(), 1);
        let c = &p.checks[0];
        assert_eq!(c.cite.clause, "§1");
        assert_eq!(c.cite.document, "A document");
        // Lists are sorted, so equal parameter sets compare equal.
        assert_eq!(
            c.params,
            Params::new()
                .with(
                    "algorithms",
                    ParamValue::List(vec!["SHA-256".into(), "SHA-512".into()])
                )
                .with("include_root", ParamValue::Bool(false))
        );
    }

    #[test]
    fn builtin_profiles_all_load() {
        for (id, text) in BUILTIN {
            let p = Profile::from_yaml(text).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(p.id, *id);
            assert_eq!(Profile::builtin(id).as_ref(), Some(&p));
        }
        assert_eq!(builtin_profiles().len(), BUILTIN.len());
        assert_eq!(Profile::builtin("all"), None);
    }

    #[test]
    fn every_profile_check_has_nonempty_citation() {
        for p in builtin_profiles() {
            for c in &p.checks {
                assert!(!c.cite.document.trim().is_empty(), "{} {}", p.id, c.id);
                assert!(!c.cite.clause.trim().is_empty(), "{} {}", p.id, c.id);
                assert!(c.cite.url.is_some(), "{} {}: no URL", p.id, c.id);
            }
        }
    }

    #[test]
    fn every_profiles_yaml_on_disk_is_registered_and_parses() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(BUILTIN_DIR);
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        on_disk.sort();
        let registered: Vec<String> = BUILTIN.iter().map(|(id, _)| format!("{id}.yaml")).collect();
        let mut sorted = registered.clone();
        sorted.sort();
        assert_eq!(
            on_disk, sorted,
            "every profiles/*.yaml must be registered in BUILTIN"
        );
        for (id, text) in BUILTIN {
            let file = std::fs::read_to_string(dir.join(format!("{id}.yaml"))).unwrap();
            assert_eq!(&file, text);
            Profile::from_path(&dir.join(format!("{id}.yaml"))).unwrap();
        }
    }

    fn err(text: &str) -> ProfileError {
        Profile::from_yaml(text).unwrap_err()
    }

    #[test]
    fn malformed_profile_yaml_is_an_error() {
        assert_eq!(err(""), ProfileError::Empty);
        assert_eq!(err("  \n"), ProfileError::Empty);
        assert_eq!(err("~\n"), ProfileError::Empty);
        // Truncated anywhere: never a panic. A prefix that stops before the checks, or inside
        // a flow mapping, is an error. (A prefix that ends just before `params:` is a valid
        // profile with default parameters.)
        for cut in 1..MINIMAL.len() {
            if let Some(prefix) = MINIMAL.get(..cut) {
                let loaded = Profile::from_yaml(prefix);
                if cut < MINIMAL.find("  - id:").unwrap() {
                    assert!(loaded.is_err(), "prefix {cut} loaded");
                }
            }
        }
        assert!(Profile::from_yaml(MINIMAL.get(..MINIMAL.len() - 3).unwrap()).is_err());
        for (text, what) in [
            ("- a\n- b\n", "list, not a map"),
            ("format: [1]\n", "wrong type"),
            ("{unclosed\n", "bad YAML"),
            ("\u{feff}\u{0}\u{1}", "control bytes"),
        ] {
            assert!(
                matches!(err(text), ProfileError::Yaml(_)),
                "{what}: {:?}",
                err(text)
            );
        }
        let with = |from: &str, to: &str| {
            assert!(MINIMAL.contains(from), "{from}");
            MINIMAL.replacen(from, to, 1)
        };
        assert_eq!(
            err(&with("rollcall-profile/1", "rollcall-profile/2")),
            ProfileError::Format("rollcall-profile/2".into())
        );
        assert_eq!(
            err(&with("id: test", "id: all")),
            ProfileError::BadId("all".into())
        );
        assert_eq!(
            err(&with("id: test", "id: Te st")),
            ProfileError::BadId("Te st".into())
        );
        assert_eq!(
            err(&with("title: Test", "title: ''")),
            ProfileError::EmptyField("title".into())
        );
        assert_eq!(
            err(&with("component.hash", "component.colour")),
            ProfileError::UnknownCheck("component.colour".into())
        );
        assert!(matches!(
            err(&with("source: s,", "source: t,")),
            ProfileError::UnknownSource { .. }
        ));
        assert!(matches!(
            err(&with("clause: \"§1\"", "clause: \"\"")),
            ProfileError::EmptyField(_)
        ));
        assert!(matches!(
            err(&with("severity: error", "severity: fatal")),
            ProfileError::Yaml(_)
        ));
        assert!(matches!(
            err(&with("include_root: false", "include_roots: false")),
            ProfileError::UnknownParam { .. }
        ));
        assert!(matches!(
            err(&with("include_root: false", "include_root: 1")),
            ProfileError::BadParam { .. }
        ));
        assert!(matches!(
            err(&with("[SHA-512, SHA-256]", "[SHA-999]")),
            ProfileError::BadParam { .. }
        ));
        assert!(matches!(
            err(&with("[SHA-512, SHA-256]", "[]")),
            ProfileError::BadParam { .. }
        ));
        assert!(matches!(
            err(&with("[SHA-512, SHA-256]", "SHA-512")),
            ProfileError::BadParam { .. }
        ));
        assert!(matches!(
            err(&with("title: Test", "title: Test\nextra: 1")),
            ProfileError::Yaml(_)
        ));
        let twice = format!(
            "{MINIMAL}  - id: component.hash\n    severity: warning\n    cite: {{ source: s, clause: x }}\n"
        );
        assert_eq!(
            err(&twice),
            ProfileError::DuplicateCheck("component.hash".into())
        );
        let no_checks = MINIMAL.split("checks:").next().unwrap().to_owned() + "checks: []\n";
        assert_eq!(err(&no_checks), ProfileError::NoChecks);
        let dup_source = with(
            "    document: A document\n",
            "    document: A document\n  - key: s\n    document: B\n",
        );
        assert_eq!(err(&dup_source), ProfileError::DuplicateSource("s".into()));
    }

    #[test]
    fn unreadable_profile_path_is_io_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Profile::from_path(&dir.path().join("absent.yaml")),
            Err(ProfileError::Io { .. })
        ));
        let bad = dir.path().join("latin1.yaml");
        std::fs::write(&bad, b"format: \xff\n").unwrap();
        assert!(matches!(
            Profile::from_path(&bad),
            Err(ProfileError::Yaml(_))
        ));
    }
}
