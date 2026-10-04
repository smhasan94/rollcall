//! `library.json`: a PlatformIO library's manifest, as installed under
//! `.pio/libdeps/<env>/<library>/`.
//!
//! Read: `name`, `version` (a string, or a number as some manifests write it, kept exactly as
//! written: `1.10` stays `1.10`), `repository` (an object with a `url`, or a URL string),
//! `license`, and `dependencies` (an array of objects with `owner`, `name` and `version`, an
//! array of strings in `lib_deps` syntax, or an object mapping names to versions). Other keys
//! are ignored. `name`, `version`, `repository` or `license` of the wrong type is an error
//! naming it; a `dependencies` entry rollcall cannot read is skipped and reported in
//! [`LibraryJson::warnings`] (third-party manifests vary, and one odd entry must not lose the
//! rest of the SBOM). A missing key is `None`.

use serde_json::Value;

use super::ini::{PackageSpec, parse_spec};

/// Why `library.json` could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LibraryJsonError {
    /// Not JSON.
    #[error("not JSON: {0}")]
    Json(String),
    /// Not a JSON object.
    #[error("expected a JSON object")]
    NotAnObject,
    /// A key with a value of the wrong type.
    #[error("{key}: expected {expected}")]
    WrongType {
        /// The key (`dependencies[2].name`).
        key: String,
        /// What it should be.
        expected: &'static str,
    },
}

/// One entry of `dependencies`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dependency {
    /// The owner, if given.
    pub owner: Option<String>,
    /// The name.
    pub name: String,
    /// The version requirement, if given.
    pub version: Option<String>,
}

/// The parts of `library.json` rollcall reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibraryJson {
    /// `name`.
    pub name: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `repository.url` (or `repository` as a string).
    pub repository: Option<String>,
    /// `license`.
    pub license: Option<String>,
    /// `dependencies`.
    pub dependencies: Vec<Dependency>,
    /// `dependencies` entries skipped, each with why.
    pub warnings: Vec<String>,
}

fn wrong(key: impl Into<String>, expected: &'static str) -> LibraryJsonError {
    LibraryJsonError::WrongType {
        key: key.into(),
        expected,
    }
}

/// A string (or, with `numbers`, a number written as one) at `key`; `None` when absent or
/// null.
fn string(v: &Value, key: &str, numbers: bool) -> Result<Option<String>, LibraryJsonError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
        Some(Value::Number(n)) if numbers => Ok(Some(n.to_string())),
        Some(_) => Err(wrong(
            key,
            if numbers {
                "a string or a number"
            } else {
                "a string"
            },
        )),
    }
}

fn dependency_object(v: &Value, key: &str) -> Result<Dependency, LibraryJsonError> {
    if !v.is_object() {
        return Err(wrong(key, "an object or a string"));
    }
    let field = |name: &str, numbers| {
        string(v, name, numbers).map_err(|_| {
            wrong(
                format!("{key}.{name}"),
                if numbers {
                    "a string or a number"
                } else {
                    "a string"
                },
            )
        })
    };
    let name = field("name", false)?.ok_or_else(|| wrong(format!("{key}.name"), "a string"))?;
    Ok(Dependency {
        owner: field("owner", false)?,
        name,
        version: field("version", true)?,
    })
}

fn dependency_string(s: &str, key: &str) -> Result<Dependency, LibraryJsonError> {
    match parse_spec(s) {
        PackageSpec::Registry {
            owner,
            name,
            requirement,
        } => Ok(Dependency {
            owner,
            name,
            version: requirement,
        }),
        PackageSpec::Vcs {
            name: Some(name), ..
        }
        | PackageSpec::Archive {
            name: Some(name), ..
        }
        | PackageSpec::Local {
            name: Some(name), ..
        } => Ok(Dependency {
            owner: None,
            name,
            version: None,
        }),
        _ => Err(wrong(key, "a dependency name")),
    }
}

/// Parses `library.json`.
pub fn parse(text: &str) -> Result<LibraryJson, LibraryJsonError> {
    let v: Value = serde_json::from_str(text).map_err(|e| LibraryJsonError::Json(e.to_string()))?;
    if !v.is_object() {
        return Err(LibraryJsonError::NotAnObject);
    }
    let repository = match v.get("repository") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.trim().to_owned()),
        Some(r @ Value::Object(_)) => {
            string(r, "url", false).map_err(|_| wrong("repository.url", "a string"))?
        }
        Some(_) => return Err(wrong("repository", "an object or a string")),
    }
    .filter(|s| !s.is_empty());
    let mut dependencies = Vec::new();
    let mut warnings = Vec::new();
    match v.get("dependencies") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                let key = format!("dependencies[{i}]");
                let dep = match item {
                    Value::String(s) => dependency_string(s, &key),
                    other => dependency_object(other, &key),
                };
                match dep {
                    Ok(d) => dependencies.push(d),
                    Err(e) => warnings.push(format!("{e}; entry skipped")),
                }
            }
        }
        Some(Value::Object(map)) => {
            for (name, version) in map {
                let version = match version {
                    Value::String(s) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Null => None,
                    _ => {
                        warnings.push(format!(
                            "{}; entry skipped",
                            wrong(format!("dependencies.{name}"), "a version string")
                        ));
                        continue;
                    }
                };
                let (owner, name) = match name.split_once('/') {
                    Some((o, n)) => (Some(o.to_owned()), n.to_owned()),
                    None => (None, name.clone()),
                };
                dependencies.push(Dependency {
                    owner,
                    name,
                    version,
                });
            }
        }
        Some(_) => warnings.push(format!(
            "{}; ignored",
            wrong("dependencies", "an array or an object")
        )),
    }
    // A numeric version as written, not as a float prints it (1.10, not 1.1).
    let version = match v.get("version") {
        Some(Value::Number(n)) => {
            Some(top_level_number(text, "version").unwrap_or_else(|| n.to_string()))
        }
        _ => string(&v, "version", true)?,
    };
    Ok(LibraryJson {
        name: string(&v, "name", false)?,
        version,
        repository,
        license: string(&v, "license", false)?,
        dependencies,
        warnings,
    })
}

/// The literal text of the number at top-level `key` of the JSON object `text` (already
/// known to be valid JSON with a number there), scanning the text with string and nesting
/// awareness.
fn top_level_number(text: &str, key: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = 0usize;
    // The last string seen at depth 1 that may be a key.
    let mut last_key: Option<(usize, usize)> = None;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => {
                let start = i + 1;
                i += 1;
                while let Some(&c) = bytes.get(i) {
                    if c == b'\\' {
                        i += 2;
                        continue;
                    }
                    if c == b'"' {
                        break;
                    }
                    i += 1;
                }
                if depth == 1 {
                    last_key = Some((start, i));
                }
            }
            b'{' | b'[' => {
                depth += 1;
                last_key = None;
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            b':' if depth == 1 => {
                let is_key = last_key
                    .and_then(|(s, e)| text.get(s..e))
                    .is_some_and(|k| k == key);
                if is_key {
                    let rest = text.get(i + 1..)?.trim_start();
                    let end = rest
                        .find(|c: char| {
                            !(c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
                        })
                        .unwrap_or(rest.len());
                    let literal = rest.get(..end)?;
                    return (!literal.is_empty()).then(|| literal.to_owned());
                }
            }
            b',' => last_key = None,
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_name_version_repository_licence_dependencies() {
        let lib = parse(
            r#"{"name": "OneButton", "version": "2.6.1", "license": "BSD-3-Clause",
                "repository": {"type": "git", "url": "https://github.com/mathertel/OneButton"},
                "dependencies": [{"owner": "bblanchon", "name": "ArduinoJson", "version": "^7"},
                                 "knolleary/PubSubClient @ 2.8"],
                "frameworks": "arduino"}"#,
        )
        .unwrap();
        assert_eq!(lib.name.as_deref(), Some("OneButton"));
        assert_eq!(lib.version.as_deref(), Some("2.6.1"));
        assert_eq!(lib.license.as_deref(), Some("BSD-3-Clause"));
        assert_eq!(
            lib.repository.as_deref(),
            Some("https://github.com/mathertel/OneButton")
        );
        assert_eq!(
            lib.dependencies,
            [
                Dependency {
                    owner: Some("bblanchon".into()),
                    name: "ArduinoJson".into(),
                    version: Some("^7".into())
                },
                Dependency {
                    owner: Some("knolleary".into()),
                    name: "PubSubClient".into(),
                    version: Some("2.8".into())
                }
            ]
        );
        // The other spellings: a numeric version, a repository string, a dependency map.
        let lib = parse(
            r#"{"name": "X", "version": 2.8, "repository": "https://h/x.git",
                "dependencies": {"me/Y": "1.0", "Z": null}}"#,
        )
        .unwrap();
        assert_eq!(lib.version.as_deref(), Some("2.8"));
        assert_eq!(lib.repository.as_deref(), Some("https://h/x.git"));
        assert_eq!(lib.dependencies.len(), 2);
        let y = lib.dependencies.iter().find(|d| d.name == "Y").unwrap();
        assert_eq!(
            (y.owner.as_deref(), y.version.as_deref()),
            (Some("me"), Some("1.0"))
        );
        // Everything optional.
        assert_eq!(parse("{}").unwrap(), LibraryJson::default());
    }

    #[test]
    fn malformed_library_json_errors_never_panic() {
        for (text, needle) in [
            ("", "not JSON"),
            ("{\"name\": ", "not JSON"),
            ("[]", "expected a JSON object"),
            ("\"x\"", "expected a JSON object"),
            ("{\"name\": 3}", "name: expected a string"),
            (
                "{\"version\": []}",
                "version: expected a string or a number",
            ),
            (
                "{\"repository\": 1}",
                "repository: expected an object or a string",
            ),
            (
                "{\"repository\": {\"url\": 1}}",
                "repository.url: expected a string",
            ),
            ("{\"license\": false}", "license: expected a string"),
        ] {
            let message = parse(text).unwrap_err().to_string();
            assert!(
                message.contains(needle),
                "{text:?}: {message:?} lacks {needle:?}"
            );
        }
        // An odd `dependencies` entry is skipped with a warning; the rest is kept.
        for (text, needle) in [
            (
                "{\"dependencies\": 1}",
                "dependencies: expected an array or an object",
            ),
            (
                "{\"dependencies\": [1]}",
                "dependencies[0]: expected an object or a string",
            ),
            (
                "{\"dependencies\": [{}]}",
                "dependencies[0].name: expected a string",
            ),
            (
                "{\"dependencies\": [{\"name\": \"a\", \"owner\": 2}]}",
                "dependencies[0].owner",
            ),
            (
                "{\"dependencies\": [\"\"]}",
                "dependencies[0]: expected a dependency name",
            ),
            (
                "{\"dependencies\": {\"a\": []}}",
                "dependencies.a: expected a version string",
            ),
        ] {
            let lib = parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
            assert!(
                lib.warnings.iter().any(|w| w.contains(needle)),
                "{text:?}: {:?} lacks {needle:?}",
                lib.warnings
            );
        }
        let lib = parse(r#"{"name": "x", "dependencies": [1, {"name": "kept"}, "also/kept @ 1"]}"#)
            .unwrap();
        assert_eq!(lib.dependencies.len(), 2);
        assert_eq!(lib.warnings.len(), 1);
    }

    #[test]
    fn numeric_versions_are_kept_as_written() {
        for (text, version) in [
            (r#"{"version": 1.10}"#, "1.10"),
            (
                r#"{"name": "v", "version" : 2.0, "x": {"version": 9}}"#,
                "2.0",
            ),
            (r#"{"x": {"version": 9}, "version": 3}"#, "3"),
            (r#"{"note": "\"version\": 7", "version": 1.50}"#, "1.50"),
        ] {
            assert_eq!(
                parse(text).unwrap().version.as_deref(),
                Some(version),
                "{text}"
            );
        }
    }

    proptest! {
        #[test]
        fn library_json_parser_never_panics(text in "\\PC{0,80}") {
            let _ = parse(&text);
        }

        #[test]
        fn library_json_parser_never_panics_on_any_json_shape(
            name in prop_oneof![Just("\"n\"".to_owned()), Just("1".to_owned()), Just("null".to_owned()), Just("[]".to_owned())],
            deps in prop_oneof![Just("[]".to_owned()), Just("{}".to_owned()), Just("[{\"name\":1}]".to_owned()), Just("[\"a@1\"]".to_owned()), Just("3".to_owned())],
        ) {
            let _ = parse(&format!("{{\"name\": {name}, \"dependencies\": {deps}}}"));
        }
    }
}
