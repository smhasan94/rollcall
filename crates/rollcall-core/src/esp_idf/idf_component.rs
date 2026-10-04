//! Parser for a component manifest, `idf_component.yml`: the project's own
//! (`main/idf_component.yml`) and each downloaded component's
//! (`managed_components/<namespace>__<name>/idf_component.yml`).
//!
//! Read: `version`, `license`, `description`, `url`, `repository` and the names of
//! `dependencies` (each a bare version constraint or a mapping with `version`, `path`, `git`,
//! …, which are not read). Every other key is ignored. An empty file is an empty manifest.
//! Anything of the wrong shape is a [`ManifestError`], never a panic.

use yaml_serde::Value;

/// The fields rollcall reads from an `idf_component.yml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// `version`, if given.
    pub version: Option<String>,
    /// `license` (an SPDX expression, by the registry's rules), if given.
    pub license: Option<String>,
    /// `description`, if given.
    pub description: Option<String>,
    /// `url` (the project's home page), if given.
    pub url: Option<String>,
    /// `repository` (its source repository), if given.
    pub repository: Option<String>,
    /// The names under `dependencies`, sorted.
    pub dependencies: Vec<String>,
}

/// Why an `idf_component.yml` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// Not YAML, with the line and column when the YAML parser gives them.
    #[error("{}not valid YAML: {message}", match line { Some(l) => format!("line {l}: "), None => String::new() })]
    Yaml {
        /// The 1-based line.
        line: Option<usize>,
        /// What is wrong.
        message: String,
    },
    /// A key has a value of the wrong type.
    #[error("{key}: expected {expected}")]
    WrongType {
        /// The key.
        key: String,
        /// What was expected.
        expected: &'static str,
    },
}

fn text(root: &Value, key: &str) -> Result<Option<String>, ManifestError> {
    match root.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone()).filter(|s| !s.trim().is_empty())),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(_) => Err(ManifestError::WrongType {
            key: key.to_owned(),
            expected: "a string",
        }),
    }
}

/// Parses an `idf_component.yml`.
pub fn parse(source: &str) -> Result<Manifest, ManifestError> {
    let value: Value = yaml_serde::from_str(source).map_err(|e| ManifestError::Yaml {
        line: e.location().map(|l| l.line()),
        message: e.to_string(),
    })?;
    let root = match value {
        Value::Null => return Ok(Manifest::default()),
        v @ Value::Mapping(_) => v,
        _ => {
            return Err(ManifestError::WrongType {
                key: "(top level)".to_owned(),
                expected: "a mapping",
            });
        }
    };
    let mut dependencies = Vec::new();
    match root.get("dependencies") {
        None | Some(Value::Null) => {}
        Some(Value::Mapping(map)) => {
            for name in map.keys() {
                match name {
                    Value::String(name) if !name.trim().is_empty() => {
                        dependencies.push(name.clone());
                    }
                    _ => {
                        return Err(ManifestError::WrongType {
                            key: "dependencies".to_owned(),
                            expected: "component names as keys",
                        });
                    }
                }
            }
        }
        Some(_) => {
            return Err(ManifestError::WrongType {
                key: "dependencies".to_owned(),
                expected: "a mapping",
            });
        }
    }
    dependencies.sort();
    Ok(Manifest {
        version: text(&root, "version")?,
        license: text(&root, "license")?,
        description: text(&root, "description")?,
        url: text(&root, "url")?,
        repository: text(&root, "repository")?,
        dependencies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reads_registry_component_manifest() {
        let m = parse(
            "dependencies:\n  idf: '>=5.0'\n  espressif/cjson:\n    version: ^1.7.15\n    rules:\n    - if: target in [esp32]\n\
             description: WebSocket protocol client\nlicense: Apache-2.0\nrepository: git://github.com/espressif/esp-protocols.git\n\
             url: https://github.com/espressif/esp-protocols/tree/master/components/esp_websocket_client\nversion: 1.8.0\nfiles:\n  exclude: [x]\n",
        )
        .unwrap();
        assert_eq!(m.version.as_deref(), Some("1.8.0"));
        assert_eq!(m.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            m.repository.as_deref(),
            Some("git://github.com/espressif/esp-protocols.git")
        );
        assert!(m.url.is_some() && m.description.is_some());
        assert_eq!(m.dependencies, ["espressif/cjson", "idf"]);
    }

    #[test]
    fn empty_manifest_is_empty_and_numbers_are_text() {
        assert_eq!(parse("").unwrap(), Manifest::default());
        assert_eq!(parse("# nothing\n").unwrap(), Manifest::default());
        assert_eq!(parse("version: 2\n").unwrap().version.as_deref(), Some("2"));
    }

    #[test]
    fn malformed_manifest_is_an_error_not_a_panic() {
        assert!(matches!(
            parse("dependencies: {\n"),
            Err(ManifestError::Yaml { line: Some(_), .. })
        ));
        for (source, key) in [
            ("- a\n", "(top level)"),
            ("dependencies: [a]\n", "dependencies"),
            ("dependencies:\n  1: x\n", "dependencies"),
            ("license: [MIT]\n", "license"),
            ("version: {a: 1}\n", "version"),
        ] {
            let err = parse(source).unwrap_err();
            assert!(
                matches!(&err, ManifestError::WrongType { key: k, .. } if k == key),
                "{source:?}: {err:?}"
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(source in "\\PC{0,200}") {
            let _ = parse(&source);
        }
    }
}
