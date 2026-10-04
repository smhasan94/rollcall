//! Parser for `dependencies.lock`, which the IDF Component Manager writes next to a project's
//! `CMakeLists.txt` (lock format `1.0.0` and `2.0.0`).
//!
//! ```yaml
//! dependencies:
//!   espressif/mdns:                 # <namespace>/<name>, or <name> for local and git ones
//!     component_hash: 3ec0af5f…     # SHA-256 of the component's files (optional)
//!     dependencies:                 # what it requires (optional)
//!     - name: idf
//!       require: private
//!       version: '>=5.0'
//!     source:
//!       registry_url: https://components.espressif.com/   # `service_url` in lock 1.x
//!       type: service               # service | git | local | idf
//!     version: 1.8.2                # for git: the commit
//!   idf:
//!     source:
//!       type: idf
//!     version: 5.5.1
//! direct_dependencies: [espressif/mdns, idf]   # lock 2.x
//! manifest_hash: 9a95…
//! target: esp32
//! version: 2.0.0
//! ```
//!
//! A version written as a YAML number (`version: 1.0`) is kept as its text. A source of a
//! type rollcall does not know is kept as [`LockSource::Other`], not an error. Unknown keys
//! are ignored. Anything of the wrong shape is a [`LockError`] naming the key, never a
//! panic.

use std::collections::BTreeMap;

use yaml_serde::Value;

/// A parsed `dependencies.lock`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lock {
    /// The lock format (`version:`), e.g. `2.0.0`.
    pub format: Option<String>,
    /// The chip the lock was resolved for.
    pub target: Option<String>,
    /// The manifest hash, if any.
    pub manifest_hash: Option<String>,
    /// The project's direct dependencies (lock 2.x), in file order.
    pub direct_dependencies: Vec<String>,
    /// Every locked component, by name.
    pub dependencies: BTreeMap<String, LockEntry>,
}

/// One locked component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntry {
    /// The locked version (for a git source, the commit), if any.
    pub version: Option<String>,
    /// The component hash (SHA-256 hex of its files), if any.
    pub component_hash: Option<String>,
    /// Where it comes from.
    pub source: LockSource,
    /// The components it requires, by name, in file order.
    pub dependencies: Vec<String>,
}

/// Where a locked component comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockSource {
    /// The ESP Component Registry (`type: service`).
    Service {
        /// `registry_url` (lock 2.x) or `service_url` (lock 1.x), if given.
        registry_url: Option<String>,
    },
    /// A git repository (`type: git`).
    Git {
        /// The repository URL.
        url: String,
        /// The component's directory within the repository, if not the root.
        path: Option<String>,
    },
    /// A directory on disk (`type: local`).
    Local {
        /// The directory, as the build saw it.
        path: Option<String>,
    },
    /// ESP-IDF itself (`type: idf`).
    Idf,
    /// Any other source type, by name.
    Other(String),
}

impl LockSource {
    /// The `type:` it was read from.
    pub fn type_name(&self) -> &str {
        match self {
            Self::Service { .. } => "service",
            Self::Git { .. } => "git",
            Self::Local { .. } => "local",
            Self::Idf => "idf",
            Self::Other(name) => name,
        }
    }
}

impl Lock {
    /// The ESP-IDF version the lock was resolved against (the `idf` entry's version).
    pub fn idf_version(&self) -> Option<&str> {
        self.dependencies
            .values()
            .find(|e| e.source == LockSource::Idf)
            .and_then(|e| e.version.as_deref())
    }
}

/// `espressif/mdns` → (`Some("espressif")`, `"mdns"`); `mdns` → (`None`, `"mdns"`).
pub fn split_namespace(name: &str) -> (Option<&str>, &str) {
    match name.split_once('/') {
        Some((namespace, rest)) if !namespace.is_empty() && !rest.is_empty() => {
            (Some(namespace), rest)
        }
        _ => (None, name),
    }
}

/// Why a `dependencies.lock` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LockError {
    /// The file is empty (or only comments).
    #[error("empty lock file")]
    Empty,
    /// Not YAML. With the line and column when the YAML parser gives them.
    #[error("{}not valid YAML: {message}", at(*line, *column))]
    Yaml {
        /// The 1-based line.
        line: Option<usize>,
        /// The 1-based column.
        column: Option<usize>,
        /// What is wrong.
        message: String,
    },
    /// A key has a value of the wrong type.
    #[error("{key}: expected {expected}")]
    WrongType {
        /// The key, as a dotted path (`dependencies.espressif/mdns.source`).
        key: String,
        /// What was expected.
        expected: &'static str,
    },
    /// A required key is missing.
    #[error("{key}: missing")]
    Missing {
        /// The key, as a dotted path.
        key: String,
    },
}

fn at(line: Option<usize>, column: Option<usize>) -> String {
    match (line, column) {
        (Some(l), Some(c)) => format!("line {l}, column {c}: "),
        (Some(l), None) => format!("line {l}: "),
        _ => String::new(),
    }
}

/// A scalar as text: a string as is, a number or bool as written by YAML.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// An optional scalar at `key` of `map`; null or absent is `None`.
fn opt_scalar(map: &Value, key: &str, path: &str) -> Result<Option<String>, LockError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => scalar(v).map(Some).ok_or_else(|| LockError::WrongType {
            key: format!("{path}.{key}"),
            expected: "a string",
        }),
    }
}

/// A non-blank string at `key` of `map`, or `None`.
fn opt_text(map: &Value, key: &str, path: &str) -> Result<Option<String>, LockError> {
    Ok(opt_scalar(map, key, path)?.filter(|s| !s.trim().is_empty()))
}

fn source(value: Option<&Value>, path: &str) -> Result<LockSource, LockError> {
    let key = format!("{path}.source");
    let map = match value {
        None | Some(Value::Null) => return Err(LockError::Missing { key }),
        Some(v @ Value::Mapping(_)) => v,
        Some(_) => {
            return Err(LockError::WrongType {
                key,
                expected: "a mapping",
            });
        }
    };
    let ty = opt_text(map, "type", &key)?.ok_or_else(|| LockError::Missing {
        key: format!("{key}.type"),
    })?;
    Ok(match ty.as_str() {
        "service" => LockSource::Service {
            registry_url: match opt_text(map, "registry_url", &key)? {
                Some(url) => Some(url),
                None => opt_text(map, "service_url", &key)?,
            },
        },
        "git" => LockSource::Git {
            url: opt_text(map, "git", &key)?.ok_or_else(|| LockError::Missing {
                key: format!("{key}.git"),
            })?,
            path: opt_text(map, "path", &key)?,
        },
        "local" => LockSource::Local {
            path: opt_text(map, "path", &key)?,
        },
        "idf" => LockSource::Idf,
        _ => LockSource::Other(ty),
    })
}

/// The names in an entry's `dependencies:` list: each item a mapping with `name`, or a bare
/// name.
fn entry_dependencies(value: Option<&Value>, path: &str) -> Result<Vec<String>, LockError> {
    let key = format!("{path}.dependencies");
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Sequence(items)) => items,
        Some(_) => {
            return Err(LockError::WrongType {
                key,
                expected: "a list",
            });
        }
    };
    let mut names = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_key = format!("{key}[{index}]");
        let name = match item {
            Value::String(name) => Some(name.clone()),
            Value::Mapping(_) => opt_text(item, "name", &item_key)?,
            _ => {
                return Err(LockError::WrongType {
                    key: item_key,
                    expected: "a mapping with a name",
                });
            }
        };
        names.push(name.ok_or(LockError::Missing {
            key: format!("{item_key}.name"),
        })?);
    }
    Ok(names)
}

/// Parses a `dependencies.lock`.
pub fn parse(text: &str) -> Result<Lock, LockError> {
    let value: Value = yaml_serde::from_str(text).map_err(|e| {
        let location = e.location();
        LockError::Yaml {
            line: location.as_ref().map(|l| l.line()),
            column: location.as_ref().map(|l| l.column()),
            message: e.to_string(),
        }
    })?;
    let root = match value {
        Value::Null => return Err(LockError::Empty),
        v @ Value::Mapping(_) => v,
        _ => {
            return Err(LockError::WrongType {
                key: "(top level)".to_owned(),
                expected: "a mapping",
            });
        }
    };
    let mut lock = Lock {
        format: opt_text(&root, "version", "(top level)")?,
        target: opt_text(&root, "target", "(top level)")?,
        manifest_hash: opt_text(&root, "manifest_hash", "(top level)")?,
        ..Lock::default()
    };
    match root.get("direct_dependencies") {
        None | Some(Value::Null) => {}
        Some(Value::Sequence(items)) => {
            for (index, item) in items.iter().enumerate() {
                let name = scalar(item).ok_or_else(|| LockError::WrongType {
                    key: format!("direct_dependencies[{index}]"),
                    expected: "a component name",
                })?;
                lock.direct_dependencies.push(name);
            }
        }
        Some(_) => {
            return Err(LockError::WrongType {
                key: "direct_dependencies".to_owned(),
                expected: "a list",
            });
        }
    }
    let dependencies = match root.get("dependencies") {
        None | Some(Value::Null) => return Ok(lock),
        Some(Value::Mapping(map)) => map,
        Some(_) => {
            return Err(LockError::WrongType {
                key: "dependencies".to_owned(),
                expected: "a mapping of component name to entry",
            });
        }
    };
    for (name, entry) in dependencies {
        let name = scalar(name)
            .filter(|n| !n.trim().is_empty())
            .ok_or_else(|| LockError::WrongType {
                key: "dependencies".to_owned(),
                expected: "component names as keys",
            })?;
        let path = format!("dependencies.{name}");
        if !matches!(entry, Value::Mapping(_)) {
            return Err(LockError::WrongType {
                key: path,
                expected: "a mapping",
            });
        }
        let parsed = LockEntry {
            version: opt_text(entry, "version", &path)?,
            component_hash: opt_text(entry, "component_hash", &path)?,
            source: source(entry.get("source"), &path)?,
            dependencies: entry_dependencies(entry.get("dependencies"), &path)?,
        };
        lock.dependencies.insert(name, parsed);
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A lock with one component of each source type, as the component manager writes it
    /// (lock 2.0.0), including a git-sourced component.
    const LOCK: &str = "\
dependencies:
  espressif/mdns:
    component_hash:
      3ec0af5f6bce310512e90f482388d21cc7c0e99668172d2f895356165fc6f7c5
    dependencies:
    - name: idf
      require: private
      version: '>=5.0'
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 1.8.2
  esp_jpeg:
    component_hash: null
    dependencies:
    - name: idf
      require: private
      version: '>=4.4'
    source:
      git: https://github.com/espressif/idf-extra-components.git
      path: esp_jpeg
      type: git
    version: 9d2c4f8c4b5f8b6a1b3e1c1f2d0a2e7b8c9d0e1f
  idf:
    source:
      type: idf
    version: 5.5.1
  protocol_examples_common:
    dependencies: []
    source:
      path: /opt/esp/idf/examples/common_components/protocol_examples_common
      type: local
    version: '*'
direct_dependencies:
- esp_jpeg
- espressif/mdns
- idf
- protocol_examples_common
manifest_hash: 9a9520c926aa0a3e6ab6efa4fb14c3591e654d3887543776c1f730f359b02661
target: esp32
version: 2.0.0
";

    #[test]
    fn parses_service_git_local_and_idf_sources() {
        let lock = parse(LOCK).unwrap();
        assert_eq!(lock.format.as_deref(), Some("2.0.0"));
        assert_eq!(lock.target.as_deref(), Some("esp32"));
        assert_eq!(lock.idf_version(), Some("5.5.1"));
        assert_eq!(
            lock.direct_dependencies,
            [
                "esp_jpeg",
                "espressif/mdns",
                "idf",
                "protocol_examples_common"
            ]
        );
        let mdns = &lock.dependencies["espressif/mdns"];
        assert_eq!(mdns.version.as_deref(), Some("1.8.2"));
        assert_eq!(
            mdns.component_hash.as_deref(),
            Some("3ec0af5f6bce310512e90f482388d21cc7c0e99668172d2f895356165fc6f7c5")
        );
        assert_eq!(mdns.dependencies, ["idf"]);
        assert_eq!(
            mdns.source,
            LockSource::Service {
                registry_url: Some("https://components.espressif.com/".into())
            }
        );
        let local = &lock.dependencies["protocol_examples_common"];
        assert_eq!(local.version.as_deref(), Some("*"));
        assert_eq!(
            local.source,
            LockSource::Local {
                path: Some(
                    "/opt/esp/idf/examples/common_components/protocol_examples_common".into()
                )
            }
        );
        assert_eq!(lock.dependencies["idf"].source, LockSource::Idf);
        assert_eq!(
            split_namespace("espressif/mdns"),
            (Some("espressif"), "mdns")
        );
        assert_eq!(split_namespace("mdns"), (None, "mdns"));
        assert_eq!(split_namespace("/mdns"), (None, "/mdns"));
    }

    #[test]
    fn git_sourced_component_has_commit_version_url_and_path() {
        let lock = parse(LOCK).unwrap();
        let git = &lock.dependencies["esp_jpeg"];
        assert_eq!(
            git.source,
            LockSource::Git {
                url: "https://github.com/espressif/idf-extra-components.git".into(),
                path: Some("esp_jpeg".into()),
            }
        );
        assert_eq!(
            git.version.as_deref(),
            Some("9d2c4f8c4b5f8b6a1b3e1c1f2d0a2e7b8c9d0e1f")
        );
        assert_eq!(git.component_hash, None);
        assert_eq!(git.source.type_name(), "git");
    }

    /// A git source locked at a branch name rather than a commit is parsed as is, and the
    /// mapping keeps the component (purl without a revision) and warns.
    #[test]
    fn git_source_without_commit_is_kept_and_warned() {
        let lock = parse(
            "dependencies:\n  esp_jpeg:\n    source:\n      git: https://github.com/espressif/idf-extra-components.git\n      path: esp_jpeg\n      type: git\n    version: main\n",
        )
        .unwrap();
        assert_eq!(
            lock.dependencies["esp_jpeg"].version.as_deref(),
            Some("main")
        );
        let ingest = crate::esp_idf::tests::git_without_commit();
        let c = ingest
            .product
            .images
            .iter()
            .flat_map(|i| &i.components)
            .find(|c| c.name == "esp_jpeg")
            .unwrap();
        assert_eq!(
            c.purl.as_ref().unwrap().as_str(),
            "pkg:generic/esp_jpeg?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fidf-extra-components.git#esp_jpeg"
        );
        assert!(
            ingest
                .warnings
                .iter()
                .any(|w| w.location == "dependencies.lock"
                    && w.message.contains("esp_jpeg")
                    && w.message.contains("not a full commit")),
            "{:?}",
            ingest.warnings
        );
    }

    #[test]
    fn lock_format_1_and_numeric_versions_and_unknown_sources_are_accepted() {
        let lock = parse(
            "dependencies:\n  a/b:\n    source:\n      service_url: https://api.components.espressif.com/\n      type: service\n    version: 1.0\n  c:\n    source:\n      type: mirror\n    version: 2\nmanifest_hash: x\ntarget: esp32s3\nversion: 1.0.0\n",
        )
        .unwrap();
        assert_eq!(lock.format.as_deref(), Some("1.0.0"));
        assert!(lock.direct_dependencies.is_empty());
        let b = &lock.dependencies["a/b"];
        assert_eq!(b.version.as_deref(), Some("1.0"));
        assert_eq!(
            b.source,
            LockSource::Service {
                registry_url: Some("https://api.components.espressif.com/".into())
            }
        );
        assert_eq!(
            lock.dependencies["c"].source,
            LockSource::Other("mirror".into())
        );
        assert_eq!(lock.dependencies["c"].version.as_deref(), Some("2"));
        // CRLF line endings are YAML too.
        let crlf = LOCK.replace('\n', "\r\n");
        assert_eq!(parse(&crlf).unwrap(), parse(LOCK).unwrap());
    }

    #[test]
    fn malformed_lock_is_an_error_not_a_panic() {
        assert_eq!(parse(""), Err(LockError::Empty));
        assert_eq!(parse("# only a comment\n"), Err(LockError::Empty));
        let yaml = parse("dependencies: [\n").unwrap_err();
        assert!(
            matches!(yaml, LockError::Yaml { line: Some(_), .. }),
            "{yaml}"
        );
        for (text, key) in [
            ("- a\n- b\n", "(top level)"),
            ("dependencies: [a]\n", "dependencies"),
            ("dependencies:\n  a: 1\n", "dependencies.a"),
            (
                "dependencies:\n  a:\n    source: git\n",
                "dependencies.a.source",
            ),
            (
                "dependencies:\n  a:\n    version: [1]\n    source: {type: idf}\n",
                "dependencies.a.version",
            ),
            (
                "dependencies:\n  a:\n    source: {type: idf}\n    dependencies: x\n",
                "dependencies.a.dependencies",
            ),
            (
                "dependencies:\n  a:\n    source: {type: idf}\n    dependencies: [3]\n",
                "dependencies.a.dependencies[0]",
            ),
            ("direct_dependencies: x\n", "direct_dependencies"),
            ("direct_dependencies: [[a]]\n", "direct_dependencies[0]"),
            ("version: [2]\n", "(top level).version"),
        ] {
            let err = parse(text).unwrap_err();
            assert!(
                matches!(&err, LockError::WrongType { key: k, .. } if k == key),
                "{text:?}: {err:?}"
            );
        }
        for (text, key) in [
            (
                "dependencies:\n  a:\n    version: 1.0.0\n",
                "dependencies.a.source",
            ),
            (
                "dependencies:\n  a:\n    source: {path: x}\n",
                "dependencies.a.source.type",
            ),
            (
                "dependencies:\n  a:\n    source: {type: git}\n",
                "dependencies.a.source.git",
            ),
            (
                "dependencies:\n  a:\n    source: {type: idf}\n    dependencies: [{require: public}]\n",
                "dependencies.a.dependencies[0].name",
            ),
        ] {
            let err = parse(text).unwrap_err();
            assert!(
                matches!(&err, LockError::Missing { key: k } if k == key),
                "{text:?}: {err:?}"
            );
        }
        // Truncated at every line boundary: an error or a smaller lock, never a panic.
        let lines: Vec<&str> = LOCK.lines().collect();
        for n in 0..lines.len() {
            let _ = parse(&lines[..n].join("\n"));
        }
        // Truncated mid-way through a byte sequence it is not even UTF-8; the caller rejects
        // that before parsing (EspIdfError::NotUtf8).
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,300}") {
            let _ = parse(&text);
        }

        #[test]
        fn arbitrary_yaml_like_text_never_panics(
            lines in proptest::collection::vec("( {0,6})(dependencies|source|type|version|git|path|- name|[a-z/_]{1,8})(: ?)([a-z0-9.'\\[\\]{}*]{0,10})", 0..20)
        ) {
            let _ = parse(&lines.join("\n"));
        }
    }
}
