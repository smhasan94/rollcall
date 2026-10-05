//! A PlatformIO package's manifest in the core directory: a development platform's
//! `platform.json` or a tool package's `package.json` (the framework's, for rollcall).
//!
//! Read: `name` and `version` (required strings), `license` and `repository.url` (or
//! `repository` as a string), and, in `platform.json`, `frameworks` (each framework's
//! `package`). Other keys are ignored. A key of the wrong type is an error naming it.

use std::collections::BTreeMap;

use serde_json::Value;

/// Why a package manifest could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PackageJsonError {
    /// Not JSON.
    #[error("not JSON: {0}")]
    Json(String),
    /// Not a JSON object.
    #[error("expected a JSON object")]
    NotAnObject,
    /// A required field is missing or empty.
    #[error("{0}: missing")]
    Missing(&'static str),
    /// A key with a value of the wrong type.
    #[error("{key}: expected {expected}")]
    WrongType {
        /// The key.
        key: String,
        /// What it should be.
        expected: &'static str,
    },
}

/// A parsed `platform.json` or `package.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageJson {
    /// `name`.
    pub name: String,
    /// `version`.
    pub version: String,
    /// `license`.
    pub license: Option<String>,
    /// `repository.url`.
    pub repository: Option<String>,
    /// `frameworks.<name>.package` (a platform's frameworks), by framework name.
    pub frameworks: BTreeMap<String, String>,
}

fn wrong(key: impl Into<String>, expected: &'static str) -> PackageJsonError {
    PackageJsonError::WrongType {
        key: key.into(),
        expected,
    }
}

fn string(v: &Value, key: &str, label: &str) -> Result<Option<String>, PackageJsonError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
        Some(_) => Err(wrong(label, "a string")),
    }
}

/// Parses a `platform.json` or `package.json`.
pub fn parse(text: &str) -> Result<PackageJson, PackageJsonError> {
    let v: Value = serde_json::from_str(text).map_err(|e| PackageJsonError::Json(e.to_string()))?;
    if !v.is_object() {
        return Err(PackageJsonError::NotAnObject);
    }
    let repository = match v.get("repository") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.trim().to_owned()).filter(|s| !s.is_empty()),
        Some(r @ Value::Object(_)) => string(r, "url", "repository.url")?,
        Some(_) => return Err(wrong("repository", "an object or a string")),
    };
    let mut frameworks = BTreeMap::new();
    match v.get("frameworks") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (name, entry) in map {
                let key = format!("frameworks.{name}");
                if !entry.is_object() {
                    return Err(wrong(key, "an object"));
                }
                if let Some(package) = string(entry, "package", &format!("{key}.package"))? {
                    frameworks.insert(name.clone(), package);
                }
            }
        }
        Some(_) => return Err(wrong("frameworks", "an object")),
    }
    Ok(PackageJson {
        name: string(&v, "name", "name")?.ok_or(PackageJsonError::Missing("name"))?,
        version: string(&v, "version", "version")?.ok_or(PackageJsonError::Missing("version"))?,
        license: string(&v, "license", "license")?,
        repository,
        frameworks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_platform_and_package_manifests() {
        let p = parse(
            r#"{"name": "espressif32", "version": "6.10.0", "license": "Apache-2.0",
                "repository": {"type": "git", "url": "https://github.com/platformio/platform-espressif32.git"},
                "frameworks": {"arduino": {"package": "framework-arduinoespressif32", "script": "a.py"},
                               "espidf": {"package": "framework-espidf"}},
                "packages": {}}"#,
        )
        .unwrap();
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("espressif32", "6.10.0")
        );
        assert_eq!(p.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            p.frameworks.get("arduino").map(String::as_str),
            Some("framework-arduinoespressif32")
        );
        assert_eq!(p.frameworks.len(), 2);
        let f = parse(
            r#"{"name": "framework-arduinoespressif32", "version": "3.20017.241212+sha.dcc1105b",
                "license": "LGPL-2.1-or-later", "repository": "https://github.com/espressif/arduino-esp32"}"#,
        )
        .unwrap();
        assert_eq!(f.version, "3.20017.241212+sha.dcc1105b");
        assert_eq!(
            f.repository.as_deref(),
            Some("https://github.com/espressif/arduino-esp32")
        );
        assert!(f.frameworks.is_empty());
    }

    #[test]
    fn malformed_package_json_errors_never_panic() {
        for (text, needle) in [
            ("", "not JSON"),
            ("{\"name\":", "not JSON"),
            ("null", "expected a JSON object"),
            ("{\"version\": \"1\"}", "name: missing"),
            ("{\"name\": \"x\"}", "version: missing"),
            (
                "{\"name\": \"x\", \"version\": 1}",
                "version: expected a string",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"license\": []}",
                "license",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"repository\": 2}",
                "repository",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"frameworks\": []}",
                "frameworks: expected an object",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"frameworks\": {\"a\": 1}}",
                "frameworks.a",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"frameworks\": {\"a\": {\"package\": 1}}}",
                "frameworks.a.package",
            ),
        ] {
            let message = parse(text).unwrap_err().to_string();
            assert!(
                message.contains(needle),
                "{text:?}: {message:?} lacks {needle:?}"
            );
        }
    }

    proptest! {
        #[test]
        fn package_json_parser_never_panics(text in "\\PC{0,80}") {
            let _ = parse(&text);
        }
    }
}
