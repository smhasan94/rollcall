//! `.piopm`: the record PlatformIO's package manager writes beside every package it installs
//! (a library under `.pio/libdeps/<env>/`, a platform or a tool package in the core
//! directory):
//!
//! ```json
//! {"type": "library", "name": "ArduinoJson", "version": "7.2.1",
//!  "spec": {"owner": "bblanchon", "id": 64, "name": "ArduinoJson", "requirements": null, "uri": null}}
//! ```
//!
//! `name` and `version` are required strings; `type` and the `spec` fields are optional
//! (`null` or absent is `None`). A field of the wrong type is an error naming it.

use serde_json::Value;

/// Why a `.piopm` could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PiopmError {
    /// Not JSON.
    #[error("not JSON: {0}")]
    Json(String),
    /// Not a JSON object.
    #[error("expected a JSON object")]
    NotAnObject,
    /// A required field is missing or empty.
    #[error("{0}: missing")]
    Missing(&'static str),
    /// A field with a value of the wrong type.
    #[error("{0}: expected a string")]
    WrongType(String),
}

/// A parsed `.piopm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piopm {
    /// `type` (`library`, `platform`, `tool`).
    pub kind: Option<String>,
    /// `name`.
    pub name: String,
    /// `version`, as installed (semver: `2.8.0` for a library that says `2.8`).
    pub version: String,
    /// `spec.owner`: the registry account it came from.
    pub owner: Option<String>,
    /// `spec.requirements`: the requirement it was installed for.
    pub requirements: Option<String>,
    /// `spec.uri`: the URL it was installed from, for a source package.
    pub uri: Option<String>,
}

fn optional(v: &Value, key: &str, label: &str) -> Result<Option<String>, PiopmError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.trim().to_owned()).filter(|s| !s.is_empty())),
        Some(_) => Err(PiopmError::WrongType(label.to_owned())),
    }
}

/// Parses a `.piopm`.
pub fn parse(text: &str) -> Result<Piopm, PiopmError> {
    let v: Value = serde_json::from_str(text).map_err(|e| PiopmError::Json(e.to_string()))?;
    if !v.is_object() {
        return Err(PiopmError::NotAnObject);
    }
    let spec = match v.get("spec") {
        None | Some(Value::Null) => Value::Null,
        Some(s @ Value::Object(_)) => s.clone(),
        Some(_) => return Err(PiopmError::WrongType("spec".to_owned())),
    };
    Ok(Piopm {
        kind: optional(&v, "type", "type")?,
        name: optional(&v, "name", "name")?.ok_or(PiopmError::Missing("name"))?,
        version: optional(&v, "version", "version")?.ok_or(PiopmError::Missing("version"))?,
        owner: optional(&spec, "owner", "spec.owner")?,
        requirements: optional(&spec, "requirements", "spec.requirements")?,
        uri: optional(&spec, "uri", "spec.uri")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_registry_and_source_records() {
        let p = parse(
            r#"{"type": "library", "name": "PubSubClient", "version": "2.8.0", "spec": {"owner": "knolleary", "id": 89, "name": "PubSubClient", "requirements": null, "uri": null}}"#,
        )
        .unwrap();
        assert_eq!(p.kind.as_deref(), Some("library"));
        assert_eq!(
            (p.name.as_str(), p.version.as_str()),
            ("PubSubClient", "2.8.0")
        );
        assert_eq!(p.owner.as_deref(), Some("knolleary"));
        assert_eq!((p.requirements, p.uri), (None, None));
        let p = parse(
            r#"{"type": "library", "name": "mylib", "version": "0.0.0+sha.1234567", "spec": {"owner": null, "name": "mylib", "requirements": null, "uri": "git+https://github.com/me/mylib.git"}}"#,
        )
        .unwrap();
        assert_eq!(p.owner, None);
        assert_eq!(
            p.uri.as_deref(),
            Some("git+https://github.com/me/mylib.git")
        );
        // No spec at all.
        let p = parse(r#"{"name": "x", "version": "1"}"#).unwrap();
        assert_eq!((p.kind, p.owner), (None, None));
    }

    #[test]
    fn malformed_piopm_errors_never_panic() {
        for (text, needle) in [
            ("", "not JSON"),
            ("{", "not JSON"),
            ("[1]", "expected a JSON object"),
            ("{\"version\": \"1\"}", "name: missing"),
            ("{\"name\": \"x\"}", "version: missing"),
            ("{\"name\": \"\", \"version\": \"1\"}", "name: missing"),
            (
                "{\"name\": 1, \"version\": \"1\"}",
                "name: expected a string",
            ),
            (
                "{\"name\": \"x\", \"version\": 1}",
                "version: expected a string",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"spec\": []}",
                "spec: expected",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"spec\": {\"owner\": 5}}",
                "spec.owner",
            ),
            (
                "{\"name\": \"x\", \"version\": \"1\", \"spec\": {\"uri\": {}}}",
                "spec.uri",
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
        fn piopm_parser_never_panics(text in "\\PC{0,80}") {
            let _ = parse(&text);
        }
    }
}
