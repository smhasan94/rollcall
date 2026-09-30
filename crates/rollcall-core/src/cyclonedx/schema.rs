//! Validation against the vendored CycloneDX 1.6 JSON schema.
//!
//! The schemas in `schema/cyclonedx/` are verbatim copies of the official files from
//! CycloneDX/specification tag 1.6.2 (see `schema/cyclonedx/SOURCE.md`), fetched and checked
//! by `scripts/vendor-cyclonedx-schema.sh`. They are compiled into the binary, and validation
//! never touches the network or the filesystem.

use std::fmt;
use std::sync::OnceLock;

use jsonschema::{Draft, Registry, Validator};
use serde_json::Value;

/// The CycloneDX 1.6 BOM schema, verbatim.
pub const BOM_1_6_SCHEMA: &str = include_str!("../../schema/cyclonedx/bom-1.6.schema.json");
/// The SPDX licence-ID schema referenced by the BOM schema, verbatim.
pub const SPDX_SCHEMA: &str = include_str!("../../schema/cyclonedx/spdx.schema.json");
/// The JSON Signature Format schema referenced by the BOM schema, verbatim.
pub const JSF_0_82_SCHEMA: &str = include_str!("../../schema/cyclonedx/jsf-0.82.schema.json");

/// SHA-256 of [`BOM_1_6_SCHEMA`], as recorded in `SOURCE.md`.
pub const BOM_1_6_SCHEMA_SHA256: &str =
    "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d";
/// SHA-256 of [`SPDX_SCHEMA`], as recorded in `SOURCE.md`.
pub const SPDX_SCHEMA_SHA256: &str =
    "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6";
/// SHA-256 of [`JSF_0_82_SCHEMA`], as recorded in `SOURCE.md`.
pub const JSF_0_82_SCHEMA_SHA256: &str =
    "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae";

/// The URI the BOM schema's relative `$ref`s resolve against.
const SCHEMA_BASE: &str = "http://cyclonedx.org/schema/";

/// One way a document breaks the schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaViolation {
    /// Where in the document, as a JSON pointer (`""` for the document itself).
    pub path: String,
    /// What is wrong there.
    pub message: String,
}

impl fmt::Display for SchemaViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

fn violation(path: &str, message: impl Into<String>) -> SchemaViolation {
    SchemaViolation {
        path: path.to_owned(),
        message: message.into(),
    }
}

/// Builds the validator from the vendored schemas: Draft 7, format assertions on, the SPDX and
/// JSF schemas registered under their `http://cyclonedx.org/schema/` URIs, and retrieval
/// disabled so nothing is ever fetched.
fn build_validator() -> Result<Validator, String> {
    let parse = |name: &str, text: &str| -> Result<Value, String> {
        serde_json::from_str(text).map_err(|e| format!("vendored {name} is not JSON: {e}"))
    };
    let bom = parse("bom-1.6.schema.json", BOM_1_6_SCHEMA)?;
    let spdx = parse("spdx.schema.json", SPDX_SCHEMA)?;
    let jsf = parse("jsf-0.82.schema.json", JSF_0_82_SCHEMA)?;
    let registry = Registry::new()
        .draft(Draft::Draft7)
        .add(format!("{SCHEMA_BASE}spdx.schema.json"), spdx)
        .and_then(|b| b.add(format!("{SCHEMA_BASE}jsf-0.82.schema.json"), jsf))
        .and_then(|b| b.prepare())
        .map_err(|e| format!("cannot register vendored schemas: {e}"))?;
    jsonschema::options()
        .with_draft(Draft::Draft7)
        .should_validate_formats(true)
        .with_registry(&registry)
        .offline()
        .build(&bom)
        .map_err(|e| format!("cannot compile vendored CycloneDX 1.6 schema: {e}"))
}

fn validator() -> Result<&'static Validator, SchemaViolation> {
    static VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(build_validator)
        .as_ref()
        .map_err(|e| violation("", e.clone()))
}

/// Validates `document` against the vendored CycloneDX 1.6 JSON schema.
///
/// The document must be a JSON object whose `specVersion` is `"1.6"`; anything else is
/// reported as a single violation without running the schema (whose `specVersion` is a free
/// string). Otherwise every schema violation is returned, sorted by path and then message, so
/// the output is deterministic.
pub fn validate_cyclonedx_1_6(document: &Value) -> Result<(), Vec<SchemaViolation>> {
    let Some(object) = document.as_object() else {
        return Err(vec![violation("", "document is not a JSON object")]);
    };
    match object.get("specVersion") {
        Some(Value::String(v)) if v == "1.6" => {}
        Some(other) => {
            return Err(vec![violation(
                "/specVersion",
                format!("expected \"1.6\", found {other}"),
            )]);
        }
        None => {
            return Err(vec![violation("/specVersion", "missing; expected \"1.6\"")]);
        }
    }
    let validator = validator().map_err(|v| vec![v])?;
    let mut violations: Vec<SchemaViolation> = validator
        .iter_errors(document)
        .map(|e| violation(e.instance_path().as_str(), e.to_string()))
        .collect();
    if violations.is_empty() {
        return Ok(());
    }
    violations.sort();
    violations.dedup();
    Err(violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sha256_hex(text: &str) -> String {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn minimal_bom() -> Value {
        json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1})
    }

    #[test]
    fn vendored_schemas_match_recorded_sha256() {
        assert_eq!(sha256_hex(BOM_1_6_SCHEMA), BOM_1_6_SCHEMA_SHA256);
        assert_eq!(sha256_hex(SPDX_SCHEMA), SPDX_SCHEMA_SHA256);
        assert_eq!(sha256_hex(JSF_0_82_SCHEMA), JSF_0_82_SCHEMA_SHA256);
        let source = include_str!("../../schema/cyclonedx/SOURCE.md");
        for sha in [
            BOM_1_6_SCHEMA_SHA256,
            SPDX_SCHEMA_SHA256,
            JSF_0_82_SCHEMA_SHA256,
        ] {
            assert!(source.contains(sha), "SOURCE.md lacks {sha}");
        }
    }

    #[test]
    fn validator_builds_offline_from_vendored_schemas() {
        // Builds from the compiled-in text alone (retrieval is disabled), and the external
        // refs to the SPDX and JSF schemas resolve: an unknown licence id and a malformed
        // signature are rejected by those schemas.
        build_validator().unwrap();
        assert_eq!(validate_cyclonedx_1_6(&minimal_bom()), Ok(()));

        let mut bad_licence = minimal_bom();
        bad_licence["components"] = json!([{
            "type": "library",
            "name": "x",
            "licenses": [{"license": {"id": "Not-A-Real-SPDX-Id"}}]
        }]);
        let errors = validate_cyclonedx_1_6(&bad_licence).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|v| v.path.starts_with("/components/0/licenses")),
            "{errors:#?}"
        );

        let mut good_licence = minimal_bom();
        good_licence["components"] = json!([{
            "type": "library",
            "name": "x",
            "licenses": [{"license": {"id": "MIT"}}]
        }]);
        assert_eq!(validate_cyclonedx_1_6(&good_licence), Ok(()));

        let mut bad_signature = minimal_bom();
        bad_signature["signature"] = json!({"algorithm": 3});
        assert!(validate_cyclonedx_1_6(&bad_signature).is_err());
    }

    #[test]
    fn violations_are_sorted_by_path_then_message() {
        let document = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:NOPE",
            "version": 0,
            "metadata": {"timestamp": "yesterday"},
            "components": [
                {"type": "widget", "name": 3},
                {"name": "no-type"}
            ]
        });
        let errors = validate_cyclonedx_1_6(&document).unwrap_err();
        assert!(errors.len() >= 5, "{errors:#?}");
        let mut sorted = errors.clone();
        sorted.sort_by(|a, b| (&a.path, &a.message).cmp(&(&b.path, &b.message)));
        assert_eq!(errors, sorted);
        let paths: Vec<&str> = errors.iter().map(|v| v.path.as_str()).collect();
        for expected in [
            "/components/0/name",
            "/components/0/type",
            "/components/1",
            "/metadata/timestamp",
            "/serialNumber",
            "/version",
        ] {
            assert!(paths.contains(&expected), "missing {expected}: {paths:?}");
        }
        // Validating again gives the same list.
        assert_eq!(validate_cyclonedx_1_6(&document).unwrap_err(), errors);
        assert_eq!(
            errors[0].to_string(),
            format!("{}: {}", errors[0].path, errors[0].message)
        );
    }

    #[test]
    fn spec_version_other_than_1_6_is_rejected() {
        for bad in [
            json!("1.5"),
            json!("1.4"),
            json!("1.60"),
            json!(1.6),
            json!(null),
        ] {
            let mut document = minimal_bom();
            document["specVersion"] = bad.clone();
            let errors = validate_cyclonedx_1_6(&document).unwrap_err();
            assert_eq!(errors.len(), 1, "{bad}: {errors:#?}");
            assert_eq!(errors[0].path, "/specVersion");
        }
        let mut document = minimal_bom();
        document.as_object_mut().unwrap().remove("specVersion");
        let errors = validate_cyclonedx_1_6(&document).unwrap_err();
        assert_eq!(errors[0].path, "/specVersion");
    }

    #[test]
    fn non_object_document_is_rejected() {
        for bad in [json!(null), json!([]), json!("bom"), json!(1), json!(true)] {
            let errors = validate_cyclonedx_1_6(&bad).unwrap_err();
            assert_eq!(
                errors,
                vec![violation("", "document is not a JSON object")],
                "{bad}"
            );
        }
    }
}
