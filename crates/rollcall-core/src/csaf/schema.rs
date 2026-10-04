//! Validation against the vendored CSAF 2.0 JSON schema.
//!
//! The schemas in `schema/csaf/` are verbatim copies of the OASIS CSAF 2.0 schema and the
//! FIRST CVSS v2.0, v3.0 and v3.1 schemas it references (see `schema/csaf/SOURCE.md`),
//! fetched and checked by `scripts/vendor-csaf-schema.sh`. They are compiled into the binary,
//! and validation never touches the network or the filesystem.

use std::sync::OnceLock;

use jsonschema::{Draft, Registry, Validator};
use serde_json::Value;

use crate::cyclonedx::SchemaViolation;

/// The CSAF 2.0 JSON schema, verbatim.
pub const CSAF_2_0_SCHEMA: &str = include_str!("../../schema/csaf/csaf_json_schema.json");
/// FIRST's CVSS v2.0 JSON schema (draft-04), verbatim.
pub const CVSS_V2_0_SCHEMA: &str = include_str!("../../schema/csaf/cvss-v2.0.json");
/// FIRST's CVSS v3.0 JSON schema (draft-04), verbatim.
pub const CVSS_V3_0_SCHEMA: &str = include_str!("../../schema/csaf/cvss-v3.0.json");
/// FIRST's CVSS v3.1 JSON schema (draft-07), verbatim.
pub const CVSS_V3_1_SCHEMA: &str = include_str!("../../schema/csaf/cvss-v3.1.json");

/// SHA-256 of [`CSAF_2_0_SCHEMA`], as recorded in `SOURCE.md`.
pub const CSAF_2_0_SCHEMA_SHA256: &str =
    "29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262";
/// SHA-256 of [`CVSS_V2_0_SCHEMA`], as recorded in `SOURCE.md`.
pub const CVSS_V2_0_SCHEMA_SHA256: &str =
    "cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2";
/// SHA-256 of [`CVSS_V3_0_SCHEMA`], as recorded in `SOURCE.md`.
pub const CVSS_V3_0_SCHEMA_SHA256: &str =
    "b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919";
/// SHA-256 of [`CVSS_V3_1_SCHEMA`], as recorded in `SOURCE.md`.
pub const CVSS_V3_1_SCHEMA_SHA256: &str =
    "77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f";

fn violation(path: &str, message: impl Into<String>) -> SchemaViolation {
    SchemaViolation {
        path: path.to_owned(),
        message: message.into(),
    }
}

/// Builds the validator from the vendored schemas: Draft 2020-12 for the CSAF schema, format
/// assertions on, the CVSS schemas registered under the exact URIs the CSAF schema's `$ref`s
/// name (each read under the draft its own `$schema` declares), and retrieval disabled so
/// nothing is ever fetched.
fn build_validator() -> Result<Validator, String> {
    let parse = |name: &str, text: &str| -> Result<Value, String> {
        serde_json::from_str(text).map_err(|e| format!("vendored {name} is not JSON: {e}"))
    };
    let csaf = parse("csaf_json_schema.json", CSAF_2_0_SCHEMA)?;
    let v2 = parse("cvss-v2.0.json", CVSS_V2_0_SCHEMA)?;
    let v30 = parse("cvss-v3.0.json", CVSS_V3_0_SCHEMA)?;
    let v31 = parse("cvss-v3.1.json", CVSS_V3_1_SCHEMA)?;
    let registry = Registry::new()
        .add("https://www.first.org/cvss/cvss-v2.0.json", v2)
        .and_then(|b| b.add("https://www.first.org/cvss/cvss-v3.0.json", v30))
        .and_then(|b| b.add("https://www.first.org/cvss/cvss-v3.1.json", v31))
        .and_then(|b| b.prepare())
        .map_err(|e| format!("cannot register vendored CVSS schemas: {e}"))?;
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .with_registry(&registry)
        .offline()
        .build(&csaf)
        .map_err(|e| format!("cannot compile vendored CSAF 2.0 schema: {e}"))
}

fn validator() -> Result<&'static Validator, SchemaViolation> {
    static VALIDATOR: OnceLock<Result<Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(build_validator)
        .as_ref()
        .map_err(|e| violation("", e.clone()))
}

/// Whether `document` claims to be CSAF: a JSON object whose `document.csaf_version` is a
/// string. `rollcall validate --schema` uses it to tell CSAF from CycloneDX.
pub fn is_csaf(document: &Value) -> bool {
    document
        .get("document")
        .and_then(|d| d.get("csaf_version"))
        .is_some_and(Value::is_string)
}

/// Validates `document` against the vendored CSAF 2.0 JSON schema.
///
/// The document must be a JSON object whose `document.csaf_version` is `"2.0"`; anything else
/// is reported as a single violation without running the schema. Otherwise every schema
/// violation is returned, sorted by path and then message, so the output is deterministic.
pub fn validate_csaf_2_0(document: &Value) -> Result<(), Vec<SchemaViolation>> {
    let Some(object) = document.as_object() else {
        return Err(vec![violation("", "document is not a JSON object")]);
    };
    match object.get("document").and_then(|d| d.get("csaf_version")) {
        Some(Value::String(v)) if v == "2.0" => {}
        Some(other) => {
            return Err(vec![violation(
                "/document/csaf_version",
                format!("expected \"2.0\", found {other}"),
            )]);
        }
        None => {
            return Err(vec![violation(
                "/document/csaf_version",
                "missing; expected \"2.0\"",
            )]);
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

    fn minimal() -> Value {
        json!({
            "document": {
                "category": "csaf_base",
                "csaf_version": "2.0",
                "publisher": {
                    "category": "vendor",
                    "name": "Example Devices Ltd",
                    "namespace": "https://devices.example"
                },
                "title": "t",
                "tracking": {
                    "current_release_date": "2026-01-02T03:04:05Z",
                    "id": "x",
                    "initial_release_date": "2026-01-02T03:04:05Z",
                    "revision_history": [
                        {"date": "2026-01-02T03:04:05Z", "number": "1", "summary": "s"}
                    ],
                    "status": "final",
                    "version": "1"
                }
            }
        })
    }

    #[test]
    fn vendored_csaf_schemas_match_recorded_sha256() {
        assert_eq!(sha256_hex(CSAF_2_0_SCHEMA), CSAF_2_0_SCHEMA_SHA256);
        assert_eq!(sha256_hex(CVSS_V2_0_SCHEMA), CVSS_V2_0_SCHEMA_SHA256);
        assert_eq!(sha256_hex(CVSS_V3_0_SCHEMA), CVSS_V3_0_SCHEMA_SHA256);
        assert_eq!(sha256_hex(CVSS_V3_1_SCHEMA), CVSS_V3_1_SCHEMA_SHA256);
        let source = include_str!("../../schema/csaf/SOURCE.md");
        for sha in [
            CSAF_2_0_SCHEMA_SHA256,
            CVSS_V2_0_SCHEMA_SHA256,
            CVSS_V3_0_SCHEMA_SHA256,
            CVSS_V3_1_SCHEMA_SHA256,
        ] {
            assert!(source.contains(sha), "SOURCE.md lacks {sha}");
        }
    }

    /// The validator builds from the compiled-in text alone (retrieval is disabled), and the
    /// absolute `$ref`s to the CVSS schemas resolve, each under its own draft: a valid CVSS
    /// v3.1 and v2.0 score passes, and malformed ones are rejected by those schemas.
    #[test]
    fn csaf_validator_builds_offline_and_resolves_cvss_refs() {
        build_validator().unwrap();
        assert_eq!(validate_csaf_2_0(&minimal()), Ok(()));

        let with_score = |score: Value| {
            let mut doc = minimal();
            doc["product_tree"] =
                json!({"full_product_names": [{"name": "p", "product_id": "P1"}]});
            doc["vulnerabilities"] = json!([{"scores": [score]}]);
            doc
        };
        let v31 = json!({
            "products": ["P1"],
            "cvss_v3": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
            }
        });
        assert_eq!(validate_csaf_2_0(&with_score(v31.clone())), Ok(()));
        let v2 = json!({
            "products": ["P1"],
            "cvss_v2": {
                "version": "2.0",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "baseScore": 7.5
            }
        });
        assert_eq!(validate_csaf_2_0(&with_score(v2.clone())), Ok(()));

        let mut bad31 = v31;
        bad31["cvss_v3"]["baseSeverity"] = json!("SEVERE");
        let errors = validate_csaf_2_0(&with_score(bad31)).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|v| v.path.starts_with("/vulnerabilities/0/scores/0/cvss_v3")),
            "{errors:#?}"
        );
        let mut bad2 = v2;
        bad2["cvss_v2"]["vectorString"] = json!("nonsense");
        let errors = validate_csaf_2_0(&with_score(bad2)).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|v| v.path.starts_with("/vulnerabilities/0/scores/0/cvss_v2")),
            "{errors:#?}"
        );
    }

    #[test]
    fn csaf_schema_rejects_broken_documents_sorted() {
        let mut doc = minimal();
        doc["document"]["category"] = json!("");
        doc["document"]["publisher"]["category"] = json!("vendr");
        doc["document"]["tracking"]["status"] = json!("done");
        doc["document"]["tracking"]["current_release_date"] = json!("yesterday");
        doc["product_tree"] = json!({
            "branches": [{"category": "vendor", "name": "x"}],
            "full_product_names": [{"name": "p", "product_id": "P1",
                "product_identification_helper": {"purl": "not a purl", "cpe": "cpe:nope"}}]
        });
        doc["vulnerabilities"] = json!([{"cve": "CVE-1", "flags": [{"label": "nope"}]}]);
        let errors = validate_csaf_2_0(&doc).unwrap_err();
        let paths: Vec<&str> = errors.iter().map(|v| v.path.as_str()).collect();
        for expected in [
            "/document/category",
            "/document/publisher/category",
            "/document/tracking/current_release_date",
            "/document/tracking/status",
            "/product_tree/branches/0",
            "/product_tree/full_product_names/0/product_identification_helper/cpe",
            "/product_tree/full_product_names/0/product_identification_helper/purl",
            "/vulnerabilities/0/cve",
            "/vulnerabilities/0/flags/0/label",
        ] {
            assert!(paths.contains(&expected), "missing {expected}: {paths:?}");
        }
        let mut sorted = errors.clone();
        sorted.sort();
        assert_eq!(errors, sorted);
        assert_eq!(validate_csaf_2_0(&doc).unwrap_err(), errors);
    }

    #[test]
    fn non_csaf_or_other_version_is_one_violation() {
        for bad in [json!(null), json!([]), json!("csaf"), json!(1)] {
            assert_eq!(
                validate_csaf_2_0(&bad).unwrap_err(),
                vec![violation("", "document is not a JSON object")]
            );
        }
        for version in [json!("2.1"), json!(2.0), json!(null)] {
            let mut doc = minimal();
            doc["document"]["csaf_version"] = version.clone();
            let errors = validate_csaf_2_0(&doc).unwrap_err();
            assert_eq!(errors.len(), 1, "{version}: {errors:?}");
            assert_eq!(errors[0].path, "/document/csaf_version");
        }
        let errors = validate_csaf_2_0(&json!({"bomFormat": "CycloneDX"})).unwrap_err();
        assert_eq!(errors[0].path, "/document/csaf_version");
        assert!(is_csaf(&minimal()));
        assert!(!is_csaf(
            &json!({"bomFormat": "CycloneDX", "specVersion": "1.6"})
        ));
        assert!(!is_csaf(&json!({"document": {"csaf_version": 2}})));
    }
}
