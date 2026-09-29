//! model → JSON → model round trips, and malformed-input handling of the JSON parser.

mod common;

use std::path::PathBuf;

use common::{base_plus, base_product, extra_component};
use rollcall_core::model::{ModelError, Product, ValidationError};
use serde_json::{Value, json};

/// A boxed edit of the base JSON.
type Edit = Box<dyn Fn(&mut Value)>;

fn base_value() -> Value {
    serde_json::from_str(&base_product().to_json().unwrap()).unwrap()
}

/// The base product's JSON after `edit`.
fn edited(edit: impl FnOnce(&mut Value)) -> String {
    let mut value = base_value();
    edit(&mut value);
    serde_json::to_string_pretty(&value).unwrap()
}

/// The application image (images sort bootloader, application, blob).
fn app(value: &mut Value) -> &mut Value {
    let app = value.pointer_mut("/images/1").unwrap();
    assert_eq!(app["kind"], "application");
    app
}

/// The application's `mbedtls` component, which has evidence, a purl and a licence.
fn mbedtls(value: &mut Value) -> &mut Value {
    let components = app(value)["components"].as_array_mut().unwrap();
    components
        .iter_mut()
        .find(|c| c["name"] == "mbedtls")
        .unwrap()
}

fn assert_json_error(text: &str) -> ModelError {
    match Product::from_json(text) {
        Ok(p) => panic!("expected an error, parsed {p:#?}"),
        Err(e) => e,
    }
}

fn assert_parse_error(text: &str) {
    let err = assert_json_error(text);
    assert!(
        matches!(err, ModelError::Json(_)),
        "expected a JSON error, got {err:?}"
    );
}

fn assert_validation_error(text: &str) -> ValidationError {
    match assert_json_error(text) {
        ModelError::Validation(v) => v,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn model_json_model_round_trip_is_equal() {
    for product in [base_product(), base_plus(extra_component())] {
        let json = product.to_json().unwrap();
        let back = Product::from_json(&json).unwrap();
        assert_eq!(back, product);
        assert_eq!(back.to_json().unwrap(), json);
        let from_bytes = Product::from_json_bytes(json.as_bytes()).unwrap();
        assert_eq!(from_bytes, product);
    }
}

#[test]
fn golden_files_reserialise_identically() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    for name in ["base.json", "base_plus_one.json"] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        let product = Product::from_json(&text).unwrap();
        assert_eq!(product.to_json().unwrap(), text, "{name}");
    }
}

#[test]
fn truncated_json_is_error_not_panic() {
    let text = base_product().to_json().unwrap();
    let body = text.trim_end();
    for len in 0..body.len() {
        let truncated = &body[..len];
        assert!(
            Product::from_json(truncated).is_err(),
            "prefix of {len} bytes parsed"
        );
    }
}

#[test]
fn empty_input_is_error() {
    for input in ["", " ", "\n", "{}", "null", "[]"] {
        assert!(Product::from_json(input).is_err(), "{input:?}");
    }
    assert!(Product::from_json_bytes(b"").is_err());
}

#[test]
fn invalid_utf8_is_error() {
    let mut bytes = base_product().to_json().unwrap().into_bytes();
    // Invalid UTF-8 inside a string value.
    let at = bytes.windows(6).position(|w| w == b"widget").unwrap();
    bytes.insert(at + 1, 0xff);
    assert!(matches!(
        Product::from_json_bytes(&bytes),
        Err(ModelError::Utf8(_))
    ));
    // UTF-16 encoded JSON.
    let utf16: Vec<u8> = "{\"schema\":\"rollcall-model/1\",\"name\":\"w\"}"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(Product::from_json_bytes(&utf16).is_err());
}

#[test]
fn wrong_type_for_confidence_is_error() {
    for bad in [
        json!("high"),
        json!(null),
        json!([9000]),
        json!({"bp": 9000}),
    ] {
        assert_parse_error(&edited(|v| {
            mbedtls(v)["evidence"][0]["confidence"] = bad.clone();
        }));
    }
}

#[test]
fn wrong_type_for_components_is_error() {
    for bad in [json!({}), json!("mbedtls"), json!(1), json!([1, 2])] {
        assert_parse_error(&edited(|v| {
            app(v)["components"] = bad.clone();
        }));
    }
}

#[test]
fn unknown_top_level_field_is_error() {
    assert_parse_error(&edited(|v| {
        v["serialNumber"] = json!("urn:uuid:0");
    }));
}

#[test]
fn unknown_nested_field_is_error() {
    let edits: Vec<Edit> = vec![
        Box::new(|v| app(v)["colour"] = json!("blue")),
        Box::new(|v| mbedtls(v)["colour"] = json!("blue")),
        Box::new(|v| mbedtls(v)["evidence"][0]["colour"] = json!("blue")),
        Box::new(|v| {
            mbedtls(v)["evidence"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e.get("occurrence").is_some())
                .unwrap()["occurrence"]["colour"] = json!("blue")
        }),
        Box::new(|v| v["supplier"]["colour"] = json!("blue")),
        Box::new(|v| v.pointer_mut("/images/0/hashes/0").unwrap()["colour"] = json!("blue")),
    ];
    for edit in edits {
        assert_parse_error(&edited(edit));
    }
}

#[test]
fn invalid_purl_is_error() {
    for bad in ["not-a-purl", "", "pkg:", "pkg:/name", "http://example.com"] {
        assert_parse_error(&edited(|v| mbedtls(v)["purl"] = json!(bad)));
    }
}

#[test]
fn invalid_cpe_is_error() {
    for bad in [
        "",
        "cpe:2.3:a:too:few",
        "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*:extra",
        "cpe:/",
        "cpe:2.3:a:v p:p:1:*:*:*:*:*:*:*",
        "zephyr",
    ] {
        assert_parse_error(&edited(|v| mbedtls(v)["cpe"] = json!(bad)));
    }
}

#[test]
fn uppercase_or_wrong_length_digest_is_error() {
    for bad in [
        "B0".repeat(32),
        "b0".repeat(31),
        "b0".repeat(33),
        "g0".repeat(32),
        String::new(),
    ] {
        assert_parse_error(&edited(|v| {
            v.pointer_mut("/images/0/hashes/0").unwrap()["digest"] = json!(bad);
        }));
    }
}

#[test]
fn unknown_hash_algorithm_is_error() {
    for bad in ["SHA-999", "sha256", "SHA256", ""] {
        assert_parse_error(&edited(|v| {
            v.pointer_mut("/images/0/hashes/0").unwrap()["algorithm"] = json!(bad);
        }));
    }
}

#[test]
fn unknown_image_kind_is_error() {
    for bad in [json!("kernel"), json!("Application"), json!(1)] {
        assert_parse_error(&edited(|v| app(v)["kind"] = bad.clone()));
    }
}

#[test]
fn confidence_out_of_range_is_error() {
    for bad in [json!(10001), json!(-1), json!(0.5)] {
        assert_parse_error(&edited(|v| {
            mbedtls(v)["evidence"][0]["confidence"] = bad.clone();
        }));
    }
}

#[test]
fn wrong_schema_tag_is_error() {
    for bad in [json!("rollcall-model/2"), json!(""), json!(1)] {
        assert_parse_error(&edited(|v| v["schema"] = bad.clone()));
    }
    assert_parse_error(&edited(|v| {
        v.as_object_mut().unwrap().remove("schema");
    }));
}

#[test]
fn duplicate_sibling_identity_is_error() {
    let text = edited(|v| {
        let mut copy = mbedtls(v).clone();
        copy["licence"] = json!("MIT");
        app(v)["components"].as_array_mut().unwrap().push(copy);
    });
    assert!(matches!(
        assert_validation_error(&text),
        ValidationError::DuplicateSibling { .. }
    ));

    let text = edited(|v| {
        let copy = v.pointer("/images/2").unwrap().clone();
        let mut copy = copy;
        copy["licence"] = json!("MIT");
        v["images"].as_array_mut().unwrap().push(copy);
    });
    assert!(matches!(
        assert_validation_error(&text),
        ValidationError::DuplicateSibling { .. }
    ));
}

#[test]
fn dangling_dependency_ref_is_error() {
    let ghost = format!("component:{}", "0".repeat(32));
    let text = edited(|v| {
        let deps = v["dependencies"].as_object_mut().unwrap();
        let (_, targets) = deps.iter_mut().next().unwrap();
        targets.as_array_mut().unwrap().push(json!(ghost));
    });
    assert!(matches!(
        assert_validation_error(&text),
        ValidationError::DanglingDependency { .. }
    ));
    let text = edited(|v| {
        v["dependencies"][ghost.as_str()] = json!([]);
    });
    assert!(matches!(
        assert_validation_error(&text),
        ValidationError::DanglingDependency { .. }
    ));
    // A malformed ref is rejected while parsing.
    assert_parse_error(&edited(|v| {
        v["dependencies"]["not-a-ref"] = json!([]);
    }));
}

#[test]
fn empty_name_is_error() {
    let edits: Vec<Edit> = vec![
        Box::new(|v| v["name"] = json!("")),
        Box::new(|v| app(v)["name"] = json!("")),
        Box::new(|v| mbedtls(v)["name"] = json!("")),
    ];
    for edit in edits {
        assert!(matches!(
            assert_validation_error(&edited(edit)),
            ValidationError::EmptyName { .. }
        ));
    }
    assert!(matches!(
        assert_validation_error(&edited(|v| mbedtls(v)["version"] = json!(""))),
        ValidationError::EmptyVersion { .. }
    ));
    // Empty supplier names and evidence sources are rejected while parsing.
    assert_parse_error(&edited(|v| v["supplier"]["name"] = json!("")));
    assert_parse_error(&edited(|v| mbedtls(v)["evidence"][0]["source"] = json!("")));
}

#[test]
fn deeply_nested_components_error_not_stack_overflow() {
    const DEPTH: usize = 100_000;
    let open = r#"{"kind":"library","name":"n","components":["#;
    let mut text = String::from(
        r#"{"schema":"rollcall-model/1","name":"p","images":[{"kind":"application","name":"a","components":["#,
    );
    for _ in 0..DEPTH {
        text.push_str(open);
    }
    for _ in 0..DEPTH {
        text.push_str("]}");
    }
    text.push_str("]}]}");
    let err = assert_json_error(&text);
    assert!(matches!(err, ModelError::Json(_)), "{err:?}");
    assert!(err.to_string().contains("recursion limit"), "{err}");
}
