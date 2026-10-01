//! The CycloneDX reader: lossless round trips of rollcall output, lenient reading of foreign
//! documents, and malformed input that errors without panicking.

mod common;

use std::path::{Path, PathBuf};

use common::{GOLDEN_TIMESTAMP, arb_entries, build, fixture_names, load_fixture};
use proptest::prelude::*;
use rollcall_core::cyclonedx::{self, ReadError, Timestamp, WriteOptions};
use rollcall_core::model::{ImageKind, Product};
use rollcall_core::zephyr::{self, IngestOptions};
use serde_json::{Value, json};

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr"),
    }
}

fn render(product: &Product) -> String {
    let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    cyclonedx::write(product, &options).unwrap()
}

fn assert_round_trips(what: &str, product: &Product) {
    let text = render(product);
    let read = cyclonedx::read_str(&text).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert_eq!(&read.product, product, "{what}");
    assert!(read.warnings.is_empty(), "{what}: {:?}", read.warnings);
    // And writing what was read gives the same bytes.
    assert_eq!(render(&read.product), text, "{what}");
}

#[test]
fn read_write_round_trip_is_lossless_for_every_fixture_and_arbitrary_products() {
    for name in fixture_names() {
        assert_round_trips(&name, &load_fixture(&name));
    }
    for (variant, image) in [
        ("baseline", "with_mcuboot"),
        ("baseline", "mcuboot"),
        ("bt", "beacon"),
        ("bt", "mcuboot"),
        ("tls", "http_server"),
        ("tls", "mcuboot"),
    ] {
        for sdk in [false, true] {
            let root = fixtures_root().join(variant);
            let options = IngestOptions::new(root.join(image))
                .with_west_list(root.join("west-list.txt"))
                .with_include_sdk(sdk);
            let product = zephyr::ingest(&options).unwrap().product;
            assert_round_trips(&format!("{variant}/{image} sdk={sdk}"), &product);
        }
    }
    proptest!(ProptestConfig::with_cases(64), |(entries in arb_entries())| {
        let product = build(&entries);
        let read = cyclonedx::read_str(&render(&product)).unwrap();
        prop_assert_eq!(read.product, product);
    });
}

#[test]
fn bytes_must_be_utf8() {
    assert!(matches!(
        cyclonedx::read_bytes(b"{\"bomFormat\": \"Cyclone\xff\"}"),
        Err(ReadError::Utf8(_))
    ));
    let text = render(&load_fixture("minimal"));
    assert_eq!(
        cyclonedx::read_bytes(text.as_bytes()).unwrap().product,
        load_fixture("minimal")
    );
}

/// A minimal valid document to break in various ways.
fn base_doc() -> Value {
    serde_json::from_str(&render(&load_fixture("minimal"))).unwrap()
}

#[test]
fn malformed_documents_error_never_panic() {
    let text = render(&load_fixture("widget"));
    let mut cases: Vec<(String, String)> = vec![
        ("empty".into(), String::new()),
        ("whitespace".into(), " \n".into()),
        (
            "truncated".into(),
            text.get(..text.len() / 2).unwrap_or_default().to_owned(),
        ),
        ("not-object".into(), "[1, 2, 3]".into()),
        ("string".into(), "\"CycloneDX\"".into()),
        ("deep".into(), "[".repeat(100_000)),
        (
            "deep-components".into(),
            format!(
                "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":{}",
                "[{\"type\":\"library\",\"name\":\"x\",\"components\":".repeat(5_000)
            ),
        ),
    ];
    for i in (0..text.len()).step_by(997) {
        if let Some(prefix) = text.get(..i) {
            cases.push((format!("prefix-{i}"), prefix.to_owned()));
        }
    }
    for (name, input) in &cases {
        let result = std::panic::catch_unwind(|| cyclonedx::read_str(input));
        let result = result.unwrap_or_else(|_| panic!("{name}: panicked"));
        assert!(result.is_err(), "{name}: read succeeded");
    }

    let check = |what: &str, doc: Value, expect: &dyn Fn(&ReadError) -> bool| {
        let result = std::panic::catch_unwind(|| cyclonedx::read(&doc))
            .unwrap_or_else(|_| panic!("{what}: panicked"));
        match result {
            Err(e) => assert!(expect(&e), "{what}: unexpected error {e:?}"),
            Ok(r) => panic!("{what}: read succeeded: {:?}", r.product),
        }
    };

    let mut doc = base_doc();
    doc["bomFormat"] = json!("SPDX");
    check("bomFormat", doc, &|e| {
        matches!(e, ReadError::NotCycloneDx(_))
    });
    let mut doc = base_doc();
    doc.as_object_mut().unwrap().remove("bomFormat");
    check("no bomFormat", doc, &|e| {
        matches!(e, ReadError::NotCycloneDx(_))
    });
    let mut doc = base_doc();
    doc["specVersion"] = json!("1.5");
    check(
        "spec 1.5",
        doc,
        &|e| matches!(e, ReadError::SpecVersion(v) if v == "1.5"),
    );
    let mut doc = base_doc();
    doc["specVersion"] = json!(1.6);
    check("spec number", doc, &|e| {
        matches!(e, ReadError::SpecVersion(_))
    });
    let mut doc = base_doc();
    doc["metadata"].as_object_mut().unwrap().remove("component");
    check("no root", doc, &|e| matches!(e, ReadError::MissingRoot));
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["type"] = json!("spaceship");
    check(
        "unknown type",
        doc,
        &|e| matches!(e, ReadError::UnknownComponentType { kind, .. } if kind == "spaceship"),
    );
    let mut doc = base_doc();
    doc["components"][0]["properties"] =
        json!([{"name": "rollcall:image-kind", "value": "kernel"}]);
    check("unknown image kind", doc, &|e| {
        matches!(e, ReadError::UnknownImageKind { .. })
    });
    let mut doc = base_doc();
    doc["dependencies"][0]["dependsOn"] = json!(["component:00000000000000000000000000000000"]);
    check("dangling ref", doc, &|e| {
        matches!(e, ReadError::UnknownRef(_))
    });
    let mut doc = base_doc();
    doc["components"][0]["type"] = json!("spaceship");
    check(
        "unknown image type",
        doc,
        &|e| matches!(e, ReadError::UnknownComponentType { kind, .. } if kind == "spaceship"),
    );
    let mut doc = base_doc();
    let root_ref = doc["metadata"]["component"]["bom-ref"].clone();
    doc["components"][0]["bom-ref"] = root_ref;
    check("duplicate ref", doc, &|e| {
        matches!(e, ReadError::DuplicateRef(_))
    });
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["name"] = json!(42);
    check("name type", doc, &|e| matches!(e, ReadError::Json(_)));
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["name"] = json!("");
    check("empty name", doc, &|e| matches!(e, ReadError::Id { .. }));
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["purl"] = json!("not a purl");
    check("bad purl", doc, &|e| matches!(e, ReadError::Id { .. }));
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["hashes"] = json!([{"alg": "SHA-256", "content": "xyz"}]);
    check("bad digest", doc, &|e| matches!(e, ReadError::Id { .. }));
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["properties"] =
        json!([{"name": "rollcall:evidence", "value": "{\"field\": \"name\""}]);
    check("bad evidence", doc, &|e| {
        matches!(e, ReadError::Evidence { .. })
    });
    let mut doc = base_doc();
    doc["components"][0]["components"][0]["version"] = json!("1.0\n");
    check("control char", doc, &|e| {
        matches!(e, ReadError::Validation(_))
    });
    let mut doc = base_doc();
    let own = doc["dependencies"][0]["ref"].clone();
    doc["dependencies"][0]["dependsOn"] = json!([own]);
    check("self dependency", doc, &|e| {
        matches!(e, ReadError::Validation(_))
    });
    let mut doc = base_doc();
    doc["components"] = json!({"not": "an array"});
    check("components type", doc, &|e| matches!(e, ReadError::Json(_)));
}

#[test]
fn foreign_document_is_read_leniently_with_warnings() {
    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "firmware", "name": "radio-fw", "version": "2.1"}},
        "components": [{
            "type": "firmware",
            "bom-ref": "vendor-radio",
            "name": "radio",
            "version": "2.1",
            "supplier": {"name": "Vendor Inc."},
            "hashes": [
                // CycloneDX `hash-content` allows upper-case hex.
                {"alg": "SHA-256", "content": "AB".repeat(32)},
                {"alg": "STREEBOG-256", "content": "cd".repeat(32)}
            ],
            "licenses": [{"license": {"id": "MIT"}}],
            "evidence": {"identity": [{"field": "name", "confidence": 1}]},
            "components": [{"type": "library", "bom-ref": "lib", "name": "libradio"}]
        }],
        "dependencies": [{"ref": "vendor-radio", "dependsOn": ["lib"]}]
    });
    let read = cyclonedx::read(&doc).unwrap();
    let image = read.product.images.first().unwrap();
    assert_eq!(image.kind, ImageKind::Application);
    assert_eq!(image.licence.as_ref().map(|l| l.as_str()), Some("MIT"));
    assert_eq!(image.hashes.len(), 1);
    let hash = image.hashes.first().unwrap();
    assert_eq!(
        hash.digest(),
        "ab".repeat(32),
        "digest is stored lower-case"
    );
    assert!(image.evidence.is_empty());
    assert_eq!(read.product.dependencies.len(), 1);
    let messages: Vec<String> = read.warnings.iter().map(|w| w.to_string()).collect();
    assert_eq!(messages.len(), 3, "{messages:?}");
    assert!(messages.iter().any(|m| m.contains("rollcall:image-kind")));
    assert!(messages.iter().any(|m| m.contains("STREEBOG-256")));
    assert!(messages.iter().any(|m| m.contains("evidence")));
}

/// A foreign document with one top-level component of `type` (and a `rollcall:image-kind`
/// property, so only the type can cause a warning).
fn foreign_with_image_type(kind: &str) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "firmware", "name": "product"}},
        "components": [{
            "type": kind,
            "name": "libvendor",
            "version": "1.0",
            "properties": [{"name": "rollcall:image-kind", "value": "application"}]
        }]
    })
}

#[test]
fn foreign_top_level_non_image_type_is_read_as_image_with_warning() {
    // Lenient: a top-level `library` is still read as an image, and the warning names the
    // component and its original type.
    let read = cyclonedx::read(&foreign_with_image_type("library")).unwrap();
    let image = read.product.images.first().unwrap();
    assert_eq!(image.name, "libvendor");
    assert_eq!(image.kind, ImageKind::Application);
    let messages: Vec<String> = read.warnings.iter().map(|w| w.to_string()).collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    let message = messages.first().unwrap();
    for needle in ["libvendor", "\"library\"", "application image"] {
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
    }

    // The three image-like types read without a warning.
    for kind in ["firmware", "application", "device"] {
        let read = cyclonedx::read(&foreign_with_image_type(kind)).unwrap();
        assert!(read.warnings.is_empty(), "{kind}: {:?}", read.warnings);
    }

    // A type that is not a CycloneDX 1.6 component type is an error, never a panic.
    let err = cyclonedx::read(&foreign_with_image_type("spaceship")).unwrap_err();
    assert!(
        matches!(&err, ReadError::UnknownComponentType { kind, .. } if kind == "spaceship"),
        "{err}"
    );

    // rollcall's own documents (every image is `firmware`) never warn about the type.
    let read = cyclonedx::read_str(&render(&load_fixture("widget"))).unwrap();
    assert!(
        read.warnings
            .iter()
            .all(|w| !w.message.contains("has type")),
        "{:?}",
        read.warnings
    );
}

/// A foreign document with a service, a component nested under `metadata.component`, and an
/// image, whose dependencies are `dependencies`.
fn foreign_with_dependencies(dependencies: Value) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {
            "type": "firmware",
            "bom-ref": "root",
            "name": "product",
            "components": [{
                "type": "library",
                "bom-ref": "nested",
                "name": "nested-lib",
                "components": [{"type": "library", "bom-ref": "nested-deep", "name": "deep"}]
            }]
        }},
        "components": [{
            "type": "firmware",
            "bom-ref": "img",
            "name": "app",
            "properties": [{"name": "rollcall:image-kind", "value": "application"}],
            "components": [{"type": "library", "bom-ref": "lib", "name": "libfoo"}]
        }],
        "services": [{
            "bom-ref": "svc",
            "name": "update-server",
            "services": [{"bom-ref": "svc-inner", "name": "auth"}]
        }],
        "dependencies": dependencies
    })
}

#[test]
fn dependency_on_service_or_dropped_nested_component_is_dropped_with_warning() {
    let doc = foreign_with_dependencies(json!([
        {"ref": "root", "dependsOn": ["img"]},
        {"ref": "img", "dependsOn": ["lib", "svc", "svc-inner", "nested", "nested-deep"]},
        {"ref": "svc", "dependsOn": ["img"]},
        {"ref": "nested", "dependsOn": []}
    ]));
    let read = cyclonedx::read(&doc).unwrap();
    // root -> img and img -> lib survive; every edge touching a service or a dropped nested
    // component is dropped.
    let edges: usize = read.product.dependencies.values().map(|to| to.len()).sum();
    assert_eq!(edges, 2, "{:?}", read.product.dependencies);
    let messages: Vec<String> = read.warnings.iter().map(|w| w.to_string()).collect();
    let dependency_warnings: Vec<&String> = messages
        .iter()
        .filter(|m| m.starts_with("dependencies: "))
        .collect();
    // Four dropped targets of "img", plus "svc"'s own edge; "nested" has none to drop.
    assert_eq!(dependency_warnings.len(), 5, "{messages:?}");
    for (needle, why) in [
        ("\"svc\"", "a service"),
        ("\"svc-inner\"", "a service"),
        ("\"nested\"", "nested under metadata.component"),
        ("\"nested-deep\"", "nested under metadata.component"),
    ] {
        assert!(
            dependency_warnings
                .iter()
                .any(|m| m.contains(&format!("depends on {needle}")) && m.contains(why)),
            "no warning for {needle}: {messages:?}"
        );
    }
    assert!(
        dependency_warnings
            .iter()
            .any(|m| m.contains("\"svc\" is a service") && m.contains("dropped")),
        "{messages:?}"
    );

    // A ref that is nowhere in the document is still an error, as a target or as a source,
    // and also as the target of a dropped source.
    for dependencies in [
        json!([{"ref": "img", "dependsOn": ["ghost"]}]),
        json!([{"ref": "ghost", "dependsOn": ["img"]}]),
        json!([{"ref": "svc", "dependsOn": ["ghost"]}]),
    ] {
        let err = cyclonedx::read(&foreign_with_dependencies(dependencies.clone())).unwrap_err();
        assert!(
            matches!(&err, ReadError::UnknownRef(r) if r == "ghost"),
            "{dependencies}: {err}"
        );
    }
}
