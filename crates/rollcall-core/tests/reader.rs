//! The CycloneDX reader: lossless round trips of rollcall output, lenient reading of foreign
//! documents, and malformed input that errors without panicking.

mod common;

use std::path::{Path, PathBuf};

use common::{GOLDEN_TIMESTAMP, arb_entries, blob_product, build, fixture_names, load_fixture};
use proptest::prelude::*;
use rollcall_core::cyclonedx::{self, ReadError, Timestamp, WriteOptions};
use rollcall_core::model::{ImageKind, ImageType, Product};
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

#[test]
fn blobs_golden_reads_back_identically_with_no_warnings() {
    // The committed golden, read from disk (not re-rendered), holds a `library` blob.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/blobs.cdx.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let read = cyclonedx::read_str(&text).unwrap();
    assert!(read.warnings.is_empty(), "{:?}", read.warnings);
    assert_eq!(read.product, blob_product());
    let libphy = read
        .product
        .images
        .iter()
        .find(|i| i.name == "libphy")
        .unwrap();
    assert_eq!(libphy.image_type, ImageType::Library);
    assert_eq!(libphy.kind, ImageKind::Blob);
    // Writing what was read gives the golden's bytes again.
    assert_eq!(render(&read.product), text);
}

#[test]
fn foreign_library_blob_image_reads_without_warning() {
    // A foreign `library` whose image kind is `blob` reads as a library blob, silently.
    let mut doc = foreign_with_image_type("library");
    doc["components"][0]["properties"] = json!([{"name": "rollcall:image-kind", "value": "blob"}]);
    let read = cyclonedx::read(&doc).unwrap();
    assert!(read.warnings.is_empty(), "{:?}", read.warnings);
    let image = read.product.images.first().unwrap();
    assert_eq!(image.kind, ImageKind::Blob);
    assert_eq!(image.image_type, ImageType::Library);

    // A `library` with another image kind still warns, and keeps its type.
    let read = cyclonedx::read(&foreign_with_image_type("library")).unwrap();
    assert_eq!(read.warnings.len(), 1, "{:?}", read.warnings);
    let image = read.product.images.first().unwrap();
    assert_eq!(image.kind, ImageKind::Application);
    assert_eq!(image.image_type, ImageType::Library);

    // A non-library, non-image type with kind `blob` still warns and reads as firmware.
    let mut doc = foreign_with_image_type("framework");
    doc["components"][0]["properties"] = json!([{"name": "rollcall:image-kind", "value": "blob"}]);
    let read = cyclonedx::read(&doc).unwrap();
    assert_eq!(read.warnings.len(), 1, "{:?}", read.warnings);
    assert_eq!(
        read.product.images.first().unwrap().image_type,
        ImageType::Firmware
    );
}

/// A product whose mbedtls carries a primary CPE, one additional CPE, and cpe evidence for
/// both values.
fn product_with_additional_cpe() -> Product {
    use rollcall_core::model::{
        Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, Image, Technique,
    };
    let primary = "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*";
    let additional = "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*";
    let mut mbedtls = Component::new(ComponentKind::Library, "mbedtls")
        .unwrap()
        .with_version("3.6.4");
    mbedtls.cpe = Some(Cpe::new(primary).unwrap());
    mbedtls
        .additional_cpes
        .insert(Cpe::new(additional).unwrap());
    for (value, bp) in [(primary, 9000), (additional, 8000)] {
        mbedtls.evidence.insert(
            Evidence::new(
                EvidenceField::Cpe,
                Technique::ManifestAnalysis,
                "identifier-db",
                value,
                Confidence::new(bp).unwrap(),
            )
            .unwrap(),
        );
    }
    let mut image = Image::new(ImageKind::Application, "app").unwrap();
    image.components.insert(mbedtls);
    let mut product = Product::new("widget").unwrap();
    product.images.insert(image);
    product
}

/// The `mbedtls` component object of a rendered document.
fn mbedtls_of(doc: &Value) -> &Value {
    &doc["components"][0]["components"][0]
}

#[test]
fn additional_cpes_are_written_as_syft_properties_and_identity_and_read_back() {
    let product = product_with_additional_cpe();
    let text = render(&product);
    assert_eq!(render(&product), text, "deterministic");
    let doc: Value = serde_json::from_str(&text).unwrap();
    cyclonedx::validate_cyclonedx_1_6(&doc).unwrap();
    let mbedtls = mbedtls_of(&doc);
    assert_eq!(
        mbedtls["cpe"],
        "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"
    );
    // grype reads syft:cpe23 properties.
    let syft: Vec<&Value> = mbedtls["properties"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["name"] == "syft:cpe23")
        .collect();
    assert_eq!(
        syft,
        [&json!({"name": "syft:cpe23", "value": "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*"})]
    );
    // evidence.identity: the primary CPE's entry, then one per additional CPE, each with the
    // observations of its own value.
    let cpe_identity: Vec<&Value> = mbedtls["evidence"]["identity"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["field"] == "cpe")
        .collect();
    assert_eq!(
        cpe_identity,
        [
            &json!({
                "field": "cpe",
                "confidence": 0.9,
                "concludedValue": "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*",
                "methods": [{"technique": "manifest-analysis", "confidence": 0.9,
                    "value": "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"}]
            }),
            &json!({
                "field": "cpe",
                "confidence": 0.8,
                "concludedValue": "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*",
                "methods": [{"technique": "manifest-analysis", "confidence": 0.8,
                    "value": "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*"}]
            }),
        ]
    );
    assert_round_trips("additional cpe", &product);
    // The model's JSON form keeps them too.
    let json = product.to_json().unwrap();
    assert!(json.contains("\"additional_cpes\""), "{json}");
    assert_eq!(Product::from_json(&json).unwrap(), product);
}

#[test]
fn malformed_additional_cpes_error_or_warn_never_panic() {
    let text = render(&product_with_additional_cpe());
    let base: Value = serde_json::from_str(&text).unwrap();
    let set_syft = |doc: &mut Value, value: Value| {
        for p in doc["components"][0]["components"][0]["properties"]
            .as_array_mut()
            .unwrap()
        {
            if p["name"] == "syft:cpe23" {
                p["value"] = value.clone();
            }
        }
    };
    // Not a CPE, empty, or not a string: dropped with a warning naming the component; the
    // rest of the component is read.
    for bad in [
        json!("not a cpe"),
        json!(""),
        json!(null),
        json!("cpe:2.3:a:x"),
    ] {
        let mut doc = base.clone();
        set_syft(&mut doc, bad.clone());
        let read = cyclonedx::read_str(&doc.to_string()).unwrap_or_else(|e| panic!("{bad}: {e}"));
        let mbedtls = read
            .product
            .images
            .iter()
            .next()
            .unwrap()
            .components
            .iter()
            .next()
            .unwrap();
        assert!(mbedtls.additional_cpes.is_empty(), "{bad}");
        assert!(mbedtls.cpe.is_some(), "{bad}");
        assert!(
            read.warnings.iter().any(|w| w.location.contains("mbedtls")
                && w.message.starts_with("syft:cpe23 value")
                && w.message.ends_with("; dropped")),
            "{bad}: {:?}",
            read.warnings
        );
    }
    // On an image the value is not parsed: a malformed one gives the same warning as any.
    let mut doc = base.clone();
    doc["components"][0]["properties"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "syft:cpe23", "value": "garbage"}));
    let read = cyclonedx::read_str(&doc.to_string()).unwrap();
    assert!(
        read.warnings.iter().any(|w| w
            .message
            .starts_with("syft:cpe23 properties on a product or image are not read")),
        "{:?}",
        read.warnings
    );
    // The primary repeated as a property: ignored without a warning.
    let mut doc = base.clone();
    set_syft(
        &mut doc,
        json!("cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"),
    );
    let read = cyclonedx::read_str(&doc.to_string()).unwrap();
    let mbedtls = read
        .product
        .images
        .iter()
        .next()
        .unwrap()
        .components
        .iter()
        .next()
        .unwrap();
    assert!(mbedtls.additional_cpes.is_empty());
    // On a component without a cpe: dropped with a warning.
    let mut doc = base.clone();
    doc["components"][0]["components"][0]
        .as_object_mut()
        .unwrap()
        .remove("cpe");
    let read = cyclonedx::read_str(&doc.to_string()).unwrap();
    let mbedtls = read
        .product
        .images
        .iter()
        .next()
        .unwrap()
        .components
        .iter()
        .next()
        .unwrap();
    assert!(mbedtls.additional_cpes.is_empty());
    assert!(
        read.warnings
            .iter()
            .any(|w| w.message == "syft:cpe23 properties without a cpe; dropped"),
        "{:?}",
        read.warnings
    );
    // On an image: dropped with a warning.
    let mut doc = base.clone();
    doc["components"][0]["properties"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": "syft:cpe23", "value": "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*"}));
    let read = cyclonedx::read_str(&doc.to_string()).unwrap();
    assert!(
        read.warnings.iter().any(|w| w
            .message
            .starts_with("syft:cpe23 properties on a product or image are not read")),
        "{:?}",
        read.warnings
    );
}

/// The identifier database provenance in `metadata.properties` (SHA-104) reads back exactly,
/// and writing what was read gives the same bytes; other metadata properties are ignored.
#[test]
fn identifier_db_provenance_round_trips() {
    use rollcall_core::identify::{self, DbSource};
    let product = load_fixture("minimal");
    let db = identify::builtin().unwrap();
    for source in [
        DbSource::Embedded,
        DbSource::Flag(PathBuf::from("/abs/db.yaml")),
        DbSource::Env(PathBuf::from("db.yaml")),
        DbSource::Cache(PathBuf::from("/home/u/.cache/x")),
    ] {
        let properties = identify::provenance(&db, &source);
        let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap())
            .with_properties(properties.clone());
        let text = cyclonedx::write(&product, &options).unwrap();
        // Valid CycloneDX, with no path in it.
        let value: Value = serde_json::from_str(&text).unwrap();
        cyclonedx::validate_cyclonedx_1_6(&value).unwrap();
        assert!(
            !text.contains("db.yaml") && !text.contains(".cache"),
            "{text}"
        );
        assert_eq!(
            value["metadata"]["properties"],
            json!([
                {"name": "rollcall:identifiers:db-version", "value": rollcall_identifiers::DB_VERSION},
                {"name": "rollcall:identifiers:source", "value": source.kind()},
            ])
        );
        let read = cyclonedx::read_str(&text).unwrap();
        assert_eq!(read.product, product);
        assert!(read.warnings.is_empty(), "{:?}", read.warnings);
        assert_eq!(read.metadata_properties, properties);
        let again = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap())
            .with_properties(read.metadata_properties);
        assert_eq!(cyclonedx::write(&read.product, &again).unwrap(), text);
    }
    // Without provenance there is no metadata.properties at all (unchanged output).
    let value: Value = serde_json::from_str(&render(&product)).unwrap();
    assert!(value["metadata"].get("properties").is_none());
    // Foreign or malformed metadata properties are ignored, not errors.
    let mut doc: Value = serde_json::from_str(&render(&product)).unwrap();
    doc["metadata"]["properties"] = json!([
        {"name": "vendor:thing", "value": "x"},
        {"name": "rollcall:identifiers:source"},
        {"name": "rollcall:identifiers:db-version", "value": "9.9.9"},
    ]);
    let read = cyclonedx::read_str(&doc.to_string()).unwrap();
    assert_eq!(read.metadata_properties.len(), 1);
    assert_eq!(read.metadata_properties[0].value, "9.9.9");
    doc["metadata"]["properties"] = json!("not a list");
    assert!(cyclonedx::read_str(&doc.to_string()).is_err());
}

#[test]
fn component_scope_round_trips_and_bad_or_misplaced_scope_is_handled() {
    use rollcall_core::model::{Component, ComponentKind, Image, Scope};
    let mut product = Product::new("p").unwrap();
    let mut image = Image::new(ImageKind::Application, "app").unwrap();
    for (name, scope) in [
        ("a", None),
        ("b", Some(Scope::Required)),
        ("c", Some(Scope::Optional)),
        ("d", Some(Scope::Excluded)),
    ] {
        let mut c = Component::new(ComponentKind::Library, name).unwrap();
        c.scope = scope;
        image.add_component(c).unwrap();
    }
    product.add_image(image).unwrap();
    assert_round_trips("scopes", &product);
    let doc: Value = serde_json::from_str(&render(&product)).unwrap();
    let scopes: Vec<Value> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.get("scope").cloned().unwrap_or(Value::Null))
        .collect();
    assert_eq!(
        scopes,
        [
            json!(null),
            json!("required"),
            json!("optional"),
            json!("excluded")
        ]
    );

    // An unknown scope is an error; a scope on an image is dropped with a warning.
    let mut bad = doc.clone();
    bad["components"][0]["components"][0]["scope"] = json!("sometimes");
    assert!(matches!(
        cyclonedx::read(&bad),
        Err(ReadError::UnknownScope { .. })
    ));
    let mut on_image = doc;
    on_image["components"][0]["scope"] = json!("excluded");
    let read = cyclonedx::read(&on_image).unwrap();
    assert_eq!(read.product, product);
    assert!(
        read.warnings
            .iter()
            .any(|w| w.message.contains("scope") && w.message.contains("dropped")),
        "{:?}",
        read.warnings
    );
}
