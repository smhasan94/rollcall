//! CycloneDX 1.6 writer: schema validation, golden files and the model → CycloneDX mapping.
//!
//! The `*.cdx.json` golden files are generated only by `scripts/regen-golden.sh`, which runs
//! this test with `ROLLCALL_BLESS=1`. Never edit them by hand.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::{
    GOLDEN_TIMESTAMP, arb_entries, base_product, build, fixture_names, line_diff, load_fixture,
};
use proptest::prelude::*;
use rollcall_core::cyclonedx::{
    self, SerialNumber, Timestamp, WriteError, WriteOptions, validate_cyclonedx_1_6,
};
use rollcall_core::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, Hash,
    HashAlgorithm, Image, ImageKind, License, Occurrence, PathSegment, Product, Purl, Supplier,
    Technique, ValidationError,
};
use serde_json::{Value, json};

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        common::bless(&path, actual);
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} differs from the writer's output; if the change is intended, run \
         scripts/regen-golden.sh and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

fn options(timestamp: &str) -> WriteOptions {
    WriteOptions::new(Timestamp::parse(timestamp).unwrap())
}

fn render(product: &Product) -> String {
    cyclonedx::write(product, &options(GOLDEN_TIMESTAMP)).unwrap()
}

fn render_value(product: &Product) -> Value {
    serde_json::from_str(&render(product)).unwrap()
}

fn assert_schema_valid(what: &str, text: &str) {
    let value: Value = serde_json::from_str(text).unwrap();
    if let Err(violations) = validate_cyclonedx_1_6(&value) {
        panic!("{what} is not valid CycloneDX 1.6:\n{violations:#?}\n{text}");
    }
}

fn confidence(bp: u16) -> Confidence {
    Confidence::new(bp).unwrap()
}

fn ev(field: EvidenceField, technique: Technique, source: &str, value: &str, bp: u16) -> Evidence {
    Evidence::new(field, technique, source, value, confidence(bp)).unwrap()
}

/// Every CycloneDX component object in the document (root, images, nested), depth-first.
fn all_components(doc: &Value) -> Vec<&Value> {
    let mut out = vec![&doc["metadata"]["component"]];
    let mut stack: Vec<&Value> = doc["components"]
        .as_array()
        .map(|a| a.iter().rev().collect())
        .unwrap_or_default();
    while let Some(c) = stack.pop() {
        out.push(c);
        if let Some(children) = c["components"].as_array() {
            stack.extend(children.iter().rev());
        }
    }
    out
}

fn find<'a>(doc: &'a Value, name: &str) -> &'a Value {
    all_components(doc)
        .into_iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no component named {name}"))
}

#[test]
fn every_fixture_output_validates_against_schema_1_6() {
    let names = fixture_names();
    assert!(
        names.contains(&"minimal".to_owned()) && names.contains(&"widget".to_owned()),
        "{names:?}"
    );
    for name in names {
        let product = load_fixture(&name);
        assert_schema_valid(&name, &render(&product));
        // With a derived serial number and with other timestamps too.
        for ts in ["1970-01-01T00:00:00Z", "2099-12-31T23:59:59.5+14:00"] {
            assert_schema_valid(&name, &cyclonedx::write(&product, &options(ts)).unwrap());
        }
    }
    // The code-built model fixtures used across the model tests as well.
    assert_schema_valid("base_product", &render(&base_product()));
    assert_schema_valid("every_fact", &render(&every_fact_product()));
    assert_schema_valid("evidence", &render(&evidence_product()));
}

#[test]
fn every_committed_golden_validates_against_schema_1_6() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let file = entry.unwrap().file_name().to_string_lossy().into_owned();
        if file.ends_with(".cdx.json") {
            let text = std::fs::read_to_string(dir.join(&file)).unwrap();
            assert_schema_valid(&file, &text);
            seen.push(file);
        }
    }
    seen.sort();
    assert_eq!(seen, ["minimal.cdx.json", "widget.cdx.json"]);
}

#[test]
fn minimal_fixture_matches_golden() {
    check_golden("minimal.cdx.json", &render(&load_fixture("minimal")));
}

#[test]
fn widget_fixture_matches_golden() {
    check_golden("widget.cdx.json", &render(&load_fixture("widget")));
}

#[test]
fn rendering_twice_is_byte_identical() {
    for name in fixture_names() {
        let first = render(&load_fixture(&name));
        let second = render(&load_fixture(&name));
        assert_eq!(first.as_bytes(), second.as_bytes(), "{name}");
        assert!(first.ends_with("}\n"), "{name}");
        // The value form is equal too.
        let product = load_fixture(&name);
        let opts = options(GOLDEN_TIMESTAMP);
        assert_eq!(
            cyclonedx::to_document(&product, &opts).unwrap(),
            cyclonedx::to_document(&product, &opts).unwrap()
        );
    }
    // The widget fixture file and the code-built base product are the same model.
    assert_eq!(render(&load_fixture("widget")), render(&base_product()));
}

#[test]
fn changing_timestamp_changes_only_the_timestamp_line() {
    for name in fixture_names() {
        let product = load_fixture(&name);
        let a = cyclonedx::write(&product, &options(GOLDEN_TIMESTAMP)).unwrap();
        let b = cyclonedx::write(&product, &options("2031-07-08T09:10:11Z")).unwrap();
        let (removed, inserted) = line_diff(&a, &b);
        assert_eq!(removed.len(), 1, "{name}: {removed:#?}");
        assert_eq!(inserted.len(), 1, "{name}: {inserted:#?}");
        assert_eq!(
            removed[0].trim(),
            format!("\"timestamp\": \"{GOLDEN_TIMESTAMP}\",")
        );
        assert_eq!(
            inserted[0].trim(),
            "\"timestamp\": \"2031-07-08T09:10:11Z\","
        );
    }
}

#[test]
fn serial_number_is_derived_from_content_not_timestamp() {
    let mut serials = BTreeSet::new();
    for name in fixture_names() {
        let product = load_fixture(&name);
        let expected = SerialNumber::derive(&product).unwrap();
        for ts in [
            GOLDEN_TIMESTAMP,
            "1999-01-01T00:00:00Z",
            "2031-07-08T09:10:11Z",
        ] {
            let doc: Value =
                serde_json::from_str(&cyclonedx::write(&product, &options(ts)).unwrap()).unwrap();
            assert_eq!(doc["serialNumber"], expected.as_str(), "{name} at {ts}");
        }
        serials.insert(expected);
    }
    assert_eq!(
        serials.len(),
        fixture_names().len(),
        "fixtures share a serial"
    );

    // Changing the model changes the serial number.
    let mut changed = load_fixture("minimal");
    changed.licence = Some(License::new("MIT").unwrap());
    assert_ne!(
        SerialNumber::derive(&changed).unwrap(),
        SerialNumber::derive(&load_fixture("minimal")).unwrap()
    );
}

#[test]
fn serial_number_override_is_used_verbatim() {
    let serial = SerialNumber::parse("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79").unwrap();
    let product = load_fixture("minimal");
    let opts = options(GOLDEN_TIMESTAMP).with_serial_number(serial.clone());
    let text = cyclonedx::write(&product, &opts).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["serialNumber"], serial.as_str());
    // Only that line differs from the derived-serial rendering.
    let (removed, inserted) = line_diff(&render(&product), &text);
    assert_eq!(removed.len(), 1);
    assert_eq!(
        inserted,
        [format!("  \"serialNumber\": \"{}\",", serial.as_str())]
    );
    assert_schema_valid("override", &text);
}

#[test]
fn root_is_product_and_images_nest_under_top_level_components() {
    let product = load_fixture("widget");
    let doc = render_value(&product);
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.6");
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["metadata"]["timestamp"], GOLDEN_TIMESTAMP);
    assert_eq!(
        doc["metadata"]["tools"]["components"],
        json!([{"type": "application", "name": "rollcall", "version": env!("CARGO_PKG_VERSION")}])
    );
    // Top-level keys in output order (serde_json's `Map` sorts, so read them from the text).
    let text = render(&product);
    let keys: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("  \""))
        .filter_map(|l| l.split('"').next())
        .collect();
    assert_eq!(
        keys,
        [
            "bomFormat",
            "specVersion",
            "serialNumber",
            "version",
            "metadata",
            "components",
            "dependencies"
        ]
    );

    let root = &doc["metadata"]["component"];
    assert_eq!(root["type"], "firmware");
    assert_eq!(root["name"], "widget");
    assert_eq!(root["version"], "1.0.0");
    assert_eq!(root["bom-ref"], BomRef::derive(&product.path()).as_str());
    assert!(
        root.get("components").is_none(),
        "root must not nest: {root}"
    );

    let images = doc["components"].as_array().unwrap();
    let summary: Vec<(&str, &str)> = images
        .iter()
        .map(|i| (i["type"].as_str().unwrap(), i["name"].as_str().unwrap()))
        .collect();
    assert_eq!(
        summary,
        [
            ("firmware", "mcuboot"),
            ("firmware", "widget-app"),
            ("firmware", "radio-fw")
        ]
    );
    for (image, cdx) in product.images.iter().zip(images) {
        let path = product.path().child(PathSegment::of_image(image));
        assert_eq!(cdx["bom-ref"], BomRef::derive(&path).as_str());
        let children: Vec<&str> = cdx["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = image.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(children, expected);
    }
    let app = &images[1];
    let zephyr = app["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "zephyr")
        .unwrap();
    assert_eq!(zephyr["type"], "operating-system");
    assert_eq!(zephyr["components"][0]["name"], "kernel");
    assert_eq!(zephyr["components"][0]["type"], "library");
    assert_eq!(images[2]["components"][0]["type"], "firmware");

    // Every walked node appears exactly once, with its walk-derived ref.
    let doc_refs: Vec<&str> = all_components(&doc)
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    let walk_refs: Vec<String> = product
        .walk()
        .map(|(_, r, _)| r.as_str().to_owned())
        .collect();
    assert_eq!(doc_refs, walk_refs);
}

#[test]
fn image_kind_is_kept_as_property() {
    let doc = render_value(&load_fixture("widget"));
    let kinds: Vec<Value> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|image| {
            let props = image["properties"].as_array().unwrap();
            let kind: Vec<&Value> = props
                .iter()
                .filter(|p| p["name"] == "rollcall:image-kind")
                .collect();
            assert_eq!(kind.len(), 1, "{image}");
            kind[0]["value"].clone()
        })
        .collect();
    assert_eq!(
        kinds,
        [json!("bootloader"), json!("application"), json!("blob")]
    );
    // Only images carry it.
    for c in all_components(&doc) {
        let has = c["properties"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p["name"] == "rollcall:image-kind"));
        let is_image = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["bom-ref"] == c["bom-ref"]);
        assert_eq!(has, is_image, "{}", c["name"]);
    }
}

#[test]
fn dependencies_cover_every_node_with_sorted_edges() {
    for name in fixture_names() {
        let product = load_fixture(&name);
        let doc = render_value(&product);
        let deps = doc["dependencies"].as_array().unwrap();
        let walked: Vec<BomRef> = product.walk().map(|(_, r, _)| r).collect();
        assert_eq!(deps.len(), walked.len(), "{name}");
        for (dep, bom_ref) in deps.iter().zip(&walked) {
            assert_eq!(dep["ref"], bom_ref.as_str(), "{name}");
            let depends_on: Vec<&str> = dep["dependsOn"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}: dependsOn missing in {dep}"))
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let expected: Vec<&str> = product
                .dependencies
                .get(bom_ref)
                .map(|t| t.iter().map(BomRef::as_str).collect())
                .unwrap_or_default();
            assert_eq!(depends_on, expected, "{name}: {bom_ref}");
            let mut sorted = depends_on.clone();
            sorted.sort_unstable();
            assert_eq!(depends_on, sorted);
        }
    }
    // No containment edges are synthesised: the minimal fixture has exactly its 3 model edges.
    let doc = render_value(&load_fixture("minimal"));
    let edges: usize = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["dependsOn"].as_array().unwrap().len())
        .sum();
    assert_eq!(edges, 3);
    let widget = render_value(&load_fixture("widget"));
    let leaves = widget["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["dependsOn"] == json!([]))
        .count();
    assert_eq!(leaves, product_node_count(&load_fixture("widget")) - 3);
}

fn product_node_count(product: &Product) -> usize {
    product.walk().count()
}

/// A product whose one component carries every kind of evidence.
fn evidence_product() -> Product {
    let mut product = Product::new("ev").unwrap();
    let mut image = Image::new(ImageKind::Application, "app").unwrap();
    let mut c = Component::new(ComponentKind::Library, "mbedtls")
        .unwrap()
        .with_version("3.6.0");
    c.purl = Some(Purl::new("pkg:generic/mbedtls@3.6.0").unwrap());
    c.cpe = Some(Cpe::new("cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*").unwrap());
    c.hashes
        .insert(Hash::new(HashAlgorithm::Sha256, &"ab".repeat(32)).unwrap());
    let spdx = Occurrence::new("build/spdx/app.spdx", Some(7)).unwrap();
    for e in [
        ev(
            EvidenceField::Name,
            Technique::Filename,
            "build-dir",
            "mbedtls",
            5000,
        ),
        ev(
            EvidenceField::Version,
            Technique::ManifestAnalysis,
            "west-spdx",
            "3.6.0",
            9000,
        )
        .at(spdx.clone()),
        ev(
            EvidenceField::Version,
            Technique::ManifestAnalysis,
            "west-list",
            "3.6.0",
            7000,
        )
        .at(Occurrence::new("west.yml", Some(3)).unwrap()),
        ev(
            EvidenceField::Purl,
            Technique::ManifestAnalysis,
            "west-spdx",
            "pkg:generic/mbedtls@3.6.0",
            9000,
        )
        .at(spdx.clone()),
        ev(
            EvidenceField::Cpe,
            Technique::Other,
            "nvd-map",
            "cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*",
            6000,
        ),
        ev(
            EvidenceField::Hash,
            Technique::HashComparison,
            "west-spdx",
            &"ab".repeat(32),
            10000,
        ),
        ev(
            EvidenceField::Licence,
            Technique::SourceCodeAnalysis,
            "west-list",
            "Apache-2.0",
            6000,
        )
        .at(Occurrence::new("LICENSE", None).unwrap()),
        ev(
            EvidenceField::Licence,
            Technique::ManifestAnalysis,
            "west-spdx",
            "Apache-2.0 OR GPL-2.0-or-later",
            8000,
        ),
        ev(
            EvidenceField::Supplier,
            Technique::ManifestAnalysis,
            "supplier-db",
            "Arm",
            4000,
        ),
    ] {
        c.evidence.insert(e);
    }
    // A component with a single licence value, and one with no evidence at all.
    let mut single = Component::new(ComponentKind::Library, "single").unwrap();
    single.evidence.insert(ev(
        EvidenceField::Licence,
        Technique::SourceCodeAnalysis,
        "west-list",
        "MIT",
        5000,
    ));
    single.evidence.insert(ev(
        EvidenceField::Licence,
        Technique::ManifestAnalysis,
        "west-spdx",
        "MIT",
        6000,
    ));
    let bare = Component::new(ComponentKind::Library, "bare").unwrap();
    image.add_component(c).unwrap();
    image.add_component(single).unwrap();
    image.add_component(bare).unwrap();
    product.add_image(image).unwrap();
    product.validate().unwrap();
    product
}

#[test]
fn evidence_maps_identity_occurrences_licenses_and_sources() {
    let doc = render_value(&evidence_product());
    let c = find(&doc, "mbedtls");
    let evidence = &c["evidence"];
    assert_eq!(
        evidence["identity"],
        json!([
            {"field": "name", "confidence": 0.5, "concludedValue": "mbedtls", "methods": [
                {"technique": "filename", "confidence": 0.5, "value": "mbedtls"}
            ]},
            {"field": "version", "confidence": 0.9, "concludedValue": "3.6.0", "methods": [
                {"technique": "manifest-analysis", "confidence": 0.7, "value": "3.6.0"},
                {"technique": "manifest-analysis", "confidence": 0.9, "value": "3.6.0"}
            ]},
            {"field": "purl", "confidence": 0.9, "concludedValue": "pkg:generic/mbedtls@3.6.0", "methods": [
                {"technique": "manifest-analysis", "confidence": 0.9, "value": "pkg:generic/mbedtls@3.6.0"}
            ]},
            {"field": "cpe", "confidence": 0.6, "concludedValue": "cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*", "methods": [
                {"technique": "other", "confidence": 0.6, "value": "cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*"}
            ]},
            {"field": "hash", "confidence": 1.0, "methods": [
                {"technique": "hash-comparison", "confidence": 1.0, "value": "ab".repeat(32)}
            ]}
        ])
    );
    // Node-level, de-duplicated (two entries share build/spdx/app.spdx:7), sorted.
    assert_eq!(
        evidence["occurrences"],
        json!([
            {"location": "LICENSE"},
            {"location": "build/spdx/app.spdx", "line": 7},
            {"location": "west.yml", "line": 3}
        ])
    );
    // Two distinct licence values: named licences, sorted.
    assert_eq!(
        evidence["licenses"],
        json!([
            {"license": {"name": "Apache-2.0"}},
            {"license": {"name": "Apache-2.0 OR GPL-2.0-or-later"}}
        ])
    );
    // Supplier evidence is not emitted as evidence, but its source is listed.
    assert!(!evidence.to_string().contains("Arm"));
    assert_eq!(
        c["properties"],
        json!([
            {"name": "rollcall:evidence-source", "value": "build-dir"},
            {"name": "rollcall:evidence-source", "value": "nvd-map"},
            {"name": "rollcall:evidence-source", "value": "supplier-db"},
            {"name": "rollcall:evidence-source", "value": "west-list"},
            {"name": "rollcall:evidence-source", "value": "west-spdx"}
        ])
    );

    // One distinct licence value becomes a single expression; no identity or occurrences.
    let single = find(&doc, "single");
    assert_eq!(
        single["evidence"],
        json!({"licenses": [{"expression": "MIT"}]})
    );

    // No evidence: no evidence object and no properties.
    let bare = find(&doc, "bare");
    assert!(bare.get("evidence").is_none(), "{bare}");
    assert!(bare.get("properties").is_none(), "{bare}");

    // The minimal fixture's one evidence entry, end to end.
    let minimal = render_value(&load_fixture("minimal"));
    let littlefs = find(&minimal, "littlefs");
    assert_eq!(
        littlefs["evidence"],
        json!({
            "identity": [{"field": "version", "confidence": 0.95, "concludedValue": "2.9.0", "methods": [
                {"technique": "manifest-analysis", "confidence": 0.95, "value": "2.9.0"}
            ]}],
            "occurrences": [{"location": "build/spdx/app.spdx", "line": 12}]
        })
    );
    assert_eq!(
        littlefs["properties"],
        json!([{"name": "rollcall:evidence-source", "value": "west-spdx"}])
    );
}

/// A product in which every node level sets every fact.
fn every_fact_product() -> Product {
    // Sets every optional fact on a product, image or component named `$name`.
    macro_rules! set_every_fact {
        ($node:expr, $name:expr) => {{
            let name: &str = $name;
            $node.supplier = Some(
                Supplier::new(name)
                    .unwrap()
                    .with_url(&format!("https://{name}.example/b"))
                    .unwrap()
                    .with_url(&format!("https://{name}.example/a"))
                    .unwrap(),
            );
            $node.purl = Some(Purl::new(&format!("pkg:generic/{name}@1.0")).unwrap());
            $node.cpe =
                Some(Cpe::new(&format!("cpe:2.3:a:example:{name}:1.0:*:*:*:*:*:*:*")).unwrap());
            $node
                .hashes
                .insert(Hash::new(HashAlgorithm::Sha512, &"cd".repeat(64)).unwrap());
            $node
                .hashes
                .insert(Hash::new(HashAlgorithm::Sha1, &"ef".repeat(20)).unwrap());
            $node.licence = Some(License::new("MIT OR Apache-2.0").unwrap());
            $node.evidence.insert(ev(
                EvidenceField::Name,
                Technique::Attestation,
                &format!("{name}-src"),
                name,
                1234,
            ));
        }};
    }
    let mut product = Product::new("prod").unwrap().with_version("1.0");
    set_every_fact!(product, "prod");
    let mut image = Image::new(ImageKind::Bootloader, "img")
        .unwrap()
        .with_version("1.0");
    set_every_fact!(image, "img");
    let mut comp = Component::new(ComponentKind::Framework, "comp")
        .unwrap()
        .with_version("1.0");
    set_every_fact!(comp, "comp");
    let mut sub = Component::new(ComponentKind::DeviceDriver, "sub")
        .unwrap()
        .with_version("1.0");
    set_every_fact!(sub, "sub");
    comp.add_component(sub).unwrap();
    image.add_component(comp).unwrap();
    product.add_image(image).unwrap();
    let refs: Vec<BomRef> = product.walk().map(|(_, r, _)| r).collect();
    product.add_dependency(refs[3].clone(), refs[0].clone());
    product.add_dependency(refs[0].clone(), refs[1].clone());
    product.validate().unwrap();
    product
}

#[test]
fn every_fact_is_mapped() {
    let product = every_fact_product();
    let doc = render_value(&product);
    let walked: Vec<(String, BomRef)> = product
        .walk()
        .map(|(p, r, _)| (p.segments().last().unwrap().name.clone(), r))
        .collect();
    let expected_types = [
        ("prod", "firmware"),
        ("img", "firmware"),
        ("comp", "framework"),
        ("sub", "device-driver"),
    ];
    for ((name, bom_ref), (expected_name, kind)) in walked.iter().zip(expected_types) {
        assert_eq!(name, expected_name);
        let c = find(&doc, name);
        assert_eq!(c["type"], kind, "{name}");
        assert_eq!(c["bom-ref"], bom_ref.as_str(), "{name}");
        assert_eq!(c["name"], *name);
        assert_eq!(c["version"], "1.0", "{name}");
        assert_eq!(
            c["supplier"],
            json!({"name": name, "url": [
                format!("https://{name}.example/a"),
                format!("https://{name}.example/b")
            ]}),
            "{name}"
        );
        assert_eq!(c["purl"], format!("pkg:generic/{name}@1.0"));
        assert_eq!(
            c["cpe"],
            format!("cpe:2.3:a:example:{name}:1.0:*:*:*:*:*:*:*")
        );
        assert_eq!(
            c["hashes"],
            json!([
                {"alg": "SHA-1", "content": "ef".repeat(20)},
                {"alg": "SHA-512", "content": "cd".repeat(64)}
            ]),
            "{name}"
        );
        assert_eq!(c["licenses"], json!([{"expression": "MIT OR Apache-2.0"}]));
        assert_eq!(
            c["evidence"]["identity"],
            json!([{"field": "name", "confidence": 0.1234, "concludedValue": name, "methods": [
                {"technique": "attestation", "confidence": 0.1234, "value": name}
            ]}]),
            "{name}"
        );
        let source = json!({"name": "rollcall:evidence-source", "value": format!("{name}-src")});
        assert!(
            c["properties"].as_array().unwrap().contains(&source),
            "{name}: {}",
            c["properties"]
        );
    }
    // Properties sort by (name, value): the evidence source before the image kind.
    assert_eq!(
        find(&doc, "img")["properties"],
        json!([
            {"name": "rollcall:evidence-source", "value": "img-src"},
            {"name": "rollcall:image-kind", "value": "bootloader"}
        ])
    );
    // Structure and dependencies.
    assert_eq!(doc["components"][0]["name"], "img");
    assert_eq!(doc["components"][0]["components"][0]["name"], "comp");
    assert_eq!(
        doc["components"][0]["components"][0]["components"][0]["name"],
        "sub"
    );
    assert_eq!(
        doc["dependencies"],
        json!([
            {"ref": walked[0].1.as_str(), "dependsOn": [walked[1].1.as_str()]},
            {"ref": walked[1].1.as_str(), "dependsOn": []},
            {"ref": walked[2].1.as_str(), "dependsOn": []},
            {"ref": walked[3].1.as_str(), "dependsOn": [walked[0].1.as_str()]}
        ])
    );
}

#[test]
fn confidence_prints_without_float_noise() {
    let mut product = Product::new("conf").unwrap();
    let mut image = Image::new(ImageKind::Blob, "blob").unwrap();
    for (name, bp) in [("a", 1), ("b", 1235), ("c", 9500), ("d", 10000)] {
        let mut c = Component::new(ComponentKind::Data, name).unwrap();
        c.evidence.insert(ev(
            EvidenceField::Name,
            Technique::Filename,
            "build-dir",
            name,
            bp,
        ));
        image.add_component(c).unwrap();
    }
    product.add_image(image).unwrap();
    let text = render(&product);
    let confidences: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("\"confidence\": "))
        .map(|v| v.trim_end_matches(','))
        .collect();
    assert_eq!(
        confidences,
        [
            "0.0001", "0.0001", "0.1235", "0.1235", "0.95", "0.95", "1.0", "1.0"
        ]
    );
    assert_schema_valid("conf", &text);
}

#[test]
fn writer_rejects_invalid_product() {
    let opts = options(GOLDEN_TIMESTAMP);
    let mut dangling = load_fixture("minimal");
    let (_, root, _) = dangling.walk().next().unwrap();
    dangling.add_dependency(
        root.clone(),
        BomRef::parse(&format!("component:{}", "0".repeat(32))).unwrap(),
    );
    let mut self_dep = load_fixture("minimal");
    self_dep.add_dependency(root.clone(), root);
    let mut empty_name = load_fixture("minimal");
    empty_name.name = String::new();
    let mut control = load_fixture("minimal");
    control.version = Some("1.0\u{7}".to_owned());

    for (what, product) in [
        ("dangling", dangling),
        ("self", self_dep),
        ("empty name", empty_name),
        ("control", control),
    ] {
        let err = cyclonedx::write(&product, &opts).unwrap_err();
        assert!(matches!(err, WriteError::Invalid(_)), "{what}: {err:?}");
        assert!(err.to_string().starts_with("invalid model: "), "{err}");
        assert!(cyclonedx::to_document(&product, &opts).is_err(), "{what}");
    }
    let mut dangling = load_fixture("minimal");
    let (_, root, _) = dangling.walk().next().unwrap();
    let ghost = BomRef::parse(&format!("image:{}", "f".repeat(32))).unwrap();
    dangling.add_dependency(root, ghost);
    assert!(matches!(
        cyclonedx::write(&dangling, &opts),
        Err(WriteError::Invalid(
            ValidationError::DanglingDependency { .. }
        ))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        // Keep generated regression files out of the repository.
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_products_render_schema_valid(
        entries in arb_entries(),
        edges in proptest::collection::vec((any::<usize>(), any::<usize>()), 0..=6),
    ) {
        let mut product = build(&entries);
        let refs: Vec<BomRef> = product.walk().map(|(_, r, _)| r).collect();
        for (from, to) in edges {
            let (from, to) = (&refs[from % refs.len()], &refs[to % refs.len()]);
            if from != to {
                product.add_dependency(from.clone(), to.clone());
            }
        }
        let text = cyclonedx::write(&product, &options(GOLDEN_TIMESTAMP)).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(validate_cyclonedx_1_6(&value), Ok(()));
        prop_assert_eq!(&cyclonedx::write(&product, &options(GOLDEN_TIMESTAMP)).unwrap(), &text);
        prop_assert_eq!(value["dependencies"].as_array().unwrap().len(), refs.len());
    }
}

#[test]
fn supplier_urls_accepted_by_model_are_schema_valid() {
    // Tricky but valid IRI references. The model must accept each one, and the rendered
    // document must then pass the real CycloneDX 1.6 schema, whose `supplier.url` items are
    // `iri-reference`s.
    let urls = [
        "https://acme.example",
        "https://acme.example/path?q=1&r=2#frag",
        "https://bücher.example/ä?ö=ü#ß",
        "https://acme.example/a%20b/%C3%A4%2f",
        "https://user:pw@acme.example:8443/x",
        "http://[::1]:8080/x",
        "http://192.0.2.1/",
        "https://acme.example/!$&'()*+,;=:@~-._",
        "relative/path",
        "./here",
        "../up",
        "//acme.example/path",
        "?query",
        "#fragment",
        "mailto:security@acme.example",
        "urn:example:supplier",
    ];
    for url in urls {
        let supplier = Supplier::new("ACME")
            .unwrap()
            .with_url(url)
            .unwrap_or_else(|e| panic!("model rejects {url:?}: {e}"));
        let mut product = Product::new("p").unwrap();
        product.supplier = Some(supplier.clone());
        let mut image = Image::new(ImageKind::Application, "app").unwrap();
        image.supplier = Some(supplier.clone());
        let mut component = Component::new(ComponentKind::Library, "lib").unwrap();
        component.supplier = Some(supplier);
        image.add_component(component).unwrap();
        product.add_image(image).unwrap();

        let text = render(&product);
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            doc["metadata"]["component"]["supplier"]["url"],
            json!([url])
        );
        if let Err(violations) = validate_cyclonedx_1_6(&doc) {
            panic!("model accepts {url:?} but the schema rejects it:\n{violations:#?}");
        }
    }
}

#[test]
fn licence_evidence_that_is_not_spdx_uses_license_name() {
    let licence_only = |name: &str, values: &[&str]| {
        let mut c = Component::new(ComponentKind::Library, name).unwrap();
        for (i, value) in values.iter().enumerate() {
            c.evidence.insert(ev(
                EvidenceField::Licence,
                Technique::SourceCodeAnalysis,
                &format!("source-{i}"),
                value,
                5000,
            ));
        }
        c
    };
    let mut product = Product::new("lic").unwrap();
    let mut image = Image::new(ImageKind::Application, "app").unwrap();
    for c in [
        licence_only("free-text", &["GPL v2 (see COPYING)"]),
        licence_only("spdx", &["Apache-2.0 OR MIT"]),
        licence_only("mixed", &["MIT", "GPL v2 (see COPYING)"]),
    ] {
        image.add_component(c).unwrap();
    }
    product.add_image(image).unwrap();
    let text = render(&product);
    let doc: Value = serde_json::from_str(&text).unwrap();

    // One value that is not an SPDX expression: a named licence, never an expression.
    assert_eq!(
        find(&doc, "free-text")["evidence"]["licenses"],
        json!([{"license": {"name": "GPL v2 (see COPYING)"}}])
    );
    // One valid SPDX expression: stays an expression.
    assert_eq!(
        find(&doc, "spdx")["evidence"]["licenses"],
        json!([{"expression": "Apache-2.0 OR MIT"}])
    );
    // Several values: always named licences, sorted, even when one is valid SPDX.
    assert_eq!(
        find(&doc, "mixed")["evidence"]["licenses"],
        json!([
            {"license": {"name": "GPL v2 (see COPYING)"}},
            {"license": {"name": "MIT"}}
        ])
    );
    assert_schema_valid("lic", &text);
}
