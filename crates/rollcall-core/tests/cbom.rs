//! SHA-138: crypto assets in the model and the CycloneDX 1.6 writer and reader (a CBOM).
//!
//! The fixture is the hand-written model `tests/data/cbom/sensor-node.cbom.model.json` (not a
//! real build). Its golden CycloneDX document, `tests/golden/cbom/sensor-node.cbom.json`, is
//! written only by `scripts/regen-golden.sh`, which runs this test with `ROLLCALL_BLESS=1`;
//! the Markdown golden beside it is written by `rollcall-assay`'s `tests/summary.rs`. Never
//! edit them by hand.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use common::{GOLDEN_TIMESTAMP, cbom_product, load_cbom_fixture};
use proptest::prelude::*;
use proptest::sample::select;
use rollcall_core::cyclonedx::{self, ReadError, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::model::{
    AlgorithmProperties, CertificateProperties, Component, ComponentKind, ConfidenceLevel,
    CryptoAsset, CryptoAssetProperties, CryptoEvidence, CryptoFunction, ExecutionEnvironment,
    Image, ImageKind, ImplementationPlatform, Locator, MaterialState, MaterialType, Mode,
    Primitive, Product, ProtocolProperties, ProtocolType, QuantumSecurityLevel,
    RelatedCryptoMaterialProperties,
};
use serde_json::{Value, json};

const GOLDEN_JSON: &str = "sensor-node.cbom.json";

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/cbom")
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(golden_dir()).unwrap();
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

/// Every component object in the document (images and nested), depth-first.
fn all_components(doc: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
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

fn crypto_components(doc: &Value) -> Vec<&Value> {
    all_components(doc)
        .into_iter()
        .filter(|c| c["type"] == "cryptographic-asset")
        .collect()
}

/// The fixture's assets and their asset types.
const ASSETS: [(&str, &str); 7] = [
    ("AES-128-GCM", "algorithm"),
    ("ChaCha20-Poly1305", "algorithm"),
    ("RSA-2048", "algorithm"),
    ("SHA-256", "algorithm"),
    ("TLS", "protocol"),
    ("device-cert", "certificate"),
    ("psk", "related-crypto-material"),
];

/// The fixture file and the code-built twin are the same model, so tests may use either.
#[test]
fn cbom_fixture_equals_code_built_twin() {
    assert_eq!(load_cbom_fixture(), cbom_product());
}

/// AC1 / TP1: the hand-written CBOM fixture renders as a CycloneDX 1.6 document that
/// validates against the vendored schema, with `cryptoProperties` on every asset.
#[test]
fn cbom_fixture_validates_against_schema_1_6() {
    let product = load_cbom_fixture();
    for ts in [
        GOLDEN_TIMESTAMP,
        "1970-01-01T00:00:00Z",
        "2099-12-31T23:59:59.5+14:00",
    ] {
        // No serial number given: derived from the model's content.
        let text = cyclonedx::write(&product, &options(ts)).unwrap();
        assert_schema_valid(&format!("CBOM at {ts}"), &text);
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert!(
            doc["serialNumber"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );
        let mut seen: Vec<(String, String)> = crypto_components(&doc)
            .into_iter()
            .map(|c| {
                let crypto = &c["cryptoProperties"];
                assert!(crypto.is_object(), "{} has no cryptoProperties", c["name"]);
                (
                    c["name"].as_str().unwrap().to_owned(),
                    crypto["assetType"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        seen.sort();
        let expected: Vec<(String, String)> = ASSETS
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned()))
            .collect();
        assert_eq!(seen, expected);
    }
}

/// AC1: the committed golden CBOM validates too. Skipped while blessing (the golden may not
/// be written yet); `scripts/regen-golden.sh` runs it in its verify pass.
#[test]
fn committed_cbom_golden_validates_against_schema_1_6() {
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        return;
    }
    let path = golden_dir().join(GOLDEN_JSON);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert_schema_valid(GOLDEN_JSON, &text);
}

/// TP2: the golden JSON, rendered with the fixed timestamp.
#[test]
fn cbom_fixture_matches_golden_json() {
    check_golden(GOLDEN_JSON, &render(&load_cbom_fixture()));
}

/// TP2: every file under tests/golden/cbom/ is checked by a test (the JSON here, the
/// Markdown by rollcall-assay's tests/summary.rs).
#[test]
fn every_committed_cbom_golden_has_a_test() {
    let mut files: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(files, ["sensor-node.cbom.json", "sensor-node.cbom.md"]);
}

/// AC2: every asset renders with its `cryptoProperties`, a `name` identity entry with one
/// method per evidence entry (technique and 0.9/0.6/0.3 confidence), one occurrence per
/// evidence entry with its reason, and the lossless `rollcall:crypto-evidence` properties.
#[test]
fn every_asset_renders_json_with_crypto_properties_identity_and_occurrences() {
    let product = load_cbom_fixture();
    let doc = render_value(&product);
    let mut models: BTreeMap<&str, &Component> = BTreeMap::new();
    for (_, _, c) in product.crypto_assets() {
        models.insert(c.name.as_str(), c);
    }
    assert_eq!(models.len(), 7);
    let crypto = crypto_components(&doc);
    assert_eq!(crypto.len(), 7);
    for c in crypto {
        let name = c["name"].as_str().unwrap();
        let asset = models[name].crypto.as_ref().unwrap();
        assert_eq!(
            c["cryptoProperties"]["assetType"],
            asset.asset_type().as_str()
        );
        assert!(c["cryptoProperties"].get("evidence").is_none());

        let identity = c["evidence"]["identity"].as_array().unwrap();
        let name_entry = identity.iter().find(|i| i["field"] == "name").unwrap();
        assert_eq!(name_entry["concludedValue"], name);
        assert_eq!(
            name_entry["confidence"],
            json!(asset.confidence().as_confidence().as_f64())
        );
        let methods = name_entry["methods"].as_array().unwrap();
        assert_eq!(methods.len(), asset.evidence.len(), "{name}");
        for (method, evidence) in methods.iter().zip(&asset.evidence) {
            assert_eq!(method["value"], evidence.locator.to_string());
            assert_eq!(
                method["technique"],
                serde_json::to_value(evidence.technique()).unwrap()
            );
            let expected = match evidence.confidence {
                ConfidenceLevel::High => 0.9,
                ConfidenceLevel::Medium => 0.6,
                ConfidenceLevel::Low => 0.3,
            };
            assert_eq!(method["confidence"], json!(expected));
        }

        let occurrences = c["evidence"]["occurrences"].as_array().unwrap();
        assert_eq!(occurrences.len(), asset.evidence.len(), "{name}");
        let reasons: BTreeSet<&str> = occurrences
            .iter()
            .map(|o| o["additionalContext"].as_str().unwrap())
            .collect();
        let expected: BTreeSet<&str> = asset.evidence.iter().map(CryptoEvidence::reason).collect();
        assert_eq!(reasons, expected);

        let properties = c["properties"].as_array().unwrap();
        let crypto_properties: Vec<CryptoEvidence> = properties
            .iter()
            .filter(|p| p["name"] == "rollcall:crypto-evidence")
            .map(|p| serde_json::from_str(p["value"].as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(
            crypto_properties.into_iter().collect::<BTreeSet<_>>(),
            asset.evidence
        );
        for evidence in &asset.evidence {
            assert!(
                properties
                    .iter()
                    .any(|p| p["name"] == "rollcall:evidence-source"
                        && p["value"] == evidence.detector()),
                "{name}: no evidence-source {}",
                evidence.detector()
            );
        }
    }
}

/// TP3: no `null` anywhere in the document: absent optional fields are omitted.
#[test]
fn cbom_document_contains_no_null_values() {
    fn walk(value: &Value, at: &str) {
        match value {
            Value::Null => panic!("null at {at}"),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, &format!("{at}[{i}]"));
                }
            }
            Value::Object(map) => {
                for (key, item) in map {
                    walk(item, &format!("{at}.{key}"));
                }
            }
            _ => {}
        }
    }
    let doc = render_value(&load_cbom_fixture());
    walk(&doc, "$");
    // The fixture's omitted optionals stay omitted, and its level 0 stays 0.
    let find = |name: &str| {
        crypto_components(&doc)
            .into_iter()
            .find(|c| c["name"] == name)
            .unwrap()
            .clone()
    };
    let sha = find("SHA-256");
    for absent in ["mode", "executionEnvironment", "implementationPlatform"] {
        assert!(
            sha["cryptoProperties"]["algorithmProperties"]
                .get(absent)
                .is_none()
        );
    }
    assert!(find("RSA-2048")["cryptoProperties"].get("oid").is_none());
    assert_eq!(
        find("RSA-2048")["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"],
        0
    );
    assert!(
        find("device-cert")["cryptoProperties"]["certificateProperties"]
            .get("certificateExtension")
            .is_none()
    );
    assert!(
        find("psk")["cryptoProperties"]["relatedCryptoMaterialProperties"]
            .get("format")
            .is_none()
    );
}

/// AC3: model → JSON → model is lossless, and the bytes are stable.
#[test]
fn cbom_fixture_round_trips_through_model_json() {
    let product = load_cbom_fixture();
    let json = product.to_json().unwrap();
    let back = Product::from_json(&json).unwrap();
    assert_eq!(back, product);
    assert_eq!(back.to_json().unwrap(), json);
    assert_eq!(Product::from_json_bytes(json.as_bytes()).unwrap(), product);
    // The committed fixture file is in the canonical form.
    let text = std::fs::read_to_string(common::cbom_fixture_path()).unwrap();
    assert_eq!(text, json);
}

/// AC3: model → CycloneDX → model is lossless too, with no warnings.
#[test]
fn cbom_fixture_round_trips_through_cyclonedx_reader() {
    let product = load_cbom_fixture();
    let read = cyclonedx::read_str(&render(&product)).unwrap();
    assert_eq!(read.warnings, Vec::new());
    assert_eq!(read.product, product);
    // And writing what was read gives the same bytes.
    assert_eq!(render(&read.product), render(&product));
}

/// A CBOM rollcall did not write: `cryptoProperties` without `rollcall:crypto-evidence`
/// properties. The component is kept as a plain cryptographic-asset, with a warning.
#[test]
fn foreign_cbom_without_crypto_evidence_warns_and_drops_crypto() {
    let mut doc = render_value(&load_cbom_fixture());
    strip_crypto_evidence(&mut doc);
    let read = cyclonedx::read(&doc).unwrap();
    // Per asset: its cryptoProperties, and the CycloneDX evidence derived from them.
    let dropped: Vec<String> = read
        .warnings
        .iter()
        .map(ToString::to_string)
        .filter(|w| w.contains("cryptoProperties without"))
        .collect();
    assert_eq!(dropped.len(), 7, "{:?}", read.warnings);
    assert_eq!(read.warnings.len(), 14, "{:?}", read.warnings);
    let mut assets = 0;
    for (_, _, node) in read.product.walk() {
        if let rollcall_core::model::NodeRef::Component(c) = node
            && c.kind == ComponentKind::CryptographicAsset
        {
            assets += 1;
            assert!(c.crypto.is_none());
        }
    }
    assert_eq!(assets, 7);
}

fn strip_crypto_evidence(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(props)) = map.get_mut("properties") {
                props.retain(|p| p["name"] != "rollcall:crypto-evidence");
            }
            for item in map.values_mut() {
                strip_crypto_evidence(item);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(strip_crypto_evidence),
        _ => {}
    }
}

/// Applies `edit` to the first cryptographic-asset component of the rendered fixture.
fn edited(edit: &dyn Fn(&mut Value)) -> Value {
    let mut doc = render_value(&load_cbom_fixture());
    // The bootloader's chacha20poly1305 → ChaCha20-Poly1305 (images sort bootloader first).
    let asset = &mut doc["components"][0]["components"][0]["components"][0];
    assert_eq!(asset["type"], "cryptographic-asset");
    edit(asset);
    doc
}

fn set_crypto_evidence(asset: &mut Value, value: &str) {
    for p in asset["properties"].as_array_mut().unwrap() {
        if p["name"] == "rollcall:crypto-evidence" {
            p["value"] = json!(value);
        }
    }
}

/// Parser robustness: malformed `cryptoProperties` and `rollcall:crypto-evidence` properties
/// are errors, never panics.
#[test]
fn malformed_crypto_properties_in_cyclonedx_error_never_panic() {
    let cases: Vec<(&str, Value)> = vec![
        (
            "unknown assetType",
            edited(&|a| a["cryptoProperties"]["assetType"] = json!("key")),
        ),
        (
            "assetType/block mismatch",
            edited(&|a| a["cryptoProperties"]["assetType"] = json!("protocol")),
        ),
        (
            "block missing",
            edited(&|a| {
                a["cryptoProperties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("algorithmProperties");
            }),
        ),
        (
            "two blocks",
            edited(&|a| a["cryptoProperties"]["protocolProperties"] = json!({})),
        ),
        (
            "not an object",
            edited(&|a| a["cryptoProperties"] = json!("algorithm")),
        ),
        ("array", edited(&|a| a["cryptoProperties"] = json!([1, 2]))),
        (
            "unmodelled field",
            edited(&|a| a["cryptoProperties"]["algorithmProperties"]["padding"] = json!("oaep")),
        ),
        (
            "level out of range",
            edited(&|a| {
                a["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] = json!(9);
            }),
        ),
        (
            "wrong type",
            edited(&|a| {
                a["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] =
                    json!("256");
            }),
        ),
        (
            "evidence inside cryptoProperties",
            edited(&|a| a["cryptoProperties"]["evidence"] = json!([])),
        ),
        (
            "crypto-evidence not JSON",
            edited(&|a| set_crypto_evidence(a, "{not json")),
        ),
        (
            "crypto-evidence truncated",
            edited(&|a| set_crypto_evidence(a, r#"{"locator":{"kind":"cargo-feature""#)),
        ),
        (
            "crypto-evidence empty",
            edited(&|a| set_crypto_evidence(a, "")),
        ),
        (
            "crypto-evidence wrong shape",
            edited(&|a| set_crypto_evidence(a, r#"{"confidence":0.9}"#)),
        ),
        (
            "crypto-evidence reason with newline",
            edited(&|a| {
                set_crypto_evidence(
                    a,
                    r#"{"locator":{"kind":"cargo-feature","location":"Cargo.toml","package":"p","feature":"f"},"detector":"d","confidence":"high","reason":"a\nb"}"#,
                );
            }),
        ),
        (
            "crypto on a library",
            edited(&|a| a["type"] = json!("library")),
        ),
    ];
    for (name, doc) in cases {
        let result = cyclonedx::read(&doc);
        assert!(result.is_err(), "{name}: accepted");
        if name != "crypto on a library" {
            assert!(
                matches!(result, Err(ReadError::Crypto { .. })),
                "{name}: {result:?}"
            );
        }
    }
    // Truncated and non-UTF-8 documents.
    let text = render(&load_cbom_fixture());
    for cut in [0, text.len() / 3, text.len() / 2, text.len() - 2] {
        assert!(cyclonedx::read_str(&text[..cut]).is_err());
    }
    let mut bytes = text.into_bytes();
    if let Some(at) = bytes.windows(4).position(|w| w == b"TLS\"") {
        bytes[at] = 0xff;
    }
    assert!(cyclonedx::read_bytes(&bytes).is_err());
}

/// A crypto evidence property without `cryptoProperties`, and crypto on an image, are
/// dropped with warnings.
#[test]
fn stray_crypto_evidence_and_crypto_on_images_are_dropped_with_warnings() {
    let doc = edited(&|a| {
        a.as_object_mut().unwrap().remove("cryptoProperties");
        a["type"] = json!("library");
    });
    let read = cyclonedx::read(&doc).unwrap();
    assert!(
        read.warnings
            .iter()
            .any(|w| w.to_string().contains("without cryptoProperties")),
        "{:?}",
        read.warnings
    );
    // A malformed stray property is dropped with the same warning, never parsed.
    for bad in ["{not json", "", r#"{"confidence":0.9}"#] {
        let doc = edited(&|a| {
            a.as_object_mut().unwrap().remove("cryptoProperties");
            a["type"] = json!("library");
            set_crypto_evidence(a, bad);
        });
        let read = cyclonedx::read(&doc)
            .unwrap_or_else(|e| panic!("stray malformed property {bad:?}: {e}"));
        assert!(
            read.warnings
                .iter()
                .any(|w| w.to_string().contains("without cryptoProperties")),
            "{bad:?}: {:?}",
            read.warnings
        );
    }
    let mut doc = render_value(&load_cbom_fixture());
    doc["components"][0]["cryptoProperties"] = json!({"assetType": "protocol"});
    let read = cyclonedx::read(&doc).unwrap();
    assert!(
        read.warnings
            .iter()
            .any(|w| w.to_string().contains("on a product or image")),
        "{:?}",
        read.warnings
    );
}

// --- Property tests -------------------------------------------------------------------------

fn arb_text() -> impl Strategy<Value = String> {
    select(vec![
        "128",
        "256",
        "P-256",
        "1.3",
        "CN=x, O=Ünïcode",
        "a|b*c_d",
    ])
    .prop_map(str::to_owned)
}

fn arb_name() -> impl Strategy<Value = String> {
    select(vec!["CONFIG_A", "mbedtls_gcm_setkey", "x"]).prop_map(str::to_owned)
}

fn arb_locator() -> impl Strategy<Value = Locator> {
    let location = select(vec![
        "src/a.c",
        "build/zephyr/.config",
        "zephyr.elf",
        "Cargo.toml",
    ])
    .prop_map(str::to_owned);
    prop_oneof![
        (location.clone(), 1u32..5000)
            .prop_map(|(location, line)| Locator::SourceLine { location, line }),
        (location.clone(), arb_name())
            .prop_map(|(location, symbol)| Locator::ElfSymbol { location, symbol }),
        (
            location.clone(),
            proptest::option::of(1u32..5000),
            arb_name()
        )
            .prop_map(|(location, line, symbol)| Locator::KconfigSymbol {
                location,
                line,
                symbol
            }),
        (location, arb_name(), arb_name()).prop_map(|(location, package, feature)| {
            Locator::CargoFeature {
                location,
                package,
                feature,
            }
        }),
    ]
}

fn arb_crypto_evidence() -> impl Strategy<Value = CryptoEvidence> {
    (
        arb_locator(),
        select(vec!["kconfig", "elf-symbols", "source-scan"]),
        select(ConfidenceLevel::ALL.to_vec()),
        select(vec!["enabled", "linked into the image", "Ünïcode | reason"]),
    )
        .prop_map(|(locator, detector, level, reason)| {
            CryptoEvidence::new(locator, detector, level, reason).unwrap()
        })
}

fn arb_algorithm() -> impl Strategy<Value = CryptoAssetProperties> {
    (
        proptest::option::of(select(Primitive::ALL.to_vec())),
        proptest::option::of(arb_text()),
        proptest::option::of(select(ExecutionEnvironment::ALL.to_vec())),
        proptest::option::of(select(ImplementationPlatform::ALL.to_vec())),
        proptest::option::of(select(Mode::ALL.to_vec())),
        proptest::sample::subsequence(CryptoFunction::ALL.to_vec(), 0..=4),
        proptest::option::of(0u32..1024),
        proptest::option::of(0u8..=QuantumSecurityLevel::MAX),
    )
        .prop_map(
            |(primitive, set, environment, platform, mode, functions, classical, nist)| {
                CryptoAssetProperties::Algorithm(AlgorithmProperties {
                    primitive,
                    parameter_set_identifier: set,
                    execution_environment: environment,
                    implementation_platform: platform,
                    mode,
                    crypto_functions: functions.into_iter().collect(),
                    classical_security_level: classical,
                    nist_quantum_security_level: nist
                        .map(|n| QuantumSecurityLevel::new(n).unwrap()),
                })
            },
        )
}

fn arb_properties() -> impl Strategy<Value = CryptoAssetProperties> {
    let date =
        select(vec!["2026-01-01T00:00:00Z", "2030-06-30T12:00:00+02:00"]).prop_map(str::to_owned);
    prop_oneof![
        arb_algorithm(),
        (
            proptest::option::of(select(ProtocolType::ALL.to_vec())),
            proptest::option::of(arb_text())
        )
            .prop_map(|(protocol_type, version)| CryptoAssetProperties::Protocol(
                ProtocolProperties {
                    protocol_type,
                    version
                }
            )),
        (
            proptest::option::of(arb_text()),
            proptest::option::of(arb_text()),
            proptest::option::of(date.clone()),
            proptest::option::of(date),
            proptest::option::of(arb_text()),
            proptest::option::of(arb_text()),
        )
            .prop_map(|(subject, issuer, before, after, format, extension)| {
                CryptoAssetProperties::Certificate(CertificateProperties {
                    subject_name: subject,
                    issuer_name: issuer,
                    not_valid_before: before,
                    not_valid_after: after,
                    certificate_format: format,
                    certificate_extension: extension,
                })
            }),
        (
            proptest::option::of(select(MaterialType::ALL.to_vec())),
            proptest::option::of(arb_text()),
            proptest::option::of(select(MaterialState::ALL.to_vec())),
            proptest::option::of(any::<u64>()),
            proptest::option::of(arb_text()),
        )
            .prop_map(|(material_type, id, state, size, format)| {
                CryptoAssetProperties::RelatedCryptoMaterial(RelatedCryptoMaterialProperties {
                    material_type,
                    id,
                    state,
                    size,
                    format,
                })
            }),
    ]
}

/// Any valid crypto asset: every asset type, every locator kind, optional fields present or
/// not, one to three evidence entries.
fn arb_crypto_asset() -> impl Strategy<Value = CryptoAsset> {
    (
        arb_properties(),
        proptest::option::of(select(vec![
            "1.2.840.113549.1.1.1",
            "2.16.840.1.101.3.4.1.6",
        ])),
        proptest::collection::vec(arb_crypto_evidence(), 1..=3),
    )
        .prop_map(|(properties, oid, evidence)| {
            let asset = CryptoAsset::new(properties, evidence).unwrap();
            match oid {
                Some(oid) => asset.with_oid(oid).unwrap(),
                None => asset,
            }
        })
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// AC3: any crypto asset survives model → JSON → model and model → CycloneDX → model,
    /// and its document validates.
    #[test]
    fn arbitrary_crypto_assets_round_trip(asset in arb_crypto_asset()) {
        let back: CryptoAsset =
            serde_json::from_str(&serde_json::to_string(&asset).unwrap()).unwrap();
        prop_assert_eq!(&back, &asset);

        let mut product = Product::new("prop").unwrap();
        let mut image = Image::new(ImageKind::Application, "app").unwrap();
        image
            .add_component(
                Component::new(ComponentKind::CryptographicAsset, "asset")
                    .unwrap()
                    .with_crypto(asset),
            )
            .unwrap();
        product.add_image(image).unwrap();
        let json = product.to_json().unwrap();
        prop_assert_eq!(&Product::from_json(&json).unwrap(), &product);

        let text = render(&product);
        let doc: Value = serde_json::from_str(&text).unwrap();
        prop_assert!(validate_cyclonedx_1_6(&doc).is_ok(), "{}", text);
        let read = cyclonedx::read_str(&text).unwrap();
        prop_assert_eq!(read.warnings, Vec::new());
        prop_assert_eq!(read.product, product);
    }
}
