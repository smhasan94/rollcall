//! SHA-139: the algorithm catalogue (`db/algorithms.yaml`), its JSON Schema, the loader and
//! lint, the lookup API and `docs/catalogue.md`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use jsonschema::{Draft, Validator};
use proptest::prelude::*;
use rollcall_assay::catalogue::{
    ALGORITHMS_SCHEMA_JSON, ALGORITHMS_YAML, Catalogue, CatalogueError, FILE_NAME, LookupError,
    Padding, QuantumRisk, Rule, lint_text,
};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::model::{
    self, AlgorithmProperties, Component, ComponentKind, ConfidenceLevel, CryptoAsset,
    CryptoAssetProperties, CryptoEvidence, CryptoFunction, Image, ImageKind, Locator, Mode,
    Primitive, Product, QuantumSecurityLevel,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn builtin() -> Catalogue {
    Catalogue::builtin().unwrap_or_else(|e| panic!("{e}"))
}

/// The catalogue text as a JSON value (YAML parsed into serde_json).
fn as_json(text: &str) -> Value {
    yaml_serde::from_str(text).unwrap()
}

fn schema() -> Value {
    serde_json::from_str(ALGORITHMS_SCHEMA_JSON).unwrap()
}

fn validator() -> Validator {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .offline()
        .build(&schema())
        .unwrap()
}

/// The schema's violations of `instance`, as text.
fn schema_errors(instance: &Value) -> Vec<String> {
    validator()
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect()
}

/// Loads a JSON value as a catalogue (JSON is YAML).
fn load_value(value: &Value) -> Result<Catalogue, CatalogueError> {
    Catalogue::load_str("value.yaml", &serde_json::to_string_pretty(value).unwrap())
}

fn level(n: u8) -> QuantumSecurityLevel {
    QuantumSecurityLevel::new(n).unwrap()
}

/// AC1: the built-in catalogue, parsed as JSON, validates against `db/algorithms.schema.json`,
/// and the schema's word lists are exactly rollcall-core's CycloneDX words and the
/// catalogue's own.
#[test]
fn builtin_validates_against_its_json_schema() {
    let errors = schema_errors(&as_json(ALGORITHMS_YAML));
    assert!(errors.is_empty(), "{errors:#?}");

    let schema = schema();
    let words = |pointer: &str| -> Vec<String> {
        schema
            .pointer(pointer)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no enum at {pointer}"))
            .iter()
            .filter_map(|w| w.as_str().map(str::to_owned))
            .collect()
    };
    let ours = |all: Vec<&str>| all.into_iter().map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(
        words("/$defs/algorithm/properties/primitive/enum"),
        ours(Primitive::ALL.iter().map(|p| p.as_str()).collect())
    );
    assert_eq!(
        words("/$defs/algorithm/properties/mode/enum"),
        ours(Mode::ALL.iter().map(|m| m.as_str()).collect())
    );
    assert_eq!(
        words("/$defs/algorithm/properties/crypto_functions/items/enum"),
        ours(CryptoFunction::ALL.iter().map(|f| f.as_str()).collect())
    );
    assert_eq!(
        words("/$defs/algorithm/properties/quantum_risk/enum"),
        ours(QuantumRisk::ALL.iter().map(|r| r.as_str()).collect())
    );
    assert_eq!(
        words("/$defs/algorithm/properties/padding/enum"),
        ours(Padding::ALL.iter().map(|p| p.as_str()).collect())
    );
    assert_eq!(
        schema
            .pointer("/properties/format/const")
            .and_then(Value::as_str),
        Some(rollcall_assay::catalogue::FORMAT)
    );
}

/// AC1: the built-in catalogue loads, the lint has nothing to say, and every entry has every
/// required field filled in (and its line known).
#[test]
fn builtin_loads_with_no_lint_findings() {
    assert_eq!(lint_text(FILE_NAME, ALGORITHMS_YAML), Vec::new());
    let catalogue = builtin();
    assert!(!catalogue.algorithms().is_empty());
    for algorithm in catalogue.algorithms() {
        assert!(algorithm.line.is_some(), "{}: line unknown", algorithm.name);
        assert!(!algorithm.family.trim().is_empty(), "{}", algorithm.name);
        assert!(!algorithm.standards.is_empty(), "{}", algorithm.name);
        assert!(!algorithm.parameter_sets.is_empty(), "{}", algorithm.name);
        for set in &algorithm.parameter_sets {
            assert!(!set.id.is_empty(), "{}", algorithm.name);
            assert!(
                !set.source.trim().is_empty(),
                "{}/{}",
                algorithm.name,
                set.id
            );
            assert!(
                set.classical_security_level > 0,
                "{}/{}",
                algorithm.name,
                set.id
            );
        }
    }
}

/// The schema's `required` list at `pointer`, sorted.
fn required(schema: &Value, pointer: &str) -> BTreeSet<String> {
    schema
        .pointer(&format!("{pointer}/required"))
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// The schema's `properties` at `pointer`.
fn properties(schema: &Value, pointer: &str) -> Vec<String> {
    schema
        .pointer(&format!("{pointer}/properties"))
        .and_then(Value::as_object)
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

/// AC1: the JSON Schema and the loader agree on which fields are required. For every property
/// the schema lists, at the top level, in an entry and in a parameter set, removing it from a
/// catalogue fails the schema exactly when it fails the loader, and the fields whose removal
/// fails are exactly the schema's `required` list. An unknown key fails both.
#[test]
fn schema_and_loader_require_the_same_fields() {
    let schema = schema();
    let doc = as_json(ALGORITHMS_YAML);
    assert!(load_value(&doc).is_ok(), "the JSON form loads");

    // Where each level's objects are in the document: the top level, every entry, every set.
    type Paths = Vec<Vec<String>>;
    let entries: Paths = (0..doc["algorithms"].as_array().unwrap().len())
        .map(|i| vec!["algorithms".to_owned(), i.to_string()])
        .collect();
    let sets: Paths = entries
        .iter()
        .flat_map(|entry| {
            let n = doc["algorithms"][entry[1].parse::<usize>().unwrap()]["parameter_sets"]
                .as_array()
                .unwrap()
                .len();
            (0..n).map(move |j| {
                let mut path = entry.clone();
                path.extend(["parameter_sets".to_owned(), j.to_string()]);
                path
            })
        })
        .collect();
    fn object_mut<'a>(
        doc: &'a mut Value,
        path: &[String],
    ) -> &'a mut serde_json::Map<String, Value> {
        let mut node = doc;
        for step in path {
            node = match step.parse::<usize>() {
                Ok(i) => &mut node[i],
                Err(_) => &mut node[step.as_str()],
            };
        }
        node.as_object_mut().unwrap()
    }

    for (pointer, candidates) in [
        ("", vec![Vec::new()]),
        ("/$defs/algorithm", entries.clone()),
        ("/$defs/parameter_set", sets.clone()),
    ] {
        let mut failing = BTreeSet::new();
        for field in properties(&schema, pointer) {
            // The first object at this level that has the field.
            let Some(path) = candidates
                .iter()
                .find(|p| object_mut(&mut doc.clone(), p).contains_key(&field))
            else {
                panic!("no object at {pointer:?} has {field}: the catalogue never uses it");
            };
            let mut edited = doc.clone();
            object_mut(&mut edited, path).remove(&field);
            let schema_fails = !schema_errors(&edited).is_empty();
            let loader = load_value(&edited);
            assert_eq!(
                schema_fails,
                loader.is_err(),
                "removing {field} at {path:?}: schema fails = {schema_fails}, loader = {loader:?}"
            );
            if schema_fails {
                failing.insert(field.clone());
            }
        }
        assert_eq!(
            failing,
            required(&schema, pointer),
            "fields whose removal fails, at {pointer:?}"
        );

        // An unknown key fails both.
        let mut edited = doc.clone();
        object_mut(&mut edited, &candidates[0]).insert("x_unknown".to_owned(), Value::Bool(true));
        assert!(
            !schema_errors(&edited).is_empty(),
            "schema accepts x_unknown at {pointer:?}"
        );
        let err = load_value(&edited).unwrap_err();
        assert!(
            err.to_string().contains("unknown field `x_unknown`"),
            "{pointer:?}: {err}"
        );
    }
}

/// The 1-based line of the first line of `text` starting with `prefix`.
fn line_of(text: &str, prefix: &str) -> u32 {
    let index = text.lines().position(|l| l.starts_with(prefix)).unwrap();
    u32::try_from(index + 1).unwrap()
}

/// TP1: deleting one entry's `quantum_risk` line fails the lint (one `schema` finding naming the
/// field and the entry's line), the loader and the JSON Schema.
#[test]
fn missing_quantum_risk_fails_the_lint_and_the_schema() {
    let entry_line = line_of(ALGORITHMS_YAML, "  - name: AES-CBC");
    let text = ALGORITHMS_YAML.replacen("    quantum_risk: grover-weakened\n", "", 1);
    assert_eq!(
        text.len() + "    quantum_risk: grover-weakened\n".len(),
        ALGORITHMS_YAML.len()
    );

    let findings = lint_text("algorithms.yaml", &text);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let finding = &findings[0];
    assert_eq!(finding.rule, Rule::Schema);
    assert!(
        finding.message.contains("missing field `quantum_risk`"),
        "{finding}"
    );
    assert_eq!(finding.line, Some(entry_line), "{finding}");
    assert!(
        finding
            .to_string()
            .starts_with(&format!("algorithms.yaml:{entry_line}: ")),
        "{finding}"
    );

    match Catalogue::load_str("algorithms.yaml", &text) {
        Err(CatalogueError::Yaml { line, message, .. }) => {
            assert_eq!(line, Some(entry_line));
            assert!(
                message.contains("missing field `quantum_risk`"),
                "{message}"
            );
        }
        other => panic!("expected a YAML error, got {other:?}"),
    }

    let errors = schema_errors(&as_json(&text));
    assert!(
        errors.iter().any(|e| e.contains("quantum_risk")),
        "{errors:#?}"
    );
}

/// AC2: looking up AES-GCM/128 gives exactly the `algorithmProperties` and `oid` E1.1 (SHA-138)
/// writes, and an asset carrying them is valid CycloneDX 1.6 in a CBOM.
#[test]
fn lookup_returns_e1_1_algorithm_properties_that_validate_in_a_cbom() {
    let catalogue = builtin();
    let entry = catalogue.lookup("AES-GCM", "128").unwrap();
    let properties = entry.algorithm_properties();
    assert_eq!(
        properties,
        AlgorithmProperties {
            primitive: Some(Primitive::Ae),
            parameter_set_identifier: Some("128".to_owned()),
            curve: None,
            execution_environment: None,
            implementation_platform: None,
            mode: Some(Mode::Gcm),
            padding: None,
            crypto_functions: [
                CryptoFunction::Encrypt,
                CryptoFunction::Decrypt,
                CryptoFunction::Tag
            ]
            .into_iter()
            .collect(),
            classical_security_level: Some(128),
            nist_quantum_security_level: Some(level(1)),
        }
    );
    assert_eq!(entry.oid(), Some("2.16.840.1.101.3.4.1.6"));
    assert_eq!(entry.quantum_risk(), QuantumRisk::GroverWeakened);
    assert_eq!(entry.curve(), None);
    assert_eq!(entry.padding(), None);
    // The name is matched ignoring ASCII case.
    assert_eq!(catalogue.lookup("aes-gcm", "128").unwrap(), entry);

    let evidence = CryptoEvidence::new(
        Locator::KconfigSymbol {
            location: "build/zephyr/.config".to_owned(),
            line: Some(812),
            symbol: "CONFIG_MBEDTLS_CIPHER_MODE_GCM".to_owned(),
        },
        "kconfig",
        ConfidenceLevel::High,
        "CONFIG_MBEDTLS_CIPHER_MODE_GCM=y builds GCM into mbedtls",
    )
    .unwrap();
    let mut asset =
        CryptoAsset::new(CryptoAssetProperties::Algorithm(properties), [evidence]).unwrap();
    if let Some(oid) = entry.oid() {
        asset = asset.with_oid(oid).unwrap();
    }
    let mut product = Product::new("sensor-node").unwrap().with_version("1.0.0");
    let mut image = Image::new(ImageKind::Application, "sensor-app").unwrap();
    image
        .add_component(
            Component::new(ComponentKind::CryptographicAsset, "AES-128-GCM")
                .unwrap()
                .with_crypto(asset),
        )
        .unwrap();
    product.add_image(image).unwrap();
    let text = cyclonedx::write(
        &product,
        &WriteOptions::new(Timestamp::parse("2026-01-02T03:04:05Z").unwrap()),
    )
    .unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    if let Err(violations) = validate_cyclonedx_1_6(&document) {
        panic!("not valid CycloneDX 1.6: {violations:#?}\n{text}");
    }
    let written = text.contains("\"algorithmProperties\"")
        && text.contains("\"parameterSetIdentifier\": \"128\"")
        && text.contains("\"nistQuantumSecurityLevel\": 1")
        && text.contains("\"classicalSecurityLevel\": 128")
        && text.contains("\"oid\": \"2.16.840.1.101.3.4.1.6\"");
    assert!(written, "{text}");
}

/// TP2: lookups of thirteen entries, classical, symmetric, hash and post-quantum, each checked
/// against its primitive, classical level, NIST category and risk class.
#[test]
fn lookup_table_of_thirteen_entries_including_pq() {
    use Primitive::*;
    use QuantumRisk::*;
    let catalogue = builtin();
    let table: &[(&str, &str, Primitive, u32, u8, QuantumRisk)] = &[
        ("AES-GCM", "128", Ae, 128, 1, GroverWeakened),
        ("AES-CBC", "256", BlockCipher, 256, 5, GroverWeakened),
        ("RSA-PSS", "3072", Signature, 128, 0, ShorBroken),
        ("ECDSA", "secp256r1", Signature, 128, 0, ShorBroken),
        ("Ed25519", "Ed25519", Signature, 128, 0, ShorBroken),
        ("X25519", "X25519", KeyAgree, 128, 0, ShorBroken),
        ("SHA2", "256", Hash, 128, 2, GroverWeakened),
        ("SHA3", "256", Hash, 128, 2, GroverWeakened),
        ("HMAC", "SHA-256", Mac, 256, 2, GroverWeakened),
        ("ChaCha20-Poly1305", "256", Ae, 256, 5, GroverWeakened),
        ("ML-KEM", "768", Kem, 192, 3, PqSafe),
        ("ML-DSA", "65", Signature, 192, 3, PqSafe),
        ("SLH-DSA", "SHA2-128s", Signature, 128, 1, PqSafe),
    ];
    assert!(table.len() >= 10);
    for &(name, id, primitive, classical, nist, risk) in table {
        let entry = catalogue
            .lookup(name, id)
            .unwrap_or_else(|e| panic!("{name}/{id}: {e}"));
        let properties = entry.algorithm_properties();
        assert_eq!(properties.primitive, Some(primitive), "{name}/{id}");
        assert_eq!(
            properties.parameter_set_identifier.as_deref(),
            Some(id),
            "{name}/{id}"
        );
        assert_eq!(
            properties.classical_security_level,
            Some(classical),
            "{name}/{id}"
        );
        assert_eq!(
            properties.nist_quantum_security_level,
            Some(level(nist)),
            "{name}/{id}"
        );
        assert_eq!(entry.quantum_risk(), risk, "{name}/{id}");
        assert_eq!(entry.algorithm.name, name);
        assert_eq!(entry.parameter_set.id, id);
    }
    // The rest of each PQ family's categories, from FIPS 203, 204 and 205.
    for (name, id, nist) in [
        ("ML-KEM", "512", 1),
        ("ML-KEM", "1024", 5),
        ("ML-DSA", "44", 2),
        ("ML-DSA", "87", 5),
        ("SLH-DSA", "SHAKE-128f", 1),
        ("SLH-DSA", "SHA2-192s", 3),
        ("SLH-DSA", "SHAKE-256f", 5),
    ] {
        let entry = catalogue.lookup(name, id).unwrap();
        assert_eq!(
            entry.parameter_set.nist_quantum_security_level,
            level(nist),
            "{name}/{id}"
        );
    }
}

/// TP2: an unknown algorithm or parameter set is an error naming what is known, never a
/// default.
#[test]
fn unknown_algorithm_or_parameter_set_is_an_error_not_a_default() {
    let catalogue = builtin();
    assert_eq!(
        catalogue.lookup("RC4", "128").unwrap_err(),
        LookupError::UnknownAlgorithm {
            name: "RC4".to_owned()
        }
    );
    let err = catalogue.lookup("AES-GCM", "512").unwrap_err();
    assert_eq!(
        err,
        LookupError::UnknownParameterSet {
            algorithm: "AES-GCM".to_owned(),
            parameter_set: "512".to_owned(),
            known: vec!["128".to_owned(), "192".to_owned(), "256".to_owned()],
        }
    );
    assert_eq!(
        err.to_string(),
        "unknown parameter set \"512\" for AES-GCM; known: 128, 192, 256"
    );
    // Ids are matched exactly; empty strings are unknown too.
    assert!(matches!(
        catalogue.lookup("ML-KEM", "ML-KEM-768"),
        Err(LookupError::UnknownParameterSet { .. })
    ));
    assert!(matches!(
        catalogue.lookup("SLH-DSA", "sha2-128s"),
        Err(LookupError::UnknownParameterSet { .. })
    ));
    assert!(matches!(
        catalogue.lookup("", ""),
        Err(LookupError::UnknownAlgorithm { .. })
    ));
    assert!(catalogue.algorithm("RC4").is_none());
}

/// Parsers never panic: each malformed catalogue is an error, from the loader and as one
/// `schema` finding from the lint.
#[test]
fn malformed_catalogues_error_never_panic() {
    let entry = "format: rollcall-algorithms/1\nalgorithms:\n  - name: AES-GCM\n    family: AES\n    \
                 primitive: ae\n    quantum_risk: grover-weakened\n    standards: [FIPS 197]\n    \
                 parameter_sets:\n      - id: \"128\"\n        classical_security_level: 128\n        \
                 nist_quantum_security_level: 1\n        source: \"x\"\n";
    assert!(Catalogue::load_str("ok.yaml", entry).is_ok());
    let truncated = &ALGORITHMS_YAML[..ALGORITHMS_YAML.find("    standards:").unwrap()];
    let cases: Vec<(&str, String, &str)> = vec![
        ("empty", String::new(), "empty"),
        ("whitespace", " \n\t\n".to_owned(), "empty"),
        ("comment only", "# nothing\n".to_owned(), "empty"),
        ("truncated mid-entry", truncated.to_owned(), "missing field"),
        (
            "top-level sequence",
            "- a\n- b\n".to_owned(),
            "invalid type",
        ),
        (
            "algorithms a map",
            "format: rollcall-algorithms/1\nalgorithms:\n  AES: 1\n".to_owned(),
            "invalid type",
        ),
        (
            "number for id",
            entry.replace("id: \"128\"", "id: 128"),
            "invalid type",
        ),
        (
            "boolean for a standard",
            entry.replace("[FIPS 197]", "[yes, true]"),
            "invalid type: boolean",
        ),
        (
            "number for an oid",
            entry.replace(
                "    source: \"x\"\n",
                "    oid: 1.5\n        source: \"x\"\n",
            ),
            "invalid type: floating point",
        ),
        (
            "NIST level 7",
            entry.replace(
                "nist_quantum_security_level: 1",
                "nist_quantum_security_level: 7",
            ),
            "above 6",
        ),
        (
            "negative classical level",
            entry.replace(
                "classical_security_level: 128",
                "classical_security_level: -1",
            ),
            "expected u32",
        ),
        (
            "unknown primitive word",
            entry.replace("primitive: ae", "primitive: aead"),
            "unknown variant `aead`",
        ),
        (
            "unknown risk class",
            entry.replace("grover-weakened", "quantum-safe"),
            "unknown variant `quantum-safe`",
        ),
        (
            "unknown key",
            entry.replace("    family: AES\n", "    family: AES\n    vendor: x\n"),
            "unknown field `vendor`",
        ),
        ("bad YAML", "format: [\n".to_owned(), ""),
        (
            "tab indentation",
            "format: rollcall-algorithms/1\nalgorithms:\n\t- name: x\n".to_owned(),
            "",
        ),
    ];
    for (what, text, needle) in &cases {
        let err = Catalogue::load_str("bad.yaml", text)
            .err()
            .unwrap_or_else(|| panic!("{what}: loaded"));
        assert!(
            err.to_string().contains(needle),
            "{what}: {err} lacks {needle:?}"
        );
        assert!(err.to_string().starts_with("bad.yaml"), "{what}: {err}");
        let findings = lint_text("bad.yaml", text);
        assert_eq!(findings.len(), 1, "{what}: {findings:#?}");
        assert_eq!(findings[0].rule, Rule::Schema, "{what}");
    }
    // A wrong format is its own error from the loader and a `format` finding from the lint.
    let wrong = entry.replace("rollcall-algorithms/1", "rollcall-algorithms/2");
    assert!(matches!(
        Catalogue::load_str("bad.yaml", &wrong),
        Err(CatalogueError::UnsupportedFormat { .. })
    ));
    assert_eq!(
        lint_text("bad.yaml", &wrong)
            .iter()
            .map(|f| f.rule)
            .collect::<Vec<_>>(),
        vec![Rule::Format]
    );

    // From disk: missing, not UTF-8, a directory.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.yaml");
    assert!(matches!(
        Catalogue::load_path(&missing),
        Err(CatalogueError::Read { .. })
    ));
    let latin1 = dir.path().join("latin1.yaml");
    std::fs::write(&latin1, b"format: rollcall-algorithms/1\n# caf\xe9\n").unwrap();
    let err = Catalogue::load_path(&latin1).unwrap_err();
    assert!(matches!(err, CatalogueError::NotUtf8 { .. }), "{err}");
    assert!(err.to_string().contains("latin1.yaml"), "{err}");
    assert!(Catalogue::load_path(dir.path()).is_err());
    let good = dir.path().join("algorithms.yaml");
    std::fs::write(&good, ALGORITHMS_YAML).unwrap();
    assert_eq!(Catalogue::load_path(&good).unwrap(), builtin());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Parsers never panic: arbitrary text, and the built-in catalogue cut anywhere, either
    /// loads or errors, and the lint returns findings without panicking.
    #[test]
    fn arbitrary_text_never_panics(text in "\\PC*", cut in 0usize..ALGORITHMS_YAML.len()) {
        let _ = Catalogue::load_str("arbitrary.yaml", &text);
        let _ = lint_text("arbitrary.yaml", &text);
        if let Some(prefix) = ALGORITHMS_YAML.get(..cut) {
            let loaded = Catalogue::load_str("cut.yaml", prefix);
            let findings = lint_text("cut.yaml", prefix);
            // The loader and the lint agree on whether the text is clean.
            prop_assert_eq!(loaded.is_ok(), findings.is_empty());
        }
    }
}

/// Determinism: loading twice gives the same catalogue, its entries are in name order (ASCII,
/// ignoring case), and lookups return the same entry.
#[test]
fn loading_twice_is_identical_and_algorithms_are_in_name_order() {
    let a = builtin();
    let b = builtin();
    assert_eq!(a, b);
    let names: Vec<String> = a
        .algorithms()
        .iter()
        .map(|x| x.name.to_ascii_lowercase())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(names, sorted);
    assert_eq!(
        a.lookup("ML-KEM", "768").unwrap(),
        b.lookup("ML-KEM", "768").unwrap()
    );
    assert_eq!(
        lint_text(FILE_NAME, ALGORITHMS_YAML),
        lint_text(FILE_NAME, ALGORITHMS_YAML)
    );
}

/// Scope: every algorithm the ticket names is in the catalogue, AES in 128/192/256 and in
/// ECB/CBC/CTR/GCM/CCM, and SP 800-208's hash-based families with every approved set.
#[test]
fn catalogue_covers_every_algorithm_the_ticket_names() {
    let catalogue = builtin();
    let has = |name: &str| {
        catalogue
            .algorithm(name)
            .unwrap_or_else(|| panic!("{name} is missing"))
    };
    let families: BTreeSet<&str> = catalogue
        .algorithms()
        .iter()
        .map(|a| a.family.as_str())
        .collect();
    for family in ["RSA", "DSA", "DH"] {
        assert!(families.contains(family), "family {family} is missing");
    }
    for name in [
        "RSA-PSS",
        "RSA-OAEP",
        "RSA-PKCS1v15",
        "DSA",
        "DH",
        "ECDSA",
        "ECDH",
        "Ed25519",
        "X25519",
        "ChaCha20-Poly1305",
        "SHA2",
        "SHA3",
        "SHAKE",
        "HMAC",
        "HKDF",
        "PBKDF2",
        "ML-KEM",
        "ML-DSA",
        "SLH-DSA",
        "LMS",
        "HSS",
        "XMSS",
        "XMSS-MT",
    ] {
        has(name);
    }
    for (mode, word) in [
        ("ECB", Mode::Ecb),
        ("CBC", Mode::Cbc),
        ("CTR", Mode::Ctr),
        ("GCM", Mode::Gcm),
        ("CCM", Mode::Ccm),
    ] {
        let aes = has(&format!("AES-{mode}"));
        assert_eq!(aes.family, "AES");
        assert_eq!(aes.mode, Some(word));
        for size in ["128", "192", "256"] {
            assert!(aes.parameter_set(size).is_some(), "AES-{mode}/{size}");
        }
    }
    for (name, sets) in [
        (
            "SHA2",
            &["224", "256", "384", "512", "512/224", "512/256"][..],
        ),
        ("SHA3", &["224", "256", "384", "512"][..]),
        ("SHAKE", &["128", "256"][..]),
        ("ML-KEM", &["512", "768", "1024"][..]),
        ("ML-DSA", &["44", "65", "87"][..]),
    ] {
        let ids: Vec<&str> = has(name)
            .parameter_sets
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, sets, "{name}");
    }
    // FIPS 205 Table 2: twelve SLH-DSA sets. SP 800-208: 20 LMS sets (SHA-256 and SHAKE256,
    // n = 32 and 24, heights 5 to 25), the same for HSS, 12 XMSS and 32 XMSS^MT sets.
    for (name, count) in [
        ("SLH-DSA", 12),
        ("LMS", 20),
        ("HSS", 20),
        ("XMSS", 12),
        ("XMSS-MT", 32),
    ] {
        assert_eq!(has(name).parameter_sets.len(), count, "{name}");
    }
    // Classical algorithms are shor-broken at NIST level 0; post-quantum ones pq-safe.
    for name in ["RSA-PSS", "DSA", "DH", "ECDSA", "ECDH", "Ed25519", "X25519"] {
        assert_eq!(has(name).quantum_risk, QuantumRisk::ShorBroken, "{name}");
    }
    for name in [
        "ML-KEM", "ML-DSA", "SLH-DSA", "LMS", "HSS", "XMSS", "XMSS-MT",
    ] {
        assert_eq!(has(name).quantum_risk, QuantumRisk::PqSafe, "{name}");
    }
}

/// SP 800-57 Pt 1 Rev 5 Table 2 levels for IFC and FFC, and the ECC curve levels.
#[test]
fn classical_levels_follow_sp_800_57_table_2() {
    let catalogue = builtin();
    let classical = |name: &str, id: &str| {
        catalogue
            .lookup(name, id)
            .unwrap()
            .parameter_set
            .classical_security_level
    };
    for name in ["RSA-PSS", "RSA-OAEP", "RSA-PKCS1v15"] {
        for (k, bits) in [
            ("2048", 112),
            ("3072", 128),
            ("4096", 128),
            ("7680", 192),
            ("15360", 256),
        ] {
            assert_eq!(classical(name, k), bits, "{name}/{k}");
        }
    }
    for (id, bits) in [("2048-224", 112), ("2048-256", 112), ("3072-256", 128)] {
        assert_eq!(classical("DSA", id), bits, "DSA/{id}");
    }
    for (id, bits) in [("ffdhe2048", 112), ("ffdhe3072", 128), ("ffdhe8192", 192)] {
        assert_eq!(classical("DH", id), bits, "DH/{id}");
    }
    for name in ["ECDSA", "ECDH"] {
        for (id, bits) in [("secp256r1", 128), ("secp384r1", 192), ("secp521r1", 256)] {
            assert_eq!(classical(name, id), bits, "{name}/{id}");
            assert_eq!(catalogue.lookup(name, id).unwrap().curve(), Some(id));
        }
    }
}

/// CycloneDX mapping: `pss` is written as CycloneDX `other`, the other paddings as themselves,
/// and an ECC or Edwards entry exposes its curve.
#[test]
fn padding_pss_maps_to_cyclonedx_other_and_curve_is_exposed() {
    let catalogue = builtin();
    let pss = catalogue.lookup("RSA-PSS", "2048").unwrap();
    assert_eq!(pss.padding(), Some(Padding::Pss));
    assert_eq!(Padding::Pss.as_cyclonedx(), "other");
    assert_eq!(Padding::Oaep.as_cyclonedx(), "oaep");
    assert_eq!(Padding::Pkcs1v15.as_cyclonedx(), "pkcs1v15");
    assert_eq!(
        catalogue.lookup("RSA-OAEP", "3072").unwrap().padding(),
        Some(Padding::Oaep)
    );
    assert_eq!(
        catalogue.lookup("ECDSA", "secp384r1").unwrap().curve(),
        Some("secp384r1")
    );
    assert_eq!(
        catalogue.lookup("Ed25519", "Ed25519").unwrap().curve(),
        Some("Ed25519")
    );
    assert_eq!(
        catalogue.lookup("X25519", "X25519").unwrap().curve(),
        Some("Curve25519")
    );
    // SHA-333: both are carried in rollcall-core's AlgorithmProperties, `pss` as `other`.
    let properties = pss.algorithm_properties();
    assert_eq!(properties.primitive, Some(Primitive::Signature));
    assert_eq!(properties.mode, None);
    assert_eq!(properties.padding, Some(model::Padding::Other));
    assert_eq!(properties.curve, None);
    let oaep = catalogue.lookup("RSA-OAEP", "3072").unwrap();
    assert_eq!(
        oaep.algorithm_properties().padding,
        Some(model::Padding::Oaep)
    );
    for (name, id, curve) in [
        ("ECDSA", "secp384r1", "secp384r1"),
        ("Ed25519", "Ed25519", "Ed25519"),
        ("X25519", "X25519", "Curve25519"),
    ] {
        let properties = catalogue.lookup(name, id).unwrap().algorithm_properties();
        assert_eq!(properties.curve.as_deref(), Some(curve), "{name}/{id}");
        assert_eq!(properties.padding, None, "{name}/{id}");
    }
}

/// SHA-333 AC2 / TP2: ECDSA/secp256r1 gives `algorithmProperties` with its `curve`.
#[test]
fn lookup_ecdsa_secp256r1_fills_curve() {
    let catalogue = builtin();
    let entry = catalogue.lookup("ECDSA", "secp256r1").unwrap();
    assert_eq!(entry.curve(), Some("secp256r1"));
    assert_eq!(
        entry.algorithm_properties(),
        AlgorithmProperties {
            primitive: Some(Primitive::Signature),
            parameter_set_identifier: Some("secp256r1".to_owned()),
            curve: Some("secp256r1".to_owned()),
            execution_environment: None,
            implementation_platform: None,
            mode: None,
            padding: None,
            crypto_functions: [CryptoFunction::Sign, CryptoFunction::Verify]
                .into_iter()
                .collect(),
            classical_security_level: Some(128),
            nist_quantum_security_level: Some(level(0)),
        }
    );
}

/// SHA-333 AC2 / TP2: RSA-PSS gives `algorithmProperties` with `padding: other`.
#[test]
fn lookup_rsa_pss_fills_padding_other() {
    let catalogue = builtin();
    let entry = catalogue.lookup("RSA-PSS", "2048").unwrap();
    assert_eq!(entry.padding(), Some(Padding::Pss));
    let properties = entry.algorithm_properties();
    assert_eq!(
        properties,
        AlgorithmProperties {
            primitive: Some(Primitive::Signature),
            parameter_set_identifier: Some("2048".to_owned()),
            curve: None,
            execution_environment: None,
            implementation_platform: None,
            mode: None,
            padding: Some(model::Padding::Other),
            crypto_functions: [CryptoFunction::Sign, CryptoFunction::Verify]
                .into_iter()
                .collect(),
            classical_security_level: Some(112),
            nist_quantum_security_level: Some(level(0)),
        }
    );
    let block = serde_json::to_value(&properties).unwrap();
    assert_eq!(block["padding"], "other", "{block}");
    assert!(block.get("curve").is_none(), "{block}");
}

/// SHA-333 TP2: every catalogue entry's `algorithmProperties` carries exactly its parameter
/// set's curve and its padding's CycloneDX word, and nothing when it has neither.
#[test]
fn every_entry_algorithm_properties_carry_its_curve_and_padding() {
    let catalogue = builtin();
    let (mut curves, mut paddings) = (0, 0);
    for entry in catalogue.entries() {
        let properties = entry.algorithm_properties();
        let what = format!("{}/{}", entry.algorithm.name, entry.parameter_set.id);
        assert_eq!(properties.curve.as_deref(), entry.curve(), "{what}");
        assert_eq!(
            properties.padding,
            entry.padding().map(model::Padding::from),
            "{what}"
        );
        if let Some(padding) = entry.padding() {
            assert_eq!(
                properties.padding.map(model::Padding::as_str),
                Some(padding.as_cyclonedx()),
                "{what}"
            );
        }
        curves += usize::from(properties.curve.is_some());
        paddings += usize::from(properties.padding.is_some());
    }
    // The catalogue has both kinds, so the loop above checked something.
    assert!(curves > 0, "no entry has a curve");
    assert!(paddings > 0, "no entry has a padding");
}

/// SHA-333 AC1: assets built from the ECDSA/secp256r1 and RSA-PSS lookups are valid
/// CycloneDX 1.6 in a CBOM, with their `curve` and `padding` written, and read back unchanged.
#[test]
fn catalogue_curve_and_padding_assets_validate_in_a_cbom() {
    let catalogue = builtin();
    let mut product = Product::new("sensor-node").unwrap().with_version("1.0.0");
    let mut image = Image::new(ImageKind::Application, "sensor-app").unwrap();
    for (component, name, id, symbol) in [
        (
            "ECDSA-P256",
            "ECDSA",
            "secp256r1",
            "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED",
        ),
        (
            "RSA-PSS-2048",
            "RSA-PSS",
            "2048",
            "CONFIG_MBEDTLS_PKCS1_V21",
        ),
    ] {
        let entry = catalogue.lookup(name, id).unwrap();
        let evidence = CryptoEvidence::new(
            Locator::KconfigSymbol {
                location: "build/zephyr/.config".to_owned(),
                line: Some(1),
                symbol: symbol.to_owned(),
            },
            "kconfig",
            ConfidenceLevel::Medium,
            &format!("{symbol}=y"),
        )
        .unwrap();
        let mut asset = CryptoAsset::new(
            CryptoAssetProperties::Algorithm(entry.algorithm_properties()),
            [evidence],
        )
        .unwrap();
        if let Some(oid) = entry.oid() {
            asset = asset.with_oid(oid).unwrap();
        }
        image
            .add_component(
                Component::new(ComponentKind::CryptographicAsset, component)
                    .unwrap()
                    .with_crypto(asset),
            )
            .unwrap();
    }
    product.add_image(image).unwrap();
    let text = cyclonedx::write(
        &product,
        &WriteOptions::new(Timestamp::parse("2026-01-02T03:04:05Z").unwrap()),
    )
    .unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    if let Err(violations) = validate_cyclonedx_1_6(&document) {
        panic!("not valid CycloneDX 1.6: {violations:#?}\n{text}");
    }
    assert!(text.contains("\"curve\": \"secp256r1\""), "{text}");
    assert!(text.contains("\"padding\": \"other\""), "{text}");
    assert!(!text.contains("\"pss\""), "{text}");
    let read = cyclonedx::read_str(&text).unwrap();
    assert_eq!(read.warnings, Vec::new());
    assert_eq!(read.product, product);
}

/// SHA-333: `docs/assay.md` lists `curve` and `padding` as modelled, and `docs/catalogue.md`'s
/// CycloneDX mapping fills both from `algorithm_properties()` with `pss` written as `other`.
#[test]
fn docs_describe_curve_and_padding_as_modelled() {
    let read = |name: &str| {
        let path = repo_root().join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let assay = read("docs/assay.md");
    let model = h2(&assay, "The model");
    let row = model
        .lines()
        .find(|l| l.starts_with("| `algorithm` |"))
        .expect("docs/assay.md has no algorithm row");
    for field in ["`curve`", "`padding`"] {
        assert!(row.contains(field), "algorithm row lacks {field}: {row}");
    }
    let not_modelled = model
        .split("Not modelled:")
        .nth(1)
        .expect("docs/assay.md has no Not modelled list");
    let not_modelled = not_modelled.split('.').next().unwrap_or_default();
    for field in ["curve", "padding"] {
        assert!(
            !not_modelled.contains(field),
            "docs/assay.md still lists {field} as not modelled: {not_modelled}"
        );
    }
    assert!(
        model.contains("`other`") && model.contains("`pss`"),
        "{model}"
    );

    let catalogue = read("docs/catalogue.md");
    let mapping = h2(&catalogue, "CycloneDX mapping");
    assert!(
        !mapping.contains("not modelled"),
        "docs/catalogue.md still says not modelled:\n{mapping}"
    );
    for (field, target) in [
        ("| `curve` |", "`algorithmProperties.curve`"),
        ("| `padding` |", "`algorithmProperties.padding`"),
    ] {
        let row = mapping
            .lines()
            .find(|l| l.starts_with(field))
            .unwrap_or_else(|| panic!("no {field} row in CycloneDX mapping"));
        assert!(row.contains(target), "{row}");
    }
    assert!(mapping.contains("`pss` is written as `other`"), "{mapping}");
}

/// The `##` sections of a Markdown document, by heading.
fn h2(doc: &str, heading: &str) -> String {
    doc.lines()
        .skip_while(|l| l.trim_end() != format!("## {heading}"))
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// AC3: `docs/catalogue.md` explains the risk classes and where each number comes from, names
/// every family in the catalogue and the sync script.
#[test]
fn catalogue_doc_explains_risk_classes_and_number_sources() {
    let path = repo_root().join("docs/catalogue.md");
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    for heading in [
        "What the catalogue is",
        "Schema",
        "Risk classes",
        "Where the numbers come from",
        "CycloneDX mapping",
        "Lookup API",
        "Export contract and sync with cbom-infra",
    ] {
        assert!(
            doc.lines().any(|l| l.trim_end() == format!("## {heading}")),
            "missing section {heading:?}"
        );
    }
    let risk = h2(&doc, "Risk classes");
    for class in QuantumRisk::ALL {
        assert!(risk.contains(class.as_str()), "Risk classes lacks {class}");
    }
    let numbers = h2(&doc, "Where the numbers come from");
    for source in [
        "SP 800-57",
        "Table 2",
        "Table 3",
        "FIPS 203",
        "FIPS 204",
        "FIPS 205",
        "SP 800-208",
        "§4.A.5",
    ] {
        assert!(
            numbers.contains(source),
            "Where the numbers come from lacks {source:?}"
        );
    }
    for family in builtin().algorithms().iter().map(|a| a.family.as_str()) {
        assert!(
            numbers.contains(family),
            "family {family} is not in the doc"
        );
    }
    let sync = h2(&doc, "Export contract and sync with cbom-infra");
    for term in [
        "scripts/check-catalogue-sync.sh",
        "algorithms.schema.json",
        "source",
        "rollcall-algorithms/1",
    ] {
        assert!(
            sync.contains(term),
            "Export contract section lacks {term:?}"
        );
    }
    assert!(
        repo_root()
            .join("scripts/check-catalogue-sync.sh")
            .is_file(),
        "the sync script is missing"
    );
}
