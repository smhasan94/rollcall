//! VEX evaluation against the real Zephyr build fixtures' evidence and captured scanner
//! output.
//!
//! - Kconfig evidence comes from `fixtures/zephyr/*/…/zephyr/.config` (real builds).
//! - Findings come from `tests/data/findings/`, captured by `scripts/capture-findings.sh`.
//! - The old-mbedTLS product is the hand-written `tests/data/old-mbedtls.model.json`, a
//!   stand-in until a real old-mbedTLS build fixture exists; the rules are the hand-written
//!   `tests/data/vex/*.rules.yml`.
//!
//! The golden report `tests/golden/vex/old-mbedtls.vex.json` is written only by
//! `scripts/regen-golden.sh` (this test with `ROLLCALL_BLESS=1`). Never edit it by hand.

mod common;

use std::path::{Path, PathBuf};

use common::{bless, load_fixture};
use rollcall_core::model::{Component, NodeRef, Product};
use rollcall_core::vex::{
    BuildEvidence, Condition, Finding, Reason, Report, RuleSet, Scanner, Status, Verdict,
    VersionRange, evaluate, parse_findings, parse_rules,
};
use rollcall_core::zephyr::kconfig;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn data(path: &str) -> PathBuf {
    manifest_dir().join("tests/data").join(path)
}

fn fixture_config(variant: &str, image: &str) -> PathBuf {
    manifest_dir()
        .join("../../fixtures/zephyr")
        .join(variant)
        .join(image)
        .join("zephyr/.config")
}

/// The image the old-mbedTLS model's components are in.
const OLD_TLS_APP: &str = "old-tls-app";

fn read_config(config: &Path) -> kconfig::Kconfig {
    kconfig::parse(&std::fs::read_to_string(config).unwrap()).unwrap()
}

fn evidence_from(image: &str, config: &Path) -> BuildEvidence {
    BuildEvidence::new().with_kconfig(image, read_config(config))
}

fn tls_evidence() -> BuildEvidence {
    evidence_from(OLD_TLS_APP, &fixture_config("tls", "http_server"))
}

fn component<'a>(product: &'a Product, name: &str) -> &'a Component {
    product
        .walk()
        .find_map(|(_, _, node)| match node {
            NodeRef::Component(c) if c.name == name => Some(c),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no component {name}"))
}

/// The real TLS build's model, as the Zephyr ingestion golden records it.
fn tls_product() -> Product {
    let path = manifest_dir().join("tests/golden/zephyr/tls.model.json");
    Product::from_json(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn off(symbol: &str) -> Condition {
    Condition::KconfigOff(symbol.to_owned())
}

#[test]
fn kconfig_off_true_when_not_set_in_tls_config() {
    let product = load_fixture("old-mbedtls");
    assert_eq!(
        off("CONFIG_MBEDTLS_SSL_PROTO_DTLS").evaluate(
            OLD_TLS_APP,
            component(&product, "mbedtls"),
            &tls_evidence()
        ),
        Verdict::True(
            "old-tls-app/zephyr/.config:403: CONFIG_MBEDTLS_SSL_PROTO_DTLS is not set".to_owned()
        )
    );
}

#[test]
fn kconfig_off_false_when_y_in_tls_config() {
    let product = load_fixture("old-mbedtls");
    assert_eq!(
        off("CONFIG_MBEDTLS_PSA_CRYPTO_C").evaluate(
            OLD_TLS_APP,
            component(&product, "mbedtls"),
            &tls_evidence()
        ),
        Verdict::False("old-tls-app/zephyr/.config:485: CONFIG_MBEDTLS_PSA_CRYPTO_C=y".to_owned())
    );
}

#[test]
fn kconfig_off_true_for_mbedtls_in_baseline_config() {
    let product = load_fixture("old-mbedtls");
    let baseline = evidence_from(OLD_TLS_APP, &fixture_config("baseline", "with_mcuboot"));
    assert_eq!(
        off("CONFIG_MBEDTLS").evaluate(OLD_TLS_APP, component(&product, "mbedtls"), &baseline),
        Verdict::True("old-tls-app/zephyr/.config:262: CONFIG_MBEDTLS is not set".to_owned())
    );
}

#[test]
fn kconfig_off_unknown_symbol_is_unknown() {
    let product = load_fixture("old-mbedtls");
    assert_eq!(
        off("CONFIG_MBEDTLS_PKCS12_C").evaluate(
            OLD_TLS_APP,
            component(&product, "mbedtls"),
            &tls_evidence()
        ),
        Verdict::Unknown("CONFIG_MBEDTLS_PKCS12_C is not in old-tls-app/zephyr/.config".to_owned())
    );
}

#[test]
fn version_in_uses_purl_version_of_tls_mbedtls() {
    let product = tls_product();
    let mbedtls = component(&product, "mbedtls");
    // The real build records a git SHA as the version; the purl carries the release tag.
    assert!(mbedtls.version.as_deref().is_some_and(|v| v.len() == 40));
    let within = Condition::VersionIn(VersionRange::parse(">=4.0.0, <4.2.0").unwrap());
    assert_eq!(
        within.evaluate(OLD_TLS_APP, mbedtls, &tls_evidence()),
        Verdict::True("mbedtls 4.1.0 is in >=4.0.0, <4.2.0".to_owned())
    );
    let before = Condition::VersionIn(VersionRange::parse("<4.1.0").unwrap());
    assert!(matches!(
        before.evaluate(OLD_TLS_APP, mbedtls, &tls_evidence()),
        Verdict::False(_)
    ));
}

#[test]
fn version_in_git_sha_is_unknown() {
    let product = tls_product();
    let mut mbedtls = component(&product, "mbedtls").clone();
    mbedtls.purl = None;
    let within = Condition::VersionIn(VersionRange::parse("<5").unwrap());
    assert!(matches!(
        within.evaluate(OLD_TLS_APP, &mbedtls, &tls_evidence()),
        Verdict::Unknown(_)
    ));
}

#[test]
fn cargo_feature_off_in_memory() {
    let product = load_fixture("old-heapless");
    let heapless = component(&product, "heapless");
    let feature = Condition::CargoFeatureOff("ufmt-impl".to_owned());
    let with = BuildEvidence::new().with_cargo_features(["serde", "ufmt-impl"]);
    let without = BuildEvidence::new().with_cargo_features(["serde"]);
    assert!(matches!(
        feature.evaluate(OLD_TLS_APP, heapless, &with),
        Verdict::False(_)
    ));
    assert!(matches!(
        feature.evaluate(OLD_TLS_APP, heapless, &without),
        Verdict::True(_)
    ));
    assert!(matches!(
        feature.evaluate(OLD_TLS_APP, heapless, &BuildEvidence::new()),
        Verdict::Unknown(_)
    ));
}

#[test]
fn symbol_not_linked_in_memory() {
    let product = load_fixture("old-mbedtls");
    let mbedtls = component(&product, "mbedtls");
    let symbol = Condition::SymbolNotLinked("mbedtls_ssl_parse_client_hello".to_owned());
    let linked = BuildEvidence::new().with_linked_symbols(["mbedtls_ssl_parse_client_hello"]);
    let not_linked = BuildEvidence::new().with_linked_symbols(["mbedtls_ssl_handshake"]);
    assert!(matches!(
        symbol.evaluate(OLD_TLS_APP, mbedtls, &linked),
        Verdict::False(_)
    ));
    assert!(matches!(
        symbol.evaluate(OLD_TLS_APP, mbedtls, &not_linked),
        Verdict::True(_)
    ));
    assert!(matches!(
        symbol.evaluate(OLD_TLS_APP, mbedtls, &BuildEvidence::new()),
        Verdict::Unknown(_)
    ));
}

fn findings(file: &str) -> Vec<Finding> {
    let bytes = std::fs::read(data(&format!("findings/{file}"))).unwrap();
    let parsed = parse_findings(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert!(parsed.warnings.is_empty(), "{file}: {:?}", parsed.warnings);
    parsed.findings
}

fn rules(file: &str) -> RuleSet {
    let path = data(&format!("vex/{file}"));
    parse_rules(&std::fs::read_to_string(&path).unwrap(), file).unwrap_or_else(|e| panic!("{e}"))
}

fn old_mbedtls_report() -> Report {
    evaluate(
        &load_fixture("old-mbedtls"),
        &tls_evidence(),
        &findings("old-mbedtls.grype.json"),
        &rules("old-mbedtls.rules.yml"),
    )
}

fn check_golden(name: &str, actual: &str) {
    let path = manifest_dir().join("tests/golden/vex").join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        bless(&path, actual);
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read golden {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} differs from the evaluator output; if the change is intended, run \
         scripts/regen-golden.sh and review the diff",
        path.display()
    );
}

#[test]
fn old_mbedtls_grype_matches_golden() {
    let report = old_mbedtls_report();
    check_golden("old-mbedtls.vex.json", &report.to_json().unwrap());
}

#[test]
fn old_mbedtls_report_has_expected_outcomes() {
    let report = old_mbedtls_report();
    let status_of = |cve: &str| {
        report
            .statements
            .iter()
            .find(|s| s.vulnerability == cve)
            .map(|s| (s.status, s.rules.clone()))
    };
    let dtls = (
        Status::NotAffected,
        vec!["mbedtls-dtls-compiled-out".to_owned()],
    );
    assert_eq!(status_of("CVE-2022-35409"), Some(dtls.clone()));
    assert_eq!(status_of("CVE-2022-46393"), Some(dtls));
    assert_eq!(
        status_of("CVE-2024-23775"),
        Some((
            Status::NotAffected,
            vec!["mbedtls-x509-write-compiled-out".to_owned()]
        ))
    );
    assert_eq!(
        status_of("CVE-2022-46392"),
        Some((
            Status::Affected,
            vec!["mbedtls-2-28-before-2-28-2".to_owned()]
        ))
    );
    // PSA crypto is on, so the specific rule is skipped and the fallback with the higher
    // priority decides.
    assert_eq!(
        status_of("CVE-2024-28960"),
        Some((
            Status::UnderInvestigation,
            vec!["mbedtls-triage".to_owned()]
        ))
    );
    let [unresolved] = report.unresolved.as_slice() else {
        panic!("{:?}", report.unresolved)
    };
    assert_eq!(unresolved.vulnerability, "CVE-2021-43666");
    assert!(
        matches!(&unresolved.reason, Reason::NeedsEvidence { rules, .. } if rules == &["mbedtls-pkcs12-off"])
    );
    assert!(unresolved.template.contains("CVE-2021-43666"));
    assert_eq!(report.statements.len() + report.unresolved.len(), 23);
    assert!(report.warnings.is_empty());
}

#[test]
fn evaluating_twice_is_byte_identical() {
    assert_eq!(
        old_mbedtls_report().to_json().unwrap(),
        old_mbedtls_report().to_json().unwrap()
    );
}

#[test]
fn conflicting_rules_warn_on_real_findings() {
    let report = evaluate(
        &load_fixture("old-mbedtls"),
        &tls_evidence(),
        &findings("old-mbedtls.grype.json"),
        &rules("conflict.rules.yml"),
    );
    let [warning] = report.warnings.as_slice() else {
        panic!("{:?}", report.warnings)
    };
    assert!(
        warning.message.contains("`dtls-says-affected`"),
        "{warning}"
    );
    assert!(
        warning.message.contains("`dtls-says-not-affected`"),
        "{warning}"
    );
    // Everything is unresolved: one conflict, and no rule for the other 22.
    assert!(report.statements.is_empty());
    assert_eq!(report.unresolved.len(), 23);
}

#[test]
fn osv_capture_of_heapless_parses_and_joins() {
    let found = findings("old-heapless.osv.json");
    assert!(!found.is_empty());
    assert!(
        found
            .iter()
            .all(|f| f.scanner == Scanner::Osv && f.name == "heapless")
    );
    assert!(
        found
            .iter()
            .any(|f| f.aliases.contains("CVE-2020-36464") || f.id == "CVE-2020-36464")
    );
    let set = parse_rules(
        "version: 1\nrules:\n  - id: heapless-clone\n    match: {name: heapless, cves: [CVE-2020-36464]}\n    status: affected\n",
        "inline.yml",
    )
    .unwrap();
    let report = evaluate(
        &load_fixture("old-heapless"),
        &BuildEvidence::new(),
        &found,
        &set,
    );
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
    // RUSTSEC-2020-0145 and GHSA-qgwf-r2jj-2ccv both alias CVE-2020-36464: one entry.
    let [statement] = report.statements.as_slice() else {
        panic!("{:?}", report.statements)
    };
    assert_eq!(statement.vulnerability, "CVE-2020-36464");
    assert!(statement.aliases.contains("RUSTSEC-2020-0145"));
    assert!(statement.aliases.contains("GHSA-qgwf-r2jj-2ccv"));
    assert_eq!(statement.status, Status::Affected);

    let unresolved = evaluate(
        &load_fixture("old-heapless"),
        &BuildEvidence::new(),
        &found,
        &RuleSet::default(),
    );
    assert_eq!(
        unresolved.unresolved.len(),
        1,
        "{:?}",
        unresolved.unresolved
    );
    assert_eq!(unresolved.unresolved[0].vulnerability, "CVE-2020-36464");
}

/// The real sysbuild build: MCUboot (`mcuboot`) and the application (`with_mcuboot`) both
/// contain mbedtls, but only MCUboot enables it (`CONFIG_MBEDTLS=y` at mcuboot's .config:467;
/// not set at with_mcuboot's .config:262).
fn sysbuild_mbedtls_report(images: &[&str]) -> Report {
    let path = manifest_dir().join("tests/golden/zephyr/baseline.sysbuild.model.json");
    let product = Product::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut evidence = BuildEvidence::new();
    for image in images {
        evidence = evidence.with_kconfig(image, read_config(&fixture_config("baseline", image)));
    }
    let mbedtls = component(&product, "mbedtls");
    let finding = Finding {
        id: "CVE-2099-0001".to_owned(),
        purl: mbedtls.purl.clone(),
        name: "mbedtls".to_owned(),
        version: mbedtls.version.clone(),
        aliases: Default::default(),
        cpes: Default::default(),
        severity: None,
        fixed_in: Default::default(),
        scanner: Scanner::Grype,
    };
    let rules = parse_rules(
        "version: 1\nrules:\n  - id: mbedtls-off\n    match: {name: mbedtls}\n    when: [{kconfig_off: CONFIG_MBEDTLS}]\n    status: not_affected\n    justification: code_not_present\n",
        "inline.yml",
    )
    .unwrap();
    evaluate(&product, &evidence, &[finding], &rules)
}

fn image_of(report_ref: &str, product: &Product) -> String {
    let mut image = String::new();
    for (_, bom_ref, node) in product.walk() {
        match node {
            NodeRef::Image(i) => image = i.name.clone(),
            NodeRef::Component(_) if bom_ref.as_str() == report_ref => return image,
            _ => {}
        }
    }
    panic!("no component {report_ref}")
}

#[test]
fn sysbuild_kconfig_is_per_image() {
    let path = manifest_dir().join("tests/golden/zephyr/baseline.sysbuild.model.json");
    let product = Product::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();

    let report = sysbuild_mbedtls_report(&["mcuboot", "with_mcuboot"]);
    let [statement] = report.statements.as_slice() else {
        panic!("{report:?}")
    };
    assert_eq!(
        image_of(&statement.component.bom_ref, &product),
        "with_mcuboot"
    );
    assert_eq!(statement.status, Status::NotAffected);
    assert_eq!(
        statement.evidence,
        ["with_mcuboot/zephyr/.config:262: CONFIG_MBEDTLS is not set"]
    );
    // MCUboot's mbedtls is compiled in: the rule does not apply, so no not_affected claim.
    let [unresolved] = report.unresolved.as_slice() else {
        panic!("{report:?}")
    };
    assert_eq!(
        image_of(&unresolved.component.as_ref().unwrap().bom_ref, &product),
        "mcuboot"
    );
    assert_eq!(unresolved.reason, Reason::NoRule);

    // With only the application's .config, MCUboot's mbedtls needs evidence.
    let report = sysbuild_mbedtls_report(&["with_mcuboot"]);
    assert_eq!(report.statements.len(), 1);
    let [unresolved] = report.unresolved.as_slice() else {
        panic!("{report:?}")
    };
    assert_eq!(
        image_of(&unresolved.component.as_ref().unwrap().bom_ref, &product),
        "mcuboot"
    );
    match &unresolved.reason {
        Reason::NeedsEvidence { missing, .. } => assert!(
            missing[0].contains("no .config given for image mcuboot"),
            "{missing:?}"
        ),
        other => panic!("{other:?}"),
    }
}

#[test]
fn osv_capture_of_old_mbedtls_has_no_findings() {
    // osv-scanner maps pkg:github purls to "GitHub Actions" and finds nothing for them.
    assert!(findings("old-mbedtls.osv.json").is_empty());
}

// ---------------------------------------------------------------------------------------
// Rendering (SHA-113): OpenVEX, CycloneDX VEX and the embedded form, from the old-mbedTLS
// report evaluated against the SBOM `rollcall generate` writes for the model.

mod render {
    use std::collections::{BTreeMap, BTreeSet};

    use rollcall_core::cyclonedx::{self, SerialNumber, Timestamp, WriteOptions};
    use rollcall_core::model::Purl;
    use rollcall_core::vex::{
        ComponentRef, DEFAULT_ACTION, DocumentKind, Justification, OPENVEX_JUSTIFICATION_PROPERTY,
        Report, SbomIndex, Statement, Status, VexError, VexOptions, document_id, embed,
        evaluate_document, to_cyclonedx_vex, to_openvex,
    };
    use serde_json::Value;

    use super::common::{GOLDEN_TIMESTAMP, load_fixture};
    use super::{check_golden, findings, rules, tls_evidence};

    /// The old-mbedTLS SBOM, exactly as `rollcall generate --model … --timestamp` writes it.
    fn sbom() -> String {
        let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
        cyclonedx::write(&load_fixture("old-mbedtls"), &options).unwrap()
    }

    fn report_for(sbom: &str) -> Report {
        let read = cyclonedx::read_str(sbom).unwrap();
        evaluate_document(
            &read.product,
            &read.refs,
            &tls_evidence(),
            &findings("old-mbedtls.grype.json"),
            &rules("old-mbedtls.rules.yml"),
        )
    }

    fn options() -> VexOptions {
        VexOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap())
    }

    fn index(sbom: &str) -> SbomIndex {
        SbomIndex::from_bytes(sbom.as_bytes()).unwrap()
    }

    fn openvex(sbom: &str, report: &Report) -> String {
        to_openvex(report, Some(&index(sbom)), &options())
            .unwrap()
            .text
    }

    fn cdx(sbom: &str, report: &Report) -> String {
        to_cyclonedx_vex(report, &index(sbom), &options())
            .unwrap()
            .text
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn assert_schema_valid(name: &str, text: &str) {
        if let Err(violations) = cyclonedx::validate_cyclonedx_1_6(&json(text)) {
            panic!("{name} violates the CycloneDX 1.6 schema: {violations:#?}");
        }
    }

    #[test]
    fn openvex_fixture_matches_golden() {
        let sbom = sbom();
        check_golden(
            "old-mbedtls.openvex.json",
            &openvex(&sbom, &report_for(&sbom)),
        );
    }

    #[test]
    fn cyclonedx_vex_fixture_matches_golden() {
        let sbom = sbom();
        check_golden("old-mbedtls.vex.cdx.json", &cdx(&sbom, &report_for(&sbom)));
    }

    #[test]
    fn embed_fixture_matches_golden_and_changes_only_vulnerabilities_key() {
        let sbom = sbom();
        let embedded = embed(sbom.as_bytes(), &report_for(&sbom)).unwrap().text;
        check_golden("old-mbedtls.embed.cdx.json", &embedded);
        // Every byte of the SBOM before its closing brace is kept, except the version token.
        assert_eq!(
            sbom.matches("\"version\": 1,").count(),
            1,
            "one version token at depth 1"
        );
        let bumped = sbom.replacen("\"version\": 1,", "\"version\": 2,", 1);
        let head = bumped.trim_end().strip_suffix('}').unwrap().trim_end();
        assert!(embedded.starts_with(head));
        let mut with = json(&embedded);
        let doc = with.as_object_mut().unwrap();
        let vulnerabilities = doc.remove("vulnerabilities");
        assert!(vulnerabilities.is_some_and(|v| !v.as_array().unwrap().is_empty()));
        assert_eq!(
            doc.insert("version".to_owned(), Value::from(1)),
            Some(Value::from(2))
        );
        assert_eq!(with, json(&sbom));
    }

    /// CycloneDX 1.6: the version SHOULD be incremented when a BOM is modified.
    #[test]
    fn embed_increments_version_and_keeps_serial_number() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let before = json(&sbom);
        let after = json(&embed(sbom.as_bytes(), &report).unwrap().text);
        assert_eq!(before["version"], 1);
        assert_eq!(after["version"], 2);
        assert_eq!(after["serialNumber"], before["serialNumber"]);
        // From any version, and only the top-level one (metadata.component.version is not
        // a BOM version).
        let v7 = sbom.replacen("\"version\": 1,", "\"version\": 7,", 1);
        let after = json(&embed(v7.as_bytes(), &report).unwrap().text);
        assert_eq!(after["version"], 8);
        assert_eq!(after["metadata"]["component"]["version"], "1.0.0");
        // Nothing to embed: the SBOM is returned unchanged, version included.
        let empty = Report {
            statements: Vec::new(),
            unresolved: Vec::new(),
            warnings: Vec::new(),
        };
        assert_eq!(embed(sbom.as_bytes(), &empty).unwrap().text, sbom);
    }

    #[test]
    fn embed_without_version_appends_version_2() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let unversioned = sbom.replacen("  \"version\": 1,\n", "", 1);
        assert!(json(&unversioned).get("version").is_none());
        let embedded = embed(unversioned.as_bytes(), &report).unwrap().text;
        let doc = json(&embedded);
        assert_eq!(doc["version"], 2);
        assert!(embedded.contains("\n  \"version\": 2,\n  \"vulnerabilities\": ["));
        assert_schema_valid("embedded, unversioned input", &embedded);
    }

    #[test]
    fn embed_replaces_an_empty_vulnerabilities_array() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let with_empty = sbom.replacen(
            "  \"metadata\": {",
            "  \"vulnerabilities\": [],\n  \"metadata\": {",
            1,
        );
        assert_ne!(with_empty, sbom);
        let embedded = embed(with_empty.as_bytes(), &report).unwrap().text;
        assert_eq!(embedded.matches("\"vulnerabilities\"").count(), 1);
        let doc = json(&embedded);
        assert!(!doc["vulnerabilities"].as_array().unwrap().is_empty());
        assert_eq!(doc["version"], 2);
        assert_schema_valid("embedded into []", &embedded);
    }

    #[test]
    fn bom_links_need_a_lowercase_uuid_serial_and_version_of_at_least_1() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let serial = json(&sbom)["serialNumber"].as_str().unwrap().to_owned();
        for bad in [
            sbom.replacen("\"version\": 1,", "\"version\": 0,", 1),
            sbom.replacen(
                &serial,
                &serial.to_uppercase().replace("URN:UUID:", "urn:uuid:"),
                1,
            ),
            sbom.replacen(&serial, "urn:isbn:0451450523", 1),
        ] {
            assert_ne!(bad, sbom);
            assert!(matches!(
                SbomIndex::from_bytes(bad.as_bytes()),
                Err(VexError::Sbom(_))
            ));
            assert!(matches!(
                embed(bad.as_bytes(), &report),
                Err(VexError::Sbom(_))
            ));
        }
    }

    #[test]
    fn cyclonedx_vex_golden_validates_against_schema_1_6() {
        let sbom = sbom();
        let text = cdx(&sbom, &report_for(&sbom));
        assert_schema_valid("CycloneDX VEX", &text);
        // A VEX document, not an SBOM: no components, no dependencies.
        let doc = json(&text);
        assert!(doc.get("components").is_none() && doc.get("dependencies").is_none());
        assert_eq!(doc["specVersion"], "1.6");
    }

    #[test]
    fn embedded_sbom_validates_against_schema_1_6() {
        let sbom = sbom();
        let embedded = embed(sbom.as_bytes(), &report_for(&sbom)).unwrap().text;
        assert_schema_valid("embedded SBOM", &embedded);
    }

    #[test]
    fn sbom_writer_never_emits_vulnerabilities() {
        // The SBOM stays VEX-free unless --embed: the writer has no vulnerabilities.
        for name in ["old-mbedtls", "minimal", "widget"] {
            let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
            let text = cyclonedx::write(&load_fixture(name), &options).unwrap();
            assert!(json(&text).get("vulnerabilities").is_none(), "{name}");
        }
    }

    /// What grype's `--vex` matches: the OpenVEX product `@id` must be the SBOM component's
    /// purl string, byte for byte.
    #[test]
    fn openvex_product_ids_equal_sbom_purls_of_not_affected_components() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let doc = json(&openvex(&sbom, &report));
        let sbom_purls: BTreeSet<String> = json(&sbom)["components"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|image| image["components"].as_array().cloned().unwrap_or_default())
            .filter_map(|c| c["purl"].as_str().map(str::to_owned))
            .collect();
        let not_affected: Vec<&Value> = doc["statements"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["status"] == "not_affected")
            .collect();
        let ids: BTreeSet<&str> = not_affected
            .iter()
            .map(|s| s["vulnerability"]["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            BTreeSet::from(["CVE-2022-35409", "CVE-2022-46393", "CVE-2024-23775"])
        );
        for s in not_affected {
            let product = s["products"][0]["@id"].as_str().unwrap();
            assert_eq!(product, "pkg:github/mbed-tls/mbedtls@v2.28.0");
            assert!(
                sbom_purls.contains(product),
                "{product} not in {sbom_purls:?}"
            );
            assert!(s["justification"].is_string());
        }
    }

    #[test]
    fn rendering_twice_is_byte_identical() {
        let sbom = sbom();
        assert_eq!(
            openvex(&sbom, &report_for(&sbom)),
            openvex(&sbom, &report_for(&sbom))
        );
        assert_eq!(
            cdx(&sbom, &report_for(&sbom)),
            cdx(&sbom, &report_for(&sbom))
        );
    }

    #[test]
    fn statements_render_identically_in_any_input_order() {
        let sbom = sbom();
        let read = cyclonedx::read_str(&sbom).unwrap();
        let mut reversed = findings("old-mbedtls.grype.json");
        reversed.reverse();
        let report = evaluate_document(
            &read.product,
            &read.refs,
            &tls_evidence(),
            &reversed,
            &rules("old-mbedtls.rules.yml"),
        );
        assert_eq!(openvex(&sbom, &report), openvex(&sbom, &report_for(&sbom)));
        assert_eq!(cdx(&sbom, &report), cdx(&sbom, &report_for(&sbom)));
        // And a report whose statements were shuffled renders the same CycloneDX groups.
        let mut shuffled = report_for(&sbom);
        shuffled.statements.reverse();
        assert_eq!(cdx(&sbom, &shuffled), cdx(&sbom, &report_for(&sbom)));
    }

    #[test]
    fn id_and_timestamp_overrides_change_only_those_lines() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let id = SerialNumber::parse("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79").unwrap();
        let mut custom = VexOptions::new(Timestamp::parse("2030-05-06T07:08:09Z").unwrap());
        custom.id = Some(id);
        for (base, other) in [
            (
                openvex(&sbom, &report),
                to_openvex(&report, Some(&index(&sbom)), &custom)
                    .unwrap()
                    .text,
            ),
            (
                cdx(&sbom, &report),
                to_cyclonedx_vex(&report, &index(&sbom), &custom)
                    .unwrap()
                    .text,
            ),
        ] {
            let changed: Vec<(&str, &str)> = base
                .lines()
                .zip(other.lines())
                .filter(|(a, b)| a != b)
                .collect();
            assert_eq!(base.lines().count(), other.lines().count());
            assert_eq!(changed.len(), 2, "{changed:#?}");
            assert!(
                changed
                    .iter()
                    .any(|(_, b)| b.contains("2030-05-06T07:08:09Z"))
            );
            assert!(
                changed
                    .iter()
                    .any(|(_, b)| b.contains("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"))
            );
        }
    }

    #[test]
    fn derived_id_is_stable_and_independent_of_timestamp() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let ov = DocumentKind::OpenVex;
        let cdx_kind = DocumentKind::CycloneDx;
        let id = document_id(&report, Some(&index(&sbom)), ov);
        assert_eq!(id, document_id(&report_for(&sbom), Some(&index(&sbom)), ov));
        let later = VexOptions::new(Timestamp::parse("2031-01-01T00:00:00Z").unwrap());
        let openvex_text = to_openvex(&report, Some(&index(&sbom)), &later)
            .unwrap()
            .text;
        assert!(openvex_text.contains(id.as_str()), "{openvex_text}");
        let cdx_id = document_id(&report, Some(&index(&sbom)), cdx_kind);
        let cdx_text = to_cyclonedx_vex(&report, &index(&sbom), &later)
            .unwrap()
            .text;
        assert!(cdx_text.contains(cdx_id.as_str()), "{cdx_text}");
        // A different triage is a different document.
        let mut fewer = report.clone();
        fewer.statements.pop();
        assert_ne!(id, document_id(&fewer, Some(&index(&sbom)), ov));
        // So is the same triage of a different SBOM version.
        let bumped = sbom.replacen("\"version\": 1,", "\"version\": 2,", 1);
        assert_ne!(id, document_id(&report, Some(&index(&bumped)), ov));
    }

    #[test]
    fn openvex_and_cyclonedx_documents_get_different_derived_ids() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let ov = document_id(&report, Some(&index(&sbom)), DocumentKind::OpenVex);
        let cdx_id = document_id(&report, Some(&index(&sbom)), DocumentKind::CycloneDx);
        assert_ne!(ov, cdx_id);
        assert_eq!(json(&openvex(&sbom, &report))["@id"], ov.as_str());
        assert_eq!(json(&cdx(&sbom, &report))["serialNumber"], cdx_id.as_str());
    }

    const STATUSES: [Status; 4] = [
        Status::NotAffected,
        Status::Affected,
        Status::Fixed,
        Status::UnderInvestigation,
    ];
    const JUSTIFICATIONS: [Justification; 14] = [
        Justification::CodeNotPresent,
        Justification::CodeNotReachable,
        Justification::RequiresConfiguration,
        Justification::RequiresDependency,
        Justification::RequiresEnvironment,
        Justification::ProtectedByCompiler,
        Justification::ProtectedAtRuntime,
        Justification::ProtectedAtPerimeter,
        Justification::ProtectedByMitigatingControl,
        Justification::ComponentNotPresent,
        Justification::VulnerableCodeNotPresent,
        Justification::VulnerableCodeNotInExecutePath,
        Justification::VulnerableCodeCannotBeControlledByAdversary,
        Justification::InlineMitigationsAlreadyExist,
    ];
    /// OpenVEX v0.2.0's justification vocabulary.
    const OPENVEX_JUSTIFICATIONS: [&str; 5] = [
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    ];

    fn statement(n: usize, bom_ref: &str, status: Status, j: Option<Justification>) -> Statement {
        Statement {
            vulnerability: format!("CVE-2099-{:04}", n + 1),
            aliases: BTreeSet::new(),
            component: ComponentRef {
                bom_ref: bom_ref.to_owned(),
                name: "mbedtls".to_owned(),
                version: Some("2.28.0".to_owned()),
                purl: Some(Purl::new("pkg:github/mbed-tls/mbedtls@v2.28.0").unwrap()),
            },
            status,
            justification: j,
            detail: None,
            rules: vec![format!("rule-{n}")],
            evidence: Vec::new(),
        }
    }

    fn mbedtls_ref(sbom: &str) -> String {
        report_for(sbom).statements[0].component.bom_ref.clone()
    }

    #[test]
    fn mapping_covers_every_status_and_justification_and_targets_schema_enums() {
        let sbom = sbom();
        let bom_ref = mbedtls_ref(&sbom);
        let mut statements: Vec<Statement> = STATUSES
            .iter()
            .filter(|s| **s != Status::NotAffected)
            .enumerate()
            .map(|(n, s)| statement(n, &bom_ref, *s, None))
            .collect();
        for (n, j) in JUSTIFICATIONS.iter().enumerate() {
            statements.push(statement(10 + n, &bom_ref, Status::NotAffected, Some(*j)));
        }
        let report = Report {
            statements,
            unresolved: Vec::new(),
            warnings: Vec::new(),
        };
        // The schema's enums for analysis.state and analysis.justification.
        let text = cdx(&sbom, &report);
        assert_schema_valid("every mapping", &text);
        let doc = json(&text);
        let vulns = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 3 + JUSTIFICATIONS.len());
        for v in vulns {
            let j = &v["analysis"]["justification"];
            let property = v["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == OPENVEX_JUSTIFICATION_PROPERTY);
            assert_eq!(j.is_string(), property.is_some(), "{v}");
        }
        let embedded = embed(sbom.as_bytes(), &report).unwrap().text;
        assert_schema_valid("every mapping, embedded", &embedded);

        let ov = json(&openvex(&sbom, &report));
        for s in ov["statements"].as_array().unwrap() {
            let status = s["status"].as_str().unwrap();
            assert!(["not_affected", "affected", "fixed", "under_investigation"].contains(&status));
            match status {
                "not_affected" => {
                    let j = s["justification"].as_str().unwrap();
                    assert!(OPENVEX_JUSTIFICATIONS.contains(&j), "{j}");
                }
                "affected" => assert_eq!(s["action_statement"], DEFAULT_ACTION),
                _ => assert!(s.get("justification").is_none()),
            }
        }
    }

    #[test]
    fn affects_refs_resolve_to_sbom_bom_refs() {
        let sbom = sbom();
        let doc = json(&sbom);
        let serial = doc["serialNumber"].as_str().unwrap();
        let prefix = format!("urn:cdx:{}/1#", serial.strip_prefix("urn:uuid:").unwrap());
        let refs: BTreeSet<String> = index(&sbom).refs.keys().cloned().collect();
        let vex = json(&cdx(&sbom, &report_for(&sbom)));
        for v in vex["vulnerabilities"].as_array().unwrap() {
            for a in v["affects"].as_array().unwrap() {
                let link = a["ref"].as_str().unwrap();
                let bom_ref = link
                    .strip_prefix(&prefix)
                    .unwrap_or_else(|| panic!("{link}"));
                assert!(refs.contains(bom_ref), "{bom_ref}");
            }
        }
        let embedded = json(&embed(sbom.as_bytes(), &report_for(&sbom)).unwrap().text);
        for v in embedded["vulnerabilities"].as_array().unwrap() {
            for a in v["affects"].as_array().unwrap() {
                assert!(refs.contains(a["ref"].as_str().unwrap()), "{a}");
            }
        }
        // A statement citing a bom-ref the SBOM does not have is an error, not a dangling link.
        let mut report = report_for(&sbom);
        report.statements[0].component.bom_ref = "component:nope".to_owned();
        assert!(matches!(
            to_cyclonedx_vex(&report, &index(&sbom), &options()),
            Err(VexError::UnknownBomRef { .. })
        ));
        assert!(matches!(
            embed(sbom.as_bytes(), &report),
            Err(VexError::UnknownBomRef { .. })
        ));
    }

    #[test]
    fn subject_without_purl_warns_and_uses_bom_link() {
        let sbom = sbom();
        let bom_ref = mbedtls_ref(&sbom);
        let mut s = statement(0, &bom_ref, Status::Fixed, None);
        s.component.purl = None;
        let report = Report {
            statements: vec![s],
            unresolved: Vec::new(),
            warnings: Vec::new(),
        };
        let mut options = options();
        options.author = Some("Example Devices Ltd".to_owned());
        // Without the SBOM: no purl anywhere, so the bom-ref, with a warning.
        let rendered = to_openvex(&report, None, &options).unwrap();
        assert_eq!(rendered.warnings.len(), 1);
        assert_eq!(
            json(&rendered.text)["statements"][0]["products"][0]["@id"],
            bom_ref
        );
        // With an SBOM whose component has no purl: its BOM-Link.
        let no_purl = sbom.replace("\"purl\": \"pkg:github/mbed-tls/mbedtls@v2.28.0\",", "");
        assert_ne!(no_purl, sbom);
        let rendered = to_openvex(&report, Some(&index(&no_purl)), &options).unwrap();
        assert_eq!(rendered.warnings.len(), 1);
        assert!(rendered.warnings[0].message.contains("no purl"));
        let id = json(&rendered.text)["statements"][0]["products"][0]["@id"].clone();
        assert_eq!(id, index(&no_purl).bom_link(&bom_ref).unwrap());
    }

    #[test]
    fn openvex_author_fallback_warns() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let rendered = to_openvex(&report, Some(&index(&sbom)), &options()).unwrap();
        assert_eq!(json(&rendered.text)["author"], "rollcall");
        assert!(
            rendered
                .warnings
                .iter()
                .any(|w| w.message.contains("--author")),
            "{:?}",
            rendered.warnings
        );
        let mut named = options();
        named.author = Some("Example Devices Ltd".to_owned());
        let rendered = to_openvex(&report, Some(&index(&sbom)), &named).unwrap();
        assert_eq!(json(&rendered.text)["author"], "Example Devices Ltd");
        assert!(rendered.warnings.is_empty(), "{:?}", rendered.warnings);
    }

    #[test]
    fn cyclonedx_vex_needs_a_serial_number_and_embed_refuses_twice() {
        let sbom = sbom();
        let report = report_for(&sbom);
        let mut doc = json(&sbom);
        doc.as_object_mut().unwrap().remove("serialNumber");
        let no_serial = serde_json::to_string(&doc).unwrap();
        assert!(matches!(
            to_cyclonedx_vex(&report, &index(&no_serial), &options()),
            Err(VexError::NoSerialNumber)
        ));
        let embedded = embed(sbom.as_bytes(), &report).unwrap().text;
        assert!(matches!(
            embed(embedded.as_bytes(), &report),
            Err(VexError::AlreadyHasVulnerabilities)
        ));
    }

    #[test]
    fn embed_rejects_malformed_sbom_without_panic() {
        let report = report_for(&sbom());
        for bad in [
            &b""[..],
            b"{",
            b"[1]",
            b"\xff",
            b"{\"bomFormat\":\"CycloneDX\",\"components\":7}",
        ] {
            assert!(embed(bad, &report).is_err(), "{bad:?}");
        }
        let truncated = sbom();
        let truncated = &truncated.as_bytes()[..truncated.len() / 2];
        assert!(embed(truncated, &report).is_err());
    }

    #[test]
    fn grouped_vulnerabilities_list_every_affected_component() {
        let sbom = sbom();
        let refs: Vec<String> = index(&sbom).refs.keys().cloned().collect();
        let mut statements = Vec::new();
        for r in &refs {
            let mut s = statement(
                0,
                r,
                Status::NotAffected,
                Some(Justification::CodeNotPresent),
            );
            s.detail = Some("same".to_owned());
            statements.push(s);
        }
        let report = Report {
            statements,
            unresolved: Vec::new(),
            warnings: Vec::new(),
        };
        let doc = json(&cdx(&sbom, &report));
        let vulns = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        let affects: BTreeMap<usize, &Value> = vulns[0]["affects"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .collect();
        assert_eq!(affects.len(), refs.len());
        // OpenVEX keeps one statement per component.
        let ov = json(&openvex(&sbom, &report));
        assert_eq!(ov["statements"].as_array().unwrap().len(), refs.len());
    }
}
