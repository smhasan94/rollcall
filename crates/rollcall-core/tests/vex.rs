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
