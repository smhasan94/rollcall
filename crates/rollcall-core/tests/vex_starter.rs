//! The starter VEX rule pack (`rollcall_identifiers::VEX_RULES_YAML`, SHA-115) on the six real
//! sysbuild builds under `fixtures/`.
//!
//! - Products are ingested from the builds with their west lists and the seed identifier
//!   database, as `rollcall generate --zephyr DIR --sysbuild --identifier-db` does.
//! - Kconfig evidence is each image's own `zephyr/.config`; linked-symbol evidence is each
//!   image's own [`linked_functions`] of its `zephyr/zephyr.map`.
//! - The rule × fixture table builds its findings in code: one finding per CVE a rule names,
//!   against every component the rule matches, carrying that component's real purl, CPE and
//!   version. Each rule is evaluated alone, so each cell shows what that rule decides.
//! - The old-mbedTLS case uses real grype output, `tests/data/findings/zephyr-old-mbedtls.grype.json`
//!   (written only by `scripts/capture-findings.sh`).
//!
//! `fixtures/` is only read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rollcall_core::linker_map::{self, linked_functions};
use rollcall_core::model::{NodeRef, Product};
use rollcall_core::vex::{
    self, BuildEvidence, Condition, Finding, Justification, KconfigSymbols, LintKind, Reason,
    Report, RuleSet, Scanner, Status,
};
use rollcall_core::zephyr::{self, IngestOptions, kconfig};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The fixtures, by the short name the table uses, and their directory under `fixtures/`.
const FIXTURES: [(&str, &str); 6] = [
    ("baseline", "zephyr/baseline"),
    ("bt", "zephyr/bt"),
    ("tls", "zephyr/tls"),
    ("old-mbedtls", "zephyr-old-mbedtls/old-mbedtls"),
    ("smp-serial", "zephyr-smp/smp-serial"),
    ("smp-bt", "zephyr-smp/smp-bt"),
];

fn variant_dir(fixture: &str) -> PathBuf {
    let (_, dir) = FIXTURES
        .iter()
        .find(|(name, _)| *name == fixture)
        .unwrap_or_else(|| panic!("no fixture {fixture}"));
    manifest_dir().join("../../fixtures").join(dir)
}

/// One real build: its product and its build evidence.
struct Build {
    product: Product,
    evidence: BuildEvidence,
    configs: Vec<kconfig::Kconfig>,
}

fn load_build(fixture: &str) -> Build {
    let dir = variant_dir(fixture);
    let options = IngestOptions::new(&dir)
        .with_sysbuild(true)
        .with_west_list(dir.join("west-list.txt"))
        .with_identifier_db(manifest_dir().join("../rollcall-identifiers/db/identifiers.yaml"));
    let product = zephyr::ingest(&options)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .product;
    let mut evidence = BuildEvidence::new();
    let mut configs = Vec::new();
    for image in &product.images {
        let image_dir = dir.join(&image.name).join("zephyr");
        let config = read_config(&image_dir.join(".config"));
        evidence = evidence.with_kconfig(&image.name, config.clone());
        configs.push(config);
        let map_path = image_dir.join("zephyr.map");
        let text = std::fs::read_to_string(&map_path)
            .unwrap_or_else(|e| panic!("{}: {e}", map_path.display()));
        let map =
            linker_map::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", map_path.display()));
        let linked = linked_functions(&map)
            .unwrap_or_else(|e| panic!("{}: no link evidence: {e}", map_path.display()));
        evidence = evidence.with_linked_symbols(&image.name, linked);
    }
    Build {
        product,
        evidence,
        configs,
    }
}

fn read_config(path: &Path) -> kconfig::Kconfig {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    kconfig::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn builds() -> BTreeMap<&'static str, Build> {
    FIXTURES
        .iter()
        .map(|(name, _)| (*name, load_build(name)))
        .collect()
}

fn starter() -> RuleSet {
    vex::parse_rules(
        rollcall_identifiers::VEX_RULES_YAML,
        rollcall_identifiers::VEX_RULES_FILE_NAME,
    )
    .unwrap()
}

fn only(rules: &RuleSet, id: &str) -> RuleSet {
    RuleSet {
        rules: rules.rules.iter().filter(|r| r.id == id).cloned().collect(),
    }
}

/// Findings for every CVE of `rules`, against every component the rules match by name, with
/// the component's own purl, CPE and version.
fn findings_for(rules: &RuleSet, product: &Product) -> Vec<Finding> {
    let mut findings = BTreeSet::new();
    for rule in &rules.rules {
        let Some(name) = &rule.target.name else {
            panic!("starter rule {} does not match by name", rule.id)
        };
        for (_, _, node) in product.walk() {
            let NodeRef::Component(component) = node else {
                continue;
            };
            if &component.name != name {
                continue;
            }
            for cve in &rule.target.cves {
                findings.insert(Finding {
                    id: cve.clone(),
                    purl: component.purl.clone(),
                    name: component.name.clone(),
                    version: component.version.clone(),
                    aliases: BTreeSet::new(),
                    cpes: component.cpe.iter().cloned().collect(),
                    severity: None,
                    fixed_in: BTreeSet::new(),
                    scanner: Scanner::Grype,
                });
            }
        }
    }
    findings.into_iter().collect()
}

/// `bom-ref` → the name of the image the component is in.
fn images_by_ref(product: &Product) -> BTreeMap<String, String> {
    let mut image = String::new();
    let mut map = BTreeMap::new();
    for (_, bom_ref, node) in product.walk() {
        match node {
            NodeRef::Image(i) => image = i.name.clone(),
            NodeRef::Component(_) => {
                map.insert(bom_ref.as_str().to_owned(), image.clone());
            }
            NodeRef::Product(_) => {}
        }
    }
    map
}

/// The images in which `report` has a statement by rule `id`, sorted, each once.
fn firing_images(report: &Report, product: &Product, id: &str) -> Vec<String> {
    let images = images_by_ref(product);
    let fired: BTreeSet<String> = report
        .statements
        .iter()
        .filter(|s| s.rules.iter().any(|r| r == id))
        .map(|s| images[&s.component.bom_ref].clone())
        .collect();
    fired.into_iter().collect()
}

/// Evaluates rule `id` alone on `build` with findings for its own CVEs.
fn cell(rules: &RuleSet, id: &str, build: &Build) -> (Report, Vec<String>) {
    let rule = only(rules, id);
    let findings = findings_for(&rule, &build.product);
    let report = vex::evaluate(&build.product, &build.evidence, &findings, &rule);
    let fired = firing_images(&report, &build.product, id);
    (report, fired)
}

/// Rule × fixture → the images in which the rule gives a statement; empty: none.
///
/// Images: baseline (mcuboot, with_mcuboot), bt (beacon, mcuboot), tls (http_server, mcuboot),
/// old-mbedtls (mbedtls, mcuboot), smp-serial and smp-bt (mcuboot, smp_svr).
const TABLE: &[(&str, &str, &[&str])] = &[
    // Mbed TLS before 3.6.5 only: the old-mbedTLS build's Mbed TLS 3.6.4, in both images
    // (TLS 1.3 and X.509 writing are off in both, and both use config-mbedtls.h). The v4.4.2
    // builds have Mbed TLS 4.1.0.
    ("mbedtls-tls13-compiled-out", "baseline", &[]),
    ("mbedtls-tls13-compiled-out", "bt", &[]),
    ("mbedtls-tls13-compiled-out", "tls", &[]),
    (
        "mbedtls-tls13-compiled-out",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    ("mbedtls-tls13-compiled-out", "smp-serial", &[]),
    ("mbedtls-tls13-compiled-out", "smp-bt", &[]),
    ("mbedtls-x509-write-compiled-out", "baseline", &[]),
    ("mbedtls-x509-write-compiled-out", "bt", &[]),
    ("mbedtls-x509-write-compiled-out", "tls", &[]),
    (
        "mbedtls-x509-write-compiled-out",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    ("mbedtls-x509-write-compiled-out", "smp-serial", &[]),
    ("mbedtls-x509-write-compiled-out", "smp-bt", &[]),
    // Only the TLS build's http_server links the TLS handshakes (both sides, as
    // mbedtls_ssl_handshake_step calls both); its MCUboot, judged by its own map, does not.
    (
        "mbedtls-tls-server-not-linked",
        "baseline",
        &["mcuboot", "with_mcuboot"],
    ),
    (
        "mbedtls-tls-server-not-linked",
        "bt",
        &["beacon", "mcuboot"],
    ),
    ("mbedtls-tls-server-not-linked", "tls", &["mcuboot"]),
    (
        "mbedtls-tls-server-not-linked",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    (
        "mbedtls-tls-server-not-linked",
        "smp-serial",
        &["mcuboot", "smp_svr"],
    ),
    (
        "mbedtls-tls-server-not-linked",
        "smp-bt",
        &["mcuboot", "smp_svr"],
    ),
    (
        "mbedtls-tls-client-not-linked",
        "baseline",
        &["mcuboot", "with_mcuboot"],
    ),
    (
        "mbedtls-tls-client-not-linked",
        "bt",
        &["beacon", "mcuboot"],
    ),
    ("mbedtls-tls-client-not-linked", "tls", &["mcuboot"]),
    (
        "mbedtls-tls-client-not-linked",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    (
        "mbedtls-tls-client-not-linked",
        "smp-serial",
        &["mcuboot", "smp_svr"],
    ),
    (
        "mbedtls-tls-client-not-linked",
        "smp-bt",
        &["mcuboot", "smp_svr"],
    ),
    // CONFIG_BT=y in bt/beacon and smp-bt/smp_svr.
    (
        "zephyr-bluetooth-off",
        "baseline",
        &["mcuboot", "with_mcuboot"],
    ),
    ("zephyr-bluetooth-off", "bt", &["mcuboot"]),
    ("zephyr-bluetooth-off", "tls", &["http_server", "mcuboot"]),
    (
        "zephyr-bluetooth-off",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    (
        "zephyr-bluetooth-off",
        "smp-serial",
        &["mcuboot", "smp_svr"],
    ),
    ("zephyr-bluetooth-off", "smp-bt", &["mcuboot"]),
    // CONFIG_UART_MCUMGR=y in both smp_svr builds; CONFIG_SHELL=y in tls/http_server.
    (
        "zephyr-mcumgr-serial-off",
        "baseline",
        &["mcuboot", "with_mcuboot"],
    ),
    ("zephyr-mcumgr-serial-off", "bt", &["beacon", "mcuboot"]),
    ("zephyr-mcumgr-serial-off", "tls", &["mcuboot"]),
    (
        "zephyr-mcumgr-serial-off",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    ("zephyr-mcumgr-serial-off", "smp-serial", &["mcuboot"]),
    ("zephyr-mcumgr-serial-off", "smp-bt", &["mcuboot"]),
    // CONFIG_FILE_SYSTEM_LIB_LINK=y in tls/http_server only.
    (
        "zephyr-filesystem-off",
        "baseline",
        &["mcuboot", "with_mcuboot"],
    ),
    ("zephyr-filesystem-off", "bt", &["beacon", "mcuboot"]),
    ("zephyr-filesystem-off", "tls", &["mcuboot"]),
    (
        "zephyr-filesystem-off",
        "old-mbedtls",
        &["mbedtls", "mcuboot"],
    ),
    (
        "zephyr-filesystem-off",
        "smp-serial",
        &["mcuboot", "smp_svr"],
    ),
    ("zephyr-filesystem-off", "smp-bt", &["mcuboot", "smp_svr"]),
];

/// Table-driven: every starter rule × every fixture → the images it gives a statement in
/// (none where the table says so). The table covers every rule and fixture exactly once.
#[test]
fn starter_rules_table_rule_by_fixture() {
    let rules = starter();
    let ids: BTreeSet<&str> = rules.rules.iter().map(|r| r.id.as_str()).collect();
    let cells: BTreeSet<(&str, &str)> = TABLE.iter().map(|(r, f, _)| (*r, *f)).collect();
    assert_eq!(cells.len(), TABLE.len(), "a cell is listed twice");
    let expected: BTreeSet<(&str, &str)> = ids
        .iter()
        .flat_map(|r| FIXTURES.iter().map(move |(f, _)| (*r, *f)))
        .collect();
    assert_eq!(cells, expected, "the table must cover every rule × fixture");

    let builds = builds();
    let mut failures = Vec::new();
    for (rule, fixture, want) in TABLE {
        let (report, got) = cell(&rules, rule, &builds[fixture]);
        if got != *want {
            failures.push(format!(
                "{rule} × {fixture}: expected {want:?}, got {got:?}; unresolved: {:?}",
                report
                    .unresolved
                    .iter()
                    .map(|u| (&u.vulnerability, &u.reason))
                    .collect::<Vec<_>>()
            ));
        }
        for s in &report.statements {
            assert_eq!(s.status, Status::NotAffected, "{rule} × {fixture}");
            assert_eq!(s.justification, Some(Justification::CodeNotPresent));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Each rule fires on the build it was written for, and stays silent on every build that
/// compiles in (or links) the code it is about, or ships an unaffected version: the home
/// image and the silent images for each rule. (A build that also leaves the code out gets
/// the statement too; the table above lists those.)
#[test]
fn each_starter_rule_fires_on_its_fixture_and_is_silent_on_the_others() {
    /// A build and one of its images.
    type At = (&'static str, &'static str);
    const HOME: &[(&str, At, &[At])] = &[
        (
            "mbedtls-tls13-compiled-out",
            ("old-mbedtls", "mbedtls"),
            // Mbed TLS 4.1.0: not this rule's version range.
            &[
                ("baseline", "mcuboot"),
                ("bt", "mcuboot"),
                ("tls", "http_server"),
                ("tls", "mcuboot"),
                ("smp-serial", "mcuboot"),
                ("smp-bt", "mcuboot"),
            ],
        ),
        (
            "mbedtls-x509-write-compiled-out",
            ("old-mbedtls", "mbedtls"),
            // Mbed TLS 4.1.0: not this rule's version range.
            &[
                ("baseline", "mcuboot"),
                ("bt", "mcuboot"),
                ("tls", "http_server"),
                ("tls", "mcuboot"),
                ("smp-serial", "mcuboot"),
                ("smp-bt", "mcuboot"),
            ],
        ),
        (
            "mbedtls-tls-server-not-linked",
            ("old-mbedtls", "mbedtls"),
            &[("tls", "http_server")],
        ),
        (
            "mbedtls-tls-client-not-linked",
            ("old-mbedtls", "mbedtls"),
            &[("tls", "http_server")],
        ),
        (
            "zephyr-bluetooth-off",
            ("baseline", "with_mcuboot"),
            &[("bt", "beacon"), ("smp-bt", "smp_svr")],
        ),
        (
            "zephyr-mcumgr-serial-off",
            ("baseline", "with_mcuboot"),
            &[
                ("smp-serial", "smp_svr"),
                ("smp-bt", "smp_svr"),
                ("tls", "http_server"),
            ],
        ),
        (
            "zephyr-filesystem-off",
            ("baseline", "with_mcuboot"),
            &[("tls", "http_server")],
        ),
    ];
    let rules = starter();
    let listed: BTreeSet<&str> = HOME.iter().map(|(r, _, _)| *r).collect();
    let ids: BTreeSet<&str> = rules.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(listed, ids, "every starter rule needs a home build");
    let builds = builds();
    for (rule, (home, home_image), silent) in HOME {
        let (_, fired) = cell(&rules, rule, &builds[home]);
        assert!(
            fired.iter().any(|i| i == home_image),
            "{rule} does not fire on {home}/{home_image}: {fired:?}"
        );
        for (fixture, image) in *silent {
            let (_, fired) = cell(&rules, rule, &builds[fixture]);
            assert!(
                !fired.iter().any(|i| i == image),
                "{rule} fires on {fixture}/{image}"
            );
        }
    }
}

/// The TLS server and client rules are the two halves: with only the client linked, the
/// server rule fires and the client rule stays silent, and the other way round. (Hand-made
/// linked-symbol sets: on stock Zephyr a TLS image links both sides.) An image without a
/// map stays unknown.
#[test]
fn tls_server_and_client_rules_split_on_linked_handshake() {
    let rules = starter();
    let build = load_build("old-mbedtls");
    for (linked, fires, silent) in [
        (
            "mbedtls_ssl_handshake_client_step",
            "mbedtls-tls-server-not-linked",
            "mbedtls-tls-client-not-linked",
        ),
        (
            "mbedtls_ssl_tls13_handshake_server_step",
            "mbedtls-tls-client-not-linked",
            "mbedtls-tls-server-not-linked",
        ),
    ] {
        let evidence = build
            .evidence
            .clone()
            .with_linked_symbols("mbedtls", [linked])
            .with_linked_symbols("mcuboot", [linked]);
        let one = Build {
            product: build.product.clone(),
            evidence,
            configs: Vec::new(),
        };
        assert_eq!(
            cell(&rules, fires, &one).1,
            ["mbedtls", "mcuboot"],
            "{linked}"
        );
        assert!(cell(&rules, silent, &one).1.is_empty(), "{linked}");
    }
    // Only the application's map: MCUboot's Mbed TLS needs evidence.
    let mut evidence = build.evidence.clone();
    evidence.linked_symbols.remove("mcuboot");
    let one = Build {
        product: build.product.clone(),
        evidence,
        configs: Vec::new(),
    };
    let (report, fired) = cell(&rules, "mbedtls-tls-server-not-linked", &one);
    assert_eq!(fired, ["mbedtls"]);
    assert!(
        report
            .unresolved
            .iter()
            .all(|u| matches!(u.reason, Reason::NeedsEvidence { .. })),
        "{report:?}"
    );
}

/// A real map cut short anywhere in its memory map gives no link evidence: the cut map would
/// lack `mbedtls_ssl_handshake_client_step` and so wrongly say it is not linked.
#[test]
fn truncated_fixture_map_gives_no_evidence() {
    let path = variant_dir("tls").join("http_server/zephyr/zephyr.map");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(linked_functions(&linker_map::parse(&text).unwrap()).is_ok());
    let start = text.find("Linker script and memory map").unwrap();
    let end = text.find("\nOUTPUT(").unwrap();
    for tenth in 1..10 {
        let cut = start + (end - start) * tenth / 10;
        let cut = text.floor_char_boundary(cut);
        let map = linker_map::parse(&text[..cut]).unwrap();
        assert!(
            matches!(
                linked_functions(&map),
                Err(linker_map::NoLinkEvidence::Incomplete { .. })
            ),
            "cut at {tenth}/10"
        );
    }
}

/// The real builds' maps give link evidence (no LTO, no unsplit code outside the C runtime),
/// and only the TLS sample's application links the TLS handshakes, both sides of them: the
/// server sample links the client state machine too.
#[test]
fn fixture_maps_give_link_evidence() {
    let steps = [
        "mbedtls_ssl_handshake_client_step",
        "mbedtls_ssl_handshake_server_step",
    ];
    for (fixture, build) in builds() {
        for (image, linked) in &build.evidence.linked_symbols {
            assert!(!linked.is_empty(), "{fixture}/{image}");
            let tls = (fixture, image.as_str()) == ("tls", "http_server");
            for step in steps {
                assert_eq!(linked.contains(step), tls, "{fixture}/{image}: {step}");
            }
        }
        assert_eq!(build.evidence.linked_symbols.len(), 2, "{fixture}");
    }
}

fn old_mbedtls_grype() -> Vec<Finding> {
    let path = manifest_dir().join("tests/data/findings/zephyr-old-mbedtls.grype.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run scripts/capture-findings.sh", path.display()));
    let parsed = vex::parse_findings(&bytes).unwrap();
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    parsed.findings
}

/// The old-mbedTLS build (Mbed TLS 3.6.4, TLS 1.3 compiled out) with real grype output and
/// the whole starter pack, from Kconfig evidence only as `rollcall vex --starter-rules` has:
/// CVE-2026-34873 is `not_affected` / `code_not_present` in both images, the detail quoting
/// CONFIG_MBEDTLS_TLS_VERSION_1_3 and the evidence citing the `.config` line.
#[test]
fn old_mbedtls_tls13_compiled_out_is_not_affected_code_not_present_quoting_symbol() {
    let build = load_build("old-mbedtls");
    let mut evidence = build.evidence.clone();
    evidence.linked_symbols.clear();
    let report = vex::evaluate(&build.product, &evidence, &old_mbedtls_grype(), &starter());
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);

    let tls13: Vec<_> = report
        .statements
        .iter()
        .filter(|s| s.vulnerability == "CVE-2026-34873")
        .collect();
    assert_eq!(tls13.len(), 2, "{report:#?}");
    let images = images_by_ref(&build.product);
    let mut evidence_lines = Vec::new();
    for s in &tls13 {
        assert_eq!(s.component.name, "mbedtls");
        assert_eq!(s.status, Status::NotAffected);
        assert_eq!(s.justification, Some(Justification::CodeNotPresent));
        assert_eq!(
            s.justification.map(Justification::cyclonedx),
            Some("code_not_present")
        );
        assert_eq!(s.rules, ["mbedtls-tls13-compiled-out"]);
        let detail = s.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("CONFIG_MBEDTLS_TLS_VERSION_1_3"),
            "{detail}"
        );
        evidence_lines.extend(s.evidence.iter().cloned());
        assert!(images.contains_key(&s.component.bom_ref));
    }
    for line in [
        "mbedtls/zephyr/.config:299: CONFIG_MBEDTLS_TLS_VERSION_1_3 is not set",
        "mcuboot/zephyr/.config:386: CONFIG_MBEDTLS_TLS_VERSION_1_3 is not set",
    ] {
        assert!(
            evidence_lines.iter().any(|e| e == line),
            "missing {line:?} in {evidence_lines:?}"
        );
    }

    // The second Mbed TLS rule: X.509 writing compiled out.
    let x509: Vec<&str> = report
        .statements
        .iter()
        .filter(|s| s.rules == ["mbedtls-x509-write-compiled-out"])
        .map(|s| s.vulnerability.as_str())
        .collect();
    assert_eq!(x509, ["CVE-2026-34874", "CVE-2026-34874"]);
    for s in &report.statements {
        let detail = s.detail.as_deref().unwrap_or_default();
        assert!(detail.contains("CONFIG_MBEDTLS_CFG_FILE"), "{detail}");
        assert!(
            s.evidence
                .iter()
                .any(|e| e.ends_with("CONFIG_MBEDTLS_CFG_FILE is \"config-mbedtls.h\"")),
            "{:?}",
            s.evidence
        );
    }
    assert_eq!(report.statements.len(), 4, "{:#?}", report.statements);

    // The TLS client rule needs linker-map evidence, which `rollcall vex` cannot take yet.
    let client: Vec<_> = report
        .unresolved
        .iter()
        .filter(|u| u.vulnerability == "CVE-2026-25834")
        .collect();
    assert_eq!(client.len(), 2);
    for u in client {
        assert!(
            matches!(&u.reason, Reason::NeedsEvidence { rules, .. } if rules == &["mbedtls-tls-client-not-linked"]),
            "{:?}",
            u.reason
        );
    }
}

/// The whole pack on every build, with every rule's findings at once: no two rules disagree
/// (no conflict warnings), and the report is the same for findings in any order.
#[test]
fn starter_pack_has_no_conflicts_and_is_order_independent() {
    let rules = starter();
    for (name, build) in builds() {
        let mut findings = findings_for(&rules, &build.product);
        let report = vex::evaluate(&build.product, &build.evidence, &findings, &rules);
        assert!(report.warnings.is_empty(), "{name}: {:?}", report.warnings);
        assert!(
            !report
                .unresolved
                .iter()
                .any(|u| matches!(u.reason, Reason::Conflict { .. })),
            "{name}"
        );
        findings.reverse();
        let reversed = vex::evaluate(&build.product, &build.evidence, &findings, &rules);
        assert_eq!(
            report.to_json().unwrap(),
            reversed.to_json().unwrap(),
            "{name}"
        );
    }
}

/// Every `kconfig_off` rule's detail names the Kconfig symbol that decides it.
#[test]
fn every_kconfig_rule_detail_quotes_its_symbol() {
    for rule in starter().rules {
        let detail = rule.detail.as_deref().unwrap_or_default();
        assert_eq!(rule.status, Status::NotAffected, "{}", rule.id);
        assert_eq!(rule.justification, Some(Justification::CodeNotPresent));
        let deciding = rule.when.iter().find_map(|c| match c {
            Condition::KconfigOff(s) | Condition::SymbolNotLinked(s) => Some(s.as_str()),
            _ => None,
        });
        let Some(symbol) = deciding else {
            panic!("{} has no build-evidence condition", rule.id)
        };
        assert!(
            detail.contains(symbol),
            "{}: {detail:?} lacks {symbol}",
            rule.id
        );
    }
}

/// The starter pack's Kconfig symbols all appear in the real builds' `.config` files.
#[test]
fn starter_pack_lints_clean_against_fixture_configs() {
    let builds = builds();
    let reference = KconfigSymbols::from_configs(builds.values().flat_map(|b| b.configs.iter()));
    let findings = vex::lint_rules(&starter(), "vex-rules.yaml", &reference);
    assert!(findings.is_empty(), "{findings:#?}");
}

/// A rule with a typo in its Kconfig symbol (CONFIG_BTT) never fires, on any build, even where
/// the real symbol is off; the correctly spelt rule does fire there; and the lint warns.
#[test]
fn typo_kconfig_symbol_never_fires_and_lint_warns() {
    let path = manifest_dir().join("tests/data/vex/typo.rules.yml");
    let typo =
        vex::parse_rules(&std::fs::read_to_string(&path).unwrap(), "typo.rules.yml").unwrap();
    let builds = builds();
    for (name, build) in &builds {
        let findings = findings_for(&typo, &build.product);
        assert!(!findings.is_empty(), "{name}");
        let report = vex::evaluate(&build.product, &build.evidence, &findings, &typo);
        assert!(
            report.statements.is_empty(),
            "{name}: {:?}",
            report.statements
        );
        for u in &report.unresolved {
            match &u.reason {
                Reason::NeedsEvidence { rules, missing } => {
                    assert_eq!(rules, &["zephyr-bluetooth-off-typo"]);
                    assert!(
                        missing.iter().all(|m| m.contains("CONFIG_BTT is not in ")),
                        "{missing:?}"
                    );
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }
    // Control: the same finding on the baseline build gets a statement from the real rule.
    let baseline = &builds["baseline"];
    let findings = findings_for(&typo, &baseline.product);
    let real = only(&starter(), "zephyr-bluetooth-off");
    let report = vex::evaluate(&baseline.product, &baseline.evidence, &findings, &real);
    assert_eq!(report.statements.len(), 2, "{report:?}");

    let reference = KconfigSymbols::from_configs(builds.values().flat_map(|b| b.configs.iter()));
    let findings = vex::lint_rules(&typo, "typo.rules.yml", &reference);
    let [finding] = findings.as_slice() else {
        panic!("{findings:?}")
    };
    assert_eq!(finding.kind, LintKind::UnknownKconfigSymbol);
    assert_eq!(finding.rule, "zephyr-bluetooth-off-typo");
    assert_eq!(finding.symbol.as_deref(), Some("CONFIG_BTT"));
    assert!(
        finding
            .to_string()
            .contains("unknown Kconfig symbol CONFIG_BTT"),
        "{finding}"
    );
}
