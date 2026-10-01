//! The identifier database lint (SHA-104): `rollcall_core::identify::lint` on the shipped
//! database, the hand-written bad databases in `tests/data/identifiers/`, malformed text and
//! the E2 fixtures.

use std::path::{Path, PathBuf};

use proptest::prelude::*;
use rollcall_core::identify::DbVersion;
use rollcall_core::identify::lint::{
    Finding, Rule, lint_fixtures, lint_text, module_blocks, module_keys,
};

const SHIPPED: &str = rollcall_identifiers::IDENTIFIERS_YAML;

fn data(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/identifiers")
        .join(name)
        .join("identifiers.yaml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn fixtures_zephyr() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr")
}

fn crate_version() -> DbVersion {
    rollcall_identifiers::DB_VERSION.parse().unwrap()
}

/// The single finding, or a panic listing them all.
fn only(findings: &[Finding]) -> &Finding {
    assert_eq!(findings.len(), 1, "{findings:#?}");
    &findings[0]
}

/// The 1-based line of the first line of `text` containing `needle`.
fn line_of(text: &str, needle: &str) -> u32 {
    let n = text.lines().position(|l| l.contains(needle)).unwrap();
    u32::try_from(n + 1).unwrap()
}

#[test]
fn bad_purl_reports_path_line_and_reason() {
    let text = data("bad-purl");
    let lint = lint_text("identifiers.yaml", &text, None);
    assert!(lint.db.is_none());
    let f = only(&lint.findings);
    assert_eq!(f.rule, Rule::Purl);
    assert_eq!(f.line, Some(line_of(&text, "'pkg:github/foo'")));
    assert_eq!(
        f.to_string(),
        format!(
            "identifiers.yaml:{}: purl: modules.beta.purl: template has no {{version}} placeholder",
            f.line.unwrap()
        )
    );
    // A template that renders to something that is not a purl at all.
    let text = SHIPPED.replace(
        "'pkg:generic/zcbor@{version}?vcs_url=git+https://github.com/NordicSemiconductor/zcbor'",
        "'pkg:x{version}'",
    );
    let f = only(&lint_text("identifiers.yaml", &text, None).findings).clone();
    assert_eq!(f.rule, Rule::Purl, "{f}");
    assert_eq!(f.line, Some(line_of(&text, "'pkg:x{version}'")));
    assert!(f.message.starts_with("modules.zcbor.purl: "), "{f}");
}

#[test]
fn duplicate_name_reports_both_lines() {
    let text = data("duplicate-name");
    let lint = lint_text("identifiers.yaml", &text, None);
    assert!(lint.db.is_none());
    let f = only(&lint.findings);
    assert_eq!(f.rule, Rule::Duplicate);
    let first = line_of(&text, "  alpha:");
    let second = u32::try_from(
        text.lines()
            .enumerate()
            .filter(|(_, l)| *l == "  alpha:")
            .nth(1)
            .unwrap()
            .0
            + 1,
    )
    .unwrap();
    assert_eq!(f.line, Some(second));
    assert_eq!(
        f.to_string(),
        format!(
            "identifiers.yaml:{second}: duplicate: module alpha is listed twice (lines {first} and {second})"
        )
    );
}

#[test]
fn bad_cpe_reports_reason() {
    let text = data("bad-cpe");
    let f = only(&lint_text("identifiers.yaml", &text, None).findings).clone();
    assert_eq!(f.rule, Rule::Cpe);
    assert_eq!(f.line, Some(line_of(&text, "cpe:2.3:a:beta")));
    assert!(f.message.contains("modules.beta.cpe"), "{f}");
    assert!(f.message.contains("13 :-separated fields"), "{f}");
    // A repeated alias is a cpe finding located at its module.
    let text = SHIPPED.replace(
        "cpe_aliases: ['cpe:2.3:a:cjson_project:cjson:{version}:*:*:*:*:*:*:*']",
        "cpe_aliases: ['cpe:2.3:a:davegamble:cjson:{version}:*:*:*:*:*:*:*']",
    );
    let f = only(&lint_text("identifiers.yaml", &text, None).findings).clone();
    assert_eq!(f.rule, Rule::Cpe, "{f}");
    assert_eq!(f.line, Some(line_of(&text, "  cjson:")));
    assert!(f.message.contains("cpe_aliases repeats"), "{f}");
}

#[test]
fn version_mismatch_reports_expected() {
    let current = crate_version();
    let expected: DbVersion = "9.9.9".parse().unwrap();
    let f = only(&lint_text("identifiers.yaml", SHIPPED, Some(&expected)).findings).clone();
    assert_eq!(f.rule, Rule::VersionMismatch);
    assert_eq!(f.line, Some(line_of(SHIPPED, "db_version: '")));
    assert!(
        f.message.contains(&format!(
            "db_version {current} differs from the expected 9.9.9"
        )),
        "{f}"
    );
    // No db_version, or one outside the pin, is a db-version finding.
    let text = SHIPPED.replace(&format!("db_version: '{current}'\n"), "");
    let f = only(&lint_text("identifiers.yaml", &text, None).findings).clone();
    assert_eq!(f.rule, Rule::DbVersion);
    assert!(f.message.starts_with("no db_version"), "{f}");
    for (name, needle) in [
        ("too-old", "older than 1.0.0"),
        ("schema-2", "major version 2"),
    ] {
        let f = only(&lint_text("identifiers.yaml", &data(name), None).findings).clone();
        assert_eq!((f.rule, f.line), (Rule::DbVersion, Some(4)), "{name}");
        assert!(f.message.contains(needle), "{f}");
    }
    let text = SHIPPED.replace(&format!("db_version: '{current}'"), "db_version: '1.0'");
    let f = only(&lint_text("identifiers.yaml", &text, None).findings).clone();
    assert_eq!(f.rule, Rule::DbVersion, "{f}");
}

#[test]
fn every_bad_entry_is_reported_not_only_the_first() {
    // A duplicate, a bad purl and a bad cpe in three different places: the loader stops at
    // the first, the lint names all three, each at its own line.
    let start = SHIPPED.find("  fatfs:\n").unwrap();
    let end = SHIPPED.find("  hal_espressif:\n").unwrap();
    let text = format!(
        "{}{}{}",
        &SHIPPED[..end],
        &SHIPPED[start..end],
        &SHIPPED[end..]
    )
    .replace(
        "'pkg:generic/zcbor@{version}?vcs_url=git+https://github.com/NordicSemiconductor/zcbor'",
        "'pkg:generic/zcbor?vcs_url=git+https://github.com/NordicSemiconductor/zcbor'",
    )
    .replace(
        "'cpe:2.3:a:semtech:loramac-node:{version}:*:*:*:*:*:*:*'",
        "'cpe:2.3:a:semtech:{version}:*:*:*:*:*:*:*'",
    );
    let lint = lint_text("identifiers.yaml", &text, None);
    assert!(lint.db.is_none());
    let got: Vec<(Rule, u32)> = lint
        .findings
        .iter()
        .map(|f| (f.rule, f.line.unwrap()))
        .collect();
    let second_fatfs = u32::try_from(
        text.lines()
            .enumerate()
            .filter(|(_, l)| *l == "  fatfs:")
            .nth(1)
            .unwrap()
            .0
            + 1,
    )
    .unwrap();
    let mut want = vec![
        (Rule::Duplicate, second_fatfs),
        (Rule::Purl, line_of(&text, "'pkg:generic/zcbor?vcs_url")),
        (Rule::Cpe, line_of(&text, "'cpe:2.3:a:semtech:{version}")),
    ];
    want.sort_by_key(|(_, line)| *line);
    let mut got_sorted = got.clone();
    got_sorted.sort_by_key(|(_, line)| *line);
    assert_eq!(got_sorted, want, "{:#?}", lint.findings);
}

#[test]
fn module_blocks_span_each_entry() {
    let text = "schema: 1\nmodules:\n  a:\n    x: 1\n  # c\n  b:\n    y: 2\nother: 1\n";
    let blocks = module_blocks(text);
    let spans: Vec<(&str, u32, u32)> = blocks
        .iter()
        .map(|b| (b.name.as_str(), b.start, b.end))
        .collect();
    assert_eq!(spans, [("a", 3, 6), ("b", 6, 8)]);
    let blocks = module_blocks("modules:\n  a:\n    x: 1");
    assert_eq!((blocks[0].start, blocks[0].end), (2, 4));
}

#[test]
fn unsorted_entries_reported() {
    // Move zephyr (last) before cjson (first).
    let start = SHIPPED.find("  zephyr:\n").unwrap();
    let zephyr = &SHIPPED[start..];
    let without = &SHIPPED[..start];
    let text = without.replacen("  cjson:\n", &format!("{zephyr}  cjson:\n"), 1);
    let lint = lint_text("identifiers.yaml", &text, None);
    assert!(lint.db.is_some(), "still a valid database");
    let f = only(&lint.findings);
    assert_eq!(f.rule, Rule::Unsorted);
    assert_eq!(f.line, Some(line_of(&text, "  cjson:")));
    assert!(
        f.message
            .starts_with("module cjson comes after zephyr (line "),
        "{f}"
    );
}

#[test]
fn self_resolve_reports_rows_without_a_cpe() {
    // A manual-table version that cannot be put in a CPE (whitespace).
    let text = SHIPPED.replace(
        "'f4ead3bf4a6dab3a07d7b5f5315795c073db568d': '0.16'",
        "'f4ead3bf4a6dab3a07d7b5f5315795c073db568d': '0 16'",
    );
    let lint = lint_text("identifiers.yaml", &text, None);
    let f = only(&lint.findings);
    assert_eq!(f.rule, Rule::SelfResolve, "{f}");
    assert_eq!(f.line, Some(line_of(&text, "  fatfs:")));
    assert!(
        f.message
            .starts_with("module fatfs revision f4ead3bf4a6dab3a07d7b5f5315795c073db568d: no cpe"),
        "{f}"
    );
}

#[test]
fn clean_db_has_no_findings() {
    let lint = lint_text("identifiers.yaml", SHIPPED, Some(&crate_version()));
    assert_eq!(lint.findings, [], "the shipped database lints clean");
    let db = lint.db.unwrap();
    assert_eq!(
        db.db_version().map(ToString::to_string).as_deref(),
        Some(rollcall_identifiers::DB_VERSION)
    );
    // Every module of every E2 fixture build resolves to a purl from the database.
    let fixtures = lint_fixtures(&db, "identifiers.yaml", &fixtures_zephyr());
    assert_eq!(fixtures.findings, []);
    assert_eq!(fixtures.builds.len(), 3);
    assert_eq!(fixtures.modules, 36);
}

#[test]
fn fixture_resolution_reports_missing_modules() {
    // Drop cmsis_6, which every fixture build uses.
    let start = SHIPPED.find("  cmsis_6:\n").unwrap();
    let end = start + SHIPPED[start..].find("  fatfs:\n").unwrap();
    let text = format!("{}{}", &SHIPPED[..start], &SHIPPED[end..]);
    let lint = lint_text("identifiers.yaml", &text, None);
    assert_eq!(lint.findings, []);
    let fixtures = lint_fixtures(&lint.db.unwrap(), "identifiers.yaml", &fixtures_zephyr());
    assert_eq!(fixtures.findings.len(), 3, "{:#?}", fixtures.findings);
    for (f, variant) in fixtures.findings.iter().zip(["baseline", "bt", "tls"]) {
        assert_eq!(f.rule, Rule::FixtureResolve);
        assert!(
            f.message
                .ends_with(&format!("{variant}: module cmsis_6 is not in the database")),
            "{f}"
        );
    }
    // A directory without builds is a finding, not a pass.
    let empty = tempfile::tempdir().unwrap();
    let db = lint_text("identifiers.yaml", SHIPPED, None).db.unwrap();
    let fixtures = lint_fixtures(&db, "identifiers.yaml", empty.path());
    let f = only(&fixtures.findings);
    assert!(f.message.starts_with("no fixture builds"), "{f}");
    let fixtures = lint_fixtures(&db, "identifiers.yaml", &empty.path().join("absent"));
    assert_eq!(fixtures.findings.len(), 1);
    // A single build directory can be given directly.
    let fixtures = lint_fixtures(&db, "identifiers.yaml", &fixtures_zephyr().join("tls"));
    assert_eq!((fixtures.builds.len(), fixtures.findings.len()), (1, 0));
}

#[test]
fn module_keys_reads_block_keys_only() {
    let text = "schema: 1\nmodules:   # the modules\n  # a comment\n  a:\n    upstream: {name: A}\n  'b c':\n  \"d\": \n  - e\nother:\n  f:\n";
    assert_eq!(
        module_keys(text),
        [
            ("a".to_owned(), 4),
            ("b c".to_owned(), 6),
            ("d".to_owned(), 7)
        ]
    );
    assert_eq!(module_keys("modules: {a: 1, b: 2}\n"), []);
    assert_eq!(module_keys(""), []);
    let keys = module_keys(SHIPPED);
    let db = lint_text("identifiers.yaml", SHIPPED, None).db.unwrap();
    let names: Vec<&str> = db.modules().map(|(name, _)| name).collect();
    let scanned: Vec<&str> = keys.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        scanned, names,
        "the line scan sees exactly the loaded modules"
    );
}

/// Malformed databases: each gives findings (never a pass, never a panic).
#[test]
fn malformed_yaml_is_finding_not_panic() {
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("whitespace", " \n\t\n".to_owned()),
        (
            "cut inside a quoted scalar",
            SHIPPED[..SHIPPED.find("purl: '").unwrap() + 8].to_owned(),
        ),
        (
            "cut after a key",
            SHIPPED[..SHIPPED.find("    version_rule:").unwrap() + 17].to_owned(),
        ),
        ("tab indented", "schema: 1\nmodules:\n\ta: 1\n".to_owned()),
        ("NUL", "schema: 1\u{0}\nmodules: {}\n".to_owned()),
        ("not a mapping", "- 1\n- 2\n".to_owned()),
        ("modules as list", "schema: 1\nmodules: [a]\n".to_owned()),
        (
            "entry as scalar",
            "schema: 1\ndb_version: '1.0.0'\nmodules:\n  a: x\n".to_owned(),
        ),
        ("schema 2", "schema: 2\nmodules: {}\n".to_owned()),
        (
            "unknown key",
            SHIPPED.replace("schema: 1\n", "schema: 1\nextra: 1\n"),
        ),
        (
            "deep",
            format!("schema: 1\nmodules: {}", "[".repeat(10_000)),
        ),
        ("quote at end", "schema: 1\nmodules:\n  '".to_owned()),
        (
            "multibyte keys",
            "schema: 1\nmodules:\n  ü:\n  'é\n".to_owned(),
        ),
    ];
    for (what, text) in cases {
        let lint = std::panic::catch_unwind(|| lint_text("identifiers.yaml", &text, None))
            .unwrap_or_else(|_| panic!("{what}: panicked"));
        assert!(!lint.findings.is_empty(), "{what}: no finding");
        for f in &lint.findings {
            assert!(f.to_string().starts_with("identifiers.yaml"), "{what}: {f}");
            assert!(!f.message.is_empty(), "{what}");
        }
    }
}

#[test]
fn byte_order_mark_is_accepted() {
    // YAML allows a leading BOM; the shipped database with one still lints clean.
    let text = format!("\u{feff}{SHIPPED}");
    assert_eq!(lint_text("identifiers.yaml", &text, None).findings, []);
}

proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in "\\PC{0,300}") {
        let _ = lint_text("identifiers.yaml", &text, None);
        let _ = module_keys(&text);
    }

    #[test]
    fn mutated_shipped_database_never_panics(cut in 0usize..SHIPPED.len(), insert in "[ :{}\\[\\]'\"#&*!|>\\-\\n\\t]{0,4}") {
        let mut text = SHIPPED.get(..cut).unwrap_or(SHIPPED).to_owned();
        text.push_str(&insert);
        text.push_str(SHIPPED.get(cut..).unwrap_or(""));
        let _ = lint_text("identifiers.yaml", &text, None);
    }
}
