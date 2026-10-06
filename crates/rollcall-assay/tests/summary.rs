//! SHA-138: the cryptographic inventory's Markdown summary.
//!
//! Reads the hand-written CBOM model fixture of rollcall-core
//! (`crates/rollcall-core/tests/data/cbom/sensor-node.cbom.model.json`) and compares the
//! summary with the golden `crates/rollcall-core/tests/golden/cbom/sensor-node.cbom.md`,
//! which only `scripts/regen-golden.sh` writes (running this test with `ROLLCALL_BLESS=1`).
//! Never edit it by hand.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use rollcall_assay::summary::{HEADER, to_markdown};
use rollcall_core::cyclonedx::Timestamp;
use rollcall_core::model::Product;

/// The fixed timestamp the CBOM goldens are rendered with (as rollcall-core's
/// `GOLDEN_TIMESTAMP`).
const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
/// The version the summary names: rollcall's, which is the workspace version.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn core_tests() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

fn fixture() -> Product {
    let path = core_tests().join("data/cbom/sensor-node.cbom.model.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    Product::from_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn golden_path() -> PathBuf {
    core_tests().join("golden/cbom/sensor-node.cbom.md")
}

fn render(product: &Product, timestamp: &str) -> String {
    to_markdown(product, &Timestamp::parse(timestamp).unwrap(), VERSION)
}

/// Writes a golden file for `ROLLCALL_BLESS=1` atomically (a copy of rollcall-core's
/// `tests/common` helper): a temporary file in the same directory, renamed into place.
fn bless(path: &Path, contents: &str) {
    let dir = path.parent().unwrap();
    std::fs::create_dir_all(dir).unwrap();
    let mut builder = tempfile::Builder::new();
    if let Ok(metadata) = std::fs::metadata(path) {
        builder.permissions(metadata.permissions());
    }
    let mut file = builder.tempfile_in(dir).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file.persist(path).unwrap();
}

/// TP2: the golden Markdown, rendered with the fixed timestamp.
#[test]
fn cbom_fixture_matches_golden_markdown() {
    let actual = render(&fixture(), GOLDEN_TIMESTAMP);
    let path = golden_path();
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        bless(&path, &actual);
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
        "{} differs from the summary; if the change is intended, run scripts/regen-golden.sh \
         and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

/// The table as parsed by a CommonMark/GFM parser: the header cells and each row's cells, as
/// rendered text.
fn parse_table(md: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let mut tables = 0;
    let mut header = Vec::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut in_head = false;
    let mut cell: Option<String> = None;
    for event in Parser::new_ext(md, Options::ENABLE_TABLES) {
        match event {
            Event::Start(Tag::Table(_)) => tables += 1,
            Event::Start(Tag::TableHead) => in_head = true,
            Event::End(TagEnd::TableHead) => in_head = false,
            Event::Start(Tag::TableRow) => rows.push(Vec::new()),
            Event::Start(Tag::TableCell) => cell = Some(String::new()),
            Event::End(TagEnd::TableCell) => {
                let text = cell.take().unwrap();
                if in_head {
                    header.push(text);
                } else {
                    rows.last_mut().unwrap().push(text);
                }
            }
            Event::Text(t) | Event::Code(t) => {
                if let Some(cell) = cell.as_mut() {
                    cell.push_str(&t);
                }
            }
            Event::Html(h) | Event::InlineHtml(h) => panic!("raw HTML {h:?}"),
            Event::Start(Tag::Link { .. }) => panic!("link in the summary"),
            _ => {}
        }
    }
    assert_eq!(tables, 1, "{md}");
    (header, rows)
}

/// AC2: a readable summary table with evidence and confidence columns: one row per evidence
/// entry, every locator shown, every confidence one of high/medium/low.
#[test]
fn table_has_evidence_and_confidence_columns_and_one_row_per_evidence() {
    let product = fixture();
    let md = render(&product, GOLDEN_TIMESTAMP);
    let (header, rows) = parse_table(&md);
    assert_eq!(header, HEADER);
    let column = |name: &str| header.iter().position(|h| h == name).unwrap();
    let (asset, evidence, confidence, reason) = (
        column("Asset"),
        column("Evidence"),
        column("Confidence"),
        column("Reason"),
    );

    let entries: Vec<_> = product
        .crypto_assets()
        .flat_map(|(_, _, c)| {
            let name = c.name.clone();
            c.crypto
                .iter()
                .flat_map(|a| a.evidence.iter())
                .map(move |e| (name.clone(), e.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(entries.len(), 9);
    assert_eq!(rows.len(), entries.len(), "{md}");
    for (row, (name, entry)) in rows.iter().zip(&entries) {
        assert_eq!(row.len(), HEADER.len(), "{row:?}");
        assert_eq!(row[asset], *name);
        assert_eq!(row[evidence], entry.locator.to_string());
        assert_eq!(row[confidence], entry.confidence.as_str());
        assert_eq!(row[reason], entry.reason());
    }
    let levels: BTreeSet<&str> = rows.iter().map(|r| r[confidence].as_str()).collect();
    assert_eq!(levels, BTreeSet::from(["high", "low", "medium"]));
    for row in &rows {
        assert!(["high", "medium", "low"].contains(&row[confidence].as_str()));
    }
    // Details are readable words, e.g. the AES row.
    let aes = rows.iter().find(|r| r[asset] == "AES-128-GCM").unwrap();
    assert!(aes[column("Details")].contains("gcm"), "{aes:?}");
    assert_eq!(aes[column("In")], "sensor-app / mbedtls@3.6.0");
    assert_eq!(aes[column("Type")], "algorithm");
    // SHA-333: curve and padding are shown in the Details cell.
    let ecdsa = rows.iter().find(|r| r[asset] == "ECDSA-P256").unwrap();
    assert!(
        ecdsa[column("Details")].contains("curve secp256r1"),
        "{ecdsa:?}"
    );
    assert!(!ecdsa[column("Details")].contains("padding"), "{ecdsa:?}");
    let rsa = rows.iter().find(|r| r[asset] == "RSA-2048").unwrap();
    assert!(
        rsa[column("Details")].contains("padding pkcs1v15"),
        "{rsa:?}"
    );
    assert!(!rsa[column("Details")].contains("curve"), "{rsa:?}");
}

/// Determinism, and the timestamp is the only thing a different `--timestamp` changes.
#[test]
fn summary_is_deterministic_and_only_the_timestamp_line_varies() {
    let product = fixture();
    let a = render(&product, GOLDEN_TIMESTAMP);
    assert_eq!(a, render(&product, GOLDEN_TIMESTAMP));
    let b = render(&product, "2030-05-06T07:08:09Z");
    let differing: Vec<(&str, &str)> = a.lines().zip(b.lines()).filter(|(x, y)| x != y).collect();
    assert_eq!(a.lines().count(), b.lines().count());
    assert_eq!(differing.len(), 1, "{differing:?}");
    assert!(differing[0].0.starts_with("Generated "));
}

/// An inventory without assets says so, with no table.
#[test]
fn empty_inventory_says_no_cryptographic_assets() {
    let product = Product::new("sensor-node").unwrap().with_version("1.0.0");
    let md = render(&product, GOLDEN_TIMESTAMP);
    assert_eq!(
        md,
        format!(
            "# Cryptographic inventory: sensor-node 1.0.0\n\nGenerated {GOLDEN_TIMESTAMP} by \
             rollcall {VERSION}.\n\nNo cryptographic assets.\n"
        )
    );
}
