//! The readiness report (SHA-120): a golden Markdown and JSON report for every fixture, the
//! JSON against `docs/report-schema.json`, the Markdown as GitHub-flavoured Markdown, and the
//! diff between two builds.
//!
//! The goldens under `tests/golden/report/` are written only by `scripts/regen-golden.sh`
//! (this test with `ROLLCALL_BLESS=1`). Never edit them by hand.
//!
//! The SBOMs reported on are rendered here, never committed: the hand-written model fixtures
//! of `tests/data/` (rendered as `rollcall generate --model` writes them), the blob manifest,
//! and every real Zephyr build under `fixtures/` ingested as `rollcall generate --zephyr DIR
//! --sysbuild --west-list DIR/west-list.txt --identify` does (with the embedded seed
//! identifier database), so unresolved modules reflect real use.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use common::{GOLDEN_TIMESTAMP, load_fixture};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions};
use rollcall_core::identify::{self, DbSource};
use rollcall_core::model::{Component, Cpe, Product, Purl};
use rollcall_core::report::{
    self, Input, ReadinessReport, ReportError, SbomIdentity, VexInputError, VexStatus, md_cell,
    parse_vex,
};
use rollcall_core::severity::{Severity, normalise_severity};
use rollcall_core::zephyr::{self, IngestOptions};
use serde_json::Value;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn data(path: &str) -> PathBuf {
    manifest_dir().join("tests/data").join(path)
}

fn golden_dir() -> PathBuf {
    manifest_dir().join("tests/golden/report")
}

fn blessing() -> bool {
    std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1")
}

fn timestamp() -> Timestamp {
    Timestamp::parse(GOLDEN_TIMESTAMP).unwrap()
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if blessing() {
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
        "{} differs from the report; if the change is intended, run scripts/regen-golden.sh \
         and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

// --- The fixtures ------------------------------------------------------------------------------

/// A real Zephyr build: its golden name, and its sysbuild directory under `fixtures/`.
const REAL_BUILDS: [(&str, &str); 6] = [
    ("zephyr-baseline", "zephyr/baseline"),
    ("zephyr-bt", "zephyr/bt"),
    ("zephyr-tls", "zephyr/tls"),
    ("zephyr-old-mbedtls", "zephyr-old-mbedtls/old-mbedtls"),
    ("zephyr-smp-serial", "zephyr-smp/smp-serial"),
    ("zephyr-smp-bt", "zephyr-smp/smp-bt"),
];

/// Every hand-written model fixture of `tests/data/`, with the scans and VEX documents its
/// report reads (captured scanner output, the blessed VEX golden).
const MODEL_FIXTURES: [(&str, &[&str], &[&str]); 5] = [
    ("clean", &[], &[]),
    ("minimal", &[], &[]),
    ("old-heapless", &["findings/old-heapless.osv.json"], &[]),
    (
        "old-mbedtls",
        &[
            "findings/old-mbedtls.grype.json",
            "findings/old-mbedtls.osv.json",
        ],
        &["vex/old-mbedtls.vex.cdx.json"],
    ),
    ("widget", &[], &[]),
];

fn fixtures_root() -> PathBuf {
    manifest_dir().join("../../fixtures")
}

/// The product of a real build, ingested with its west list and the embedded seed identifier
/// database, as `rollcall generate --zephyr DIR --sysbuild --west-list … --identify` does.
fn ingest_real(dir: &str) -> Product {
    let root = fixtures_root().join(dir);
    let options = IngestOptions::new(&root)
        .with_sysbuild(true)
        .with_west_list(root.join("west-list.txt"));
    let db = identify::builtin().unwrap();
    zephyr::ingest_with_db(&options, Some(&db))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .product
}

/// `product` as CycloneDX, as `rollcall generate --timestamp <golden>` writes it; with the
/// embedded database's provenance for a real build.
fn render(product: &Product, identified: bool) -> String {
    let mut options = WriteOptions::new(timestamp());
    if identified {
        let db = identify::builtin().unwrap();
        options = options.with_properties(identify::provenance(&db, &DbSource::Embedded));
    }
    cyclonedx::write(product, &options).unwrap()
}

/// The real builds' products, ingested once per test run.
fn real_products() -> &'static BTreeMap<&'static str, Product> {
    static PRODUCTS: OnceLock<BTreeMap<&'static str, Product>> = OnceLock::new();
    PRODUCTS.get_or_init(|| {
        REAL_BUILDS
            .iter()
            .map(|(name, dir)| (*name, ingest_real(dir)))
            .collect()
    })
}

/// One report case: the SBOM text, and the scan and VEX files (name, bytes).
struct Case {
    sbom: String,
    scans: Vec<(String, Vec<u8>)>,
    vex: Vec<(String, Vec<u8>)>,
}

fn file(path: &Path) -> (String, Vec<u8>) {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    (name, bytes)
}

/// The report case for the golden `name`.
fn case(name: &str) -> Case {
    if let Some(product) = real_products().get(name) {
        return Case {
            sbom: render(product, true),
            scans: Vec::new(),
            vex: Vec::new(),
        };
    }
    if name == "blobs" {
        return Case {
            sbom: render(&common::blob_product(), false),
            scans: Vec::new(),
            vex: Vec::new(),
        };
    }
    let (_, scans, vex) = MODEL_FIXTURES
        .iter()
        .find(|(n, _, _)| *n == name)
        .unwrap_or_else(|| panic!("no fixture {name}"));
    Case {
        sbom: render(&load_fixture(name), false),
        scans: scans.iter().map(|s| file(&data(s))).collect(),
        vex: vex
            .iter()
            .map(|v| file(&manifest_dir().join("tests/golden").join(v)))
            .collect(),
    }
}

fn inputs(list: &[(String, Vec<u8>)]) -> Vec<Input<'_>> {
    list.iter()
        .map(|(name, bytes)| Input {
            name: name.as_str(),
            bytes: bytes.as_slice(),
        })
        .collect()
}

fn build(sbom: &str, scans: &[(String, Vec<u8>)], vex: &[(String, Vec<u8>)]) -> ReadinessReport {
    report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: sbom.as_bytes(),
        },
        &inputs(scans),
        &inputs(vex),
        &timestamp(),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn report_of(name: &str) -> ReadinessReport {
    let c = case(name);
    build(&c.sbom, &c.scans, &c.vex)
}

/// Every golden name: the model fixtures, the blob manifest and the real builds.
fn all_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = MODEL_FIXTURES.iter().map(|(n, _, _)| *n).collect();
    names.push("blobs");
    names.extend(REAL_BUILDS.iter().map(|(n, _)| *n));
    names.sort();
    names
}

fn check_report_goldens(name: &str) {
    let report = report_of(name);
    check_golden(
        &format!("{name}.report.json"),
        &report::to_json(&report).unwrap(),
    );
    check_golden(&format!("{name}.report.md"), &report::to_markdown(&report));
}

// --- AC: report generated for every fixture; the clean fixture scores 100 -------------------

/// Every fixture has both goldens, and every golden is a fixture's. The fixture lists here
/// are the whole of `tests/data/*.model.json` and every real build under `fixtures/`.
#[test]
fn every_fixture_has_md_and_json_report_goldens() {
    if blessing() {
        // The bless pass writes them; the second pass checks.
        return;
    }
    let models: Vec<&str> = MODEL_FIXTURES.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        models,
        common::fixture_names(),
        "MODEL_FIXTURES must list every tests/data/*.model.json"
    );
    let mut on_disk = Vec::new();
    for group in ["zephyr", "zephyr-old-mbedtls", "zephyr-smp"] {
        for entry in std::fs::read_dir(fixtures_root().join(group)).unwrap() {
            let path = entry.unwrap().path();
            if path.join("build_info.yml").is_file() {
                let variant = path.file_name().unwrap().to_string_lossy().into_owned();
                on_disk.push(format!("{group}/{variant}"));
            }
        }
    }
    on_disk.sort();
    let mut listed: Vec<String> = REAL_BUILDS.iter().map(|(_, d)| d.to_string()).collect();
    listed.sort();
    assert_eq!(listed, on_disk, "REAL_BUILDS must list every real build");
    let mut expected: Vec<String> = all_names()
        .iter()
        .flat_map(|n| [format!("{n}.report.json"), format!("{n}.report.md")])
        .collect();
    expected.sort();
    let mut goldens: Vec<String> = std::fs::read_dir(golden_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    goldens.sort();
    assert_eq!(goldens, expected);
}

#[test]
fn clean_report_matches_golden() {
    check_report_goldens("clean");
}

#[test]
fn minimal_report_matches_golden() {
    check_report_goldens("minimal");
}

#[test]
fn widget_report_matches_golden() {
    check_report_goldens("widget");
}

#[test]
fn blobs_report_matches_golden() {
    check_report_goldens("blobs");
}

#[test]
fn old_heapless_report_matches_golden() {
    check_report_goldens("old-heapless");
}

#[test]
fn old_mbedtls_report_matches_golden() {
    check_report_goldens("old-mbedtls");
}

#[test]
fn zephyr_baseline_report_matches_golden() {
    check_report_goldens("zephyr-baseline");
}

#[test]
fn zephyr_bt_report_matches_golden() {
    check_report_goldens("zephyr-bt");
}

#[test]
fn zephyr_tls_report_matches_golden() {
    check_report_goldens("zephyr-tls");
}

#[test]
fn zephyr_old_mbedtls_report_matches_golden() {
    check_report_goldens("zephyr-old-mbedtls");
}

#[test]
fn zephyr_smp_serial_report_matches_golden() {
    check_report_goldens("zephyr-smp-serial");
}

#[test]
fn zephyr_smp_bt_report_matches_golden() {
    check_report_goldens("zephyr-smp-bt");
}

/// The clean fixture (every node identified, hashed, licensed and passing both profiles)
/// scores 100 with no warnings, no unresolved module and no validation finding; every other
/// fixture scores less.
#[test]
fn clean_fixture_scores_100_with_no_warnings() {
    let report = report_of("clean");
    assert_eq!(report.score.value, 100);
    assert_eq!(report.score.basis_points, 10_000);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
    assert!(report.validation.schema.valid);
    assert!(report.validation.profiles.passed);
    assert!(report.validation.profiles.findings.is_empty());
    for c in &report.score.categories {
        if c.assessed {
            assert_eq!(c.earned, u64::from(c.weight) * 10_000, "{}", c.id);
        }
    }
    let md = report::to_markdown(&report);
    assert!(md.contains("**100 / 100**"), "{md}");
    assert!(md.contains("## Warnings\n\nNone.\n"), "{md}");
    // The summary tells a reader that no scan was supplied.
    assert!(
        report
            .summary
            .contains("No vulnerability scan was supplied")
    );
    for name in all_names().into_iter().filter(|n| *n != "clean") {
        let other = report_of(name);
        assert!(other.score.value < 100, "{name}: {}", other.score.value);
    }
}

/// With the seed database, the real builds resolve every module except the two the database
/// does not list for Zephyr v4.2.0 (`cmsis-6`, `hal-nordic`, renamed in that release); each
/// unresolved entry has a stub naming the module, prefilled from its GitHub purl.
#[test]
fn unresolved_modules_have_paste_ready_stubs() {
    for (name, _) in REAL_BUILDS {
        let report = report_of(name);
        let unresolved: BTreeSet<&str> =
            report.unresolved.iter().map(|u| u.name.as_str()).collect();
        if name == "zephyr-old-mbedtls" {
            assert_eq!(
                unresolved,
                BTreeSet::from(["cmsis-6", "hal-nordic"]),
                "{name}"
            );
        } else {
            assert!(unresolved.is_empty(), "{name}: {unresolved:?}");
        }
        for u in &report.unresolved {
            assert_eq!(u.reason, "module-not-in-identifier-db");
            assert!(
                u.hint.starts_with(&format!("  {}:\n", u.name)),
                "{}",
                u.hint
            );
            let repo = u.name.replace('-', "_");
            assert!(
                u.hint.contains(&format!(
                    "pkg:github/zephyrproject-rtos/{repo}@v{{version}}"
                )),
                "{}",
                u.hint
            );
            let version = u.version.as_deref().unwrap();
            assert!(
                u.hint.contains(&format!("\"{version}\": \"\"")),
                "{}",
                u.hint
            );
            // Valid YAML under `modules:` as printed.
            let yaml = format!("schema: 1\nmodules:\n{}", u.hint);
            let value: yaml_serde::Value = yaml_serde::from_str(&yaml).unwrap();
            assert!(value["modules"][u.name.as_str()].is_mapping());
        }
    }
    // Without the database every module of a real build is unresolved.
    let root = fixtures_root().join("zephyr/baseline");
    let options = IngestOptions::new(&root)
        .with_sysbuild(true)
        .with_west_list(root.join("west-list.txt"));
    let product = zephyr::ingest(&options).unwrap().product;
    let report = build(&render(&product, false), &[], &[]);
    let modules = report
        .score
        .categories
        .iter()
        .find(|c| c.id == "modules")
        .unwrap();
    assert!(modules.denominator > 0);
    assert_eq!(modules.numerator, 0);
    assert_eq!(report.unresolved.len() as u64, modules.denominator);
    // A component with no identifier at all is listed too (the widget's kernel).
    let widget = report_of("widget");
    assert!(
        widget
            .unresolved
            .iter()
            .any(|u| u.name == "kernel" && u.reason == "no-identifier"),
        "{:?}",
        widget.unresolved
    );
}

// --- AC: the JSON validates against its schema; the Markdown renders in GitHub --------------

fn schema() -> Value {
    let path = manifest_dir().join("../../docs/report-schema.json");
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn validator() -> jsonschema::Validator {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&schema())
        .unwrap()
}

/// Every fixture's JSON report validates against `docs/report-schema.json`. CI runs this as
/// its own step (`Report schema`).
#[test]
fn json_validates_against_schema_for_every_fixture() {
    let validator = validator();
    for name in all_names() {
        let text = report::to_json(&report_of(name)).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:#?}");
    }
}

/// The schema is itself valid draft 2020-12, versioned, closed, and rejects a report with a
/// missing field, an extra field, a wrong type, an out-of-range score or the wrong version.
#[test]
fn schema_is_valid_draft_2020_12_and_rejects_broken_reports() {
    let schema = schema();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    assert_eq!(schema["title"], "rollcall-report/1");
    assert_eq!(
        schema["properties"]["schema"]["const"],
        report::REPORT_SCHEMA
    );
    assert_eq!(schema["additionalProperties"], false);
    assert!(
        schema["description"]
            .as_str()
            .unwrap()
            .contains("basis points")
    );
    let validator = validator();
    let text = report::to_json(&report_of("old-mbedtls")).unwrap();
    let good: Value = serde_json::from_str(&text).unwrap();
    assert!(validator.is_valid(&good));
    type Mutation = fn(&mut Value);
    let mutations: [(&str, Mutation); 8] = [
        ("missing summary", |v| {
            v.as_object_mut().unwrap().remove("summary");
        }),
        ("extra top-level field", |v| {
            v["extra"] = Value::Bool(true);
        }),
        ("extra row field", |v| {
            v["components"][0]["extra"] = Value::Bool(true);
        }),
        ("score over 100", |v| {
            v["score"]["value"] = 101.into();
        }),
        ("wrong schema version", |v| {
            v["schema"] = "rollcall-report/2".into();
        }),
        ("severity not normalised", |v| {
            v["findings"]["items"][0]["severity"] = "Critical".into();
        }),
        ("boolean as string", |v| {
            v["components"][0]["purl"] = "yes".into();
        }),
        ("bad timestamp", |v| {
            v["generated"] = "yesterday".into();
        }),
    ];
    for (what, mutate) in mutations {
        let mut bad = good.clone();
        mutate(&mut bad);
        assert!(!validator.is_valid(&bad), "{what} was accepted");
    }
}

/// The Markdown goldens parse as GitHub-flavoured Markdown (pulldown-cmark with tables) into
/// the expected outline: one H1, the sections in order, every table row with its header's
/// number of cells, no raw HTML, and stubs in fenced YAML blocks. GitHub's own renderer is
/// checked in CI (`report-markdown`, scripts/check-report-markdown.sh).
#[test]
fn markdown_goldens_parse_as_gfm() {
    use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
    const SECTIONS: [&str; 8] = [
        "Score",
        "Coverage",
        "Components",
        "Unresolved modules",
        "Findings",
        "VEX coverage",
        "Validation",
        "Warnings",
    ];
    for name in all_names() {
        let report = report_of(name);
        let md = report::to_markdown(&report);
        assert!(!md.contains('\r'), "{name}: CR in Markdown");
        assert!(md.ends_with('\n') && !md.ends_with("\n\n"), "{name}");
        let mut h1 = 0;
        let mut h2: Vec<String> = Vec::new();
        let mut heading: Option<HeadingLevel> = None;
        let mut text = String::new();
        let mut tables = 0;
        let mut header_cells = 0;
        let mut row_cells = 0;
        let mut in_head = false;
        let mut yaml_blocks = 0;
        for event in Parser::new_ext(&md, Options::ENABLE_TABLES) {
            match event {
                Event::Start(Tag::Heading { level, .. }) => {
                    heading = Some(level);
                    text.clear();
                }
                Event::End(TagEnd::Heading(level)) => {
                    match level {
                        HeadingLevel::H1 => h1 += 1,
                        HeadingLevel::H2 => h2.push(text.clone()),
                        _ => panic!("{name}: unexpected heading {level:?}"),
                    }
                    heading = None;
                }
                Event::Text(t) | Event::Code(t) if heading.is_some() => text.push_str(&t),
                Event::Start(Tag::Table(_)) => tables += 1,
                Event::Start(Tag::TableHead) => {
                    in_head = true;
                    header_cells = 0;
                }
                Event::End(TagEnd::TableHead) => in_head = false,
                Event::Start(Tag::TableRow) => row_cells = 0,
                Event::End(TagEnd::TableRow) => {
                    assert_eq!(row_cells, header_cells, "{name}: ragged table row")
                }
                Event::Start(Tag::TableCell) => {
                    if in_head {
                        header_cells += 1;
                    } else {
                        row_cells += 1;
                    }
                }
                Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(lang))) => {
                    assert_eq!(&*lang, "yaml", "{name}");
                    yaml_blocks += 1;
                }
                Event::Html(h) | Event::InlineHtml(h) => panic!("{name}: raw HTML {h:?}"),
                Event::Start(Tag::Link { .. }) => panic!("{name}: link in report"),
                _ => {}
            }
        }
        assert_eq!(h1, 1, "{name}");
        assert_eq!(h2, SECTIONS, "{name}");
        // Score, coverage and components at least.
        assert!(tables >= 3, "{name}: {tables} tables");
        let names: BTreeSet<&str> = report.unresolved.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(yaml_blocks, names.len(), "{name}");
        // Every component row is a table row: as many rows as nodes.
        let rows = md
            .lines()
            .skip_while(|l| *l != "## Components")
            .skip(4)
            .take_while(|l| l.starts_with('|'))
            .count();
        assert_eq!(rows, report.components.len(), "{name}");
    }
}

/// Values from the inputs cannot break a cell, a row or the document.
#[test]
fn md_cell_escapes_pipes_backticks_html_newlines() {
    assert_eq!(md_cell("a|b"), "a\\|b");
    assert_eq!(md_cell("`code`"), "\\`code\\`");
    assert_eq!(md_cell("<script>"), "\\<script\\>");
    assert_eq!(md_cell("a\nb\r\nc\td"), "a b  c d");
    assert_eq!(
        md_cell("[x](y) *b* _i_ ~s~ # & \\"),
        "\\[x\\](y) \\*b\\* \\_i\\_ \\~s\\~ \\# \\& \\\\"
    );
    assert_eq!(md_cell("plain-1.0+x"), "plain-1.0+x");
    // GitHub renders `$…$` as math.
    assert_eq!(md_cell("$x$"), "\\$x\\$");
    // A hostile component name in a real report stays inside its cell.
    let mut product = load_fixture("minimal");
    let mut image = product.images.iter().next().unwrap().clone();
    product.images.clear();
    image
        .add_component(
            Component::new(rollcall_core::model::ComponentKind::Library, "x|<b>`y` # z").unwrap(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
    product.add_image(image).unwrap();
    let md = report::to_markdown(&build(&render(&product, false), &[], &[]));
    use pulldown_cmark::{Event, Options, Parser};
    for event in Parser::new_ext(&md, Options::ENABLE_TABLES) {
        assert!(
            !matches!(event, Event::Html(_) | Event::InlineHtml(_)),
            "{event:?}"
        );
    }
    assert!(md.contains("x\\|\\<b\\>\\`y\\` \\# z"), "{md}");
}

// --- AC: a dependency bump changes only that component and the totals -----------------------

/// `product` with the component `name` of image `image` at `version`, and every `old` in its
/// purl and CPEs replaced by `new` (a dependency bump). Dependency edges follow the new
/// `bom-ref`.
fn bump(
    product: &Product,
    image: &str,
    name: &str,
    version: &str,
    old: &str,
    new: &str,
) -> Product {
    use rollcall_core::model::{BomRef, PathSegment};
    let mut out = product.clone();
    let mut img = out.images.iter().find(|i| i.name == image).unwrap().clone();
    out.images.remove(&img);
    let image_path = out.path().child(PathSegment::of_image(&img));
    let component = img
        .components
        .iter()
        .find(|c| c.name == name)
        .unwrap()
        .clone();
    assert!(component.components.is_empty(), "{name} has subcomponents");
    img.components.remove(&component);
    let mut bumped = component.clone();
    bumped.version = Some(version.to_owned());
    bumped.purl = component
        .purl
        .as_ref()
        .map(|p| Purl::new(&p.as_str().replace(old, new)).unwrap());
    bumped.cpe = component
        .cpe
        .as_ref()
        .map(|c| Cpe::new(&c.as_str().replace(old, new)).unwrap());
    bumped.additional_cpes = component
        .additional_cpes
        .iter()
        .map(|c| Cpe::new(&c.as_str().replace(old, new)).unwrap())
        .collect();
    let old_ref = BomRef::derive(&image_path.child(PathSegment::of_component(&component)));
    let new_ref = BomRef::derive(&image_path.child(PathSegment::of_component(&bumped)));
    img.components.insert(bumped);
    out.images.insert(img);
    let swap = |r: &BomRef| {
        if *r == old_ref {
            new_ref.clone()
        } else {
            r.clone()
        }
    };
    out.dependencies = out
        .dependencies
        .iter()
        .map(|(from, to)| (swap(from), to.iter().map(swap).collect()))
        .collect();
    out.validate().unwrap();
    out
}

/// `v` without the totals (score, coverage, summary, validation counts) and without every
/// entry about one of `paths`.
fn strip(v: &Value, paths: &[&str]) -> Value {
    let mut v = v.clone();
    let o = v.as_object_mut().unwrap();
    for key in ["score", "coverage", "summary"] {
        o.remove(key);
    }
    let about = |entry: &Value, key: &str| entry[key].as_str().is_some_and(|p| paths.contains(&p));
    for (list, key) in [("components", "path"), ("unresolved", "path")] {
        o[list].as_array_mut().unwrap().retain(|e| !about(e, key));
    }
    let profiles = o["validation"]["profiles"].as_object_mut().unwrap();
    for key in ["errors", "warnings", "passed"] {
        profiles.remove(key);
    }
    profiles["findings"]
        .as_array_mut()
        .unwrap()
        .retain(|e| !about(e, "component"));
    if let Some(findings) = o.get_mut("findings").and_then(Value::as_object_mut) {
        for key in [
            "total",
            "in_sbom",
            "not_in_sbom",
            "open",
            "closed",
            "open_by_severity",
        ] {
            findings.remove(key);
        }
        findings["items"]
            .as_array_mut()
            .unwrap()
            .retain(|e| !about(e, "component"));
    }
    v
}

/// Lines of `a` not in `b` and lines of `b` not in `a`, as multisets.
fn changed_lines(a: &str, b: &str) -> Vec<String> {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for l in a.lines() {
        *counts.entry(l).or_default() += 1;
    }
    for l in b.lines() {
        *counts.entry(l).or_default() -= 1;
    }
    counts
        .into_iter()
        .filter(|(_, n)| *n != 0)
        .map(|(l, _)| l.to_owned())
        .collect()
}

/// The Markdown sections (by `## ` heading; "" before the first) holding each line.
fn sections(md: &str) -> BTreeMap<&str, BTreeSet<&str>> {
    let mut out: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut section = "";
    for line in md.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            section = h;
        }
        out.entry(line).or_default().insert(section);
    }
    out
}

/// Asserts the JSON and Markdown of `a` and `b` differ only in the rows of `paths` and in
/// the totals.
fn assert_diff_only(a: &ReadinessReport, b: &ReadinessReport, paths: &[&str]) {
    let (ja, jb) = (
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(b).unwrap(),
    );
    assert_ne!(ja, jb, "the reports do not differ");
    assert_eq!(strip(&ja, paths), strip(&jb, paths));
    let (ma, mb) = (report::to_markdown(a), report::to_markdown(b));
    let cells: Vec<String> = paths
        .iter()
        .map(|p| format!("| {} |", md_cell(p)))
        .collect();
    let (sa, sb) = (sections(&ma), sections(&mb));
    let changed = changed_lines(&ma, &mb);
    assert!(!changed.is_empty());
    for line in &changed {
        let in_sections: BTreeSet<&str> = sa
            .get(line.as_str())
            .into_iter()
            .chain(sb.get(line.as_str()))
            .flatten()
            .copied()
            .collect();
        let row = cells.iter().any(|c| line.contains(c.as_str()));
        let total = in_sections
            .iter()
            .all(|s| ["", "Score", "Coverage"].contains(s))
            || (in_sections == BTreeSet::from(["Validation"])
                && line.starts_with("- Profiles `cisa-2026`, `cra`: "));
        assert!(
            row || total,
            "unexpected changed line {line:?} in {in_sections:?}"
        );
    }
}

/// Two builds differing by one dependency bump: their reports differ only in that
/// component's rows and the totals. Built in memory (nothing committed): the clean fixture's
/// `littlefs` 2.9.0 → 2.9.1, and the real TLS build's application `mbedtls` moved to a new
/// fork revision and upstream release.
#[test]
fn dependency_bump_diff_touches_only_that_component_and_totals() {
    let clean = load_fixture("clean");
    let bumped = bump(&clean, "sensor-app", "littlefs", "2.9.1", "2.9.0", "2.9.1");
    let (a, b) = (
        build(&render(&clean, false), &[], &[]),
        build(&render(&bumped, false), &[], &[]),
    );
    assert_diff_only(&a, &b, &["sensor-app / littlefs"]);
    let row = |r: &ReadinessReport| {
        r.components
            .iter()
            .find(|c| c.path == "sensor-app / littlefs")
            .unwrap()
            .clone()
    };
    assert_eq!(row(&a).version.as_deref(), Some("2.9.0"));
    assert_eq!(row(&b).version.as_deref(), Some("2.9.1"));
    assert_ne!(row(&a).bom_ref, row(&b).bom_ref);
    // A clean bump keeps every count, so the summary and score do not change at all.
    assert_eq!(a.summary, b.summary);
    assert_eq!(a.score, b.score);

    let tls = &real_products()["zephyr-tls"];
    let app = tls
        .images
        .iter()
        .find(|i| i.name != "mcuboot")
        .unwrap()
        .name
        .clone();
    let mbedtls = tls
        .images
        .iter()
        .find(|i| i.name == app)
        .unwrap()
        .components
        .iter()
        .find(|c| c.name == "mbedtls")
        .unwrap();
    let release = mbedtls
        .purl
        .as_ref()
        .unwrap()
        .as_str()
        .split_once('@')
        .unwrap()
        .1
        .split(['?', '#'])
        .next()
        .unwrap()
        .to_owned();
    let next = format!("{release}.1");
    let bumped = bump(tls, &app, "mbedtls", &"c0".repeat(20), &release, &next);
    let (a, b) = (
        build(&render(tls, true), &[], &[]),
        build(&render(&bumped, true), &[], &[]),
    );
    let path = format!("{app} / mbedtls");
    assert_diff_only(&a, &b, &[path.as_str()]);
    // The bootloader's own copy of mbedtls is untouched.
    let boot = |r: &ReadinessReport| {
        r.components
            .iter()
            .find(|c| c.path == "mcuboot / mbedtls")
            .unwrap()
            .clone()
    };
    assert_eq!(boot(&a), boot(&b));
}

// --- Test plan: goldens with a timestamp override, determinism ---------------------------------

/// `sbom` with every `components`, `dependencies` and `dependsOn` array reversed, at every
/// level.
fn reversed(sbom: &str) -> String {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(o) => {
                for (key, child) in o.iter_mut() {
                    if let ("components" | "dependencies" | "dependsOn", Value::Array(a)) =
                        (key.as_str(), &mut *child)
                    {
                        a.reverse();
                    }
                    walk(child);
                }
            }
            Value::Array(a) => a.iter_mut().for_each(walk),
            _ => {}
        }
    }
    let mut value: Value = serde_json::from_str(sbom).unwrap();
    walk(&mut value);
    serde_json::to_string(&value).unwrap()
}

/// The same inputs give byte-identical reports, whatever order the scans, the VEX documents
/// and the SBOM's arrays are given in; the timestamp changes only the `generated` line.
#[test]
fn report_is_byte_identical_across_runs_and_input_order() {
    let c = case("old-mbedtls");
    let mut more_vex = c.vex.clone();
    more_vex.push(file(
        &manifest_dir().join("tests/golden/vex/old-mbedtls.openvex.json"),
    ));
    let first = build(&c.sbom, &c.scans, &more_vex);
    let again = build(&c.sbom, &c.scans, &more_vex);
    assert_eq!(
        report::to_json(&first).unwrap(),
        report::to_json(&again).unwrap()
    );
    let mut scans = c.scans.clone();
    scans.reverse();
    more_vex.reverse();
    let shuffled = build(&reversed(&c.sbom), &scans, &more_vex);
    assert_eq!(
        report::to_json(&first).unwrap(),
        report::to_json(&shuffled).unwrap()
    );
    assert_eq!(report::to_markdown(&first), report::to_markdown(&shuffled));
    // A multi-image real build with profile findings: reversing every array at every level
    // changes nothing either (profile findings are sorted by node, not document order).
    let tls = case("zephyr-tls");
    let a = build(&tls.sbom, &[], &[]);
    assert!(a.components.iter().filter(|r| r.level == "image").count() > 1);
    assert!(a.validation.profiles.findings.len() > 1);
    let b = build(&reversed(&tls.sbom), &[], &[]);
    assert_eq!(report::to_json(&a).unwrap(), report::to_json(&b).unwrap());
    assert_eq!(report::to_markdown(&a), report::to_markdown(&b));
    // Another timestamp: only the `generated` field and the provenance line change.
    let later = report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: c.sbom.as_bytes(),
        },
        &inputs(&c.scans),
        &inputs(&more_vex),
        &Timestamp::parse("2030-05-06T07:08:09Z").unwrap(),
    )
    .unwrap();
    let changed = changed_lines(
        &report::to_json(&first).unwrap(),
        &report::to_json(&later).unwrap(),
    );
    assert_eq!(
        changed,
        [
            "  \"generated\": \"2026-01-02T03:04:05Z\",",
            "  \"generated\": \"2030-05-06T07:08:09Z\","
        ]
    );
    let changed = changed_lines(&report::to_markdown(&first), &report::to_markdown(&later));
    assert_eq!(changed.len(), 2, "{changed:?}");
    assert!(changed.iter().all(|l| l.starts_with("Generated ")));
}

// --- Test plan: the BT-on and BT-off reports ---------------------------------------------------

/// The real BT-on (`smp-bt`) and BT-off (`smp-serial`) builds of the same sample: their
/// reports differ exactly in the `bluetooth-controller` and `bluetooth-host` rows (which only
/// the BT-on report has) and the totals.
#[test]
fn bt_on_vs_bt_off_report_diff_is_bluetooth_rows_and_totals() {
    let off = report_of("zephyr-smp-serial");
    let on = report_of("zephyr-smp-bt");
    let bt = [
        "smp_svr / zephyr / bluetooth-controller",
        "smp_svr / zephyr / bluetooth-host",
    ];
    assert_diff_only(&off, &on, &bt);
    let paths = |r: &ReadinessReport| -> BTreeSet<String> {
        r.components.iter().map(|c| c.path.clone()).collect()
    };
    let added: Vec<String> = paths(&on).difference(&paths(&off)).cloned().collect();
    assert_eq!(added, bt);
    assert!(paths(&off).is_subset(&paths(&on)));
    assert_eq!(on.coverage.nodes, off.coverage.nodes + 2);
}

// --- Inputs: scans, VEX, severity, malformed input ------------------------------------------

#[test]
fn severity_normalisation_table() {
    let cases = [
        (Some("Critical"), Severity::Critical),
        (Some("CRITICAL"), Severity::Critical),
        (Some("high"), Severity::High),
        (Some("High"), Severity::High),
        (Some("Medium"), Severity::Medium),
        (Some("moderate"), Severity::Medium),
        (Some("MODERATE"), Severity::Medium),
        (Some("Low"), Severity::Low),
        (Some("Negligible"), Severity::Low),
        (Some("Unknown"), Severity::Unknown),
        (Some("7.5"), Severity::Unknown),
        (Some(""), Severity::Unknown),
        (Some("informational"), Severity::Unknown),
        (None, Severity::Unknown),
    ];
    for (word, expected) in cases {
        assert_eq!(normalise_severity(word), expected, "{word:?}");
    }
    assert!(Severity::Unknown < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    // In a report: grype's words are normalised, and the open counts add up.
    let report = report_of("old-mbedtls");
    let findings = report.findings.unwrap();
    assert!(
        findings
            .items
            .iter()
            .all(|i| { i.severity == report_severity(i.scanner_severity.as_deref()) })
    );
    let s = findings.open_by_severity;
    assert_eq!(
        s.critical + s.high + s.medium + s.low + s.unknown,
        findings.open
    );
}

fn report_severity(word: Option<&str>) -> &'static str {
    match normalise_severity(word) {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

/// The old-mbedTLS VEX golden in every format rollcall writes (rollcall-vex/1, OpenVEX,
/// CycloneDX VEX, embedded) gives the same findings and VEX coverage.
#[test]
fn parse_vex_reads_all_three_rollcall_vex_formats_identically() {
    let c = case("old-mbedtls");
    let mut seen = Vec::new();
    for format in ["vex.json", "openvex.json", "vex.cdx.json", "embed.cdx.json"] {
        let vex = [file(
            &manifest_dir().join(format!("tests/golden/vex/old-mbedtls.{format}")),
        )];
        let report = build(&c.sbom, &c.scans, &vex);
        assert!(
            report.warnings.is_empty(),
            "{format}: {:?}",
            report.warnings
        );
        let vex = report.vex.clone().unwrap();
        assert_eq!(vex.unmatched_statements, 0, "{format}");
        seen.push((format, report.findings.unwrap(), vex));
    }
    let (_, first_findings, first_vex) = &seen[0];
    assert!(first_findings.closed > 0 && first_findings.open > 0);
    for (format, findings, vex) in &seen {
        assert_eq!(findings, first_findings, "{format}");
        assert_eq!(vex, first_vex, "{format}");
    }
}

/// A `not_affected` or `fixed` statement closes its finding; an `affected` or
/// `under_investigation` one keeps it open; with a closing and an open statement it stays
/// open; a statement for another component, or a BOM-Link into another SBOM, applies to
/// nothing (the latter with a warning).
#[test]
fn vex_statement_closes_finding_and_affected_keeps_it_open() {
    let c = case("old-mbedtls");
    let sbom: Value = serde_json::from_str(&c.sbom).unwrap();
    let serial = sbom["serialNumber"].as_str().unwrap().to_owned();
    let uuid = serial.strip_prefix("urn:uuid:").unwrap();
    let mbedtls = sbom["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "mbedtls")
        .unwrap()["bom-ref"]
        .as_str()
        .unwrap()
        .to_owned();
    let doc = |statements: &[(&str, &str, &str)]| -> Vec<(String, Vec<u8>)> {
        let vulns: Vec<Value> = statements
            .iter()
            .map(|(id, state, target)| {
                serde_json::json!({"id": id, "analysis": {"state": state}, "affects": [{"ref": target}]})
            })
            .collect();
        let text = serde_json::json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "vulnerabilities": vulns});
        vec![("v.cdx.json".to_owned(), text.to_string().into_bytes())]
    };
    let link = format!("urn:cdx:{uuid}/1#{mbedtls}");
    let item = |r: &ReadinessReport, id: &str| {
        r.findings
            .as_ref()
            .unwrap()
            .items
            .iter()
            .find(|i| i.id == id)
            .unwrap()
            .clone()
    };
    let id = "CVE-2022-46392";
    for (state, status, vex_status) in [
        ("not_affected", "closed", "not_affected"),
        ("false_positive", "closed", "not_affected"),
        ("resolved", "closed", "fixed"),
        ("exploitable", "open", "affected"),
        ("in_triage", "open", "under_investigation"),
    ] {
        for target in [mbedtls.as_str(), link.as_str()] {
            let r = build(&c.sbom, &c.scans, &doc(&[(id, state, target)]));
            let i = item(&r, id);
            assert_eq!(
                (i.status, i.vex_status),
                (status, Some(vex_status)),
                "{state}"
            );
        }
    }
    // A CycloneDX `pkg:` ref matches by purl (it is tried as a bom-ref too).
    let purl = "pkg:github/mbed-tls/mbedtls@v2.28.0";
    let r = build(&c.sbom, &c.scans, &doc(&[(id, "not_affected", purl)]));
    assert_eq!(item(&r, id).status, "closed");
    // An OpenVEX product with only `identifiers.purl` (no `@id`) matches by purl.
    let openvex = serde_json::json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "statements": [{"vulnerability": {"name": id}, "status": "fixed",
                        "products": [{"identifiers": {"purl": purl}}]}]
    });
    let r = build(
        &c.sbom,
        &c.scans,
        &[("o.json".to_owned(), openvex.to_string().into_bytes())],
    );
    assert_eq!(
        (item(&r, id).status, item(&r, id).vex_status),
        ("closed", Some("fixed"))
    );
    // Closing and open statements together: open.
    let r = build(
        &c.sbom,
        &c.scans,
        &doc(&[(id, "not_affected", &mbedtls), (id, "exploitable", &link)]),
    );
    assert_eq!(item(&r, id).status, "open");
    // No statement: open, no VEX status; the closed count follows.
    let r = build(&c.sbom, &c.scans, &[]);
    assert_eq!(
        (item(&r, id).status, item(&r, id).vex_status),
        ("open", None)
    );
    assert_eq!(r.findings.as_ref().unwrap().closed, 0);
    assert!(r.vex.is_none());
    // Another component, or another SBOM: nothing applies; the latter warns.
    let other = format!("urn:cdx:00000000-0000-0000-0000-000000000000/1#{mbedtls}");
    let r = build(
        &c.sbom,
        &c.scans,
        &doc(&[
            (id, "not_affected", "component:nope"),
            (id, "not_affected", &other),
        ]),
    );
    assert_eq!(item(&r, id).status, "open");
    assert_eq!(r.vex.as_ref().unwrap().unmatched_statements, 2);
    assert_eq!(r.warnings.len(), 1, "{:#?}", r.warnings);
    assert!(
        r.warnings[0].message.contains("not this one"),
        "{:?}",
        r.warnings
    );
    // VEX without a scan: statements counted, nothing assessed.
    let r = build(&c.sbom, &[], &c.vex);
    assert!(r.findings.is_none());
    let vex = r.vex.unwrap();
    assert_eq!(vex.statements, vex.unmatched_statements);
    assert!(vex.findings_covered.is_none());
}

/// Malformed VEX documents are errors naming the problem, never panics.
#[test]
fn parse_vex_malformed_inputs_error_never_panic() {
    let sbom = SbomIdentity {
        serial_number: Some("urn:uuid:69f2589c-ad74-860e-9e94-8014f9de18a7"),
    };
    let golden =
        std::fs::read(manifest_dir().join("tests/golden/vex/old-mbedtls.vex.cdx.json")).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("truncated", golden[..golden.len() / 2].to_vec()),
        ("not UTF-8", vec![0xff, 0xfe, b'{', b'}']),
        ("array", b"[]".to_vec()),
        ("string", b"\"vex\"".to_vec()),
        ("unknown object", b"{\"hello\": 1}".to_vec()),
        ("rollcall no statements", br#"{"schema": "rollcall-vex/1"}"#.to_vec()),
        (
            "rollcall statements not array",
            br#"{"schema": "rollcall-vex/1", "statements": {}}"#.to_vec(),
        ),
        (
            "rollcall statement not object",
            br#"{"schema": "rollcall-vex/1", "statements": [1]}"#.to_vec(),
        ),
        (
            "rollcall no component",
            br#"{"schema": "rollcall-vex/1", "statements": [{"vulnerability": "CVE-1", "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "rollcall bad status",
            br#"{"schema": "rollcall-vex/1", "statements": [{"vulnerability": "CVE-1", "component": {"bom-ref": "r"}, "status": "maybe"}]}"#.to_vec(),
        ),
        (
            "rollcall aliases not strings",
            br#"{"schema": "rollcall-vex/1", "statements": [{"vulnerability": "CVE-1", "aliases": [1], "component": {"bom-ref": "r"}, "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "openvex products missing",
            br#"{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "openvex vulnerability number",
            br#"{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": 7, "products": [], "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "openvex product with neither @id nor identifiers.purl",
            br#"{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "products": [{"identifiers": {}}], "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "openvex @id number",
            br#"{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{"vulnerability": "CVE-1", "products": [{"@id": 1}], "status": "fixed"}]}"#.to_vec(),
        ),
        (
            "cyclonedx vulnerabilities object",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": {}}"#.to_vec(),
        ),
        (
            "cyclonedx no id",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"affects": []}]}"#.to_vec(),
        ),
        (
            "cyclonedx bad state",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "fine"}, "affects": [{"ref": "r"}]}]}"#.to_vec(),
        ),
        (
            "cyclonedx ref number",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": 3}]}]}"#.to_vec(),
        ),
        (
            "cyclonedx bad BOM-Link",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "urn:cdx:nope"}]}]}"#.to_vec(),
        ),
        (
            "cyclonedx bad percent escape",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-1", "affects": [{"ref": "urn:cdx:a/1#b%zz"}]}]}"#.to_vec(),
        ),
        (
            "cyclonedx references not array",
            br#"{"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-1", "references": "x", "affects": []}]}"#.to_vec(),
        ),
    ];
    for (what, bytes) in &cases {
        let e = parse_vex(bytes, "v.json", &sbom).expect_err(what);
        let message = e.to_string();
        assert!(!message.is_empty(), "{what}");
        if *what == "rollcall bad status" {
            assert!(matches!(e, VexInputError::Shape { .. }), "{what}: {e}");
            assert!(message.contains("$.statements[0].status"), "{message}");
        }
    }
    // Deep nesting is refused by the JSON parser, not a stack overflow.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(parse_vex(deep.as_bytes(), "v.json", &sbom).is_err());
    // An SBOM without vulnerabilities parses, with a warning and no statements.
    let none = parse_vex(br#"{"bomFormat": "CycloneDX"}"#, "v.json", &sbom).unwrap();
    assert!(none.statements.is_empty());
    assert_eq!(none.warnings.len(), 1);
    // Every golden parses; the CycloneDX one has statements, all closing or not.
    let parsed = parse_vex(&golden, "v.json", &sbom).unwrap();
    assert!(
        parsed
            .statements
            .iter()
            .any(|s| s.status == VexStatus::NotAffected)
    );
    assert!(parsed.warnings.is_empty());
}

/// A malformed SBOM, scan or VEX document makes `build` fail with an error naming the file,
/// never panic.
#[test]
fn build_malformed_inputs_error_never_panic() {
    let c = case("old-mbedtls");
    let truncated = &c.sbom[..c.sbom.len() / 2];
    let sboms: [(&str, &[u8]); 7] = [
        ("empty", b""),
        ("truncated", truncated.as_bytes()),
        ("not UTF-8", &[0xff, 0xfe]),
        ("array", b"[]"),
        ("not CycloneDX", br#"{"bomFormat": "SPDX"}"#),
        (
            "CycloneDX 1.4",
            br#"{"bomFormat": "CycloneDX", "specVersion": "1.4"}"#,
        ),
        (
            "no product",
            br#"{"bomFormat": "CycloneDX", "specVersion": "1.6"}"#,
        ),
    ];
    for (what, bytes) in sboms {
        let e = report::build(
            Input {
                name: "bad.cdx.json",
                bytes,
            },
            &[],
            &[],
            &timestamp(),
        )
        .expect_err(what);
        assert!(
            matches!(e, ReportError::SbomJson { .. } | ReportError::Sbom { .. }),
            "{what}: {e}"
        );
        assert!(e.to_string().starts_with("bad.cdx.json: "), "{e}");
    }
    let bad_scans: [(&str, &[u8]); 4] = [
        ("empty", b""),
        ("not a scan", br#"{"x": 1}"#),
        ("grype matches object", br#"{"matches": {}}"#),
        ("truncated", br#"{"matches": [{"vulnerability": "#),
    ];
    for (what, bytes) in bad_scans {
        let e = report::build(
            Input {
                name: "sbom.cdx.json",
                bytes: c.sbom.as_bytes(),
            },
            &[Input {
                name: "scan.json",
                bytes,
            }],
            &[],
            &timestamp(),
        )
        .expect_err(what);
        assert!(matches!(e, ReportError::Scan { .. }), "{what}: {e}");
        assert!(e.to_string().starts_with("scan.json: "), "{e}");
    }
    let e = report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: c.sbom.as_bytes(),
        },
        &[],
        &[Input {
            name: "v.json",
            bytes: b"{}",
        }],
        &timestamp(),
    )
    .unwrap_err();
    assert!(matches!(e, ReportError::Vex { .. }), "{e}");
    assert!(e.to_string().starts_with("v.json: "), "{e}");
    // A foreign but valid CycloneDX document is reported on, with reader warnings.
    let foreign = br#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "firmware", "name": "thing", "bom-ref": "p"}},
        "components": [{"type": "framework", "name": "fw", "bom-ref": "f"}]}"#;
    let r = report::build(
        Input {
            name: "foreign.cdx.json",
            bytes: foreign,
        },
        &[],
        &[],
        &timestamp(),
    )
    .unwrap();
    assert!(!r.warnings.is_empty());
    assert!(r.score.value < 100);
}

/// A scan none of whose findings is for a component of the SBOM is warned about (it was
/// probably run on another build); and the product row keeps the SBOM's own
/// `metadata.component.type` (which the CycloneDX reader requires).
#[test]
fn scan_matching_nothing_warns_and_product_type_is_kept() {
    // The old-mbedTLS grype capture against the widget: 23 findings, none for its mbedtls.
    let widget = case("widget");
    let scan = [file(&data("findings/old-mbedtls.grype.json"))];
    let r = build(&widget.sbom, &scan, &[]);
    let f = r.findings.as_ref().unwrap();
    assert_eq!((f.in_sbom, f.not_in_sbom > 0), (0, true));
    assert!(
        r.warnings
            .iter()
            .any(|w| w.message.contains("none of the scan's")),
        "{:?}",
        r.warnings
    );
    // A scan that joins does not warn.
    let c = case("old-mbedtls");
    assert!(build(&c.sbom, &c.scans, &[]).warnings.is_empty());
    // The product row's type is the document's own; `firmware` only when it has none.
    let mut sbom: Value = serde_json::from_str(&case("minimal").sbom).unwrap();
    sbom["metadata"]["component"]["type"] = "device".into();
    let r = build(&sbom.to_string(), &[], &[]);
    assert_eq!(r.components[0].kind, "device");
    sbom["metadata"]["component"]
        .as_object_mut()
        .unwrap()
        .remove("type");
    let r = report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: sbom.to_string().as_bytes(),
        },
        &[],
        &[],
        &timestamp(),
    );
    // The reader requires `type`, so an SBOM without one is malformed input, not a guess.
    assert!(matches!(r, Err(ReportError::Sbom { .. })));
}
