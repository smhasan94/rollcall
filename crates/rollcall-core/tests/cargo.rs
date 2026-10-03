//! Cargo ingestion against the real `cargo auditable` build fixtures in `fixtures/cargo-*/`:
//! `cargo-keelsign` (keelsign's nrf52840-hello), `cargo-deps` (git, path, dev and host-only
//! dependencies) and `cargo-old-heapless` (heapless 0.5.6).
//!
//! The `tests/golden/cargo/*` files are generated only by `scripts/regen-golden.sh`, which runs
//! this test with `ROLLCALL_BLESS=1`. Never edit them by hand. The fixtures are never modified:
//! negative tests copy files into a temporary directory first.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use common::GOLDEN_TIMESTAMP;
use rollcall_core::cargo::{
    self, AuditableError, CargoError, CargoIngest, CargoOptions, MetadataError, auditable, metadata,
};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::model::{Component, ComponentKind, EvidenceField, Product, Scope};
use serde_json::Value;

fn fixture(variant: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(variant)
}

fn metadata_file(variant: &str) -> PathBuf {
    fixture(variant).join("cargo-metadata.json")
}

fn elf(variant: &str) -> PathBuf {
    fixture(variant).join("firmware.elf")
}

fn ingest(options: &CargoOptions) -> CargoIngest {
    cargo::ingest(options).unwrap_or_else(|e| panic!("{e}"))
}

/// The fixture ingested with its ELF (and `include_unlinked`).
fn with_elf(variant: &str, include_unlinked: bool) -> CargoIngest {
    ingest(
        &CargoOptions::from_metadata_file(metadata_file(variant))
            .with_elf(elf(variant))
            .with_include_unlinked(include_unlinked),
    )
}

fn render(product: &Product) -> String {
    let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    cyclonedx::write(product, &options).unwrap()
}

fn assert_schema_valid(what: &str, text: &str) {
    let value: Value = serde_json::from_str(text).unwrap();
    if let Err(violations) = validate_cyclonedx_1_6(&value) {
        panic!("{what} is not valid CycloneDX 1.6:\n{violations:#?}");
    }
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/cargo")
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        fs::create_dir_all(golden_dir()).unwrap();
        common::bless(&path, actual);
        return;
    }
    let expected = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} differs from the ingested output; if the change is intended, run \
         scripts/regen-golden.sh and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

fn components(product: &Product) -> Vec<&Component> {
    product.images.iter().flat_map(|i| &i.components).collect()
}

fn component<'a>(product: &'a Product, name: &str) -> Option<&'a Component> {
    components(product).into_iter().find(|c| c.name == name)
}

/// `(name, version)` of every library component.
fn crate_set(product: &Product) -> BTreeSet<(String, String)> {
    components(product)
        .into_iter()
        .filter(|c| c.kind == ComponentKind::Library)
        .map(|c| (c.name.clone(), c.version.clone().unwrap_or_default()))
        .collect()
}

/// `(name, version)` of every package `rust-audit-info` printed for the fixture, and the root.
fn dep_v0_list(variant: &str) -> (BTreeSet<(String, String)>, (String, String)) {
    let text = fs::read_to_string(fixture(variant).join("dep-v0.json")).unwrap();
    let dep_v0 = auditable::parse_json(&text).unwrap();
    let root = dep_v0.root().unwrap();
    let root = (root.name.clone(), root.version.clone());
    let others = dep_v0
        .packages
        .iter()
        .filter(|p| !p.root)
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    (others, root)
}

/// `(name, version)` of every line of the fixture's `cargo tree --target … -e normal,build
/// --prefix none --format {p}` output, without the `(*)`, `(proc-macro)` and source suffixes.
fn cargo_tree(variant: &str) -> BTreeSet<(String, String)> {
    let text = fs::read_to_string(fixture(variant).join("cargo-tree.txt")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut words = l.split_whitespace();
            let name = words.next().unwrap().to_owned();
            let version = words.next().unwrap().trim_start_matches('v').to_owned();
            (name, version)
        })
        .collect()
}

// --- Acceptance criterion 1: keelsign → schema-valid SBOM equal to the .dep-v0 list --------

#[test]
fn keelsign_fixture_sbom_is_schema_valid() {
    let out = with_elf("cargo-keelsign", false);
    assert_schema_valid("cargo-keelsign", &render(&out.product));
}

#[test]
fn keelsign_fixture_components_equal_dep_v0_list() {
    let out = with_elf("cargo-keelsign", false);
    let (dep_v0, root) = dep_v0_list("cargo-keelsign");
    assert_eq!(
        dep_v0.len(),
        82,
        "the spike recorded 83 packages, root included"
    );
    assert_eq!(crate_set(&out.product), dep_v0);
    let image = out.product.images.first().unwrap();
    assert_eq!(
        (image.name.clone(), image.version.clone().unwrap()),
        root,
        "the image is the .dep-v0 root"
    );
    assert_eq!(out.product.name, "nrf52840-hello");
    // Every component was seen by the binary.
    for c in components(&out.product) {
        assert!(
            c.evidence
                .iter()
                .any(|e| e.source() == cargo::AUDITABLE_SOURCE),
            "{} has no cargo-auditable evidence",
            c.name
        );
        assert_eq!(c.scope, None, "{}", c.name);
    }
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
}

#[test]
fn keelsign_matches_golden() {
    let out = with_elf("cargo-keelsign", false);
    check_golden("keelsign.cdx.json", &render(&out.product));
}

#[test]
fn deps_and_old_heapless_match_goldens() {
    for (variant, name) in [
        ("cargo-deps", "deps.cdx.json"),
        ("cargo-old-heapless", "old-heapless.cdx.json"),
    ] {
        let text = render(&with_elf(variant, false).product);
        assert_schema_valid(variant, &text);
        check_golden(name, &text);
    }
    let text = render(&with_elf("cargo-deps", true).product);
    assert_schema_valid("cargo-deps --include-unlinked", &text);
    check_golden("deps.include-unlinked.cdx.json", &text);
}

#[test]
fn every_committed_cargo_golden_validates_against_schema_1_6() {
    let mut seen = 0;
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            assert_schema_valid(
                &path.display().to_string(),
                &fs::read_to_string(&path).unwrap(),
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 4);
}

// --- Acceptance criterion 2: metadata-only crates excluded, or flagged ----------------------

#[test]
fn metadata_only_crates_excluded_by_default() {
    // The dev-dependency is in the metadata, never in the binary.
    let out = with_elf("cargo-deps", false);
    assert!(component(&out.product, "static_assertions").is_none());
    assert_eq!(crate_set(&out.product), dep_v0_list("cargo-deps").0);

    // keelsign with unfiltered metadata: 31 other-platform crates, none of them linked.
    let all = fixture("cargo-keelsign").join("cargo-metadata.all.json");
    let out = ingest(&CargoOptions::from_metadata_file(&all).with_elf(elf("cargo-keelsign")));
    assert_eq!(crate_set(&out.product), dep_v0_list("cargo-keelsign").0);
    let text = fs::read_to_string(&all).unwrap();
    let m = metadata::parse(&text).unwrap();
    assert_eq!(m.packages.len() - 1 - crate_set(&out.product).len(), 31);
}

#[test]
fn include_unlinked_marks_metadata_only_crates_scope_excluded() {
    let out = with_elf("cargo-deps", true);
    let dev = component(&out.product, "static_assertions").unwrap();
    assert_eq!(dev.scope, Some(Scope::Excluded));
    assert!(
        !dev.evidence
            .iter()
            .any(|e| e.source() == cargo::AUDITABLE_SOURCE)
    );
    for c in components(&out.product) {
        if c.name != "static_assertions" {
            assert_eq!(c.scope, None, "{}", c.name);
        }
    }
    let doc: Value = serde_json::from_str(&render(&out.product)).unwrap();
    let excluded: Vec<&str> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["scope"] == "excluded")
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(excluded, ["static_assertions"]);

    // keelsign, unfiltered: exactly the 31 other-platform crates are excluded.
    let all = fixture("cargo-keelsign").join("cargo-metadata.all.json");
    let out = ingest(
        &CargoOptions::from_metadata_file(all)
            .with_elf(elf("cargo-keelsign"))
            .with_include_unlinked(true),
    );
    let excluded = components(&out.product)
        .iter()
        .filter(|c| c.scope == Some(Scope::Excluded))
        .count();
    assert_eq!(excluded, 31);
}

// --- Acceptance criterion 3: cross-target resolution matches cargo tree --target ------------

#[test]
fn keelsign_resolution_matches_cargo_tree_target() {
    for variant in ["cargo-keelsign", "cargo-deps", "cargo-old-heapless"] {
        // Without an ELF, the components are what the target-filtered metadata resolves.
        let out = ingest(&CargoOptions::from_metadata_file(metadata_file(variant)));
        let mut resolved = crate_set(&out.product);
        let image = out.product.images.first().unwrap();
        resolved.insert((image.name.clone(), image.version.clone().unwrap()));
        assert_eq!(resolved, cargo_tree(variant), "{variant}");
        // And the binary links exactly that set.
        let (mut dep_v0, root) = dep_v0_list(variant);
        dep_v0.insert(root);
        assert_eq!(dep_v0, cargo_tree(variant), "{variant}: .dep-v0");
        assert!(
            out.warnings.iter().any(|w| w.message.contains("no ELF")),
            "{variant}"
        );
    }
}

#[test]
fn host_only_dependency_absent_when_filtered_for_target() {
    let filtered = ingest(&CargoOptions::from_metadata_file(metadata_file(
        "cargo-deps",
    )));
    assert!(component(&filtered.product, "itoa").is_none());
    let all = ingest(&CargoOptions::from_metadata_file(
        fixture("cargo-deps").join("cargo-metadata.all.json"),
    ));
    assert!(component(&all.product, "itoa").is_some());
}

// --- Test plan ---------------------------------------------------------------------------

#[test]
fn metadata_vs_auditable_known_dev_dependency_only_in_metadata() {
    let text = fs::read_to_string(metadata_file("cargo-deps")).unwrap();
    let m = metadata::parse(&text).unwrap();
    let root = m.root.clone().unwrap();
    let (dev_id, _) = m
        .packages
        .iter()
        .find(|(_, p)| p.name == "static_assertions")
        .expect("static_assertions is in cargo metadata");
    let kinds = &m.nodes[&root].deps[dev_id];
    assert_eq!(
        kinds.iter().copied().collect::<Vec<_>>(),
        [metadata::DepKind::Dev]
    );
    assert_eq!(m.reach(&root).get(dev_id), Some(&metadata::Reach::DevOnly));
    let (dep_v0, _) = dep_v0_list("cargo-deps");
    assert!(!dep_v0.iter().any(|(n, _)| n == "static_assertions"));
    assert!(component(&with_elf("cargo-deps", false).product, "static_assertions").is_none());
    assert_eq!(
        component(&with_elf("cargo-deps", true).product, "static_assertions").and_then(|c| c.scope),
        Some(Scope::Excluded)
    );
}

#[test]
fn git_and_path_dependencies_get_generic_purl_with_revision() {
    let out = with_elf("cargo-deps", false);
    let purl = |name: &str| {
        component(&out.product, name)
            .and_then(|c| c.purl.as_ref())
            .map(|p| p.as_str().to_owned())
    };
    assert_eq!(
        purl("panic-halt").as_deref(),
        Some(
            "pkg:generic/panic-halt@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fkorken89%2Fpanic-halt%405505dccc8162d36ae260a12c7d9de870fadcf783"
        )
    );
    assert_eq!(
        purl("board-support").as_deref(),
        Some("pkg:generic/board-support@0.1.0")
    );
    assert_eq!(
        purl("cortex-m-rt").as_deref(),
        Some("pkg:cargo/cortex-m-rt@0.7.5")
    );
    let image = out.product.images.first().unwrap();
    assert_eq!(
        image.purl.as_ref().map(|p| p.as_str()),
        Some("pkg:generic/rollcall-cargo-deps@0.1.0")
    );
    let text = render(&out.product);
    assert!(!text.contains("/cargo-fixture"), "a host path leaked");
    assert!(!text.contains("file://"), "a path package id leaked");
}

#[test]
fn old_heapless_fixture_lists_the_old_crate() {
    let out = with_elf("cargo-old-heapless", false);
    let heapless = component(&out.product, "heapless").unwrap();
    assert_eq!(
        heapless.purl.as_ref().map(|p| p.as_str()),
        Some("pkg:cargo/heapless@0.5.6")
    );
    let expected = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/cargo-old-heapless-expected-advisories.txt"),
    )
    .unwrap();
    assert!(expected.lines().any(|l| l.trim() == "GHSA-qgwf-r2jj-2ccv"));
}

// --- Mapping details ---------------------------------------------------------------------

#[test]
fn features_and_licences_come_from_metadata() {
    let out = with_elf("cargo-keelsign", false);
    let nrf = component(&out.product, "embassy-nrf").unwrap();
    let features: BTreeSet<&str> = nrf
        .evidence
        .iter()
        .filter(|e| e.field == EvidenceField::Name && e.source() == cargo::METADATA_SOURCE)
        .filter_map(|e| e.value.strip_prefix("feature:"))
        .collect();
    for f in ["nrf52840", "time-driver-rtc1", "gpiote", "defmt"] {
        assert!(
            features.contains(f),
            "embassy-nrf lacks feature:{f}: {features:?}"
        );
    }
    assert_eq!(
        nrf.licence.as_ref().map(|l| l.as_str()),
        Some("MIT OR Apache-2.0")
    );
    let image = out.product.images.first().unwrap();
    assert_eq!(
        image.licence.as_ref().map(|l| l.as_str()),
        Some("MIT OR Apache-2.0")
    );
}

#[test]
fn image_depends_on_the_root_direct_dependencies() {
    let out = with_elf("cargo-keelsign", false);
    let p = &out.product;
    let mut image_ref = None;
    let mut names = std::collections::BTreeMap::new();
    for (path, bom_ref, node) in p.walk() {
        if let rollcall_core::model::NodeRef::Image(_) = node {
            image_ref = Some(bom_ref.clone());
        }
        names.insert(bom_ref, path.to_string());
    }
    let image_ref = image_ref.unwrap();
    let direct: BTreeSet<String> = p.dependencies[&image_ref]
        .iter()
        .map(|r| names[r].rsplit(" / ").next().unwrap().to_owned())
        .collect();
    assert_eq!(
        direct,
        BTreeSet::from(
            [
                "library:cortex-m-rt@0.7.7",
                "library:cortex-m@0.7.9",
                "library:defmt-rtt@1.3.0",
                "library:defmt@1.1.1",
                "library:embassy-executor@0.10.0",
                "library:embassy-nrf@0.11.0",
                "library:embassy-time@0.5.1",
                "library:panic-probe@1.0.0",
            ]
            .map(str::to_owned)
        )
    );
}

#[test]
fn ingesting_twice_is_byte_identical() {
    for include_unlinked in [false, true] {
        let a = render(&with_elf("cargo-deps", include_unlinked).product);
        let b = render(&with_elf("cargo-deps", include_unlinked).product);
        assert_eq!(a, b);
    }
    let a = render(&with_elf("cargo-keelsign", false).product);
    let b = render(&with_elf("cargo-keelsign", false).product);
    assert_eq!(a, b);
}

#[test]
fn scope_round_trips_through_cyclonedx() {
    let product = with_elf("cargo-deps", true).product;
    let read = cyclonedx::read_str(&render(&product)).unwrap();
    assert_eq!(read.product, product);
    assert!(read.warnings.is_empty(), "{:?}", read.warnings);
}

// --- Malformed and mismatched input: errors, never panics ---------------------------------

#[test]
fn elf_without_dep_v0_is_an_error_naming_cargo_auditable() {
    let zephyr_elf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zephyr/baseline/mcuboot/zephyr/zephyr.elf");
    let err = cargo::ingest(
        &CargoOptions::from_metadata_file(metadata_file("cargo-keelsign")).with_elf(&zephyr_elf),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            CargoError::Auditable {
                source: AuditableError::NoAuditData,
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("cargo auditable"));
    assert!(err.to_string().contains("zephyr.elf"));
}

#[test]
fn truncated_and_corrupted_elf_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = fs::read(elf("cargo-deps")).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty.elf", Vec::new()),
        ("header.elf", bytes.get(..64).unwrap().to_vec()),
        ("half.elf", bytes.get(..bytes.len() / 2).unwrap().to_vec()),
        ("garbage.elf", vec![0xA5; 4096]),
    ];
    for (name, data) in cases {
        let path = dir.path().join(name);
        fs::write(&path, data).unwrap();
        let err = cargo::ingest(
            &CargoOptions::from_metadata_file(metadata_file("cargo-deps")).with_elf(&path),
        )
        .unwrap_err();
        assert!(matches!(err, CargoError::Auditable { .. }), "{name}: {err}");
    }
    // Flip every byte of the compressed section in turn: never a panic.
    let mut corrupt = bytes.clone();
    for i in (0..corrupt.len()).step_by(997) {
        if let Some(b) = corrupt.get_mut(i) {
            *b ^= 0xFF;
        }
        let _ = auditable::read(&corrupt);
    }
}

#[test]
fn elf_of_another_package_is_a_root_mismatch() {
    let err = cargo::ingest(
        &CargoOptions::from_metadata_file(metadata_file("cargo-deps"))
            .with_elf(elf("cargo-old-heapless")),
    )
    .unwrap_err();
    assert!(matches!(err, CargoError::RootMismatch { .. }), "{err}");
    assert!(
        err.to_string()
            .contains("rollcall-cargo-old-heapless@0.1.0")
    );
}

#[test]
fn malformed_metadata_is_an_error_naming_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let good = fs::read_to_string(metadata_file("cargo-deps")).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty.json", Vec::new()),
        (
            "truncated.json",
            good.as_bytes().get(..good.len() / 3).unwrap().to_vec(),
        ),
        ("not-json.json", b"cargo metadata failed".to_vec()),
        ("latin1.json", vec![0x7B, 0xE9, 0x7D]),
        ("array.json", b"[]".to_vec()),
        (
            "version-2.json",
            good.replacen("\"version\":1", "\"version\":2", 1)
                .into_bytes(),
        ),
        (
            "no-resolve.json",
            br#"{"version":1,"packages":[],"resolve":null}"#.to_vec(),
        ),
        (
            "virtual.json",
            br#"{"version":1,"packages":[],"resolve":{"nodes":[],"root":null}}"#.to_vec(),
        ),
    ];
    for (name, data) in cases {
        let path = dir.path().join(name);
        fs::write(&path, data).unwrap();
        let err = cargo::ingest(&CargoOptions::from_metadata_file(&path)).unwrap_err();
        assert!(
            err.to_string().contains(name),
            "{name}: error does not name the file: {err}"
        );
        assert!(!err.is_read_error(), "{name}");
    }
    let err = cargo::ingest(&CargoOptions::from_metadata_file(
        dir.path().join("version-2.json"),
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        CargoError::Metadata {
            source: MetadataError::FormatVersion(2),
            ..
        }
    ));
}

#[test]
fn missing_inputs_are_read_errors() {
    let dir = tempfile::tempdir().unwrap();
    let err = cargo::ingest(&CargoOptions::from_metadata_file(
        dir.path().join("nope.json"),
    ))
    .unwrap_err();
    assert!(err.is_read_error());
    let err = cargo::ingest(
        &CargoOptions::from_metadata_file(metadata_file("cargo-deps"))
            .with_elf(dir.path().join("nope.elf")),
    )
    .unwrap_err();
    assert!(err.is_read_error());
    // A directory where the ELF should be.
    let err = cargo::ingest(
        &CargoOptions::from_metadata_file(metadata_file("cargo-deps")).with_elf(dir.path()),
    )
    .unwrap_err();
    assert!(err.is_read_error(), "{err}");
}

#[test]
fn oversized_metadata_is_refused_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.json");
    // Sparse: no disk is used, but the size is over the limit.
    let file = fs::File::create(&path).unwrap();
    file.set_len(cargo::MAX_METADATA_BYTES + 1).unwrap();
    let err = cargo::ingest(&CargoOptions::from_metadata_file(&path)).unwrap_err();
    assert!(matches!(err, CargoError::MetadataTooLarge { .. }), "{err}");
    assert!(err.to_string().contains("huge.json"));
}
