//! Zephyr ingestion against the real build fixtures in `fixtures/zephyr/`.
//!
//! The `tests/golden/zephyr/*` files are generated only by `scripts/regen-golden.sh`, which
//! runs this test with `ROLLCALL_BLESS=1`. Never edit them by hand. The fixtures themselves are
//! never modified: negative tests copy a build directory into a temporary directory first.
//!
//! `ROLLCALL_FIXTURES_DIR` points the tests at another fixture tree, as in `tests/fixtures.rs`.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use common::GOLDEN_TIMESTAMP;
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::{Component, ComponentKind, EvidenceField, ImageKind, Product};
use rollcall_core::zephyr::{
    self, BuildInfoError, Ingest, IngestOptions, KconfigError, SpdxError, WestListError,
    ZephyrError, build_info, kconfig, spdx, west_list,
};
use serde_json::Value;

const VARIANTS: [&str; 3] = ["baseline", "bt", "tls"];
/// `(variant, application image)` for the three fixture application builds.
const APP_BUILDS: [(&str, &str); 3] = [
    ("baseline", "with_mcuboot"),
    ("bt", "beacon"),
    ("tls", "http_server"),
];
/// `(variant, bootloader image)`.
const MCUBOOT_BUILDS: [(&str, &str); 3] = [
    ("baseline", "mcuboot"),
    ("bt", "mcuboot"),
    ("tls", "mcuboot"),
];
const MODULES_PER_VARIANT: usize = 6;

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr"),
    }
}

fn build_dir(variant: &str, image: &str) -> PathBuf {
    fixtures_root().join(variant).join(image)
}

fn west_list_path(variant: &str) -> PathBuf {
    fixtures_root().join(variant).join("west-list.txt")
}

fn options(variant: &str, image: &str, west_list: bool, sdk: bool) -> IngestOptions {
    let mut options = IngestOptions::new(build_dir(variant, image)).with_include_sdk(sdk);
    if west_list {
        options = options.with_west_list(west_list_path(variant));
    }
    options
}

fn ingest_fixture(variant: &str, image: &str, west_list: bool, sdk: bool) -> Ingest {
    let options = options(variant, image, west_list, sdk);
    zephyr::ingest(&options).unwrap_or_else(|e| panic!("{variant}/{image}: {e}"))
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/zephyr")
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

/// Copies the inputs of one build directory (not the binaries) into a fresh temporary
/// directory, so negative tests never touch `fixtures/`.
fn copy_build_to_tempdir(variant: &str, image: &str) -> tempfile::TempDir {
    let from = build_dir(variant, image);
    let dir = tempfile::tempdir().unwrap();
    for rel in [
        "build_info.yml",
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "spdx/zephyr.spdx",
        "zephyr/.config",
    ] {
        let to = dir.path().join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(from.join(rel), &to).unwrap_or_else(|e| panic!("{rel}: {e}"));
    }
    fs::copy(west_list_path(variant), dir.path().join("west-list.txt")).unwrap();
    dir
}

fn ingest_dir(dir: &Path, west_list: bool) -> Result<Ingest, ZephyrError> {
    let mut options = IngestOptions::new(dir);
    if west_list {
        options = options.with_west_list(dir.join("west-list.txt"));
    }
    zephyr::ingest(&options)
}

/// Every file under `dir` whose name satisfies `keep`, sorted.
fn files_named(dir: &Path, keep: &dyn Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if keep(&path.file_name().unwrap().to_string_lossy()) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// `(name, version)` of every library component of the (single) image, sorted, with repeats.
fn libraries(product: &Product) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = product
        .images
        .iter()
        .flat_map(|i| &i.components)
        .filter(|c| c.kind == ComponentKind::Library)
        .map(|c| (c.name.clone(), c.version.clone().unwrap_or_default()))
        .collect();
    out.sort();
    out
}

/// `(name, revision)` of every module row of a variant's `west-list.txt`, sorted.
fn west_list_modules(variant: &str) -> Vec<(String, String)> {
    let text = fs::read_to_string(west_list_path(variant)).unwrap();
    let list = west_list::parse(&text).unwrap();
    let mut out: Vec<(String, String)> = list
        .modules()
        .map(|p| (p.name.clone(), p.revision.clone()))
        .collect();
    out.sort();
    out
}

#[test]
fn every_fixture_build_ingests_and_validates_against_schema_1_6() {
    for (variant, image) in APP_BUILDS.into_iter().chain(MCUBOOT_BUILDS) {
        for west_list in [true, false] {
            for sdk in [true, false] {
                let out = ingest_fixture(variant, image, west_list, sdk);
                let what = format!("{variant}/{image} west_list={west_list} sdk={sdk}");
                assert_schema_valid(&what, &render(&out.product));
                // The internal form round-trips too.
                let json = out.product.to_json().unwrap();
                assert_eq!(Product::from_json(&json).unwrap(), out.product, "{what}");
            }
        }
    }
}

#[test]
fn baseline_matches_golden() {
    let out = ingest_fixture("baseline", "with_mcuboot", true, false);
    check_golden("baseline.cdx.json", &render(&out.product));
    check_golden("baseline.model.json", &out.product.to_json().unwrap());
}

#[test]
fn bt_matches_golden() {
    let out = ingest_fixture("bt", "beacon", true, false);
    check_golden("bt.cdx.json", &render(&out.product));
    check_golden("bt.model.json", &out.product.to_json().unwrap());
}

#[test]
fn tls_matches_golden() {
    let out = ingest_fixture("tls", "http_server", true, false);
    check_golden("tls.cdx.json", &render(&out.product));
    check_golden("tls.model.json", &out.product.to_json().unwrap());
}

#[test]
fn baseline_include_sdk_matches_golden() {
    let out = ingest_fixture("baseline", "with_mcuboot", true, true);
    check_golden("baseline.include-sdk.cdx.json", &render(&out.product));
}

#[test]
fn baseline_mcuboot_matches_golden() {
    let out = ingest_fixture("baseline", "mcuboot", true, false);
    check_golden("baseline.mcuboot.cdx.json", &render(&out.product));
    check_golden(
        "baseline.mcuboot.model.json",
        &out.product.to_json().unwrap(),
    );
}

fn sysbuild_options(variant: &str, west_list: bool, sdk: bool) -> IngestOptions {
    let mut options = IngestOptions::new(fixtures_root().join(variant))
        .with_sysbuild(true)
        .with_include_sdk(sdk);
    if west_list {
        options = options.with_west_list(west_list_path(variant));
    }
    options
}

#[test]
fn baseline_sysbuild_matches_golden() {
    let out = zephyr::ingest(&sysbuild_options("baseline", true, false)).unwrap();
    let text = render(&out.product);
    assert_schema_valid("baseline sysbuild", &text);
    check_golden("baseline.sysbuild.cdx.json", &text);
    check_golden(
        "baseline.sysbuild.model.json",
        &out.product.to_json().unwrap(),
    );
}

#[test]
fn mcuboot_build_is_bootloader_image_named_mcuboot() {
    for (variant, image) in MCUBOOT_BUILDS {
        let out = ingest_fixture(variant, image, true, false);
        let product = &out.product;
        assert_eq!(product.name, "mcuboot", "{variant}");
        assert_eq!(product.version, None);
        assert_eq!(product.images.len(), 1);
        let boot = product.images.first().unwrap();
        assert_eq!(
            (boot.kind, boot.name.as_str(), boot.version.as_deref()),
            (ImageKind::Bootloader, "mcuboot", None),
            "{variant}"
        );
        let sources: BTreeSet<&str> = boot.evidence.iter().map(|e| e.source()).collect();
        assert!(
            sources.contains("build-info") && sources.contains("kconfig"),
            "{variant}: {sources:?}"
        );
        let kconfig = boot
            .evidence
            .iter()
            .find(|e| e.source() == "kconfig")
            .unwrap();
        assert_eq!(kconfig.value, "CONFIG_MCUBOOT");
        assert_eq!(
            kconfig.occurrence.as_ref().map(|o| o.location()),
            Some("zephyr/.config")
        );
        // The Zephyr kernel and the mcuboot module are components of the bootloader image.
        assert!(boot.components.iter().any(|c| c.name == "zephyr"));
        assert!(boot.components.iter().any(|c| c.name == "mcuboot"));
    }
    // Application builds stay application images named after the application.
    for (variant, image) in APP_BUILDS {
        let out = ingest_fixture(variant, image, true, false);
        let app = out.product.images.first().unwrap();
        assert_eq!(
            (app.kind, app.name.as_str()),
            (ImageKind::Application, image)
        );
    }
}

#[test]
fn mcuboot_without_config_is_recognised_by_source_dir() {
    let dir = copy_build_to_tempdir("baseline", "mcuboot");
    fs::remove_file(dir.path().join("zephyr/.config")).unwrap();
    let out = ingest_dir(dir.path(), true).unwrap();
    let boot = out.product.images.first().unwrap();
    assert_eq!(
        (boot.kind, boot.name.as_str()),
        (ImageKind::Bootloader, "mcuboot")
    );
    let sources: BTreeSet<&str> = boot.evidence.iter().map(|e| e.source()).collect();
    assert!(
        sources.contains("build-info") && !sources.contains("kconfig"),
        "{sources:?}"
    );
    // An application whose .config says CONFIG_MCUBOOT is not set stays an application.
    let dir = copy_build_to_tempdir("baseline", "mcuboot");
    let config = dir.path().join("zephyr/.config");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("CONFIG_MCUBOOT=y", "# CONFIG_MCUBOOT is not set");
    fs::write(&config, text).unwrap();
    let out = ingest_dir(dir.path(), true).unwrap();
    assert_eq!(
        out.product.images.first().unwrap().kind,
        ImageKind::Application
    );
}

#[test]
fn sysbuild_ingest_equals_merge_of_image_ingests() {
    for ((variant, app), (_, boot)) in APP_BUILDS.into_iter().zip(MCUBOOT_BUILDS) {
        for (west_list, sdk) in [(true, false), (false, true)] {
            let sysbuild = zephyr::ingest(&sysbuild_options(variant, west_list, sdk))
                .unwrap_or_else(|e| panic!("{variant}: {e}"));
            let app_ingest = ingest_fixture(variant, app, west_list, sdk);
            let boot_ingest = ingest_fixture(variant, boot, west_list, sdk);
            let spec: ProductSpec = app.parse().unwrap();
            let manual =
                merge::merge(vec![app_ingest.product, boot_ingest.product], Some(&spec)).unwrap();
            assert_eq!(sysbuild.product, manual, "{variant}");
            assert_eq!(render(&sysbuild.product), render(&manual), "{variant}");
            assert_eq!(sysbuild.product.name, app);
            assert_eq!(sysbuild.product.images.len(), 2);
            // Warnings are each image's, prefixed with the image name.
            let expected: Vec<String> =
                [(boot, &boot_ingest.warnings), (app, &app_ingest.warnings)]
                    .into_iter()
                    .flat_map(|(name, ws)| ws.iter().map(move |w| format!("{name}: {w}")))
                    .collect();
            let mut expected = expected;
            expected.sort();
            let mut actual: Vec<String> =
                sysbuild.warnings.iter().map(ToString::to_string).collect();
            actual.sort();
            assert_eq!(actual, expected, "{variant}");
        }
    }
}

#[test]
fn sysbuild_discovery_reads_images_from_top_level_build_info() {
    for ((variant, app), (_, boot)) in APP_BUILDS.into_iter().zip(MCUBOOT_BUILDS) {
        let images = zephyr::discover(&fixtures_root().join(variant)).unwrap();
        let names: Vec<(&str, bool)> = images
            .iter()
            .map(|i| (i.name.as_str(), i.is_main()))
            .collect();
        let mut expected = vec![(app, true), (boot, false)];
        expected.sort();
        assert_eq!(names, expected, "{variant}");
    }
    // An image build directory is not a sysbuild one.
    let err = zephyr::discover(&build_dir("baseline", "with_mcuboot")).unwrap_err();
    assert!(matches!(err, ZephyrError::NotASysbuild { .. }), "{err}");
    let err = zephyr::ingest(
        &IngestOptions::new(build_dir("baseline", "with_mcuboot")).with_sysbuild(true),
    )
    .unwrap_err();
    assert!(matches!(err, ZephyrError::NotASysbuild { .. }), "{err}");

    // Malformed sysbuild metadata errors, naming the file, never panicking.
    let cases = [
        (
            "no MAIN",
            "cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images:\n   - name: mcuboot\n     type: BOOTLOADER\n",
        ),
        (
            "empty images",
            "cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images: []\n",
        ),
        (
            "traversal",
            "cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images:\n   - name: ../etc\n     type: MAIN\n",
        ),
        ("not yaml", "cmake: [\n"),
        ("empty", ""),
    ];
    for (what, text) in cases {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("build_info.yml"), text).unwrap();
        let result = std::panic::catch_unwind(|| zephyr::discover(dir.path()))
            .unwrap_or_else(|_| panic!("{what}: panicked"));
        let err = result.unwrap_err();
        assert!(err.to_string().contains("build_info.yml"), "{what}: {err}");
    }
    // A listed image directory that is missing is a read error.
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("build_info.yml"),
        "cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images:\n   - name: app\n     type: MAIN\n",
    )
    .unwrap();
    let err = zephyr::ingest(&IngestOptions::new(dir.path()).with_sysbuild(true)).unwrap_err();
    assert!(err.is_read_error(), "{err}");
}

/// Copies the inputs (not the binaries) of the fixture image build `variant/image` into `to`.
fn copy_inputs_into(variant: &str, image: &str, to: &Path) {
    let from = build_dir(variant, image);
    for rel in [
        "build_info.yml",
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "spdx/zephyr.spdx",
        "zephyr/.config",
    ] {
        let dest = to.join(rel);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(from.join(rel), &dest).unwrap_or_else(|e| panic!("{rel}: {e}"));
    }
}

/// A sysbuild top-level `build_info.yml` listing `images` as `(name, type)`.
fn sysbuild_build_info(images: &[(&str, &str)]) -> String {
    let mut text =
        String::from("cmake:\n  application:\n    source-dir: /x/share/sysbuild\n  images:\n");
    for (name, kind) in images {
        text.push_str(&format!("   - name: '{name}'\n     type: '{kind}'\n"));
    }
    text
}

#[test]
fn sysbuild_two_images_with_the_same_identity_are_an_error() {
    // An NCS-style `s1_image`: a second MCUboot build, so both become `bootloader:mcuboot`.
    // Built in a temporary directory from copies of the baseline fixture; `fixtures/` is
    // never touched.
    let top = tempfile::tempdir().unwrap();
    fs::write(
        top.path().join("build_info.yml"),
        sysbuild_build_info(&[
            ("with_mcuboot", "MAIN"),
            ("mcuboot", "BOOTLOADER"),
            ("s1_image", "BOOTLOADER"),
        ]),
    )
    .unwrap();
    copy_inputs_into("baseline", "with_mcuboot", &top.path().join("with_mcuboot"));
    copy_inputs_into("baseline", "mcuboot", &top.path().join("mcuboot"));
    copy_inputs_into("baseline", "mcuboot", &top.path().join("s1_image"));

    let err = zephyr::ingest(&IngestOptions::new(top.path()).with_sysbuild(true)).unwrap_err();
    match &err {
        ZephyrError::DuplicateImage {
            path,
            image,
            first,
            second,
        } => {
            assert_eq!(path, &top.path().join("build_info.yml"));
            assert!(image.starts_with("bootloader:mcuboot"), "{image}");
            assert_eq!(first, &top.path().join("mcuboot"));
            assert_eq!(second, &top.path().join("s1_image"));
        }
        other => panic!("expected DuplicateImage, got {other}"),
    }
    assert!(!err.is_read_error());
    let message = err.to_string();
    for needle in [
        "build_info.yml",
        "mcuboot",
        "s1_image",
        "bootloader:mcuboot",
    ] {
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
    }

    // Without the second bootloader the same layout ingests.
    fs::write(
        top.path().join("build_info.yml"),
        sysbuild_build_info(&[("with_mcuboot", "MAIN"), ("mcuboot", "BOOTLOADER")]),
    )
    .unwrap();
    let ok = zephyr::ingest(&IngestOptions::new(top.path()).with_sysbuild(true)).unwrap();
    assert_eq!(ok.product.images.len(), 2);
}

#[test]
fn sysbuild_repeated_or_unsafe_image_names_are_errors() {
    // The same name listed twice is an error, not silently dropped.
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("build_info.yml"),
        sysbuild_build_info(&[("app", "MAIN"), ("mcuboot", "BOOTLOADER"), ("app", "MAIN")]),
    )
    .unwrap();
    let err = zephyr::discover(dir.path()).unwrap_err();
    match &err {
        ZephyrError::DuplicateImageName { path, name } => {
            assert_eq!(path, &dir.path().join("build_info.yml"));
            assert_eq!(name, "app");
        }
        other => panic!("expected DuplicateImageName, got {other}"),
    }
    assert!(err.to_string().contains("\"app\" twice"), "{err}");

    // Names that are not exactly one plain directory component.
    for name in ["C:", "a:b", "..", ".", "a/b", "/abs", "a\\b", ""] {
        fs::write(
            dir.path().join("build_info.yml"),
            sysbuild_build_info(&[(name, "MAIN")]),
        )
        .unwrap();
        let result = std::panic::catch_unwind(|| zephyr::discover(dir.path()))
            .unwrap_or_else(|_| panic!("{name:?}: panicked"));
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ZephyrError::InvalidImageName { name: n, .. } if n == name),
            "{name:?}: {err}"
        );
    }
}

#[test]
fn ingesting_twice_is_byte_identical() {
    for (variant, image) in APP_BUILDS {
        let a = ingest_fixture(variant, image, true, true);
        let b = ingest_fixture(variant, image, true, true);
        assert_eq!(a, b);
        assert_eq!(render(&a.product).as_bytes(), render(&b.product).as_bytes());
        assert_eq!(a.product.to_json().unwrap(), b.product.to_json().unwrap());
    }
}

#[test]
fn every_committed_zephyr_golden_validates_against_schema_1_6() {
    let mut seen = Vec::new();
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let file = entry.unwrap().file_name().to_string_lossy().into_owned();
        let text = fs::read_to_string(golden_dir().join(&file)).unwrap();
        if file.ends_with(".cdx.json") {
            assert_schema_valid(&file, &text);
        } else if file.ends_with(".model.json") {
            Product::from_json(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
        }
        seen.push(file);
    }
    seen.sort();
    assert_eq!(
        seen,
        [
            "baseline.cdx.json",
            "baseline.include-sdk.cdx.json",
            "baseline.mcuboot.cdx.json",
            "baseline.mcuboot.model.json",
            "baseline.model.json",
            "baseline.sysbuild.cdx.json",
            "baseline.sysbuild.model.json",
            "bt.cdx.json",
            "bt.model.json",
            "old-mbedtls.cdx.json",
            "old-mbedtls.model.json",
            "tls.cdx.json",
            "tls.model.json",
        ]
    );
}

#[test]
fn every_fixture_module_set_matches_west_list() {
    for (variant, image) in APP_BUILDS {
        let expected = west_list_modules(variant);
        assert_eq!(expected.len(), MODULES_PER_VARIANT, "{variant}");
        let out = ingest_fixture(variant, image, true, false);
        let actual = libraries(&out.product);
        // Same (name, revision) multiset both ways: every module exactly once, at its revision.
        assert_eq!(actual, expected, "{variant}");
        assert_eq!(actual.len(), MODULES_PER_VARIANT, "{variant}");
        let names: BTreeSet<&String> = actual.iter().map(|(n, _)| n).collect();
        assert_eq!(
            names.len(),
            MODULES_PER_VARIANT,
            "{variant}: duplicate module"
        );
    }
}

#[test]
fn module_set_from_spdx_alone_matches_west_list() {
    for (variant, image) in APP_BUILDS {
        let out = ingest_fixture(variant, image, false, false);
        assert_eq!(
            libraries(&out.product),
            west_list_modules(variant),
            "{variant}"
        );
    }
}

#[test]
fn app_and_zephyr_are_present_in_every_fixture() {
    for (variant, image) in APP_BUILDS {
        let out = ingest_fixture(variant, image, true, false);
        let product = &out.product;
        assert_eq!(product.name, image, "{variant}");
        assert_eq!(product.images.len(), 1, "{variant}");
        let app = product.images.iter().next().unwrap();
        assert_eq!(app.kind, ImageKind::Application);
        assert_eq!(app.name, image);
        let zephyrs: Vec<_> = app
            .components
            .iter()
            .filter(|c| c.kind == ComponentKind::OperatingSystem)
            .collect();
        assert_eq!(zephyrs.len(), 1, "{variant}");
        assert_eq!(zephyrs[0].name, "zephyr");
        assert_eq!(zephyrs[0].version.as_deref(), Some("4.4.2"));
        assert!(out.warnings.is_empty(), "{variant}: {:?}", out.warnings);
    }
}

#[test]
fn fixture_spdx_documents_parse_fully() {
    let files = files_named(&fixtures_root(), &|n| n.ends_with(".spdx"));
    assert_eq!(files.len(), 24);
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        let doc = spdx::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(doc.version, "SPDX-2.3");
        assert_eq!(doc.spdx_id, "SPDXRef-DOCUMENT");
        let expected_packages = match path.file_name().unwrap().to_str().unwrap() {
            "app.spdx" => Some(1),
            "zephyr.spdx" | "modules-deps.spdx" => Some(1 + MODULES_PER_VARIANT),
            _ => None,
        };
        if let Some(n) = expected_packages {
            assert_eq!(doc.packages.len(), n, "{}", path.display());
        } else {
            assert!(!doc.packages.is_empty(), "{}", path.display());
        }
        let mut ids: BTreeSet<&str> = doc
            .packages
            .iter()
            .map(|p| p.spdx_id.as_str())
            .chain(doc.files.iter().map(|f| f.spdx_id.as_str()))
            .collect();
        ids.insert("SPDXRef-DOCUMENT");
        let documents: BTreeSet<&str> = doc
            .external_document_refs
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        assert!(!doc.relationships.is_empty());
        for r in &doc.relationships {
            for end in [&r.subject, &r.object] {
                match &end.document {
                    Some(d) => assert!(
                        documents.contains(d.as_str()),
                        "{}:{}",
                        path.display(),
                        r.line
                    ),
                    None => assert!(
                        ids.contains(end.id.as_str()),
                        "{}:{}: {} is not defined",
                        path.display(),
                        r.line,
                        end.id
                    ),
                }
            }
        }
    }
}

#[test]
fn fixture_configs_parse() {
    let files = files_named(&fixtures_root(), &|n| n == ".config");
    assert_eq!(files.len(), 9);
    let mut sysbuild = 0;
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        let config = kconfig::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(!config.symbols.is_empty());
        if config.symbols.keys().all(|k| k.starts_with("SB_CONFIG_")) {
            sysbuild += 1;
            assert!(
                config.is_set("SB_CONFIG_BOOTLOADER_MCUBOOT"),
                "{}",
                path.display()
            );
        } else {
            assert_eq!(
                config.zephyr_sdk_version().map(|(v, _)| v).as_deref(),
                Some("1.0"),
                "{}",
                path.display()
            );
        }
    }
    assert_eq!(sysbuild, 3);
}

#[test]
fn fixture_build_infos_parse() {
    let files = files_named(&fixtures_root(), &|n| n == "build_info.yml");
    assert_eq!(files.len(), 9);
    let mut sysbuild = BTreeSet::new();
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        let info = build_info::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if info.is_sysbuild() {
            sysbuild.insert(info.main_image().unwrap().to_owned());
        } else {
            assert_eq!(info.zephyr_version(), Some("4.4.2"), "{}", path.display());
            assert_eq!(info.toolchain_name(), Some("zephyr"));
            assert!(info.app_name().is_some());
        }
    }
    let apps: BTreeSet<String> = APP_BUILDS.iter().map(|(_, a)| (*a).to_owned()).collect();
    assert_eq!(sysbuild, apps);
    // A sysbuild top-level directory is refused, naming the image directory to use.
    for variant in VARIANTS {
        let err = zephyr::ingest(&IngestOptions::new(fixtures_root().join(variant))).unwrap_err();
        assert!(matches!(err, ZephyrError::NotAnImageBuild { .. }), "{err}");
    }
}

#[test]
fn fixture_west_lists_parse() {
    for variant in VARIANTS {
        let text = fs::read_to_string(west_list_path(variant)).unwrap();
        let list = west_list::parse(&text).unwrap();
        assert_eq!(list.projects.len(), 1 + MODULES_PER_VARIANT);
        assert!(list.projects[0].is_manifest_repository());
        assert_eq!(list.modules().count(), MODULES_PER_VARIANT);
        for module in list.modules() {
            assert_eq!(module.revision.len(), 40, "{}", module.name);
            assert!(module.url.starts_with("https://github.com/"));
        }
    }
}

#[test]
fn malformed_inputs_error_with_file_and_line_never_panic() {
    let expect = |dir: &Path, west_list: bool, file: &str, needle: &str| -> ZephyrError {
        let err = ingest_dir(dir, west_list).unwrap_err();
        let message = err.to_string();
        assert!(message.contains(file), "{message:?} lacks {file:?}");
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
        err
    };

    // Bad UTF-8 in an SPDX document.
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    fs::write(
        dir.path().join("spdx/zephyr.spdx"),
        b"SPDXVersion: \xff\xfe\n",
    )
    .unwrap();
    let err = expect(dir.path(), true, "spdx/zephyr.spdx", "UTF-8");
    assert!(matches!(err, ZephyrError::NotUtf8 { .. }));

    // An empty optional SPDX document is present, so it is an error.
    let dir = copy_build_to_tempdir("bt", "beacon");
    fs::write(dir.path().join("spdx/app.spdx"), "").unwrap();
    let err = expect(dir.path(), true, "spdx/app.spdx", "empty");
    assert!(matches!(
        err,
        ZephyrError::Spdx {
            source: SpdxError::Empty,
            ..
        }
    ));

    // .config garbage.
    let dir = copy_build_to_tempdir("tls", "http_server");
    fs::write(dir.path().join("zephyr/.config"), "\u{0}\u{1}garbage\n").unwrap();
    let err = expect(dir.path(), true, "zephyr/.config", "line 1");
    assert!(matches!(
        err,
        ZephyrError::Kconfig {
            source: KconfigError::UnknownSyntax { line: 1 },
            ..
        }
    ));

    // build_info.yml that is not YAML, and one without `cmake`.
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    fs::write(dir.path().join("build_info.yml"), "cmake: [unclosed\n").unwrap();
    let err = expect(dir.path(), true, "build_info.yml", "line");
    assert!(matches!(
        err,
        ZephyrError::BuildInfo {
            source: BuildInfoError::Yaml(_),
            ..
        }
    ));
    fs::write(dir.path().join("build_info.yml"), "version: '0.1.0'\n").unwrap();
    let err = expect(dir.path(), true, "build_info.yml", "cmake");
    assert!(matches!(
        err,
        ZephyrError::BuildInfo {
            source: BuildInfoError::Missing { key: "cmake" },
            ..
        }
    ));

    // A west list row with three fields.
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    fs::write(
        dir.path().join("west-list.txt"),
        "manifest zephyr HEAD N/A\ncmsis modules/hal/cmsis 512cc7e\n",
    )
    .unwrap();
    let err = expect(dir.path(), true, "west-list.txt", "line 2");
    assert!(matches!(
        err,
        ZephyrError::WestList {
            source: WestListError::FieldCount { line: 2, found: 3 },
            ..
        }
    ));

    // An SPDX document with a line that is not `Tag: value`.
    let dir = copy_build_to_tempdir("bt", "beacon");
    let path = dir.path().join("spdx/modules-deps.spdx");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{text}this is not a tag\n")).unwrap();
    let lines = text.lines().count() + 1;
    expect(
        dir.path(),
        true,
        "spdx/modules-deps.spdx",
        &format!("line {lines}"),
    );
}

#[test]
fn truncated_fixture_spdx_is_error_naming_file_and_never_panics() {
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    let path = dir.path().join("spdx/zephyr.spdx");
    let full = fs::read(&path).unwrap();
    let text = String::from_utf8(full.clone()).unwrap();

    let in_text_block = text.find("<text>\n").unwrap() + "<text>\n".len();
    let package_line = text.find("PackageName: ").unwrap();
    let after_package_name = package_line + text[package_line..].find('\n').unwrap() + 1;
    let must_fail = [in_text_block, after_package_name];

    let mut offsets: Vec<usize> = (0..64).map(|i| i * full.len() / 64).collect();
    offsets.extend(must_fail);
    for offset in offsets {
        fs::write(&path, &full[..offset]).unwrap();
        match ingest_dir(dir.path(), true) {
            Ok(out) => {
                assert!(!must_fail.contains(&offset), "cut at {offset} was accepted");
                assert_schema_valid(&format!("cut at {offset}"), &render(&out.product));
            }
            Err(e) => {
                let message = e.to_string();
                assert!(
                    message.contains("spdx/zephyr.spdx"),
                    "cut at {offset}: {message:?}"
                );
            }
        }
    }
    let expected_line = |offset: usize| text[..offset].lines().count();
    fs::write(&path, &full[..in_text_block]).unwrap();
    assert!(matches!(
        ingest_dir(dir.path(), true),
        Err(ZephyrError::Spdx { source: SpdxError::UnterminatedText { line }, .. })
            if line as usize == expected_line(in_text_block)
    ));
    fs::write(&path, &full[..after_package_name]).unwrap();
    assert!(matches!(
        ingest_dir(dir.path(), true),
        Err(ZephyrError::Spdx {
            source: SpdxError::SectionWithoutSpdxId {
                tag: "PackageName",
                ..
            },
            ..
        })
    ));
}

#[test]
fn config_with_unknown_syntax_is_error_naming_file() {
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    let path = dir.path().join("zephyr/.config");
    let original = fs::read_to_string(&path).unwrap();
    let line = original.lines().count() + 1;
    for bad in ["CONFIG_FOO", "CONFIG_X=", "foo bar"] {
        fs::write(&path, format!("{original}{bad}\n")).unwrap();
        let err = ingest_dir(dir.path(), true).unwrap_err();
        let message = err.to_string();
        assert!(
            matches!(
                &err,
                ZephyrError::Kconfig { path, source: KconfigError::UnknownSyntax { line: l } }
                    if path.ends_with("zephyr/.config") && *l as usize == line
            ),
            "{bad:?}: {message}"
        );
        assert!(message.contains("zephyr/.config"), "{message}");
        assert!(message.contains(&format!("line {line}")), "{message}");
    }
}

#[test]
fn missing_build_info_is_error_naming_file() {
    let dir = copy_build_to_tempdir("baseline", "with_mcuboot");
    fs::remove_file(dir.path().join("build_info.yml")).unwrap();
    let err = ingest_dir(dir.path(), true).unwrap_err();
    assert!(err.is_not_found(), "{err}");
    assert!(err.to_string().contains("build_info.yml"), "{err}");
    // A build directory that does not exist at all names the file it looked for.
    let err = ingest_dir(&dir.path().join("absent"), false).unwrap_err();
    assert!(err.is_not_found());
    assert!(err.to_string().contains("absent"), "{err}");
    // So does a missing zephyr.spdx, which is required too.
    let dir = copy_build_to_tempdir("bt", "beacon");
    fs::remove_file(dir.path().join("spdx/zephyr.spdx")).unwrap();
    let err = ingest_dir(dir.path(), true).unwrap_err();
    assert!(err.is_not_found());
    assert!(err.to_string().contains("spdx/zephyr.spdx"), "{err}");
}

#[test]
fn missing_optional_files_warn_and_still_validate() {
    let dir = copy_build_to_tempdir("tls", "http_server");
    for rel in [
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "zephyr/.config",
    ] {
        fs::remove_file(dir.path().join(rel)).unwrap();
    }
    let out = ingest_dir(dir.path(), false).unwrap();
    let locations: Vec<&str> = out.warnings.iter().map(|w| w.location.as_str()).collect();
    assert_eq!(
        locations,
        [
            "spdx/app.spdx",
            "spdx/build.spdx",
            "spdx/modules-deps.spdx",
            "zephyr/.config",
            "west list",
        ]
    );
    for w in &out.warnings {
        assert!(!w.message.is_empty());
        assert!(w.to_string().starts_with(&format!("{}: ", w.location)));
    }
    assert_schema_valid("tls without optional files", &render(&out.product));
    // Every module is still there, from zephyr.spdx alone.
    assert_eq!(libraries(&out.product), west_list_modules("tls"));
}

// --- The seed identifier database (`db/identifiers.yaml`) on the fixtures ---------------------

/// The seed identifier database shipped with rollcall.
fn seed_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("db/identifiers.yaml")
}

/// Values of `field` evidence from the identifier database.
fn identifier_db_values(component: &Component, field: EvidenceField) -> Vec<String> {
    component
        .evidence
        .iter()
        .filter(|e| e.field == field && e.source() == "identifier-db")
        .map(|e| e.value.clone())
        .collect()
}

/// Each fixture module, the NVD-dictionary CPE the seed gives it (`None` when its upstream has
/// no dictionary entry, checked 2026-10-01; see docs/identifiers.md), and every CPE the
/// component then carries, primary first. Zephyr v4.4's own `modules-deps.spdx` names mbedtls
/// and tf-psa-crypto under `arm`, so that is the primary CPE and the database's
/// `trustedfirmware` one is an additional CPE.
#[allow(clippy::type_complexity)]
const FIXTURE_MODULE_CPES: [(&str, Option<&str>, &[&str]); 6] = [
    ("cmsis", None, &[]),
    ("cmsis_6", None, &[]),
    ("hal_nordic", None, &[]),
    (
        "mbedtls",
        Some("cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*"),
        &[
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*",
        ],
    ),
    ("mcuboot", None, &[]),
    (
        "tf-psa-crypto",
        Some("cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*"),
        &[
            "cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*",
        ],
    ),
];

/// The `syft:cpe23` property values of the library component `name` in a CycloneDX text.
fn syft_cpes(text: &str, name: &str) -> Vec<String> {
    fn walk<'v>(v: &'v Value, name: &str, out: &mut Vec<&'v Value>) {
        if let Some(components) = v["components"].as_array() {
            for c in components {
                if c["type"] == "library" && c["name"] == name {
                    out.push(c);
                }
                walk(c, name, out);
            }
        }
    }
    let doc: Value = serde_json::from_str(text).unwrap();
    let mut found = Vec::new();
    walk(&doc, name, &mut found);
    assert_eq!(found.len(), 1, "{name}");
    found[0]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["name"] == "syft:cpe23")
        .map(|p| p["value"].as_str().unwrap().to_owned())
        .collect()
}

/// Every CPE a component carries: the primary, then the additional ones in order.
fn emitted_cpes(c: &Component) -> Vec<&str> {
    c.cpe
        .iter()
        .chain(&c.additional_cpes)
        .map(|cpe| cpe.as_str())
        .collect()
}

#[test]
fn fixture_modules_resolve_a_purl_and_nvd_listed_modules_their_cpe() {
    let expected: std::collections::BTreeMap<&str, (Option<&str>, &[&str])> = FIXTURE_MODULE_CPES
        .into_iter()
        .map(|(module, nvd, emitted)| (module, (nvd, emitted)))
        .collect();
    let (mut modules, mut with_purl, mut with_db_purl, mut with_nvd_cpe) = (0, 0, 0, 0);
    let mut seen = BTreeSet::new();
    for (variant, image) in APP_BUILDS.into_iter().chain(MCUBOOT_BUILDS) {
        let options = options(variant, image, true, false).with_identifier_db(seed_db_path());
        let out = zephyr::ingest(&options).unwrap_or_else(|e| panic!("{variant}/{image}: {e}"));
        assert!(
            out.unknown_modules.is_empty(),
            "{variant}/{image}: {:?}",
            out.unknown_modules
        );
        let text = render(&out.product);
        assert_schema_valid(&format!("{variant}/{image}"), &text);
        for c in out
            .product
            .images
            .iter()
            .flat_map(|i| &i.components)
            .filter(|c| c.kind == ComponentKind::Library)
        {
            let what = format!("{variant}/{image} {}", c.name);
            let Some((nvd_cpe, want_emitted)) = expected.get(c.name.as_str()) else {
                panic!("{what}: not a known fixture module; add it to FIXTURE_MODULE_CPES");
            };
            seen.insert(c.name.clone());
            modules += 1;
            // A purl on the component, and an upstream one from the database.
            if c.purl.is_some() {
                with_purl += 1;
            }
            let db_purls = identifier_db_values(c, EvidenceField::Purl);
            assert_eq!(db_purls.len(), 1, "{what}: {db_purls:?}");
            assert!(
                db_purls[0].starts_with("pkg:generic/"),
                "{what}: {db_purls:?}"
            );
            with_db_purl += 1;
            // Exactly these CPEs, including the dictionary's; none constructed.
            let emitted = emitted_cpes(c);
            assert_eq!(emitted, *want_emitted, "{what}");
            let db_cpes = identifier_db_values(c, EvidenceField::Cpe);
            match nvd_cpe {
                Some(cpe) => {
                    assert!(emitted.contains(cpe), "{what}: {emitted:?} lacks {cpe}");
                    assert!(db_cpes.iter().any(|v| v == cpe), "{what}: {db_cpes:?}");
                    // Each additional CPE reaches grype as a syft:cpe23 property.
                    let extra: Vec<&str> = c.additional_cpes.iter().map(|c| c.as_str()).collect();
                    assert_eq!(syft_cpes(&text, &c.name), extra, "{what}");
                    with_nvd_cpe += 1;
                }
                None => assert!(db_cpes.is_empty(), "{what}: constructed cpe {db_cpes:?}"),
            }
        }
    }
    assert_eq!(
        seen.iter().map(String::as_str).collect::<Vec<_>>(),
        expected.keys().copied().collect::<Vec<_>>(),
        "every fixture module is checked"
    );
    let listed = expected.values().filter(|(nvd, _)| nvd.is_some()).count();
    // 6 modules in each of 6 builds: every one has a purl (all from the database too); the 2
    // NVD-listed modules (12 components) carry their dictionary CPE; the 4 others none.
    assert_eq!(modules, 6 * MODULES_PER_VARIANT);
    assert_eq!((with_purl, with_db_purl), (36, 36));
    assert_eq!((listed, with_nvd_cpe), (2, 12));
    println!(
        "{modules} module components in 6 builds: purl {with_purl}/{modules}, database purl \
         {with_db_purl}/{modules}, NVD-dictionary cpe {with_nvd_cpe}/{modules}; distinct \
         modules {}, NVD-listed {listed}",
        expected.len()
    );
}

/// `fixtures/zephyr-old-mbedtls/old-mbedtls/`: the real Zephyr v4.2.0 build (see
/// docs/fixtures.md), whose mbedTLS fork commit is Mbed TLS 3.6.4.
fn old_mbedtls_variant_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr-old-mbedtls/old-mbedtls")
}

/// The application image of the old-mbedTLS build, with its west list and the seed database.
fn ingest_old_mbedtls() -> Ingest {
    let variant = old_mbedtls_variant_dir();
    let options = IngestOptions::new(variant.join("mbedtls"))
        .with_west_list(variant.join("west-list.txt"))
        .with_identifier_db(seed_db_path());
    zephyr::ingest(&options).unwrap_or_else(|e| panic!("{}: {e}", variant.display()))
}

/// Zephyr v4.2.0's own `modules-deps.spdx` names mbedtls `arm:mbed_tls:3.6.4`, which stays the
/// primary CPE; the seed database's `trustedfirmware` CPE is an additional one (written as a
/// `syft:cpe23` property), so grype searches both vendors NVD files 3.6.4's CVEs under.
#[test]
fn old_mbedtls_fixture_resolves_mbedtls_3_6_4_with_both_cpes() {
    let out = ingest_old_mbedtls();
    let mbedtls = out
        .product
        .images
        .iter()
        .flat_map(|i| &i.components)
        .find(|c| c.name == "mbedtls")
        .expect("mbedtls component");
    assert_eq!(
        mbedtls.version.as_deref(),
        Some("85440ef5fffa95d0e9971e9163719189cf34d979")
    );
    assert_eq!(
        identifier_db_values(mbedtls, EvidenceField::Version),
        ["3.6.4"]
    );
    assert_eq!(
        emitted_cpes(mbedtls),
        [
            "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*",
        ]
    );
    // Zephyr v4.2.0 writes the purl ExternalRef with the SPDX 2.2 category spelling
    // `PACKAGE_MANAGER`, which ingestion (reading SPDX 2.3's `PACKAGE-MANAGER`) does not take,
    // so the database's upstream purl is the component's.
    let deps = fs::read_to_string(old_mbedtls_variant_dir().join("mbedtls/spdx/modules-deps.spdx"))
        .unwrap();
    assert!(deps.contains("ExternalRef: PACKAGE_MANAGER purl pkg:github/Mbed-TLS/mbedtls@v3.6.4"));
    let db_purl =
        "pkg:generic/mbedtls@3.6.4?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2FMbed-TLS%2Fmbedtls";
    assert_eq!(mbedtls.purl.as_ref().map(|p| p.as_str()), Some(db_purl));
    assert_eq!(
        identifier_db_values(mbedtls, EvidenceField::Purl),
        [db_purl]
    );
    assert!(
        !out.unknown_modules.iter().any(|m| m.name == "mbedtls"),
        "{:?}",
        out.unknown_modules
    );
    let text = render(&out.product);
    assert_schema_valid("old-mbedtls", &text);
    assert_eq!(
        syft_cpes(&text, "mbedtls"),
        ["cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"]
    );
    // The SPDX cpe `arm:mbed_tls` is one of the database's cpe_aliases: the same project under
    // another NVD vendor, so the difference is not a warning.
    let differs: Vec<&str> = out
        .warnings
        .iter()
        .map(|w| w.message.as_str())
        .filter(|m| m.starts_with("module mbedtls:") && m.contains("differs"))
        .collect();
    assert!(differs.is_empty(), "{differs:?}");
}

#[test]
fn old_mbedtls_fixture_matches_golden() {
    let out = ingest_old_mbedtls();
    check_golden("old-mbedtls.cdx.json", &render(&out.product));
    check_golden("old-mbedtls.model.json", &out.product.to_json().unwrap());
}
