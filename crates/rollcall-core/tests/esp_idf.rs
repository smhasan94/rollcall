//! ESP-IDF ingestion (SHA-129) against the real builds in `fixtures/esp-idf/`: `hello-world`
//! (`examples/get-started/hello_world`) and `wifi-tls` (`examples/protocols/https_request`),
//! both built for esp32 in the pinned `espressif/idf:v5.5.1` image.
//!
//! The `tests/golden/esp-idf/*` files are generated only by `scripts/regen-golden.sh`, which
//! runs this test with `ROLLCALL_BLESS=1`. Never edit them by hand. The fixtures are never
//! modified: negative tests copy files into a temporary directory first.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use common::GOLDEN_TIMESTAMP;
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::esp_idf::{
    self, EspIdfError, EspIdfIngest, EspIdfOptions, LockSource, dependencies_lock, idf_component,
    sdkconfig,
};
use rollcall_core::identify::{self, DbSource};
use rollcall_core::model::{Component, ComponentKind, Image, ImageKind, Product};
use rollcall_core::report::{self, Input};
use rollcall_core::zephyr::{self, IngestOptions};
use serde_json::Value;

const VARIANTS: [&str; 2] = ["hello-world", "wifi-tls"];

fn fixture(variant: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/esp-idf")
        .join(variant)
}

fn options(variant: &str) -> EspIdfOptions {
    EspIdfOptions::new(fixture(variant)).with_idf_path(fixture(variant).join("idf"))
}

fn ingest(options: &EspIdfOptions) -> EspIdfIngest {
    esp_idf::ingest(options).unwrap_or_else(|e| panic!("{e}"))
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/esp-idf")
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

fn app_image(product: &Product) -> &Image {
    product
        .images
        .iter()
        .find(|i| i.kind == ImageKind::Application)
        .unwrap()
}

fn blob_images(product: &Product) -> Vec<&Image> {
    product
        .images
        .iter()
        .filter(|i| i.kind == ImageKind::Blob)
        .collect()
}

fn idf_component(product: &Product) -> &Component {
    app_image(product)
        .components
        .iter()
        .find(|c| c.name == esp_idf::IDF_COMPONENT)
        .unwrap()
}

fn lock(variant: &str) -> Option<dependencies_lock::Lock> {
    let path = fixture(variant).join("dependencies.lock");
    path.is_file()
        .then(|| dependencies_lock::parse(&fs::read_to_string(path).unwrap()).unwrap())
}

// --- AC1: schema-valid SBOMs and a readiness score close to Zephyr's -------------------------

#[test]
fn both_fixtures_render_schema_valid_cyclonedx() {
    for variant in VARIANTS {
        let out = ingest(&options(variant));
        assert_schema_valid(variant, &render(&out.product));
        let without = ingest(&EspIdfOptions::new(fixture(variant)));
        assert_schema_valid(
            &format!("{variant} without --idf-path"),
            &render(&without.product),
        );
    }
}

#[test]
fn fixtures_match_goldens() {
    for variant in VARIANTS {
        let out = ingest(&options(variant));
        check_golden(
            &format!("{variant}.model.json"),
            &out.product.to_json().unwrap(),
        );
        check_golden(&format!("{variant}.cdx.json"), &render(&out.product));
    }
    let without = ingest(&EspIdfOptions::new(fixture("wifi-tls")));
    check_golden("wifi-tls.no-idf-path.cdx.json", &render(&without.product));
}

#[test]
fn every_committed_esp_idf_golden_validates_against_schema_1_6() {
    let mut seen = 0;
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".cdx.json") {
            assert_schema_valid(&name, &fs::read_to_string(&path).unwrap());
            seen += 1;
        }
    }
    assert_eq!(seen, 3);
}

/// The readiness score (`rollcall report`, without scans) of a CycloneDX document.
fn score(sbom: &str) -> u32 {
    let r = report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: sbom.as_bytes(),
        },
        &[],
        &[],
        &Timestamp::parse(GOLDEN_TIMESTAMP).unwrap(),
    )
    .unwrap();
    r.score.value
}

/// AC1 (as amended on the ticket, 2026-10-04): each ESP-IDF fixture's readiness score is no
/// more than 10 points below the lowest Zephyr fixture score. The Zephyr fixtures are
/// ingested as `rollcall report`'s goldens are (`--sysbuild --west-list … --identify`).
#[test]
fn readiness_score_is_within_10_points_of_the_zephyr_fixtures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let db = identify::builtin().unwrap();
    let mut zephyr_scores = BTreeMap::new();
    for dir in [
        "zephyr/baseline",
        "zephyr/bt",
        "zephyr/tls",
        "zephyr-old-mbedtls/old-mbedtls",
        "zephyr-smp/smp-serial",
        "zephyr-smp/smp-bt",
    ] {
        let build = root.join(dir);
        let options = IngestOptions::new(&build)
            .with_sysbuild(true)
            .with_west_list(build.join("west-list.txt"));
        let product = zephyr::ingest_with_db(&options, Some(&db)).unwrap().product;
        let write = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap())
            .with_properties(identify::provenance(&db, &DbSource::Embedded));
        zephyr_scores.insert(dir, score(&cyclonedx::write(&product, &write).unwrap()));
    }
    let lowest = *zephyr_scores.values().min().unwrap();
    for variant in VARIANTS {
        let esp = score(&render(&ingest(&options(variant)).product));
        assert!(
            esp + 10 >= lowest,
            "{variant} scores {esp}, more than 10 below the lowest Zephyr score {lowest} ({zephyr_scores:?})"
        );
    }
}

// --- AC2: identifiers for every managed component and ESP-IDF; blobs carry hashes ------------

#[test]
fn every_lock_dependency_is_a_component_with_a_purl() {
    let mut checked = 0;
    for variant in VARIANTS {
        let out = ingest(&options(variant));
        let image = app_image(&out.product);
        let Some(lock) = lock(variant) else {
            // hello_world has no manifest and so no lock: only esp-idf.
            let names: Vec<&str> = image.components.iter().map(|c| c.name.as_str()).collect();
            assert_eq!(names, [esp_idf::IDF_COMPONENT], "{variant}");
            continue;
        };
        for (name, entry) in &lock.dependencies {
            if entry.source == LockSource::Idf {
                continue;
            }
            let c = image
                .components
                .iter()
                .find(|c| c.name == *name)
                .unwrap_or_else(|| panic!("{variant}: {name} is not a component"));
            assert!(c.purl.is_some(), "{variant}: {name} has no purl");
            assert!(c.version.is_some(), "{variant}: {name} has no version");
            checked += 1;
        }
        // https_request's only managed component is ESP-IDF's protocol_examples_common, a
        // local component inside the tree: the esp-idf purl with its directory as subpath.
        let pec = image
            .components
            .iter()
            .find(|c| c.name == "protocol_examples_common")
            .unwrap();
        assert_eq!(
            pec.purl.as_ref().unwrap().as_str(),
            "pkg:generic/esp-idf@5.5.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-idf#examples/common_components/protocol_examples_common"
        );
        assert_eq!(pec.version.as_deref(), Some("5.5.1"));
    }
    assert_eq!(checked, 1);
}

#[test]
fn esp_idf_component_has_version_purl_cpe_and_supplier() {
    for variant in VARIANTS {
        let out = ingest(&options(variant));
        let idf = idf_component(&out.product);
        assert_eq!(idf.kind, ComponentKind::Framework, "{variant}");
        assert_eq!(idf.version.as_deref(), Some("5.5.1"), "{variant}");
        assert_eq!(
            idf.purl.as_ref().unwrap().as_str(),
            "pkg:generic/esp-idf@5.5.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-idf"
        );
        assert_eq!(
            idf.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:espressif:esp-idf:5.5.1:*:*:*:*:*:*:*"
        );
        assert_eq!(idf.supplier.as_ref().unwrap().name(), "Espressif Systems");
        assert_eq!(idf.licence.as_ref().unwrap().as_str(), "Apache-2.0");
        // Every subsystem has an identifier too.
        for sub in &idf.components {
            assert!(sub.purl.is_some(), "{variant}: {} has no purl", sub.name);
        }
        // The version is confirmed by the version file, the lock and the sdkconfig header:
        // no disagreement warning.
        assert!(
            !out.warnings
                .iter()
                .any(|w| w.message.contains("says ESP-IDF")),
            "{:?}",
            out.warnings
        );
    }
}

#[test]
fn every_linked_blob_has_a_sha256_matching_the_fixture_manifest() {
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(fixture("").join("MANIFEST.json")).unwrap())
            .unwrap();
    let recorded: BTreeMap<&str, &str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["path"].as_str().unwrap(), f["sha256"].as_str().unwrap()))
        .collect();
    for variant in VARIANTS {
        let out = ingest(&options(variant));
        let blobs = blob_images(&out.product);
        // The fixture holds every blob archive the map lists as a member; the image's blobs
        // are those with code in it (wifi-tls: all but libmesh.a).
        let expected = manifest["variants"][variant]["blobs"].as_array().unwrap();
        assert_eq!(
            blobs.len(),
            if variant == "wifi-tls" { 6 } else { 0 },
            "{variant}"
        );
        assert!(blobs.len() <= expected.len());
        for blob in blobs {
            let hash = blob
                .hashes
                .iter()
                .next()
                .unwrap_or_else(|| panic!("{} has no hash", blob.name));
            let path = expected
                .iter()
                .map(|p| p.as_str().unwrap())
                .find(|p| p.ends_with(&format!("/{}.a", blob.name)))
                .unwrap();
            assert_eq!(
                Some(hash.digest()),
                recorded
                    .get(format!("{variant}/idf/{path}").as_str())
                    .copied(),
                "{variant}: {}",
                blob.name
            );
            assert_eq!(blob.supplier.as_ref().unwrap().name(), "Espressif Systems");
            assert!(
                blob.purl
                    .as_ref()
                    .unwrap()
                    .as_str()
                    .ends_with(&format!("#{path}"))
            );
        }
        assert!(
            out.warnings
                .iter()
                .all(|w| !w.message.contains("--idf-path"))
        );
    }
    // Without --idf-path the blobs are still listed, without hashes, and one warning says so.
    let out = ingest(&EspIdfOptions::new(fixture("wifi-tls")));
    assert_eq!(blob_images(&out.product).len(), 6);
    assert!(
        blob_images(&out.product)
            .iter()
            .all(|b| b.hashes.is_empty())
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.message.contains("pass --idf-path"))
    );
}

// --- TP2: dependencies.lock and sdkconfig parsing of the real files --------------------------

#[test]
fn fixture_sdkconfig_lock_and_manifests_parse() {
    for variant in VARIANTS {
        let text = fs::read_to_string(fixture(variant).join("sdkconfig")).unwrap();
        let config = sdkconfig::parse(&text).unwrap_or_else(|e| panic!("{variant}: {e}"));
        assert_eq!(config.target().map(|(t, _)| t), Some("esp32"));
        assert_eq!(config.header_version().map(|(v, _)| v), Some("5.5.1"));
    }
    let lock = lock("wifi-tls").unwrap();
    assert_eq!(lock.format.as_deref(), Some("2.0.0"));
    assert_eq!(lock.idf_version(), Some("5.5.1"));
    assert_eq!(lock.direct_dependencies, ["protocol_examples_common"]);
    let manifest = idf_component::parse(
        &fs::read_to_string(fixture("wifi-tls").join("main/idf_component.yml")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.dependencies, ["protocol_examples_common"]);
}

// --- TP3: the Wi-Fi example differs from hello_world exactly in Wi-Fi/TLS and blobs ---------

/// Every node below the application image, by its path of names (`esp-idf/mbedtls`), with the
/// facts that identify it (evidence aside: it cites lines of different files).
fn nodes(product: &Product) -> BTreeMap<String, String> {
    fn walk(prefix: &str, c: &Component, out: &mut BTreeMap<String, String>) {
        let path = format!("{prefix}{}", c.name);
        let facts = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            c.kind,
            c.version,
            c.purl.as_ref().map(|p| p.as_str().to_owned()),
            c.cpe.as_ref().map(|p| p.as_str().to_owned()),
            c.supplier.as_ref().map(|s| s.name().to_owned()),
            c.licence.as_ref().map(|l| l.as_str().to_owned()),
            c.hashes
        );
        out.insert(path.clone(), facts);
        for sub in &c.components {
            walk(&format!("{path}/"), sub, out);
        }
    }
    let mut out = BTreeMap::new();
    for c in &app_image(product).components {
        walk("", c, &mut out);
    }
    for blob in blob_images(product) {
        out.insert(
            format!("blob:{}", blob.name),
            format!("{:?} {:?} {:?}", blob.version, blob.purl, blob.hashes),
        );
    }
    out
}

#[test]
fn wifi_tls_differs_from_hello_world_exactly_in_wifi_tls_subsystems_and_blobs() {
    let hello = nodes(&ingest(&options("hello-world")).product);
    let wifi = nodes(&ingest(&options("wifi-tls")).product);
    // Nothing of hello_world is missing from the Wi-Fi build, and what they share is the same.
    for (path, facts) in &hello {
        assert_eq!(wifi.get(path), Some(facts), "{path}");
    }
    let added: BTreeSet<&str> = wifi
        .keys()
        .filter(|k| !hello.contains_key(*k))
        .map(String::as_str)
        .collect();
    assert_eq!(
        added,
        BTreeSet::from([
            // The Wi-Fi and TLS subsystems of esp-idf.
            "esp-idf/esp-tls",
            "esp-idf/lwip",
            "esp-idf/mbedtls",
            "esp-idf/wifi",
            // The Wi-Fi and PHY blobs. libmesh.a is pulled in as an archive member but none
            // of its sections is in the image (garbage-collected): not a blob of the image.
            "blob:libcore",
            "blob:libespnow",
            "blob:libnet80211",
            "blob:libphy",
            "blob:libpp",
            "blob:librtc",
            // The example's one managed component: ESP-IDF's protocol_examples_common, the
            // helper that brings Wi-Fi up (example_connect), from its dependencies.lock.
            "protocol_examples_common",
        ])
    );
    // Every addition is a Wi-Fi/TLS subsystem, a blob or a lock entry; nothing else moved.
    let lock = lock("wifi-tls").unwrap();
    for path in added {
        let ok = matches!(
            path,
            "esp-idf/esp-tls" | "esp-idf/lwip" | "esp-idf/mbedtls" | "esp-idf/wifi"
        ) || path.starts_with("blob:")
            || lock.dependencies.contains_key(path);
        assert!(ok, "{path}");
    }
}

// --- Errors, never panics, on malformed inputs -------------------------------------------------

/// A copy of the wifi-tls fixture (without its blobs) in a temporary directory.
fn copy_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let src = fixture("wifi-tls");
    for rel in [
        "sdkconfig",
        "dependencies.lock",
        "main/idf_component.yml",
        "build/project_description.json",
        "build/https_request.map",
    ] {
        let to = dir.path().join(rel);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(src.join(rel), to).unwrap();
    }
    dir
}

#[test]
fn malformed_inputs_error_with_the_file_and_never_panic() {
    let cases: [(&str, &[u8], &str); 9] = [
        (
            "build/project_description.json",
            b"{\"project_name\": ",
            "project_description.json",
        ),
        ("build/project_description.json", b"", "empty file"),
        (
            "build/project_description.json",
            b"\xff\xfe{}",
            "not valid UTF-8",
        ),
        ("sdkconfig", b"CONFIG_A=y\nnot a line\n", "line 2"),
        (
            "dependencies.lock",
            b"dependencies: [\n",
            "dependencies.lock",
        ),
        (
            "dependencies.lock",
            b"dependencies:\n  a: 1\n",
            "dependencies.a",
        ),
        (
            "main/idf_component.yml",
            b"dependencies: [x]\n",
            "idf_component.yml",
        ),
        (
            "build/https_request.map",
            b"not a map\n",
            "not a GNU ld map",
        ),
        (
            "build/https_request.map",
            b"Linker script and memory map\n .text 0xZZ 0x1 a.o\n",
            "https_request.map",
        ),
    ];
    for (file, contents, needle) in cases {
        let dir = copy_fixture();
        fs::write(dir.path().join(file), contents).unwrap();
        let result = esp_idf::ingest(&EspIdfOptions::new(dir.path()));
        match result {
            Err(e) => {
                assert!(!e.is_read_error(), "{file}: {e}");
                let message = e.to_string();
                assert!(
                    message.contains(needle),
                    "{file}: {message:?} lacks {needle:?}"
                );
            }
            // A map line that is not an input section is skipped, as GNU ld's own format
            // allows; that is not a panic either.
            Ok(_) => assert_eq!(file, "build/https_request.map", "{file} was accepted"),
        }
    }
    // Truncated at any point, each text input is an error or a smaller product, never a
    // panic.
    for file in [
        "dependencies.lock",
        "sdkconfig",
        "build/project_description.json",
    ] {
        let full = fs::read(fixture("wifi-tls").join(file)).unwrap();
        let dir = copy_fixture();
        for cut in (0..full.len()).step_by((full.len() / 40).max(1)) {
            fs::write(dir.path().join(file), &full[..cut]).unwrap();
            let _ = esp_idf::ingest(&EspIdfOptions::new(dir.path()));
        }
    }
}

#[test]
fn missing_inputs_are_read_errors_and_optional_ones_warn() {
    for file in ["sdkconfig", "build/project_description.json"] {
        let dir = copy_fixture();
        fs::remove_file(dir.path().join(file)).unwrap();
        let err = esp_idf::ingest(&EspIdfOptions::new(dir.path())).unwrap_err();
        assert!(err.is_read_error(), "{file}: {err}");
        assert!(matches!(err, EspIdfError::Read { .. }));
    }
    let dir = copy_fixture();
    fs::remove_file(dir.path().join("dependencies.lock")).unwrap();
    fs::remove_file(dir.path().join("build/https_request.map")).unwrap();
    let out = esp_idf::ingest(&EspIdfOptions::new(dir.path())).unwrap();
    let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    assert!(
        text.iter()
            .any(|w| w.starts_with("dependencies.lock: missing although")),
        "{text:?}"
    );
    assert!(
        text.iter()
            .any(|w| w.starts_with("build/https_request.map: no link map")),
        "{text:?}"
    );
    assert!(idf_component(&out.product).components.is_empty());
    // A custom build directory is honoured.
    let dir = copy_fixture();
    fs::rename(dir.path().join("build"), dir.path().join("out")).unwrap();
    let out =
        esp_idf::ingest(&EspIdfOptions::new(dir.path()).with_build_dir(dir.path().join("out")))
            .unwrap();
    assert_eq!(idf_component(&out.product).components.len(), 4);
}

#[test]
fn ingestion_is_deterministic_and_warnings_are_pinned() {
    for variant in VARIANTS {
        let a = ingest(&options(variant));
        let b = ingest(&options(variant));
        assert_eq!(a, b);
        assert_eq!(render(&a.product), render(&b.product));
        assert!(a.warnings.is_empty(), "{variant}: {:?}", a.warnings);
    }
}

// --- No absolute path reaches the SBOM (review B1) ------------------------------------------

/// Copies `src` to `dst` recursively.
fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let path = entry.unwrap().path();
        let to = dst.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_tree(&path, &to);
        } else {
            fs::copy(&path, &to).unwrap();
        }
    }
}

/// The wifi-tls build as if made on another machine: ESP-IDF at `/home/alice/esp/esp-idf`
/// and the project at `/home/alice/proj`, with the map naming the build's own archives by
/// absolute path, gives a byte-identical SBOM with no absolute path in it.
#[test]
fn another_machines_paths_give_the_same_sbom_with_no_absolute_path() {
    let original = render(&ingest(&options("wifi-tls")).product);
    let dir = tempfile::tempdir().unwrap();
    copy_tree(&fixture("wifi-tls"), dir.path());
    let build_relative = regex::Regex::new(r"(?m)(^|[ \t])esp-idf/").unwrap();
    for rel in [
        "build/project_description.json",
        "build/https_request.map",
        "dependencies.lock",
    ] {
        let path = dir.path().join(rel);
        let mut text = fs::read_to_string(&path).unwrap();
        text = text
            .replace("/opt/esp/idf", "/home/alice/esp/esp-idf")
            .replace("/project/wifi-tls", "/home/alice/proj");
        if rel.ends_with(".map") {
            text = build_relative
                .replace_all(&text, "${1}/home/alice/proj/build/esp-idf/")
                .into_owned();
            assert!(text.contains("/home/alice/proj/build/esp-idf/lwip/liblwip.a("));
        }
        fs::write(&path, text).unwrap();
    }
    let moved =
        esp_idf::ingest(&EspIdfOptions::new(dir.path()).with_idf_path(dir.path().join("idf")))
            .unwrap();
    assert!(moved.warnings.is_empty(), "{:?}", moved.warnings);
    let moved = render(&moved.product);
    for needle in [
        "/home/",
        "/opt/",
        "/project/",
        "/Users/",
        "/tmp/",
        "/private/",
    ] {
        assert!(
            !original.contains(needle),
            "the fixture's SBOM contains {needle}"
        );
        assert!(
            !moved.contains(needle),
            "the moved build's SBOM contains {needle}"
        );
    }
    assert!(
        moved == original,
        "the SBOM depends on where the build and the tree live"
    );
}

// --- Registry and git components end to end (review S5) --------------------------------------

/// A hand-written model project (not a real build, so it lives in a temporary directory and
/// not under `fixtures/`): one registry component with a manifest whose version differs from
/// the lock's, one registry component without a manifest, and one git component whose
/// manifest has a licence that is not SPDX.
fn model_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let path = dir.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };
    write(
        "build/project_description.json",
        r#"{"project_name": "model", "project_version": "2.0.0", "idf_path": "/opt/esp/idf",
           "git_revision": "v5.5.1", "target": "esp32", "build_dir": "/project/model/build"}"#,
    );
    write(
        "sdkconfig",
        "# Espressif IoT Development Framework (ESP-IDF) 5.5.1 Project Configuration\nCONFIG_IDF_TARGET=\"esp32\"\n",
    );
    write(
        "main/idf_component.yml",
        "dependencies:\n  espressif/mdns: ^1.8.0\n  espressif/cjson: ^1.7.0\n  esp_jpeg:\n    git: https://github.com/espressif/idf-extra-components.git\n    path: esp_jpeg\n",
    );
    write(
        "dependencies.lock",
        "dependencies:
  esp_jpeg:
    component_hash: null
    dependencies:
    - name: idf
      require: private
      version: '>=4.4'
    source:
      git: https://github.com/espressif/idf-extra-components.git
      path: esp_jpeg
      type: git
    version: 9d2c4f8c4b5f8b6a1b3e1c1f2d0a2e7b8c9d0e1f
  espressif/cjson:
    component_hash: e788323270d90738662d66fffa910bfe1fba019bba087f01557e70c40485b469
    dependencies:
    - name: idf
      require: private
      version: '>=5.0'
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 1.7.19~2
  espressif/mdns:
    component_hash: 3ec0af5f6bce310512e90f482388d21cc7c0e99668172d2f895356165fc6f7c5
    dependencies:
    - name: espressif/cjson
      require: private
      version: '*'
    - name: idf
      require: private
      version: '>=5.0'
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 1.8.2
  idf:
    source:
      type: idf
    version: 5.5.1
direct_dependencies:
- esp_jpeg
- espressif/cjson
- espressif/mdns
- idf
manifest_hash: 9a9520c926aa0a3e6ab6efa4fb14c3591e654d3887543776c1f730f359b02661
target: esp32
version: 2.0.0
",
    );
    write(
        "managed_components/espressif__mdns/idf_component.yml",
        "description: mDNS\nlicense: Apache-2.0\nurl: https://github.com/espressif/esp-protocols/tree/master/components/mdns\nversion: 1.8.1\n",
    );
    write(
        "managed_components/esp_jpeg/idf_component.yml",
        "description: JPEG decoder\nlicense: Espressif Modified MIT\nversion: 1.3.0\n",
    );
    dir
}

#[test]
fn registry_and_git_components_get_purls_licences_suppliers_and_warnings() {
    let dir = model_project();
    let out = esp_idf::ingest(&EspIdfOptions::new(dir.path())).unwrap();
    let image = app_image(&out.product);
    let component = |name: &str| image.components.iter().find(|c| c.name == name).unwrap();

    let mdns = component("espressif/mdns");
    assert_eq!(
        mdns.version.as_deref(),
        Some("1.8.2"),
        "the lock's version wins"
    );
    assert_eq!(
        mdns.purl.as_ref().unwrap().as_str(),
        "pkg:generic/espressif/mdns@1.8.2?repository_url=https:%2F%2Fcomponents.espressif.com"
    );
    assert_eq!(mdns.licence.as_ref().unwrap().as_str(), "Apache-2.0");
    assert_eq!(mdns.supplier.as_ref().unwrap().name(), "Espressif Systems");

    let cjson = component("espressif/cjson");
    assert_eq!(
        cjson.purl.as_ref().unwrap().as_str(),
        "pkg:generic/espressif/cjson@1.7.19~2?repository_url=https:%2F%2Fcomponents.espressif.com"
    );
    assert_eq!(cjson.licence, None, "no manifest, no licence");
    assert_eq!(cjson.supplier.as_ref().unwrap().name(), "Espressif Systems");

    let jpeg = component("esp_jpeg");
    let commit = "9d2c4f8c4b5f8b6a1b3e1c1f2d0a2e7b8c9d0e1f";
    assert_eq!(jpeg.version.as_deref(), Some(commit));
    assert_eq!(
        jpeg.purl.as_ref().unwrap().as_str(),
        format!(
            "pkg:generic/esp_jpeg@{commit}?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fidf-extra-components.git%40{commit}#esp_jpeg"
        )
    );
    assert_eq!(jpeg.licence, None, "not an SPDX expression: omitted");
    assert_eq!(jpeg.supplier, None, "no namespace, not in the ESP-IDF tree");

    let warnings: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    for expected in [
        "managed_components/espressif__mdns/idf_component.yml: espressif/mdns: version 1.8.1 differs from the lock's 1.8.2; the lock's is used",
        "managed_components/espressif__cjson/idf_component.yml: espressif/cjson: missing; its licence is not known",
        "managed_components/esp_jpeg/idf_component.yml: esp_jpeg: license \"Espressif Modified MIT\" is not an SPDX expression; licence omitted",
    ] {
        assert!(
            warnings.iter().any(|w| w == expected),
            "{expected:?} not in {warnings:#?}"
        );
    }
    // The lock's edges: image → each direct dependency, mdns → cjson, each → esp-idf.
    let text = render(&out.product);
    assert_schema_valid("model project", &text);
    let doc: Value = serde_json::from_str(&text).unwrap();
    let refs: BTreeMap<String, String> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["bom-ref"].as_str().unwrap().to_owned(),
                c["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let mut edges = BTreeSet::new();
    for d in doc["dependencies"].as_array().unwrap() {
        let from = refs.get(d["ref"].as_str().unwrap());
        for to in d["dependsOn"].as_array().into_iter().flatten() {
            if let (Some(from), Some(to)) = (from, refs.get(to.as_str().unwrap())) {
                edges.insert((from.clone(), to.clone()));
            }
        }
    }
    for (from, to) in [
        ("espressif/mdns", "espressif/cjson"),
        ("espressif/mdns", "esp-idf"),
        ("esp_jpeg", "esp-idf"),
    ] {
        assert!(
            edges.contains(&(from.to_owned(), to.to_owned())),
            "{from} -> {to}: {edges:?}"
        );
    }
}

#[test]
fn names_without_a_lock_entry_and_a_missing_idf_path_warn() {
    let dir = model_project();
    let lock = dir.path().join("dependencies.lock");
    let text = fs::read_to_string(&lock)
        .unwrap()
        .replace("- name: espressif/cjson\n", "- name: espressif/ghost\n")
        .replace("- espressif/cjson\n", "- espressif/missing\n");
    fs::write(&lock, text).unwrap();
    let desc = dir.path().join("build/project_description.json");
    let text = fs::read_to_string(&desc)
        .unwrap()
        .replace(r#""idf_path": "/opt/esp/idf","#, "");
    fs::write(&desc, text).unwrap();
    fs::write(
        dir.path().join("build/model.map"),
        "Linker script and memory map\n\n.flash.text 0x400d0000 0x10\n .text.a 0x400d0000 0x10 esp-idf/main/libmain.a(main.c.obj)\n",
    )
    .unwrap();
    let out = esp_idf::ingest(&EspIdfOptions::new(dir.path())).unwrap();
    let warnings: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    for expected in [
        "dependencies.lock: direct dependency espressif/missing has no entry in the lock; no edge to it",
        "dependencies.lock: espressif/mdns depends on espressif/ghost, which has no entry in the lock; no edge to it",
        "build/project_description.json: no idf_path: the map's ESP-IDF archives cannot be recognised, so no blob is listed",
    ] {
        assert!(
            warnings.iter().any(|w| w == expected),
            "{expected:?} not in {warnings:#?}"
        );
    }
}

// --- Upstream identifiers of Mbed TLS and lwIP (review S3, S4) -------------------------------

/// Mbed TLS and lwIP carry the upstream projects' purls in the identifier database's form
/// (naming the Espressif forks), and Mbed TLS also `arm:mbed_tls`, which NVD still files its
/// CVEs under, as an additional CPE: written as a `syft:cpe23` property, as for Zephyr's
/// mbedtls module.
#[test]
fn mbedtls_and_lwip_carry_upstream_purls_and_the_arm_cpe_alias() {
    let out = ingest(&options("wifi-tls"));
    let idf = idf_component(&out.product);
    let sub = |name: &str| idf.components.iter().find(|c| c.name == name).unwrap();
    let mbedtls = sub("mbedtls");
    assert_eq!(
        mbedtls.purl.as_ref().unwrap().as_str(),
        "pkg:generic/mbedtls@3.6.4?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fmbedtls"
    );
    assert_eq!(
        mbedtls.cpe.as_ref().unwrap().as_str(),
        "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.4:*:*:*:*:*:*:*"
    );
    let aliases: Vec<&str> = mbedtls.additional_cpes.iter().map(|c| c.as_str()).collect();
    assert_eq!(aliases, ["cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*"]);
    assert_eq!(
        sub("lwip").purl.as_ref().unwrap().as_str(),
        "pkg:generic/lwip@2.2.0d?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-lwip"
    );
    assert!(sub("lwip").additional_cpes.is_empty());
    // Without an upstream version the esp-idf purl with a subpath stays.
    assert!(
        sub("esp-tls")
            .purl
            .as_ref()
            .unwrap()
            .as_str()
            .ends_with("#components/esp-tls")
    );
    let doc: Value = serde_json::from_str(&render(&out.product)).unwrap();
    let mbedtls = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "esp-idf")
        .unwrap()["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "mbedtls")
        .unwrap()
        .clone();
    assert!(
        mbedtls["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "syft:cpe23"
                && p["value"] == "cpe:2.3:a:arm:mbed_tls:3.6.4:*:*:*:*:*:*:*"),
        "{mbedtls:#}"
    );
}
