//! PlatformIO ingestion (SHA-131) against the real build in `fixtures/platformio/`:
//! `arduino-mqtt`, an Arduino-ESP32 sketch with three registry `lib_deps` built with
//! `pio run` (PlatformIO Core 6.1.18, espressif32 6.10.0, Arduino-ESP32 2.0.17).
//!
//! The `tests/golden/platformio/*` files are generated only by `scripts/regen-golden.sh`, which
//! runs this test with `ROLLCALL_BLESS=1`. Never edit them by hand. The fixtures are never
//! modified: negative tests copy files into a temporary directory first, and the multi-env
//! projects are hand-written in temporary directories (they are not real builds).

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::GOLDEN_TIMESTAMP;
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::identify::{self, DbSource};
use rollcall_core::model::{Component, ComponentKind, Cpe, Image, ImageKind, Product, Scope};
use rollcall_core::platformio::{self, PlatformIoError, PlatformIoIngest, PlatformIoOptions};
use rollcall_core::report::{self, Input};
use rollcall_core::zephyr::{self, IngestOptions};
use serde_json::Value;

const VARIANT: &str = "arduino-mqtt";
/// (component name, version, purl) of each `lib_deps` library.
const LIBRARIES: [(&str, &str, &str); 3] = [
    (
        "bblanchon/ArduinoJson",
        "7.2.1",
        "pkg:generic/bblanchon/ArduinoJson@7.2.1?repository_url=https:%2F%2Fregistry.platformio.org",
    ),
    (
        "knolleary/PubSubClient",
        "2.8",
        "pkg:generic/knolleary/PubSubClient@2.8?repository_url=https:%2F%2Fregistry.platformio.org",
    ),
    (
        "mathertel/OneButton",
        "2.6.1",
        "pkg:generic/mathertel/OneButton@2.6.1?repository_url=https:%2F%2Fregistry.platformio.org",
    ),
];

/// The fixture's warnings: two of its libraries publish no licence.
const FIXTURE_WARNINGS: [&str; 2] = [
    ".pio/libdeps/esp32dev/ArduinoJson/library.json: bblanchon/ArduinoJson: no license in library.json; the component has no licence",
    ".pio/libdeps/esp32dev/PubSubClient/library.json: knolleary/PubSubClient: no license in library.json; the component has no licence",
];

fn warning_texts(warnings: &[platformio::Warning]) -> Vec<String> {
    warnings.iter().map(ToString::to_string).collect()
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/platformio")
        .join(VARIANT)
}

fn options() -> PlatformIoOptions {
    PlatformIoOptions::new(fixture()).with_core_dir(fixture().join("pio-core"))
}

fn ingest(options: &PlatformIoOptions) -> PlatformIoIngest {
    platformio::ingest(options).unwrap_or_else(|e| panic!("{e}"))
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
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/platformio")
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

fn image(product: &Product) -> &Image {
    product
        .images
        .iter()
        .find(|i| i.kind == ImageKind::Application)
        .unwrap()
}

fn component<'a>(product: &'a Product, name: &str) -> &'a Component {
    image(product)
        .components
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no component {name}"))
}

// --- AC1: schema-valid SBOM with every library identified -----------------------------------

#[test]
fn fixture_renders_schema_valid_cyclonedx() {
    let out = ingest(&options());
    assert_schema_valid("arduino-mqtt", &render(&out.product));
    let without = ingest(&PlatformIoOptions::new(fixture()));
    assert_schema_valid(
        "arduino-mqtt without a core directory",
        &render(&without.product),
    );
    assert_eq!(out.env, "esp32dev");
}

#[test]
fn every_installed_library_is_a_component_with_owner_name_version_and_purl() {
    for options in [options(), PlatformIoOptions::new(fixture())] {
        let out = ingest(&options);
        let p = &out.product;
        let libraries: Vec<&Component> = image(p)
            .components
            .iter()
            .filter(|c| c.kind == ComponentKind::Library)
            .collect();
        assert_eq!(libraries.len(), 3, "{libraries:#?}");
        for (name, version, purl) in LIBRARIES {
            let c = component(p, name);
            assert_eq!(c.version.as_deref(), Some(version), "{name}");
            assert_eq!(c.purl.as_ref().map(|p| p.as_str()), Some(purl), "{name}");
            // The upstream repository's purl is recorded as evidence.
            let short = name.split('/').nth(1).unwrap();
            assert!(
                c.evidence.iter().any(|e| e.source() == "library-json"
                    && e.value.starts_with(&format!(
                        "pkg:generic/{short}@{version}?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2F"
                    ))),
                "{name}: {:#?}",
                c.evidence
            );
            // The lib_deps entry is evidence, with its line.
            assert!(
                c.evidence.iter().any(|e| e.source() == "platformio-ini"
                    && e.occurrence
                        .as_ref()
                        .is_some_and(|o| o.location() == "platformio.ini" && o.line().is_some())),
                "{name}"
            );
        }
        // OneButton's library.json carries a licence; the others carry none.
        assert_eq!(
            component(p, "mathertel/OneButton")
                .licence
                .as_ref()
                .map(|l| l.as_str()),
            Some("BSD-3-Clause")
        );
        // The image depends on each of them.
        let doc: Value = serde_json::from_str(&render(p)).unwrap();
        let image_ref = doc["components"][0]["bom-ref"].as_str().unwrap().to_owned();
        let deps = doc["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["ref"] == image_ref.as_str())
            .unwrap();
        assert_eq!(deps["dependsOn"].as_array().unwrap().len(), 4, "{deps:#}");
    }
}

#[test]
fn framework_component_has_upstream_version_purl_and_supplier() {
    for (label, options) in [
        ("core", options()),
        ("pins", PlatformIoOptions::new(fixture())),
    ] {
        let out = ingest(&options);
        let fw = component(&out.product, "arduino-esp32");
        assert_eq!(fw.kind, ComponentKind::Framework, "{label}");
        assert_eq!(fw.version.as_deref(), Some("2.0.17"), "{label}");
        assert_eq!(
            fw.purl.as_ref().map(|p| p.as_str()),
            Some(
                "pkg:generic/arduino-esp32@2.0.17?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Farduino-esp32"
            ),
            "{label}"
        );
        assert_eq!(
            fw.cpe.as_ref().map(Cpe::as_str),
            Some("cpe:2.3:a:espressif:arduino-esp32:2.0.17:*:*:*:*:*:*:*"),
            "{label}"
        );
        assert_eq!(
            fw.supplier.as_ref().map(|s| s.name()),
            Some("Espressif Systems")
        );
        assert_eq!(
            fw.licence.as_ref().map(|l| l.as_str()),
            Some("LGPL-2.1-or-later")
        );
        // The PlatformIO package version is evidence beside the upstream release.
        assert!(
            fw.evidence
                .iter()
                .any(|e| e.value.starts_with("3.20017.241212")),
            "{label}: {:#?}",
            fw.evidence
        );
        let platform = component(&out.product, "espressif32");
        assert_eq!(platform.kind, ComponentKind::Platform);
        assert_eq!(platform.scope, Some(Scope::Excluded));
        assert_eq!(platform.version.as_deref(), Some("6.10.0"), "{label}");
        assert!(
            platform
                .purl
                .as_ref()
                .unwrap()
                .as_str()
                .starts_with("pkg:generic/platformio/espressif32@6.10.0?repository_url=")
        );
    }
    // With the core directory, the versions come from the installed packages.
    let out = ingest(&options());
    let fw = component(&out.product, "arduino-esp32");
    assert!(fw.evidence.iter().any(|e| e.source() == "piopm"
        && e.occurrence.as_ref().is_some_and(
            |o| o.location() == "pio-core/packages/framework-arduinoespressif32/.piopm"
        )));
    assert_eq!(
        component(&out.product, "espressif32")
            .licence
            .as_ref()
            .map(|l| l.as_str()),
        Some("Apache-2.0")
    );
}

#[test]
fn fixture_matches_golden() {
    let out = ingest(&options());
    check_golden(
        &format!("{VARIANT}.model.json"),
        &out.product.to_json().unwrap(),
    );
    check_golden(&format!("{VARIANT}.cdx.json"), &render(&out.product));
    let without = ingest(&PlatformIoOptions::new(fixture()));
    check_golden(
        &format!("{VARIANT}.no-core.cdx.json"),
        &render(&without.product),
    );
}

#[test]
fn every_committed_platformio_golden_validates_against_schema_1_6() {
    let mut seen = 0;
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".cdx.json") {
            assert_schema_valid(&name, &fs::read_to_string(&path).unwrap());
            seen += 1;
        }
    }
    assert_eq!(seen, 2);
}

/// The readiness score (`rollcall report`, without scans) of a CycloneDX document.
fn score(sbom: &str) -> u32 {
    report::build(
        Input {
            name: "sbom.cdx.json",
            bytes: sbom.as_bytes(),
        },
        &[],
        &[],
        &Timestamp::parse(GOLDEN_TIMESTAMP).unwrap(),
    )
    .unwrap()
    .score
    .value
}

/// The epic's exit bar (decision 5): the PlatformIO fixture's readiness score is no more than
/// 10 points below the lowest Zephyr fixture score, the Zephyr fixtures ingested as
/// `rollcall report`'s goldens are (`--sysbuild --west-list … --identify`).
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
    for (label, options) in [
        ("core", options()),
        ("pins", PlatformIoOptions::new(fixture())),
    ] {
        let pio = score(&render(&ingest(&options).product));
        eprintln!("readiness: platformio ({label}) {pio}, Zephyr {zephyr_scores:?}");
        assert!(
            pio + 10 >= lowest,
            "{label}: scores {pio}, more than 10 below the lowest Zephyr score {lowest} ({zephyr_scores:?})"
        );
    }
}

#[test]
fn ingestion_is_deterministic_and_warnings_are_pinned() {
    for options in [options(), PlatformIoOptions::new(fixture())] {
        let a = ingest(&options);
        let b = ingest(&options);
        assert_eq!(a, b);
        assert_eq!(render(&a.product), render(&b.product));
        assert_eq!(warning_texts(&a.warnings), FIXTURE_WARNINGS);
    }
}

// --- No absolute path reaches the SBOM ------------------------------------------------------

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

/// Every evidence location in a model's JSON.
fn locations(model: &Value, out: &mut Vec<String>) {
    match model {
        Value::Object(map) => {
            if let Some(Value::String(l)) = map.get("location") {
                out.push(l.clone());
            }
            for v in map.values() {
                locations(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| locations(v, out)),
        _ => {}
    }
}

/// The project and the core directory moved elsewhere (a home directory, the core apart from
/// the project) give a byte-identical SBOM; every evidence location is relative and no
/// absolute path is in the output.
#[test]
fn another_machines_paths_give_the_same_sbom_with_no_absolute_path() {
    let original = ingest(&options());
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("home/alice/src").join(VARIANT);
    let core = dir.path().join("home/alice/.platformio");
    copy_tree(&fixture(), &project);
    fs::rename(project.join("pio-core"), &core).unwrap();
    let moved = ingest(&PlatformIoOptions::new(&project).with_core_dir(&core));
    assert_eq!(warning_texts(&moved.warnings), FIXTURE_WARNINGS);
    let (a, b) = (render(&original.product), render(&moved.product));
    assert!(
        a == b,
        "the SBOM depends on where the project and core directory live"
    );
    let tmp = dir.path().to_string_lossy().into_owned();
    for needle in [
        "/home/",
        "/Users/",
        "/tmp/",
        "/private/",
        "/var/",
        tmp.as_str(),
    ] {
        assert!(!a.contains(needle), "the SBOM contains {needle}");
    }
    let model: Value = serde_json::from_str(&moved.product.to_json().unwrap()).unwrap();
    let mut found = Vec::new();
    locations(&model, &mut found);
    assert!(!found.is_empty());
    for location in found {
        assert!(
            !location.starts_with('/') && !location.contains(":\\") && !location.contains(".."),
            "evidence location {location:?} is not project-relative"
        );
    }
}

// --- Malformed and missing inputs ----------------------------------------------------------

/// The fixture without its core directory, in a temporary directory named like it.
fn copy_fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(VARIANT);
    copy_tree(&fixture(), &project);
    (dir, project)
}

#[test]
fn malformed_inputs_error_with_the_file_and_never_panic() {
    let lib = ".pio/libdeps/esp32dev/ArduinoJson";
    let platform = "pio-core/platforms/espressif32";
    let package = "pio-core/packages/framework-arduinoespressif32";
    let cases: Vec<(String, &[u8], &str)> = vec![
        (
            "platformio.ini".into(),
            b"lib_deps = x\n",
            "line 1: option outside any [section]",
        ),
        (
            "platformio.ini".into(),
            b"[env:a\n",
            "malformed section header",
        ),
        (
            "platformio.ini".into(),
            b"\xff\xfe[env:a]\n",
            "not valid UTF-8",
        ),
        (
            "platformio.ini".into(),
            b"[env:esp32dev]\nlib_deps = ${nope.x}\n",
            "${nope.x} names no option",
        ),
        (
            "platformio.ini".into(),
            b"; no environments\n[platformio]\n",
            "no [env:NAME] section",
        ),
        (
            format!("{lib}/library.json"),
            b"{\"name\": ",
            "library.json: not JSON",
        ),
        (
            format!("{lib}/library.json"),
            b"{\"version\": []}",
            "version: expected a string or a number",
        ),
        (format!("{lib}/.piopm"), b"", ".piopm: not JSON"),
        (
            format!("{lib}/.piopm"),
            b"{\"name\": \"x\"}",
            "version: missing",
        ),
        (
            format!("{platform}/platform.json"),
            b"[]",
            "platform.json: expected a JSON object",
        ),
        (
            format!("{platform}/.piopm"),
            b"{\"name\": 1, \"version\": \"1\"}",
            "name: expected a string",
        ),
        (
            format!("{package}/package.json"),
            b"{\"name\": \"x\"}",
            "version: missing",
        ),
    ];
    for (file, contents, needle) in cases {
        let (_dir, project) = copy_fixture();
        fs::write(project.join(&file), contents).unwrap();
        let err = platformio::ingest(
            &PlatformIoOptions::new(&project).with_core_dir(project.join("pio-core")),
        )
        .expect_err(&file);
        assert!(!err.is_read_error(), "{file}: {err}");
        let message = err.to_string();
        assert!(
            message.contains(needle),
            "{file}: {message:?} lacks {needle:?}"
        );
        let short = file.rsplit('/').next().unwrap();
        assert!(
            message.contains(short),
            "{file}: {message:?} does not name the file"
        );
    }
    // Truncated at any point, each input is an error or a product, never a panic.
    for file in [
        "platformio.ini".to_owned(),
        format!("{lib}/library.json"),
        format!("{lib}/.piopm"),
        format!("{platform}/platform.json"),
        format!("{package}/.piopm"),
    ] {
        let full = fs::read(fixture().join(&file)).unwrap();
        let (_dir, project) = copy_fixture();
        for cut in 0..full.len() {
            fs::write(project.join(&file), &full[..cut]).unwrap();
            let _ = platformio::ingest(
                &PlatformIoOptions::new(&project).with_core_dir(project.join("pio-core")),
            );
        }
    }
}

#[test]
fn missing_inputs_are_read_errors_and_optional_ones_warn() {
    let (_dir, project) = copy_fixture();
    fs::remove_file(project.join("platformio.ini")).unwrap();
    let err = platformio::ingest(&PlatformIoOptions::new(&project)).unwrap_err();
    assert!(err.is_read_error(), "{err}");
    assert!(matches!(err, PlatformIoError::Read { .. }));
    assert!(err.to_string().contains("platformio.ini"));

    // No libraries installed: a warning naming the command to run, no library components.
    let (_dir, project) = copy_fixture();
    fs::remove_dir_all(project.join(".pio")).unwrap();
    let out = platformio::ingest(&PlatformIoOptions::new(&project)).unwrap();
    let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    assert_eq!(
        text,
        [
            ".pio/libdeps/esp32dev: no library is installed for environment esp32dev: run `pio pkg install -e esp32dev` (or `pio run`) first"
        ]
    );
    assert!(
        image(&out.product)
            .components
            .iter()
            .all(|c| c.kind != ComponentKind::Library)
    );

    // One library removed: its lib_deps entry is warned about, with its line.
    let (_dir, project) = copy_fixture();
    fs::remove_dir_all(project.join(".pio/libdeps/esp32dev/OneButton")).unwrap();
    let out = platformio::ingest(&PlatformIoOptions::new(&project)).unwrap();
    let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    assert!(
        text.iter().any(|w| w.starts_with(
            "platformio.ini:21: lib_deps mathertel/OneButton @ 2.6.1 is not installed"
        )),
        "{text:?}"
    );

    // A core directory without the packages: warnings, and the ini pins still give versions.
    let (_dir, project) = copy_fixture();
    let empty = project.join("empty-core");
    fs::create_dir_all(&empty).unwrap();
    let out = platformio::ingest(&PlatformIoOptions::new(&project).with_core_dir(&empty)).unwrap();
    let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    assert_eq!(
        text,
        [
            FIXTURE_WARNINGS[0],
            FIXTURE_WARNINGS[1],
            "pio-core/packages: framework-arduinoespressif32 3.20017.241212 is not installed in the core directory",
            "pio-core/platforms: espressif32 6.10.0 is not installed in the core directory",
        ]
    );
    assert_eq!(
        component(&out.product, "arduino-esp32").version.as_deref(),
        Some("2.0.17")
    );
}

// --- Multi-env projects and lib_deps forms (hand-written, not real builds) ------------------

/// A hand-written project in a temporary directory: `platformio.ini` and, for each
/// `(env, dir, piopm, library.json)`, an installed library.
fn model_project(ini: &str, libs: &[(&str, &str, &str, Option<&str>)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("platformio.ini"), ini).unwrap();
    for (env, name, piopm, manifest) in libs {
        let lib = dir.path().join(format!(".pio/libdeps/{env}/{name}"));
        fs::create_dir_all(&lib).unwrap();
        fs::write(lib.join(".piopm"), piopm).unwrap();
        if let Some(m) = manifest {
            fs::write(lib.join("library.json"), m).unwrap();
        }
    }
    dir
}

const MULTI_ENV: &str = "[platformio]\ndefault_envs = release\n\n[env]\nplatform = espressif32 @ 6.10.0\nframework = arduino\nplatform_packages = platformio/framework-arduinoespressif32 @ 3.20017.241212\n\n[common]\nlib_deps =\n    bblanchon/ArduinoJson @ 7.2.1\n\n[env:release]\nboard = esp32dev\nlib_deps = ${common.lib_deps}\n\n[env:debug]\nextends = env:release\nlib_deps =\n    ${common.lib_deps}\n    https://github.com/me/DebugLib.git#v1.0.0\n";

const ARDUINOJSON_PIOPM: &str = r#"{"type": "library", "name": "ArduinoJson", "version": "7.2.1", "spec": {"owner": "bblanchon", "id": 64, "name": "ArduinoJson", "requirements": null, "uri": null}}"#;

#[test]
fn multi_env_project_selects_env_by_flag_default_envs_or_errors() {
    let libs = [
        ("release", "ArduinoJson", ARDUINOJSON_PIOPM, None),
        ("debug", "ArduinoJson", ARDUINOJSON_PIOPM, None),
        (
            "debug",
            "DebugLib",
            r#"{"type": "library", "name": "DebugLib", "version": "1.0.0+sha.abcdef0", "spec": {"owner": null, "name": "DebugLib", "requirements": null, "uri": "git+https://github.com/me/DebugLib.git#v1.0.0"}}"#,
            Some(
                r#"{"name": "DebugLib", "version": "1.0.0", "dependencies": [{"owner": "bblanchon", "name": "ArduinoJson"}]}"#,
            ),
        ),
    ];
    let dir = model_project(MULTI_ENV, &libs);
    // default_envs picks release.
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    assert_eq!(out.env, "release");
    let names: Vec<&str> = image(&out.product)
        .components
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(names.len(), 3, "{names:?}");
    // --env debug inherits [env] and release's board, adds the git library.
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path()).with_env("debug")).unwrap();
    assert_eq!(out.env, "debug");
    let debug = component(&out.product, "DebugLib");
    assert_eq!(
        debug.purl.as_ref().unwrap().as_str(),
        "pkg:generic/DebugLib@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fme%2FDebugLib.git%23v1.0.0"
    );
    // Only the licences are missing: these hand-written libraries publish none.
    assert!(
        out.warnings
            .iter()
            .all(|w| w.message.ends_with("the component has no licence")),
        "{:?}",
        out.warnings
    );
    // DebugLib depends on ArduinoJson (library.json), the image on both (lib_deps).
    let doc: Value = serde_json::from_str(&render(&out.product)).unwrap();
    let edges: usize = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["dependsOn"].as_array().map_or(0, Vec::len))
        .sum();
    // product → image; image → framework, ArduinoJson, DebugLib; DebugLib → ArduinoJson.
    assert_eq!(edges, 5, "{doc:#}");
    // An unknown environment, and several with no default, are usage errors listing them.
    let err = platformio::ingest(&PlatformIoOptions::new(dir.path()).with_env("nope")).unwrap_err();
    assert!(err.is_usage_error());
    assert!(
        err.to_string()
            .contains("no environment \"nope\" (environments: debug, release)"),
        "{err}"
    );
    let dir = model_project(
        &MULTI_ENV.replace("default_envs = release", "default_envs = release, debug"),
        &libs,
    );
    let err = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap_err();
    assert!(err.is_usage_error());
    assert!(
        err.to_string()
            .contains("choose one with --env: debug, release"),
        "{err}"
    );
    let dir = model_project(&MULTI_ENV.replace("default_envs = release\n", ""), &libs);
    assert!(
        platformio::ingest(&PlatformIoOptions::new(dir.path()))
            .unwrap_err()
            .is_usage_error()
    );
    // One environment needs no choice.
    let dir = model_project("[env:only]\nplatform = espressif32\n", &[]);
    assert_eq!(
        platformio::ingest(&PlatformIoOptions::new(dir.path()))
            .unwrap()
            .env,
        "only"
    );
}

#[test]
fn version_disagreement_bad_licence_and_unknown_dependency_warn() {
    let dir = model_project(
        "[env:e]\nplatform = espressif32 @ 6.10.0\nlib_deps = bblanchon/ArduinoJson\n",
        &[(
            "e",
            "ArduinoJson",
            ARDUINOJSON_PIOPM,
            Some(
                r#"{"name": "ArduinoJson", "version": "7.2.0", "license": "MIT-ish licence", "dependencies": ["Wire"]}"#,
            ),
        )],
    );
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
    for needle in [
        "library.json: bblanchon/ArduinoJson: library.json says version 7.2.0, .piopm 7.2.1; 7.2.1 is used",
        "license \"MIT-ish licence\" is not an SPDX expression",
        "bblanchon/ArduinoJson depends on Wire, which is not installed",
    ] {
        assert!(
            text.iter().any(|w| w.contains(needle)),
            "{needle}: {text:?}"
        );
    }
    assert_eq!(
        component(&out.product, "bblanchon/ArduinoJson")
            .version
            .as_deref(),
        Some("7.2.1")
    );
}

/// Review S4: a library installed from a local path (`file://`) gets no purl (its path is the
/// build machine's), and one from an archive URL a `download_url`; no absolute path reaches
/// the SBOM.
#[test]
fn local_and_archive_libraries_get_no_host_path_in_the_sbom() {
    let dir = model_project(
        "[env:e]\nplatform = espressif32 @ 6.10.0\nlib_deps =\n    file:///home/alice/libs/LocalLib\n    https://example.com/dl/ZipLib-1.2.0.zip\n",
        &[
            (
                "e",
                "LocalLib",
                r#"{"type": "library", "name": "LocalLib", "version": "0.1.0", "spec": {"owner": null, "name": "LocalLib", "requirements": null, "uri": "file:///home/alice/libs/LocalLib"}}"#,
                Some(
                    r#"{"name": "LocalLib", "version": "0.1.0", "license": "MIT", "repository": "file:///home/alice/libs/LocalLib"}"#,
                ),
            ),
            (
                "e",
                "ZipLib",
                r#"{"type": "library", "name": "ZipLib", "version": "1.2.0", "spec": {"owner": null, "name": "ZipLib", "requirements": null, "uri": "https://example.com/dl/ZipLib-1.2.0.zip"}}"#,
                Some(r#"{"name": "ZipLib", "version": "1.2.0", "license": "MIT"}"#),
            ),
        ],
    );
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    let local = component(&out.product, "LocalLib");
    assert_eq!(local.purl, None);
    assert_eq!(
        warning_texts(&out.warnings),
        [
            ".pio/libdeps/e/LocalLib/.piopm: LocalLib: installed from a local path, which is not an identifier; no purl"
        ]
    );
    assert_eq!(
        component(&out.product, "ZipLib")
            .purl
            .as_ref()
            .unwrap()
            .as_str(),
        "pkg:generic/ZipLib@1.2.0?download_url=https:%2F%2Fexample.com%2Fdl%2FZipLib-1.2.0.zip"
    );
    let sbom = render(&out.product);
    for needle in ["/home/alice", "file:", "file%3A"] {
        assert!(!sbom.contains(needle), "the SBOM contains {needle}");
    }
}

/// Review S5: `[platformio]` options that move rollcall's inputs are warned about.
#[test]
fn unfollowed_platformio_options_warn() {
    let dir = model_project(
        "[platformio]\ncore_dir = /opt/pio\nlibdeps_dir = deps\nextra_configs = extra.ini\n[env:e]\nplatform = espressif32 @ 6.10.0\n",
        &[],
    );
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    assert_eq!(
        warning_texts(&out.warnings),
        [
            "platformio.ini:2: [platformio] core_dir is set, but rollcall does not follow it: the core directory is read only from --pio-core or $PLATFORMIO_CORE_DIR",
            "platformio.ini:3: [platformio] libdeps_dir is set, but rollcall does not follow it: libraries are read only from .pio/libdeps/<env>/",
            "platformio.ini:4: [platformio] extra_configs is set, but rollcall does not follow it: the extra configuration files are not read; options they set are missed",
        ]
    );
}

/// configparser's `%`-interpolation and `[DEFAULT]` are not modelled: each is warned about,
/// with its line.
#[test]
fn percent_interpolation_and_default_section_warn() {
    let dir = model_project(
        "[DEFAULT]\nboard = esp32dev\n[common]\nlib_deps = me/Lib @ 100%%\n[env:e]\nplatform = espressif32 @ 6.10.0\nbuild_flags = -DX=10%\nlib_deps = ${common.lib_deps}\n",
        &[],
    );
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    let text = warning_texts(&out.warnings);
    assert!(
        text.contains(&"platformio.ini:1: [DEFAULT] is configparser's defaults section: PlatformIO applies its options to every section, but rollcall does not; options set only there are missed".to_owned()),
        "{text:#?}"
    );
    assert!(
        text.iter()
            .any(|w| w.starts_with("platformio.ini:4: lib_deps contains %")),
        "{text:#?}"
    );
    // build_flags is not read, so its % is not warned about.
    assert!(!text.iter().any(|w| w.contains("build_flags")), "{text:#?}");
}

/// A local (`file://`, `symlink://`) lib_deps entry matches its installed library by the
/// `.piopm` `spec.uri`, even when the path's last segment is not the library's name; the image
/// depends on it and no path reaches the SBOM.
#[test]
fn local_lib_deps_match_by_spec_uri_without_printing_the_path() {
    let dir = model_project(
        "[env:e]\nplatform = espressif32 @ 6.10.0\nlib_deps =\n    file:///home/alice/x\n    symlink:///home/alice/y\n",
        &[
            (
                "e",
                "LocalLib",
                r#"{"type": "library", "name": "LocalLib", "version": "0.1.0", "spec": {"owner": null, "name": "LocalLib", "requirements": null, "uri": "file:///home/alice/x"}}"#,
                Some(r#"{"name": "LocalLib", "version": "0.1.0", "license": "MIT"}"#),
            ),
            (
                "e",
                "LinkLib",
                r#"{"type": "library", "name": "LinkLib", "version": "0.2.0", "spec": {"owner": null, "name": "LinkLib", "requirements": null, "uri": "symlink:///home/alice/y"}}"#,
                Some(r#"{"name": "LinkLib", "version": "0.2.0", "license": "MIT"}"#),
            ),
        ],
    );
    let out = platformio::ingest(&PlatformIoOptions::new(dir.path())).unwrap();
    let text = warning_texts(&out.warnings);
    assert!(
        !text.iter().any(|w| w.contains("is not installed")),
        "{text:#?}"
    );
    let sbom = render(&out.product);
    assert!(!sbom.contains("/home/alice"), "the SBOM contains the path");
    let doc: Value = serde_json::from_str(&sbom).unwrap();
    let image_ref = doc["components"][0]["bom-ref"].as_str().unwrap().to_owned();
    let refs: std::collections::BTreeMap<&str, &str> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c["bom-ref"].as_str().unwrap()))
        .collect();
    let deps = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == image_ref.as_str())
        .unwrap()["dependsOn"]
        .clone();
    for name in ["LocalLib", "LinkLib"] {
        assert!(
            deps.as_array().unwrap().iter().any(|d| d == refs[name]),
            "image does not depend on {name}: {deps}"
        );
        // The lib_deps evidence cites the library, never its path.
        assert!(
            component(&out.product, name)
                .evidence
                .iter()
                .any(|e| e.source() == "platformio-ini" && e.value == format!("local:{name}")),
            "{name}"
        );
    }
}
