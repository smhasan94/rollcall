//! Ecosystem auto-detection (SHA-131) against every build fixture in `fixtures/`: the table
//! below is the expected ecosystem of each fixture directory, and a walk of `fixtures/` checks
//! that no directory with a signal is missing from it. Ambiguous and empty directories are
//! made in temporary directories (hand-written, not real builds).

use std::fs;
use std::path::{Path, PathBuf};

use rollcall_core::detect::{
    self, DetectError, DetectOptions, Detection, Ecosystem, Inferred, SIGNALS,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// How a fixture directory is expected to be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    /// A Zephyr sysbuild top-level directory (with a west list).
    ZephyrSysbuild,
    /// A Zephyr image directory.
    ZephyrImage,
    /// Captured cargo metadata.
    CargoMetadata,
    EspIdf,
    PlatformIo,
    /// No ecosystem (a fixture set's root, holding only MANIFEST.json and variants).
    None,
}

/// Every fixture directory and what it is detected as.
const TABLE: &[(&str, Expected)] = &[
    ("zephyr", Expected::None),
    ("zephyr/baseline", Expected::ZephyrSysbuild),
    ("zephyr/baseline/mcuboot", Expected::ZephyrImage),
    ("zephyr/baseline/with_mcuboot", Expected::ZephyrImage),
    ("zephyr/bt", Expected::ZephyrSysbuild),
    ("zephyr/bt/beacon", Expected::ZephyrImage),
    ("zephyr/bt/mcuboot", Expected::ZephyrImage),
    ("zephyr/tls", Expected::ZephyrSysbuild),
    ("zephyr/tls/http_server", Expected::ZephyrImage),
    ("zephyr/tls/mcuboot", Expected::ZephyrImage),
    ("zephyr-old-mbedtls", Expected::None),
    ("zephyr-old-mbedtls/old-mbedtls", Expected::ZephyrSysbuild),
    (
        "zephyr-old-mbedtls/old-mbedtls/mbedtls",
        Expected::ZephyrImage,
    ),
    (
        "zephyr-old-mbedtls/old-mbedtls/mcuboot",
        Expected::ZephyrImage,
    ),
    ("zephyr-smp", Expected::None),
    ("zephyr-smp/smp-serial", Expected::ZephyrSysbuild),
    ("zephyr-smp/smp-serial/mcuboot", Expected::ZephyrImage),
    ("zephyr-smp/smp-serial/smp_svr", Expected::ZephyrImage),
    ("zephyr-smp/smp-bt", Expected::ZephyrSysbuild),
    ("zephyr-smp/smp-bt/mcuboot", Expected::ZephyrImage),
    ("zephyr-smp/smp-bt/smp_svr", Expected::ZephyrImage),
    ("cargo-keelsign", Expected::CargoMetadata),
    ("cargo-deps", Expected::CargoMetadata),
    ("cargo-old-heapless", Expected::CargoMetadata),
    ("esp-idf", Expected::None),
    ("esp-idf/hello-world", Expected::EspIdf),
    ("esp-idf/wifi-tls", Expected::EspIdf),
    ("platformio", Expected::None),
    ("platformio/arduino-mqtt", Expected::PlatformIo),
];

fn check(rel: &str, expected: Expected, got: Result<Detection, DetectError>) {
    let ecosystem = |e| match &got {
        Ok(d) => assert_eq!(d.ecosystem, e, "{rel}: {d:?}"),
        Err(err) => panic!("{rel}: expected {e}, got {err}"),
    };
    match expected {
        Expected::ZephyrSysbuild | Expected::ZephyrImage => {
            ecosystem(Ecosystem::Zephyr);
            let Ok(Detection {
                inferred:
                    Inferred::Zephyr {
                        sysbuild,
                        west_list,
                    },
                ..
            }) = &got
            else {
                panic!("{rel}: {got:?}");
            };
            let top = expected == Expected::ZephyrSysbuild;
            assert_eq!(*sysbuild, top, "{rel}");
            assert_eq!(west_list.is_some(), top, "{rel}");
        }
        Expected::CargoMetadata => {
            ecosystem(Ecosystem::Cargo);
            assert!(
                matches!(&got, Ok(Detection { inferred: Inferred::CargoMetadata(p), .. }) if p.ends_with("cargo-metadata.json")),
                "{rel}: {got:?}"
            );
        }
        Expected::EspIdf => ecosystem(Ecosystem::EspIdf),
        Expected::PlatformIo => ecosystem(Ecosystem::PlatformIo),
        Expected::None => assert!(
            matches!(got, Err(DetectError::NoMatch { .. })),
            "{rel}: {got:?}"
        ),
    }
}

#[test]
fn every_fixture_directory_detects_as_expected() {
    for (rel, expected) in TABLE {
        let dir = fixtures().join(rel);
        assert!(dir.is_dir(), "{rel} is not a fixture directory");
        check(
            rel,
            *expected,
            detect::detect(&dir, &DetectOptions::default()),
        );
    }
}

/// Every directory under `fixtures/`, relative, sorted.
fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.push(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            walk(&path, base, out);
        }
    }
}

#[test]
fn every_fixture_directory_with_a_signal_is_in_the_table() {
    let mut dirs = Vec::new();
    walk(&fixtures(), &fixtures(), &mut dirs);
    dirs.sort();
    assert!(dirs.len() > TABLE.len(), "{dirs:?}");
    for rel in dirs {
        let listed = TABLE.iter().any(|(r, _)| *r == rel);
        match detect::detect(&fixtures().join(&rel), &DetectOptions::default()) {
            Err(DetectError::NoMatch { .. }) => {}
            other => assert!(listed, "{rel} is detected ({other:?}) but not in the table"),
        }
    }
    // Every top-level fixture set is in the table.
    for entry in fs::read_dir(fixtures()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            TABLE.iter().any(|(r, _)| *r == name),
            "fixtures/{name} not in the table"
        );
    }
}

#[test]
fn empty_directory_is_an_error_listing_every_ecosystem_signal() {
    let dir = tempfile::tempdir().unwrap();
    let err = detect::detect(dir.path(), &DetectOptions::default()).unwrap_err();
    let DetectError::NoMatch {
        looked_for, hints, ..
    } = &err
    else {
        panic!("{err:?}");
    };
    assert_eq!(looked_for, &SIGNALS.to_vec());
    assert!(hints.is_empty());
    let message = err.to_string();
    for needle in [
        "no ecosystem recognised; looked for",
        "build_info.yml (zephyr)",
        "Cargo.toml or cargo-metadata.json (cargo)",
        "sdkconfig and build/project_description.json (esp-idf)",
        "platformio.ini (platformio)",
    ] {
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
    }
    // A half-matching ESP-IDF project (not built) is named in a hint.
    fs::write(dir.path().join("sdkconfig"), "").unwrap();
    let message = detect::detect(dir.path(), &DetectOptions::default())
        .unwrap_err()
        .to_string();
    assert!(message.contains("run idf.py build"), "{message}");
    // Missing, or a file: not a directory.
    for path in [dir.path().join("nowhere"), dir.path().join("sdkconfig")] {
        assert!(matches!(
            detect::detect(&path, &DetectOptions::default()),
            Err(DetectError::NotADirectory { .. })
        ));
    }
}

#[test]
fn ambiguous_directory_lists_candidates() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("platformio.ini"), "[env:a]\n").unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();
    let err = detect::detect(dir.path(), &DetectOptions::default()).unwrap_err();
    let DetectError::Ambiguous { candidates, .. } = &err else {
        panic!("{err:?}");
    };
    let names: Vec<Ecosystem> = candidates.iter().map(|c| c.ecosystem).collect();
    assert_eq!(names, [Ecosystem::Cargo, Ecosystem::PlatformIo]);
    let message = err.to_string();
    assert!(
        message.contains(
            "matches more than one ecosystem: cargo (Cargo.toml), platformio (platformio.ini); pass --ecosystem cargo|platformio"
        ),
        "{message}"
    );
    // --ecosystem resolves it.
    let d =
        detect::detect_as(dir.path(), Ecosystem::PlatformIo, &DetectOptions::default()).unwrap();
    assert_eq!(d.inferred, Inferred::PlatformIo);
    let d = detect::detect_as(dir.path(), Ecosystem::Cargo, &DetectOptions::default()).unwrap();
    assert_eq!(d.inferred, Inferred::CargoPackage);
    // And names what is missing when it does not hold.
    let err =
        detect::detect_as(dir.path(), Ecosystem::Zephyr, &DetectOptions::default()).unwrap_err();
    assert!(
        err.to_string()
            .contains("not a zephyr directory: no build_info.yml (zephyr)"),
        "{err}"
    );
    // All four at once.
    fs::write(dir.path().join("build_info.yml"), "").unwrap();
    fs::write(dir.path().join("sdkconfig"), "").unwrap();
    fs::create_dir_all(dir.path().join("build")).unwrap();
    fs::write(dir.path().join("build/project_description.json"), "{}").unwrap();
    let Err(DetectError::Ambiguous { candidates, .. }) =
        detect::detect(dir.path(), &DetectOptions::default())
    else {
        panic!("not ambiguous");
    };
    assert_eq!(candidates.len(), 4);
}

/// A PlatformIO project built with `framework = espidf` keeps `sdkconfig.<env>` and the
/// ESP-IDF build under `.pio/build/<env>/`: it is PlatformIO, not ESP-IDF.
#[test]
fn platformio_espidf_project_is_platformio_not_esp_idf() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("platformio.ini"),
        "[env:esp32dev]\nplatform = espressif32\nframework = espidf\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("sdkconfig.esp32dev"),
        "CONFIG_IDF_TARGET=\"esp32\"\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".pio/build/esp32dev")).unwrap();
    fs::write(
        dir.path()
            .join(".pio/build/esp32dev/project_description.json"),
        "{}",
    )
    .unwrap();
    let d = detect::detect(dir.path(), &DetectOptions::default()).unwrap();
    assert_eq!(d.ecosystem, Ecosystem::PlatformIo);
    assert_eq!(d.matched, ["platformio.ini"]);
}

#[test]
fn esp_idf_build_directory_option_is_honoured() {
    let src = fixtures().join("esp-idf/hello-world");
    let dir = tempfile::tempdir().unwrap();
    fs::copy(src.join("sdkconfig"), dir.path().join("sdkconfig")).unwrap();
    let out = dir.path().join("out");
    fs::create_dir_all(&out).unwrap();
    fs::copy(
        src.join("build/project_description.json"),
        out.join("project_description.json"),
    )
    .unwrap();
    assert!(detect::detect(dir.path(), &DetectOptions::default()).is_err());
    let options = DetectOptions {
        build_dir: Some(out.clone()),
    };
    let d = detect::detect(dir.path(), &options).unwrap();
    assert_eq!(d.ecosystem, Ecosystem::EspIdf);
    // `matched` names the build directory actually read.
    assert_eq!(d.matched, ["sdkconfig", "out/project_description.json"]);
    let elsewhere = tempfile::tempdir().unwrap();
    fs::copy(
        out.join("project_description.json"),
        elsewhere.path().join("project_description.json"),
    )
    .unwrap();
    let options = DetectOptions {
        build_dir: Some(elsewhere.path().to_owned()),
    };
    let d = detect::detect(dir.path(), &options).unwrap();
    assert_eq!(
        d.matched[1],
        elsewhere
            .path()
            .join("project_description.json")
            .to_string_lossy()
    );
}

/// A Zephyr application's source directory (prj.conf, or a build/ with build_info.yml below
/// it) is no match, with a hint to pass the build directory.
#[test]
fn zephyr_source_directory_gets_a_hint() {
    for setup in ["prj.conf", "build/build_info.yml"] {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(setup);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, "").unwrap();
        let message = detect::detect(dir.path(), &DetectOptions::default())
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("looks like a Zephyr application source directory")
                && message.contains("pass its build directory"),
            "{setup}: {message}"
        );
    }
}
