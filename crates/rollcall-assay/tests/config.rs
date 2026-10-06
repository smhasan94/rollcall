//! The configuration detectors against the real Zephyr and ESP-IDF fixture builds (SHA-144).
//!
//! The expected lists in `tests/data/config/*.expected` are hand-written test data (see the
//! README there), not generated: each line was checked against the fixture's own `.config` or
//! `sdkconfig`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rollcall_assay::catalogue::Catalogue;
use rollcall_assay::config::{self, ConfigError, ConfigInventory, RuleSet};
use rollcall_core::merge::ProductSpec;
use rollcall_core::model::{
    AlgorithmProperties, ConfidenceLevel, CryptoAssetProperties, ExecutionEnvironment, Locator,
    NodeRef,
};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(path: &str) -> PathBuf {
    repo().join("fixtures").join(path)
}

/// Every fixture with a configuration, its expected-list file and its product name.
const FIXTURES: &[(&str, &str, &str)] = &[
    ("zephyr/baseline", "zephyr-baseline", "baseline"),
    ("zephyr/tls", "zephyr-tls", "tls"),
    ("zephyr/bt", "zephyr-bt", "bt"),
    ("zephyr-smp/smp-bt", "zephyr-smp-smp-bt", "smp-bt"),
    (
        "zephyr-smp/smp-serial",
        "zephyr-smp-smp-serial",
        "smp-serial",
    ),
    (
        "zephyr-old-mbedtls/old-mbedtls",
        "zephyr-old-mbedtls",
        "old-mbedtls",
    ),
    ("esp-idf/wifi-tls", "esp-idf-wifi-tls", "wifi-tls"),
    ("esp-idf/hello-world", "esp-idf-hello-world", "hello-world"),
];

fn detect(path: &Path, product: &str) -> Result<ConfigInventory, ConfigError> {
    let catalogue = Catalogue::builtin().unwrap();
    let spec: ProductSpec = product.parse().unwrap();
    config::detect_build(path, &spec, &catalogue)
}

/// The inventory as the expected lists write it: `asset IMAGE / LIBRARY / NAME [hardware] |
/// LOCATOR, …`, then `compiled-out IMAGE LIBRARY ALGORITHM[-SET]`, then `note TEXT`, each
/// group in order.
fn render(inventory: &ConfigInventory) -> Vec<String> {
    let mut out = Vec::new();
    let mut product = rollcall_core::model::Product::new("p").unwrap();
    for image in &inventory.images {
        product.add_image(image.clone()).unwrap();
    }
    for (path, _, node) in product.walk() {
        let NodeRef::Component(component) = node else {
            continue;
        };
        let Some(crypto) = &component.crypto else {
            continue;
        };
        let segments: Vec<String> = path
            .segments()
            .iter()
            .skip(1)
            .map(ToString::to_string)
            .collect();
        let hardware = match &crypto.properties {
            CryptoAssetProperties::Algorithm(AlgorithmProperties {
                execution_environment: Some(ExecutionEnvironment::Hardware),
                ..
            }) => " [hardware]",
            _ => "",
        };
        let place = segments
            .iter()
            .take(segments.len().saturating_sub(1))
            .map(|s| s.replace("library:", ""))
            .collect::<Vec<_>>()
            .join(" / ");
        // In evidence order (file, then line), each locator once.
        let mut locators: Vec<String> = Vec::new();
        for e in &crypto.evidence {
            let text = e.locator.to_string();
            if !locators.contains(&text) {
                locators.push(text);
            }
        }
        out.push(format!(
            "asset {place} / {}{hardware} | {}",
            component.name,
            locators.join(", ")
        ));
    }
    for image in inventory.compiled_out.images() {
        for entry in inventory.compiled_out.entries(image) {
            let name = rollcall_assay::assets::asset_name(
                &entry.algorithm,
                entry.parameter_set.as_deref(),
            );
            out.push(format!("compiled-out {image} {} {name}", entry.library));
        }
    }
    for note in &inventory.notes {
        out.push(format!("note {note}"));
    }
    out
}

/// The expected list's lines, without comments and blank lines.
fn expected(name: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/config")
        .join(format!("{name}.expected"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    assert!(
        text.starts_with("# hand-written test data, SHA-144, not generated"),
        "{}: missing the hand-written header",
        path.display()
    );
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Checks `inventory` against the expected list `name`, printing the difference.
fn check_expected(fixture_path: &str, name: &str, product: &str) {
    let inventory = detect(&fixture(fixture_path), product).unwrap();
    let actual = render(&inventory);
    let wanted = expected(name);
    if actual != wanted {
        let missing: Vec<&String> = wanted.iter().filter(|l| !actual.contains(l)).collect();
        let extra: Vec<&String> = actual.iter().filter(|l| !wanted.contains(l)).collect();
        panic!(
            "{fixture_path}: inventory differs from {name}.expected\nmissing:\n{}\nunexpected:\n{}\nactual:\n{}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            extra
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            actual.join("\n")
        );
    }
}

/// Every evidence entry of every asset is a `kconfig-symbol` locator, confidence high, from
/// the detector the layout names.
fn check_evidence(inventory: &ConfigInventory, detector: &str) {
    for image in &inventory.images {
        let mut product = rollcall_core::model::Product::new("p").unwrap();
        product.add_image(image.clone()).unwrap();
        for (_, _, component) in product.crypto_assets() {
            let crypto = component.crypto.as_ref().unwrap();
            assert!(!crypto.evidence.is_empty(), "{}", component.name);
            for e in &crypto.evidence {
                assert!(
                    matches!(e.locator, Locator::KconfigSymbol { line: Some(_), .. }),
                    "{}: {}",
                    component.name,
                    e.locator
                );
                assert_eq!(e.confidence, ConfidenceLevel::High, "{}", component.name);
                assert_eq!(e.detector(), detector, "{}", component.name);
            }
        }
    }
}

/// AC1: every Zephyr and ESP-IDF fixture gives exactly the assets, compiled-out entries and
/// notes of its hand-written expected list; every evidence entry is a `kconfig-symbol` at
/// confidence high from `kconfig` or `sdkconfig`; and two runs are identical.
#[test]
fn config_assets_match_expected_list_for_every_zephyr_and_esp_idf_fixture() {
    for (path, name, product) in FIXTURES {
        check_expected(path, name, product);
        let inventory = detect(&fixture(path), product).unwrap();
        let detector = if path.starts_with("esp-idf") {
            "sdkconfig"
        } else {
            "kconfig"
        };
        check_evidence(&inventory, detector);
        assert_eq!(inventory.detectors, BTreeSet::from([detector]), "{path}");
        let again = detect(&fixture(path), product).unwrap();
        assert_eq!(again, inventory, "{path}: not deterministic");
        assert_eq!(render(&again), render(&inventory));
    }
}

/// TP1: the Zephyr baseline fixture (sysbuild with MCUboot) against its expected list.
#[test]
fn expected_zephyr_baseline() {
    check_expected("zephyr/baseline", "zephyr-baseline", "baseline");
}

/// TP1: the Zephyr TLS fixture against its expected list.
#[test]
fn expected_zephyr_tls() {
    check_expected("zephyr/tls", "zephyr-tls", "tls");
}

/// TP1: the ESP-IDF Wi-Fi/TLS fixture against its expected list.
#[test]
fn expected_esp_idf_wifi_tls() {
    check_expected("esp-idf/wifi-tls", "esp-idf-wifi-tls", "wifi-tls");
}

/// Every directory under `dir` holding a `build_info.yml` that lists a `BOOTLOADER` image.
fn bootloader_builds(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            bootloader_builds(&path, out);
        } else if path.file_name().is_some_and(|n| n == "build_info.yml") {
            let text = std::fs::read_to_string(&path).unwrap();
            let info = rollcall_core::zephyr::build_info::parse(&text).unwrap();
            let has_bootloader = info
                .cmake
                .as_ref()
                .and_then(|c| c.images.as_ref())
                .is_some_and(|images| {
                    images
                        .iter()
                        .any(|i| i.kind.as_deref() == Some("BOOTLOADER"))
                });
            if has_bootloader {
                out.insert(path.parent().unwrap().to_owned());
            }
        }
    }
}

/// AC2: every fixture with a bootloader reports MCUboot's signature algorithm, RSA-PSS-2048,
/// backed by the MCUboot image's `.config` and the sysbuild `SB_CONFIG_*` setting; the ESP-IDF
/// fixtures, which have secure boot off, say so.
#[test]
fn mcuboot_signature_reported_for_every_fixture_with_a_bootloader() {
    let mut found = BTreeSet::new();
    bootloader_builds(&repo().join("fixtures"), &mut found);
    let expected: BTreeSet<PathBuf> = [
        "zephyr/baseline",
        "zephyr/bt",
        "zephyr/tls",
        "zephyr-old-mbedtls/old-mbedtls",
        "zephyr-smp/smp-bt",
        "zephyr-smp/smp-serial",
    ]
    .iter()
    .map(|p| fixture(p))
    .collect();
    assert_eq!(found, expected);
    for dir in &found {
        let inventory = detect(dir, "product").unwrap();
        let lines = render(&inventory);
        let signature = lines
            .iter()
            .find(|l| l.starts_with("asset bootloader:mcuboot / mcuboot / RSA-PSS-2048 | "))
            .unwrap_or_else(|| {
                panic!(
                    "{}: no MCUboot signature\n{}",
                    dir.display(),
                    lines.join("\n")
                )
            });
        assert!(
            signature.contains("mcuboot/zephyr/.config:16 CONFIG_BOOT_SIGNATURE_TYPE_RSA"),
            "{signature}"
        );
        assert!(
            signature.contains("mcuboot/zephyr/.config:17 CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN"),
            "{signature}"
        );
        assert!(
            signature.contains("zephyr/.config:")
                && signature.contains(" SB_CONFIG_BOOT_SIGNATURE_TYPE_RSA"),
            "{signature}"
        );
        assert!(
            signature.contains(" SB_CONFIG_SIGNATURE_TYPE"),
            "{signature}"
        );
    }
    for path in ["esp-idf/wifi-tls", "esp-idf/hello-world"] {
        let inventory = detect(&fixture(path), "product").unwrap();
        assert!(
            inventory.notes.contains(
                &"sdkconfig:358: secure boot not enabled (CONFIG_SECURE_BOOT is not set)"
                    .to_owned()
            ),
            "{path}: {:?}",
            inventory.notes
        );
        assert!(
            !inventory.images.iter().any(|i| i.name == "bootloader"),
            "{path}"
        );
    }
}

/// The compiled-out list records every evaluated image: the baseline application image
/// compiles nothing out, so nothing is compiled out *everywhere*, although MCUboot compiles out
/// a long list (of `psa-crypto`).
#[test]
fn everywhere_is_empty_when_an_image_compiles_nothing_out() {
    let inventory = detect(&fixture("zephyr/baseline"), "baseline").unwrap();
    let images: Vec<String> = inventory
        .compiled_out
        .images()
        .map(ToString::to_string)
        .collect();
    assert_eq!(images, ["bootloader:mcuboot", "application:baseline"]);
    let mcuboot =
        config::ImageKey::new(rollcall_core::model::ImageKind::Bootloader, "mcuboot", None);
    let entries: Vec<_> = inventory.compiled_out.entries(&mcuboot).collect();
    assert_eq!(entries.len(), 24);
    assert!(entries.iter().all(|e| e.library == "psa-crypto"));
    assert!(inventory.compiled_out.everywhere().is_empty());
    // Where every image compiles the same thing out of the same library, it is listed.
    let inventory = detect(&fixture("zephyr-old-mbedtls/old-mbedtls"), "old-mbedtls").unwrap();
    let every: Vec<String> = inventory
        .compiled_out
        .everywhere()
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e.library,
                rollcall_assay::assets::asset_name(&e.algorithm, e.parameter_set.as_deref())
            )
        })
        .collect();
    assert!(every.contains(&"mbedtls AES-CBC".to_owned()), "{every:?}");
    assert!(!every.iter().any(|e| e.contains("RSA")), "{every:?}");
}

/// `assay()` carries the configuration detectors' compiled-out list and crypto APIs on the
/// [`Inventory`](rollcall_assay::Inventory), for the source engine to use; without `--build`
/// both are empty.
#[test]
fn assay_inventory_carries_compiled_out_and_apis() {
    let path = fixture("zephyr/tls");
    let spec: ProductSpec = "tls".parse().unwrap();
    let inventory = rollcall_assay::assay(&rollcall_assay::Inputs {
        source: None,
        build: Some(&path),
        elf: None,
        product: spec,
    })
    .unwrap();
    let direct = detect(&path, "tls").unwrap();
    assert_eq!(inventory.compiled_out, direct.compiled_out);
    assert_eq!(inventory.apis, direct.apis);
    assert!(!inventory.compiled_out.is_empty());
    let app = config::ImageKey::new(rollcall_core::model::ImageKind::Application, "tls", None);
    assert_eq!(inventory.apis.get(&app), Some(&config::CryptoApi::Psa));
    assert_eq!(inventory.apis.len(), 2);
    assert!(
        inventory
            .compiled_out
            .covers(&app, "psa-crypto", "AES-CBC", Some("128"))
            .is_some()
    );
}

/// A sysbuild image that is not `MAIN` but carries the `--product` name would merge into the
/// `MAIN` image's `application:<product>`; that is an error naming `build_info.yml`, not a
/// silent merge.
#[test]
fn non_main_sysbuild_image_with_the_product_name_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("domains.yaml"),
        b"default: app
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("build_info.yml"),
        b"cmake:
  application:
    source-dir: '/x'
  sysbuild: 'true'
  images:
   - name: 'app'
     type: 'MAIN'
   - name: 'widget'
",
    )
    .unwrap();
    for image in ["app", "widget"] {
        std::fs::create_dir_all(dir.path().join(image).join("zephyr")).unwrap();
        std::fs::write(
            dir.path().join(image).join("zephyr/.config"),
            b"CONFIG_PSA_WANT_ALG_SHA_256=y
",
        )
        .unwrap();
    }
    let err = detect(dir.path(), "widget").unwrap_err();
    assert!(matches!(err, ConfigError::BuildInfo { .. }), "{err}");
    assert!(!err.is_input_error());
    let message = err.to_string();
    assert!(message.contains("build_info.yml"), "{message}");
    assert!(
        message.contains("\"widget\" is not the MAIN image but has the --product name"),
        "{message}"
    );
    // Another product name: two application images.
    let inventory = detect(dir.path(), "gadget").unwrap();
    let names: Vec<String> = inventory
        .images
        .iter()
        .map(|i| format!("{}:{}", i.kind, i.name))
        .collect();
    assert_eq!(names, ["application:gadget", "application:widget"]);
}

/// AC3: the baseline application image (`with_mcuboot`, no crypto enabled) has no assets and
/// nothing compiled out: its many set symbols are all irrelevant to crypto.
#[test]
fn baseline_app_image_has_no_assets() {
    let inventory = detect(&fixture("zephyr/baseline"), "baseline").unwrap();
    assert!(
        inventory
            .images
            .iter()
            .all(|i| i.kind != rollcall_core::model::ImageKind::Application),
        "{:?}",
        inventory.images.iter().map(|i| &i.name).collect::<Vec<_>>()
    );
    let app = config::ImageKey::new(
        rollcall_core::model::ImageKind::Application,
        "baseline",
        None,
    );
    assert_eq!(inventory.compiled_out.entries(&app).count(), 0);
    assert!(!inventory.apis.contains_key(&app));
    // Its .config does set hundreds of symbols.
    let text =
        std::fs::read_to_string(fixture("zephyr/baseline/with_mcuboot/zephyr/.config")).unwrap();
    let set = text.lines().filter(|l| l.ends_with("=y")).count();
    assert!(set > 100, "{set}");
}

/// AC3: every symbol that appears in evidence anywhere is one a rule maps; nothing else in the
/// fixtures' (thousands of) set symbols reaches an asset.
#[test]
fn every_evidence_symbol_is_a_mapped_symbol() {
    let zephyr = RuleSet::builtin_zephyr().unwrap();
    let esp = RuleSet::builtin_esp_idf().unwrap();
    for (path, _, product) in FIXTURES {
        let rules = if path.starts_with("esp-idf") {
            &esp
        } else {
            &zephyr
        };
        let mapped = rules.symbols();
        let inventory = detect(&fixture(path), product).unwrap();
        let mut product_model = rollcall_core::model::Product::new("p").unwrap();
        for image in &inventory.images {
            product_model.add_image(image.clone()).unwrap();
        }
        for (_, _, component) in product_model.crypto_assets() {
            for e in &component.crypto.as_ref().unwrap().evidence {
                let symbol = e.locator.symbol().unwrap();
                assert!(mapped.contains(symbol.as_str()), "{path}: {symbol}");
            }
        }
    }
}

/// Malformed inputs are errors (or notes), never panics: truncated, empty, non-UTF-8 and
/// UTF-16 `.config`/`sdkconfig`, a `.config` that is a directory, a bad `build_info.yml`, a
/// missing image `.config`, a bad `project_description.json`, and wrong value types.
#[test]
fn malformed_build_inputs_error_never_panic() {
    let tls = std::fs::read(fixture("zephyr/tls/http_server/zephyr/.config")).unwrap();
    let sdk = std::fs::read(fixture("esp-idf/wifi-tls/sdkconfig")).unwrap();
    let single_info = b"cmake:\n  application:\n    source-dir: '/x/app'\n".to_vec();
    // A single-image Zephyr build whose .config is `bytes`.
    let zephyr_with = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build_info.yml"), &single_info).unwrap();
        std::fs::create_dir_all(dir.path().join("zephyr")).unwrap();
        std::fs::write(dir.path().join("zephyr/.config"), bytes).unwrap();
        dir
    };
    // An ESP-IDF project whose sdkconfig is `bytes`.
    let esp_with = |bytes: &[u8]| {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("build")).unwrap();
        std::fs::write(
            dir.path().join("build/project_description.json"),
            std::fs::read(fixture("esp-idf/wifi-tls/build/project_description.json")).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join("sdkconfig"), bytes).unwrap();
        dir
    };
    let mut utf16 = vec![0xff, 0xfe];
    for unit in "CONFIG_A=y\n".encode_utf16() {
        utf16.extend(unit.to_le_bytes());
    }
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "truncated mid-string",
            b"CONFIG_A=\"unterminated\n".to_vec(),
            ":1: unterminated string value",
        ),
        (
            "garbage line",
            b"CONFIG_A=y\nthis is not kconfig\n".to_vec(),
            ":2: unknown syntax",
        ),
        (
            "non-UTF-8",
            vec![b'C', 0xff, 0xfe, b'\n'],
            "not valid UTF-8",
        ),
        ("UTF-16 with BOM", utf16, "not valid UTF-8"),
        (
            "UTF-8 BOM",
            b"\xef\xbb\xbfCONFIG_A=y\n".to_vec(),
            ":1: unknown syntax",
        ),
        // Cut in the middle of line 1555, which is left as a bare `CONFIG_`.
        (
            "truncated fixture",
            tls[..tls.len() / 2 + 7].to_vec(),
            ":1555: unknown syntax",
        ),
    ];
    for (name, bytes, needle) in &cases {
        for (layout, dir) in [("zephyr", zephyr_with(bytes)), ("esp-idf", esp_with(bytes))] {
            match detect(dir.path(), "p") {
                Ok(_) => assert!(needle.is_empty(), "{layout} {name}: expected an error"),
                Err(e) => {
                    let message = e.to_string();
                    assert!(message.contains(needle), "{layout} {name}: {message}");
                    assert!(!e.is_input_error(), "{layout} {name}: {message}");
                }
            }
        }
    }
    // Empty files are valid, empty configurations.
    let dir = zephyr_with(b"");
    let inventory = detect(dir.path(), "p").unwrap();
    assert!(inventory.images.is_empty());
    let dir = esp_with(b"");
    assert!(detect(dir.path(), "p").unwrap().images.is_empty());
    // A truncated sdkconfig still parses up to where it stops, or errors; never a panic.
    for cut in [1, sdk.len() / 3, sdk.len() / 2, sdk.len() - 1] {
        let dir = esp_with(&sdk[..cut]);
        let _ = detect(dir.path(), "p");
    }
    // Wrong value types: notes, not errors.
    let dir = zephyr_with(
        b"CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\nCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=\"2048\"\nCONFIG_PSA_WANT_ALG_GCM=7\n",
    );
    let inventory = detect(dir.path(), "p").unwrap();
    assert_eq!(inventory.notes.len(), 2, "{:?}", inventory.notes);
    // .config is a directory: unreadable input (exit 66).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("build_info.yml"), &single_info).unwrap();
    std::fs::create_dir_all(dir.path().join("zephyr/.config")).unwrap();
    let err = detect(dir.path(), "p").unwrap_err();
    assert!(err.is_input_error(), "{err}");
    assert!(matches!(err, ConfigError::Read { .. }), "{err}");
    // A recognised Zephyr build without a .config: missing input (exit 66), naming it.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("build_info.yml"), &single_info).unwrap();
    let err = detect(dir.path(), "p").unwrap_err();
    assert!(matches!(err, ConfigError::Missing { .. }), "{err}");
    assert!(err.to_string().contains(".config"), "{err}");
    // A bad build_info.yml: a data error naming the file.
    for text in [
        &b""[..],
        b"cmake: [",
        b"cmake:\n  application: 5\n",
        b"\xff\xfe",
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build_info.yml"), text).unwrap();
        let err = detect(dir.path(), "p").unwrap_err();
        assert!(!err.is_input_error(), "{err}");
        assert!(err.to_string().contains("build_info.yml"), "{err}");
    }
    // A sysbuild whose image list is unusable, or whose image .config is missing.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("domains.yaml"), b"default: app\n").unwrap();
    std::fs::write(
        dir.path().join("build_info.yml"),
        b"cmake:\n  application:\n    source-dir: '/x'\n  sysbuild: 'true'\n  images:\n   - name: '../escape'\n     type: 'MAIN'\n",
    )
    .unwrap();
    let err = detect(dir.path(), "p").unwrap_err();
    assert!(matches!(err, ConfigError::BuildInfo { .. }), "{err}");
    std::fs::write(
        dir.path().join("build_info.yml"),
        b"cmake:\n  application:\n    source-dir: '/x'\n  sysbuild: 'true'\n  images:\n   - name: 'app'\n     type: 'MAIN'\n",
    )
    .unwrap();
    let err = detect(dir.path(), "p").unwrap_err();
    assert!(matches!(err, ConfigError::Missing { .. }), "{err}");
    // An ESP-IDF build directory with a bad project_description.json.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("build")).unwrap();
    std::fs::write(
        dir.path().join("build/project_description.json"),
        b"{\"project_name\": 5",
    )
    .unwrap();
    std::fs::write(dir.path().join("sdkconfig"), b"CONFIG_A=y\n").unwrap();
    let err = detect(&dir.path().join("build"), "p").unwrap_err();
    assert!(
        matches!(err, ConfigError::ProjectDescription { .. }),
        "{err}"
    );
    // Unrecognised directories: a note, no detector.
    let dir = tempfile::tempdir().unwrap();
    let inventory = detect(dir.path(), "p").unwrap();
    assert!(inventory.detectors.is_empty());
    assert_eq!(inventory.notes.len(), 1);
}

/// The ESP-IDF build directory resolves `../sdkconfig` and cites it so.
#[test]
fn esp_idf_build_directory_reads_parent_sdkconfig() {
    let from_project = detect(&fixture("esp-idf/wifi-tls"), "wifi-tls").unwrap();
    let from_build = detect(&fixture("esp-idf/wifi-tls/build"), "wifi-tls").unwrap();
    let project = render(&from_project);
    let build = render(&from_build);
    assert_eq!(project.len(), build.len());
    for (a, b) in project.iter().zip(&build) {
        assert_eq!(a.replace("sdkconfig", "../sdkconfig"), *b);
    }
}
