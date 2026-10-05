//! `rollcall generate DIR` and `rollcall detect DIR` (SHA-131): ecosystem auto-detection on
//! every build fixture in `fixtures/`, byte-identical to the explicit input flags, and the
//! errors for directories that match no or several ecosystems. Ambiguous and empty
//! directories are made in temporary directories (hand-written, not real builds).

use std::fs;
use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rollcall"));
    c.env_remove("PLATFORMIO_CORE_DIR")
        .env_remove("IDF_PATH")
        .env_remove("ROLLCALL_IDENTIFIERS");
    c
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// Each fixture directory, its ecosystem, and the explicit flags `generate DIR` must equal.
fn table() -> Vec<(&'static str, &'static str, Vec<String>)> {
    let root = fixtures();
    let p = |rel: &str| root.join(rel).display().to_string();
    let mut rows = Vec::new();
    for top in [
        "zephyr/baseline",
        "zephyr/bt",
        "zephyr/tls",
        "zephyr-old-mbedtls/old-mbedtls",
        "zephyr-smp/smp-serial",
        "zephyr-smp/smp-bt",
    ] {
        rows.push((
            top,
            "zephyr",
            vec![
                "--zephyr".into(),
                p(top),
                "--sysbuild".into(),
                "--west-list".into(),
                p(&format!("{top}/west-list.txt")),
            ],
        ));
    }
    for image in [
        "zephyr/baseline/mcuboot",
        "zephyr/baseline/with_mcuboot",
        "zephyr/bt/beacon",
        "zephyr/bt/mcuboot",
        "zephyr/tls/http_server",
        "zephyr/tls/mcuboot",
        "zephyr-old-mbedtls/old-mbedtls/mbedtls",
        "zephyr-old-mbedtls/old-mbedtls/mcuboot",
        "zephyr-smp/smp-serial/mcuboot",
        "zephyr-smp/smp-serial/smp_svr",
        "zephyr-smp/smp-bt/mcuboot",
        "zephyr-smp/smp-bt/smp_svr",
    ] {
        rows.push((image, "zephyr", vec!["--zephyr".into(), p(image)]));
    }
    for cargo in ["cargo-keelsign", "cargo-deps", "cargo-old-heapless"] {
        rows.push((
            cargo,
            "cargo",
            vec![
                "--cargo-metadata".into(),
                p(&format!("{cargo}/cargo-metadata.json")),
            ],
        ));
    }
    for esp in ["esp-idf/hello-world", "esp-idf/wifi-tls"] {
        rows.push((esp, "esp-idf", vec!["--esp-idf".into(), p(esp)]));
    }
    rows.push((
        "platformio/arduino-mqtt",
        "platformio",
        vec!["--platformio".into(), p("platformio/arduino-mqtt")],
    ));
    rows
}

fn generate(args: &[String]) -> Output {
    rollcall()
        .arg("generate")
        .args(args)
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap()
}

/// AC2: for every fixture, `generate DIR` (auto) and `generate DIR --ecosystem X` give the
/// same bytes and warnings as the explicit flags.
#[test]
fn generate_dir_auto_matches_explicit_flags_for_every_fixture() {
    for (rel, ecosystem, explicit) in table() {
        let dir = fixtures().join(rel).display().to_string();
        let expected = generate(&explicit);
        assert_eq!(
            expected.status.code(),
            Some(0),
            "{rel}: {}",
            stderr_of(&expected)
        );
        for args in [
            vec![dir.clone()],
            vec![dir.clone(), "--ecosystem".into(), ecosystem.into()],
        ] {
            let got = generate(&args);
            assert_eq!(
                got.status.code(),
                Some(0),
                "{rel} {args:?}: {}",
                stderr_of(&got)
            );
            assert!(
                got.stdout == expected.stdout,
                "{rel} {args:?}: differs from {explicit:?}"
            );
            assert_eq!(stderr_of(&got), stderr_of(&expected), "{rel} {args:?}");
        }
    }
}

/// TP2: `rollcall detect` prints each fixture's ecosystem; a fixture set's root is no
/// ecosystem (exit 66).
#[test]
fn detect_subcommand_prints_ecosystem_for_every_fixture() {
    for (rel, ecosystem, _) in table() {
        let out = rollcall()
            .arg("detect")
            .arg(fixtures().join(rel))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{rel}: {}", stderr_of(&out));
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!("{ecosystem}\n"),
            "{rel}"
        );
    }
    for root in [
        "zephyr",
        "zephyr-smp",
        "zephyr-old-mbedtls",
        "esp-idf",
        "platformio",
    ] {
        let out = rollcall()
            .arg("detect")
            .arg(fixtures().join(root))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(66), "{root}");
        assert!(out.stdout.is_empty());
    }
}

/// TP2: an empty directory is an error listing what each ecosystem is recognised by.
#[test]
fn generate_empty_dir_exits_66() {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["generate", "detect"] {
        let out = rollcall().arg(sub).arg(dir.path()).output().unwrap();
        assert_eq!(out.status.code(), Some(66), "{sub}: {}", stderr_of(&out));
        assert!(out.stdout.is_empty());
        let stderr = stderr_of(&out);
        for needle in [
            "no ecosystem recognised; looked for build_info.yml (zephyr)",
            "Cargo.toml or cargo-metadata.json (cargo)",
            "sdkconfig and build/project_description.json (esp-idf)",
            "platformio.ini (platformio)",
        ] {
            assert!(
                stderr.contains(needle),
                "{sub}: {stderr:?} lacks {needle:?}"
            );
        }
    }
    let out = rollcall()
        .args(["generate", "/nonexistent/rollcall"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    assert!(stderr_of(&out).contains("not a directory"));
}

/// AC2: an ambiguous directory exits 64 listing the candidates; --ecosystem resolves it.
#[test]
fn generate_ambiguous_dir_exits_64_listing_candidates() {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("platformio/arduino-mqtt/platformio.ini"),
        dir.path().join("platformio.ini"),
    )
    .unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    for sub in ["generate", "detect"] {
        let out = rollcall().arg(sub).arg(dir.path()).output().unwrap();
        assert_eq!(out.status.code(), Some(64), "{sub}: {}", stderr_of(&out));
        assert!(out.stdout.is_empty());
        assert!(
            stderr_of(&out).contains(
                "matches more than one ecosystem: cargo (Cargo.toml), platformio (platformio.ini); pass --ecosystem cargo|platformio"
            ),
            "{sub}: {}",
            stderr_of(&out)
        );
    }
    let out = rollcall()
        .arg("generate")
        .arg(dir.path())
        .args(["--ecosystem", "platformio", "--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    // No library installed in this copy: a warning, and the project's framework and platform.
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("no library is installed for environment esp32dev"));
}

/// `--ecosystem` naming what DIR is not: 66, naming the missing file; another ecosystem's
/// flags with DIR: 64; `--ecosystem` without DIR: 64.
#[test]
fn generate_ecosystem_override_and_flags_that_do_not_fit_exit_64_or_66() {
    let pio = fixtures().join("platformio/arduino-mqtt");
    let out = rollcall()
        .arg("generate")
        .arg(&pio)
        .args(["--ecosystem", "zephyr"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("not a zephyr directory: no build_info.yml"));
    for (dir, flags, needle) in [
        (
            pio.clone(),
            vec!["--west-list", "x"],
            "--west-list applies to zephyr input, but DIR is platformio",
        ),
        (
            pio.clone(),
            vec!["--idf-path", "x"],
            "--idf-path applies to esp-idf input, but DIR is platformio",
        ),
        (
            pio.clone(),
            vec!["--verbose"],
            "--verbose applies to zephyr or esp-idf input, but DIR is platformio",
        ),
        (
            fixtures().join("zephyr/tls"),
            vec!["--env", "x"],
            "--env applies to platformio input, but DIR is zephyr",
        ),
        (
            fixtures().join("esp-idf/wifi-tls"),
            vec!["--elf", "x"],
            "--elf applies to cargo input, but DIR is esp-idf",
        ),
        (
            fixtures().join("cargo-keelsign"),
            vec!["--target", "thumbv7em-none-eabihf"],
            "--target applies to a package directory",
        ),
    ] {
        let out = rollcall()
            .arg("generate")
            .arg(&dir)
            .args(&flags)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(64),
            "{flags:?}: {}",
            stderr_of(&out)
        );
        assert!(
            stderr_of(&out).contains(needle),
            "{flags:?}: {}",
            stderr_of(&out)
        );
    }
    let out = rollcall()
        .args(["generate", "--platformio"])
        .arg(&pio)
        .args(["--ecosystem", "platformio"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", stderr_of(&out));
}

/// `--product` works for every ingester: for Cargo and ESP-IDF input too, it gives exactly
/// `generate` followed by `merge --product`.
#[test]
fn generate_product_equals_generate_plus_merge_for_cargo_and_esp_idf() {
    let dir = tempfile::tempdir().unwrap();
    let inputs = [
        (
            "cargo",
            vec![
                "--cargo-metadata".to_owned(),
                fixtures()
                    .join("cargo-keelsign/cargo-metadata.json")
                    .display()
                    .to_string(),
            ],
        ),
        (
            "esp-idf",
            vec![
                "--esp-idf".to_owned(),
                fixtures().join("esp-idf/wifi-tls").display().to_string(),
            ],
        ),
    ];
    for (label, input) in inputs {
        let plain = dir.path().join(format!("{label}.cdx.json"));
        let mut args = input.clone();
        args.extend(["-o".to_owned(), plain.display().to_string()]);
        let out = generate(&args);
        assert_eq!(out.status.code(), Some(0), "{label}: {}", stderr_of(&out));
        let merged = rollcall()
            .arg("merge")
            .arg(&plain)
            .args(["--product", "widget@2.0.0", "--timestamp", GOLDEN_TIMESTAMP])
            .output()
            .unwrap();
        assert_eq!(
            merged.status.code(),
            Some(0),
            "{label}: {}",
            stderr_of(&merged)
        );
        let mut args = input.clone();
        args.extend(["--product".to_owned(), "widget@2.0.0".to_owned()]);
        let direct = generate(&args);
        assert_eq!(
            direct.status.code(),
            Some(0),
            "{label}: {}",
            stderr_of(&direct)
        );
        assert!(
            direct.stdout == merged.stdout,
            "{label}: differs from merge --product"
        );
        let doc: serde_json::Value = serde_json::from_slice(&direct.stdout).unwrap();
        assert_eq!(doc["metadata"]["component"]["name"], "widget", "{label}");
        assert_eq!(doc["metadata"]["component"]["version"], "2.0.0", "{label}");
    }
}

/// `rollcall detect --build` reads the ESP-IDF build from another directory, as
/// `generate --build` does.
#[test]
fn detect_build_option_names_the_esp_idf_build_directory() {
    let src = fixtures().join("esp-idf/hello-world");
    let dir = tempfile::tempdir().unwrap();
    fs::copy(src.join("sdkconfig"), dir.path().join("sdkconfig")).unwrap();
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();
    fs::copy(
        src.join("build/project_description.json"),
        out_dir.join("project_description.json"),
    )
    .unwrap();
    let out = rollcall().arg("detect").arg(dir.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(66), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("run idf.py build"));
    let out = rollcall()
        .arg("detect")
        .arg(dir.path())
        .arg("--build")
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "esp-idf\n");
}
