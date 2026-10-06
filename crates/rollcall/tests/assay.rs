//! End-to-end tests for `rollcall assay` (SHA-138). The expected outputs are the rollcall-core
//! CBOM goldens (`crates/rollcall-core/tests/golden/cbom/`), written only by
//! `scripts/regen-golden.sh`; the input is the hand-written CBOM model fixture
//! `crates/rollcall-core/tests/data/cbom/sensor-node.cbom.model.json`.

use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

const TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests")
}

fn model() -> PathBuf {
    core_dir().join("data/cbom/sensor-node.cbom.model.json")
}

fn golden(name: &str) -> String {
    let path = core_dir().join("golden/cbom").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    })
}

/// `rollcall assay --model <fixture> --format <format> --timestamp <ts>`: (exit code, stdout,
/// stderr).
fn assay_model(format: &str, timestamp: &str) -> (Option<i32>, String, String) {
    let out = rollcall()
        .args([
            "assay",
            "--format",
            format,
            "--timestamp",
            timestamp,
            "--model",
        ])
        .arg(model())
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// TP2: the CBOM `rollcall assay --model` writes is the core golden, byte for byte.
#[test]
fn assay_model_cyclonedx_matches_golden_bytes() {
    let (code, stdout, stderr) = assay_model("cyclonedx", TIMESTAMP);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout, golden("sensor-node.cbom.json"));
    // cyclonedx is the default format.
    let out = rollcall()
        .args(["assay", "--timestamp", TIMESTAMP, "--model"])
        .arg(model())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap(), stdout);
}

/// AC2 / TP2: the Markdown summary is the core golden, byte for byte.
#[test]
fn assay_format_md_matches_golden_bytes() {
    let (code, stdout, stderr) = assay_model("md", TIMESTAMP);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout, golden("sensor-node.cbom.md"));
}

/// TP2: the timestamp override is the only thing that varies between runs: another
/// `--timestamp` changes exactly the timestamp line, in both formats.
#[test]
fn assay_changing_timestamp_changes_only_the_timestamp_line() {
    for (format, line_start) in [("cyclonedx", "\"timestamp\": "), ("md", "Generated ")] {
        let (_, a, _) = assay_model(format, TIMESTAMP);
        let (_, again, _) = assay_model(format, TIMESTAMP);
        assert_eq!(a, again, "{format}: not deterministic");
        let (_, b, _) = assay_model(format, "2030-05-06T07:08:09Z");
        assert_eq!(a.lines().count(), b.lines().count());
        let differing: Vec<(&str, &str)> =
            a.lines().zip(b.lines()).filter(|(x, y)| x != y).collect();
        assert_eq!(differing.len(), 1, "{format}: {differing:?}");
        assert!(
            differing[0].0.trim_start().starts_with(line_start),
            "{format}: {differing:?}"
        );
        assert!(differing[0].1.contains("2030-05-06T07:08:09Z"));
    }
}

/// `-o FILE` writes exactly what stdout would get.
#[test]
fn assay_output_file_equals_stdout() {
    let dir = tempfile::tempdir().unwrap();
    for format in ["cyclonedx", "md"] {
        let path = dir.path().join(format!("out.{format}"));
        let out = rollcall()
            .args([
                "assay",
                "--format",
                format,
                "--timestamp",
                TIMESTAMP,
                "--model",
            ])
            .arg(model())
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stdout.is_empty());
        let (_, stdout, _) = assay_model(format, TIMESTAMP);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), stdout, "{format}");
    }
}

/// AC1: the CBOM the CLI writes passes `rollcall validate --schema`.
#[test]
fn assay_model_output_validates_against_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sensor-node.cbom.json");
    rollcall()
        .args(["assay", "--model"])
        .arg(model())
        .arg("-o")
        .arg(&path)
        .assert()
        .code(0);
    let out = rollcall()
        .args(["validate", "--schema"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--source`, `--build` and `--elf` need `--product`; `--model` takes none of them.
#[test]
fn assay_build_without_product_is_usage_error_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let out = rollcall()
        .args(["assay", "--build"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--product <NAME[@VERSION]>"));
    for extra in [
        vec!["--product".into(), "x".into()],
        vec!["--build".into(), dir.path().as_os_str().to_owned()],
    ] {
        let out = rollcall()
            .args(["assay", "--model"])
            .arg(model())
            .args(&extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{extra:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
            "{extra:?}"
        );
    }
    // A malformed --product or --timestamp is a usage error too.
    for args in [
        vec!["--product", "@1.0"],
        vec!["--product", "x", "--timestamp", "yesterday"],
    ] {
        let out = rollcall()
            .args(["assay", "--build"])
            .arg(dir.path())
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{args:?}");
    }
}

/// A missing or wrong-kind input path is exit 66, naming the flag and the path.
#[test]
fn assay_missing_elf_exits_66() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("zephyr.elf");
    let cases: [(&str, PathBuf); 4] = [
        ("--elf", missing.clone()),
        ("--elf", dir.path().to_owned()),
        ("--build", missing.clone()),
        ("--model", missing.clone()),
    ];
    for (flag, path) in cases {
        let mut cmd = rollcall();
        cmd.args(["assay", flag]).arg(&path);
        if flag != "--model" {
            cmd.args(["--product", "sensor-node"]);
        }
        let out = cmd.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(66),
            "{flag} {}: {stderr}",
            path.display()
        );
        assert!(stderr.starts_with("rollcall assay: "), "{stderr}");
        assert!(stderr.contains(&path.display().to_string()), "{stderr}");
        assert!(out.stdout.is_empty());
    }
}

/// A `--model` that is not a valid model is exit 65, never a panic.
#[test]
fn assay_malformed_model_exits_65() {
    let dir = tempfile::tempdir().unwrap();
    let valid = std::fs::read_to_string(model()).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("truncated", valid.as_bytes()[..valid.len() / 2].to_vec()),
        ("not UTF-8", vec![0xff, 0xfe, b'{']),
        ("not a model", b"{\"bomFormat\":\"CycloneDX\"}".to_vec()),
        (
            "bad crypto",
            valid
                .replacen(
                    "\"nistQuantumSecurityLevel\": 5",
                    "\"nistQuantumSecurityLevel\": 9",
                    1,
                )
                .into_bytes(),
        ),
        (
            "crypto on a library",
            valid
                .replacen(
                    "\"kind\": \"cryptographic-asset\"",
                    "\"kind\": \"library\"",
                    1,
                )
                .into_bytes(),
        ),
    ];
    for (name, bytes) in cases {
        let path = dir.path().join(format!("{name}.model.json"));
        std::fs::write(&path, &bytes).unwrap();
        let out = rollcall()
            .args(["assay", "--model"])
            .arg(&path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{name}: {stderr}");
        assert!(stderr.starts_with("rollcall assay: "), "{name}: {stderr}");
        assert!(!stderr.contains("panicked"), "{name}: {stderr}");
        assert!(out.stdout.is_empty(), "{name}");
    }
}

/// With no detector for its inputs, assay gives a valid, empty CBOM that says no detector ran
/// (`rollcall:assay:detectors` = `none`), one note on stderr, and exit 0.
#[test]
fn assay_build_without_detectors_emits_empty_cbom_with_detectors_none_property_and_note() {
    let dir = tempfile::tempdir().unwrap();
    let elf = dir.path().join("zephyr.elf");
    std::fs::write(&elf, b"\x7fELF").unwrap();
    let out = rollcall()
        .args(["assay", "--source"])
        .arg(dir.path())
        .arg("--elf")
        .arg(&elf)
        .args(["--product", "sensor-node@1.0.0", "--timestamp", TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        stderr,
        "rollcall assay: note: no cryptographic-asset detector ran for these inputs; the \
         inventory is empty\n"
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(rollcall_core::cyclonedx::validate_cyclonedx_1_6(&doc).is_ok());
    assert_eq!(doc["metadata"]["component"]["name"], "sensor-node");
    assert_eq!(doc["metadata"]["component"]["version"], "1.0.0");
    assert_eq!(
        doc["metadata"]["properties"],
        serde_json::json!([{"name": "rollcall:assay:detectors", "value": "none"}])
    );
    assert!(doc.get("components").is_none(), "{doc}");
    // The Markdown summary of the same says there are none.
    let out = rollcall()
        .args(["assay", "--format", "md", "--source"])
        .arg(dir.path())
        .args(["--product", "sensor-node@1.0.0", "--timestamp", TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .ends_with("\nNo cryptographic assets.\n")
    );
}

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(path)
}

/// Every `cryptographic-asset` component of a CBOM as `bom-ref name`, with its
/// `cryptoProperties`.
fn crypto_components(doc: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    let mut stack: Vec<&Value> = doc["components"].as_array().into_iter().flatten().collect();
    while let Some(c) = stack.pop() {
        if c["type"] == "cryptographic-asset" {
            out.push(c);
        }
        stack.extend(c["components"].as_array().into_iter().flatten());
    }
    out
}

/// AC1 (CLI): `rollcall assay --build` on the Zephyr TLS fixture writes a schema-valid CBOM
/// with the configuration's assets (MCUboot's RSA-PSS-2048 signature, the TLS app's
/// AES-GCM and TLS 1.2), names the `kconfig` detector, prints its notes, exits 0, and is
/// byte-identical across runs.
#[test]
fn assay_build_zephyr_tls_fixture_reports_config_assets() {
    let run = || {
        rollcall()
            .args(["assay", "--build"])
            .arg(fixture("zephyr/tls"))
            .args(["--product", "tls@1.0.0", "--timestamp", TIMESTAMP])
            .output()
            .unwrap()
    };
    let out = run();
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr
            .contains("rollcall assay: note: http_server/zephyr/.config: uses the PSA Crypto API"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("no cryptographic-asset detector ran"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(rollcall_core::cyclonedx::validate_cyclonedx_1_6(&doc).is_ok());
    assert_eq!(
        doc["metadata"]["properties"],
        serde_json::json!([{"name": "rollcall:assay:detectors", "value": "kconfig"}])
    );
    let assets = crypto_components(&doc);
    let names: Vec<&str> = assets.iter().filter_map(|c| c["name"].as_str()).collect();
    for name in [
        "RSA-PSS-2048",
        "AES-GCM",
        "AES-GCM-128",
        "TLS-1.2",
        "ECDSA-secp256r1",
    ] {
        assert!(names.contains(&name), "{name}: {names:?}");
    }
    let rsa = assets.iter().find(|c| c["name"] == "RSA-PSS-2048").unwrap();
    assert_eq!(rsa["cryptoProperties"]["assetType"], "algorithm");
    assert_eq!(
        rsa["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"],
        "2048"
    );
    let tls = assets.iter().find(|c| c["name"] == "TLS-1.2").unwrap();
    assert_eq!(
        tls["cryptoProperties"]["protocolProperties"]["version"],
        "1.2"
    );
    // The CLI's own validator agrees.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tls.cbom.json");
    std::fs::write(&path, &out.stdout).unwrap();
    let validated = rollcall()
        .args(["validate", "--schema"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(validated.status.code(), Some(0));
    // Deterministic.
    assert_eq!(run().stdout, out.stdout);
}

/// A `--build` directory that is no Zephyr or ESP-IDF build: a note saying so, the
/// no-detector note, an empty CBOM, exit 0.
#[test]
fn assay_build_unrecognised_dir_notes_and_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.txt"), b"not a build").unwrap();
    let out = rollcall()
        .args(["assay", "--build"])
        .arg(dir.path())
        .args(["--product", "x", "--timestamp", TIMESTAMP])
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{stderr}");
    assert!(
        lines[0].starts_with("rollcall assay: note: --build "),
        "{stderr}"
    );
    assert!(
        lines[0].contains("not a Zephyr or ESP-IDF build"),
        "{stderr}"
    );
    assert!(
        lines[1].contains("no cryptographic-asset detector ran"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(rollcall_core::cyclonedx::validate_cyclonedx_1_6(&doc).is_ok());
    assert_eq!(doc["metadata"]["properties"][0]["value"], "none");
}

/// A malformed `.config` is exit 65 naming `file:line`; a recognised Zephyr build without its
/// `.config` is exit 66; neither panics.
#[test]
fn assay_build_malformed_config_exits_65() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("build_info.yml"),
        b"cmake:\n  application:\n    source-dir: '/x/app'\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("zephyr")).unwrap();
    for (bytes, needle) in [
        (
            &b"CONFIG_A=y\nnot kconfig\n"[..],
            ".config:2: unknown syntax",
        ),
        (b"CONFIG_A=\"open\n", ".config:1: unterminated string"),
        (b"\xff\xfe", "not valid UTF-8"),
    ] {
        std::fs::write(dir.path().join("zephyr/.config"), bytes).unwrap();
        let out = rollcall()
            .args(["assay", "--build"])
            .arg(dir.path())
            .args(["--product", "x"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(65), "{stderr}");
        assert!(stderr.starts_with("rollcall assay: "), "{stderr}");
        assert!(stderr.contains(needle), "{needle}: {stderr}");
        assert!(!stderr.contains("panicked"), "{stderr}");
        assert!(out.stdout.is_empty());
    }
    std::fs::remove_file(dir.path().join("zephyr/.config")).unwrap();
    let out = rollcall()
        .args(["assay", "--build"])
        .arg(dir.path())
        .args(["--product", "x"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(66), "{stderr}");
    assert!(stderr.contains(".config: not found"), "{stderr}");
}
