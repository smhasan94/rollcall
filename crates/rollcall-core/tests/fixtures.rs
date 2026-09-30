//! Checks on the Zephyr build fixtures in `fixtures/zephyr/` (see `docs/fixtures.md`).
//!
//! The fixtures are produced only by `scripts/regen-fixtures.sh`; these tests check that the
//! committed tree is what its `MANIFEST.json` says it is, and that each variant was built with
//! the options it claims.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

const VARIANTS: [&str; 3] = ["baseline", "bt", "tls"];
const SPDX_DOCS: [&str; 4] = ["app", "zephyr", "build", "modules-deps"];
const MAX_TOTAL_BYTES: u64 = 50_000_000;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr")
}

fn manifest() -> Value {
    let path = fixtures_root().join("MANIFEST.json");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every file under `dir`, as `/`-separated paths relative to `dir`, sorted.
fn walk(dir: &Path) -> Vec<String> {
    fn go(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let entries =
            fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                go(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).expect("path under base");
                let parts: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push(parts.join("/"));
            }
        }
    }
    let mut out = Vec::new();
    go(dir, dir, &mut out);
    out.sort();
    out
}

/// True if the Kconfig text sets `key` to `y` (a line exactly `KEY=y`).
fn config_is_set(text: &str, key: &str) -> bool {
    let want = format!("{key}=y");
    text.lines().any(|l| l.trim_end_matches('\r') == want)
}

/// True if the Kconfig text has `# KEY is not set`.
fn config_is_unset(text: &str, key: &str) -> bool {
    let want = format!("# {key} is not set");
    text.lines().any(|l| l.trim_end_matches('\r') == want)
}

/// Reads a fixture as text, replacing invalid UTF-8 rather than failing.
fn read_text(rel: &str) -> String {
    let path = fixtures_root().join(rel);
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The application image name of a variant, from the manifest.
fn app_image(manifest: &Value, variant: &str) -> String {
    manifest
        .pointer(&format!("/variants/{variant}/images/app"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("manifest has no variants.{variant}.images.app"))
        .to_owned()
}

fn manifest_files(manifest: &Value) -> Vec<&Value> {
    manifest
        .get("files")
        .and_then(Value::as_array)
        .expect("manifest has a files array")
        .iter()
        .collect()
}

fn is_text_fixture(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        ".config"
            | "build_info.yml"
            | "domains.yaml"
            | "zephyr.meta"
            | "zephyr.map"
            | "west-list.txt"
    ) || name.ends_with(".spdx")
}

#[test]
fn config_helpers_tolerate_malformed_lines() {
    let text = "\n\u{0}\r\nCONFIG_BT\nCONFIG_BT=yes\nCONFIG_BT_X=y\n=y\n# CONFIG_BT is not set really\n\
                #CONFIG_BT is not set\nCONFIG_BT= y\n\u{fffd}\u{fffd}=y\n";
    assert!(!config_is_set(text, "CONFIG_BT"));
    assert!(!config_is_unset(text, "CONFIG_BT"));
    assert!(!config_is_set("", "CONFIG_BT"));
    assert!(!config_is_unset("", ""));
    assert!(config_is_set("CONFIG_BT=y\r\n", "CONFIG_BT"));
    assert!(config_is_unset("x\n# CONFIG_BT is not set", "CONFIG_BT"));
    // A key that is a prefix of another is not confused with it.
    assert!(!config_is_set("CONFIG_BT_HCI=y\n", "CONFIG_BT"));
    // Invalid UTF-8 read through `read_text`'s lossy path still yields searchable text.
    let lossy = String::from_utf8_lossy(b"\xff\xfeCONFIG_BT=y\n\xc3\nCONFIG_MBEDTLS=y\n");
    assert!(config_is_set(&lossy, "CONFIG_MBEDTLS"));
    assert!(!config_is_set(&lossy, "CONFIG_BT"));
}

#[test]
fn manifest_pins_zephyr_revision_and_sdk_version() {
    let m = manifest();
    assert_eq!(
        m.get("format").and_then(Value::as_str),
        Some("rollcall-fixtures/1")
    );
    assert_eq!(
        m.pointer("/zephyr/tag").and_then(Value::as_str),
        Some("v4.4.2")
    );
    let commit = m
        .pointer("/zephyr/commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        commit.len(),
        40,
        "zephyr.commit is not 40 hex digits: {commit:?}"
    );
    assert!(
        commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "zephyr.commit is not lowercase hex: {commit:?}"
    );
    assert_eq!(
        m.pointer("/sdk/version").and_then(Value::as_str),
        Some("1.0.1")
    );
    let variants: Vec<&str> = m
        .get("variants")
        .and_then(Value::as_object)
        .expect("manifest has variants")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(variants, VARIANTS, "manifest variants");
}

#[test]
fn every_variant_has_the_required_file_set() {
    let m = manifest();
    let root = fixtures_root();
    for v in VARIANTS {
        let app = app_image(&m, v);
        let mut required = vec![
            format!("{v}/west-list.txt"),
            format!("{v}/build_info.yml"),
            format!("{v}/domains.yaml"),
            format!("{v}/zephyr/.config"),
            format!("{v}/{app}/zephyr/zephyr.signed.hex"),
            format!("{v}/mcuboot/zephyr/zephyr.hex"),
        ];
        for img in [app.as_str(), "mcuboot"] {
            for f in [
                "build_info.yml",
                "zephyr/.config",
                "zephyr/zephyr.map",
                "zephyr/zephyr.meta",
                "zephyr/zephyr.elf",
            ] {
                required.push(format!("{v}/{img}/{f}"));
            }
            for doc in SPDX_DOCS {
                required.push(format!("{v}/{img}/spdx/{doc}.spdx"));
            }
        }
        for rel in &required {
            let path = root.join(rel);
            assert!(path.is_file(), "missing fixture {rel}");
            let len = fs::metadata(&path).map(|md| md.len()).unwrap_or(0);
            assert!(len > 0, "empty fixture {rel}");
        }
    }
}

#[test]
fn manifest_lists_exactly_the_committed_files() {
    let m = manifest();
    let listed: Vec<String> = manifest_files(&m)
        .iter()
        .map(|e| {
            e.get("path")
                .and_then(Value::as_str)
                .expect("file entry has a path")
                .to_owned()
        })
        .collect();
    let mut sorted = listed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(listed, sorted, "manifest files are not sorted and unique");
    let on_disk: Vec<String> = walk(&fixtures_root())
        .into_iter()
        .filter(|p| p != "MANIFEST.json")
        .collect();
    assert_eq!(listed, on_disk, "manifest file list differs from the tree");
    let total: u64 = manifest_files(&m)
        .iter()
        .map(|e| e.get("bytes").and_then(Value::as_u64).unwrap_or(0))
        .sum();
    assert_eq!(m.get("total_bytes").and_then(Value::as_u64), Some(total));
}

#[test]
fn manifest_sha256s_match_committed_files() {
    let m = manifest();
    let root = fixtures_root();
    let files = manifest_files(&m);
    assert!(!files.is_empty(), "manifest lists no files");
    for entry in files {
        let rel = entry.get("path").and_then(Value::as_str).expect("path");
        let bytes = fs::read(root.join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"));
        assert_eq!(
            entry.get("sha256").and_then(Value::as_str),
            Some(sha256_hex(&bytes).as_str()),
            "sha256 of {rel}"
        );
        assert_eq!(
            entry.get("bytes").and_then(Value::as_u64),
            Some(bytes.len() as u64),
            "size of {rel}"
        );
    }
}

#[test]
fn fixture_tree_is_under_50_mb() {
    let root = fixtures_root();
    let total: u64 = walk(&root)
        .iter()
        .map(|rel| fs::metadata(root.join(rel)).map(|md| md.len()).unwrap_or(0))
        .sum();
    assert!(total > 0, "fixture tree is empty");
    assert!(
        total < MAX_TOTAL_BYTES,
        "fixture tree is {total} bytes, limit {MAX_TOTAL_BYTES}"
    );
}

#[test]
fn baseline_config_has_bt_and_mbedtls_off() {
    let m = manifest();
    let config = read_text(&format!(
        "baseline/{}/zephyr/.config",
        app_image(&m, "baseline")
    ));
    assert!(
        config_is_unset(&config, "CONFIG_BT"),
        "baseline: CONFIG_BT is not off"
    );
    assert!(
        config_is_unset(&config, "CONFIG_MBEDTLS"),
        "baseline: CONFIG_MBEDTLS is not off"
    );
}

#[test]
fn bt_config_has_bt_on_and_mbedtls_off() {
    let m = manifest();
    let config = read_text(&format!("bt/{}/zephyr/.config", app_image(&m, "bt")));
    assert!(
        config_is_set(&config, "CONFIG_BT"),
        "bt: CONFIG_BT is not on"
    );
    assert!(
        config_is_unset(&config, "CONFIG_MBEDTLS"),
        "bt: CONFIG_MBEDTLS is not off"
    );
}

#[test]
fn tls_config_has_mbedtls_and_tls_sockets_on_and_bt_off() {
    let m = manifest();
    let config = read_text(&format!("tls/{}/zephyr/.config", app_image(&m, "tls")));
    assert!(
        config_is_set(&config, "CONFIG_MBEDTLS"),
        "tls: CONFIG_MBEDTLS is not on"
    );
    assert!(
        config_is_set(&config, "CONFIG_NET_SOCKETS_SOCKOPT_TLS"),
        "tls: CONFIG_NET_SOCKETS_SOCKOPT_TLS is not on"
    );
    assert!(
        config_is_unset(&config, "CONFIG_BT"),
        "tls: CONFIG_BT is not off"
    );
}

#[test]
fn every_variant_enables_mcuboot_via_sysbuild() {
    let m = manifest();
    for v in VARIANTS {
        let sysbuild = read_text(&format!("{v}/zephyr/.config"));
        assert!(
            config_is_set(&sysbuild, "SB_CONFIG_BOOTLOADER_MCUBOOT"),
            "{v}: sysbuild does not enable MCUboot"
        );
        let app = read_text(&format!("{v}/{}/zephyr/.config", app_image(&m, v)));
        assert!(
            config_is_set(&app, "CONFIG_BOOTLOADER_MCUBOOT"),
            "{v}: app is not built for MCUboot"
        );
        let boot = read_text(&format!("{v}/mcuboot/zephyr/.config"));
        assert!(
            config_is_set(&boot, "CONFIG_MCUBOOT"),
            "{v}: mcuboot image is not MCUboot"
        );
    }
}

#[test]
fn spdx_documents_are_2_3_with_pinned_namespace() {
    let m = manifest();
    for v in VARIANTS {
        let app = app_image(&m, v);
        for img in [app.as_str(), "mcuboot"] {
            for doc in SPDX_DOCS {
                let rel = format!("{v}/{img}/spdx/{doc}.spdx");
                let text = read_text(&rel);
                assert_eq!(
                    text.lines().next(),
                    Some("SPDXVersion: SPDX-2.3"),
                    "{rel}: not SPDX 2.3"
                );
                let want =
                    format!("DocumentNamespace: http://spdx.org/spdxdocs/rollcall-{v}-{img}/");
                assert!(
                    text.lines().any(|l| l.starts_with(&want)),
                    "{rel}: no namespace starting {want:?}"
                );
            }
        }
    }
}

#[test]
fn text_fixtures_contain_no_host_paths() {
    let root = fixtures_root();
    let mut build_infos = 0;
    for rel in walk(&root).iter().filter(|p| is_text_fixture(p)) {
        let text = read_text(rel);
        for needle in ["/Users/", "/home/", "/private/"] {
            assert!(
                !text.contains(needle),
                "{rel} contains host path {needle:?}"
            );
        }
        if rel.ends_with("build_info.yml") {
            build_infos += 1;
            assert!(
                text.contains("/zephyrproject"),
                "{rel} does not use /zephyrproject"
            );
        }
    }
    assert_eq!(build_infos, VARIANTS.len() * 3, "build_info.yml count");
}

#[test]
fn fixtures_doc_has_required_sections() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/fixtures.md");
    let doc =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    for heading in [
        "# Zephyr build fixtures",
        "## What is here",
        "## Pins",
        "## Prerequisites",
        "## Regenerating",
        "## Determinism",
        "## Trimming",
        "## Checks",
        "## Bumping the pin",
    ] {
        assert!(
            doc.lines().any(|l| l.trim_end() == heading),
            "docs/fixtures.md lacks {heading:?}"
        );
    }
    for term in [
        "scripts/regen-fixtures.sh",
        "--check-stable",
        "gh workflow run regen-fixtures.yml",
        "gh run download",
        "canonical",
        "v4.4.2",
        "1.0.1",
        "/zephyrproject",
        "/zephyr-sdk",
    ] {
        assert!(
            doc.contains(term),
            "docs/fixtures.md does not mention {term:?}"
        );
    }
}
