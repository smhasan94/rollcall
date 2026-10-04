//! Checks on the ESP-IDF build fixtures, `fixtures/esp-idf/` (see `docs/esp-idf.md`,
//! *Fixtures*): `hello-world` (`examples/get-started/hello_world`) and `wifi-tls`
//! (`examples/protocols/https_request`), each a real build for esp32 in the pinned
//! `espressif/idf` Docker image.
//!
//! The fixtures are produced only by `scripts/regen-fixtures-esp-idf.sh`; these tests check
//! that the committed tree is what its `MANIFEST.json` says, that it records the script's
//! pins, that the script runs the image by digest, that no build-machine path is in it, and
//! that every blob the map links is in it with the recorded hash.
//!
//! `ROLLCALL_ESP_IDF_FIXTURES_DIR` points the tests at another tree; the script uses it to
//! test a staged tree before installing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rollcall_core::esp_idf::{self, project_description, sdkconfig, split, table};
use rollcall_core::linker_map;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// (variant, project name, sample).
const VARIANTS: [(&str, &str, &str); 2] = [
    (
        "hello-world",
        "hello_world",
        "examples/get-started/hello_world",
    ),
    (
        "wifi-tls",
        "https_request",
        "examples/protocols/https_request",
    ),
];

/// The fixture tree is kept under this size.
const MAX_TREE_BYTES: u64 = 16_000_000;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn root() -> PathBuf {
    match std::env::var_os("ROLLCALL_ESP_IDF_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => repo_root().join("fixtures/esp-idf"),
    }
}

fn manifest() -> Value {
    let path = root().join("MANIFEST.json");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read(rel: &str) -> Vec<u8> {
    let path = root().join(rel);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every file under the tree, relative, sorted.
fn files_on_disk() -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy();
                out.push(rel.replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root(), &root(), &mut out);
    out.sort();
    out
}

/// A `NAME=value` assignment in `scripts/regen-fixtures-esp-idf.sh`.
fn script_pin(name: &str) -> String {
    let script = fs::read_to_string(repo_root().join("scripts/regen-fixtures-esp-idf.sh")).unwrap();
    script
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name}= in regen-fixtures-esp-idf.sh"))
        .trim()
        .to_owned()
}

#[test]
fn manifest_pins_match_the_script_and_the_image_digest() {
    let m = manifest();
    assert_eq!(m["format"], "rollcall-fixtures/1");
    assert_eq!(m["generator"], "scripts/regen-fixtures-esp-idf.sh");
    assert_eq!(m["ecosystem"], "esp-idf");
    let idf = &m["esp_idf"];
    for (key, pin) in [
        ("image", "IDF_IMAGE"),
        ("tag", "IDF_TAG"),
        ("digest", "IDF_IMAGE_DIGEST"),
        ("target", "TARGET"),
    ] {
        assert_eq!(idf[key].as_str(), Some(script_pin(pin).as_str()), "{key}");
    }
    assert_eq!(idf["image"], "espressif/idf");
    assert_eq!(idf["tag"], "v5.5.1");
    assert_eq!(idf["target"], "esp32");
    let digest = idf["digest"].as_str().unwrap();
    let hex = digest.strip_prefix("sha256:").unwrap();
    assert!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "{digest}"
    );
    // The ESP-IDF table rollcall ships was checked against the same release.
    assert_eq!(
        table::builtin().unwrap().idf.tag,
        idf["tag"].as_str().unwrap()
    );
    let variants = m["variants"].as_object().unwrap();
    let names: Vec<&str> = variants.keys().map(String::as_str).collect();
    assert_eq!(names, ["hello-world", "wifi-tls"]);
    for (v, project, sample) in VARIANTS {
        assert_eq!(variants[v]["sample"], sample, "{v}");
        assert_eq!(variants[v]["project"], project, "{v}");
    }
}

#[test]
fn script_runs_the_image_by_digest_only() {
    let script = fs::read_to_string(repo_root().join("scripts/regen-fixtures-esp-idf.sh")).unwrap();
    assert!(script.contains("IMAGE_REF=\"$IDF_IMAGE@$IDF_IMAGE_DIGEST\""));
    for line in script.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("docker run") || line.starts_with("docker pull") {
            assert!(line.contains("\"$IMAGE_REF\""), "not by digest: {line}");
        }
        assert!(
            !line.contains("espressif/idf:") && !line.contains(":latest"),
            "image by tag: {line}"
        );
    }
}

#[test]
fn every_tree_holds_exactly_the_expected_files() {
    let m = manifest();
    let mut expected: BTreeSet<String> = BTreeSet::from(["MANIFEST.json".to_owned()]);
    for (v, project, _) in VARIANTS {
        for f in [
            "sdkconfig".to_owned(),
            "build/project_description.json".to_owned(),
            format!("build/{project}.map"),
            "idf/components/esp_common/include/esp_idf_version.h".to_owned(),
        ] {
            expected.insert(format!("{v}/{f}"));
        }
        for blob in m["variants"][v]["blobs"].as_array().unwrap() {
            expected.insert(format!("{v}/idf/{}", blob.as_str().unwrap()));
        }
    }
    // https_request has a manifest (protocol_examples_common, a local component) and so a
    // lock; hello_world has neither. Neither downloads a registry component.
    for f in [
        "wifi-tls/dependencies.lock",
        "wifi-tls/main/idf_component.yml",
    ] {
        expected.insert(f.to_owned());
    }
    let on_disk: BTreeSet<String> = files_on_disk().into_iter().collect();
    assert_eq!(on_disk, expected);
    assert!(
        m["variants"]["hello-world"]["blobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(m["variants"]["wifi-tls"]["blobs"].as_array().unwrap().len() >= 4);
}

#[test]
fn manifest_lists_every_file_with_its_size_and_sha256() {
    let m = manifest();
    let files = m["files"].as_array().unwrap();
    let listed: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    let expected: Vec<String> = files_on_disk()
        .into_iter()
        .filter(|f| f != "MANIFEST.json")
        .collect();
    assert_eq!(listed, expected);
    let mut total = 0;
    for f in files {
        let rel = f["path"].as_str().unwrap();
        let bytes = read(rel);
        assert_eq!(f["sha256"].as_str(), Some(sha256(&bytes).as_str()), "{rel}");
        assert_eq!(f["bytes"].as_u64(), Some(bytes.len() as u64), "{rel}");
        assert_eq!(
            f["transform"].as_str(),
            rel.ends_with(".map").then_some("strip-cref"),
            "{rel}"
        );
        total += bytes.len() as u64;
    }
    assert_eq!(m["total_bytes"].as_u64(), Some(total));
    assert!(total <= MAX_TREE_BYTES, "the tree is {total} bytes");
}

#[test]
fn no_build_machine_path_is_left_in_any_text_file() {
    let needles = [
        "/Users/",
        "/home/",
        "/private/",
        "/var/folders/",
        "/tmp/",
        "C:\\",
    ];
    for rel in files_on_disk() {
        if rel.ends_with(".a") {
            continue;
        }
        let bytes = read(&rel);
        for needle in needles {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{rel} contains {needle:?}"
            );
        }
    }
    // The only absolute paths are the container's.
    for (v, _, _) in VARIANTS {
        let text = String::from_utf8(read(&format!("{v}/build/project_description.json"))).unwrap();
        let d = project_description::parse(&text).unwrap();
        assert_eq!(d.idf_path.as_deref(), Some("/opt/esp/idf"), "{v}");
        assert_eq!(d.build_dir, Some(format!("/project/{v}/build")), "{v}");
    }
    for (v, project, _) in VARIANTS {
        let map = read(&format!("{v}/build/{project}.map"));
        let needle = b"Cross Reference Table";
        assert!(
            !map.windows(needle.len()).any(|w| w == needle),
            "{v}: the cref table was not stripped"
        );
    }
}

#[test]
fn linked_blob_archives_hash_as_recorded() {
    let m = manifest();
    let t = table::builtin().unwrap();
    for (v, project, _) in VARIANTS {
        let text = String::from_utf8(read(&format!("{v}/build/project_description.json"))).unwrap();
        let d = project_description::parse(&text).unwrap();
        let config =
            sdkconfig::parse(&String::from_utf8(read(&format!("{v}/sdkconfig"))).unwrap()).unwrap();
        let map_text = String::from_utf8(read(&format!("{v}/build/{project}.map"))).unwrap();
        let map = linker_map::parse(&map_text).unwrap();
        let outcome = split::split(
            &t,
            &config,
            &map,
            d.idf_path.as_deref(),
            d.build_dir.as_deref(),
            "map",
        );
        let recorded: BTreeSet<&str> = m["variants"][v]["blobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_str().unwrap())
            .collect();
        for blob in &outcome.blobs {
            assert!(
                recorded.contains(blob.path.as_str()),
                "{v}: {} not in the fixture",
                blob.path
            );
            let rel = format!("{v}/idf/{}", blob.path);
            let entry = m["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["path"] == rel.as_str())
                .unwrap_or_else(|| panic!("{rel} not in MANIFEST.json"));
            let file = root().join(&rel);
            assert_eq!(
                entry["sha256"].as_str(),
                Some(rollcall_core::blob::sha256_file(&file).unwrap().as_str()),
                "{rel}"
            );
        }
        let version_header = String::from_utf8(read(&format!(
            "{v}/idf/components/esp_common/include/esp_idf_version.h"
        )))
        .unwrap();
        assert_eq!(
            esp_idf::version_from_header(&version_header).as_deref(),
            Some("5.5.1")
        );
    }
}
