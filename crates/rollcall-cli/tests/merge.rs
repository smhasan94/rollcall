//! End-to-end tests for `rollcall merge` on the real Zephyr build fixtures and the
//! hand-written blob test data in `crates/rollcall-core/tests/data/blobs/`.
//!
//! The expected document `crates/rollcall-core/tests/golden/zephyr/baseline.sysbuild.cdx.json`
//! is generated only by `scripts/regen-golden.sh`. Inputs are generated into temporary
//! directories; `fixtures/` is never modified.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
/// `(variant, application image, bootloader image)`.
const BUILDS: [(&str, &str, &str); 3] = [
    ("baseline", "with_mcuboot", "mcuboot"),
    ("bt", "beacon", "mcuboot"),
    ("tls", "http_server", "mcuboot"),
];
const OPAQUE_NOTE: &str = "contents not analysed; hashes computed from the file";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr")
}

fn blobs_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rollcall-core/tests/data/blobs/blobs.yaml")
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden/zephyr")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Runs `rollcall generate --zephyr <variant>/<image> --west-list … -o <out>`.
fn generate(variant: &str, image: &str, out: &Path) {
    let root = fixtures_root().join(variant);
    rollcall()
        .arg("generate")
        .arg("--zephyr")
        .arg(root.join(image))
        .arg("--west-list")
        .arg(root.join("west-list.txt"))
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .arg("-o")
        .arg(out)
        .assert()
        .code(0);
}

fn merge(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let mut cmd = rollcall();
    cmd.arg("merge");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

fn stdout_json(out: &Output) -> Value {
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn property<'a>(c: &'a Value, name: &str) -> Vec<&'a str> {
    c["properties"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter(|p| p["name"] == name)
                .filter_map(|p| p["value"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

/// Every `bom-ref` in the document.
fn refs(doc: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<&Value> = vec![&doc["metadata"]["component"]];
    stack.extend(doc["components"].as_array().unwrap());
    while let Some(c) = stack.pop() {
        out.insert(c["bom-ref"].as_str().unwrap().to_owned());
        if let Some(children) = c["components"].as_array() {
            stack.extend(children);
        }
    }
    out
}

fn assert_fails(out: &Output, code: i32, needles: &[&str]) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(code), "stderr: {stderr}");
    assert!(out.stdout.is_empty());
    assert!(!stderr.contains("panicked"), "{stderr}");
    for needle in needles {
        assert!(stderr.contains(needle), "{stderr:?} lacks {needle:?}");
    }
    stderr
}

#[test]
fn merge_app_and_mcuboot_validates_with_two_images_under_one_product() {
    let dir = tempfile::tempdir().unwrap();
    for (variant, app, boot) in BUILDS {
        let app_path = dir.path().join(format!("{variant}-app.cdx.json"));
        let boot_path = dir.path().join(format!("{variant}-boot.cdx.json"));
        let merged_path = dir.path().join(format!("{variant}-merged.cdx.json"));
        generate(variant, app, &app_path);
        generate(variant, boot, &boot_path);
        rollcall()
            .arg("merge")
            .arg(&app_path)
            .arg(&boot_path)
            .args(["--product", "widget@1.2.0", "--timestamp", GOLDEN_TIMESTAMP])
            .arg("-o")
            .arg(&merged_path)
            .assert()
            .code(0)
            .stdout("")
            .stderr("");
        rollcall()
            .args(["validate", "--schema"])
            .arg(&merged_path)
            .assert()
            .code(0);

        let doc: Value = serde_json::from_str(&fs::read_to_string(&merged_path).unwrap()).unwrap();
        let root = &doc["metadata"]["component"];
        assert_eq!(root["name"], "widget", "{variant}");
        assert_eq!(root["version"], "1.2.0");
        let images = doc["components"].as_array().unwrap();
        assert_eq!(images.len(), 2, "{variant}");
        let mut kinds: Vec<(String, String)> = images
            .iter()
            .map(|i| {
                assert_eq!(i["type"], "firmware");
                (
                    i["name"].as_str().unwrap().to_owned(),
                    property(i, "rollcall:image-kind").join(","),
                )
            })
            .collect();
        kinds.sort();
        let mut expected = vec![
            (app.to_owned(), "application".to_owned()),
            (boot.to_owned(), "bootloader".to_owned()),
        ];
        expected.sort();
        assert_eq!(kinds, expected, "{variant}");
        for image in images {
            let nested = image["components"].as_array().unwrap();
            assert!(
                nested.iter().any(|c| c["name"] == "zephyr"),
                "{variant}: no zephyr under {}",
                image["name"]
            );
        }
        // The root depends on both images; no ref dangles.
        let all = refs(&doc);
        let deps = doc["dependencies"].as_array().unwrap();
        let root_deps = deps.iter().find(|d| d["ref"] == root["bom-ref"]).unwrap();
        let image_refs: BTreeSet<&str> = images
            .iter()
            .map(|i| i["bom-ref"].as_str().unwrap())
            .collect();
        let root_targets: BTreeSet<&str> = root_deps["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        assert_eq!(root_targets, image_refs, "{variant}");
        for dep in deps {
            assert!(all.contains(dep["ref"].as_str().unwrap()));
            for target in dep["dependsOn"].as_array().unwrap() {
                assert!(
                    all.contains(target.as_str().unwrap()),
                    "{variant}: {target}"
                );
            }
        }
        assert_eq!(deps.len(), all.len(), "one dependencies entry per node");
    }
}

#[test]
fn merge_baseline_app_and_mcuboot_matches_golden_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app.cdx.json");
    let boot = dir.path().join("boot.cdx.json");
    generate("baseline", "with_mcuboot", &app);
    generate("baseline", "mcuboot", &boot);
    let expected = golden("baseline.sysbuild.cdx.json");
    // Either order gives the same bytes.
    for (a, b) in [(&app, &boot), (&boot, &app)] {
        let out = merge(&[
            a,
            b,
            &"--product",
            &"with_mcuboot",
            &"--timestamp",
            &GOLDEN_TIMESTAMP,
        ]);
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        assert!(
            out.stdout == expected.as_bytes(),
            "merge output differs from baseline.sysbuild.cdx.json; run scripts/regen-golden.sh \
             if intended"
        );
    }
}

#[test]
fn merge_document_with_itself_is_byte_identical_to_input() {
    let dir = tempfile::tempdir().unwrap();
    for (variant, app, boot) in BUILDS {
        for image in [app, boot] {
            let path = dir.path().join(format!("{variant}-{image}.cdx.json"));
            generate(variant, image, &path);
            let out = merge(&[&path, &path, &"--timestamp", &GOLDEN_TIMESTAMP]);
            assert_eq!(out.status.code(), Some(0), "{variant}/{image}");
            assert!(
                out.stdout == fs::read(&path).unwrap(),
                "{variant}/{image}: merge a a differs from a"
            );
            // Merging the merged document again changes nothing either.
            let once = dir.path().join("once.cdx.json");
            fs::write(&once, &out.stdout).unwrap();
            let again = merge(&[&once, &path, &"--timestamp", &GOLDEN_TIMESTAMP]);
            assert_eq!(again.stdout, out.stdout);
        }
    }
}

#[test]
fn merge_conflicting_product_versions_exit_65_names_both_files() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.cdx.json");
    generate("baseline", "with_mcuboot", &a);
    // The same product at another version: --product re-parents a copy under a new version.
    let b = dir.path().join("b.cdx.json");
    rollcall()
        .arg("merge")
        .arg(&a)
        .args(["--product", "with_mcuboot@2.0.0", "-o"])
        .arg(&b)
        .assert()
        .code(0);
    let c = dir.path().join("c.cdx.json");
    rollcall()
        .arg("merge")
        .arg(&a)
        .args(["--product", "with_mcuboot@3.0.0", "-o"])
        .arg(&c)
        .assert()
        .code(0);
    let out = merge(&[&b, &c]);
    let b_name = b.display().to_string();
    let c_name = c.display().to_string();
    assert_fails(
        &out,
        65,
        &[
            "conflicting product versions",
            &b_name,
            &c_name,
            "with_mcuboot@2.0.0",
            "with_mcuboot@3.0.0",
        ],
    );
    // A different product name conflicts too, naming both files.
    let boot = dir.path().join("boot.cdx.json");
    generate("baseline", "mcuboot", &boot);
    let out = merge(&[&a, &boot]);
    assert_fails(
        &out,
        65,
        &[
            "conflicting product names",
            &a.display().to_string(),
            &boot.display().to_string(),
        ],
    );
    // --product resolves it.
    let out = merge(&[&b, &c, &"--product", &"with_mcuboot@4.0.0"]);
    assert_eq!(
        stdout_json(&out)["metadata"]["component"]["version"],
        "4.0.0"
    );
}

#[test]
fn merge_blob_manifest_emits_hash_supplier_and_opaque_property() {
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app.cdx.json");
    generate("baseline", "with_mcuboot", &app);
    let manifest = blobs_manifest();
    let out = merge(&[
        &app,
        &"--blob-manifest",
        &manifest,
        &"--timestamp",
        &GOLDEN_TIMESTAMP,
    ]);
    let doc = stdout_json(&out);
    assert_eq!(doc["metadata"]["component"]["name"], "with_mcuboot");
    let merged_path = dir.path().join("merged.cdx.json");
    fs::write(&merged_path, &out.stdout).unwrap();
    rollcall()
        .args(["validate", "--schema"])
        .arg(&merged_path)
        .assert()
        .code(0);
    let blobs: Vec<&Value> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| property(c, "rollcall:image-kind") == ["blob"])
        .collect();
    assert_eq!(blobs.len(), 2);
    let softdevice = blobs
        .iter()
        .find(|b| b["name"] == "s140_nrf52_softdevice")
        .unwrap();
    assert_eq!(
        softdevice["hashes"],
        json!([{"alg": "SHA-256", "content": "3051d54d0d3116c3818e01bbc6c8ad9d7023a1dad799f97392e440fd5a546fa6"}])
    );
    assert_eq!(softdevice["supplier"]["name"], "Nordic Semiconductor ASA");
    assert_eq!(softdevice["version"], "7.3.0");
    for blob in &blobs {
        assert_eq!(property(blob, "rollcall:opaque"), [OPAQUE_NOTE]);
        assert_eq!(blob["hashes"][0]["alg"], "SHA-256");
        assert!(blob["supplier"]["name"].is_string());
    }
    // The root depends on every blob.
    let root_ref = &doc["metadata"]["component"]["bom-ref"];
    let root_dep = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| &d["ref"] == root_ref)
        .unwrap();
    for blob in &blobs {
        assert!(
            root_dep["dependsOn"]
                .as_array()
                .unwrap()
                .contains(&blob["bom-ref"])
        );
    }

    // Blobs alone need --product.
    let out = merge(&[&"--blob-manifest", &manifest]);
    assert_fails(&out, 64, &["--product"]);
    let out = merge(&[&"--blob-manifest", &manifest, &"--product", &"radio-pack@1"]);
    assert_eq!(stdout_json(&out)["components"].as_array().unwrap().len(), 2);
}

#[test]
fn merge_bad_inputs_exit_with_the_right_code_never_panic() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.cdx.json");
    assert_fails(&merge(&[&missing]), 66, &["absent.cdx.json"]);
    let cases: [(&str, &[u8]); 5] = [
        ("empty", b""),
        ("truncated", b"{\"bomFormat\": \"CycloneDX\", \"specVer"),
        ("latin1", b"{\"bomFormat\": \"Cyclone\xff\"}"),
        (
            "spec15",
            b"{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.5\", \"metadata\": {}}",
        ),
        ("array", b"[]"),
    ];
    for (name, bytes) in cases {
        let path = dir.path().join(format!("{name}.cdx.json"));
        fs::write(&path, bytes).unwrap();
        assert_fails(&merge(&[&path]), 65, &[&format!("{name}.cdx.json")]);
    }
    let bad_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/blobs/bad-missing-file.yaml");
    assert_fails(
        &merge(&[&"--blob-manifest", &bad_manifest, &"--product", &"p"]),
        66,
        &["missing-file.bin"],
    );
    let bad_manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/blobs/bad-unknown-key.yaml");
    assert_fails(
        &merge(&[&"--blob-manifest", &bad_manifest, &"--product", &"p"]),
        65,
        &["bad-unknown-key.yaml"],
    );
    // Usage errors.
    assert_fails(&merge(&[]), 64, &["<FILE>"]);
    for spec in ["", "@1.0", "name@"] {
        assert_fails(&merge(&[&missing, &"--product", &spec]), 64, &["--product"]);
    }
}

#[test]
fn merge_blob_warnings_name_the_manifest_once() {
    // An entry no recogniser knows, without version or supplier: two warnings, each naming
    // the manifest exactly once, then `blobs[N]: <name>: …`.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("vendor-radio.bin"), b"radio").unwrap();
    let manifest = dir.path().join("m.yaml");
    fs::write(
        &manifest,
        "blobs:\n  - name: vendor-radio\n    path: vendor-radio.bin\n",
    )
    .unwrap();
    let out = merge(&[&"--blob-manifest", &manifest, &"--product", &"p"]);
    stdout_json(&out);
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();
    let m = manifest.display();
    assert_eq!(
        stderr,
        format!(
            "rollcall merge: warning: {m}: blobs[0]: vendor-radio: no version (none in the \
             manifest, none recognised)\n\
             rollcall merge: warning: {m}: blobs[0]: vendor-radio: no supplier (none in the \
             manifest, none recognised)\n"
        )
    );
    for line in stderr.lines() {
        assert_eq!(line.matches("m.yaml").count(), 1, "{line}");
    }
}

#[test]
fn merge_scoped_product_name_needs_an_explicit_version() {
    // `NAME[@VERSION]` splits at the last `@`: a bare scoped name is an empty NAME.
    let manifest = blobs_manifest();
    assert_fails(
        &merge(&[
            &"--blob-manifest",
            &manifest,
            &"--product",
            &"@scope/widget",
        ]),
        64,
        &["--product"],
    );
    let out = merge(&[
        &"--blob-manifest",
        &manifest,
        &"--product",
        &"@scope/widget@1.0.0",
        &"--timestamp",
        &GOLDEN_TIMESTAMP,
    ]);
    let doc = stdout_json(&out);
    assert_eq!(doc["metadata"]["component"]["name"], "@scope/widget");
    assert_eq!(doc["metadata"]["component"]["version"], "1.0.0");
}
