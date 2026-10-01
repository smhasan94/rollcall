//! Blob manifests: hashing, recognisers, the opaque note, and malformed input.
//!
//! The inputs are the hand-written files in `tests/data/blobs/` (see `tests/data/README.md`),
//! not real-build fixtures. `tests/golden/blobs.cdx.json` is generated only by
//! `scripts/regen-golden.sh`, which runs this test with `ROLLCALL_BLESS=1`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::GOLDEN_TIMESTAMP;
use rollcall_core::blob::{self, BlobError};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::{EvidenceField, HashAlgorithm, Image, ImageKind, Product, Technique};
use serde_json::{Value, json};

/// `sha256sum crates/rollcall-core/tests/data/blobs/s140_nrf52_7.3.0_softdevice.hex`.
const FAKE_SOFTDEVICE_SHA256: &str =
    "3051d54d0d3116c3818e01bbc6c8ad9d7023a1dad799f97392e440fd5a546fa6";
/// `sha256sum crates/rollcall-core/tests/data/blobs/libphy.a`.
const FAKE_LIBPHY_SHA256: &str = "40a0cdacd5afb8e813d7e72396cf1faf2ea3fe52d306216aed61de44fe35d977";
const OPAQUE_NOTE: &str = "contents not analysed; hashes computed from the file";

fn blobs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/blobs")
}

fn manifest() -> PathBuf {
    blobs_dir().join("blobs.yaml")
}

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr"),
    }
}

fn sha256(image: &Image) -> &str {
    image
        .hashes
        .iter()
        .find(|h| h.algorithm() == HashAlgorithm::Sha256)
        .map(|h| h.digest())
        .unwrap()
}

/// The blobs of `blobs.yaml` under the product `blobs-demo@1.0.0`.
fn blob_product() -> Product {
    let ingest = blob::load(&manifest()).unwrap();
    let spec: ProductSpec = "blobs-demo@1.0.0".parse().unwrap();
    let mut product = merge::merge(Vec::new(), Some(&spec)).unwrap();
    merge::add_blobs(&mut product, ingest.images).unwrap();
    product
}

fn render(product: &Product) -> String {
    let options = WriteOptions::new(Timestamp::parse(GOLDEN_TIMESTAMP).unwrap());
    cyclonedx::write(product, &options).unwrap()
}

fn check_golden(name: &str, actual: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
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
        "{} differs; if the change is intended, run scripts/regen-golden.sh and review the \
         diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

#[test]
fn fake_softdevice_hash_matches_sha256sum() {
    let file = blobs_dir().join("s140_nrf52_7.3.0_softdevice.hex");
    assert_eq!(blob::sha256_file(&file).unwrap(), FAKE_SOFTDEVICE_SHA256);
    let ingest = blob::load(&manifest()).unwrap();
    let softdevice = ingest
        .images
        .iter()
        .find(|i| i.name == "s140_nrf52_softdevice")
        .unwrap();
    assert_eq!(sha256(softdevice), FAKE_SOFTDEVICE_SHA256);
    let libphy = ingest.images.iter().find(|i| i.name == "libphy").unwrap();
    assert_eq!(sha256(libphy), FAKE_LIBPHY_SHA256);
}

#[test]
fn real_signed_hex_hash_matches_fixture_manifest() {
    // An independent oracle: MANIFEST.json records the SHA-256 of every fixture file.
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(fixtures_root().join("MANIFEST.json")).unwrap())
            .unwrap();
    let rel = "baseline/with_mcuboot/zephyr/zephyr.signed.hex";
    let expected = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == rel)
        .and_then(|f| f["sha256"].as_str())
        .unwrap();
    assert_eq!(
        blob::sha256_file(&fixtures_root().join(rel)).unwrap(),
        expected
    );

    // Through a manifest, too (written to a temporary directory; fixtures/ is untouched).
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("blobs.yaml");
    fs::write(
        &manifest_path,
        format!(
            "blobs:\n  - name: with_mcuboot-signed\n    path: {}\n",
            fixtures_root().join(rel).display()
        ),
    )
    .unwrap();
    let ingest = blob::load(&manifest_path).unwrap();
    assert_eq!(sha256(&ingest.images[0]), expected);
}

#[test]
fn blob_image_carries_sha256_supplier_and_opaque_property() {
    let ingest = blob::load(&manifest()).unwrap();
    assert_eq!(ingest.images.len(), 2);
    let softdevice = &ingest.images[0];
    assert_eq!(softdevice.kind, ImageKind::Blob);
    assert_eq!(softdevice.name, "s140_nrf52_softdevice");
    assert_eq!(softdevice.version.as_deref(), Some("7.3.0"));
    assert_eq!(
        softdevice.supplier.as_ref().map(|s| s.name()),
        Some("Nordic Semiconductor ASA")
    );
    assert_eq!(
        softdevice.licence.as_ref().map(|l| l.as_str()),
        Some("LicenseRef-Nordic-5-Clause")
    );
    // Recogniser evidence for the facts it supplied; manifest evidence for the licence;
    // binary-analysis evidence for the hash.
    let has = |field, technique, source: &str| {
        softdevice
            .evidence
            .iter()
            .any(|e| e.field == field && e.technique == technique && e.source() == source)
    };
    assert!(has(
        EvidenceField::Name,
        Technique::Filename,
        "blob-recogniser"
    ));
    assert!(has(
        EvidenceField::Version,
        Technique::Filename,
        "blob-recogniser"
    ));
    assert!(has(
        EvidenceField::Supplier,
        Technique::Filename,
        "blob-recogniser"
    ));
    assert!(has(
        EvidenceField::Licence,
        Technique::ManifestAnalysis,
        "blob-manifest"
    ));
    assert!(has(
        EvidenceField::Hash,
        Technique::BinaryAnalysis,
        "blob-file"
    ));
    let libphy = &ingest.images[1];
    assert_eq!(libphy.name, "libphy");
    assert_eq!(libphy.version.as_deref(), Some("5.2.1"));
    assert_eq!(
        libphy.purl.as_ref().map(|p| p.as_str()),
        Some("pkg:generic/espressif/libphy@5.2.1")
    );
    assert!(ingest.warnings.is_empty(), "{:?}", ingest.warnings);

    // In CycloneDX: hash, supplier and the opaque note on every blob image.
    let text = render(&blob_product());
    let doc: Value = serde_json::from_str(&text).unwrap();
    validate_cyclonedx_1_6(&doc).unwrap();
    let images = doc["components"].as_array().unwrap();
    assert_eq!(images.len(), 2);
    for image in images {
        let name = image["name"].as_str().unwrap();
        let expected_hash = if name == "libphy" {
            FAKE_LIBPHY_SHA256
        } else {
            FAKE_SOFTDEVICE_SHA256
        };
        assert_eq!(
            image["hashes"],
            json!([{"alg": "SHA-256", "content": expected_hash}]),
            "{name}"
        );
        assert!(image["supplier"]["name"].is_string(), "{name}");
        let properties = image["properties"].as_array().unwrap();
        assert!(
            properties.contains(&json!({"name": "rollcall:opaque", "value": OPAQUE_NOTE})),
            "{name}: {properties:?}"
        );
        assert!(properties.contains(&json!({"name": "rollcall:image-kind", "value": "blob"})));
    }
}

#[test]
fn blob_manifest_matches_golden() {
    let product = blob_product();
    let text = render(&product);
    check_golden("blobs.cdx.json", &text);
    // And it reads back losslessly.
    assert_eq!(cyclonedx::read_str(&text).unwrap().product, product);
}

#[test]
fn malformed_manifest_and_missing_file_error_never_panic() {
    let dir = blobs_dir();
    let load = |name: &str| blob::load(&dir.join(name)).unwrap_err();
    assert!(matches!(
        load("bad-missing-path.yaml"),
        BlobError::MissingField {
            index: 0,
            field: "path"
        }
    ));
    assert!(matches!(load("bad-unknown-key.yaml"), BlobError::Yaml(m) if m.contains("vendor")));
    let missing = load("bad-missing-file.yaml");
    assert!(missing.is_read_error(), "{missing}");
    assert!(
        missing.to_string().contains("missing-file.bin"),
        "{missing}"
    );
    assert!(matches!(
        load("bad-duplicate.yaml"),
        BlobError::Duplicate { index: 1, .. }
    ));
    assert!(matches!(load("bad-truncated.yaml"), BlobError::Yaml(_)));
    assert!(matches!(
        load("bad-licence.yaml"),
        BlobError::Id { index: 0, .. }
    ));
    assert!(matches!(
        load("bad-no-name.yaml"),
        BlobError::MissingField {
            index: 0,
            field: "name"
        }
    ));
    let absent = load("no-such-manifest.yaml");
    assert!(absent.is_read_error());

    // Generated malformed input: empty, whitespace, wrong types, wrong encoding, deep nesting.
    let tmp = tempfile::tempdir().unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("blank", b"  \n\t\n".to_vec()),
        ("no-blobs", b"other: 1\n".to_vec()),
        ("empty-list", b"blobs: []\n".to_vec()),
        ("scalar", b"42\n".to_vec()),
        ("list-not-map", b"- a\n- b\n".to_vec()),
        ("blobs-not-list", b"blobs: libphy.a\n".to_vec()),
        ("entry-not-map", b"blobs:\n  - libphy.a\n".to_vec()),
        (
            "name-is-map",
            b"blobs:\n  - path: libphy.a\n    name: {a: 1}\n".to_vec(),
        ),
        (
            "empty-name",
            b"blobs:\n  - path: libphy.a\n    name: ''\n".to_vec(),
        ),
        ("latin1", b"blobs:\n  - path: caf\xe9.bin\n".to_vec()),
        (
            "deep",
            format!("blobs: {}", "[".repeat(10_000)).into_bytes(),
        ),
    ];
    for (name, bytes) in cases {
        let path = tmp.path().join(format!("{name}.yaml"));
        fs::write(&path, bytes).unwrap();
        let result = std::panic::catch_unwind(|| blob::load(&path));
        let result = result.unwrap_or_else(|_| panic!("{name}: panicked"));
        assert!(result.is_err(), "{name}: {result:?}");
    }
    // A directory where a blob file should be is a read error, not a panic.
    fs::create_dir(tmp.path().join("adir")).unwrap();
    fs::write(
        tmp.path().join("dir.yaml"),
        "blobs:\n  - name: d\n    path: adir\n",
    )
    .unwrap();
    assert!(
        blob::load(&tmp.path().join("dir.yaml"))
            .unwrap_err()
            .is_read_error()
    );
    // Every parser error goes through manifest::parse without panicking.
    assert!(matches!(blob::manifest::parse(""), Err(BlobError::Empty)));
}

#[test]
fn blob_path_that_is_not_a_regular_file_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("adir")).unwrap();
    let manifest = tmp.path().join("m.yaml");
    fs::write(&manifest, "blobs:\n  - name: d\n    path: adir\n").unwrap();
    let err = blob::load(&manifest).unwrap_err();
    match &err {
        BlobError::NotAFile { path } => assert_eq!(path, &tmp.path().join("adir")),
        other => panic!("expected NotAFile, got {other}"),
    }
    assert!(err.is_read_error(), "{err}");
    assert!(err.to_string().contains("not a regular file"), "{err}");

    // A device that never ends is refused before hashing, so the load cannot hang.
    #[cfg(unix)]
    {
        fs::write(&manifest, "blobs:\n  - name: z\n    path: /dev/zero\n").unwrap();
        let err = blob::load(&manifest).unwrap_err();
        assert!(matches!(err, BlobError::NotAFile { .. }), "{err}");
    }
}

#[test]
fn blob_path_may_climb_out_of_the_manifest_directory() {
    // Relative paths are joined to the manifest's directory and may use `..`.
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("radio.bin"), b"radio").unwrap();
    fs::create_dir(tmp.path().join("sub")).unwrap();
    let manifest = tmp.path().join("sub/m.yaml");
    fs::write(
        &manifest,
        "blobs:\n  - name: radio\n    version: '1'\n    supplier: Vendor\n    path: ../radio.bin\n",
    )
    .unwrap();
    let ingest = blob::load(&manifest).unwrap();
    assert_eq!(ingest.images.len(), 1);
    assert!(ingest.warnings.is_empty(), "{:?}", ingest.warnings);
}
