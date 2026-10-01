//! Blob manifests: hashing, recognisers, the opaque note, and malformed input.
//!
//! The inputs are the hand-written files in `tests/data/blobs/` (see `tests/data/README.md`),
//! not real-build fixtures. `tests/golden/blobs.cdx.json` is generated only by
//! `scripts/regen-golden.sh`, which runs this test with `ROLLCALL_BLESS=1`.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::{GOLDEN_TIMESTAMP, blob_product};
use rollcall_core::blob::{self, BlobEntry, BlobError};
use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions, validate_cyclonedx_1_6};
use rollcall_core::merge;
use rollcall_core::model::{BomRef, PathSegment};
use rollcall_core::model::{
    EvidenceField, HashAlgorithm, Image, ImageKind, ImageType, Product, Technique,
};
use rollcall_core::zephyr::{self, IngestOptions};
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
    common::blobs_manifest()
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
        .images()
        .find(|i| i.name == "s140_nrf52_softdevice")
        .unwrap();
    assert_eq!(sha256(softdevice), FAKE_SOFTDEVICE_SHA256);
    let libphy = ingest.images().find(|i| i.name == "libphy").unwrap();
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
    assert_eq!(sha256(&ingest.blobs[0].image), expected);
}

#[test]
fn blob_image_carries_sha256_supplier_and_opaque_property() {
    let ingest = blob::load(&manifest()).unwrap();
    assert_eq!(ingest.blobs.len(), 2);
    let softdevice = &ingest.blobs[0].image;
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
    let libphy = &ingest.blobs[1].image;
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
    assert!(matches!(load("bad-kind.yaml"), BlobError::Yaml(m) if m.contains("bogus")));
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
    assert_eq!(ingest.blobs.len(), 1);
    assert!(ingest.warnings.is_empty(), "{:?}", ingest.warnings);
}

#[test]
fn static_archive_blob_is_library_and_softdevice_is_firmware() {
    // In the model: the recogniser (and the `.a` extension) make libphy a library; the
    // SoftDevice `.hex` stays firmware.
    let product = blob_product();
    let type_of = |name: &str| {
        product
            .images
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.image_type)
            .unwrap()
    };
    assert_eq!(type_of("libphy"), ImageType::Library);
    assert_eq!(type_of("s140_nrf52_softdevice"), ImageType::Firmware);

    // In CycloneDX: the component `type`, in a schema-valid document; the product root
    // stays firmware.
    let doc: Value = serde_json::from_str(&render(&product)).unwrap();
    validate_cyclonedx_1_6(&doc).unwrap();
    assert_eq!(doc["metadata"]["component"]["type"], "firmware");
    let images = doc["components"].as_array().unwrap();
    let doc_type = |name: &str| {
        images
            .iter()
            .find(|i| i["name"] == name)
            .map(|i| i["type"].clone())
            .unwrap()
    };
    assert_eq!(doc_type("libphy"), "library");
    assert_eq!(doc_type("s140_nrf52_softdevice"), "firmware");
}

/// Writes `files` (each a few bytes) and a manifest with `body` into a temporary directory
/// and loads it.
fn load_with(body: &str, files: &[&str]) -> Result<blob::BlobIngest, BlobError> {
    let tmp = tempfile::tempdir().unwrap();
    for file in files {
        fs::write(tmp.path().join(file), b"blob").unwrap();
    }
    let manifest = tmp.path().join("m.yaml");
    fs::write(&manifest, body).unwrap();
    blob::load(&manifest)
}

#[test]
fn manifest_kind_library_firmware_and_bogus() {
    // `kind: firmware` on libphy.a overrides both the recogniser and the `.a` extension.
    let ingest = load_with(
        "blobs:\n  - path: libphy.a\n    version: '1'\n    kind: firmware\n",
        &["libphy.a"],
    )
    .unwrap();
    assert_eq!(ingest.blobs[0].image.name, "libphy");
    assert_eq!(ingest.blobs[0].image.image_type, ImageType::Firmware);

    // `kind: library` on radio.bin overrides the `.bin` extension.
    let ingest = load_with(
        "blobs:\n  - name: radio\n    version: '1'\n    supplier: V\n    path: radio.bin\n    \
         kind: library\n",
        &["radio.bin"],
    )
    .unwrap();
    assert_eq!(ingest.blobs[0].image.image_type, ImageType::Library);
    // Without `kind`, the same file is firmware by its extension.
    let ingest = load_with(
        "blobs:\n  - name: radio\n    version: '1'\n    supplier: V\n    path: radio.bin\n",
        &["radio.bin"],
    )
    .unwrap();
    assert_eq!(ingest.blobs[0].image.image_type, ImageType::Firmware);

    // `kind: bogus` is a manifest error naming the value, from the committed bad manifest
    // and from a generated one.
    let err = blob::load(&blobs_dir().join("bad-kind.yaml")).unwrap_err();
    assert!(
        matches!(&err, BlobError::Yaml(m) if m.contains("bogus")),
        "{err}"
    );
    assert!(!err.is_read_error(), "{err}");
    let err = load_with(
        "blobs:\n  - name: radio\n    path: radio.bin\n    kind: bogus\n",
        &["radio.bin"],
    )
    .unwrap_err();
    assert!(
        matches!(&err, BlobError::Yaml(m) if m.contains("bogus")),
        "{err}"
    );
}

#[test]
fn blob_type_falls_back_to_extension_then_firmware() {
    let entry = |path: &str| BlobEntry {
        name: Some("x".to_owned()),
        version: None,
        supplier: None,
        path: path.to_owned(),
        licence: None,
        purl: None,
        kind: None,
        image: None,
    };
    // No manifest kind, no recogniser: the extension decides.
    for (file, expected) in [
        ("vendor.a", ImageType::Library),
        ("vendor.LIB", ImageType::Library),
        ("vendor.o", ImageType::Library),
        ("vendor.hex", ImageType::Firmware),
        ("vendor.bin", ImageType::Firmware),
        ("vendor.elf", ImageType::Firmware),
        // No extension that means anything: firmware.
        ("vendor.so", ImageType::Firmware),
        ("vendor", ImageType::Firmware),
        ("", ImageType::Firmware),
    ] {
        assert_eq!(
            blob::blob_type(&entry(file), None, file),
            expected,
            "{file:?}"
        );
    }
    // A recogniser beats the extension; the manifest beats both.
    let recognised = blob::recognise("libphy.a").unwrap();
    assert_eq!(
        blob::blob_type(&entry("libphy.hex"), Some(&recognised), "libphy.hex"),
        ImageType::Library
    );
    let mut explicit = entry("libphy.a");
    explicit.kind = Some(ImageType::Firmware);
    assert_eq!(
        blob::blob_type(&explicit, Some(&recognised), "libphy.a"),
        ImageType::Firmware
    );

    // End to end through `load`: an unrecognised `.a` is a library, an unknown extension
    // firmware.
    let ingest = load_with(
        "blobs:\n  - name: vendor\n    path: vendor.a\n  - name: other\n    path: other.dat\n",
        &["vendor.a", "other.dat"],
    )
    .unwrap();
    assert_eq!(ingest.blobs[0].image.image_type, ImageType::Library);
    assert_eq!(ingest.blobs[1].image.image_type, ImageType::Firmware);
}

/// The `bom-ref` of the image `name` of `product`.
fn image_ref(product: &Product, name: &str) -> BomRef {
    let image = product.images.iter().find(|i| i.name == name).unwrap();
    BomRef::derive(&product.path().child(PathSegment::of_image(image)))
}

/// A manifest entry's `image:` attaches the blob to that image: the blob is a dependency of
/// the named image (here the real `bt/beacon` application), not of the product root.
#[test]
fn manifest_image_attaches_blob_to_the_named_image() {
    let app = zephyr::ingest(&IngestOptions::new(fixtures_root().join("bt/beacon"))).unwrap();
    let ingest = load_with(
        "blobs:\n  - path: libsoftdevice_controller_multirole.a\n    name: softdevice_controller\n    version: 6.1.0\n    supplier: Nordic Semiconductor ASA\n    image: beacon\n  - path: libphy.a\n    name: libphy\n    version: 1.0.0\n    supplier: Espressif Systems\n",
        &["libsoftdevice_controller_multirole.a", "libphy.a"],
    )
    .unwrap();
    let owners: Vec<Option<&str>> = ingest.blobs.iter().map(|b| b.owner.as_deref()).collect();
    assert_eq!(owners, [Some("beacon"), None]);
    let spec: merge::ProductSpec = "widget@1.0.0".parse().unwrap();
    let mut product = merge::merge(vec![app.product], Some(&spec)).unwrap();
    merge::attach_blobs(&mut product, ingest.blobs).unwrap();

    let root = BomRef::derive(&product.path());
    let beacon = image_ref(&product, "beacon");
    let controller = image_ref(&product, "softdevice_controller");
    let libphy = image_ref(&product, "libphy");
    let deps = |from: &BomRef| product.dependencies.get(from).cloned().unwrap_or_default();
    assert!(deps(&beacon).contains(&controller));
    assert!(!deps(&root).contains(&controller));
    // Without `image:`, the product root.
    assert!(deps(&root).contains(&libphy));
    assert!(!deps(&beacon).contains(&libphy));
    // The blob is still an image of its own, of kind blob, and the document validates.
    let image = product
        .images
        .iter()
        .find(|i| i.name == "softdevice_controller")
        .unwrap();
    assert_eq!(image.kind, ImageKind::Blob);
    assert_eq!(image.image_type, ImageType::Library);
    let doc: Value = serde_json::from_str(&render(&product)).unwrap();
    validate_cyclonedx_1_6(&doc).unwrap();
    // add_blobs is attach_blobs with no owners.
    let mut a = merge::merge(Vec::new(), Some(&spec)).unwrap();
    let mut b = a.clone();
    let blobs = load_with(
        "blobs:\n  - path: libphy.a\n    name: libphy\n",
        &["libphy.a"],
    )
    .unwrap()
    .blobs;
    assert_eq!(blobs[0].owner, None);
    merge::add_blobs(&mut a, blobs.iter().map(|b| b.image.clone()).collect()).unwrap();
    merge::attach_blobs(&mut b, blobs).unwrap();
    assert_eq!(a, b);
}

#[test]
fn manifest_image_naming_no_image_or_an_ambiguous_one_is_an_error() {
    let ingest = load_with(
        "blobs:\n  - path: libphy.a\n    name: libphy\n    image: nope\n",
        &["libphy.a"],
    )
    .unwrap();
    let spec: merge::ProductSpec = "widget@1.0.0".parse().unwrap();
    let mut product = merge::merge(Vec::new(), Some(&spec)).unwrap();
    product
        .add_image(Image::new(ImageKind::Application, "app").unwrap())
        .unwrap();
    product
        .add_image(Image::new(ImageKind::Bootloader, "app").unwrap())
        .unwrap();
    let before = product.clone();
    let blobs = ingest.blobs;
    let err = merge::attach_blobs(&mut product, blobs.clone()).unwrap_err();
    assert_eq!(
        err.to_string(),
        "blob libphy: the product has no image named \"nope\" to attach it to"
    );
    // Atomic: unchanged on error.
    assert_eq!(product, before);
    let ambiguous = blobs
        .into_iter()
        .map(|b| blob::BlobImage {
            owner: Some("app".to_owned()),
            ..b
        })
        .collect();
    let err = merge::attach_blobs(&mut product, ambiguous).unwrap_err();
    assert!(
        matches!(&err, merge::Error::AmbiguousImage { blob, image } if blob == "libphy" && image == "app"),
        "{err}"
    );
    assert_eq!(product, before);
    // A blob image is not a target: naming another blob is no image.
    let first = load_with(
        "blobs:\n  - path: libphy.a\n    name: libphy\n",
        &["libphy.a"],
    )
    .unwrap();
    merge::add_blobs(&mut product, first.into_images()).unwrap();
    let second = load_with(
        "blobs:\n  - path: x.a\n    name: x\n    image: libphy\n",
        &["x.a"],
    )
    .unwrap();
    let err = merge::attach_blobs(&mut product, second.blobs).unwrap_err();
    assert!(matches!(err, merge::Error::NoSuchImage { .. }), "{err}");
}
