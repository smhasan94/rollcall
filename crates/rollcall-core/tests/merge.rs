//! `merge`: re-parenting, dependency-ref re-derivation, idempotence, order independence and
//! conflicts, on hand-written model products and the real Zephyr fixtures.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use common::{arb_entries, build};
use proptest::prelude::*;
use rollcall_core::merge::{self, ProductSpec, ProductSpecError};
use rollcall_core::model::{
    BomRef, Component, ComponentKind, Image, ImageKind, MergeError, NodeRef, PathSegment, Product,
};
use rollcall_core::zephyr::{self, IngestOptions};

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr"),
    }
}

fn ingest(variant: &str, image: &str) -> Product {
    let root = fixtures_root().join(variant);
    let options = IngestOptions::new(root.join(image)).with_west_list(root.join("west-list.txt"));
    zephyr::ingest(&options).unwrap().product
}

/// A product with one image holding one component, and edges root → image → component.
fn single(product: &str, version: Option<&str>, kind: ImageKind, image: &str) -> Product {
    let mut p = Product::new(product).unwrap();
    p.version = version.map(str::to_owned);
    let mut img = Image::new(kind, image).unwrap();
    let zephyr = Component::new(ComponentKind::OperatingSystem, "zephyr")
        .unwrap()
        .with_version("4.4.2");
    let zephyr_segment = PathSegment::of_component(&zephyr);
    img.add_component(zephyr).unwrap();
    let image_path = p.path().child(PathSegment::of_image(&img));
    p.add_image(img).unwrap();
    p.add_dependency(BomRef::derive(&p.path()), BomRef::derive(&image_path));
    p.add_dependency(
        BomRef::derive(&image_path),
        BomRef::derive(&image_path.child(zephyr_segment)),
    );
    p
}

#[test]
fn product_spec_parses_name_and_optional_version_split_at_last_at() {
    let spec: ProductSpec = "widget@1.2.0".parse().unwrap();
    assert_eq!((spec.name(), spec.version()), ("widget", Some("1.2.0")));
    let spec: ProductSpec = "widget".parse().unwrap();
    assert_eq!((spec.name(), spec.version()), ("widget", None));
    let spec: ProductSpec = "@scope/widget@2".parse().unwrap();
    assert_eq!((spec.name(), spec.version()), ("@scope/widget", Some("2")));
    assert_eq!(spec.to_string(), "@scope/widget@2");
    for bad in ["", "@1.0", " @1.0", "\u{7}x"] {
        assert!(
            matches!(bad.parse::<ProductSpec>(), Err(ProductSpecError::Name(_))),
            "{bad:?}"
        );
    }
    for bad in ["widget@", "widget@ ", "widget@1\n"] {
        assert!(
            matches!(
                bad.parse::<ProductSpec>(),
                Err(ProductSpecError::Version(_))
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn merge_reparents_images_and_rederives_dependency_refs() {
    let app = ingest("baseline", "with_mcuboot");
    let boot = ingest("baseline", "mcuboot");
    let spec: ProductSpec = "widget@1.0.0".parse().unwrap();
    let merged = merge::merge(vec![app.clone(), boot.clone()], Some(&spec)).unwrap();
    merged.validate().unwrap();
    assert_eq!(merged.name, "widget");
    assert_eq!(merged.version.as_deref(), Some("1.0.0"));
    // Root facts and evidence of the inputs are dropped.
    assert!(merged.evidence.is_empty());
    let images: Vec<(ImageKind, &str)> = merged
        .images
        .iter()
        .map(|i| (i.kind, i.name.as_str()))
        .collect();
    assert_eq!(
        images,
        [
            (ImageKind::Bootloader, "mcuboot"),
            (ImageKind::Application, "with_mcuboot")
        ]
    );
    // Each image is carried over unchanged.
    assert!(merged.images.contains(app.images.first().unwrap()));
    assert!(merged.images.contains(boot.images.first().unwrap()));
    // Every edge of every input is present, translated to the new root; nothing else.
    let root = merged.path();
    let mut expected_edges = 0;
    for input in [&app, &boot] {
        for (from, targets) in &input.dependencies {
            let reroot = |r: &BomRef| {
                let (path, _, _) = input.walk().find(|(_, b, _)| b == r).unwrap();
                let mut segments = path.segments().to_vec();
                segments[0] = root.segments()[0].clone();
                BomRef::derive(&rollcall_core::model::NodePath(segments))
            };
            for to in targets {
                expected_edges += 1;
                assert!(
                    merged.dependencies[&reroot(from)].contains(&reroot(to)),
                    "{from} → {to}"
                );
            }
        }
    }
    let actual_edges: usize = merged.dependencies.values().map(BTreeSet::len).sum();
    // The two root → image edges become two edges from the one new root.
    assert_eq!(actual_edges, expected_edges);
    let root_ref = BomRef::derive(&root);
    assert_eq!(merged.dependencies[&root_ref].len(), 2);
    // `zephyr` is present under each image, as two nodes with two refs.
    let zephyr_refs: Vec<BomRef> = merged
        .walk()
        .filter(|(_, _, n)| matches!(n, NodeRef::Component(c) if c.name == "zephyr"))
        .map(|(_, r, _)| r)
        .collect();
    assert_eq!(zephyr_refs.len(), 2);
    assert_ne!(zephyr_refs[0], zephyr_refs[1]);
}

#[test]
fn merge_with_self_is_identity() {
    for (variant, image) in [
        ("baseline", "with_mcuboot"),
        ("baseline", "mcuboot"),
        ("bt", "beacon"),
        ("tls", "http_server"),
    ] {
        let product = ingest(variant, image);
        let merged = merge::merge(vec![product.clone(), product.clone()], None).unwrap();
        assert_eq!(merged, product, "{variant}/{image}");
        assert_eq!(merge::merge(vec![product.clone()], None).unwrap(), product);
    }
    // With a spec, merging a re-parented product with itself changes nothing either.
    let product = ingest("baseline", "with_mcuboot");
    let spec: ProductSpec = "with_mcuboot".parse().unwrap();
    let once = merge::merge(vec![product.clone()], Some(&spec)).unwrap();
    let twice = merge::merge(vec![product.clone(), product], Some(&spec)).unwrap();
    assert_eq!(once, twice);
}

#[test]
fn merge_conflicting_versions_is_error() {
    let a = single("widget", Some("1.0.0"), ImageKind::Application, "app");
    let b = single("widget", Some("2.0.0"), ImageKind::Bootloader, "mcuboot");
    let err = merge::merge(vec![a.clone(), b.clone()], None).unwrap_err();
    let merge::Error::Conflict(MergeError::Conflict {
        field,
        existing,
        incoming,
        ..
    }) = err
    else {
        panic!("{err:?}");
    };
    assert_eq!(field, "version");
    assert!(existing.contains("1.0.0") && incoming.contains("2.0.0"));
    // A different name conflicts too; --product resolves both.
    let c = single("gadget", Some("1.0.0"), ImageKind::Blob, "radio");
    assert!(matches!(
        merge::merge(vec![a.clone(), c.clone()], None),
        Err(merge::Error::Conflict(_))
    ));
    let spec: ProductSpec = "widget@3.0.0".parse().unwrap();
    let merged = merge::merge(vec![a, b, c], Some(&spec)).unwrap();
    assert_eq!(merged.images.len(), 3);
    // Nothing to merge at all.
    assert!(matches!(
        merge::merge(Vec::new(), None),
        Err(merge::Error::NoInputs)
    ));
}

#[test]
fn merge_conflicting_fact_in_shared_image_is_error() {
    let a = single("widget", None, ImageKind::Application, "app");
    let mut b = a.clone();
    let mut image = b.images.pop_first().unwrap();
    image.licence = Some(rollcall_core::model::License::new("MIT").unwrap());
    b.images.insert(image);
    let mut c = a.clone();
    let mut image = c.images.pop_first().unwrap();
    image.licence = Some(rollcall_core::model::License::new("Apache-2.0").unwrap());
    c.images.insert(image);
    assert!(matches!(
        merge::merge(vec![b, c], None),
        Err(merge::Error::Conflict(MergeError::Conflict { .. }))
    ));
}

#[test]
fn add_blobs_adds_images_with_root_edges() {
    let mut product = single("widget", None, ImageKind::Application, "app");
    let radio = Image::new(ImageKind::Blob, "radio").unwrap();
    let radio_ref = BomRef::derive(&product.path().child(PathSegment::of_image(&radio)));
    merge::add_blobs(&mut product, vec![radio]).unwrap();
    assert!(product.dependencies[&BomRef::derive(&product.path())].contains(&radio_ref));
    product.validate().unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn merge_is_order_independent(
        left in arb_entries(),
        right in arb_entries(),
        middle in arb_entries(),
    ) {
        let (a, b, c) = (build(&left), build(&right), build(&middle));
        let abc = merge::merge(vec![a.clone(), b.clone(), c.clone()], None).unwrap();
        let cba = merge::merge(vec![c.clone(), b.clone(), a.clone()], None).unwrap();
        let bac = merge::merge(vec![b.clone(), a.clone(), c.clone()], None).unwrap();
        prop_assert_eq!(&abc, &cba);
        prop_assert_eq!(&abc, &bac);
        let spec: ProductSpec = "prop@1".parse().unwrap();
        let x = merge::merge(vec![a.clone(), b.clone()], Some(&spec)).unwrap();
        let y = merge::merge(vec![b, a], Some(&spec)).unwrap();
        prop_assert_eq!(x, y);
    }
}
