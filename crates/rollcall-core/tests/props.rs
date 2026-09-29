//! Property tests: deterministic serialisation, order-independent merging, round trips, and
//! a parser that never panics.

mod common;

use proptest::prelude::*;
use proptest::sample::select;
use rollcall_core::model::{
    Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, EvidenceSet, Hash,
    HashAlgorithm, Image, ImageKind, License, Product, Purl, Technique,
};

const NAMES: &[&str] = &["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
const SUB_NAMES: &[&str] = &["core", "net", "fs", "usb"];
const VERSIONS: &[Option<&str>] = &[None, Some("1.0"), Some("2.0")];
const KINDS: &[ComponentKind] = &[
    ComponentKind::Library,
    ComponentKind::OperatingSystem,
    ComponentKind::Firmware,
];
const IMAGES: &[(ImageKind, &str)] = &[
    (ImageKind::Bootloader, "mcuboot"),
    (ImageKind::Application, "app"),
    (ImageKind::Blob, "radio"),
];
const ALGORITHMS: &[HashAlgorithm] = &[
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
];
const LICENCES: &[&str] = &["MIT", "Apache-2.0", "BSD-3-Clause OR MIT"];

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        // Keep generated regression files out of the repository.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// A digest that depends only on the component identity and algorithm, so that two copies
/// of the same component never conflict whichever facts each carries.
fn digest_for(
    kind: ComponentKind,
    name: &str,
    version: Option<&str>,
    algorithm: HashAlgorithm,
) -> String {
    let seed = format!("{kind}{name}{version:?}{algorithm}");
    let sum: usize = seed.bytes().map(usize::from).sum();
    let nibble = char::from(b"0123456789abcdef"[sum % 16]);
    std::iter::repeat_n(nibble, algorithm.digest_len_hex()).collect()
}

fn arb_evidence() -> impl Strategy<Value = Evidence> {
    (
        select(vec![
            EvidenceField::Name,
            EvidenceField::Version,
            EvidenceField::Licence,
        ]),
        select(vec![Technique::ManifestAnalysis, Technique::BinaryAnalysis]),
        select(vec!["west-spdx", "west-list", "kconfig"]),
        select(vec!["1.0", "MIT"]),
        0u16..=10_000,
    )
        .prop_map(|(field, technique, source, value, bp)| {
            Evidence::new(
                field,
                technique,
                source,
                value,
                Confidence::new(bp).unwrap(),
            )
            .unwrap()
        })
}

/// Facts for a component, each present or absent at random but with values fixed by the
/// component's identity, so merges in any order agree.
fn arb_facts(
    kind: ComponentKind,
    name: &'static str,
    version: Option<&'static str>,
) -> impl Strategy<Value = Component> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        proptest::sample::subsequence(ALGORITHMS.to_vec(), 0..=ALGORITHMS.len()),
        proptest::collection::vec(arb_evidence(), 0..=4),
    )
        .prop_map(move |(licence, purl, cpe, algorithms, evidence)| {
            let mut c = Component::new(kind, name).unwrap();
            c.version = version.map(str::to_owned);
            let index = NAMES
                .iter()
                .chain(SUB_NAMES)
                .position(|n| *n == name)
                .unwrap_or(0);
            if licence {
                c.licence = Some(License::new(LICENCES[index % LICENCES.len()]).unwrap());
            }
            if purl {
                c.purl = Some(
                    Purl::new(&format!("pkg:generic/{name}@{}", version.unwrap_or("0"))).unwrap(),
                );
            }
            if cpe {
                c.cpe = Some(
                    Cpe::new(&format!(
                        "cpe:2.3:a:example:{name}:{}:*:*:*:*:*:*:*",
                        version.unwrap_or("*")
                    ))
                    .unwrap(),
                );
            }
            for algorithm in algorithms {
                c.hashes.insert(
                    Hash::new(algorithm, &digest_for(kind, name, version, algorithm)).unwrap(),
                );
            }
            c.evidence = evidence.into_iter().collect();
            c
        })
}

fn arb_leaf() -> impl Strategy<Value = Component> {
    (
        select(KINDS.to_vec()),
        select(SUB_NAMES.to_vec()),
        select(VERSIONS.to_vec()),
    )
        .prop_flat_map(|(kind, name, version)| arb_facts(kind, name, version))
}

fn arb_component() -> impl Strategy<Value = Component> {
    (
        select(KINDS.to_vec()),
        select(NAMES.to_vec()),
        select(VERSIONS.to_vec()),
    )
        .prop_flat_map(|(kind, name, version)| {
            (
                arb_facts(kind, name, version),
                proptest::collection::vec(arb_leaf(), 0..=3),
            )
        })
        .prop_map(|(mut c, subs)| {
            for sub in subs {
                c.add_component(sub).unwrap();
            }
            c
        })
}

/// (image index, component) entries: up to 3 images and up to 12 components per image.
fn arb_entries() -> impl Strategy<Value = Vec<(usize, Component)>> {
    proptest::collection::vec(proptest::collection::vec(arb_component(), 0..=12), 1..=3).prop_map(
        |images| {
            images
                .into_iter()
                .enumerate()
                .flat_map(|(i, cs)| cs.into_iter().map(move |c| (i, c)))
                .collect()
        },
    )
}

fn build(entries: &[(usize, Component)]) -> Product {
    let mut product = Product::new("prop").unwrap();
    for (image, component) in entries {
        let (kind, name) = IMAGES[*image];
        let mut img = Image::new(kind, name).unwrap();
        img.add_component(component.clone()).unwrap();
        product.add_image(img).unwrap();
    }
    product
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn serialisation_is_independent_of_insertion_order(
        (entries, shuffled) in arb_entries()
            .prop_flat_map(|e| (Just(e.clone()), Just(e).prop_shuffle()))
    ) {
        let a = build(&entries);
        let b = build(&shuffled);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
        prop_assert!(a.validate().is_ok());
    }

    #[test]
    fn evidence_merge_is_order_independent(
        (items, shuffled) in proptest::collection::vec(arb_evidence(), 0..=12)
            .prop_flat_map(|e| (Just(e.clone()), Just(e).prop_shuffle()))
    ) {
        let a: EvidenceSet = items.iter().cloned().collect();
        let b: EvidenceSet = shuffled.iter().cloned().collect();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());

        // Merging two components carrying halves of the evidence, either way round, agrees.
        let (left, right) = items.split_at(items.len() / 2);
        let component = |ev: &[Evidence]| {
            let mut c = Component::new(ComponentKind::Library, "x").unwrap();
            c.evidence = ev.iter().cloned().collect();
            c
        };
        let mut lr = component(left);
        lr.merge(component(right)).unwrap();
        let mut rl = component(right);
        rl.merge(component(left)).unwrap();
        prop_assert_eq!(&lr.evidence, &a);
        prop_assert_eq!(&rl.evidence, &a);
    }

    #[test]
    fn json_round_trip_holds_for_random_products(
        entries in arb_entries(),
        edges in proptest::collection::vec((any::<usize>(), any::<usize>()), 0..=4),
    ) {
        let mut product = build(&entries);
        let refs: Vec<_> = product.walk().map(|(_, r, _)| r).collect();
        for (from, to) in edges {
            product.add_dependency(refs[from % refs.len()].clone(), refs[to % refs.len()].clone());
        }
        let json = product.to_json().unwrap();
        let back = Product::from_json(&json).unwrap();
        prop_assert_eq!(&back, &product);
        prop_assert_eq!(back.to_json().unwrap(), json);
    }

    #[test]
    fn random_bytes_never_panic_parser(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512),
        position in any::<usize>(),
        byte in any::<u8>(),
        cut in any::<bool>(),
    ) {
        // Arbitrary bytes.
        let _ = Product::from_json_bytes(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let _ = Product::from_json(&text);
        let _ = Purl::new(&text);
        let _ = Cpe::new(&text);
        let _ = License::new(&text);

        // A valid document with one byte changed, or cut short.
        let mut base = common::base_product().to_json().unwrap().into_bytes();
        let at = position % base.len();
        if cut {
            base.truncate(at);
        } else {
            base[at] = byte;
        }
        let _ = Product::from_json_bytes(&base);
    }
}
