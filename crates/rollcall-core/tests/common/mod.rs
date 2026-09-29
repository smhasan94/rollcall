//! Shared helpers for the model integration tests.
//!
//! The model built here, and the `tests/data/*.model.json` files, are hand-written *model*
//! fixtures for these tests; they are not real-build fixtures and do not live under
//! `fixtures/`.

#![allow(dead_code)]

use std::path::PathBuf;

use proptest::prelude::*;
use proptest::sample::select;
use rollcall_core::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, Hash,
    HashAlgorithm, Image, ImageKind, License, Occurrence, PathSegment, Product, Purl, Supplier,
    Technique,
};

/// The fixed `--timestamp` the CycloneDX golden files are rendered with.
pub const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

/// `tests/data/<name>.model.json`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(format!("{name}.model.json"))
}

/// Reads and parses (with validation) `tests/data/<name>.model.json`.
pub fn load_fixture(name: &str) -> Product {
    let path = fixture_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    Product::from_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The names of every `tests/data/*.model.json` fixture (without the suffix), sorted.
pub fn fixture_names() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter_map(|file| file.strip_suffix(".model.json").map(str::to_owned))
        .collect();
    names.sort();
    names
}

fn confidence(bp: u16) -> Confidence {
    Confidence::new(bp).unwrap()
}

fn evidence(
    field: EvidenceField,
    technique: Technique,
    source: &str,
    value: &str,
    bp: u16,
) -> Evidence {
    Evidence::new(field, technique, source, value, confidence(bp)).unwrap()
}

fn lib(name: &str, version: &str) -> Component {
    Component::new(ComponentKind::Library, name)
        .unwrap()
        .with_version(version)
}

/// The base product: three images, six components plus one nested subcomponent, one
/// component seen by two sources, and three dependency edges.
pub fn base_product() -> Product {
    let mut product = Product::new("widget").unwrap().with_version("1.0.0");
    product.supplier = Some(
        Supplier::new("Example Devices Ltd")
            .unwrap()
            .with_url("https://devices.example")
            .unwrap(),
    );

    // Bootloader: MCUboot with its own copy of mbedtls.
    let mut boot = Image::new(ImageKind::Bootloader, "mcuboot")
        .unwrap()
        .with_version("2.1.0");
    boot.hashes
        .insert(Hash::new(HashAlgorithm::Sha256, &"b0".repeat(32)).unwrap());
    let mut boot_mbedtls = lib("mbedtls", "3.6.0");
    boot_mbedtls.evidence.insert(evidence(
        EvidenceField::Version,
        Technique::ManifestAnalysis,
        "mcuboot-sysbuild",
        "3.6.0",
        8000,
    ));
    boot.add_component(boot_mbedtls).unwrap();
    boot.add_component(lib("tinycrypt", "0.2.8")).unwrap();

    // Application: Zephyr with a kernel subcomponent, CMSIS, and mbedtls from two sources.
    let mut app = Image::new(ImageKind::Application, "widget-app")
        .unwrap()
        .with_version("1.0.0");
    app.licence = Some(License::new("LicenseRef-proprietary").unwrap());

    let mut zephyr = Component::new(ComponentKind::OperatingSystem, "zephyr")
        .unwrap()
        .with_version("3.7.0");
    zephyr.purl = Some(Purl::new("pkg:github/zephyrproject-rtos/zephyr@v3.7.0").unwrap());
    zephyr.cpe = Some(Cpe::new("cpe:2.3:o:zephyrproject:zephyr:3.7.0:*:*:*:*:*:*:*").unwrap());
    zephyr.licence = Some(License::new("Apache-2.0").unwrap());
    let mut kernel = Component::new(ComponentKind::Library, "kernel").unwrap();
    kernel.evidence.insert(evidence(
        EvidenceField::Name,
        Technique::ManifestAnalysis,
        "west-spdx",
        "kernel",
        9000,
    ));
    zephyr.add_component(kernel).unwrap();
    app.add_component(zephyr).unwrap();

    let mut cmsis = lib("cmsis", "5.9.0");
    cmsis.purl = Some(Purl::new("pkg:github/zephyrproject-rtos/cmsis@5.9.0").unwrap());
    app.add_component(cmsis).unwrap();

    let mut mbedtls_spdx = lib("mbedtls", "3.6.0");
    mbedtls_spdx.purl = Some(Purl::new("pkg:github/Mbed-TLS/mbedtls@v3.6.0").unwrap());
    mbedtls_spdx.evidence.insert(
        evidence(
            EvidenceField::Purl,
            Technique::ManifestAnalysis,
            "west-spdx",
            "pkg:github/Mbed-TLS/mbedtls@v3.6.0",
            9000,
        )
        .at(Occurrence::new("build/spdx/app.spdx", Some(120)).unwrap()),
    );
    let mut mbedtls_list = lib("mbedtls", "3.6.0");
    mbedtls_list.licence = Some(License::new("Apache-2.0 OR GPL-2.0-or-later").unwrap());
    mbedtls_list.evidence.insert(evidence(
        EvidenceField::Licence,
        Technique::SourceCodeAnalysis,
        "west-list",
        "Apache-2.0 OR GPL-2.0-or-later",
        6000,
    ));
    app.add_component(mbedtls_spdx).unwrap();
    app.add_component(mbedtls_list).unwrap();

    // Blob: prebuilt radio firmware.
    let mut radio = Image::new(ImageKind::Blob, "radio-fw").unwrap();
    let mut controller = Component::new(ComponentKind::Firmware, "sdc").unwrap();
    controller
        .hashes
        .insert(Hash::new(HashAlgorithm::Sha1, &"5d".repeat(20)).unwrap());
    radio.add_component(controller).unwrap();

    product.add_image(boot).unwrap();
    product.add_image(app).unwrap();
    product.add_image(radio).unwrap();

    // Dependency edges: product -> app image -> zephyr -> mbedtls.
    let root = product.path();
    let app_path = root.child(PathSegment::of_image(
        &Image::new(ImageKind::Application, "widget-app")
            .unwrap()
            .with_version("1.0.0"),
    ));
    let zephyr_path = app_path.child(PathSegment::of_component(
        &Component::new(ComponentKind::OperatingSystem, "zephyr")
            .unwrap()
            .with_version("3.7.0"),
    ));
    let mbedtls_path = app_path.child(PathSegment::of_component(&lib("mbedtls", "3.6.0")));
    product.add_dependency(BomRef::derive(&root), BomRef::derive(&app_path));
    product.add_dependency(BomRef::derive(&app_path), BomRef::derive(&zephyr_path));
    product.add_dependency(BomRef::derive(&zephyr_path), BomRef::derive(&mbedtls_path));

    product.validate().unwrap();
    product
}

/// A component that sorts strictly between two existing application components
/// (`cmsis` < `littlefs` < `mbedtls`).
pub fn extra_component() -> Component {
    let mut littlefs = lib("littlefs", "2.9.0");
    littlefs.purl = Some(Purl::new("pkg:github/littlefs-project/littlefs@v2.9.0").unwrap());
    littlefs.licence = Some(License::new("BSD-3-Clause").unwrap());
    littlefs
        .hashes
        .insert(Hash::new(HashAlgorithm::Sha256, &"1f".repeat(32)).unwrap());
    littlefs.evidence.insert(evidence(
        EvidenceField::Version,
        Technique::ManifestAnalysis,
        "west-spdx",
        "2.9.0",
        9500,
    ));
    littlefs
}

/// A component that sorts after all of its application siblings (`data` sorts after
/// `operating-system`).
pub fn last_component() -> Component {
    let mut dts = Component::new(ComponentKind::Data, "devicetree").unwrap();
    dts.evidence.insert(evidence(
        EvidenceField::Name,
        Technique::Filename,
        "build-dir",
        "zephyr.dts",
        7000,
    ));
    dts
}

/// `base_product()` with `component` added to the application image.
pub fn base_plus(component: Component) -> Product {
    let mut product = base_product();
    let mut app = Image::new(ImageKind::Application, "widget-app")
        .unwrap()
        .with_version("1.0.0");
    app.add_component(component).unwrap();
    product.add_image(app).unwrap();
    product
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A line diff of `other` against `base` from their longest common prefix and suffix of lines:
/// returns the lines removed from `base` and the lines inserted in `other`.
///
/// A pure insertion can often be placed at several equivalent positions (for example a JSON
/// object inserted between two siblings matches equally well one line earlier or later). The
/// insertion is slid up through the equivalent positions to the one whose first line is least
/// indented, the latest such position winning a tie, so the hunk lines up with whole
/// structural blocks.
pub fn line_diff(base: &str, other: &str) -> (Vec<String>, Vec<String>) {
    let a: Vec<&str> = base.lines().collect();
    let b: Vec<&str> = other.lines().collect();
    let max = a.len().min(b.len());
    let mut prefix = 0;
    while prefix < max && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < max - prefix && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix] {
        suffix += 1;
    }
    let removed_len = a.len() - prefix - suffix;
    let inserted_len = b.len() - prefix - suffix;

    let mut start = prefix;
    if removed_len == 0 && inserted_len > 0 {
        let mut best_indent = indent(b[start]);
        let mut candidate = prefix;
        while candidate > 0 && b[candidate - 1] == b[candidate - 1 + inserted_len] {
            candidate -= 1;
            if indent(b[candidate]) < best_indent {
                best_indent = indent(b[candidate]);
                start = candidate;
            }
        }
    }

    let removed = a[prefix..prefix + removed_len]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let inserted = b[start..start + inserted_len]
        .iter()
        .map(|s| s.to_string())
        .collect();
    (removed, inserted)
}

/// Removes the common leading-space indentation of `lines`.
pub fn dedent(lines: &[String]) -> Vec<String> {
    let min = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| indent(l))
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| l[min.min(l.len())..].to_string())
        .collect()
}

// Proptest strategies for random products, shared by `props.rs` and `cyclonedx.rs`.

pub const NAMES: &[&str] = &["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
pub const SUB_NAMES: &[&str] = &["core", "net", "fs", "usb"];
pub const VERSIONS: &[Option<&str>] = &[None, Some("1.0"), Some("2.0")];
pub const KINDS: &[ComponentKind] = &[
    ComponentKind::Library,
    ComponentKind::OperatingSystem,
    ComponentKind::Firmware,
];
pub const IMAGES: &[(ImageKind, &str)] = &[
    (ImageKind::Bootloader, "mcuboot"),
    (ImageKind::Application, "app"),
    (ImageKind::Blob, "radio"),
];
pub const ALGORITHMS: &[HashAlgorithm] = &[
    HashAlgorithm::Md5,
    HashAlgorithm::Sha1,
    HashAlgorithm::Sha256,
];
pub const LICENCES: &[&str] = &["MIT", "Apache-2.0", "BSD-3-Clause OR MIT"];

/// A digest that depends only on the component identity and algorithm, so that two copies
/// of the same component never conflict whichever facts each carries.
pub fn digest_for(
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

pub fn arb_evidence() -> impl Strategy<Value = Evidence> {
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
pub fn arb_facts(
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

pub fn arb_leaf() -> impl Strategy<Value = Component> {
    (
        select(KINDS.to_vec()),
        select(SUB_NAMES.to_vec()),
        select(VERSIONS.to_vec()),
    )
        .prop_flat_map(|(kind, name, version)| arb_facts(kind, name, version))
}

/// A component and the subcomponents to add to it (not yet added, so that tests can vary the
/// order they are added in).
pub type Entry = (usize, Component, Vec<Component>);

pub fn arb_component() -> impl Strategy<Value = (Component, Vec<Component>)> {
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
}

/// (image index, component, subcomponents) entries: up to 3 images, up to 12 components per
/// image and up to 3 subcomponents per component.
pub fn arb_entries() -> impl Strategy<Value = Vec<Entry>> {
    proptest::collection::vec(proptest::collection::vec(arb_component(), 0..=12), 1..=3).prop_map(
        |images| {
            images
                .into_iter()
                .enumerate()
                .flat_map(|(i, cs)| cs.into_iter().map(move |(c, subs)| (i, c, subs)))
                .collect()
        },
    )
}

/// The same entries with both the component order and each component's subcomponent order
/// shuffled.
pub fn shuffled(entries: Vec<Entry>) -> impl Strategy<Value = Vec<Entry>> {
    entries
        .into_iter()
        .map(|(image, component, subs)| (Just(image), Just(component), Just(subs).prop_shuffle()))
        .collect::<Vec<_>>()
        .prop_shuffle()
}

pub fn build(entries: &[Entry]) -> Product {
    let mut product = Product::new("prop").unwrap();
    for (image, component, subs) in entries {
        let (kind, name) = IMAGES[*image];
        let mut component = component.clone();
        for sub in subs {
            component.add_component(sub.clone()).unwrap();
        }
        let mut img = Image::new(kind, name).unwrap();
        img.add_component(component).unwrap();
        product.add_image(img).unwrap();
    }
    product
}
