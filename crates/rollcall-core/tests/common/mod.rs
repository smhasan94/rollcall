//! Shared helpers for the model integration tests.
//!
//! The model built here is a hand-written *model* fixture, built in code for these tests; it
//! is not a real-build fixture and does not live under `fixtures/`.

#![allow(dead_code)]

use rollcall_core::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, Hash,
    HashAlgorithm, Image, ImageKind, License, Occurrence, PathSegment, Product, Purl, Supplier,
    Technique,
};

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
            .with_url("https://devices.example"),
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
