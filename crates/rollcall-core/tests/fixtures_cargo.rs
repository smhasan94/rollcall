//! Checks on the Cargo build fixtures (see `docs/fixtures.md`): `fixtures/cargo-keelsign/`
//! (keelsign's `examples/nrf52840-hello`), `fixtures/cargo-deps/` and
//! `fixtures/cargo-old-heapless/` (the hand-written projects under `scripts/fixture-src/`),
//! each a real `cargo auditable` build for thumbv7em-none-eabihf.
//!
//! The fixtures are produced only by `scripts/regen-fixtures-cargo.sh`; these tests check that
//! each committed tree is what its `MANIFEST.json` says it is, that it records the script's
//! pins, that no build-machine path is left in it, and that its ELF carries the `.dep-v0`
//! list `rust-audit-info` printed.
//!
//! `ROLLCALL_CARGO_FIXTURES_DIR` points the tests at one other tree (its variant follows from
//! its manifest); the script uses it to test a staged tree before installing it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rollcall_core::cargo::{auditable, metadata};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// (variant, root package).
const VARIANTS: [(&str, &str); 3] = [
    ("cargo-keelsign", "nrf52840-hello"),
    ("cargo-deps", "rollcall-cargo-deps"),
    ("cargo-old-heapless", "rollcall-cargo-old-heapless"),
];

const FILES: [&str; 6] = [
    "MANIFEST.json",
    "cargo-metadata.all.json",
    "cargo-metadata.json",
    "cargo-tree.txt",
    "dep-v0.json",
    "firmware.elf",
];

const MAX_TREE_BYTES: u64 = 5_000_000;

struct Tree {
    root: PathBuf,
    variant: &'static str,
    package: &'static str,
}

impl Tree {
    fn manifest(&self) -> Value {
        let path = self.root.join("MANIFEST.json");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn read(&self, name: &str) -> Vec<u8> {
        let path = self.root.join(name);
        fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn trees() -> Vec<Tree> {
    match std::env::var_os("ROLLCALL_CARGO_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => {
            let root = PathBuf::from(dir);
            let text = fs::read_to_string(root.join("MANIFEST.json")).unwrap();
            let manifest: Value = serde_json::from_str(&text).unwrap();
            let variant = manifest["variant"].as_str().unwrap_or_default().to_owned();
            let (variant, package) = VARIANTS
                .into_iter()
                .find(|(v, _)| *v == variant)
                .unwrap_or_else(|| panic!("unknown cargo fixture variant {variant:?}"));
            vec![Tree {
                root,
                variant,
                package,
            }]
        }
        _ => VARIANTS
            .into_iter()
            .map(|(variant, package)| Tree {
                root: repo_root().join("fixtures").join(variant),
                variant,
                package,
            })
            .collect(),
    }
}

/// A `NAME=value` assignment in `scripts/regen-fixtures-cargo.sh`.
fn script_pin(name: &str) -> String {
    let script = fs::read_to_string(repo_root().join("scripts/regen-fixtures-cargo.sh")).unwrap();
    script
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name}= in regen-fixtures-cargo.sh"))
        .trim()
        .to_owned()
}

#[test]
fn every_tree_holds_exactly_the_expected_files() {
    for tree in trees() {
        let mut names: Vec<String> = fs::read_dir(&tree.root)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", tree.root.display()))
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, FILES, "{}", tree.variant);
    }
}

#[test]
fn manifest_lists_every_file_with_its_size_and_sha256() {
    for tree in trees() {
        let manifest = tree.manifest();
        let files = manifest["files"].as_array().unwrap();
        let listed: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
        let expected: Vec<&str> = FILES
            .iter()
            .copied()
            .filter(|f| *f != "MANIFEST.json")
            .collect();
        assert_eq!(listed, expected, "{}", tree.variant);
        let mut total = 0;
        for f in files {
            let name = f["path"].as_str().unwrap();
            let bytes = tree.read(name);
            let digest: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(f["sha256"].as_str(), Some(digest.as_str()), "{name}");
            assert_eq!(f["bytes"].as_u64(), Some(bytes.len() as u64), "{name}");
            total += bytes.len() as u64;
        }
        assert_eq!(manifest["total_bytes"].as_u64(), Some(total));
        assert!(total <= MAX_TREE_BYTES, "{} is {total} bytes", tree.variant);
    }
}

#[test]
fn manifest_records_the_script_pins() {
    for tree in trees() {
        let m = tree.manifest();
        assert_eq!(m["format"], "rollcall-fixtures/1");
        assert_eq!(m["generator"], "scripts/regen-fixtures-cargo.sh");
        assert_eq!(m["ecosystem"], "cargo");
        assert_eq!(m["variant"], tree.variant);
        assert_eq!(m["package"], tree.package);
        let pins = &m["pins"];
        for (key, pin) in [
            ("rust_toolchain", "RUST_TOOLCHAIN"),
            ("target", "TARGET"),
            ("cargo_auditable", "CARGO_AUDITABLE_VERSION"),
            ("rust_audit_info", "RUST_AUDIT_INFO_VERSION"),
            ("flip_link", "FLIP_LINK_VERSION"),
        ] {
            assert_eq!(pins[key].as_str(), Some(script_pin(pin).as_str()), "{key}");
        }
        assert_eq!(pins["rust_toolchain"], "1.91.1");
        assert_eq!(pins["target"], "thumbv7em-none-eabihf");
        assert_eq!(pins["cargo_auditable"], "0.7.7");
        let rustc = pins["rustc"].as_str().unwrap();
        assert!(rustc.starts_with("rustc 1.91.1 "), "{rustc}");
        if tree.variant == "cargo-keelsign" {
            assert_eq!(
                m["keelsign"]["commit"].as_str(),
                Some(script_pin("KEELSIGN_COMMIT").as_str())
            );
            assert_eq!(m["keelsign"]["path"], "examples/nrf52840-hello");
        }
    }
}

#[test]
fn no_build_machine_paths_in_any_fixture_file() {
    let needles = ["/Users/", "/home/", "/private/", "/var/folders/", "C:\\"];
    for tree in trees() {
        for name in FILES {
            let bytes = tree.read(name);
            for needle in needles {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "{}/{name} contains {needle:?}",
                    tree.variant
                );
            }
        }
        let metadata = String::from_utf8(tree.read("cargo-metadata.json")).unwrap();
        assert!(
            metadata.contains(&format!("/cargo-fixture/{}", tree.package)),
            "{}: the project path is not normalised to /cargo-fixture/{}",
            tree.variant,
            tree.package
        );
    }
}

#[test]
fn every_elf_has_a_dep_v0_section_equal_to_rust_audit_info_output() {
    for tree in trees() {
        let from_elf = auditable::read(&tree.read("firmware.elf"))
            .unwrap_or_else(|e| panic!("{}: {e}", tree.variant));
        let printed = String::from_utf8(tree.read("dep-v0.json")).unwrap();
        let from_json = auditable::parse_json(&printed).unwrap();
        assert_eq!(from_elf, from_json, "{}", tree.variant);
        assert_eq!(
            from_elf.root().map(|p| p.name.as_str()),
            Some(tree.package),
            "{}",
            tree.variant
        );
    }
}

#[test]
fn metadata_parses_and_its_root_is_the_package() {
    for tree in trees() {
        for name in ["cargo-metadata.json", "cargo-metadata.all.json"] {
            let text = String::from_utf8(tree.read(name)).unwrap();
            let m = metadata::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let root = m.root.as_ref().unwrap();
            assert_eq!(m.packages[root].name, tree.package, "{name}");
        }
        // Unfiltered metadata is a superset of the target-filtered one.
        let filtered =
            metadata::parse(&String::from_utf8(tree.read("cargo-metadata.json")).unwrap()).unwrap();
        let all =
            metadata::parse(&String::from_utf8(tree.read("cargo-metadata.all.json")).unwrap())
                .unwrap();
        let f: BTreeSet<&String> = filtered.packages.keys().collect();
        let a: BTreeSet<&String> = all.packages.keys().collect();
        assert!(f.is_subset(&a), "{}", tree.variant);
    }
}
