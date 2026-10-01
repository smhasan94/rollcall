//! The identifier database against the real Zephyr build fixtures in `fixtures/zephyr/`, with
//! the hand-written database `tests/data/identifiers-stub.yaml` (see `tests/data/README.md`).
//!
//! The fixtures are never modified. `ROLLCALL_FIXTURES_DIR` points the tests at another
//! fixture tree, as in `tests/zephyr.rs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions};
use rollcall_core::identify::{self, Level, Outcome, Query, Resolver};
use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::{Component, EvidenceField, Product};
use rollcall_core::zephyr::{self, Ingest, IngestOptions, ZephyrError, west_list};

const VARIANTS: [&str; 3] = ["baseline", "bt", "tls"];
/// `(variant, application image, bootloader image)`.
const BUILDS: [(&str, &str, &str); 3] = [
    ("baseline", "with_mcuboot", "mcuboot"),
    ("bt", "beacon", "mcuboot"),
    ("tls", "http_server", "mcuboot"),
];
/// The fixture modules `identifiers-stub.yaml` leaves out.
const UNMAPPED: [&str; 3] = ["cmsis_6", "hal_nordic", "mcuboot"];
const DB_NAME: &str = "identifiers-stub.yaml";
const DB_SOURCE: &str = "identifier-db";

fn fixtures_root() -> PathBuf {
    match std::env::var_os("ROLLCALL_FIXTURES_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/zephyr"),
    }
}

fn stub_db_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(DB_NAME)
}

fn west_list_path(variant: &str) -> PathBuf {
    fixtures_root().join(variant).join("west-list.txt")
}

fn image_options(variant: &str, image: &str) -> IngestOptions {
    IngestOptions::new(fixtures_root().join(variant).join(image))
        .with_west_list(west_list_path(variant))
        .with_identifier_db(stub_db_path())
}

fn sysbuild_options(variant: &str) -> IngestOptions {
    IngestOptions::new(fixtures_root().join(variant))
        .with_sysbuild(true)
        .with_west_list(west_list_path(variant))
        .with_identifier_db(stub_db_path())
}

fn ingest(options: &IngestOptions) -> Ingest {
    zephyr::ingest(options).unwrap_or_else(|e| panic!("{}: {e}", options.build_dir.display()))
}

fn render(product: &Product) -> String {
    let options = WriteOptions::new(Timestamp::parse("2026-01-02T03:04:05Z").unwrap());
    cyclonedx::write(product, &options).unwrap()
}

/// Every library component of every image, by image name.
fn modules(product: &Product) -> Vec<(String, &Component)> {
    product
        .images
        .iter()
        .flat_map(|image| {
            image
                .components
                .iter()
                .filter(|c| c.kind == rollcall_core::ComponentKind::Library)
                .map(move |c| (image.name.clone(), c))
        })
        .collect()
}

fn db_values(component: &Component, field: EvidenceField) -> Vec<(String, u16)> {
    component
        .evidence
        .iter()
        .filter(|e| e.field == field && e.source() == DB_SOURCE)
        .map(|e| (e.value.clone(), e.confidence.basis_points()))
        .collect()
}

/// The modules named by "not in the database" warnings, in order.
fn unknown_warnings(ingest: &Ingest) -> Vec<String> {
    let needle = format!(" is not in {DB_NAME}; stub entry printed");
    ingest
        .warnings
        .iter()
        .filter_map(|w| {
            w.message
                .strip_suffix(&needle)?
                .strip_prefix("module ")
                .map(str::to_owned)
        })
        .collect()
}

/// Checks one ingest (an image, or a sysbuild product) against the stub database.
fn check(what: &str, out: &Ingest) {
    let unmapped: Vec<String> = UNMAPPED.iter().map(|s| (*s).to_owned()).collect();
    // Exactly the unmapped modules, each warned about and stubbed once.
    assert_eq!(
        unknown_warnings(out),
        unmapped,
        "{what}: {:#?}",
        out.warnings
    );
    let stubbed: Vec<&str> = out
        .unknown_modules
        .iter()
        .map(|u| u.name.as_str())
        .collect();
    assert_eq!(stubbed, UNMAPPED, "{what}");
    for unknown in &out.unknown_modules {
        assert!(
            unknown.stub.starts_with(&format!("  {}:\n", unknown.name)),
            "{what}: {}",
            unknown.stub
        );
    }
    let mut seen = BTreeSet::new();
    for (image, module) in modules(&out.product) {
        let at = format!("{what}/{image}/{}", module.name);
        seen.insert(module.name.clone());
        match module.name.as_str() {
            "mbedtls" | "tf-psa-crypto" => {
                let (version, purl, cpe) = if module.name == "mbedtls" {
                    (
                        "4.1.0",
                        "pkg:github/mbed-tls/mbedtls@v4.1.0",
                        "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*",
                    )
                } else {
                    (
                        "1.1.0",
                        "pkg:github/mbed-tls/tf-psa-crypto@v1.1.0",
                        "cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*",
                    )
                };
                let high = Level::High.basis_points();
                assert_eq!(
                    db_values(module, EvidenceField::Version),
                    [(version.into(), high)],
                    "{at}"
                );
                assert_eq!(
                    db_values(module, EvidenceField::Purl),
                    [(purl.into(), high)],
                    "{at}"
                );
                assert_eq!(
                    db_values(module, EvidenceField::Cpe),
                    [(cpe.into(), high)],
                    "{at}"
                );
                assert_eq!(module.purl.as_ref().map(|p| p.as_str()), Some(purl), "{at}");
                assert_eq!(module.cpe.as_ref().map(|c| c.as_str()), Some(cpe), "{at}");
            }
            "cmsis" => {
                // A git_tag rule with a commit and no sources: low, so no version, purl or cpe.
                // The supplier is asserted by the database, so it is High whatever the rule.
                assert!(db_values(module, EvidenceField::Version).is_empty(), "{at}");
                assert!(db_values(module, EvidenceField::Purl).is_empty(), "{at}");
                assert_eq!(
                    db_values(module, EvidenceField::Supplier),
                    [("Arm".into(), Level::High.basis_points())],
                    "{at}"
                );
            }
            name => {
                assert!(UNMAPPED.contains(&name), "{at}: unexpected module");
                assert!(
                    module.evidence.iter().all(|e| e.source() != DB_SOURCE),
                    "{at}"
                );
            }
        }
    }
    let expected: BTreeSet<String> = [
        "cmsis",
        "cmsis_6",
        "hal_nordic",
        "mbedtls",
        "mcuboot",
        "tf-psa-crypto",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(seen, expected, "{what}");
    // cmsis is reported as unversionable in each image (each has its own cmsis component);
    // nothing else from the database is a warning.
    let db_warnings: Vec<&str> = out
        .warnings
        .iter()
        .filter(|w| w.location.ends_with(DB_NAME))
        .map(|w| w.message.as_str())
        .filter(|m| !m.ends_with("stub entry printed"))
        .collect();
    assert_eq!(
        db_warnings.len(),
        out.product.images.len(),
        "{what}: {db_warnings:?}"
    );
    for warning in db_warnings {
        assert!(
            warning.starts_with("module cmsis: revision 512cc7e895e8491696b61f7ba8066b4a182569b8 is a commit and there is no module source tree"),
            "{what}: {warning}"
        );
    }
}

#[test]
fn every_fixture_module_resolves_with_stub_db_and_warnings_list_exactly_the_unmapped() {
    let db = identify::load(&stub_db_path()).unwrap();
    for variant in VARIANTS {
        // Straight from the west list: every module is identified or unknown, and the unknown
        // ones are exactly the unmapped ones.
        let list = west_list::parse(&fs::read_to_string(west_list_path(variant)).unwrap()).unwrap();
        let mut resolver = Resolver::new(&db);
        for project in list.modules() {
            let query = Query {
                module: &project.name,
                revision: Some(&project.revision),
                path: None,
            };
            match resolver.resolve(&query, Some(&project.url)) {
                Outcome::Identified(id) => {
                    assert!(
                        !UNMAPPED.contains(&project.name.as_str()),
                        "{}",
                        project.name
                    );
                    let expect = if project.name == "cmsis" {
                        Level::Low
                    } else {
                        Level::High
                    };
                    assert_eq!(id.level, expect, "{}", project.name);
                    assert_eq!(id.purl.is_some(), expect == Level::High, "{}", project.name);
                }
                Outcome::Unknown { stub } => {
                    assert!(
                        UNMAPPED.contains(&project.name.as_str()),
                        "{}",
                        project.name
                    );
                    assert!(stub.is_some(), "{}", project.name);
                }
            }
        }
        assert_eq!(
            resolver.unknown_modules().collect::<Vec<_>>(),
            UNMAPPED,
            "{variant}"
        );
    }

    // Every image build, then each variant as one sysbuild run: the one-warning-per-module
    // rule holds across both images of a run.
    for (variant, app, boot) in BUILDS {
        for image in [app, boot] {
            check(
                &format!("{variant}/{image}"),
                &ingest(&image_options(variant, image)),
            );
        }
        let sysbuild = ingest(&sysbuild_options(variant));
        assert_eq!(sysbuild.product.images.len(), 2);
        check(&format!("{variant} --sysbuild"), &sysbuild);
        // The image whose name sorts first carries the warnings.
        let first = app.min(boot);
        for module in UNMAPPED {
            let located: Vec<&str> = sysbuild
                .warnings
                .iter()
                .filter(|w| {
                    w.message == format!("module {module} is not in {DB_NAME}; stub entry printed")
                })
                .map(|w| w.location.as_str())
                .collect();
            assert_eq!(
                located,
                [format!("{first}: {DB_NAME}")],
                "{variant} {module}"
            );
        }
        // The sysbuild product is still the merge of the separately resolved images.
        let spec: ProductSpec = app.parse().unwrap();
        let manual = merge::merge(
            vec![
                ingest(&image_options(variant, app)).product,
                ingest(&image_options(variant, boot)).product,
            ],
            Some(&spec),
        )
        .unwrap();
        assert_eq!(render(&sysbuild.product), render(&manual), "{variant}");
    }
}

#[test]
fn builtin_seed_loads_and_resolves_its_own_samples() {
    let db = identify::builtin().unwrap();
    assert_eq!(db.name(), "identifiers.yaml");
    let names: Vec<&str> = db.modules().map(|(name, _)| name).collect();
    assert_eq!(names, ["cmsis", "mbedtls", "tf-psa-crypto"]);
    let mut resolver = Resolver::new(&db);
    let cases = [
        (
            "mbedtls",
            "a3e190fe44c78d1ba67f55979e1257328cc7d0d8",
            "4.1.0",
            "pkg:github/mbed-tls/mbedtls@v4.1.0",
        ),
        (
            "tf-psa-crypto",
            "dc575a2ddcc8cb16275d24c42a52eaf79ebe2231",
            "1.1.0",
            "pkg:github/mbed-tls/tf-psa-crypto@v1.1.0",
        ),
        (
            "cmsis",
            "v5.9.0",
            "5.9.0",
            "pkg:github/arm-software/cmsis_5@5.9.0",
        ),
    ];
    for (module, revision, version, purl) in cases {
        let query = Query {
            module,
            revision: Some(revision),
            path: None,
        };
        let Outcome::Identified(id) = resolver.resolve(&query, None) else {
            panic!("{module} is not in the seed");
        };
        assert_eq!(id.version.as_deref(), Some(version), "{module}");
        assert_eq!(id.level, Level::High, "{module}");
        assert_eq!(id.purl.as_ref().map(|p| p.as_str()), Some(purl), "{module}");
    }
    // The seed's entries agree with the hand-written test database.
    let stub_db = identify::load(&stub_db_path()).unwrap();
    for (name, entry) in db.modules() {
        assert_eq!(stub_db.get(name), Some(entry), "{name}");
    }
}

#[test]
fn ingest_with_identifier_db_is_byte_identical_twice() {
    for (variant, app, _) in BUILDS {
        for options in [image_options(variant, app), sysbuild_options(variant)] {
            let first = ingest(&options);
            let second = ingest(&options);
            assert_eq!(render(&first.product), render(&second.product), "{variant}");
            assert_eq!(
                first.product.to_json().unwrap(),
                second.product.to_json().unwrap()
            );
            assert_eq!(first.warnings, second.warnings);
            assert_eq!(first.unknown_modules, second.unknown_modules);
        }
    }
}

#[test]
fn workspace_sources_resolve_git_tag_module() {
    // A stand-in west workspace holding only cmsis's .git, with a tag at the fixture revision.
    let workspace = tempfile::tempdir().unwrap();
    let git = workspace.path().join("modules/hal/cmsis/.git");
    fs::create_dir_all(&git).unwrap();
    fs::write(
        git.join("packed-refs"),
        "512cc7e895e8491696b61f7ba8066b4a182569b8 refs/tags/v5.9.0\n",
    )
    .unwrap();
    let options = image_options("baseline", "with_mcuboot").with_workspace(workspace.path());
    let out = ingest(&options);
    let cmsis = modules(&out.product)
        .into_iter()
        .find(|(_, c)| c.name == "cmsis")
        .unwrap()
        .1;
    let high = Level::High.basis_points();
    assert_eq!(
        db_values(cmsis, EvidenceField::Version),
        [("5.9.0".into(), high)]
    );
    assert_eq!(
        cmsis.purl.as_ref().unwrap().as_str(),
        "pkg:github/arm-software/cmsis_5@5.9.0"
    );
    assert!(
        out.warnings
            .iter()
            .all(|w| !w.message.starts_with("module cmsis:")),
        "{:?}",
        out.warnings
    );
}

#[test]
fn missing_or_malformed_identifier_db_is_error_naming_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.yaml");
    let e = zephyr::ingest(&image_options("baseline", "with_mcuboot").with_identifier_db(&missing))
        .unwrap_err();
    assert!(e.is_read_error(), "{e}");
    assert!(
        e.to_string().starts_with(&missing.display().to_string()),
        "{e}"
    );

    let bad = dir.path().join("identifiers.yaml");
    let text = fs::read_to_string(stub_db_path()).unwrap().replace(
        "cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*",
        "cpe:2.3:a:arm:mbed_tls:{version}",
    );
    fs::write(&bad, text).unwrap();
    for options in [
        image_options("baseline", "with_mcuboot").with_identifier_db(&bad),
        sysbuild_options("baseline").with_identifier_db(&bad),
    ] {
        let e = zephyr::ingest(&options).unwrap_err();
        assert!(matches!(e, ZephyrError::IdentifierDb { .. }), "{e:?}");
        assert!(!e.is_read_error());
        let shown = e.to_string();
        assert!(
            shown.starts_with(&format!("{}:21:10: ", bad.display())),
            "{shown}"
        );
        assert!(shown.contains("modules.mbedtls.cpe"), "{shown}");
    }
}
