//! Cryptographic inventory (CycloneDX CBOM) for rollcall, invoked as `rollcall assay`.
//!
//! [`assay`] takes a build's inputs ([`Inputs`]: a source tree, a build directory and/or an
//! ELF file) and returns an [`Inventory`]: a product whose `cryptographic-asset` components
//! carry [`CryptoAsset`](rollcall_core::model::CryptoAsset)s, written as a CycloneDX 1.6 CBOM
//! by [`rollcall_core::cyclonedx::write`] or as a Markdown table by [`summary::to_markdown`].
//!
//! The detectors so far are the configuration detectors of [`config`]: with a `--build`
//! directory (a Zephyr build, or an ESP-IDF project or build directory), [`assay`] reads its
//! Kconfig output and reports the algorithms, protocols and MCUboot signature it configures.
//! When no detector ran, [`Inventory::detectors`] is empty and a note says so; a CBOM written
//! for it carries the document property [`DETECTORS_PROPERTY`] = [`NO_DETECTORS`], so an empty
//! inventory is never mistaken for a build without cryptography.
//!
//! [`catalogue`] is the algorithm catalogue (`db/algorithms.yaml`): for each algorithm and
//! parameter set, its CycloneDX primitive, mode and functions, its classical and NIST
//! post-quantum security levels and its quantum-risk class. [`catalogue::Catalogue::lookup`]
//! turns an (algorithm, parameter set) into the
//! [`AlgorithmProperties`](rollcall_core::model::AlgorithmProperties) a detector puts on an
//! asset; an unknown one is an error, never a default.

#![deny(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod assets;
pub mod catalogue;
pub mod config;
pub mod summary;

use std::io;
use std::path::{Path, PathBuf};

use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::Product;

use crate::catalogue::{Catalogue, CatalogueError};
use crate::config::ConfigError;

/// The CBOM `metadata.properties` entry naming the detectors that ran, comma-separated, or
/// [`NO_DETECTORS`] when none did.
pub const DETECTORS_PROPERTY: &str = "rollcall:assay:detectors";

/// The value of [`DETECTORS_PROPERTY`] when no detector ran.
pub const NO_DETECTORS: &str = "none";

/// The note [`assay`] returns when no detector ran.
pub const NO_DETECTORS_NOTE: &str =
    "no cryptographic-asset detector ran for these inputs; the inventory is empty";

/// What to take an inventory of. At least one of `source`, `build` and `elf` should be given;
/// each that is given must exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inputs<'a> {
    /// The source tree (a directory).
    pub source: Option<&'a Path>,
    /// The build directory.
    pub build: Option<&'a Path>,
    /// The linked ELF image (a file).
    pub elf: Option<&'a Path>,
    /// The product the inventory is of.
    pub product: ProductSpec,
}

/// The result of [`assay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// The product, with each crypto asset as a `cryptographic-asset` component under the
    /// component that implements it (or under the image, for a protocol, certificate or key
    /// that belongs to the image).
    pub product: Product,
    /// The detectors that ran, sorted (`kconfig`, `sdkconfig`).
    pub detectors: Vec<&'static str>,
    /// What the configuration detectors found compiled out, per image and library: what the
    /// source detector passes to [`config::apply_compiled_out`]. Empty without `build`.
    pub compiled_out: config::CompiledOut,
    /// The crypto API each image with mbedTLS uses, from the configuration detectors.
    pub apis: std::collections::BTreeMap<config::ImageKey, config::CryptoApi>,
    /// Things the user should know about the inventory, one line each.
    pub notes: Vec<String>,
}

impl Inventory {
    /// The value for [`DETECTORS_PROPERTY`]: the detectors, comma-separated, or
    /// [`NO_DETECTORS`].
    pub fn detectors_property(&self) -> String {
        if self.detectors.is_empty() {
            NO_DETECTORS.to_owned()
        } else {
            self.detectors.join(",")
        }
    }
}

/// Why [`assay`] could not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AssayError {
    /// An input does not exist or cannot be read.
    #[error("{what} {}: {source}", path.display())]
    MissingInput {
        /// Which input (`--source`, `--build` or `--elf`).
        what: &'static str,
        /// The path given.
        path: PathBuf,
        /// The error reading it.
        source: io::Error,
    },
    /// A directory input (`--source`, `--build`) is not a directory.
    #[error("{what} {}: not a directory", path.display())]
    NotADirectory {
        /// Which input.
        what: &'static str,
        /// The path given.
        path: PathBuf,
    },
    /// A file input (`--elf`) is not a file.
    #[error("{what} {}: not a file", path.display())]
    NotAFile {
        /// Which input.
        what: &'static str,
        /// The path given.
        path: PathBuf,
    },
    /// The product could not be built.
    #[error(transparent)]
    Merge(#[from] merge::Error),
    /// A configuration detector could not read the `--build` directory.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The built-in algorithm catalogue does not load.
    #[error(transparent)]
    Catalogue(#[from] CatalogueError),
}

impl AssayError {
    /// Whether the error is about an input path (missing, unreadable or the wrong kind),
    /// rather than about the model.
    pub fn is_input_error(&self) -> bool {
        match self {
            Self::MissingInput { .. } | Self::NotADirectory { .. } | Self::NotAFile { .. } => true,
            Self::Config(e) => e.is_input_error(),
            _ => false,
        }
    }
}

/// Checks `path` exists and is a directory (`dir`) or a file.
fn check_path(what: &'static str, path: &Path, dir: bool) -> Result<(), AssayError> {
    let metadata = std::fs::metadata(path).map_err(|source| AssayError::MissingInput {
        what,
        path: path.to_owned(),
        source,
    })?;
    match (dir, metadata.is_dir()) {
        (true, false) => Err(AssayError::NotADirectory {
            what,
            path: path.to_owned(),
        }),
        (false, true) => Err(AssayError::NotAFile {
            what,
            path: path.to_owned(),
        }),
        _ => Ok(()),
    }
}

/// Takes the cryptographic inventory of `inputs`.
///
/// Checks each given input exists and is a directory (`source`, `build`) or a file (`elf`),
/// then runs the detectors: with `build`, the configuration detectors
/// ([`config::detect_build`]), whose images are merged into the product `inputs.product` names.
/// The notes are the detectors' notes, plus [`NO_DETECTORS_NOTE`] when none ran.
pub fn assay(inputs: &Inputs<'_>) -> Result<Inventory, AssayError> {
    if let Some(path) = inputs.source {
        check_path("--source", path, true)?;
    }
    if let Some(path) = inputs.build {
        check_path("--build", path, true)?;
    }
    if let Some(path) = inputs.elf {
        check_path("--elf", path, false)?;
    }
    let mut product = inputs.product.empty_product();
    let mut detectors = std::collections::BTreeSet::new();
    let mut notes = Vec::new();
    let mut compiled_out = config::CompiledOut::new();
    let mut apis = std::collections::BTreeMap::new();
    if let Some(build) = inputs.build {
        let catalogue = Catalogue::builtin()?;
        let found = config::detect_build(build, &inputs.product, &catalogue)?;
        for image in found.images {
            product.add_image(image).map_err(merge::Error::from)?;
        }
        detectors.extend(found.detectors);
        notes.extend(found.notes);
        compiled_out = found.compiled_out;
        apis = found.apis;
    }
    let product = merge::merge(vec![product], Some(&inputs.product))?;
    if detectors.is_empty() {
        notes.push(NO_DETECTORS_NOTE.to_owned());
    }
    Ok(Inventory {
        product,
        detectors: detectors.into_iter().collect(),
        compiled_out,
        apis,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ProductSpec {
        "sensor-node@1.0.0".parse().unwrap()
    }

    #[test]
    fn assay_with_missing_source_build_or_elf_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("zephyr.elf");
        std::fs::write(&file, b"\x7fELF").unwrap();
        let missing = dir.path().join("nope");
        let base = || Inputs {
            source: None,
            build: None,
            elf: None,
            product: spec(),
        };
        let cases = [
            (
                "--source missing",
                Inputs {
                    source: Some(&missing),
                    ..base()
                },
            ),
            (
                "--build missing",
                Inputs {
                    build: Some(&missing),
                    ..base()
                },
            ),
            (
                "--elf missing",
                Inputs {
                    elf: Some(&missing),
                    ..base()
                },
            ),
            (
                "--source a file",
                Inputs {
                    source: Some(&file),
                    ..base()
                },
            ),
            (
                "--build a file",
                Inputs {
                    build: Some(&file),
                    ..base()
                },
            ),
            (
                "--elf a directory",
                Inputs {
                    elf: Some(dir.path()),
                    ..base()
                },
            ),
            (
                "one good, one missing",
                Inputs {
                    build: Some(dir.path()),
                    elf: Some(&missing),
                    ..base()
                },
            ),
        ];
        for (name, inputs) in cases {
            let err = assay(&inputs).unwrap_err();
            assert!(err.is_input_error(), "{name}: {err}");
            let message = err.to_string();
            assert!(message.starts_with("--"), "{name}: {message}");
        }
        assert!(matches!(
            assay(&Inputs {
                elf: Some(&missing),
                ..base()
            }),
            Err(AssayError::MissingInput { what: "--elf", .. })
        ));
        assert!(matches!(
            assay(&Inputs {
                elf: Some(dir.path()),
                ..base()
            }),
            Err(AssayError::NotAFile { .. })
        ));
        assert!(matches!(
            assay(&Inputs {
                build: Some(&file),
                ..base()
            }),
            Err(AssayError::NotADirectory { .. })
        ));
    }

    #[test]
    fn assay_with_existing_inputs_and_no_detectors_returns_empty_inventory_with_note() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("zephyr.elf");
        std::fs::write(&file, b"\x7fELF").unwrap();
        let inventory = assay(&Inputs {
            source: Some(dir.path()),
            build: None,
            elf: Some(&file),
            product: spec(),
        })
        .unwrap();
        assert_eq!(inventory.product.name, "sensor-node");
        assert_eq!(inventory.product.version.as_deref(), Some("1.0.0"));
        assert!(inventory.product.images.is_empty());
        assert_eq!(inventory.product.crypto_assets().count(), 0);
        assert!(inventory.detectors.is_empty());
        assert_eq!(inventory.detectors_property(), NO_DETECTORS);
        assert_eq!(inventory.notes, vec![NO_DETECTORS_NOTE.to_owned()]);
        // Deterministic.
        let again = assay(&Inputs {
            source: Some(dir.path()),
            build: None,
            elf: Some(&file),
            product: spec(),
        })
        .unwrap();
        assert_eq!(again, inventory);
        // A --build that is no build the configuration detectors read: a note saying so,
        // then the no-detector note; still an empty inventory.
        let inventory = assay(&Inputs {
            source: None,
            build: Some(dir.path()),
            elf: None,
            product: spec(),
        })
        .unwrap();
        assert!(inventory.detectors.is_empty());
        assert!(inventory.compiled_out.is_empty());
        assert_eq!(inventory.compiled_out.images().count(), 0);
        assert!(inventory.apis.is_empty());
        assert_eq!(inventory.notes.len(), 2, "{:?}", inventory.notes);
        assert!(inventory.notes[0].contains("not a Zephyr or ESP-IDF build"));
        assert_eq!(inventory.notes[1], NO_DETECTORS_NOTE);
    }
}
