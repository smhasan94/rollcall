//! Cryptographic inventory (CycloneDX CBOM) for rollcall, invoked as `rollcall assay`.
//!
//! [`assay`] takes a build's inputs ([`Inputs`]: a source tree, a build directory and/or an
//! ELF file) and returns an [`Inventory`]: a product whose `cryptographic-asset` components
//! carry [`CryptoAsset`](rollcall_core::model::CryptoAsset)s, written as a CycloneDX 1.6 CBOM
//! by [`rollcall_core::cyclonedx::write`] or as a Markdown table by [`summary::to_markdown`].
//!
//! This version has no detectors yet: [`assay`] checks its inputs exist and returns an empty
//! inventory, with [`Inventory::detectors`] empty and a note saying so. A CBOM written for it
//! carries the document property [`DETECTORS_PROPERTY`] = [`NO_DETECTORS`], so an empty
//! inventory is never mistaken for a build without cryptography.

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

pub mod summary;

use std::io;
use std::path::{Path, PathBuf};

use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::Product;

/// The CBOM `metadata.properties` entry naming the detectors that ran, comma-separated, or
/// [`NO_DETECTORS`] when none did.
pub const DETECTORS_PROPERTY: &str = "rollcall:assay:detectors";

/// The value of [`DETECTORS_PROPERTY`] when no detector ran.
pub const NO_DETECTORS: &str = "none";

/// The note [`assay`] returns while it has no detectors.
pub const NO_DETECTORS_NOTE: &str =
    "no cryptographic-asset detectors in this version; the inventory is empty";

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
    /// The detectors that ran, sorted. Empty in this version.
    pub detectors: Vec<&'static str>,
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
}

impl AssayError {
    /// Whether the error is about an input path (missing, unreadable or the wrong kind),
    /// rather than about the model.
    pub fn is_input_error(&self) -> bool {
        matches!(
            self,
            Self::MissingInput { .. } | Self::NotADirectory { .. } | Self::NotAFile { .. }
        )
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
/// then runs the detectors. There are none in this version, so the inventory is the empty
/// product `inputs.product` names, with no detectors and the note [`NO_DETECTORS_NOTE`].
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
    let product = merge::merge(Vec::new(), Some(&inputs.product))?;
    Ok(Inventory {
        product,
        detectors: Vec::new(),
        notes: vec![NO_DETECTORS_NOTE.to_owned()],
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
            build: Some(dir.path()),
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
            build: Some(dir.path()),
            elf: Some(&file),
            product: spec(),
        })
        .unwrap();
        assert_eq!(again, inventory);
    }
}
