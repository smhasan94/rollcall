//! Opaque binary blobs (radio firmware, vendor HAL libraries) listed in a blob manifest.
//!
//! [`load`] reads a manifest ([`manifest::parse`]), hashes every file it lists with SHA-256
//! and turns each entry into an [`Image`] of kind [`ImageKind::Blob`]. rollcall does not look
//! inside a blob: the CycloneDX writer marks every blob image with the property
//! `rollcall:opaque` = `contents not analysed; hashes computed from the file`.
//!
//! # Evidence
//!
//! | Fact | Technique | Source | Occurrence | Confidence |
//! |------|-----------|--------|------------|------------|
//! | name, version, supplier, licence, purl from the manifest | `manifest-analysis` | `blob-manifest` | the manifest's file name | 9000 |
//! | the SHA-256 hash | `binary-analysis` | `blob-file` | the entry's `path` (when relative) | 10000 |
//! | name, version, supplier from a built-in recogniser ([`recognise()`]) | `filename` | `blob-recogniser` | the blob's file name | 7000 |
//!
//! A recogniser only fills facts the manifest leaves out, and its evidence is recorded only
//! for values it agrees with. An entry with no name after recognition is an error; one with
//! no version or no supplier is a [`Warning`].

pub mod manifest;
pub mod recognise;

use std::collections::BTreeSet;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::model::{
    Confidence, Evidence, EvidenceField, Hash, HashAlgorithm, IdError, Image, ImageKind, License,
    Occurrence, Purl, Supplier, Technique,
};
use crate::warning::Warning;

pub use manifest::{BlobEntry, BlobManifest};
pub use recognise::{Recognised, recognise};

/// Evidence source for values read from the manifest.
const MANIFEST_SOURCE: &str = "blob-manifest";
/// Evidence source for the hash computed from the file.
const FILE_SOURCE: &str = "blob-file";
/// Evidence source for values a built-in recogniser supplied.
const RECOGNISER_SOURCE: &str = "blob-recogniser";

const MANIFEST_CONFIDENCE: u16 = 9000;
const RECOGNISER_CONFIDENCE: u16 = 7000;

/// Why a blob manifest could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlobError {
    /// The manifest is empty or lists no blobs.
    #[error("the blob manifest lists no blobs (expected a top-level `blobs:` list)")]
    Empty,
    /// Not YAML, an unknown key, or a value of the wrong type. Includes line and column.
    #[error("not a valid blob manifest: {0}")]
    Yaml(String),
    /// The manifest is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The manifest.
        path: PathBuf,
    },
    /// A required key is missing (`path` always; `name` when no recogniser knows the file).
    #[error("blobs[{index}]: missing key {field}")]
    MissingField {
        /// The 0-based entry index.
        index: usize,
        /// The key.
        field: &'static str,
    },
    /// A key is present but empty.
    #[error("blobs[{index}]: {field} is empty")]
    EmptyField {
        /// The 0-based entry index.
        index: usize,
        /// The key.
        field: &'static str,
    },
    /// Two entries have the same name and version.
    #[error("blobs[{index}]: duplicate blob {name}")]
    Duplicate {
        /// The 0-based index of the second entry.
        index: usize,
        /// The name (and `@version`).
        name: String,
    },
    /// A value is rejected by the model (an invalid licence, purl, …).
    #[error("blobs[{index}]: {source}")]
    Id {
        /// The 0-based entry index.
        index: usize,
        /// The model's objection.
        source: IdError,
    },
    /// A blob path names something that is not a regular file (a directory, a FIFO, a
    /// device such as `/dev/zero`), which rollcall refuses to hash.
    #[error("{}: not a regular file", path.display())]
    NotAFile {
        /// The path, joined to the manifest's directory.
        path: PathBuf,
    },
    /// The manifest or a blob file could not be read.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
}

impl BlobError {
    /// True when a file is missing, unreadable or not a regular file (the CLI reports this
    /// as exit 66).
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Read { .. } | Self::NotAFile { .. })
    }
}

/// The result of [`load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobIngest {
    /// One `blob` image per manifest entry, in manifest order.
    pub images: Vec<Image>,
    /// Entries missing a version or supplier, in manifest order, each located `blobs[N]`
    /// (the caller names the manifest file).
    pub warnings: Vec<Warning>,
}

/// The SHA-256 of a file, read in chunks, as lowercase hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(buffer.get(..n).unwrap_or_default());
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest.iter() {
        text.push_str(&format!("{byte:02x}"));
    }
    Ok(text)
}

/// Reads the manifest at `path`, hashes every blob it lists (paths relative to the
/// manifest's directory) and returns one `blob` image per entry.
pub fn load(path: &Path) -> Result<BlobIngest, BlobError> {
    let bytes = std::fs::read(path).map_err(|source| BlobError::Read {
        path: path.to_owned(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| BlobError::NotUtf8 {
        path: path.to_owned(),
    })?;
    let manifest = manifest::parse(&text)?;
    let mut images = Vec::with_capacity(manifest.blobs.len());
    let mut warnings = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, entry) in manifest.blobs.iter().enumerate() {
        let (image, mut entry_warnings) = to_image(entry, index, path)?;
        let key = (image.name.clone(), image.version.clone());
        if !seen.insert(key) {
            let name = match &image.version {
                Some(version) => format!("{}@{version}", image.name),
                None => image.name.clone(),
            };
            return Err(BlobError::Duplicate { index, name });
        }
        images.push(image);
        warnings.append(&mut entry_warnings);
    }
    Ok(BlobIngest { images, warnings })
}

/// A file name as an evidence occurrence, when it is a valid relative path.
fn occurrence(location: &str) -> Option<Occurrence> {
    Occurrence::new(location, None).ok()
}

/// Builds an evidence entry, located when `location` is usable.
fn evidence(
    field: EvidenceField,
    technique: Technique,
    source: &str,
    value: &str,
    bp: u16,
    location: Option<&str>,
) -> Result<Evidence, IdError> {
    let entry = Evidence::new(field, technique, source, value, Confidence::new(bp)?)?;
    Ok(match location.and_then(occurrence) {
        Some(occurrence) => entry.at(occurrence),
        None => entry,
    })
}

/// Turns one manifest entry into a `blob` image: hashes the file at `entry.path` (relative
/// to `manifest_path`'s directory), fills missing facts from a recogniser and records
/// evidence for every fact. Returns warnings for a missing version or supplier.
pub fn to_image(
    entry: &BlobEntry,
    index: usize,
    manifest_path: &Path,
) -> Result<(Image, Vec<Warning>), BlobError> {
    let id = |source: IdError| BlobError::Id { index, source };
    let manifest_name = manifest_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "blob-manifest".to_owned());
    let base = manifest_path.parent().unwrap_or_else(|| Path::new(""));
    let file = base.join(&entry.path);
    let file_name = Path::new(&entry.path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let recognised = recognise(&file_name);

    let name = entry
        .name
        .clone()
        .or_else(|| recognised.as_ref().map(|r| r.name.clone()))
        .ok_or(BlobError::MissingField {
            index,
            field: "name",
        })?;
    let version = entry
        .version
        .clone()
        .or_else(|| recognised.as_ref().and_then(|r| r.version.clone()));
    let supplier = entry
        .supplier
        .clone()
        .or_else(|| recognised.as_ref().map(|r| r.supplier.to_owned()));

    // Only regular files are hashed, so a FIFO or a device cannot block or read forever.
    let metadata = std::fs::metadata(&file).map_err(|source| BlobError::Read {
        path: file.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BlobError::NotAFile { path: file });
    }
    let digest = sha256_file(&file).map_err(|source| BlobError::Read {
        path: file.clone(),
        source,
    })?;

    let mut image = Image::new(ImageKind::Blob, &name).map_err(id)?;
    image.version = version.clone();
    image.supplier = supplier
        .as_deref()
        .map(Supplier::new)
        .transpose()
        .map_err(id)?;
    image.licence = entry
        .licence
        .as_deref()
        .map(License::new)
        .transpose()
        .map_err(id)?;
    image.purl = entry
        .purl
        .as_deref()
        .map(Purl::new)
        .transpose()
        .map_err(id)?;
    image
        .hashes
        .insert(Hash::new(HashAlgorithm::Sha256, &digest).map_err(id)?);

    let manifest_facts = [
        (EvidenceField::Name, entry.name.as_deref()),
        (EvidenceField::Version, entry.version.as_deref()),
        (EvidenceField::Supplier, entry.supplier.as_deref()),
        (EvidenceField::Licence, entry.licence.as_deref()),
        (EvidenceField::Purl, entry.purl.as_deref()),
    ];
    for (field, value) in manifest_facts {
        if let Some(value) = value {
            image.evidence.insert(
                evidence(
                    field,
                    Technique::ManifestAnalysis,
                    MANIFEST_SOURCE,
                    value,
                    MANIFEST_CONFIDENCE,
                    Some(&manifest_name),
                )
                .map_err(id)?,
            );
        }
    }
    image.evidence.insert(
        evidence(
            EvidenceField::Hash,
            Technique::BinaryAnalysis,
            FILE_SOURCE,
            &digest,
            Confidence::FULL.basis_points(),
            Some(&entry.path),
        )
        .map_err(id)?,
    );
    if let Some(r) = &recognised {
        let recogniser_facts = [
            (
                EvidenceField::Name,
                Some(r.name.as_str()),
                Some(name.as_str()),
            ),
            (
                EvidenceField::Version,
                r.version.as_deref(),
                version.as_deref(),
            ),
            (
                EvidenceField::Supplier,
                Some(r.supplier),
                supplier.as_deref(),
            ),
        ];
        for (field, seen, kept) in recogniser_facts {
            if let Some(value) = seen.filter(|v| Some(*v) == kept) {
                image.evidence.insert(
                    evidence(
                        field,
                        Technique::Filename,
                        RECOGNISER_SOURCE,
                        value,
                        RECOGNISER_CONFIDENCE,
                        Some(&file_name),
                    )
                    .map_err(id)?,
                );
            }
        }
    }

    // The caller names the manifest file; the location is the entry within it.
    let location = format!("blobs[{index}]");
    let mut warnings = Vec::new();
    if version.is_none() {
        warnings.push(Warning::new(
            location.clone(),
            format!("{name}: no version (none in the manifest, none recognised)"),
        ));
    }
    if supplier.is_none() {
        warnings.push(Warning::new(
            location,
            format!("{name}: no supplier (none in the manifest, none recognised)"),
        ));
    }
    Ok((image, warnings))
}
