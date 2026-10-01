//! Parser for a blob manifest (`--blob-manifest blobs.yaml`).
//!
//! ```yaml
//! blobs:
//!   - name: s140_nrf52_softdevice      # optional when a recogniser knows the file
//!     version: 7.3.0                   # optional
//!     supplier: Nordic Semiconductor ASA  # optional
//!     path: s140_nrf52_7.3.0_softdevice.hex  # required, relative to the manifest file
//!     licence: LicenseRef-Nordic-5-Clause    # optional SPDX expression (or `license`)
//!     purl: pkg:generic/s140_nrf52_softdevice@7.3.0  # optional
//!     kind: firmware                   # optional: firmware | library (the CycloneDX type)
//! ```
//!
//! `kind` is the blob's CycloneDX component type, not its `rollcall:image-kind` (which is
//! always `blob`). Any other value is a [`BlobError::Yaml`].
//!
//! Unknown keys are rejected, so a misspelt key is an error rather than a silently missing
//! fact.

use serde::Deserialize;

use super::BlobError;
use crate::model::ImageType;

/// A parsed blob manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobManifest {
    /// The entries, in file order.
    pub blobs: Vec<BlobEntry>,
}

/// One `blobs[]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobEntry {
    /// The component name, if given.
    pub name: Option<String>,
    /// The version, if given.
    pub version: Option<String>,
    /// The supplier's name, if given.
    pub supplier: Option<String>,
    /// The file, relative to the manifest's directory (or absolute).
    pub path: String,
    /// The SPDX licence expression, if given.
    pub licence: Option<String>,
    /// The package URL, if given.
    pub purl: Option<String>,
    /// The CycloneDX component type (`kind: firmware | library`), if given.
    pub kind: Option<ImageType>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(default)]
    blobs: Option<Vec<RawEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    supplier: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default, alias = "license")]
    licence: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    kind: Option<ImageType>,
}

/// An optional string that, when present, must not be empty.
fn non_empty(
    value: Option<String>,
    index: usize,
    field: &'static str,
) -> Result<Option<String>, BlobError> {
    match value {
        Some(v) if v.trim().is_empty() => Err(BlobError::EmptyField { index, field }),
        other => Ok(other),
    }
}

/// Parses a blob manifest. An empty file, or one listing no blobs, is [`BlobError::Empty`].
pub fn parse(text: &str) -> Result<BlobManifest, BlobError> {
    if text.trim().is_empty() {
        return Err(BlobError::Empty);
    }
    let raw: Option<RawManifest> =
        yaml_serde::from_str(text).map_err(|e| BlobError::Yaml(e.to_string()))?;
    let entries = raw.and_then(|r| r.blobs).unwrap_or_default();
    if entries.is_empty() {
        return Err(BlobError::Empty);
    }
    let mut blobs = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let path = non_empty(entry.path, index, "path")?.ok_or(BlobError::MissingField {
            index,
            field: "path",
        })?;
        blobs.push(BlobEntry {
            name: non_empty(entry.name, index, "name")?,
            version: non_empty(entry.version, index, "version")?,
            supplier: non_empty(entry.supplier, index, "supplier")?,
            path,
            licence: non_empty(entry.licence, index, "licence")?,
            purl: non_empty(entry.purl, index, "purl")?,
            kind: entry.kind,
        });
    }
    Ok(BlobManifest { blobs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_kind_library_and_firmware() {
        let manifest = parse(
            "blobs:\n  - name: a\n    path: a.bin\n    kind: library\n  \
             - name: b\n    path: b.a\n    kind: firmware\n  - name: c\n    path: c.hex\n",
        )
        .unwrap();
        let kinds: Vec<Option<ImageType>> = manifest.blobs.iter().map(|b| b.kind).collect();
        assert_eq!(
            kinds,
            [Some(ImageType::Library), Some(ImageType::Firmware), None]
        );
    }

    #[test]
    fn parse_rejects_bogus_kind() {
        for kind in ["bogus", "Library", "''", "1", "[library]", "{a: 1}", "blob"] {
            let text = format!("blobs:\n  - name: a\n    path: a.bin\n    kind: {kind}\n");
            let err = parse(&text).unwrap_err();
            assert!(matches!(err, BlobError::Yaml(_)), "{kind}: {err}");
        }
        let err = parse("blobs:\n  - name: a\n    path: a.bin\n    kind: bogus\n").unwrap_err();
        assert!(err.to_string().contains("bogus"), "{err}");
    }
}
