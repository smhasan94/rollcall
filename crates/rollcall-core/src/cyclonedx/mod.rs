//! CycloneDX 1.6 JSON output and schema validation.
//!
//! [`write()`] turns a [`Product`] into a CycloneDX 1.6 JSON document; [`to_document`] gives the
//! same document as a value. [`validate_cyclonedx_1_6`] checks any JSON value against the
//! official CycloneDX 1.6 JSON schema, vendored verbatim under `schema/cyclonedx/` and compiled
//! into the crate, so validation works offline.
//!
//! ```
//! use rollcall_core::cyclonedx::{self, Timestamp, WriteOptions};
//! use rollcall_core::model::{Image, ImageKind, Product};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut product = Product::new("widget")?.with_version("1.0.0");
//! product.add_image(Image::new(ImageKind::Application, "widget-app")?)?;
//!
//! let options = WriteOptions::new(Timestamp::parse("2026-01-02T03:04:05Z")?);
//! let json = cyclonedx::write(&product, &options)?;
//! let value: serde_json::Value = serde_json::from_str(&json)?;
//! assert!(cyclonedx::validate_cyclonedx_1_6(&value).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! # Mapping
//!
//! Every field of the model is written somewhere, or listed under *Not represented* below.
//!
//! | Model | CycloneDX 1.6 |
//! |-------|---------------|
//! | — | `bomFormat` `"CycloneDX"`, `specVersion` `"1.6"`, `version` `1` |
//! | — | `serialNumber`: [`WriteOptions::serial_number`], else [`SerialNumber::derive`] |
//! | — | `metadata.timestamp`: [`WriteOptions::timestamp`] |
//! | — | `metadata.tools.components[0]`: `{type: application, name: rollcall, version}` |
//! | [`Product`] | `metadata.component`, `type` `firmware`; no nested `components` (osv-scanner ignores components under the root) |
//! | [`Product::images`], each [`Image`](crate::model::Image) | a top-level `components[]` entry, `type` `firmware` |
//! | [`Image::kind`](crate::model::Image::kind) | property `rollcall:image-kind` = `bootloader` \| `application` \| `blob` |
//! | [`Image::components`](crate::model::Image::components) | that image entry's nested `components` |
//! | [`Component`](crate::model::Component) | a nested `components[]` entry, `type` = [`ComponentKind::as_str`](crate::model::ComponentKind::as_str) |
//! | [`Component::components`](crate::model::Component::components) | its nested `components`, to any depth |
//! | node path | `bom-ref` = [`BomRef::derive`](crate::model::BomRef::derive) of the node's path, as [`Product::walk`] derives it |
//! | `name`, `version` | `name`, `version` |
//! | `supplier` | `supplier.name`, `supplier.url[]` (sorted) |
//! | `purl`, `cpe` | `purl`, `cpe` |
//! | `hashes` | `hashes[]` of `{alg, content}`, sorted by algorithm |
//! | `licence` | `licenses: [{expression}]` |
//! | [`Product::dependencies`] | `dependencies[]`: one entry per node in walk order (product, each image, its components depth-first); `dependsOn` is that node's edges, sorted, or `[]` when it has none. Containment is not turned into edges. |
//! | `name`/`version`/`purl`/`cpe`/`hash` evidence | `evidence.identity[]`, one entry per field present, in that order: `confidence` = the highest for the field; `concludedValue` = the node's stored value (omitted for `hash` and when the node has none); `methods[]` = one `{technique, confidence, value}` per [`Evidence`](crate::model::Evidence), in set order |
//! | evidence `occurrence` | `evidence.occurrences[]` of `{location, line}` for the node (not per identity entry), de-duplicated and sorted |
//! | `licence` evidence | `evidence.licenses`: `[{expression}]` when there is one distinct value, else `[{license: {name}}…]` sorted |
//! | evidence `source` | property `rollcall:evidence-source`, one per distinct source |
//! | [`Confidence`](crate::model::Confidence) | a number from [`Confidence::as_f64`](crate::model::Confidence::as_f64), e.g. 9500 bp → `0.95` |
//!
//! Properties sort by (name, value). Empty arrays and an empty `evidence` object are omitted,
//! except `dependsOn`, which is always present.
//!
//! # Determinism
//!
//! The same model and [`WriteOptions`] always give byte-identical output. Every array is built
//! from sorted (`BTreeSet`/`BTreeMap`) iteration or from [`Product::walk`], never from hash
//! order; keys appear in a fixed declaration order; confidences are exact basis-point
//! fractions. The serial number is derived from the model's content only, so it does not
//! change with the timestamp or the rollcall version; the timestamp is the only value that
//! varies between runs unless [`WriteOptions::timestamp`] is fixed.
//!
//! # Not represented
//!
//! - `supplier` evidence: CycloneDX 1.6 has no evidence field for the supplier. The entry's
//!   source is still listed as a `rollcall:evidence-source` property.
//! - Which source reported which identity method: `methods[]` has no source field, so sources
//!   are listed per node, not per method.
//! - Which evidence entry an occurrence belongs to: occurrences are node-level in CycloneDX.
//! - The internal schema tag (`rollcall-model/1`).
//!
//! # Known scanner behaviour
//!
//! grype (verified with 0.119.0) silently ignores components whose `type` is
//! `operating-system`: it treats them as distro information rather than packages, so it does
//! not scan them for vulnerabilities. The writer keeps the model's
//! [`ComponentKind::OperatingSystem`](crate::model::ComponentKind::OperatingSystem) label
//! anyway, because it is accurate; how an RTOS kernel such as Zephyr is typed is decided at
//! ingestion. osv-scanner is unaffected.

mod document;
mod schema;
mod serial;
mod timestamp;
mod writer;

pub use document::{
    Bom, Component, Dependency, Evidence, Hash, Identity, LicenseChoice, Metadata, Method,
    NamedLicense, Occurrence, Property, Supplier, Tool, Tools,
};
pub use schema::{
    BOM_1_6_SCHEMA, BOM_1_6_SCHEMA_SHA256, JSF_0_82_SCHEMA, JSF_0_82_SCHEMA_SHA256, SPDX_SCHEMA,
    SPDX_SCHEMA_SHA256, SchemaViolation, validate_cyclonedx_1_6,
};
pub use serial::SerialNumber;
pub use timestamp::Timestamp;

use crate::model::{Product, ValidationError, to_canonical_json};

/// Options for [`write()`] and [`to_document`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOptions {
    /// Written to `metadata.timestamp`.
    pub timestamp: Timestamp,
    /// Written to `serialNumber`; when `None`, [`SerialNumber::derive`] is used.
    pub serial_number: Option<SerialNumber>,
}

impl WriteOptions {
    /// Options with this timestamp and a derived serial number.
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            serial_number: None,
        }
    }

    /// Uses `serial_number` verbatim instead of deriving one.
    pub fn with_serial_number(mut self, serial_number: SerialNumber) -> Self {
        self.serial_number = Some(serial_number);
        self
    }
}

/// Error returned by [`write()`] and [`to_document`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WriteError {
    /// The product breaks a model invariant ([`Product::validate`]).
    #[error("invalid model: {0}")]
    Invalid(#[from] ValidationError),
    /// Serialisation failed.
    #[error("cannot serialise CycloneDX JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Error returned when parsing a [`Timestamp`] or [`SerialNumber`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Not an RFC 3339 date-time with an offset.
    #[error("invalid timestamp {input:?}: {reason} (expected RFC 3339, e.g. 2026-01-02T03:04:05Z)")]
    Timestamp {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: String,
    },
    /// Not `urn:uuid:` and a lowercase 8-4-4-4-12 UUID.
    #[error("invalid serial number {input:?}: {reason}")]
    SerialNumber {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

/// Maps `product` to a CycloneDX 1.6 document, after checking it with [`Product::validate`].
pub fn to_document(product: &Product, options: &WriteOptions) -> Result<Bom, WriteError> {
    writer::to_document(product, options)
}

/// Writes `product` as CycloneDX 1.6 JSON: two-space indented, keys in a fixed order, and a
/// trailing newline (see [`to_canonical_json`]).
pub fn write(product: &Product, options: &WriteOptions) -> Result<String, WriteError> {
    let bom = to_document(product, options)?;
    to_canonical_json(&bom).map_err(|e| match e {
        crate::model::ModelError::Json(e) => WriteError::Json(e),
        // `to_canonical_json` only fails while serialising.
        other => WriteError::Json(serde::ser::Error::custom(other)),
    })
}
