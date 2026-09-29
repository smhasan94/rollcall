//! The component-graph model: what a firmware product is made of, and how we know.
//!
//! Every ingester (Zephyr `west spdx`, `west list`, Kconfig, MCUboot, …) writes into this
//! model, and every emitter (CycloneDX, VEX, …) reads from it. It is deliberately small, fully
//! ordered and serialisable, so that the same inputs always produce the same model and the
//! same bytes.
//!
//! # Hierarchy
//!
//! - A [`Product`] is the shipped thing. It holds product-level facts, a set of [`Image`]s and
//!   the dependency edges between nodes.
//! - An [`Image`] is one firmware image in the product. Its [`ImageKind`] is `bootloader`
//!   (e.g. MCUboot), `application` (e.g. the Zephyr application) or `blob` (an opaque binary
//!   such as radio firmware).
//! - A [`Component`] is something built into an image, typed with a CycloneDX 1.6
//!   [`ComponentKind`]. Components can contain subcomponents to any depth (e.g. the Zephyr
//!   kernel package broken down into subsystems).
//!
//! Every node carries the same facts: name, version, supplier, [`Purl`], [`Cpe`], [`Hash`](struct@Hash)es
//! (at most one per algorithm), a [`License`] expression, and an [`EvidenceSet`].
//!
//! A node's *identity* is `(kind, name, version)` ([`Component::key`], [`Image::key`]).
//! Siblings never share an identity: [`Product::add_image`], [`Image::add_component`] and
//! [`Component::add_component`] merge a node whose identity is already present into the
//! existing one, and [`Product::validate`] rejects a model where two siblings share one.
//!
//! Merging follows one rule for every optional fact: missing takes the incoming value,
//! equal is kept, different is a [`MergeError::Conflict`]. Hashes merge per algorithm under
//! the same rule; evidence is unioned; subcomponents merge recursively by identity. A merge
//! is atomic: when it fails the target is left exactly as it was.
//!
//! # Evidence
//!
//! Each fact in the model should be traceable to where it came from. An [`Evidence`] entry
//! records one observation of one fact:
//!
//! - `field` — which fact it supports ([`EvidenceField`]: name, version, purl, cpe, hash,
//!   licence or supplier);
//! - `technique` — how it was established, as a CycloneDX 1.6 identity technique
//!   ([`Technique`], e.g. `manifest-analysis`, `hash-comparison`);
//! - `source` — the input that produced it, e.g. `west-spdx`;
//! - `occurrence` — optionally, where in that input: a forward-slash relative path and line
//!   ([`Occurrence`]), never an absolute build-machine path;
//! - `value` — the value that source saw, as text;
//! - `confidence` — how sure that source is (see below).
//!
//! When the same component is seen by two sources (say `west spdx` and `west list`), merging
//! keeps one component with both sources' evidence, so the output can show that two
//! independent inputs agree. An [`EvidenceSet`] holds at most one entry per observation
//! ([`Evidence::key`]: every field except confidence); re-reporting the same observation keeps
//! the higher confidence.
//!
//! Mapping to CycloneDX 1.6 evidence: `name`, `version`, `purl`, `cpe` and `hash` evidence
//! map to `evidence.identity[].field` (with `technique`, `confidence` and `occurrence` as that
//! identity entry's methods and occurrences); `licence` evidence maps to `evidence.licenses`;
//! `supplier` evidence has no CycloneDX evidence field and is kept internal to rollcall.
//!
//! # Confidence
//!
//! [`Confidence`] is stored in basis points, `0..=10000` (`Confidence::NONE` to
//! `Confidence::FULL`), so it orders, compares and serialises exactly. [`Confidence::from_f64`]
//! converts a fraction, rounding to the nearest basis point, and [`Confidence::as_f64`]
//! converts back.
//!
//! The combination rule is **maximum**: repeated observations of the same fact, and a node's
//! overall [`Component::confidence`], take the highest confidence present. Agreement between
//! sources is visible as multiple evidence entries rather than as an inflated number, and a
//! weak source never lowers a strong one. [`Component::confidence_for`] gives the confidence
//! for one fact.
//!
//! # Determinism and bom-refs
//!
//! Nothing in the model depends on insertion order or randomness. Sets and maps are
//! `BTreeSet`/`BTreeMap`; nodes sort by identity first; evidence sorts by its fields; hashes
//! sort by algorithm and digest. Serialising the same model twice gives byte-identical output,
//! and adding one component changes only that component's lines.
//!
//! A node's [`BomRef`] is derived from its [`NodePath`] — the levels, kinds, names and versions
//! from the product root down to the node — by [`BomRef::derive`]: SHA-256 over an unambiguous
//! length-prefixed encoding, truncated to 128 bits, written `<level>:<32 hex>` (e.g.
//! `component:ea5acaf79b26b412fa4e30fb33143147`). A ref never changes unless the node's
//! identity or position changes, and does not depend on hashes, licences, purls or evidence.
//! The same library in two images has two paths and so two refs. [`Product::walk`] yields
//! every node with its path and ref, and [`Product::resolve`] looks a ref up.
//!
//! # Internal JSON form
//!
//! [`Product::to_json`] writes the model as pretty-printed JSON with a trailing newline (see
//! [`to_canonical_json`]); [`Product::from_json`] and [`Product::from_json_bytes`] read it
//! back and run [`Product::validate`]. The top-level `schema` field is always
//! `"rollcall-model/1"`. Unknown fields are rejected at every level, and every identifier is
//! re-validated on the way in, so model → JSON → model is lossless. This form is for fixtures
//! and debugging; it is not CycloneDX.
//!
//! ```
//! use rollcall_core::model::{
//!     Component, ComponentKind, Confidence, Evidence, EvidenceField, Image, ImageKind,
//!     License, Product, Purl, Technique,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut product = Product::new("widget")?.with_version("1.0.0");
//! let mut app = Image::new(ImageKind::Application, "widget-app")?;
//!
//! // The same component, seen by two sources.
//! let mut from_spdx = Component::new(ComponentKind::Library, "mbedtls")?.with_version("3.6.0");
//! from_spdx.purl = Some(Purl::new("pkg:github/Mbed-TLS/mbedtls@v3.6.0")?);
//! from_spdx.evidence.insert(Evidence::new(
//!     EvidenceField::Purl,
//!     Technique::ManifestAnalysis,
//!     "west-spdx",
//!     "pkg:github/Mbed-TLS/mbedtls@v3.6.0",
//!     Confidence::from_f64(0.9)?,
//! )?);
//!
//! let mut from_list = Component::new(ComponentKind::Library, "mbedtls")?.with_version("3.6.0");
//! from_list.licence = Some(License::new("Apache-2.0 OR GPL-2.0-or-later")?);
//! from_list.evidence.insert(Evidence::new(
//!     EvidenceField::Licence,
//!     Technique::SourceCodeAnalysis,
//!     "west-list",
//!     "Apache-2.0 OR GPL-2.0-or-later",
//!     Confidence::from_f64(0.6)?,
//! )?);
//!
//! app.add_component(from_spdx)?;
//! app.add_component(from_list)?; // merges: one component, both facts, both evidence entries
//! product.add_image(app)?;
//!
//! let json = product.to_json()?;
//! println!("{json}");
//! assert_eq!(Product::from_json(&json)?, product);
//! # Ok(())
//! # }
//! ```

mod bom_ref;
mod confidence;
mod evidence;
mod graph;
mod ids;
mod json;

pub use bom_ref::{BomRef, NodeLevel, NodePath, PathSegment};
pub use confidence::Confidence;
pub use evidence::{Evidence, EvidenceField, EvidenceKey, EvidenceSet, Occurrence, Technique};
pub use graph::{Component, Image, MergeError, NodeRef, Product, Schema, ValidationError};
pub use ids::{
    ComponentKind, Cpe, Hash, HashAlgorithm, IdError, ImageKind, License, Purl, Supplier,
};
pub use json::{ModelError, to_canonical_json};
