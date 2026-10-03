//! Component-graph model and ingestion for rollcall.
//!
//! See [`model`] for the product → image → component model, evidence, confidence and
//! deterministic `bom-ref` derivation, and [`cyclonedx`] for CycloneDX 1.6 output, input and
//! schema validation. [`zephyr`] ingests a Zephyr image (or sysbuild) build directory into
//! the model, [`blob`] turns a blob manifest into opaque blob images, and [`merge`] combines
//! separately generated products into one. [`subsystems`] is the table of Zephyr subsystems
//! (enabling Kconfig symbols and source paths) used to split the kernel package, and
//! [`linker_map`] parses the GNU ld map that split is cross-checked against. [`vex`]
//! evaluates VEX rules against scanner findings and build evidence. [`validate`] checks a
//! CycloneDX document against regulators' SBOM profiles (CISA 2026, CRA). [`report`] builds
//! the readiness report (Markdown and JSON) for an SBOM. [`scan`] normalises grype and
//! osv-scanner findings for an SBOM, triages them with VEX documents and decides
//! `rollcall scan`'s exit code. Both use [`severity`] to normalise scanners' severity words.

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

pub mod blob;
pub mod cyclonedx;
pub mod identify;
pub mod linker_map;
pub mod merge;
pub mod model;
pub mod report;
pub mod scan;
pub mod severity;
pub mod subsystems;
pub mod validate;
pub mod vex;
pub mod warning;
pub mod zephyr;

pub use blob::{BlobError, BlobImage, BlobIngest};
pub use cyclonedx::{
    ReadError, SchemaViolation, SerialNumber, Timestamp, WriteError, WriteOptions,
    validate_cyclonedx_1_6,
};
pub use identify::{IdentifierDb, Level, Resolver};
pub use merge::{ProductSpec, ProductSpecError};
pub use subsystems::{Subsystem, SubsystemTable, SubsystemsError};
pub use warning::Warning;

pub use model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, EvidenceSet, Hash,
    HashAlgorithm, IdError, Image, ImageKind, License, MergeError, ModelError, NodeLevel, NodePath,
    NodeRef, Occurrence, PathSegment, Product, Purl, Schema, Supplier, Technique, ValidationError,
};

pub use zephyr::{Ingest, IngestOptions, ZephyrError};
