//! Component-graph model and ingestion for rollcall.
//!
//! See [`model`] for the product → image → component model, evidence, confidence and
//! deterministic `bom-ref` derivation.

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

pub mod model;

pub use model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, EvidenceSet, Hash,
    HashAlgorithm, IdError, Image, ImageKind, License, MergeError, ModelError, NodeLevel, NodePath,
    NodeRef, Occurrence, PathSegment, Product, Purl, Schema, Supplier, Technique, ValidationError,
};
