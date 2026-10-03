//! The CycloneDX 1.6 JSON document, as the subset rollcall writes.
//!
//! Each struct declares its fields in output order, and every optional field is skipped when
//! absent or empty, so serialising with [`to_canonical_json`](crate::model::to_canonical_json)
//! gives stable bytes. Collections are `Vec`s built from sorted (BTree) iteration by the
//! writer; nothing here sorts.

use serde::Serialize;

use crate::model::{EvidenceField, Technique};

/// A CycloneDX 1.6 BOM.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Bom {
    /// Always `"CycloneDX"`.
    #[serde(rename = "bomFormat")]
    pub bom_format: &'static str,
    /// Always `"1.6"`.
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,
    /// `urn:uuid:…`.
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    /// The BOM version; always 1.
    pub version: u32,
    /// Timestamp, tool and the product (root component).
    pub metadata: Metadata,
    /// The images, each with its components nested under it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    /// One entry per node.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
}

/// `metadata`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Metadata {
    /// When the document was written (RFC 3339, UTC).
    pub timestamp: String,
    /// The tool that wrote it.
    pub tools: Tools,
    /// The product.
    pub component: Component,
    /// Document-level properties ([`WriteOptions::properties`](super::WriteOptions)), sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

/// `metadata.tools`, in the 1.5+ object form.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Tools {
    /// The tools, as components.
    pub components: Vec<Tool>,
}

/// One tool in `metadata.tools.components`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Tool {
    /// Always `"application"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The tool name.
    pub name: &'static str,
    /// The tool version.
    pub version: &'static str,
}

/// A component (the product, an image, or a component at any depth).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Component {
    /// The CycloneDX component type.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The node's stable ref.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// The name.
    pub name: String,
    /// The version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `required`, `optional` or `excluded`; omitted when the model has none (CycloneDX's
    /// default is `required`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<&'static str>,
    /// The supplier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplier: Option<Supplier>,
    /// The package URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// The CPE.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// Content hashes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Hash>,
    /// The concluded licence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<LicenseChoice>,
    /// Where the facts came from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// `rollcall:*` properties.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
    /// Nested components.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
}

/// An organisational entity (`supplier`).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Supplier {
    /// The name.
    pub name: String,
    /// URLs, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub url: Vec<String>,
}

/// A hash.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Hash {
    /// The CycloneDX algorithm name.
    pub alg: &'static str,
    /// Lowercase hex digest.
    pub content: String,
}

/// One entry of a `licenses` array: an SPDX expression or a named licence.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum LicenseChoice {
    /// `{"expression": …}`; must be the only entry of its array.
    Expression {
        /// The SPDX expression.
        expression: String,
    },
    /// `{"license": {"name": …}}`.
    License {
        /// The licence.
        license: NamedLicense,
    },
}

/// `{"name": …}` inside a `license`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NamedLicense {
    /// The licence name.
    pub name: String,
}

/// `evidence` on a component.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evidence {
    /// Identity evidence, one entry per field.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub identity: Vec<Identity>,
    /// Where the evidence was found.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub occurrences: Vec<Occurrence>,
    /// Licence evidence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<LicenseChoice>,
}

impl Evidence {
    /// Whether every part is empty (the object would serialise as `{}`).
    pub fn is_empty(&self) -> bool {
        self.identity.is_empty() && self.occurrences.is_empty() && self.licenses.is_empty()
    }
}

/// One `evidence.identity[]` entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Identity {
    /// The identity field: `name`, `version`, `purl`, `cpe` or `hash` (serialised as
    /// CycloneDX names them).
    pub field: EvidenceField,
    /// The highest confidence of any method; omitted for an additional CPE nothing observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// The node's value for the field.
    #[serde(rename = "concludedValue", skip_serializing_if = "Option::is_none")]
    pub concluded_value: Option<String>,
    /// One per observation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<Method>,
}

/// One `methods[]` entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Method {
    /// The technique (serialised as its CycloneDX name).
    pub technique: Technique,
    /// The observation's confidence.
    pub confidence: f64,
    /// The value observed.
    pub value: String,
}

/// One `evidence.occurrences[]` entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Occurrence {
    /// Relative path.
    pub location: String,
    /// 1-based line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// A `{name, value}` property.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Property {
    /// The property name.
    pub name: &'static str,
    /// The property value.
    pub value: String,
}

/// A `dependencies[]` entry.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Dependency {
    /// The node.
    #[serde(rename = "ref")]
    pub bom_ref: String,
    /// What it depends on, sorted; empty when nothing is known.
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>,
}
