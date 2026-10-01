//! CycloneDX 1.6 document → model. See the [module docs](super) for the mapping it inverts.
//!
//! The reader is written for documents rollcall produced, for which it is lossless:
//! `read(write(p)) == p`. Each node's facts are read from the component fields, its evidence
//! from its `rollcall:evidence` properties (the CycloneDX `evidence` object is derived from
//! those and is not read), and dependency edges are translated from the document's `bom-ref`s
//! to the paths of the nodes that carry them.
//!
//! Other CycloneDX 1.6 documents are read leniently, each change with a [`Warning`]:
//!
//! - a top-level component without a `rollcall:image-kind` property is an `application` image;
//! - a top-level component whose `type` is not `firmware`, `application` or `device` (e.g. a
//!   `framework`) is still read as an image, and the warning names its original type. A
//!   `library` is read as an image of type [`ImageType::Library`]; it warns unless its
//!   `rollcall:image-kind` is `blob` (rollcall writes static-archive blobs as `library`);
//! - evidence that is not in `rollcall:evidence` properties is dropped;
//! - `syft:cpe23` properties are a component's additional CPEs; on a product or image, on a
//!   component without a `cpe`, or when the value is not a CPE 2.3 name, they are dropped
//!   (one repeating the `cpe` is ignored silently);
//! - components nested under `metadata.component` are dropped, and so is every dependency
//!   edge to or from one of them or to or from a `services[]` entry.
//!
//! Hash digests are read case-insensitively (CycloneDX allows upper-case hex) and stored in
//! lower case. Anything that does not fit the model (an unknown component type, an invalid
//! purl, a dependency on a ref that is nowhere in the document, …) is a [`ReadError`]. The reader never panics; the nesting depth
//! of a document read with [`read_str`] or [`read_bytes`] is bounded by `serde_json`'s
//! recursion limit.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::{IgnoredAny, IntoDeserializer};
use serde_json::Value;

use super::writer::{ADDITIONAL_CPE, EVIDENCE_PROPERTY, IMAGE_KIND};
use crate::model::{
    BomRef, Component, ComponentKind, Cpe, Evidence, EvidenceSet, Hash, HashAlgorithm, IdError,
    Image, ImageKind, ImageType, License, MergeError, NodePath, PathSegment, Product, Purl,
    Supplier, ValidationError,
};
use crate::warning::Warning;

/// The result of [`read`]: the product and any non-fatal problems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    /// The product the document describes.
    pub product: Product,
    /// What could not be represented and was dropped, in document order.
    pub warnings: Vec<Warning>,
    /// Each `bom-ref` in the document that names a node of `product`, with that node's path.
    /// rollcall derives its own refs from paths ([`BomRef::derive`]); this table maps them
    /// back to the document's, which may differ for documents rollcall did not write.
    pub refs: BTreeMap<String, NodePath>,
}

/// Why a CycloneDX document could not be read into the model.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReadError {
    /// Not JSON, or a field has the wrong JSON type.
    #[error("invalid CycloneDX JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The bytes are not UTF-8.
    #[error("not UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// The document is not a CycloneDX BOM.
    #[error("not a CycloneDX document: {0}")]
    NotCycloneDx(String),
    /// The document is CycloneDX, but not version 1.6.
    #[error("unsupported CycloneDX specVersion {0:?} (rollcall reads 1.6)")]
    SpecVersion(String),
    /// There is no `metadata.component`, so no product.
    #[error("no metadata.component: the document names no product")]
    MissingRoot,
    /// A component's `type` is not a CycloneDX 1.6 component type.
    #[error("{at}: unknown component type {kind:?}")]
    UnknownComponentType {
        /// The component.
        at: String,
        /// The rejected type.
        kind: String,
    },
    /// A `rollcall:image-kind` property is not `bootloader`, `application` or `blob`.
    #[error("{at}: unknown {IMAGE_KIND} {kind:?}")]
    UnknownImageKind {
        /// The image.
        at: String,
        /// The rejected kind.
        kind: String,
    },
    /// A dependency names a `bom-ref` that no component carries.
    #[error("dependencies: unknown bom-ref {0:?}")]
    UnknownRef(String),
    /// Two components that are not the same node carry the same `bom-ref`.
    #[error("bom-ref {0:?} is carried by two different components")]
    DuplicateRef(String),
    /// A value is rejected by the model (an empty name, an invalid purl, cpe, licence, …).
    #[error("{at}: {source}")]
    Id {
        /// The component.
        at: String,
        /// The model's objection.
        source: IdError,
    },
    /// A `rollcall:evidence` property is not a valid evidence entry.
    #[error("{at}: malformed {EVIDENCE_PROPERTY} property: {source}")]
    Evidence {
        /// The component.
        at: String,
        /// Why.
        source: serde_json::Error,
    },
    /// Two components that merge into one node disagree about a fact.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// The product read breaks a model invariant.
    #[error("invalid model: {0}")]
    Validation(#[from] ValidationError),
}

#[derive(Deserialize)]
struct RawBom {
    #[serde(default)]
    metadata: Option<RawMetadata>,
    #[serde(default)]
    components: Vec<RawComponent>,
    #[serde(default)]
    dependencies: Vec<RawDependency>,
    #[serde(default)]
    services: Vec<RawService>,
}

#[derive(Deserialize)]
struct RawService {
    #[serde(rename = "bom-ref", default)]
    bom_ref: Option<String>,
    #[serde(default)]
    services: Vec<RawService>,
}

#[derive(Deserialize)]
struct RawMetadata {
    #[serde(default)]
    component: Option<RawComponent>,
}

#[derive(Deserialize)]
struct RawComponent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "bom-ref", default)]
    bom_ref: Option<String>,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    supplier: Option<RawSupplier>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    hashes: Vec<RawHash>,
    #[serde(default)]
    licenses: Vec<RawLicenseChoice>,
    #[serde(default)]
    evidence: Option<IgnoredAny>,
    #[serde(default)]
    properties: Vec<RawProperty>,
    #[serde(default)]
    components: Vec<RawComponent>,
}

#[derive(Deserialize)]
struct RawSupplier {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Vec<String>,
}

#[derive(Deserialize)]
struct RawHash {
    alg: String,
    content: String,
}

#[derive(Deserialize)]
struct RawLicenseChoice {
    #[serde(default)]
    expression: Option<String>,
    #[serde(default)]
    license: Option<RawLicense>,
}

#[derive(Deserialize)]
struct RawLicense {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct RawProperty {
    name: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct RawDependency {
    #[serde(rename = "ref")]
    bom_ref: String,
    #[serde(rename = "dependsOn", default)]
    depends_on: Vec<String>,
}

/// The facts every node level shares.
struct Facts {
    supplier: Option<Supplier>,
    purl: Option<Purl>,
    cpe: Option<Cpe>,
    hashes: std::collections::BTreeSet<Hash>,
    licence: Option<License>,
    evidence: EvidenceSet,
}

/// Sets the shared facts on a product, image or component.
macro_rules! apply_facts {
    ($node:expr, $facts:expr) => {{
        let facts = $facts;
        $node.supplier = facts.supplier;
        $node.purl = facts.purl;
        $node.cpe = facts.cpe;
        $node.hashes = facts.hashes;
        $node.licence = facts.licence;
        $node.evidence = facts.evidence;
    }};
}

/// Top-level component types that are read as images without a warning.
const IMAGE_TYPES: [&str; 3] = ["firmware", "application", "device"];

/// State shared while walking the document.
#[derive(Default)]
struct Reader {
    /// Each document `bom-ref` and the path of the node carrying it.
    refs: BTreeMap<String, NodePath>,
    /// `bom-ref`s that are in the document but carried by nothing the model reads, and why.
    dropped: BTreeMap<String, &'static str>,
    warnings: Vec<Warning>,
}

impl Reader {
    fn warn(&mut self, at: &str, message: impl Into<String>) {
        self.warnings.push(Warning::new(at, message));
    }

    /// Records that `raw`'s `bom-ref` (if any) names the node at `path`.
    fn bind(&mut self, raw: &RawComponent, path: &NodePath) -> Result<(), ReadError> {
        let Some(bom_ref) = &raw.bom_ref else {
            return Ok(());
        };
        match self.refs.get(bom_ref) {
            Some(existing) if existing != path => Err(ReadError::DuplicateRef(bom_ref.clone())),
            Some(_) => Ok(()),
            None => {
                self.refs.insert(bom_ref.clone(), path.clone());
                Ok(())
            }
        }
    }

    /// A component's additional CPEs from its `syft:cpe23` properties. Lenient, as for other
    /// foreign input: a value that is not a CPE 2.3 name is dropped with a warning, the primary
    /// CPE repeated is ignored, and without a primary CPE all are dropped with a warning.
    fn additional_cpes(
        &mut self,
        raw: &RawComponent,
        primary: Option<&Cpe>,
        at: &str,
    ) -> std::collections::BTreeSet<Cpe> {
        let mut out = std::collections::BTreeSet::new();
        for property in raw.properties.iter().filter(|p| p.name == ADDITIONAL_CPE) {
            let value = property.value.as_deref().unwrap_or("");
            match Cpe::new(value) {
                Ok(cpe) if Some(&cpe) == primary => {}
                Ok(cpe) => {
                    out.insert(cpe);
                }
                Err(e) => self.warn(
                    at,
                    format!("{ADDITIONAL_CPE} value {value:?} is not a CPE ({e}); dropped"),
                ),
            }
        }
        if primary.is_none() && !out.is_empty() {
            self.warn(
                at,
                format!("{ADDITIONAL_CPE} properties without a cpe; dropped"),
            );
            out.clear();
        }
        out
    }

    /// Products and images hold no additional CPEs: warns when the document gives some.
    fn drop_additional_cpes(&mut self, raw: &RawComponent, at: &str) {
        if raw.properties.iter().any(|p| p.name == ADDITIONAL_CPE) {
            self.warn(
                at,
                format!("{ADDITIONAL_CPE} properties on a product or image are not read; dropped"),
            );
        }
    }

    fn facts(&mut self, raw: &RawComponent, at: &str) -> Result<Facts, ReadError> {
        let id = |source: IdError| ReadError::Id {
            at: at.to_owned(),
            source,
        };
        let supplier = match &raw.supplier {
            None => None,
            Some(RawSupplier { name: None, .. }) => {
                self.warn(at, "supplier without a name; dropped");
                None
            }
            Some(RawSupplier {
                name: Some(name),
                url,
            }) => Some(
                url.iter()
                    .try_fold(Supplier::new(name).map_err(id)?, |s, u| s.with_url(u))
                    .map_err(id)?,
            ),
        };
        let purl = raw.purl.as_deref().map(Purl::new).transpose().map_err(id)?;
        let cpe = raw.cpe.as_deref().map(Cpe::new).transpose().map_err(id)?;
        let mut hashes = std::collections::BTreeSet::new();
        for hash in &raw.hashes {
            let algorithm: Result<HashAlgorithm, serde::de::value::Error> =
                HashAlgorithm::deserialize(hash.alg.as_str().into_deserializer());
            match algorithm {
                Ok(algorithm) => {
                    // CycloneDX `hash-content` allows upper-case hex; the model stores lower.
                    let content = hash.content.to_ascii_lowercase();
                    hashes.insert(Hash::new(algorithm, &content).map_err(id)?);
                }
                Err(_) => self.warn(
                    at,
                    format!("unknown hash algorithm {:?}; hash dropped", hash.alg),
                ),
            }
        }
        let licence = self.licence(&raw.licenses, at)?;

        let mut evidence = EvidenceSet::new();
        let mut any_evidence_property = false;
        for property in raw
            .properties
            .iter()
            .filter(|p| p.name == EVIDENCE_PROPERTY)
        {
            any_evidence_property = true;
            let entry: Evidence = serde_json::from_str(property.value.as_deref().unwrap_or(""))
                .map_err(|source| ReadError::Evidence {
                    at: at.to_owned(),
                    source,
                })?;
            evidence.insert(entry);
        }
        if raw.evidence.is_some() && !any_evidence_property {
            self.warn(
                at,
                format!("evidence without {EVIDENCE_PROPERTY} properties is not read; dropped"),
            );
        }
        Ok(Facts {
            supplier,
            purl,
            cpe,
            hashes,
            licence,
            evidence,
        })
    }

    /// The concluded licence: one SPDX expression, or one licence by id or (valid SPDX) name.
    fn licence(
        &mut self,
        choices: &[RawLicenseChoice],
        at: &str,
    ) -> Result<Option<License>, ReadError> {
        let id = |source: IdError| ReadError::Id {
            at: at.to_owned(),
            source,
        };
        let [only] = choices else {
            if !choices.is_empty() {
                self.warn(
                    at,
                    format!(
                        "{} licences where the model holds one expression; dropped",
                        choices.len()
                    ),
                );
            }
            return Ok(None);
        };
        match (&only.expression, &only.license) {
            (Some(expression), _) => Ok(Some(License::new(expression).map_err(id)?)),
            (None, Some(RawLicense { id: Some(spdx), .. })) => {
                Ok(Some(License::new(spdx).map_err(id)?))
            }
            (
                None,
                Some(RawLicense {
                    name: Some(name), ..
                }),
            ) => match License::new(name) {
                Ok(licence) => Ok(Some(licence)),
                Err(_) => {
                    self.warn(
                        at,
                        format!("licence name {name:?} is not an SPDX expression; dropped"),
                    );
                    Ok(None)
                }
            },
            _ => {
                self.warn(at, "licence without an expression, id or name; dropped");
                Ok(None)
            }
        }
    }

    fn component(&mut self, raw: &RawComponent, parent: &NodePath) -> Result<Component, ReadError> {
        let named = format!("{parent} / {}", raw.name);
        let kind: ComponentKind = ComponentKind::deserialize(raw.kind.as_str().into_deserializer())
            .map_err(
                |_: serde::de::value::Error| ReadError::UnknownComponentType {
                    at: named.clone(),
                    kind: raw.kind.clone(),
                },
            )?;
        let mut component = Component::new(kind, &raw.name)
            .map_err(|source| ReadError::Id { at: named, source })?;
        component.version = raw.version.clone();
        let path = parent.child(PathSegment::of_component(&component));
        let at = path.to_string();
        self.bind(raw, &path)?;
        let facts = self.facts(raw, &at)?;
        component.additional_cpes = self.additional_cpes(raw, facts.cpe.as_ref(), &at);
        apply_facts!(component, facts);
        for child in &raw.components {
            let child = self.component(child, &path)?;
            component.add_component(child)?;
        }
        Ok(component)
    }

    fn image(&mut self, raw: &RawComponent, root: &NodePath) -> Result<Image, ReadError> {
        let named = format!("{root} / {}", raw.name);
        let component_type: ComponentKind =
            ComponentKind::deserialize(raw.kind.as_str().into_deserializer()).map_err(
                |_: serde::de::value::Error| ReadError::UnknownComponentType {
                    at: named.clone(),
                    kind: raw.kind.clone(),
                },
            )?;
        let kinds: Vec<&str> = raw
            .properties
            .iter()
            .filter(|p| p.name == IMAGE_KIND)
            .map(|p| p.value.as_deref().unwrap_or(""))
            .collect();
        let kind = match kinds.as_slice() {
            [] => {
                self.warn(
                    &named,
                    format!("no {IMAGE_KIND} property; read as an application image"),
                );
                ImageKind::Application
            }
            [kind] => ImageKind::deserialize(kind.into_deserializer()).map_err(
                |_: serde::de::value::Error| ReadError::UnknownImageKind {
                    at: named.clone(),
                    kind: (*kind).to_owned(),
                },
            )?,
            _ => {
                return Err(ReadError::UnknownImageKind {
                    at: named,
                    kind: kinds.join(", "),
                });
            }
        };
        let image_type = match component_type {
            ComponentKind::Library => ImageType::Library,
            _ => ImageType::Firmware,
        };
        let library_blob = image_type == ImageType::Library && kind == ImageKind::Blob;
        if !library_blob && !IMAGE_TYPES.contains(&component_type.as_str()) {
            self.warn(
                &named,
                format!(
                    "top-level component {:?} has type {:?}, not firmware, application or \
                     device; read as {} {} image",
                    raw.name,
                    component_type.as_str(),
                    if kind.as_str().starts_with(['a', 'e', 'i', 'o', 'u']) {
                        "an"
                    } else {
                        "a"
                    },
                    kind.as_str()
                ),
            );
        }
        let mut image =
            Image::new(kind, &raw.name).map_err(|source| ReadError::Id { at: named, source })?;
        image.version = raw.version.clone();
        image.image_type = image_type;
        let path = root.child(PathSegment::of_image(&image));
        let at = path.to_string();
        self.bind(raw, &path)?;
        let facts = self.facts(raw, &at)?;
        self.drop_additional_cpes(raw, &at);
        apply_facts!(image, facts);
        for child in &raw.components {
            let child = self.component(child, &path)?;
            image.add_component(child)?;
        }
        Ok(image)
    }

    /// Records the `bom-ref`s of `raw` and everything nested in it as dropped for `why`.
    fn drop_component_refs(&mut self, raw: &RawComponent, why: &'static str) {
        if let Some(bom_ref) = &raw.bom_ref {
            self.dropped.entry(bom_ref.clone()).or_insert(why);
        }
        for child in &raw.components {
            self.drop_component_refs(child, why);
        }
    }

    /// Records the `bom-ref`s of `service` and its nested services as dropped.
    fn drop_service_refs(&mut self, service: &RawService) {
        if let Some(bom_ref) = &service.bom_ref {
            self.dropped
                .entry(bom_ref.clone())
                .or_insert("a service, which is not read");
        }
        for child in &service.services {
            self.drop_service_refs(child);
        }
    }

    /// The node carrying `bom_ref`, or why it is in the document but not read
    /// (`Ok(Err(why))`); a ref that is nowhere in the document is [`ReadError::UnknownRef`].
    fn resolve(&self, bom_ref: &str) -> Result<Result<NodePath, &'static str>, ReadError> {
        if let Some(path) = self.refs.get(bom_ref) {
            return Ok(Ok(path.clone()));
        }
        match self.dropped.get(bom_ref) {
            Some(why) => Ok(Err(*why)),
            None => Err(ReadError::UnknownRef(bom_ref.to_owned())),
        }
    }
}

/// Reads a CycloneDX 1.6 document into a product, checked with [`Product::validate`].
pub fn read(document: &Value) -> Result<Read, ReadError> {
    let Some(object) = document.as_object() else {
        return Err(ReadError::NotCycloneDx("not a JSON object".to_owned()));
    };
    match object.get("bomFormat") {
        Some(Value::String(format)) if format == "CycloneDX" => {}
        Some(other) => {
            return Err(ReadError::NotCycloneDx(format!(
                "bomFormat is {other}, not \"CycloneDX\""
            )));
        }
        None => return Err(ReadError::NotCycloneDx("no bomFormat".to_owned())),
    }
    match object.get("specVersion") {
        Some(Value::String(version)) if version == "1.6" => {}
        Some(Value::String(version)) => return Err(ReadError::SpecVersion(version.clone())),
        Some(other) => return Err(ReadError::SpecVersion(other.to_string())),
        None => return Err(ReadError::SpecVersion(String::new())),
    }
    let bom = RawBom::deserialize(document)?;
    let root_raw = bom
        .metadata
        .as_ref()
        .and_then(|m| m.component.as_ref())
        .ok_or(ReadError::MissingRoot)?;

    let mut reader = Reader::default();
    let mut product = Product::new(&root_raw.name).map_err(|source| ReadError::Id {
        at: "metadata.component".to_owned(),
        source,
    })?;
    product.version = root_raw.version.clone();
    let root = product.path();
    let at = root.to_string();
    reader.bind(root_raw, &root)?;
    let facts = reader.facts(root_raw, &at)?;
    reader.drop_additional_cpes(root_raw, &at);
    apply_facts!(product, facts);
    if !root_raw.components.is_empty() {
        reader.warn(
            &at,
            "components nested under metadata.component are not read; dropped",
        );
    }
    for nested in &root_raw.components {
        reader.drop_component_refs(
            nested,
            "a component nested under metadata.component, which is not read",
        );
    }
    for service in &bom.services {
        reader.drop_service_refs(service);
    }
    for raw in &bom.components {
        let image = reader.image(raw, &root)?;
        product.add_image(image)?;
    }
    for dependency in &bom.dependencies {
        let from = match reader.resolve(&dependency.bom_ref)? {
            Ok(path) => BomRef::derive(&path),
            Err(why) => {
                // Still reject targets that are nowhere in the document.
                for target in &dependency.depends_on {
                    let _in_document = reader.resolve(target)?;
                }
                if !dependency.depends_on.is_empty() {
                    reader.warn(
                        "dependencies",
                        format!(
                            "{:?} is {why}; its {} dependency edge(s) dropped",
                            dependency.bom_ref,
                            dependency.depends_on.len()
                        ),
                    );
                }
                continue;
            }
        };
        for target in &dependency.depends_on {
            match reader.resolve(target)? {
                Ok(path) => product.add_dependency(from.clone(), BomRef::derive(&path)),
                Err(why) => reader.warn(
                    "dependencies",
                    format!(
                        "{:?} depends on {target:?}, which is {why}; edge dropped",
                        dependency.bom_ref
                    ),
                ),
            }
        }
    }
    product.validate()?;
    Ok(Read {
        product,
        warnings: reader.warnings,
        refs: reader.refs,
    })
}

/// Parses `text` as JSON and reads it with [`read`].
pub fn read_str(text: &str) -> Result<Read, ReadError> {
    let document: Value = serde_json::from_str(text)?;
    read(&document)
}

/// Checks `bytes` are UTF-8, then reads them with [`read_str`].
pub fn read_bytes(bytes: &[u8]) -> Result<Read, ReadError> {
    read_str(std::str::from_utf8(bytes)?)
}
