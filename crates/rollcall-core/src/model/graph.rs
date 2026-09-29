//! The product → image → component hierarchy, merging and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::bom_ref::{BomRef, NodePath, PathSegment};
use super::confidence::Confidence;
use super::evidence::{EvidenceField, EvidenceSet};
use super::ids::{
    ComponentKind, Cpe, Hash, HashAlgorithm, IdError, ImageKind, License, Purl, Supplier,
};

/// The internal JSON form's schema tag. Serialises as the constant `"rollcall-model/1"`;
/// any other value is rejected when deserialising.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum Schema {
    /// Version 1 of the internal model form.
    #[default]
    #[serde(rename = "rollcall-model/1")]
    V1,
}

/// Error returned when merging two nodes that disagree about a fact.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MergeError {
    /// Both sides have a value for `field` and the values differ. The merge target is left
    /// unchanged.
    #[error("conflicting {field} at {path}: existing {existing:?}, incoming {incoming:?}")]
    Conflict {
        /// The node the conflict is on, relative to the node the merge was called on.
        path: NodePath,
        /// The conflicting field, e.g. `licence` or `hashes[SHA-256]`.
        field: String,
        /// The value already present.
        existing: String,
        /// The value being merged in.
        incoming: String,
    },
}

/// Error returned by [`Product::validate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// A node has an empty name.
    #[error("empty name at {path}")]
    EmptyName {
        /// The node.
        path: NodePath,
    },
    /// A node's name is whitespace-only or contains a control character.
    #[error("invalid name at {path} (whitespace-only or contains a control character)")]
    InvalidName {
        /// The node.
        path: NodePath,
    },
    /// A node's version is whitespace-only or contains a control character.
    #[error("invalid version at {path} (whitespace-only or contains a control character)")]
    InvalidVersion {
        /// The node.
        path: NodePath,
    },
    /// A node has a version that is present but empty.
    #[error("empty version at {path} (omit the version instead)")]
    EmptyVersion {
        /// The node.
        path: NodePath,
    },
    /// Two siblings share a (kind, name, version) identity.
    #[error("duplicate sibling identity at {path}")]
    DuplicateSibling {
        /// The duplicated node.
        path: NodePath,
    },
    /// A node has two digests for the same hash algorithm.
    #[error("more than one {algorithm} digest at {path}")]
    DuplicateHashAlgorithm {
        /// The node.
        path: NodePath,
        /// The repeated algorithm.
        algorithm: HashAlgorithm,
    },
    /// A dependency edge names a `bom-ref` that is not in the product.
    #[error("dependency refers to unknown bom-ref {bom_ref}")]
    DanglingDependency {
        /// The unresolved ref.
        bom_ref: BomRef,
    },
    /// A dependency edge goes from a node to itself. Cycles between distinct nodes are
    /// allowed.
    #[error("{bom_ref} depends on itself")]
    SelfDependency {
        /// The node's ref.
        bom_ref: BomRef,
    },
    /// Two distinct paths derive the same `bom-ref`.
    #[error("bom-ref {bom_ref} derived for both {first} and {second}")]
    BomRefCollision {
        /// The shared ref.
        bom_ref: BomRef,
        /// The first path.
        first: NodePath,
        /// The second path.
        second: NodePath,
    },
}

/// A software or hardware component inside an image, or inside another component.
///
/// The identity fields (`kind`, `name`, `version`) come first, so the derived ordering sorts
/// siblings by identity. Siblings never share an identity: adding a component whose identity
/// is already present merges into it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    /// The component type (CycloneDX `type`). Part of the identity.
    pub kind: ComponentKind,
    /// The component name. Part of the identity; never empty.
    pub name: String,
    /// The component version, if known. Part of the identity; never empty when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Who supplied the component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<Supplier>,
    /// The component's package URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
    /// The component's CPE name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Cpe>,
    /// Content hashes, at most one per algorithm.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub hashes: BTreeSet<Hash>,
    /// The component's SPDX licence expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence: Option<License>,
    /// Where each fact above came from, and how sure each source is.
    #[serde(default, skip_serializing_if = "EvidenceSet::is_empty")]
    pub evidence: EvidenceSet,
    /// Subcomponents, sorted by identity.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub components: BTreeSet<Component>,
}

/// A firmware image in a product: a bootloader, an application or an opaque blob.
///
/// Same shape as [`Component`], with an [`ImageKind`] instead of a component kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    /// The image's role. Part of the identity.
    pub kind: ImageKind,
    /// The image name, e.g. `mcuboot` or the application name. Part of the identity; never
    /// empty.
    pub name: String,
    /// The image version, if known. Part of the identity; never empty when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Who supplied the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<Supplier>,
    /// The image's package URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
    /// The image's CPE name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Cpe>,
    /// Hashes of the image binary, at most one per algorithm.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub hashes: BTreeSet<Hash>,
    /// The image's SPDX licence expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence: Option<License>,
    /// Where each fact above came from, and how sure each source is.
    #[serde(default, skip_serializing_if = "EvidenceSet::is_empty")]
    pub evidence: EvidenceSet,
    /// The components built into the image, sorted by identity.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub components: BTreeSet<Component>,
}

/// The root of the model: one shipped product made of firmware images.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    /// The schema tag, always `"rollcall-model/1"`.
    pub schema: Schema,
    /// The product name. Part of the identity; never empty.
    pub name: String,
    /// The product version, if known. Part of the identity; never empty when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Who supplied the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<Supplier>,
    /// The product's package URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
    /// The product's CPE name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<Cpe>,
    /// Hashes of the product artefact, at most one per algorithm.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub hashes: BTreeSet<Hash>,
    /// The product's SPDX licence expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence: Option<License>,
    /// Where each fact above came from, and how sure each source is.
    #[serde(default, skip_serializing_if = "EvidenceSet::is_empty")]
    pub evidence: EvidenceSet,
    /// The product's images, sorted by identity.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub images: BTreeSet<Image>,
    /// Dependency edges: each key depends on every ref in its set. Keys and targets are
    /// `bom-ref`s of nodes in this product.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<BomRef, BTreeSet<BomRef>>,
}

/// A borrowed node of any level, as yielded by [`Product::walk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRef<'a> {
    /// The product.
    Product(&'a Product),
    /// An image.
    Image(&'a Image),
    /// A component or subcomponent.
    Component(&'a Component),
}

impl NodeRef<'_> {
    fn name(&self) -> &str {
        match self {
            Self::Product(p) => &p.name,
            Self::Image(i) => &i.name,
            Self::Component(c) => &c.name,
        }
    }

    fn version(&self) -> Option<&str> {
        match self {
            Self::Product(p) => p.version.as_deref(),
            Self::Image(i) => i.version.as_deref(),
            Self::Component(c) => c.version.as_deref(),
        }
    }

    fn hashes(&self) -> &BTreeSet<Hash> {
        match self {
            Self::Product(p) => &p.hashes,
            Self::Image(i) => &i.hashes,
            Self::Component(c) => &c.hashes,
        }
    }
}

fn check_name(name: &str) -> Result<(), IdError> {
    if name.is_empty() {
        return Err(IdError::Empty { what: "name" });
    }
    Ok(())
}

fn conflict(path: &NodePath, field: &str, existing: String, incoming: String) -> MergeError {
    MergeError::Conflict {
        path: path.clone(),
        field: field.to_owned(),
        existing,
        incoming,
    }
}

/// Fills `existing` from `incoming` if empty; errors if both are set and differ.
fn merge_option<T: PartialEq + fmt::Display>(
    path: &NodePath,
    field: &str,
    existing: &mut Option<T>,
    incoming: Option<T>,
) -> Result<(), MergeError> {
    match (existing.as_ref(), incoming) {
        (_, None) => Ok(()),
        (None, Some(value)) => {
            *existing = Some(value);
            Ok(())
        }
        (Some(old), Some(new)) if *old == new => Ok(()),
        (Some(old), Some(new)) => Err(conflict(path, field, old.to_string(), new.to_string())),
    }
}

/// Adds hashes for new algorithms; errors if an algorithm is present with another digest.
fn merge_hashes(
    path: &NodePath,
    existing: &mut BTreeSet<Hash>,
    incoming: BTreeSet<Hash>,
) -> Result<(), MergeError> {
    for hash in incoming {
        if let Some(old) = existing
            .iter()
            .find(|h| h.algorithm() == hash.algorithm() && *h != &hash)
        {
            return Err(conflict(
                path,
                &format!("hashes[{}]", hash.algorithm()),
                old.digest().to_owned(),
                hash.digest().to_owned(),
            ));
        }
        existing.insert(hash);
    }
    Ok(())
}

/// Checks an identity field is equal on both sides of a merge.
fn same_identity<T: PartialEq + fmt::Debug>(
    path: &NodePath,
    field: &str,
    existing: &T,
    incoming: &T,
) -> Result<(), MergeError> {
    if existing == incoming {
        Ok(())
    } else {
        Err(conflict(
            path,
            field,
            format!("{existing:?}"),
            format!("{incoming:?}"),
        ))
    }
}

/// Merges the non-identity facts shared by every node level.
macro_rules! merge_facts {
    ($path:expr, $target:expr, $incoming:expr) => {{
        merge_option($path, "supplier", &mut $target.supplier, $incoming.supplier)?;
        merge_option($path, "purl", &mut $target.purl, $incoming.purl)?;
        merge_option($path, "cpe", &mut $target.cpe, $incoming.cpe)?;
        merge_hashes($path, &mut $target.hashes, $incoming.hashes)?;
        merge_option($path, "licence", &mut $target.licence, $incoming.licence)?;
        $target.evidence.extend($incoming.evidence);
    }};
}

/// Inserts `incoming` into `set`, or merges it into the sibling with the same identity.
/// On error `set` is unchanged.
fn insert_or_merge_component(
    set: &mut BTreeSet<Component>,
    incoming: Component,
    parent: &NodePath,
) -> Result<(), MergeError> {
    let existing = set.iter().find(|c| c.key() == incoming.key()).cloned();
    match existing {
        None => {
            set.insert(incoming);
        }
        Some(old) => {
            let path = parent.child(PathSegment::of_component(&old));
            let mut merged = old.clone();
            merged.merge_in_place(incoming, &path)?;
            set.remove(&old);
            set.insert(merged);
        }
    }
    Ok(())
}

impl Component {
    /// A component with only its kind and name set. The name must be non-empty.
    pub fn new(kind: ComponentKind, name: &str) -> Result<Self, IdError> {
        check_name(name)?;
        Ok(Self {
            kind,
            name: name.to_owned(),
            version: None,
            supplier: None,
            purl: None,
            cpe: None,
            hashes: BTreeSet::new(),
            licence: None,
            evidence: EvidenceSet::new(),
            components: BTreeSet::new(),
        })
    }

    /// Sets the version and returns the component.
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_owned());
        self
    }

    /// The identity: (kind, name, version).
    pub fn key(&self) -> (ComponentKind, &str, Option<&str>) {
        (self.kind, &self.name, self.version.as_deref())
    }

    /// The highest confidence over all of this component's evidence (the combination rule
    /// is maximum), or [`Confidence::NONE`] if it has none.
    pub fn confidence(&self) -> Confidence {
        self.evidence.max_confidence()
    }

    /// The highest confidence over this component's evidence for `field`.
    pub fn confidence_for(&self, field: EvidenceField) -> Confidence {
        self.evidence.confidence_for(field)
    }

    /// Adds a subcomponent, merging it into the existing subcomponent with the same identity
    /// if there is one. On error `self` is unchanged.
    pub fn add_component(&mut self, component: Component) -> Result<(), MergeError> {
        let path = NodePath::root(PathSegment::of_component(self));
        insert_or_merge_component(&mut self.components, component, &path)
    }

    /// Merges `other` (which must have the same identity) into `self`.
    ///
    /// - An optional fact that is missing takes the incoming value; equal values are kept;
    ///   different values are a [`MergeError::Conflict`].
    /// - Hashes for new algorithms are added; the same algorithm with another digest is a
    ///   conflict.
    /// - Evidence is the union (keeping the higher confidence for the same observation).
    /// - Subcomponents merge recursively by identity.
    ///
    /// Atomic: on error `self` is unchanged.
    pub fn merge(&mut self, other: Component) -> Result<(), MergeError> {
        let path = NodePath::root(PathSegment::of_component(self));
        let mut work = self.clone();
        work.merge_in_place(other, &path)?;
        *self = work;
        Ok(())
    }

    fn merge_in_place(&mut self, other: Component, path: &NodePath) -> Result<(), MergeError> {
        same_identity(path, "kind", &self.kind, &other.kind)?;
        same_identity(path, "name", &self.name, &other.name)?;
        same_identity(path, "version", &self.version, &other.version)?;
        merge_facts!(path, self, other);
        for child in other.components {
            insert_or_merge_component(&mut self.components, child, path)?;
        }
        Ok(())
    }
}

impl Image {
    /// An image with only its kind and name set. The name must be non-empty.
    pub fn new(kind: ImageKind, name: &str) -> Result<Self, IdError> {
        check_name(name)?;
        Ok(Self {
            kind,
            name: name.to_owned(),
            version: None,
            supplier: None,
            purl: None,
            cpe: None,
            hashes: BTreeSet::new(),
            licence: None,
            evidence: EvidenceSet::new(),
            components: BTreeSet::new(),
        })
    }

    /// Sets the version and returns the image.
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_owned());
        self
    }

    /// The identity: (kind, name, version).
    pub fn key(&self) -> (ImageKind, &str, Option<&str>) {
        (self.kind, &self.name, self.version.as_deref())
    }

    /// Adds a component, merging it into the existing component with the same identity if
    /// there is one. On error `self` is unchanged.
    pub fn add_component(&mut self, component: Component) -> Result<(), MergeError> {
        let path = NodePath::root(PathSegment::of_image(self));
        insert_or_merge_component(&mut self.components, component, &path)
    }

    /// Merges `other` (which must have the same identity) into `self`, with the same rules
    /// as [`Component::merge`]. Atomic: on error `self` is unchanged.
    pub fn merge(&mut self, other: Image) -> Result<(), MergeError> {
        let path = NodePath::root(PathSegment::of_image(self));
        let mut work = self.clone();
        work.merge_in_place(other, &path)?;
        *self = work;
        Ok(())
    }

    fn merge_in_place(&mut self, other: Image, path: &NodePath) -> Result<(), MergeError> {
        same_identity(path, "kind", &self.kind, &other.kind)?;
        same_identity(path, "name", &self.name, &other.name)?;
        same_identity(path, "version", &self.version, &other.version)?;
        merge_facts!(path, self, other);
        for child in other.components {
            insert_or_merge_component(&mut self.components, child, path)?;
        }
        Ok(())
    }
}

impl Product {
    /// A product with only its name set. The name must be non-empty.
    pub fn new(name: &str) -> Result<Self, IdError> {
        check_name(name)?;
        Ok(Self {
            schema: Schema::V1,
            name: name.to_owned(),
            version: None,
            supplier: None,
            purl: None,
            cpe: None,
            hashes: BTreeSet::new(),
            licence: None,
            evidence: EvidenceSet::new(),
            images: BTreeSet::new(),
            dependencies: BTreeMap::new(),
        })
    }

    /// Sets the version and returns the product.
    pub fn with_version(mut self, version: &str) -> Self {
        self.version = Some(version.to_owned());
        self
    }

    /// The path of the product itself: the root of every other node's path.
    pub fn path(&self) -> NodePath {
        NodePath::root(PathSegment::of_product(self))
    }

    /// Adds an image, merging it into the existing image with the same identity if there is
    /// one. On error `self` is unchanged.
    pub fn add_image(&mut self, image: Image) -> Result<(), MergeError> {
        let root = self.path();
        let existing = self.images.iter().find(|i| i.key() == image.key()).cloned();
        match existing {
            None => {
                self.images.insert(image);
            }
            Some(old) => {
                let path = root.child(PathSegment::of_image(&old));
                let mut merged = old.clone();
                merged.merge_in_place(image, &path)?;
                self.images.remove(&old);
                self.images.insert(merged);
            }
        }
        Ok(())
    }

    /// Records that `from` depends on `to`. Both should be refs of nodes in this product;
    /// [`Product::validate`] checks that they are.
    pub fn add_dependency(&mut self, from: BomRef, to: BomRef) {
        self.dependencies.entry(from).or_default().insert(to);
    }

    /// Merges `other` (which must have the same name and version) into `self`: facts as in
    /// [`Component::merge`], images by identity, dependency edges by union. Atomic: on error
    /// `self` is unchanged.
    pub fn merge(&mut self, other: Product) -> Result<(), MergeError> {
        let path = self.path();
        let mut work = self.clone();
        same_identity(&path, "schema", &work.schema, &other.schema)?;
        same_identity(&path, "name", &work.name, &other.name)?;
        same_identity(&path, "version", &work.version, &other.version)?;
        merge_facts!(&path, work, other);
        for image in other.images {
            work.add_image(image)?;
        }
        for (from, targets) in other.dependencies {
            work.dependencies.entry(from).or_default().extend(targets);
        }
        *self = work;
        Ok(())
    }

    /// Every node, depth-first in sorted order (product, then each image followed by its
    /// components and their subcomponents), with its path and `bom-ref`.
    pub fn walk(&self) -> impl Iterator<Item = (NodePath, BomRef, NodeRef<'_>)> {
        let mut out = Vec::new();
        let root = self.path();
        out.push((root.clone(), BomRef::derive(&root), NodeRef::Product(self)));
        for image in &self.images {
            let image_path = root.child(PathSegment::of_image(image));
            out.push((
                image_path.clone(),
                BomRef::derive(&image_path),
                NodeRef::Image(image),
            ));
            // Explicit stack rather than recursion, so depth never threatens the call stack.
            let mut stack: Vec<(NodePath, &Component)> = image
                .components
                .iter()
                .rev()
                .map(|c| (image_path.child(PathSegment::of_component(c)), c))
                .collect();
            while let Some((path, component)) = stack.pop() {
                for child in component.components.iter().rev() {
                    stack.push((path.child(PathSegment::of_component(child)), child));
                }
                let bom_ref = BomRef::derive(&path);
                out.push((path, bom_ref, NodeRef::Component(component)));
            }
        }
        out.into_iter()
    }

    /// The node with this `bom-ref`, if any.
    pub fn resolve(&self, bom_ref: &BomRef) -> Option<NodeRef<'_>> {
        self.walk()
            .find(|(_, r, _)| r == bom_ref)
            .map(|(_, _, node)| node)
    }

    /// Checks the invariants the type system does not: the schema tag; names and versions
    /// that are non-empty, not whitespace-only and free of control characters; no two
    /// siblings with the same identity; at most one digest per hash algorithm per node; every
    /// dependency ref resolves; no node depends on itself; and no two distinct paths derive
    /// the same `bom-ref`.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self.schema {
            Schema::V1 => {}
        }
        let mut refs: BTreeMap<BomRef, NodePath> = BTreeMap::new();
        for (path, bom_ref, node) in self.walk() {
            if node.name().is_empty() {
                return Err(ValidationError::EmptyName { path });
            }
            if !is_clean_text(node.name()) {
                return Err(ValidationError::InvalidName { path });
            }
            match node.version() {
                Some("") => return Err(ValidationError::EmptyVersion { path }),
                Some(version) if !is_clean_text(version) => {
                    return Err(ValidationError::InvalidVersion { path });
                }
                _ => {}
            }
            let mut previous: Option<HashAlgorithm> = None;
            for hash in node.hashes() {
                if previous == Some(hash.algorithm()) {
                    return Err(ValidationError::DuplicateHashAlgorithm {
                        path,
                        algorithm: hash.algorithm(),
                    });
                }
                previous = Some(hash.algorithm());
            }
            let duplicate_child =
                match node {
                    NodeRef::Product(p) => {
                        adjacent_duplicate(&p.images, Image::key).map(PathSegment::of_image)
                    }
                    NodeRef::Image(i) => adjacent_duplicate(&i.components, Component::key)
                        .map(PathSegment::of_component),
                    NodeRef::Component(c) => adjacent_duplicate(&c.components, Component::key)
                        .map(PathSegment::of_component),
                };
            if let Some(segment) = duplicate_child {
                return Err(ValidationError::DuplicateSibling {
                    path: path.child(segment),
                });
            }
            if let Some(first) = refs.get(&bom_ref) {
                if *first != path {
                    return Err(ValidationError::BomRefCollision {
                        bom_ref,
                        first: first.clone(),
                        second: path,
                    });
                }
            } else {
                refs.insert(bom_ref, path);
            }
        }
        for (from, targets) in &self.dependencies {
            if targets.contains(from) {
                return Err(ValidationError::SelfDependency {
                    bom_ref: from.clone(),
                });
            }
            for bom_ref in std::iter::once(from).chain(targets) {
                if !refs.contains_key(bom_ref) {
                    return Err(ValidationError::DanglingDependency {
                        bom_ref: bom_ref.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Whether a name or version is usable text: not whitespace-only and free of control
/// characters.
fn is_clean_text(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(char::is_control)
}

/// The first element whose identity equals the previous one's. Siblings are sorted by
/// identity first, so equal identities are adjacent.
fn adjacent_duplicate<'a, T, K: PartialEq>(
    set: &'a BTreeSet<T>,
    key: impl Fn(&'a T) -> K,
) -> Option<&'a T> {
    let mut previous: Option<K> = None;
    for item in set {
        let current = key(item);
        if previous.as_ref() == Some(&current) {
            return Some(item);
        }
        previous = Some(current);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, Technique};

    fn ev(field: EvidenceField, source: &str, value: &str, bp: u16) -> Evidence {
        Evidence::new(
            field,
            Technique::ManifestAnalysis,
            source,
            value,
            Confidence::new(bp).unwrap(),
        )
        .unwrap()
    }

    fn lib(name: &str, version: &str) -> Component {
        Component::new(ComponentKind::Library, name)
            .unwrap()
            .with_version(version)
    }

    fn app() -> Image {
        Image::new(ImageKind::Application, "app").unwrap()
    }

    #[test]
    fn components_serialise_sorted_regardless_of_insertion_order() {
        let items = [
            lib("zlib", "1.3"),
            Component::new(ComponentKind::OperatingSystem, "zephyr")
                .unwrap()
                .with_version("3.7.0"),
            lib("cmsis", "5.9.0"),
            lib("cmsis", "5.10.0"),
            Component::new(ComponentKind::Library, "hal").unwrap(),
            Component::new(ComponentKind::Firmware, "radio").unwrap(),
        ];
        let mut forward = app();
        for c in items.iter().cloned() {
            forward.add_component(c).unwrap();
        }
        let mut backward = app();
        for c in items.iter().rev().cloned() {
            backward.add_component(c).unwrap();
        }
        assert_eq!(forward, backward);
        assert_eq!(
            serde_json::to_string_pretty(&forward).unwrap(),
            serde_json::to_string_pretty(&backward).unwrap()
        );
        let order: Vec<(ComponentKind, &str, Option<&str>)> =
            forward.components.iter().map(Component::key).collect();
        assert_eq!(
            order,
            vec![
                (ComponentKind::Library, "cmsis", Some("5.10.0")),
                (ComponentKind::Library, "cmsis", Some("5.9.0")),
                (ComponentKind::Library, "hal", None),
                (ComponentKind::Library, "zlib", Some("1.3")),
                (ComponentKind::OperatingSystem, "zephyr", Some("3.7.0")),
                (ComponentKind::Firmware, "radio", None),
            ]
        );
    }

    #[test]
    fn same_component_from_two_sources_merges_into_one_with_both_evidence() {
        let mut from_spdx = lib("mbedtls", "3.6.0");
        from_spdx.purl = Some(Purl::new("pkg:github/Mbed-TLS/mbedtls@v3.6.0").unwrap());
        from_spdx
            .evidence
            .insert(ev(EvidenceField::Version, "west-spdx", "3.6.0", 9000));
        let mut from_manifest = lib("mbedtls", "3.6.0");
        from_manifest.licence = Some(License::new("Apache-2.0 OR GPL-2.0-or-later").unwrap());
        from_manifest
            .evidence
            .insert(ev(EvidenceField::Version, "west-list", "3.6.0", 7000));
        from_manifest.evidence.insert(ev(
            EvidenceField::Licence,
            "west-list",
            "Apache-2.0 OR GPL-2.0-or-later",
            6000,
        ));

        let mut image = app();
        image.add_component(from_spdx).unwrap();
        image.add_component(from_manifest).unwrap();
        assert_eq!(image.components.len(), 1);
        let merged = image.components.first().unwrap();
        assert!(merged.purl.is_some());
        assert!(merged.licence.is_some());
        let sources: BTreeSet<&str> = merged.evidence.iter().map(Evidence::source).collect();
        assert_eq!(sources, BTreeSet::from(["west-list", "west-spdx"]));
        assert_eq!(merged.evidence.len(), 3);
        assert_eq!(merged.confidence().basis_points(), 9000);
        assert_eq!(
            merged.confidence_for(EvidenceField::Licence).basis_points(),
            6000
        );
    }

    #[test]
    fn duplicate_evidence_keeps_max_confidence() {
        let mut a = lib("mbedtls", "3.6.0");
        a.evidence
            .insert(ev(EvidenceField::Version, "west-spdx", "3.6.0", 4000));
        let mut b = lib("mbedtls", "3.6.0");
        b.evidence
            .insert(ev(EvidenceField::Version, "west-spdx", "3.6.0", 8000));
        let mut c = lib("mbedtls", "3.6.0");
        c.evidence
            .insert(ev(EvidenceField::Version, "west-spdx", "3.6.0", 2000));
        a.merge(b).unwrap();
        a.merge(c).unwrap();
        assert_eq!(a.evidence.len(), 1);
        assert_eq!(a.confidence().basis_points(), 8000);
    }

    #[test]
    fn merge_fills_missing_fields() {
        let mut target = lib("mbedtls", "3.6.0");
        target.licence = Some(License::new("Apache-2.0").unwrap());
        let mut incoming = lib("mbedtls", "3.6.0");
        incoming.licence = Some(License::new("Apache-2.0").unwrap());
        incoming.supplier = Some(Supplier::new("Trusted Firmware").unwrap());
        incoming.purl = Some(Purl::new("pkg:github/Mbed-TLS/mbedtls@v3.6.0").unwrap());
        incoming.cpe = Some(Cpe::new("cpe:2.3:a:arm:mbed_tls:3.6.0:*:*:*:*:*:*:*").unwrap());
        incoming
            .hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"0f".repeat(32)).unwrap());
        target.merge(incoming.clone()).unwrap();
        assert_eq!(target, incoming);

        // Merging a sparser node back in changes nothing.
        let before = target.clone();
        target.merge(lib("mbedtls", "3.6.0")).unwrap();
        assert_eq!(target, before);
    }

    #[test]
    fn conflicting_licence_is_error_and_target_unchanged() {
        let mut image = app();
        let mut first = lib("mbedtls", "3.6.0");
        first.licence = Some(License::new("Apache-2.0").unwrap());
        image.add_component(first).unwrap();
        let before = image.clone();

        let mut second = lib("mbedtls", "3.6.0");
        second.licence = Some(License::new("MIT").unwrap());
        // Would fill a missing field too, which must also not be applied.
        second.supplier = Some(Supplier::new("Someone").unwrap());
        let err = image.add_component(second).unwrap_err();
        let MergeError::Conflict {
            path,
            field,
            existing,
            incoming,
        } = err;
        assert_eq!(field, "licence");
        assert_eq!(existing, "Apache-2.0");
        assert_eq!(incoming, "MIT");
        assert_eq!(path.to_string(), "application:app / library:mbedtls@3.6.0");
        assert_eq!(image, before);

        let mut direct = before.components.first().unwrap().clone();
        let direct_before = direct.clone();
        let mut other = lib("mbedtls", "3.6.0");
        other.licence = Some(License::new("MIT").unwrap());
        other.purl = Some(Purl::new("pkg:generic/mbedtls@3.6.0").unwrap());
        assert!(direct.merge(other).is_err());
        assert_eq!(direct, direct_before);
    }

    #[test]
    fn conflicting_digest_for_same_algorithm_is_error() {
        let mut a = lib("mbedtls", "3.6.0");
        a.hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"aa".repeat(32)).unwrap());
        let before = a.clone();
        let mut b = lib("mbedtls", "3.6.0");
        b.hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"bb".repeat(32)).unwrap());
        let err = a.merge(b).unwrap_err();
        let MergeError::Conflict { field, .. } = err;
        assert_eq!(field, "hashes[SHA-256]");
        assert_eq!(a, before);

        // A different algorithm is simply added.
        let mut c = lib("mbedtls", "3.6.0");
        c.hashes
            .insert(Hash::new(HashAlgorithm::Sha1, &"cc".repeat(20)).unwrap());
        a.merge(c).unwrap();
        assert_eq!(a.hashes.len(), 2);
    }

    #[test]
    fn merge_recurses_into_subcomponents() {
        let mut parent_a = Component::new(ComponentKind::OperatingSystem, "zephyr")
            .unwrap()
            .with_version("3.7.0");
        let mut kernel_a = Component::new(ComponentKind::Library, "kernel").unwrap();
        kernel_a
            .evidence
            .insert(ev(EvidenceField::Name, "west-spdx", "kernel", 9000));
        parent_a.add_component(kernel_a).unwrap();

        let mut parent_b = parent_a.clone();
        parent_b.components.clear();
        let mut kernel_b = Component::new(ComponentKind::Library, "kernel").unwrap();
        kernel_b.licence = Some(License::new("Apache-2.0").unwrap());
        kernel_b
            .evidence
            .insert(ev(EvidenceField::Licence, "kconfig", "Apache-2.0", 5000));
        parent_b.add_component(kernel_b).unwrap();
        parent_b
            .add_component(Component::new(ComponentKind::Library, "net").unwrap())
            .unwrap();

        let mut image = app();
        image.add_component(parent_a).unwrap();
        image.add_component(parent_b).unwrap();
        assert_eq!(image.components.len(), 1);
        let zephyr = image.components.first().unwrap();
        assert_eq!(zephyr.components.len(), 2);
        let kernel = zephyr.components.first().unwrap();
        assert_eq!(kernel.name, "kernel");
        assert_eq!(
            kernel.licence.as_ref().map(License::as_str),
            Some("Apache-2.0")
        );
        assert_eq!(kernel.evidence.len(), 2);

        // A conflict deep in the tree leaves the whole image unchanged.
        let before = image.clone();
        let mut parent_c = Component::new(ComponentKind::OperatingSystem, "zephyr")
            .unwrap()
            .with_version("3.7.0");
        let mut kernel_c = Component::new(ComponentKind::Library, "kernel").unwrap();
        kernel_c.licence = Some(License::new("MIT").unwrap());
        parent_c.add_component(kernel_c).unwrap();
        parent_c.licence = Some(License::new("Apache-2.0").unwrap());
        let err = image.add_component(parent_c).unwrap_err();
        let MergeError::Conflict { path, .. } = err;
        assert_eq!(
            path.to_string(),
            "application:app / operating-system:zephyr@3.7.0 / library:kernel"
        );
        assert_eq!(image, before);
    }

    #[test]
    fn identity_mismatch_is_conflict() {
        let mut a = lib("a", "1");
        assert!(a.merge(lib("b", "1")).is_err());
        assert!(a.merge(lib("a", "2")).is_err());
        assert_eq!(a, lib("a", "1"));
    }

    #[test]
    fn walk_is_sorted_and_resolve_finds_nodes() {
        let mut product = Product::new("widget").unwrap();
        let mut image = app();
        let mut os = Component::new(ComponentKind::OperatingSystem, "zephyr").unwrap();
        os.add_component(lib("kernel", "3.7.0")).unwrap();
        image.add_component(os).unwrap();
        image.add_component(lib("mbedtls", "3.6.0")).unwrap();
        product.add_image(image).unwrap();
        product
            .add_image(Image::new(ImageKind::Bootloader, "mcuboot").unwrap())
            .unwrap();
        let names: Vec<String> = product.walk().map(|(p, _, _)| p.to_string()).collect();
        assert_eq!(
            names,
            vec![
                "product:widget",
                "product:widget / bootloader:mcuboot",
                "product:widget / application:app",
                "product:widget / application:app / library:mbedtls@3.6.0",
                "product:widget / application:app / operating-system:zephyr",
                "product:widget / application:app / operating-system:zephyr / library:kernel@3.7.0",
            ]
        );
        for (_, bom_ref, node) in product.walk() {
            assert_eq!(product.resolve(&bom_ref), Some(node));
        }
        assert!(product.validate().is_ok());
    }

    #[test]
    fn validate_catches_duplicate_hash_algorithm_and_dangling_ref() {
        let mut product = Product::new("widget").unwrap();
        let mut image = app();
        image
            .hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"aa".repeat(32)).unwrap());
        image
            .hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"bb".repeat(32)).unwrap());
        product.images.insert(image);
        assert!(matches!(
            product.validate(),
            Err(ValidationError::DuplicateHashAlgorithm { .. })
        ));

        let mut product = Product::new("widget").unwrap();
        let root = BomRef::derive(&product.path());
        let ghost = BomRef::derive(&product.path().child(PathSegment::of_image(&app())));
        product.add_dependency(root, ghost);
        assert!(matches!(
            product.validate(),
            Err(ValidationError::DanglingDependency { .. })
        ));
    }

    fn blob() -> Image {
        Image::new(ImageKind::Blob, "radio").unwrap()
    }

    fn boot() -> Image {
        Image::new(ImageKind::Bootloader, "mcuboot").unwrap()
    }

    fn zephyr() -> Component {
        Component::new(ComponentKind::OperatingSystem, "zephyr")
            .unwrap()
            .with_version("3.7.0")
    }

    #[test]
    fn product_merge_unions_images_and_dependencies() {
        let mut left = Product::new("widget").unwrap().with_version("1.0.0");
        let mut left_app = app();
        left_app.add_component(lib("cmsis", "5.9.0")).unwrap();
        left_app.add_component(lib("mbedtls", "3.6.0")).unwrap();
        left.add_image(left_app).unwrap();
        left.add_image(boot()).unwrap();

        let mut right = Product::new("widget").unwrap().with_version("1.0.0");
        let mut right_app = app();
        let mut mbedtls = lib("mbedtls", "3.6.0");
        mbedtls.licence = Some(License::new("Apache-2.0").unwrap());
        right_app.add_component(mbedtls).unwrap();
        right_app.add_component(zephyr()).unwrap();
        right.add_image(right_app).unwrap();
        right.add_image(blob()).unwrap();

        let root = left.path();
        let app_path = root.child(PathSegment::of_image(&app()));
        let root_ref = BomRef::derive(&root);
        let app_ref = BomRef::derive(&app_path);
        let boot_ref = BomRef::derive(&root.child(PathSegment::of_image(&boot())));
        let blob_ref = BomRef::derive(&root.child(PathSegment::of_image(&blob())));
        let zephyr_ref = BomRef::derive(&app_path.child(PathSegment::of_component(&zephyr())));
        left.add_dependency(root_ref.clone(), app_ref.clone());
        left.add_dependency(root_ref.clone(), boot_ref.clone());
        right.add_dependency(root_ref.clone(), app_ref.clone());
        right.add_dependency(root_ref.clone(), blob_ref.clone());
        right.add_dependency(app_ref.clone(), zephyr_ref.clone());

        left.merge(right).unwrap();
        left.validate().unwrap();

        let images: Vec<(ImageKind, &str, Option<&str>)> =
            left.images.iter().map(Image::key).collect();
        assert_eq!(
            images,
            vec![
                (ImageKind::Bootloader, "mcuboot", None),
                (ImageKind::Application, "app", None),
                (ImageKind::Blob, "radio", None),
            ]
        );
        let merged_app = left
            .images
            .iter()
            .find(|i| i.kind == ImageKind::Application)
            .unwrap();
        let components: Vec<&str> = merged_app
            .components
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(components, vec!["cmsis", "mbedtls", "zephyr"]);
        let merged_mbedtls = merged_app
            .components
            .iter()
            .find(|c| c.name == "mbedtls")
            .unwrap();
        assert_eq!(
            merged_mbedtls.licence.as_ref().map(License::as_str),
            Some("Apache-2.0")
        );

        let expected: BTreeMap<BomRef, BTreeSet<BomRef>> = BTreeMap::from([
            (
                root_ref,
                BTreeSet::from([app_ref.clone(), boot_ref, blob_ref]),
            ),
            (app_ref, BTreeSet::from([zephyr_ref])),
        ]);
        assert_eq!(left.dependencies, expected);
    }

    #[test]
    fn product_merge_conflict_deep_in_image_leaves_target_unchanged() {
        let mut target = Product::new("widget").unwrap();
        let mut target_app = app();
        let mut mbedtls = lib("mbedtls", "3.6.0");
        mbedtls.licence = Some(License::new("Apache-2.0").unwrap());
        target_app.add_component(mbedtls).unwrap();
        target.add_image(target_app).unwrap();
        let before = target.clone();

        let mut incoming = Product::new("widget").unwrap();
        // Changes that would apply cleanly before the conflict is reached.
        incoming.supplier = Some(Supplier::new("Example").unwrap());
        incoming.add_image(boot()).unwrap();
        let root = incoming.path();
        incoming.add_dependency(
            BomRef::derive(&root),
            BomRef::derive(&root.child(PathSegment::of_image(&boot()))),
        );
        let mut incoming_app = app();
        incoming_app.add_component(zephyr()).unwrap();
        let mut conflicting = lib("mbedtls", "3.6.0");
        conflicting.licence = Some(License::new("MIT").unwrap());
        incoming_app.add_component(conflicting).unwrap();
        incoming.add_image(incoming_app).unwrap();

        let err = target.merge(incoming).unwrap_err();
        let MergeError::Conflict { path, field, .. } = err;
        assert_eq!(field, "licence");
        assert_eq!(
            path.to_string(),
            "product:widget / application:app / library:mbedtls@3.6.0"
        );
        assert_eq!(target, before);
    }

    #[test]
    fn image_merge_conflict_leaves_target_unchanged() {
        let mut target = app();
        target.add_component(lib("cmsis", "5.9.0")).unwrap();
        target
            .hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"aa".repeat(32)).unwrap());
        let before = target.clone();

        let mut incoming = app();
        incoming.licence = Some(License::new("Apache-2.0").unwrap());
        incoming.add_component(zephyr()).unwrap();
        incoming
            .hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"bb".repeat(32)).unwrap());

        let err = target.merge(incoming).unwrap_err();
        let MergeError::Conflict { path, field, .. } = err;
        assert_eq!(field, "hashes[SHA-256]");
        assert_eq!(path.to_string(), "application:app");
        assert_eq!(target, before);

        // A non-conflicting image merge applies every change.
        let mut other = app();
        other.licence = Some(License::new("Apache-2.0").unwrap());
        other.add_component(zephyr()).unwrap();
        target.merge(other).unwrap();
        assert_eq!(target.components.len(), 2);
        assert!(target.licence.is_some());
    }

    #[test]
    fn whitespace_only_name_is_error() {
        for name in [" ", "\t", "  \n "] {
            let mut product = Product::new("widget").unwrap();
            let mut image = app();
            image.components.insert(lib(name, "1.0"));
            product.images.insert(image);
            assert!(
                matches!(product.validate(), Err(ValidationError::InvalidName { .. })),
                "{name:?}"
            );
        }
        let product = Product::new(" ").unwrap();
        assert!(matches!(
            product.validate(),
            Err(ValidationError::InvalidName { .. })
        ));
    }

    #[test]
    fn control_char_in_version_is_error() {
        for version in ["1.0\n", "\u{7}1.0", "1.\u{0}0", " "] {
            let mut product = Product::new("widget").unwrap();
            let mut image = app();
            image.components.insert(lib("mbedtls", version));
            product.images.insert(image);
            assert!(
                matches!(
                    product.validate(),
                    Err(ValidationError::InvalidVersion { .. })
                ),
                "{version:?}"
            );
        }
        let mut product = Product::new("widget").unwrap();
        product.images.insert(app().with_version("1.0\r"));
        assert!(matches!(
            product.validate(),
            Err(ValidationError::InvalidVersion { .. })
        ));
        // A control character in a name is rejected too.
        let product = Product::new("wid\u{1b}get").unwrap();
        assert!(matches!(
            product.validate(),
            Err(ValidationError::InvalidName { .. })
        ));
    }
}
