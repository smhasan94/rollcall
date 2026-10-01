//! Merging separately generated products (bootloader, application, blobs) into one product.
//!
//! [`merge`] folds products with [`Product::merge`]: images and components that share an
//! identity `(kind, name, version)` at the same position merge into one node (missing facts
//! take the incoming value, equal facts are kept, different facts are a
//! [`MergeError::Conflict`]; evidence is unioned), and dependency edges are unioned. The same
//! library under two *different* images stays two nodes with two `bom-ref`s.
//!
//! With a [`ProductSpec`] (`--product NAME[@VERSION]`), every input is first moved under that
//! product with [`reparent`]: its images are kept, its own root facts and evidence are
//! dropped, and every dependency edge is re-derived for the new root. Without one, the inputs
//! must already agree on the product name and version.
//!
//! Merging is order-independent, and merging a product with itself gives the same product.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use crate::blob::BlobImage;
use crate::model::{
    BomRef, EvidenceSet, Image, ImageKind, MergeError, NodePath, PathSegment, Product, Schema,
    ValidationError,
};

/// The product to merge into: `NAME[@VERSION]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProductSpec {
    name: String,
    version: Option<String>,
}

/// Why a `NAME[@VERSION]` product spec was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProductSpecError {
    /// The name is empty, whitespace-only or contains a control character.
    #[error("invalid product name {0:?} (expected NAME[@VERSION] with a non-empty NAME)")]
    Name(String),
    /// The version after `@` is empty, whitespace-only or contains a control character.
    #[error("invalid product version {0:?} (expected NAME[@VERSION]; omit @ for no version)")]
    Version(String),
}

/// Whether a name or version is usable text, as [`Product::validate`] requires.
fn is_clean_text(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(char::is_control)
}

impl ProductSpec {
    /// A spec with this name and optional version. Both must be non-empty, not
    /// whitespace-only and free of control characters.
    pub fn new(name: &str, version: Option<&str>) -> Result<Self, ProductSpecError> {
        if !is_clean_text(name) {
            return Err(ProductSpecError::Name(name.to_owned()));
        }
        if let Some(version) = version
            && !is_clean_text(version)
        {
            return Err(ProductSpecError::Version(version.to_owned()));
        }
        Ok(Self {
            name: name.to_owned(),
            version: version.map(str::to_owned),
        })
    }

    /// The product name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The product version, if any.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// An empty product with this name and version.
    pub fn empty_product(&self) -> Product {
        Product {
            schema: Schema::V1,
            name: self.name.clone(),
            version: self.version.clone(),
            supplier: None,
            purl: None,
            cpe: None,
            hashes: BTreeSet::new(),
            licence: None,
            evidence: EvidenceSet::new(),
            images: BTreeSet::new(),
            dependencies: BTreeMap::new(),
        }
    }
}

impl FromStr for ProductSpec {
    type Err = ProductSpecError;

    /// Parses `NAME[@VERSION]`, splitting at the last `@`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once('@') {
            Some((name, version)) => Self::new(name, Some(version)),
            None => Self::new(s, None),
        }
    }
}

impl fmt::Display for ProductSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

/// Why products could not be merged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// There was nothing to merge and no product spec to start from.
    #[error("nothing to merge: no input documents and no product given")]
    NoInputs,
    /// The product spec is invalid.
    #[error(transparent)]
    Spec(#[from] ProductSpecError),
    /// Two inputs disagree about a fact (including the product name or version when no
    /// product spec is given).
    #[error("{0}")]
    Conflict(#[from] MergeError),
    /// The merged product breaks a model invariant.
    #[error("invalid merged product: {0}")]
    Validation(#[from] ValidationError),
    /// A blob names an image (`image:`) the product does not have.
    #[error("blob {blob}: the product has no image named {image:?} to attach it to")]
    NoSuchImage {
        /// The blob's name.
        blob: String,
        /// The image it names.
        image: String,
    },
    /// A blob names an image (`image:`) that more than one image of the product is called.
    #[error("blob {blob}: more than one image is named {image:?}; cannot tell which it belongs to")]
    AmbiguousImage {
        /// The blob's name.
        blob: String,
        /// The image it names.
        image: String,
    },
}

/// `path` with its root segment replaced by `root`.
fn rerooted(path: &NodePath, root: &PathSegment) -> NodePath {
    let mut segments = path.segments().to_vec();
    if let Some(first) = segments.first_mut() {
        *first = root.clone();
    }
    NodePath(segments)
}

/// Moves `product`'s images under the product `spec` names. The product's own facts and
/// evidence are dropped; every dependency edge is re-derived for the new root (refs of moved
/// nodes change, because a ref encodes the node's path, but are stable across runs). Edges
/// naming a ref that is not in the product are dropped.
pub fn reparent(product: Product, spec: &ProductSpec) -> Product {
    let mut out = spec.empty_product();
    let root = PathSegment::of_product(&out);
    let refs: BTreeMap<BomRef, BomRef> = product
        .walk()
        .map(|(path, bom_ref, _)| (bom_ref, BomRef::derive(&rerooted(&path, &root))))
        .collect();
    for (from, targets) in &product.dependencies {
        let Some(new_from) = refs.get(from) else {
            continue;
        };
        for to in targets {
            if let Some(new_to) = refs.get(to) {
                out.add_dependency(new_from.clone(), new_to.clone());
            }
        }
    }
    out.images = product.images;
    out
}

/// Merges `inputs` into one product.
///
/// With `spec`, each input is [`reparent`]ed under it first and the result is that product
/// (an empty one when there are no inputs). Without it, the inputs must share a name and
/// version: a difference is an [`Error::Conflict`], and no inputs is [`Error::NoInputs`].
/// The result is checked with [`Product::validate`].
pub fn merge(inputs: Vec<Product>, spec: Option<&ProductSpec>) -> Result<Product, Error> {
    let mut iter = inputs.into_iter();
    let merged = match spec {
        Some(spec) => {
            let mut merged = spec.empty_product();
            for product in iter {
                merged.merge(reparent(product, spec))?;
            }
            merged
        }
        None => {
            let mut merged = iter.next().ok_or(Error::NoInputs)?;
            for product in iter {
                merged.merge(product)?;
            }
            merged
        }
    };
    merged.validate()?;
    Ok(merged)
}

/// Adds `images` (e.g. opaque blobs) to `product`, each as a dependency of the product root.
/// An image whose identity is already present merges into it. Atomic: on error `product` is
/// unchanged.
pub fn add_blobs(product: &mut Product, images: Vec<Image>) -> Result<(), Error> {
    attach_blobs(
        product,
        images
            .into_iter()
            .map(|image| BlobImage { image, owner: None })
            .collect(),
    )
}

/// Adds blob images to `product`, each with the name of the image it belongs to
/// ([`BlobImage::owner`]): a blob
/// with an owner becomes a dependency of that image (the one non-blob image of the product
/// with that name), one without becomes a dependency of the product root. The blob image
/// itself sits beside the other images, as every image does. An owner no image is called is
/// [`Error::NoSuchImage`]; one several images are called is [`Error::AmbiguousImage`]. An
/// image whose identity is already present merges into it. Atomic: on error `product` is
/// unchanged.
pub fn attach_blobs(product: &mut Product, blobs: Vec<BlobImage>) -> Result<(), Error> {
    let mut work = product.clone();
    let root = work.path();
    let root_ref = BomRef::derive(&root);
    for BlobImage { image, owner } in blobs {
        let from = match &owner {
            None => root_ref.clone(),
            Some(name) => {
                let named: Vec<&Image> = work
                    .images
                    .iter()
                    .filter(|i| i.kind != ImageKind::Blob && i.name == *name)
                    .collect();
                let (blob, image_name) = (image.name.clone(), name.clone());
                match named.as_slice() {
                    [found] => BomRef::derive(&root.child(PathSegment::of_image(found))),
                    [] => {
                        return Err(Error::NoSuchImage {
                            blob,
                            image: image_name,
                        });
                    }
                    _ => {
                        return Err(Error::AmbiguousImage {
                            blob,
                            image: image_name,
                        });
                    }
                }
            }
        };
        let image_ref = BomRef::derive(&root.child(PathSegment::of_image(&image)));
        work.add_image(image)?;
        work.add_dependency(from, image_ref);
    }
    work.validate()?;
    *product = work;
    Ok(())
}
