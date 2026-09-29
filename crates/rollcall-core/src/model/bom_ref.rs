//! Stable `bom-ref` derivation from a node's path in the product hierarchy.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::graph::{Component, Image, Product};
use super::ids::IdError;

/// Domain-separation prefix hashed before every path; bump the suffix if the encoding changes.
const DOMAIN: &[u8] = b"rollcall-bom-ref/1\n";

/// The level of a node in the product hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeLevel {
    /// The product (root).
    Product,
    /// A firmware image in the product.
    Image,
    /// A component in an image, or a subcomponent of a component.
    Component,
}

impl NodeLevel {
    /// The level's name as used in `bom-ref` text: `product`, `image` or `component`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::Image => "image",
            Self::Component => "component",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Product => 0x01,
            Self::Image => 0x02,
            Self::Component => 0x03,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "product" => Some(Self::Product),
            "image" => Some(Self::Image),
            "component" => Some(Self::Component),
            _ => None,
        }
    }
}

/// One step of a [`NodePath`]: a node's level and identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathSegment {
    /// The node's level.
    pub level: NodeLevel,
    /// The node's kind as serialised: `product` for the product, the [`ImageKind`] name for an
    /// image, the [`ComponentKind`] name for a component.
    ///
    /// [`ImageKind`]: super::ids::ImageKind
    /// [`ComponentKind`]: super::ids::ComponentKind
    pub kind: String,
    /// The node's name.
    pub name: String,
    /// The node's version, if it has one.
    pub version: Option<String>,
}

impl PathSegment {
    /// The segment identifying a product.
    pub fn of_product(product: &Product) -> Self {
        Self {
            level: NodeLevel::Product,
            kind: "product".to_owned(),
            name: product.name.clone(),
            version: product.version.clone(),
        }
    }

    /// The segment identifying an image.
    pub fn of_image(image: &Image) -> Self {
        Self {
            level: NodeLevel::Image,
            kind: image.kind.as_str().to_owned(),
            name: image.name.clone(),
            version: image.version.clone(),
        }
    }

    /// The segment identifying a component.
    pub fn of_component(component: &Component) -> Self {
        Self {
            level: NodeLevel::Component,
            kind: component.kind.as_str().to_owned(),
            name: component.name.clone(),
            version: component.version.clone(),
        }
    }
}

impl fmt::Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

/// The path from the product root to a node: one [`PathSegment`] per level.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePath(pub Vec<PathSegment>);

impl NodePath {
    /// A path of one segment.
    pub fn root(segment: PathSegment) -> Self {
        Self(vec![segment])
    }

    /// This path extended by `segment`.
    pub fn child(&self, segment: PathSegment) -> Self {
        let mut path = self.clone();
        path.0.push(segment);
        path
    }

    /// The segments, root first.
    pub fn segments(&self) -> &[PathSegment] {
        &self.0
    }

    /// The level of the last segment, if any.
    pub fn level(&self) -> Option<NodeLevel> {
        self.0.last().map(|s| s.level)
    }
}

impl fmt::Display for NodePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" / ")?;
            }
            write!(f, "{segment}")?;
        }
        Ok(())
    }
}

/// A stable CycloneDX `bom-ref`: `<level>:<32 lowercase hex>`.
///
/// Derived from a node's [`NodePath`] only (levels, kinds, names and versions from the root
/// down), so it never depends on hashes, licences, purls, evidence, insertion order or
/// randomness. The same component under two images has two paths and so two refs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BomRef(String);

impl BomRef {
    /// Derives the ref for `path`.
    ///
    /// Hashes, with SHA-256, the bytes `"rollcall-bom-ref/1\n"` followed by, per segment: a
    /// level tag byte (`0x01` product, `0x02` image, `0x03` component); the kind and then the
    /// name, each as a big-endian `u32` byte length and the UTF-8 bytes; and the version as
    /// `0x00` if absent or `0x01`, `u32` length and bytes if present. The first 16 bytes of the
    /// digest, in lowercase hex, follow the last segment's level name. An empty path uses the
    /// level `product`.
    pub fn derive(path: &NodePath) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        for segment in &path.0 {
            hasher.update([segment.level.tag()]);
            update_len_prefixed(&mut hasher, segment.kind.as_bytes());
            update_len_prefixed(&mut hasher, segment.name.as_bytes());
            match &segment.version {
                None => hasher.update([0x00]),
                Some(version) => {
                    hasher.update([0x01]);
                    update_len_prefixed(&mut hasher, version.as_bytes());
                }
            }
        }
        let digest = hasher.finalize();
        let mut text = String::with_capacity(48);
        text.push_str(path.level().unwrap_or(NodeLevel::Product).as_str());
        text.push(':');
        for byte in digest.iter().take(16) {
            text.push(hex_digit(byte >> 4));
            text.push(hex_digit(byte & 0x0f));
        }
        Self(text)
    }

    /// Parses a ref of the form `<level>:<32 lowercase hex>`.
    pub fn parse(input: &str) -> Result<Self, IdError> {
        let err = || IdError::BomRef {
            input: input.to_owned(),
        };
        let (level, hex) = input.split_once(':').ok_or_else(err)?;
        NodeLevel::parse(level).ok_or_else(err)?;
        if hex.len() != 32 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(err());
        }
        Ok(Self(input.to_owned()))
    }

    /// The ref text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    // Lengths beyond u32::MAX cannot occur for in-memory model strings in practice; saturate
    // rather than panic so the function stays total.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

fn hex_digit(nibble: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(nibble & 0x0f))
            .copied()
            .unwrap_or(b'0'),
    )
}

impl TryFrom<String> for BomRef {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<BomRef> for String {
    fn from(value: BomRef) -> Self {
        value.0
    }
}

impl fmt::Display for BomRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ComponentKind, Confidence, Evidence, EvidenceField, Hash, HashAlgorithm, ImageKind,
        License, Purl, Technique,
    };

    fn seg(level: NodeLevel, kind: &str, name: &str, version: Option<&str>) -> PathSegment {
        PathSegment {
            level,
            kind: kind.to_owned(),
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    fn lib_path(image: &str, name: &str, version: Option<&str>) -> NodePath {
        NodePath(vec![
            seg(NodeLevel::Product, "product", "widget", Some("1.0.0")),
            seg(NodeLevel::Image, "application", image, None),
            seg(NodeLevel::Component, "library", name, version),
        ])
    }

    #[test]
    fn ref_depends_only_on_kind_name_version_and_path() {
        let base = BomRef::derive(&lib_path("app", "mbedtls", Some("3.6.0")));
        assert_eq!(
            base,
            BomRef::derive(&lib_path("app", "mbedtls", Some("3.6.0")))
        );
        assert!(base.as_str().starts_with("component:"));
        assert_eq!(base.as_str().len(), "component:".len() + 32);

        let mut differ = vec![
            lib_path("app", "mbedtls", Some("3.6.1")),
            lib_path("app", "mbedtls", None),
            lib_path("app", "tinycrypt", Some("3.6.0")),
            lib_path("other", "mbedtls", Some("3.6.0")),
        ];
        let mut kind = lib_path("app", "mbedtls", Some("3.6.0"));
        if let Some(last) = kind.0.last_mut() {
            last.kind = "framework".to_owned();
        }
        differ.push(kind);
        let mut level = lib_path("app", "mbedtls", Some("3.6.0"));
        level.0.truncate(2);
        level
            .0
            .push(seg(NodeLevel::Image, "library", "mbedtls", Some("3.6.0")));
        differ.push(level);
        let mut parent = lib_path("app", "mbedtls", Some("3.6.0"));
        if let Some(product) = parent.0.first_mut() {
            product.version = Some("1.0.1".to_owned());
        }
        differ.push(parent);

        let mut seen = std::collections::BTreeSet::new();
        seen.insert(base.clone());
        for path in &differ {
            assert!(seen.insert(BomRef::derive(path)), "collision for {path}");
        }
    }

    #[test]
    fn ref_ignores_hashes_licence_purl_and_evidence() {
        let plain = Component::new(ComponentKind::Library, "mbedtls")
            .unwrap()
            .with_version("3.6.0");
        let mut rich = plain.clone();
        rich.hashes
            .insert(Hash::new(HashAlgorithm::Sha256, &"ab".repeat(32)).unwrap());
        rich.licence = Some(License::new("Apache-2.0 OR GPL-2.0-or-later").unwrap());
        rich.purl = Some(Purl::new("pkg:github/Mbed-TLS/mbedtls@v3.6.0").unwrap());
        rich.evidence.insert(
            Evidence::new(
                EvidenceField::Version,
                Technique::ManifestAnalysis,
                "west-spdx",
                "3.6.0",
                Confidence::FULL,
            )
            .unwrap(),
        );
        assert_ne!(plain, rich);
        let image = Image::new(ImageKind::Application, "app").unwrap();
        let root = NodePath::root(seg(NodeLevel::Product, "product", "p", None))
            .child(PathSegment::of_image(&image));
        assert_eq!(
            BomRef::derive(&root.child(PathSegment::of_component(&plain))),
            BomRef::derive(&root.child(PathSegment::of_component(&rich)))
        );
    }

    #[test]
    fn encoding_is_unambiguous_for_a_bc_vs_ab_c() {
        let a_bc = NodePath::root(seg(NodeLevel::Component, "a", "bc", None));
        let ab_c = NodePath::root(seg(NodeLevel::Component, "ab", "c", None));
        assert_ne!(BomRef::derive(&a_bc), BomRef::derive(&ab_c));

        let name_ver = NodePath::root(seg(NodeLevel::Component, "k", "a", Some("b")));
        let name_only = NodePath::root(seg(NodeLevel::Component, "k", "ab", None));
        assert_ne!(BomRef::derive(&name_ver), BomRef::derive(&name_only));

        let empty_version = NodePath::root(seg(NodeLevel::Component, "k", "a", Some("")));
        let no_version = NodePath::root(seg(NodeLevel::Component, "k", "a", None));
        assert_ne!(BomRef::derive(&empty_version), BomRef::derive(&no_version));
    }

    #[test]
    fn same_component_under_two_images_gets_distinct_refs() {
        let boot = BomRef::derive(&NodePath(vec![
            seg(NodeLevel::Product, "product", "widget", Some("1.0.0")),
            seg(NodeLevel::Image, "bootloader", "mcuboot", None),
            seg(NodeLevel::Component, "library", "mbedtls", Some("3.6.0")),
        ]));
        let app = BomRef::derive(&lib_path("app", "mbedtls", Some("3.6.0")));
        assert_ne!(boot, app);
    }

    #[test]
    fn ref_matches_pinned_value() {
        // Pinned: changing this value changes every bom-ref rollcall has ever emitted.
        let path = lib_path("app", "mbedtls", Some("3.6.0"));
        assert_eq!(
            BomRef::derive(&path).as_str(),
            "component:ea5acaf79b26b412fa4e30fb33143147"
        );
        let product = NodePath::root(seg(NodeLevel::Product, "product", "widget", None));
        assert_eq!(
            BomRef::derive(&product).as_str(),
            "product:ede59524120137dafefce402111d233b"
        );
    }

    #[test]
    fn parse_rejects_malformed_refs() {
        let good = BomRef::derive(&lib_path("app", "x", None));
        assert_eq!(BomRef::parse(good.as_str()).unwrap(), good);
        for bad in [
            "",
            "component",
            "component:",
            "widget:0123456789abcdef0123456789abcdef",
            "component:0123456789ABCDEF0123456789ABCDEF",
            "component:0123456789abcdef0123456789abcde",
            "component:0123456789abcdef0123456789abcdef0",
        ] {
            assert!(BomRef::parse(bad).is_err(), "{bad:?}");
        }
    }
}
