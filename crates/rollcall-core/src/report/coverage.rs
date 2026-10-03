//! The SBOM's nodes, one row each, and the coverage totals over them.

use std::collections::BTreeMap;

use super::model::{ComponentRow, Coverage, Share};
use crate::cyclonedx::Read;
use crate::model::{EvidenceSet, NodePath, NodeRef, Purl};

/// One node of the product as the report sees it.
pub(super) struct Node<'a> {
    /// Its `bom-ref` in the SBOM (the lowest, should the document give it several).
    pub doc_ref: Option<String>,
    /// `product`, `image` or `component`.
    pub level: &'static str,
    /// Names from the image down (the product's name for the product).
    pub label: String,
    /// The CycloneDX `type`.
    pub kind: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<&'a Purl>,
    pub has_cpe: bool,
    pub has_hash: bool,
    pub has_licence: bool,
    pub evidence: &'a EvidenceSet,
}

/// Every node of `read.product`, in walk order (product, then each image followed by its
/// components depth-first, all sorted).
/// `product_type` is the SBOM's `metadata.component.type` (`firmware` when it has none).
pub(super) fn nodes<'a>(read: &'a Read, product_type: &str) -> Vec<Node<'a>> {
    let mut by_path: BTreeMap<&NodePath, &str> = BTreeMap::new();
    for (doc_ref, path) in &read.refs {
        by_path.entry(path).or_insert(doc_ref.as_str());
    }
    let mut out = Vec::new();
    // The names of the current node's ancestors from the image down, by depth.
    let mut names: Vec<String> = Vec::new();
    for (path, _, node) in read.product.walk() {
        let doc_ref = by_path.get(&path).map(|r| (*r).to_owned());
        let depth = path.0.len();
        let (level, name, kind) = match node {
            NodeRef::Product(p) => ("product", p.name.clone(), product_type.to_owned()),
            NodeRef::Image(i) => ("image", i.name.clone(), i.image_type.as_str().to_owned()),
            NodeRef::Component(c) => ("component", c.name.clone(), c.kind.as_str().to_owned()),
        };
        // Depth 1 is the product; an image is depth 2 and starts the label.
        names.truncate(depth.saturating_sub(2));
        let label = if depth <= 1 {
            name.clone()
        } else {
            names.push(name.clone());
            names.join(" / ")
        };
        let (version, purl, has_cpe, has_hash, has_licence, evidence) = match node {
            NodeRef::Product(p) => (
                p.version.clone(),
                p.purl.as_ref(),
                p.cpe.is_some(),
                !p.hashes.is_empty(),
                p.licence.is_some(),
                &p.evidence,
            ),
            NodeRef::Image(i) => (
                i.version.clone(),
                i.purl.as_ref(),
                i.cpe.is_some(),
                !i.hashes.is_empty(),
                i.licence.is_some(),
                &i.evidence,
            ),
            NodeRef::Component(c) => (
                c.version.clone(),
                c.purl.as_ref(),
                c.cpe.is_some(),
                !c.hashes.is_empty(),
                c.licence.is_some(),
                &c.evidence,
            ),
        };
        out.push(Node {
            doc_ref,
            level,
            label,
            kind,
            name,
            version,
            purl,
            has_cpe,
            has_hash,
            has_licence,
            evidence,
        });
    }
    out
}

/// One row per node.
pub(super) fn rows(nodes: &[Node<'_>]) -> Vec<ComponentRow> {
    nodes
        .iter()
        .map(|n| ComponentRow {
            level: n.level,
            path: n.label.clone(),
            kind: n.kind.clone(),
            name: n.name.clone(),
            version: n.version.clone(),
            bom_ref: n.doc_ref.clone(),
            purl: n.purl.is_some(),
            cpe: n.has_cpe,
            hash: n.has_hash,
            licence: n.has_licence,
        })
        .collect()
}

/// `count / total` in basis points, rounded down; 0 when `total` is 0.
pub(super) fn share(count: u64, total: u64) -> Share {
    let basis_points = if total == 0 {
        0
    } else {
        // count <= total, so the quotient is at most 10000.
        u32::try_from(u128::from(count) * 10_000 / u128::from(total)).unwrap_or(10_000)
    };
    Share {
        count,
        basis_points,
    }
}

/// The coverage totals over `rows`.
pub(super) fn totals(rows: &[ComponentRow]) -> Coverage {
    let total = rows.len() as u64;
    let count = |f: &dyn Fn(&ComponentRow) -> bool| rows.iter().filter(|r| f(r)).count() as u64;
    Coverage {
        nodes: total,
        purl: share(count(&|r| r.purl), total),
        cpe: share(count(&|r| r.cpe), total),
        identified: share(count(&|r| r.purl || r.cpe), total),
        hash: share(count(&|r| r.hash), total),
        licence: share(count(&|r| r.licence), total),
    }
}
