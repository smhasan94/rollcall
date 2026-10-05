//! The cryptographic inventory as a Markdown summary: one GitHub-flavoured table row per
//! (asset, evidence entry), with the evidence and its confidence.
//!
//! ```text
//! # Cryptographic inventory: sensor-node 1.0.0
//!
//! Generated 2026-01-02T03:04:05Z by rollcall 0.1.0.
//!
//! 7 cryptographic assets, 8 evidence entries.
//!
//! | Asset | Type | Details | In | Evidence | Confidence | Reason |
//! |-------|------|---------|----|----------|------------|--------|
//! | AES-128-GCM | algorithm | ae · 128 · … | sensor-app / mbedtls@3.6.0 | build/zephyr/.config:812 CONFIG_… | high | … |
//! ```
//!
//! Rows follow [`Product::walk`] order, then each asset's evidence in its sorted order, so the
//! same product always gives the same bytes. Every cell goes through
//! [`md_cell`], so no value can break the table.

use rollcall_core::cyclonedx::Timestamp;
use rollcall_core::model::{
    AlgorithmProperties, CertificateProperties, CryptoAsset, CryptoAssetProperties, NodePath,
    Product, ProtocolProperties, RelatedCryptoMaterialProperties,
};
use rollcall_core::report::md_cell;

/// The table header.
pub const HEADER: [&str; 7] = [
    "Asset",
    "Type",
    "Details",
    "In",
    "Evidence",
    "Confidence",
    "Reason",
];

/// Joins the present parts with ` · `, or `—` when there are none.
fn joined(parts: Vec<String>) -> String {
    if parts.is_empty() {
        "—".to_owned()
    } else {
        parts.join(" · ")
    }
}

fn algorithm(p: &AlgorithmProperties) -> Vec<String> {
    let mut parts = Vec::new();
    parts.extend(p.primitive.map(|v| v.as_str().to_owned()));
    parts.extend(p.parameter_set_identifier.clone());
    parts.extend(p.mode.map(|v| v.as_str().to_owned()));
    parts.extend(p.execution_environment.map(|v| v.as_str().to_owned()));
    parts.extend(p.implementation_platform.map(|v| v.as_str().to_owned()));
    if !p.crypto_functions.is_empty() {
        let functions: Vec<&str> = p.crypto_functions.iter().map(|f| f.as_str()).collect();
        parts.push(functions.join(","));
    }
    parts.extend(p.classical_security_level.map(|v| format!("{v}-bit")));
    parts.extend(
        p.nist_quantum_security_level
            .map(|v| format!("NIST {}", v.get())),
    );
    parts
}

fn protocol(p: &ProtocolProperties) -> Vec<String> {
    let mut parts = Vec::new();
    parts.extend(p.protocol_type.map(|v| v.as_str().to_owned()));
    parts.extend(p.version.clone());
    parts
}

fn certificate(p: &CertificateProperties) -> Vec<String> {
    let mut parts = Vec::new();
    parts.extend(p.certificate_format.clone());
    parts.extend(p.subject_name.clone());
    parts.extend(p.issuer_name.as_ref().map(|v| format!("issued by {v}")));
    match (&p.not_valid_before, &p.not_valid_after) {
        (Some(from), Some(to)) => parts.push(format!("valid {from} to {to}")),
        (Some(from), None) => parts.push(format!("valid from {from}")),
        (None, Some(to)) => parts.push(format!("valid until {to}")),
        (None, None) => {}
    }
    parts.extend(p.certificate_extension.as_ref().map(|v| format!(".{v}")));
    parts
}

fn material(p: &RelatedCryptoMaterialProperties) -> Vec<String> {
    let mut parts = Vec::new();
    parts.extend(p.material_type.map(|v| v.as_str().to_owned()));
    parts.extend(p.size.map(|v| format!("{v}-bit")));
    parts.extend(p.state.map(|v| v.as_str().to_owned()));
    parts.extend(p.id.as_ref().map(|v| format!("id {v}")));
    parts.extend(p.format.clone());
    parts
}

/// The Details cell: the asset's properties in a fixed order, then its OID.
pub fn details(asset: &CryptoAsset) -> String {
    let mut parts = match &asset.properties {
        CryptoAssetProperties::Algorithm(p) => algorithm(p),
        CryptoAssetProperties::Protocol(p) => protocol(p),
        CryptoAssetProperties::Certificate(p) => certificate(p),
        CryptoAssetProperties::RelatedCryptoMaterial(p) => material(p),
    };
    parts.extend(asset.oid.as_ref().map(|oid| format!("OID {oid}")));
    joined(parts)
}

/// `name` or `name@version`.
fn named(name: &str, version: Option<&str>) -> String {
    match version {
        Some(version) => format!("{name}@{version}"),
        None => name.to_owned(),
    }
}

/// The In cell: the path between the product and the asset, e.g. `sensor-app /
/// mbedtls@3.6.0`.
fn parent(path: &NodePath) -> String {
    let segments = path.segments();
    let inner = segments
        .get(1..segments.len().saturating_sub(1))
        .unwrap_or_default();
    let names: Vec<String> = inner
        .iter()
        .map(|s| named(&s.name, s.version.as_deref()))
        .collect();
    if names.is_empty() {
        "—".to_owned()
    } else {
        names.join(" / ")
    }
}

fn row(cells: &[String]) -> String {
    format!("| {} |\n", cells.join(" | "))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The inventory of `product` as Markdown: a title, when and by what it was generated, a
/// count, and the table (omitted when there are no assets). Deterministic: the same product,
/// timestamp and version give the same bytes.
pub fn to_markdown(product: &Product, generated: &Timestamp, tool_version: &str) -> String {
    let mut out = format!(
        "# Cryptographic inventory: {}\n\nGenerated {} by rollcall {}.\n\n",
        md_cell(&match &product.version {
            Some(version) => format!("{} {version}", product.name),
            None => product.name.clone(),
        }),
        generated.as_str(),
        md_cell(tool_version),
    );
    let assets: Vec<_> = product
        .crypto_assets()
        .filter_map(|(path, _, c)| c.crypto.as_ref().map(|asset| (path, c, asset)))
        .collect();
    if assets.is_empty() {
        out.push_str("No cryptographic assets.\n");
        return out;
    }
    let evidence: usize = assets.iter().map(|(_, _, a)| a.evidence.len()).sum();
    out.push_str(&format!(
        "{}, {}.\n\n",
        plural(assets.len(), "cryptographic asset", "cryptographic assets"),
        plural(evidence, "evidence entry", "evidence entries"),
    ));
    let header: Vec<String> = HEADER.iter().map(|h| (*h).to_owned()).collect();
    out.push_str(&row(&header));
    let rule: Vec<String> = HEADER.iter().map(|h| "-".repeat(h.len())).collect();
    out.push_str(&row(&rule));
    for (path, component, asset) in assets {
        let fixed = [
            md_cell(&named(&component.name, component.version.as_deref())),
            md_cell(asset.asset_type().as_str()),
            md_cell(&details(asset)),
            md_cell(&parent(&path)),
        ];
        for entry in &asset.evidence {
            let mut cells = fixed.to_vec();
            cells.push(md_cell(&entry.locator.to_string()));
            cells.push(md_cell(entry.confidence.as_str()));
            cells.push(md_cell(entry.reason()));
            out.push_str(&row(&cells));
        }
    }
    out
}
