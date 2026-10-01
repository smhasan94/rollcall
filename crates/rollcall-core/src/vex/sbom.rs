//! What the VEX renderers need to know about the SBOM a report is about: its identity (for
//! BOM-Links), its product, and each `bom-ref`'s purl exactly as the SBOM spells it.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::render::VexError;
use crate::cyclonedx::SerialNumber;

/// The parts of a CycloneDX SBOM that VEX documents refer to. Built with
/// [`SbomIndex::from_bytes`], which never panics on malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomIndex {
    /// `serialNumber`, if the SBOM has one (always a lowercase `urn:uuid:`, as the CycloneDX
    /// 1.6 schema requires; anything else is rejected).
    pub serial_number: Option<SerialNumber>,
    /// `version` (1 when absent, the CycloneDX default; 0 is rejected).
    pub version: u64,
    /// Whether the document gives `version` explicitly.
    pub version_given: bool,
    /// A summary of `metadata.component`: its `type`, `name`, `version`, `purl` and `cpe`.
    pub product: Option<Map<String, Value>>,
    /// The product's supplier name (`metadata.component.supplier.name`).
    pub supplier: Option<String>,
    /// Every `bom-ref` in the document, with the purl its component gives (as written).
    pub refs: BTreeMap<String, Option<String>>,
    /// Whether the document already has a non-empty `vulnerabilities` array (an empty one
    /// counts as absent).
    pub has_vulnerabilities: bool,
}

impl SbomIndex {
    /// Indexes the CycloneDX JSON document in `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VexError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| VexError::Sbom(e.to_string()))?;
        Self::from_value(&value)
    }

    /// Indexes an already parsed CycloneDX JSON document.
    pub fn from_value(value: &Value) -> Result<Self, VexError> {
        let Some(doc) = value.as_object() else {
            return Err(VexError::Sbom(
                "the document is not a JSON object".to_owned(),
            ));
        };
        if doc.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX") {
            return Err(VexError::Sbom(
                "not a CycloneDX document (bomFormat is not \"CycloneDX\")".to_owned(),
            ));
        }
        let serial_number = match doc.get("serialNumber") {
            None => None,
            Some(Value::String(s)) => Some(SerialNumber::parse(s).map_err(|e| {
                VexError::Sbom(format!(
                    "serialNumber {s:?} is not a lowercase urn:uuid: ({e}), so BOM-Links to \
                     the SBOM cannot be formed"
                ))
            })?),
            Some(_) => return Err(VexError::Sbom("serialNumber is not a string".to_owned())),
        };
        let version = match doc.get("version") {
            None => 1,
            Some(v) => match v.as_u64() {
                Some(n) if n >= 1 => n,
                _ => {
                    return Err(VexError::Sbom(format!(
                        "version {v} is not an integer of at least 1"
                    )));
                }
            },
        };
        let has_vulnerabilities = match doc.get("vulnerabilities") {
            None => false,
            Some(Value::Array(list)) => !list.is_empty(),
            Some(_) => {
                return Err(VexError::Sbom("vulnerabilities is not an array".to_owned()));
            }
        };
        let component = doc
            .get("metadata")
            .and_then(Value::as_object)
            .and_then(|m| m.get("component"))
            .and_then(Value::as_object);
        let product = component.map(|c| {
            ["type", "name", "version", "purl", "cpe"]
                .iter()
                .filter_map(|k| {
                    c.get(*k)
                        .filter(|v| v.is_string())
                        .map(|v| ((*k).to_owned(), v.clone()))
                })
                .collect::<Map<String, Value>>()
        });
        let supplier = component
            .and_then(|c| c.get("supplier"))
            .and_then(Value::as_object)
            .and_then(|s| s.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut refs = BTreeMap::new();
        if let Some(c) = component {
            collect(c, &mut refs)?;
        }
        if let Some(list) = doc.get("components") {
            collect_list(list, &mut refs)?;
        }
        Ok(Self {
            serial_number,
            version,
            version_given: doc.contains_key("version"),
            product,
            supplier,
            refs,
            has_vulnerabilities,
        })
    }

    /// The CycloneDX BOM-Link to `bom_ref` in this SBOM (`urn:cdx:<uuid>/<version>#<ref>`),
    /// or `None` without a serial number. The fragment is percent-encoded where the BOM-Link
    /// syntax requires it.
    pub fn bom_link(&self, bom_ref: &str) -> Option<String> {
        let uuid = self
            .serial_number
            .as_ref()?
            .as_str()
            .strip_prefix("urn:uuid:")?;
        Some(format!(
            "urn:cdx:{uuid}/{}#{}",
            self.version,
            encode_fragment(bom_ref)
        ))
    }

    /// The purl the SBOM gives the component with `bom_ref`, exactly as written.
    pub fn purl_of(&self, bom_ref: &str) -> Option<&str> {
        self.refs.get(bom_ref).and_then(|p| p.as_deref())
    }
}

fn collect_list(list: &Value, refs: &mut BTreeMap<String, Option<String>>) -> Result<(), VexError> {
    let Some(items) = list.as_array() else {
        return Err(VexError::Sbom("components is not an array".to_owned()));
    };
    for item in items {
        let Some(c) = item.as_object() else {
            return Err(VexError::Sbom(
                "a component is not a JSON object".to_owned(),
            ));
        };
        collect(c, refs)?;
    }
    Ok(())
}

fn collect(
    component: &Map<String, Value>,
    refs: &mut BTreeMap<String, Option<String>>,
) -> Result<(), VexError> {
    match component.get("bom-ref") {
        None => {}
        Some(Value::String(r)) => {
            let purl = component
                .get("purl")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if refs.insert(r.clone(), purl).is_some() {
                return Err(VexError::Sbom(format!(
                    "bom-ref {r:?} is used more than once"
                )));
            }
        }
        Some(_) => return Err(VexError::Sbom("a bom-ref is not a string".to_owned())),
    }
    if let Some(list) = component.get("components") {
        collect_list(list, refs)?;
    }
    Ok(())
}

/// Percent-encodes everything but RFC 3986 unreserved characters and `:`, which rollcall's
/// `bom-ref`s (`component:<hex>`) use.
fn encode_fragment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_index_rejects_malformed_sbom_without_panic() {
        for bad in [
            &b""[..],
            b"{",
            b"[]",
            b"\xff\xfe",
            b"{\"bomFormat\":\"SPDX\"}",
            b"{\"bomFormat\":\"CycloneDX\",\"serialNumber\":7}",
            b"{\"bomFormat\":\"CycloneDX\",\"version\":-1}",
            b"{\"bomFormat\":\"CycloneDX\",\"version\":0}",
            b"{\"bomFormat\":\"CycloneDX\",\"version\":1.5}",
            b"{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"urn:uuid:3E671687-395B-41F5-A30F-A58921A69B79\"}",
            b"{\"bomFormat\":\"CycloneDX\",\"serialNumber\":\"3e671687-395b-41f5-a30f-a58921a69b79\"}",
            b"{\"bomFormat\":\"CycloneDX\",\"vulnerabilities\":{}}",
            b"{\"bomFormat\":\"CycloneDX\",\"components\":{}}",
            b"{\"bomFormat\":\"CycloneDX\",\"components\":[1]}",
            b"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"bom-ref\":[]}]}",
            b"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"bom-ref\":\"a\"},{\"bom-ref\":\"a\"}]}",
        ] {
            assert!(SbomIndex::from_bytes(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bom_link_needs_a_uuid_serial() {
        let index = SbomIndex::from_bytes(
            br#"{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":2,
                 "components":[{"bom-ref":"a b","purl":"pkg:generic/a@1"}]}"#,
        )
        .unwrap();
        assert_eq!(
            index.bom_link("a b").as_deref(),
            Some("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/2#a%20b")
        );
        assert_eq!(index.purl_of("a b"), Some("pkg:generic/a@1"));
        let none = SbomIndex::from_bytes(br#"{"bomFormat":"CycloneDX"}"#).unwrap();
        assert_eq!(none.bom_link("x"), None);
        assert_eq!(none.version, 1);
    }
}
