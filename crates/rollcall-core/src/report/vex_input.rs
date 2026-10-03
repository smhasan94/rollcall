//! VEX documents as `rollcall report --vex` reads them: rollcall's `rollcall-vex/1` report,
//! OpenVEX, and CycloneDX VEX (a standalone VEX BOM or an SBOM with embedded
//! `vulnerabilities`), told apart by content and normalised to [`VexStatement`]s.
//!
//! The parser never panics: anything it reads that has the wrong JSON type is a
//! [`VexInputError`] naming its JSON path; fields it does not read are ignored.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::model::ReportWarning;

/// A statement's status, in OpenVEX's (and `rollcall-vex/1`'s) words. CycloneDX analysis
/// states map onto them: `resolved` and `resolved_with_pedigree` are `fixed`, `exploitable`
/// is `affected`, `in_triage` (or no analysis) is `under_investigation`, and
/// `false_positive` is `not_affected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VexStatus {
    /// Not affected.
    NotAffected,
    /// Affected.
    Affected,
    /// Fixed.
    Fixed,
    /// Under investigation.
    UnderInvestigation,
}

impl VexStatus {
    /// The OpenVEX word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    /// Whether the status closes a finding (`not_affected` or `fixed`).
    pub fn closes(self) -> bool {
        matches!(self, Self::NotAffected | Self::Fixed)
    }
}

/// One vulnerability's status for one product, normalised from any VEX format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VexStatement {
    /// The vulnerability id and its aliases.
    pub ids: BTreeSet<String>,
    /// The SBOM `bom-ref` the statement is about (a bare `bom-ref`, or a BOM-Link's
    /// fragment), if it names one.
    pub bom_ref: Option<String>,
    /// The purl the statement is about, if it names one.
    pub purl: Option<String>,
    /// The status.
    pub status: VexStatus,
}

/// A VEX document that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VexInputError {
    /// Not JSON (including empty, truncated or not UTF-8).
    #[error("invalid JSON: {0}")]
    Json(String),
    /// Not a format rollcall reads.
    #[error("not a VEX document rollcall reads (rollcall-vex/1, OpenVEX or CycloneDX): {0}")]
    UnknownFormat(String),
    /// A field rollcall reads is missing or has the wrong type or value.
    #[error("{path}: expected {expected}")]
    Shape {
        /// The JSON path, e.g. `statements[3].status`.
        path: String,
        /// What was expected there.
        expected: String,
    },
}

/// The parsed statements, and problems that did not stop parsing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VexInput {
    /// The statements, sorted and de-duplicated.
    pub statements: Vec<VexStatement>,
    /// Non-fatal problems (e.g. a BOM-Link into another SBOM).
    pub warnings: Vec<ReportWarning>,
}

fn shape(path: impl Into<String>, expected: impl Into<String>) -> VexInputError {
    VexInputError::Shape {
        path: path.into(),
        expected: expected.into(),
    }
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, VexInputError> {
    value.as_object().ok_or_else(|| shape(path, "an object"))
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a [Value], VexInputError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| shape(path, "an array"))
}

fn string<'a>(value: &'a Value, path: &str) -> Result<&'a str, VexInputError> {
    value.as_str().ok_or_else(|| shape(path, "a string"))
}

fn required<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, VexInputError> {
    obj.get(key)
        .filter(|v| !v.is_null())
        .ok_or_else(|| shape(format!("{path}.{key}"), "a value"))
}

/// `key` of `obj` as an array of strings; absent or `null` is empty.
fn strings(
    obj: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<BTreeSet<String>, VexInputError> {
    let Some(value) = obj.get(key).filter(|v| !v.is_null()) else {
        return Ok(BTreeSet::new());
    };
    let path = format!("{path}.{key}");
    array(value, &path)?
        .iter()
        .enumerate()
        .map(|(i, v)| string(v, &format!("{path}[{i}]")).map(str::to_owned))
        .collect()
}

/// The identity of the SBOM the statements should be about, for BOM-Link checks.
pub struct SbomIdentity<'a> {
    /// The SBOM's `serialNumber` (`urn:uuid:…`), if it has one.
    pub serial_number: Option<&'a str>,
}

/// Parses one VEX document. `name` locates warnings.
pub fn parse_vex(
    bytes: &[u8],
    name: &str,
    sbom: &SbomIdentity<'_>,
) -> Result<VexInput, VexInputError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| VexInputError::Json(e.to_string()))?;
    let Some(root) = value.as_object() else {
        return Err(VexInputError::UnknownFormat(
            "the top level is not a JSON object".to_owned(),
        ));
    };
    let mut out = VexInput::default();
    let context = root.get("@context").and_then(Value::as_str);
    if root.get("schema").and_then(Value::as_str) == Some(crate::vex::REPORT_SCHEMA) {
        rollcall(root, &mut out)?;
    } else if context.is_some_and(|c| c.starts_with("https://openvex.dev/ns")) {
        openvex(root, name, sbom, &mut out)?;
    } else if root.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        cyclonedx(root, name, sbom, &mut out)?;
    } else {
        return Err(VexInputError::UnknownFormat(
            "no `schema: rollcall-vex/1`, OpenVEX `@context` or CycloneDX `bomFormat` at the \
             top level"
                .to_owned(),
        ));
    }
    out.statements.sort();
    out.statements.dedup();
    out.warnings.sort();
    out.warnings.dedup();
    Ok(out)
}

/// `rollcall-vex/1`: `statements[]` of `{vulnerability, aliases, component: {bom-ref, purl},
/// status}`. Unresolved findings are not statements.
fn rollcall(root: &Map<String, Value>, out: &mut VexInput) -> Result<(), VexInputError> {
    let list = array(required(root, "statements", "$")?, "$.statements")?;
    for (i, item) in list.iter().enumerate() {
        let at = format!("$.statements[{i}]");
        let st = object(item, &at)?;
        let mut ids = strings(st, "aliases", &at)?;
        ids.insert(
            string(
                required(st, "vulnerability", &at)?,
                &format!("{at}.vulnerability"),
            )?
            .to_owned(),
        );
        let component_at = format!("{at}.component");
        let component = object(required(st, "component", &at)?, &component_at)?;
        let bom_ref = string(
            required(component, "bom-ref", &component_at)?,
            &format!("{component_at}.bom-ref"),
        )?;
        let purl = match component.get("purl").filter(|v| !v.is_null()) {
            Some(v) => Some(string(v, &format!("{component_at}.purl"))?.to_owned()),
            None => None,
        };
        let status_at = format!("{at}.status");
        let status = openvex_status(
            string(required(st, "status", &at)?, &status_at)?,
            &status_at,
        )?;
        out.statements.push(VexStatement {
            ids,
            bom_ref: Some(bom_ref.to_owned()),
            purl,
            status,
        });
    }
    Ok(())
}

fn openvex_status(word: &str, path: &str) -> Result<VexStatus, VexInputError> {
    match word {
        "not_affected" => Ok(VexStatus::NotAffected),
        "affected" => Ok(VexStatus::Affected),
        "fixed" => Ok(VexStatus::Fixed),
        "under_investigation" => Ok(VexStatus::UnderInvestigation),
        _ => Err(shape(
            path,
            format!("not_affected, affected, fixed or under_investigation, found {word:?}"),
        )),
    }
}

fn cyclonedx_state(word: &str, path: &str) -> Result<VexStatus, VexInputError> {
    match word {
        "not_affected" | "false_positive" => Ok(VexStatus::NotAffected),
        "exploitable" => Ok(VexStatus::Affected),
        "resolved" | "resolved_with_pedigree" => Ok(VexStatus::Fixed),
        "in_triage" => Ok(VexStatus::UnderInvestigation),
        _ => Err(shape(
            path,
            format!(
                "a CycloneDX 1.6 analysis state (resolved, resolved_with_pedigree, \
                 exploitable, in_triage, false_positive, not_affected), found {word:?}"
            ),
        )),
    }
}

/// Splits a CycloneDX BOM-Link `urn:cdx:<uuid>/<version>#<fragment>` into the SBOM's serial
/// number (`urn:uuid:<uuid>`) and the percent-decoded `bom-ref`.
fn bom_link(link: &str) -> Option<(String, String)> {
    let rest = link.strip_prefix("urn:cdx:")?;
    let (document, fragment) = rest.split_once('#')?;
    let (uuid, _version) = document.split_once('/')?;
    Some((format!("urn:uuid:{uuid}"), percent_decode(fragment)?))
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            if !hex.bytes().all(|h| h.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A reference to an SBOM component: a BOM-Link (checked against the SBOM's serial number),
/// a purl, or a bare `bom-ref`. Returns `(bom_ref, purl)`; a BOM-Link into another SBOM
/// gives neither, with a warning, so it matches nothing.
fn target(
    reference: &str,
    path: &str,
    name: &str,
    sbom: &SbomIdentity<'_>,
    out: &mut VexInput,
) -> Result<(Option<String>, Option<String>), VexInputError> {
    if reference.starts_with("urn:cdx:") {
        let Some((serial, bom_ref)) = bom_link(reference) else {
            return Err(shape(
                path,
                format!("a BOM-Link urn:cdx:<uuid>/<version>#<bom-ref>, found {reference:?}"),
            ));
        };
        if sbom.serial_number != Some(serial.as_str()) {
            out.warnings.push(ReportWarning {
                location: name.to_owned(),
                message: format!(
                    "{path}: {reference} links to SBOM {serial}, not this one ({}); the \
                     statement is not applied",
                    sbom.serial_number.unwrap_or("which has no serialNumber")
                ),
            });
            return Ok((None, None));
        }
        return Ok((Some(bom_ref), None));
    }
    if reference.starts_with("pkg:") {
        return Ok((None, Some(reference.to_owned())));
    }
    Ok((Some(reference.to_owned()), None))
}

/// OpenVEX: `statements[]` of `{vulnerability: {name, aliases} | "<id>", products[]:
/// {@id, identifiers.purl}, status}` (a product needs an `@id` or an `identifiers.purl`).
/// One statement per product.
fn openvex(
    root: &Map<String, Value>,
    name: &str,
    sbom: &SbomIdentity<'_>,
    out: &mut VexInput,
) -> Result<(), VexInputError> {
    let list = array(required(root, "statements", "$")?, "$.statements")?;
    for (i, item) in list.iter().enumerate() {
        let at = format!("$.statements[{i}]");
        let st = object(item, &at)?;
        let vuln_at = format!("{at}.vulnerability");
        let ids = match required(st, "vulnerability", &at)? {
            Value::String(id) => BTreeSet::from([id.clone()]),
            other => {
                let v = object(other, &vuln_at)?;
                let mut ids = strings(v, "aliases", &vuln_at)?;
                ids.insert(
                    string(required(v, "name", &vuln_at)?, &format!("{vuln_at}.name"))?.to_owned(),
                );
                ids
            }
        };
        let status_at = format!("{at}.status");
        let status = openvex_status(
            string(required(st, "status", &at)?, &status_at)?,
            &status_at,
        )?;
        let products_at = format!("{at}.products");
        for (j, product) in array(required(st, "products", &at)?, &products_at)?
            .iter()
            .enumerate()
        {
            let p_at = format!("{products_at}[{j}]");
            let p = object(product, &p_at)?;
            let id_at = format!("{p_at}.@id");
            // OpenVEX v0.2.0 allows a product with `identifiers` and no `@id`.
            let (bom_ref, mut purl, linked_elsewhere) = match p.get("@id").filter(|v| !v.is_null())
            {
                Some(id) => {
                    let (bom_ref, purl) = target(string(id, &id_at)?, &id_at, name, sbom, out)?;
                    let elsewhere = bom_ref.is_none() && purl.is_none();
                    (bom_ref, purl, elsewhere)
                }
                None => (None, None, false),
            };
            let mut given_purl = None;
            if let Some(identifiers) = p.get("identifiers").filter(|v| !v.is_null()) {
                let ident_at = format!("{p_at}.identifiers");
                let identifiers = object(identifiers, &ident_at)?;
                if let Some(v) = identifiers.get("purl").filter(|v| !v.is_null()) {
                    given_purl = Some(string(v, &format!("{ident_at}.purl"))?.to_owned());
                }
            }
            if bom_ref.is_none() && purl.is_none() && given_purl.is_none() && !linked_elsewhere {
                return Err(shape(p_at, "an @id or identifiers.purl"));
            }
            // A BOM-Link into another SBOM matches nothing, its purl included.
            if !linked_elsewhere && given_purl.is_some() {
                purl = given_purl;
            }
            out.statements.push(VexStatement {
                ids: ids.clone(),
                bom_ref,
                purl,
                status,
            });
        }
    }
    Ok(())
}

/// CycloneDX: `vulnerabilities[]` of `{id, references[].id, analysis.state, affects[].ref}`.
/// One statement per `affects` entry; no analysis (or no state) is `under_investigation`. A
/// `ref` starting with `pkg:` is matched both as a `bom-ref` and as a purl.
/// A BOM without `vulnerabilities` has no statements.
fn cyclonedx(
    root: &Map<String, Value>,
    name: &str,
    sbom: &SbomIdentity<'_>,
    out: &mut VexInput,
) -> Result<(), VexInputError> {
    let Some(list) = root.get("vulnerabilities").filter(|v| !v.is_null()) else {
        out.warnings.push(ReportWarning {
            location: name.to_owned(),
            message: "the CycloneDX document has no vulnerabilities, so no VEX statements"
                .to_owned(),
        });
        return Ok(());
    };
    for (i, item) in array(list, "$.vulnerabilities")?.iter().enumerate() {
        let at = format!("$.vulnerabilities[{i}]");
        let v = object(item, &at)?;
        let mut ids =
            BTreeSet::from([string(required(v, "id", &at)?, &format!("{at}.id"))?.to_owned()]);
        if let Some(refs) = v.get("references").filter(|r| !r.is_null()) {
            let refs_at = format!("{at}.references");
            for (j, r) in array(refs, &refs_at)?.iter().enumerate() {
                let r_at = format!("{refs_at}[{j}]");
                let r = object(r, &r_at)?;
                ids.insert(string(required(r, "id", &r_at)?, &format!("{r_at}.id"))?.to_owned());
            }
        }
        let status = match v.get("analysis").filter(|a| !a.is_null()) {
            None => VexStatus::UnderInvestigation,
            Some(analysis) => {
                let a_at = format!("{at}.analysis");
                let analysis = object(analysis, &a_at)?;
                match analysis.get("state").filter(|s| !s.is_null()) {
                    None => VexStatus::UnderInvestigation,
                    Some(state) => {
                        let s_at = format!("{a_at}.state");
                        cyclonedx_state(string(state, &s_at)?, &s_at)?
                    }
                }
            }
        };
        let affects_at = format!("{at}.affects");
        let affects = match v.get("affects").filter(|a| !a.is_null()) {
            Some(a) => array(a, &affects_at)?,
            None => &[],
        };
        for (j, affected) in affects.iter().enumerate() {
            let e_at = format!("{affects_at}[{j}]");
            let e = object(affected, &e_at)?;
            let ref_at = format!("{e_at}.ref");
            let reference = string(required(e, "ref", &e_at)?, &ref_at)?;
            let (bom_ref, purl) = target(reference, &ref_at, name, sbom, out)?;
            // A `bom-ref` may itself be a purl (other tools use the purl as the bom-ref), so a
            // `pkg:` ref is tried both ways.
            let bom_ref =
                bom_ref.or_else(|| reference.starts_with("pkg:").then(|| reference.to_owned()));
            out.statements.push(VexStatement {
                ids: ids.clone(),
                bom_ref,
                purl,
                status,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_link_splits_and_decodes() {
        assert_eq!(
            bom_link("urn:cdx:1234/1#component:ab%23c"),
            Some(("urn:uuid:1234".to_owned(), "component:ab#c".to_owned()))
        );
        assert_eq!(bom_link("urn:cdx:1234#x"), None);
        assert_eq!(bom_link("urn:cdx:1234/1#x%2"), None);
        assert_eq!(bom_link("urn:cdx:1234/1#x%zz"), None);
        assert_eq!(bom_link("urn:cdx:1234/1#x%+1"), None);
        assert_eq!(bom_link("urn:cdx:1234/1#%ff"), None);
    }
}
