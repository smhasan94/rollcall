//! Reading VEX documents for `rollcall scan --vex`: the claims each makes about which
//! vulnerability affects which component.
//!
//! Three formats are read, told apart by content:
//!
//! - **OpenVEX** (`@context` starting `https://openvex.dev/ns`): each statement's
//!   `vulnerability` (`name` and `aliases`, or a bare string), `status`, `justification`,
//!   and its `products` (`@id` and `identifiers.purl`), or their `subcomponents` when a
//!   product has any (the product is then kept in [`Claim::products`], so the caller can
//!   check it is the scanned SBOM's). `identifiers.cpe23`/`cpe22` are ignored, with a
//!   warning. OpenVEX statements form a timeline: a statement's time is its
//!   `last_updated`, else its `timestamp`, else the document's `timestamp` (RFC 3339), and
//!   for each vulnerability and product only the latest statements of the document are
//!   kept; a statement without any time is older than one with a time.
//! - **CycloneDX** (`bomFormat` `CycloneDX`): a standalone VEX BOM or an SBOM with embedded
//!   `vulnerabilities`; each vulnerability's `id`, `references[].id` (aliases),
//!   `analysis.state` and `analysis.justification`, and `affects[].ref`. A vulnerability
//!   without `analysis.state` makes no claim and is skipped with a warning; `affects[]
//!   .versions` are ignored, with a warning. A plain `affects[].ref` (not a BOM-Link) is a
//!   `bom-ref` of the document itself, so when the document has a `serialNumber` it is read
//!   as a BOM-Link into that document (its `version`, default 1): applied to the scanned
//!   SBOM only when the serial numbers agree.
//! - **`rollcall-vex/1`** (`schema`): `rollcall vex`'s own report; each statement's
//!   `vulnerability`, `aliases`, `status`, `justification` and `component.bom-ref`.
//!   Unresolved entries are not claims.
//!
//! A product reference is a purl (`pkg:…`), a CycloneDX BOM-Link (`urn:cdx:<uuid>/<version>
//! #<bom-ref>`, the fragment percent-decoded) or, otherwise, a bare `bom-ref`.
//!
//! The parser never panics: a field it reads with the wrong JSON type, or an unknown status,
//! is a [`VexDocError::Shape`] naming its JSON path; an unusable product reference is
//! skipped with a [`Warning`].

use std::collections::BTreeSet;
use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::warning::Warning;

/// The format of a VEX document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VexFormat {
    /// OpenVEX.
    OpenVex,
    /// CycloneDX VEX, standalone or embedded in an SBOM.
    CycloneDx,
    /// `rollcall-vex/1`.
    Rollcall,
}

/// What a claim says about the vulnerability on the component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimStatus {
    /// Not affected (OpenVEX `not_affected`, CycloneDX `not_affected`).
    NotAffected,
    /// The finding is a false positive (CycloneDX `false_positive`).
    FalsePositive,
    /// Fixed (OpenVEX `fixed`, CycloneDX `resolved` or `resolved_with_pedigree`).
    Fixed,
    /// Affected (OpenVEX `affected`, CycloneDX `exploitable`).
    Affected,
    /// Under investigation (OpenVEX `under_investigation`, CycloneDX `in_triage`).
    UnderInvestigation,
}

impl ClaimStatus {
    /// The status's name, in OpenVEX's words (and `false_positive`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::FalsePositive => "false_positive",
            Self::Fixed => "fixed",
            Self::Affected => "affected",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    fn openvex(word: &str) -> Option<Self> {
        Some(match word {
            "not_affected" => Self::NotAffected,
            "affected" => Self::Affected,
            "fixed" => Self::Fixed,
            "under_investigation" => Self::UnderInvestigation,
            _ => return None,
        })
    }

    fn cyclonedx(word: &str) -> Option<Self> {
        Some(match word {
            "not_affected" => Self::NotAffected,
            "false_positive" => Self::FalsePositive,
            "resolved" | "resolved_with_pedigree" => Self::Fixed,
            "exploitable" => Self::Affected,
            "in_triage" => Self::UnderInvestigation,
            _ => return None,
        })
    }
}

impl fmt::Display for ClaimStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ClaimStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The component a claim is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimTarget {
    /// A bare `bom-ref` of the scanned SBOM.
    BomRef(String),
    /// A purl, as written.
    Purl(String),
    /// A CycloneDX BOM-Link: `urn:cdx:<uuid>/<version>#<bom-ref>`.
    BomLink {
        /// The SBOM's serial number (`urn:uuid:<uuid>`).
        serial_number: String,
        /// The SBOM's version.
        version: u64,
        /// The `bom-ref` (percent-decoded).
        bom_ref: String,
    },
}

/// One claim: a vulnerability's status on some components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The vulnerability id.
    pub vulnerability: String,
    /// Its other ids.
    pub aliases: BTreeSet<String>,
    /// The components it is about.
    pub targets: Vec<ClaimTarget>,
    /// The status.
    pub status: ClaimStatus,
    /// The justification, as written.
    pub justification: Option<String>,
    /// The statement's free-text detail, as written. OpenVEX: chosen by status,
    /// `impact_statement` for `not_affected`, `action_statement` for `affected`, then (for
    /// any status) `status_notes`. CycloneDX: `analysis.detail`. `rollcall-vex/1`: `detail`.
    /// Only `rollcall csaf` uses it (as the CSAF impact or action text); a value that is not
    /// a string is ignored.
    pub detail: Option<String>,
    /// CycloneDX `analysis.response` (e.g. `update`, `workaround_available`), sorted and
    /// deduplicated; empty for the other formats. Only `rollcall csaf` uses it (to choose a
    /// remediation category); values that are not strings are ignored.
    pub response: Vec<String>,
    /// For an OpenVEX statement whose products have `subcomponents`: those products (the
    /// claim's targets are the subcomponents). Empty otherwise.
    pub products: Vec<ClaimTarget>,
}

/// A parsed VEX document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexDocument {
    /// The format it was read as.
    pub format: VexFormat,
    /// Its claims, in document order.
    pub claims: Vec<Claim>,
    /// Skipped statements and product references, located by JSON path.
    pub warnings: Vec<Warning>,
}

/// Why a VEX document could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VexDocError {
    /// Not JSON (including empty, truncated or not UTF-8).
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Not OpenVEX, CycloneDX or `rollcall-vex/1`.
    #[error("not an OpenVEX, CycloneDX or rollcall-vex/1 document: {0}")]
    UnknownFormat(String),
    /// A field rollcall reads is missing, has the wrong type or an unknown value.
    #[error("{path}: expected {expected}")]
    Shape {
        /// The JSON path, e.g. `statements[3].status`.
        path: String,
        /// What was expected there.
        expected: &'static str,
    },
}

fn shape(path: impl Into<String>, expected: &'static str) -> VexDocError {
    VexDocError::Shape {
        path: path.into(),
        expected,
    }
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, VexDocError> {
    value.as_object().ok_or_else(|| shape(path, "an object"))
}

fn get<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn opt_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<&'a str>, VexDocError> {
    match get(obj, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(shape(format!("{path}.{key}"), "a string")),
    }
}

fn req_str<'a>(obj: &'a Map<String, Value>, key: &str, path: &str) -> Result<&'a str, VexDocError> {
    opt_str(obj, key, path)?.ok_or_else(|| shape(format!("{path}.{key}"), "a string"))
}

fn opt_array<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a [Value], VexDocError> {
    match get(obj, key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(shape(format!("{path}.{key}"), "an array")),
    }
}

fn opt_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<&'a Map<String, Value>>, VexDocError> {
    match get(obj, key) {
        None => Ok(None),
        Some(v) => object(v, &format!("{path}.{key}")).map(Some),
    }
}

/// A free-text field for [`Claim::detail`]: the first of `keys` that holds a non-empty string.
/// Lenient on purpose: the detail is informational, so a wrong type is ignored rather than
/// failing a document `rollcall scan` reads.
fn detail_text(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|k| obj.get(*k).and_then(Value::as_str))
        .find(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

fn strings(
    obj: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<BTreeSet<String>, VexDocError> {
    opt_array(obj, key, path)?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| shape(format!("{path}.{key}[{i}]"), "a string"))
        })
        .collect()
}

/// Parses an OpenVEX, CycloneDX (VEX or SBOM with `vulnerabilities`) or `rollcall-vex/1`
/// document, telling them apart by content.
pub fn parse_vex(bytes: &[u8]) -> Result<VexDocument, VexDocError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let Some(root) = value.as_object() else {
        return Err(VexDocError::UnknownFormat(
            "the top level is not a JSON object".to_owned(),
        ));
    };
    let context = root.get("@context").and_then(Value::as_str);
    if context.is_some_and(|c| c.starts_with("https://openvex.dev/ns")) {
        parse_openvex(root)
    } else if root.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        parse_cyclonedx(root)
    } else if root.get("schema").and_then(Value::as_str) == Some(crate::vex::REPORT_SCHEMA) {
        parse_rollcall(root)
    } else {
        Err(VexDocError::UnknownFormat(
            "no OpenVEX `@context`, CycloneDX `bomFormat` or rollcall-vex/1 `schema`".to_owned(),
        ))
    }
}

/// Percent-decodes a BOM-Link fragment; `None` if an escape is malformed or the result is
/// not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Interprets a product reference; an unusable one is `Err(reason)`.
fn target(reference: &str) -> Result<ClaimTarget, String> {
    if reference.is_empty() {
        return Err("empty product reference".to_owned());
    }
    if reference.starts_with("pkg:") {
        return Ok(ClaimTarget::Purl(reference.to_owned()));
    }
    let Some(link) = reference.strip_prefix("urn:cdx:") else {
        return Ok(ClaimTarget::BomRef(reference.to_owned()));
    };
    let malformed = || format!("malformed BOM-Link {reference:?}");
    let (bom, fragment) = link.split_once('#').ok_or_else(|| {
        format!("BOM-Link {reference:?} names a whole BOM, not a component; skipped")
    })?;
    let (uuid, version) = bom.split_once('/').ok_or_else(malformed)?;
    let version: u64 = version.parse().map_err(|_| malformed())?;
    if uuid.is_empty() || fragment.is_empty() {
        return Err(malformed());
    }
    let bom_ref = percent_decode(fragment).ok_or_else(malformed)?;
    Ok(ClaimTarget::BomLink {
        serial_number: format!("urn:uuid:{uuid}"),
        version,
        bom_ref,
    })
}

fn push_target(
    targets: &mut Vec<ClaimTarget>,
    reference: &str,
    path: String,
    warnings: &mut Vec<Warning>,
) {
    match target(reference) {
        Ok(t) => {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
        Err(reason) => warnings.push(Warning::new(path, reason)),
    }
}

/// An OpenVEX product or subcomponent: its `@id` and `identifiers.purl`.
fn openvex_product(
    product: &Map<String, Value>,
    path: &str,
    targets: &mut Vec<ClaimTarget>,
    warnings: &mut Vec<Warning>,
) -> Result<(), VexDocError> {
    if let Some(id) = opt_str(product, "@id", path)? {
        push_target(targets, id, format!("{path}.@id"), warnings);
    }
    if let Some(identifiers) = opt_object(product, "identifiers", path)? {
        let ipath = format!("{path}.identifiers");
        if let Some(purl) = opt_str(identifiers, "purl", &ipath)? {
            push_target(targets, purl, format!("{ipath}.purl"), warnings);
        }
        for key in ["cpe23", "cpe22"] {
            if get(identifiers, key).is_some() {
                warnings.push(Warning::new(
                    format!("{ipath}.{key}"),
                    "ignored: rollcall scan matches products by purl, BOM-Link or bom-ref",
                ));
            }
        }
    }
    Ok(())
}

/// An RFC 3339 time at `key` of `obj`, as nanoseconds since the epoch.
fn opt_time(obj: &Map<String, Value>, key: &str, path: &str) -> Result<Option<i128>, VexDocError> {
    match opt_str(obj, key, path)? {
        None => Ok(None),
        Some(text) => OffsetDateTime::parse(text, &Rfc3339)
            .map(|t| Some(t.unix_timestamp_nanos()))
            .map_err(|_| shape(format!("{path}.{key}"), "an RFC 3339 date-time")),
    }
}

/// Keeps, for each (vulnerability, target), only the latest of `claims` (one target each).
fn latest_only(claims: Vec<(Option<i128>, Claim)>) -> Vec<Claim> {
    let key = |c: &Claim| {
        (
            c.vulnerability.to_ascii_uppercase(),
            c.targets.first().cloned(),
        )
    };
    let mut latest: std::collections::BTreeMap<(String, Option<ClaimTarget>), Option<i128>> =
        std::collections::BTreeMap::new();
    for (time, claim) in &claims {
        let entry = latest.entry(key(claim)).or_insert(*time);
        if *time > *entry {
            *entry = *time;
        }
    }
    claims
        .into_iter()
        .filter(|(time, claim)| latest.get(&key(claim)) == Some(time))
        .map(|(_, claim)| claim)
        .collect()
}

fn parse_openvex(root: &Map<String, Value>) -> Result<VexDocument, VexDocError> {
    let mut claims = Vec::new();
    let mut warnings = Vec::new();
    let document_time = opt_time(root, "timestamp", "$")?;
    for (i, statement) in opt_array(root, "statements", "$")?.iter().enumerate() {
        let path = format!("statements[{i}]");
        let statement = object(statement, &path)?;
        let time = match opt_time(statement, "last_updated", &path)? {
            Some(t) => Some(t),
            None => opt_time(statement, "timestamp", &path)?.or(document_time),
        };
        let vpath = format!("{path}.vulnerability");
        let (vulnerability, aliases) = match get(statement, "vulnerability") {
            Some(Value::String(name)) => (name.clone(), BTreeSet::new()),
            Some(Value::Object(v)) => (
                req_str(v, "name", &vpath)?.to_owned(),
                strings(v, "aliases", &vpath)?,
            ),
            _ => return Err(shape(vpath, "an object or a string")),
        };
        let word = req_str(statement, "status", &path)?;
        let status = ClaimStatus::openvex(word).ok_or_else(|| {
            shape(
                format!("{path}.status"),
                "not_affected, affected, fixed or under_investigation",
            )
        })?;
        let justification = opt_str(statement, "justification", &path)?.map(str::to_owned);
        let detail = match status {
            ClaimStatus::NotAffected => {
                detail_text(statement, &["impact_statement", "status_notes"])
            }
            ClaimStatus::Affected => detail_text(statement, &["action_statement", "status_notes"]),
            _ => detail_text(statement, &["status_notes"]),
        };
        let mut targets = Vec::new();
        let mut products = Vec::new();
        for (p, product) in opt_array(statement, "products", &path)?.iter().enumerate() {
            let ppath = format!("{path}.products[{p}]");
            let product = object(product, &ppath)?;
            let subcomponents = opt_array(product, "subcomponents", &ppath)?;
            if subcomponents.is_empty() {
                openvex_product(product, &ppath, &mut targets, &mut warnings)?;
            } else {
                openvex_product(product, &ppath, &mut products, &mut warnings)?;
            }
            for (s, sub) in subcomponents.iter().enumerate() {
                let spath = format!("{ppath}.subcomponents[{s}]");
                openvex_product(object(sub, &spath)?, &spath, &mut targets, &mut warnings)?;
            }
        }
        if targets.is_empty() {
            warnings.push(Warning::new(
                path,
                format!("statement for {vulnerability} names no usable product; skipped"),
            ));
            continue;
        }
        let aliases: BTreeSet<String> = aliases
            .into_iter()
            .filter(|a| *a != vulnerability)
            .collect();
        // One claim per target, so the timeline is kept per (vulnerability, product).
        for target in targets {
            claims.push((
                time,
                Claim {
                    vulnerability: vulnerability.clone(),
                    aliases: aliases.clone(),
                    targets: vec![target],
                    status,
                    justification: justification.clone(),
                    detail: detail.clone(),
                    response: Vec::new(),
                    products: products.clone(),
                },
            ));
        }
    }
    Ok(VexDocument {
        format: VexFormat::OpenVex,
        claims: latest_only(claims),
        warnings,
    })
}

fn parse_cyclonedx(root: &Map<String, Value>) -> Result<VexDocument, VexDocError> {
    let mut claims = Vec::new();
    let mut warnings = Vec::new();
    let serial_number = opt_str(root, "serialNumber", "$")?;
    let version = match get(root, "version") {
        None => 1,
        Some(v) => v
            .as_u64()
            .filter(|n| *n >= 1)
            .ok_or_else(|| shape("$.version", "an integer of at least 1"))?,
    };
    for (i, vulnerability) in opt_array(root, "vulnerabilities", "$")?.iter().enumerate() {
        let path = format!("vulnerabilities[{i}]");
        let v = object(vulnerability, &path)?;
        let id = req_str(v, "id", &path)?.to_owned();
        let mut aliases = BTreeSet::new();
        for (r, reference) in opt_array(v, "references", &path)?.iter().enumerate() {
            let rpath = format!("{path}.references[{r}]");
            let alias = req_str(object(reference, &rpath)?, "id", &rpath)?;
            if alias != id {
                aliases.insert(alias.to_owned());
            }
        }
        let apath = format!("{path}.analysis");
        let analysis = opt_object(v, "analysis", &path)?;
        let state = match analysis {
            Some(a) => opt_str(a, "state", &apath)?,
            None => None,
        };
        let Some(state) = state else {
            warnings.push(Warning::new(
                path,
                format!("{id} has no analysis.state, so it makes no VEX claim; skipped"),
            ));
            continue;
        };
        let status = ClaimStatus::cyclonedx(state).ok_or_else(|| {
            shape(
                format!("{apath}.state"),
                "a CycloneDX 1.6 impactAnalysisState",
            )
        })?;
        let justification = match analysis {
            Some(a) => opt_str(a, "justification", &apath)?.map(str::to_owned),
            None => None,
        };
        let detail = analysis.and_then(|a| detail_text(a, &["detail"]));
        // Lenient like the detail: informational, never a reason to reject the document.
        let response: Vec<String> = analysis
            .and_then(|a| a.get("response"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<String>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
        let mut targets = Vec::new();
        for (a, affects) in opt_array(v, "affects", &path)?.iter().enumerate() {
            let fpath = format!("{path}.affects[{a}]");
            let affects = object(affects, &fpath)?;
            let reference = req_str(affects, "ref", &fpath)?;
            if get(affects, "versions").is_some() {
                warnings.push(Warning::new(
                    format!("{fpath}.versions"),
                    "ignored: the claim applies to the referenced component as a whole",
                ));
            }
            let before = targets.len();
            push_target(
                &mut targets,
                reference,
                format!("{fpath}.ref"),
                &mut warnings,
            );
            // A plain bom-ref is a component of this document.
            if let (Some(serial), Some(ClaimTarget::BomRef(r))) =
                (serial_number, targets.get(before).cloned())
                && targets.len() > before
            {
                let link = ClaimTarget::BomLink {
                    serial_number: serial.to_owned(),
                    version,
                    bom_ref: r,
                };
                targets.truncate(before);
                if !targets.contains(&link) {
                    targets.push(link);
                }
            }
        }
        if targets.is_empty() {
            warnings.push(Warning::new(
                path,
                format!("{id} affects no usable component; skipped"),
            ));
            continue;
        }
        claims.push(Claim {
            vulnerability: id,
            aliases,
            targets,
            status,
            justification,
            detail,
            response,
            products: Vec::new(),
        });
    }
    Ok(VexDocument {
        format: VexFormat::CycloneDx,
        claims,
        warnings,
    })
}

fn parse_rollcall(root: &Map<String, Value>) -> Result<VexDocument, VexDocError> {
    let mut claims = Vec::new();
    for (i, statement) in opt_array(root, "statements", "$")?.iter().enumerate() {
        let path = format!("statements[{i}]");
        let s = object(statement, &path)?;
        let vulnerability = req_str(s, "vulnerability", &path)?.to_owned();
        let aliases = strings(s, "aliases", &path)?
            .into_iter()
            .filter(|a| *a != vulnerability)
            .collect();
        let word = req_str(s, "status", &path)?;
        let status = ClaimStatus::openvex(word).ok_or_else(|| {
            shape(
                format!("{path}.status"),
                "not_affected, affected, fixed or under_investigation",
            )
        })?;
        let justification = opt_str(s, "justification", &path)?.map(str::to_owned);
        let detail = detail_text(s, &["detail"]);
        let cpath = format!("{path}.component");
        let component =
            opt_object(s, "component", &path)?.ok_or_else(|| shape(&cpath, "an object"))?;
        let bom_ref = req_str(component, "bom-ref", &cpath)?;
        claims.push(Claim {
            vulnerability,
            aliases,
            targets: vec![ClaimTarget::BomRef(bom_ref.to_owned())],
            status,
            justification,
            detail,
            response: Vec::new(),
            products: Vec::new(),
        });
    }
    Ok(VexDocument {
        format: VexFormat::Rollcall,
        claims,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn parse(value: &Value) -> Result<VexDocument, VexDocError> {
        parse_vex(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn openvex_reads_statements_products_and_subcomponents() {
        let doc = parse(&json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"vulnerability": {"name": "CVE-1", "aliases": ["GHSA-1", "CVE-1"]},
                 "products": [{"@id": "pkg:cargo/a@1", "identifiers": {"purl": "pkg:cargo/a@1"}}],
                 "status": "not_affected", "justification": "vulnerable_code_not_present"},
                {"vulnerability": "CVE-2",
                 "products": [{"@id": "pkg:generic/image@1",
                               "subcomponents": [{"@id": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/2#a%20b"}]}],
                 "status": "affected"},
                {"vulnerability": {"name": "CVE-3"}, "products": [], "status": "fixed"}
            ]
        }))
        .unwrap();
        assert_eq!(doc.format, VexFormat::OpenVex);
        assert_eq!(doc.claims.len(), 2);
        let first = &doc.claims[0];
        assert_eq!(first.aliases, BTreeSet::from(["GHSA-1".to_owned()]));
        assert_eq!(
            first.targets,
            vec![ClaimTarget::Purl("pkg:cargo/a@1".to_owned())]
        );
        assert_eq!(first.status, ClaimStatus::NotAffected);
        assert_eq!(
            doc.claims[1].targets,
            vec![ClaimTarget::BomLink {
                serial_number: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79".to_owned(),
                version: 2,
                bom_ref: "a b".to_owned(),
            }]
        );
        assert_eq!(doc.warnings.len(), 1, "{:?}", doc.warnings);
        assert_eq!(doc.warnings[0].location, "statements[2]");
    }

    #[test]
    fn cyclonedx_maps_states_and_skips_claimless_vulnerabilities() {
        let doc = parse(&json!({
            "bomFormat": "CycloneDX",
            "vulnerabilities": [
                {"id": "CVE-1", "references": [{"id": "GHSA-1", "source": {}}],
                 "analysis": {"state": "resolved_with_pedigree"}, "affects": [{"ref": "c:1"}]},
                {"id": "CVE-2", "analysis": {"state": "false_positive"}, "affects": [{"ref": "c:2"}]},
                {"id": "CVE-3", "analysis": {"state": "in_triage"}, "affects": [{"ref": "c:3"}]},
                {"id": "CVE-4", "analysis": {"state": "exploitable"}, "affects": [{"ref": "c:4"}]},
                {"id": "CVE-5", "affects": [{"ref": "c:5"}]},
                {"id": "CVE-6", "analysis": {"state": "not_affected", "justification": "code_not_present"},
                 "affects": [{"ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1"}]}
            ]
        }))
        .unwrap();
        let statuses: Vec<_> = doc.claims.iter().map(|c| c.status).collect();
        assert_eq!(
            statuses,
            [
                ClaimStatus::Fixed,
                ClaimStatus::FalsePositive,
                ClaimStatus::UnderInvestigation,
                ClaimStatus::Affected
            ]
        );
        assert_eq!(doc.claims[0].aliases, BTreeSet::from(["GHSA-1".to_owned()]));
        assert_eq!(
            doc.claims[0].targets,
            vec![ClaimTarget::BomRef("c:1".to_owned())]
        );
        // CVE-5 has no analysis; CVE-6's only ref is a whole-BOM link.
        assert_eq!(doc.warnings.len(), 3, "{:?}", doc.warnings);
    }

    #[test]
    fn rollcall_report_statements_are_claims_and_unresolved_are_not() {
        let doc = parse(&json!({
            "schema": "rollcall-vex/1",
            "statements": [{"vulnerability": "CVE-1", "aliases": ["GHSA-1"],
                            "component": {"bom-ref": "component:1", "name": "x"},
                            "status": "under_investigation", "rules": ["r"]}],
            "unresolved": [{"vulnerability": "CVE-2"}],
            "warnings": []
        }))
        .unwrap();
        assert_eq!(doc.format, VexFormat::Rollcall);
        assert_eq!(doc.claims.len(), 1);
        assert_eq!(
            doc.claims[0].targets,
            vec![ClaimTarget::BomRef("component:1".to_owned())]
        );
    }

    #[test]
    fn malformed_vex_is_an_error_never_a_panic() {
        let full = serde_json::to_vec(&json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": {"name": "CVE-1"}, "status": "fixed",
                            "products": [{"@id": "pkg:cargo/a@1"}]}]
        }))
        .unwrap();
        for bytes in [
            &b""[..],
            b"  ",
            &full[..full.len() / 2],
            b"\xff\xfe{}",
            b"{\"a\":}",
        ] {
            assert!(
                matches!(parse_vex(bytes), Err(VexDocError::Json(_))),
                "{bytes:?}"
            );
        }
        for bytes in [
            &b"[]"[..],
            b"{}",
            b"\"x\"",
            b"{\"@context\": \"https://example.com\"}",
        ] {
            assert!(
                matches!(parse_vex(bytes), Err(VexDocError::UnknownFormat(_))),
                "{bytes:?}"
            );
        }
        let ov = |statements: Value| json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": statements});
        let cases = [
            (ov(json!(5)), "$.statements"),
            (ov(json!([5])), "statements[0]"),
            (
                ov(json!([{"status": "fixed"}])),
                "statements[0].vulnerability",
            ),
            (
                ov(json!([{"vulnerability": {"name": 1}, "status": "fixed"}])),
                "statements[0].vulnerability.name",
            ),
            (
                ov(json!([{"vulnerability": "CVE-1"}])),
                "statements[0].status",
            ),
            (
                ov(json!([{"vulnerability": "CVE-1", "status": "bogus"}])),
                "statements[0].status",
            ),
            (
                ov(
                    json!([{"vulnerability": "CVE-1", "status": "fixed", "products": [{"@id": 3}]}]),
                ),
                "statements[0].products[0].@id",
            ),
            (
                ov(
                    json!([{"vulnerability": "CVE-1", "status": "fixed", "products": [{"subcomponents": {}}]}]),
                ),
                "statements[0].products[0].subcomponents",
            ),
            (
                json!({"@context": "https://openvex.dev/ns/v0.2.0", "timestamp": "yesterday"}),
                "$.timestamp",
            ),
            (
                ov(json!([{"vulnerability": "CVE-1", "status": "fixed", "last_updated": 5}])),
                "statements[0].last_updated",
            ),
            (
                ov(
                    json!([{"vulnerability": "CVE-1", "status": "fixed", "timestamp": "2026-13-01T00:00:00Z"}]),
                ),
                "statements[0].timestamp",
            ),
            (
                json!({"bomFormat": "CycloneDX", "serialNumber": 1}),
                "$.serialNumber",
            ),
            (json!({"bomFormat": "CycloneDX", "version": 0}), "$.version"),
            (
                json!({"bomFormat": "CycloneDX", "vulnerabilities": {}}),
                "$.vulnerabilities",
            ),
            (
                json!({"bomFormat": "CycloneDX", "vulnerabilities": [{"analysis": {"state": "x"}}]}),
                "vulnerabilities[0].id",
            ),
            (
                json!({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "C", "analysis": {"state": "bogus"}}]}),
                "vulnerabilities[0].analysis.state",
            ),
            (
                json!({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "C", "analysis": {"state": "exploitable"}, "affects": [{"ref": 1}]}]}),
                "vulnerabilities[0].affects[0].ref",
            ),
            (
                json!({"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "C", "analysis": 7}]}),
                "vulnerabilities[0].analysis",
            ),
            (
                json!({"schema": "rollcall-vex/1", "statements": [{"vulnerability": "C", "status": "fixed"}]}),
                "statements[0].component",
            ),
            (
                json!({"schema": "rollcall-vex/1", "statements": [{"vulnerability": "C", "status": "fixed", "component": {}}]}),
                "statements[0].component.bom-ref",
            ),
        ];
        for (doc, want) in cases {
            match parse(&doc) {
                Err(VexDocError::Shape { path, .. }) => assert_eq!(path, want, "{doc}"),
                other => panic!("{doc}: {other:?}"),
            }
        }
    }

    #[test]
    fn claim_detail_is_read_from_every_format_and_wrong_types_are_ignored() {
        let openvex_with = |status: &str, extra: Value| {
            let mut statement = json!({"vulnerability": "CVE-1", "status": status,
                "products": [{"@id": "pkg:generic/a@1"}]});
            for (k, v) in extra.as_object().unwrap() {
                statement[k] = v.clone();
            }
            json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": [statement]})
        };
        let openvex = |extra: Value| openvex_with("not_affected", extra);
        let detail = |doc: &Value| parse(doc).unwrap().claims[0].detail.clone();
        assert_eq!(
            detail(&openvex(
                json!({"impact_statement": "i", "action_statement": "a"})
            )),
            Some("i".to_owned())
        );
        // The detail is chosen by status: not_affected never takes the action statement.
        assert_eq!(
            detail(&openvex(
                json!({"action_statement": "a", "status_notes": "n"})
            )),
            Some("n".to_owned())
        );
        assert_eq!(detail(&openvex(json!({"action_statement": "a"}))), None);
        assert_eq!(
            detail(&openvex(
                json!({"impact_statement": " ", "status_notes": "n"})
            )),
            Some("n".to_owned())
        );
        assert_eq!(detail(&openvex(json!({"impact_statement": 5}))), None);
        assert_eq!(detail(&openvex(json!({}))), None);
        // affected: the action statement, never the impact statement.
        let both = json!({"impact_statement": "i", "action_statement": "a", "status_notes": "n"});
        assert_eq!(
            detail(&openvex_with("affected", both.clone())),
            Some("a".to_owned())
        );
        assert_eq!(
            detail(&openvex_with("affected", json!({"impact_statement": "i"}))),
            None
        );
        // fixed and under_investigation: only status_notes.
        for status in ["fixed", "under_investigation"] {
            assert_eq!(
                detail(&openvex_with(status, both.clone())),
                Some("n".to_owned()),
                "{status}"
            );
        }
        // Only CycloneDX carries a response.
        assert!(
            parse(&openvex(json!({}))).unwrap().claims[0]
                .response
                .is_empty()
        );

        let cdx = |analysis: Value| {
            json!({"bomFormat": "CycloneDX", "vulnerabilities": [
                {"id": "CVE-1", "analysis": analysis, "affects": [{"ref": "c:1"}]}]})
        };
        assert_eq!(
            detail(&cdx(json!({"state": "not_affected", "detail": "d"}))),
            Some("d".to_owned())
        );
        assert_eq!(
            detail(&cdx(json!({"state": "not_affected", "detail": ["d"]}))),
            None
        );
        let response = |analysis: Value| parse(&cdx(analysis)).unwrap().claims[0].response.clone();
        assert_eq!(
            response(json!({"state": "exploitable",
                "response": ["workaround_available", "update", 3, "update"]})),
            ["update", "workaround_available"]
        );
        assert!(response(json!({"state": "exploitable", "response": "update"})).is_empty());
        assert!(response(json!({"state": "exploitable"})).is_empty());

        let rollcall = json!({"schema": "rollcall-vex/1", "statements": [
            {"vulnerability": "CVE-1", "status": "affected", "detail": "upgrade",
             "component": {"bom-ref": "c:1"}}]});
        assert_eq!(detail(&rollcall), Some("upgrade".to_owned()));
    }

    #[test]
    fn ignored_identifiers_and_versions_warn() {
        let doc = parse(&json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [{"vulnerability": "CVE-1", "status": "fixed",
                "products": [{"@id": "pkg:cargo/a@1",
                              "identifiers": {"cpe23": "cpe:2.3:a:x:a:1:*:*:*:*:*:*:*", "cpe22": "cpe:/a:x:a:1"}}]}]
        }))
        .unwrap();
        let locations: Vec<&str> = doc.warnings.iter().map(|w| w.location.as_str()).collect();
        assert_eq!(
            locations,
            [
                "statements[0].products[0].identifiers.cpe23",
                "statements[0].products[0].identifiers.cpe22"
            ]
        );
        let doc = parse(&json!({
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{"id": "CVE-1", "analysis": {"state": "exploitable"},
                "affects": [{"ref": "c:1", "versions": [{"version": "1.0"}]}]}]
        }))
        .unwrap();
        assert_eq!(doc.claims.len(), 1);
        assert_eq!(doc.warnings.len(), 1, "{:?}", doc.warnings);
        assert_eq!(
            doc.warnings[0].location,
            "vulnerabilities[0].affects[0].versions"
        );
    }

    #[test]
    fn openvex_keeps_only_the_latest_statement_per_product() {
        let doc = parse(&json!({
            "@context": "https://openvex.dev/ns/v0.2.0",
            "timestamp": "2026-01-01T00:00:00Z",
            "statements": [
                {"vulnerability": "CVE-1", "status": "under_investigation",
                 "products": [{"@id": "pkg:cargo/a@1"}, {"@id": "pkg:cargo/b@1"}]},
                {"vulnerability": "cve-1", "status": "fixed", "timestamp": "2026-01-01T02:00:00+01:00",
                 "products": [{"@id": "pkg:cargo/a@1"}]}
            ]
        }))
        .unwrap();
        let claims: Vec<(ClaimStatus, &ClaimTarget)> = doc
            .claims
            .iter()
            .map(|c| (c.status, &c.targets[0]))
            .collect();
        assert_eq!(
            claims,
            [
                (
                    ClaimStatus::UnderInvestigation,
                    &ClaimTarget::Purl("pkg:cargo/b@1".to_owned())
                ),
                (
                    ClaimStatus::Fixed,
                    &ClaimTarget::Purl("pkg:cargo/a@1".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn product_references_and_malformed_bom_links() {
        assert_eq!(
            target("pkg:a/b@1"),
            Ok(ClaimTarget::Purl("pkg:a/b@1".to_owned()))
        );
        assert_eq!(
            target("component:x"),
            Ok(ClaimTarget::BomRef("component:x".to_owned()))
        );
        for bad in [
            "",
            "urn:cdx:uuid",
            "urn:cdx:uuid/1",
            "urn:cdx:uuid/x#a",
            "urn:cdx:/1#a",
            "urn:cdx:uuid/1#",
            "urn:cdx:uuid/1#%zz",
            "urn:cdx:uuid/1#%f",
            "urn:cdx:uuid/1#%ff",
        ] {
            assert!(target(bad).is_err(), "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn vex_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_vex(&bytes);
        }

        #[test]
        fn vex_parsers_never_panic_on_near_valid_json(
            head in prop::sample::select(vec![
                r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":"#,
                r#"{"bomFormat":"CycloneDX","vulnerabilities":"#,
                r#"{"schema":"rollcall-vex/1","statements":"#,
            ]),
            tail in r#"[\[\]\{\}",:a-z0-9_@#%/ ]{0,60}"#
        ) {
            let _ = parse_vex(format!("{head}{tail}").as_bytes());
        }

        #[test]
        fn bom_link_parser_never_panics(text in r"urn:cdx:[a-z0-9%/#-]{0,30}") {
            let _ = target(&text);
        }
    }
}
