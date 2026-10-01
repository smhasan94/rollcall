//! Rendering a [`Report`] as an OpenVEX document, a standalone CycloneDX 1.6 VEX BOM, or
//! `vulnerabilities` embedded in the SBOM itself. See the [module docs](super) (`# Output
//! formats`) for the mapping. Nothing is re-evaluated: each statement of the report becomes
//! exactly one OpenVEX statement and one `affects` entry of a CycloneDX vulnerability.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde::Serialize;
use serde_json::{Map, Value};

use super::evaluate::{Report, Statement};
use super::rules::{Justification, Status};
use super::sbom::SbomIndex;
use crate::cyclonedx::{SerialNumber, Timestamp};
use crate::model::to_canonical_json;
use crate::warning::Warning;

/// The OpenVEX version rollcall writes.
pub const OPENVEX_CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

/// Domain separation for derived VEX document ids ([`document_id`]); the format's name and a
/// newline follow it, so an OpenVEX document and a CycloneDX VEX document for the same
/// triage get different ids.
const ID_DOMAIN: &str = "rollcall-vex-id/1 ";

/// Which kind of VEX document an id is derived for ([`document_id`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    /// An OpenVEX document (`@id`).
    OpenVex,
    /// A CycloneDX VEX document (`serialNumber`).
    CycloneDx,
}

impl DocumentKind {
    fn name(self) -> &'static str {
        match self {
            Self::OpenVex => "openvex",
            Self::CycloneDx => "cyclonedx",
        }
    }
}

/// The `action_statement` of an OpenVEX `affected` statement whose rule gives no detail
/// (OpenVEX requires one for `affected`).
pub const DEFAULT_ACTION: &str =
    "No remediation is recorded in the VEX rules; see the vulnerability's advisory.";

/// Property recording the OpenVEX justification on a CycloneDX vulnerability, so the
/// many-to-one mapping between the vocabularies loses nothing.
pub const OPENVEX_JUSTIFICATION_PROPERTY: &str = "rollcall:openvex-justification";

/// Why a VEX document could not be rendered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VexError {
    /// The SBOM is not a CycloneDX JSON document rollcall can index.
    #[error("invalid SBOM: {0}")]
    Sbom(String),
    /// A CycloneDX VEX document needs the SBOM's `serialNumber` for its BOM-Links.
    #[error(
        "the SBOM has no urn:uuid serialNumber, so a CycloneDX VEX document cannot link to its \
         components; give it one (rollcall generate always does) or use --format openvex"
    )]
    NoSerialNumber,
    /// A statement cites a `bom-ref` the SBOM does not have.
    #[error("statement for {vulnerability} cites bom-ref {bom_ref:?}, which is not in the SBOM")]
    UnknownBomRef {
        /// The vulnerability.
        vulnerability: String,
        /// The missing `bom-ref`.
        bom_ref: String,
    },
    /// `--embed` into an SBOM that already has `vulnerabilities`.
    #[error("the SBOM already has a `vulnerabilities` array; refusing to embed a second one")]
    AlreadyHasVulnerabilities,
    /// Serialisation failed.
    #[error("cannot serialise the VEX document: {0}")]
    Json(String),
}

/// Document-level settings shared by both formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexOptions {
    /// The document timestamp.
    pub timestamp: Timestamp,
    /// The document id (OpenVEX `@id`, CycloneDX `serialNumber`); derived by [`document_id`]
    /// when `None`.
    pub id: Option<SerialNumber>,
    /// The OpenVEX `author`; defaults to the SBOM product's supplier, else `rollcall`.
    pub author: Option<String>,
}

impl VexOptions {
    /// Options with `timestamp` and every other setting defaulted.
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            id: None,
            author: None,
        }
    }
}

/// A rendered document, with what the reader should be told about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The document, as canonical JSON ending in a newline.
    pub text: String,
    /// E.g. statements about a component without a purl.
    pub warnings: Vec<Warning>,
}

/// The id of the `kind` VEX document for `report` about `sbom`: a `urn:uuid:` derived from
/// the document kind, the statements and the SBOM's serial number and version alone — not
/// the timestamp or the order of anything — so the same triage of the same SBOM always gets
/// the same id, and its OpenVEX and CycloneDX renderings get different ones.
pub fn document_id(report: &Report, sbom: Option<&SbomIndex>, kind: DocumentKind) -> SerialNumber {
    // Each statement's compact JSON, sorted, one per line: independent of statement order.
    let mut lines: Vec<String> = report
        .statements
        .iter()
        .map(|s| serde_json::to_string(s).unwrap_or_default())
        .collect();
    lines.sort();
    let mut content = Vec::new();
    for line in lines {
        content.extend_from_slice(line.as_bytes());
        content.push(b'\n');
    }
    if let Some(sbom) = sbom {
        let serial = sbom.serial_number.as_ref().map_or("", SerialNumber::as_str);
        content.extend_from_slice(serial.as_bytes());
        content.push(b'/');
        content.extend_from_slice(sbom.version.to_string().as_bytes());
    }
    let domain = format!("{ID_DOMAIN}{}\n", kind.name());
    SerialNumber::derive_from(domain.as_bytes(), &content)
}

fn tooling() -> String {
    format!("rollcall/{}", env!("CARGO_PKG_VERSION"))
}

fn json(value: &impl Serialize) -> Result<String, VexError> {
    to_canonical_json(value).map_err(|e| VexError::Json(e.to_string()))
}

// ---------------------------------------------------------------------------------------
// OpenVEX

#[derive(Serialize)]
struct OpenVex<'a> {
    #[serde(rename = "@context")]
    context: &'static str,
    #[serde(rename = "@id")]
    id: String,
    author: String,
    timestamp: &'a str,
    version: u32,
    tooling: String,
    statements: Vec<OpenVexStatement>,
}

#[derive(Serialize)]
struct OpenVexStatement {
    vulnerability: OpenVexVulnerability,
    products: Vec<OpenVexProduct>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    status_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact_statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_statement: Option<String>,
}

#[derive(Serialize)]
struct OpenVexVulnerability {
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
}

#[derive(Serialize)]
struct OpenVexProduct {
    #[serde(rename = "@id")]
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifiers: Option<Identifiers>,
}

#[derive(Serialize)]
struct Identifiers {
    purl: String,
}

/// The product id of a statement: the component's purl, spelled as the SBOM spells it
/// (grype matches it against the SBOM's purl string), else its BOM-Link, else its
/// `bom-ref`; the last two with a warning, since scanners match products by purl.
fn product_of(
    statement: &Statement,
    sbom: Option<&SbomIndex>,
) -> (OpenVexProduct, Option<Warning>) {
    let bom_ref = &statement.component.bom_ref;
    let purl = sbom
        .and_then(|s| s.purl_of(bom_ref))
        .map(str::to_owned)
        .or_else(|| {
            statement
                .component
                .purl
                .as_ref()
                .map(|p| p.as_str().to_owned())
        });
    if let Some(purl) = purl {
        return (
            OpenVexProduct {
                id: purl.clone(),
                identifiers: Some(Identifiers { purl }),
            },
            None,
        );
    }
    let id = sbom
        .and_then(|s| s.bom_link(bom_ref))
        .unwrap_or_else(|| bom_ref.clone());
    let warning = Warning::new(
        format!(
            "{} on {} ({bom_ref})",
            statement.vulnerability, statement.component.name
        ),
        format!(
            "the component has no purl, so the OpenVEX product is {id}, which scanners \
             matching by purl will not recognise"
        ),
    );
    (
        OpenVexProduct {
            id,
            identifiers: None,
        },
        Some(warning),
    )
}

/// Renders `report` as an OpenVEX v0.2.0 document: one statement per report statement, in
/// the report's order (by vulnerability, then component).
pub fn to_openvex(
    report: &Report,
    sbom: Option<&SbomIndex>,
    options: &VexOptions,
) -> Result<Rendered, VexError> {
    let mut warnings = Vec::new();
    let statements = report
        .statements
        .iter()
        .map(|s| {
            let (product, warning) = product_of(s, sbom);
            warnings.extend(warning);
            let (status_notes, impact_statement, action_statement) = match s.status {
                Status::NotAffected => (None, s.detail.clone(), None),
                Status::Affected => (
                    None,
                    None,
                    Some(
                        s.detail
                            .clone()
                            .unwrap_or_else(|| DEFAULT_ACTION.to_owned()),
                    ),
                ),
                Status::Fixed | Status::UnderInvestigation => (s.detail.clone(), None, None),
            };
            OpenVexStatement {
                vulnerability: OpenVexVulnerability {
                    name: s.vulnerability.clone(),
                    aliases: s.aliases.iter().cloned().collect(),
                },
                products: vec![product],
                status: s.status.openvex(),
                status_notes,
                justification: s.justification.map(|j| j.openvex()),
                impact_statement,
                action_statement,
            }
        })
        .collect();
    let id = options
        .id
        .clone()
        .unwrap_or_else(|| document_id(report, sbom, DocumentKind::OpenVex));
    let author = match options
        .author
        .clone()
        .or_else(|| sbom.and_then(|s| s.supplier.clone()))
    {
        Some(author) => author,
        None => {
            warnings.push(Warning::new(
                "OpenVEX author",
                "no --author and no supplier on the SBOM's product, so the document's author \
                 is \"rollcall\"; name the party responsible for these statements with \
                 --author",
            ));
            "rollcall".to_owned()
        }
    };
    let doc = OpenVex {
        context: OPENVEX_CONTEXT,
        id: id.as_str().to_owned(),
        author,
        timestamp: options.timestamp.as_str(),
        version: 1,
        tooling: tooling(),
        statements,
    };
    Ok(Rendered {
        text: json(&doc)?,
        warnings,
    })
}

// ---------------------------------------------------------------------------------------
// CycloneDX

#[derive(Serialize)]
struct VexBom<'a> {
    #[serde(rename = "bomFormat")]
    bom_format: &'static str,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    version: u32,
    metadata: Metadata<'a>,
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Serialize)]
struct Metadata<'a> {
    timestamp: &'a str,
    tools: Tools,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<&'a Map<String, Value>>,
}

#[derive(Serialize)]
struct Tools {
    components: Vec<Tool>,
}

#[derive(Serialize)]
struct Tool {
    #[serde(rename = "type")]
    kind: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct Vulnerability {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    references: Vec<Reference>,
    analysis: Analysis,
    affects: Vec<Affects>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize)]
struct Source {
    name: &'static str,
    url: String,
}

#[derive(Serialize)]
struct Reference {
    id: String,
    source: Source,
}

#[derive(Serialize)]
struct Analysis {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    justification: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Serialize)]
struct Affects {
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Property {
    name: &'static str,
    value: String,
}

/// Where a vulnerability id is published: NVD for `CVE-` ids, else OSV (which also indexes
/// GHSA, RUSTSEC and the other ecosystems' ids).
fn source_of(id: &str) -> Source {
    if id.starts_with("CVE-") {
        Source {
            name: "NVD",
            url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
        }
    } else {
        Source {
            name: "OSV",
            url: format!("https://osv.dev/vulnerability/{id}"),
        }
    }
}

/// Groups statements that say the same thing about the same vulnerability (id, status,
/// justification and detail) into one CycloneDX vulnerability whose `affects` lists every
/// component, each referenced by `reference(bom_ref)`.
fn vulnerabilities(
    report: &Report,
    reference: impl Fn(&Statement) -> Result<String, VexError>,
) -> Result<Vec<Vulnerability>, VexError> {
    type Key = (String, Status, Option<Justification>, Option<String>);
    #[derive(Default)]
    struct Group {
        aliases: BTreeSet<String>,
        affects: BTreeSet<String>,
        properties: BTreeSet<Property>,
        cyclonedx_justification: Option<&'static str>,
    }
    let mut groups: BTreeMap<Key, Group> = BTreeMap::new();
    for s in &report.statements {
        let key = (
            s.vulnerability.clone(),
            s.status,
            s.justification,
            s.detail.clone(),
        );
        let group = groups.entry(key).or_default();
        group.aliases.extend(s.aliases.iter().cloned());
        group.affects.insert(reference(s)?);
        if let Some(j) = s.justification {
            group.cyclonedx_justification = Some(j.cyclonedx());
            group.properties.insert(Property {
                name: OPENVEX_JUSTIFICATION_PROPERTY,
                value: j.openvex().to_owned(),
            });
        }
        for rule in &s.rules {
            group.properties.insert(Property {
                name: "rollcall:rule",
                value: rule.clone(),
            });
        }
        for e in &s.evidence {
            group.properties.insert(Property {
                name: "rollcall:evidence",
                value: e.clone(),
            });
        }
    }
    Ok(groups
        .into_iter()
        .map(|((id, status, _, detail), g)| Vulnerability {
            source: Some(source_of(&id)),
            references: g
                .aliases
                .into_iter()
                .map(|a| Reference {
                    source: source_of(&a),
                    id: a,
                })
                .collect(),
            analysis: Analysis {
                state: status.cyclonedx_state(),
                justification: g.cyclonedx_justification,
                detail,
            },
            affects: g
                .affects
                .into_iter()
                .map(|reference| Affects { reference })
                .collect(),
            properties: g.properties.into_iter().collect(),
            id,
        })
        .collect())
}

fn known_ref(sbom: &SbomIndex, s: &Statement) -> Result<(), VexError> {
    if sbom.refs.contains_key(&s.component.bom_ref) {
        Ok(())
    } else {
        Err(VexError::UnknownBomRef {
            vulnerability: s.vulnerability.clone(),
            bom_ref: s.component.bom_ref.clone(),
        })
    }
}

/// Renders `report` as a standalone CycloneDX 1.6 VEX BOM: no `components`, the SBOM's
/// product as `metadata.component`, and one vulnerability per (id, status, justification,
/// detail) whose `affects[].ref` are BOM-Links into `sbom`.
pub fn to_cyclonedx_vex(
    report: &Report,
    sbom: &SbomIndex,
    options: &VexOptions,
) -> Result<Rendered, VexError> {
    if sbom.bom_link("").is_none() {
        return Err(VexError::NoSerialNumber);
    }
    let vulnerabilities = vulnerabilities(report, |s| {
        known_ref(sbom, s)?;
        sbom.bom_link(&s.component.bom_ref)
            .ok_or(VexError::NoSerialNumber)
    })?;
    let id = options
        .id
        .clone()
        .unwrap_or_else(|| document_id(report, Some(sbom), DocumentKind::CycloneDx));
    let bom = VexBom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: id.as_str().to_owned(),
        version: 1,
        metadata: Metadata {
            timestamp: options.timestamp.as_str(),
            tools: Tools {
                components: vec![Tool {
                    kind: "application",
                    name: "rollcall",
                    version: env!("CARGO_PKG_VERSION"),
                }],
            },
            component: sbom.product.as_ref(),
        },
        vulnerabilities,
    };
    Ok(Rendered {
        text: json(&bom)?,
        warnings: Vec::new(),
    })
}

/// The SBOM in `sbom_bytes` with `report`'s statements added as a top-level
/// `vulnerabilities` array whose `affects[].ref` are the SBOM's own `bom-ref`s, and its
/// `version` incremented by one (CycloneDX: the version SHOULD be incremented when a BOM is
/// modified; `serialNumber` is kept, so BOM-Links to the new version use the new number).
///
/// Only two token spans change: the top-level `version` value is rewritten in place, and
/// the array is appended before the closing `}` (or replaces an existing empty
/// `vulnerabilities: []`). Every other byte of the SBOM is kept. An SBOM without `version`
/// is implicitly version 1; it gets `"version": 2` appended next to the array. An SBOM whose
/// `vulnerabilities` is not empty is refused. A report without statements leaves the SBOM
/// unchanged, version included.
pub fn embed(sbom_bytes: &[u8], report: &Report) -> Result<Rendered, VexError> {
    let sbom = SbomIndex::from_bytes(sbom_bytes)?;
    if sbom.has_vulnerabilities {
        return Err(VexError::AlreadyHasVulnerabilities);
    }
    let vulnerabilities = vulnerabilities(report, |s| {
        known_ref(&sbom, s)?;
        Ok(s.component.bom_ref.clone())
    })?;
    // from_bytes succeeded, so the bytes are UTF-8 JSON whose root is an object.
    let text = std::str::from_utf8(sbom_bytes).map_err(|e| VexError::Sbom(e.to_string()))?;
    if vulnerabilities.is_empty() {
        return Ok(Rendered {
            text: text.to_owned(),
            warnings: Vec::new(),
        });
    }
    let members = top_level_members(text).ok_or_else(|| {
        VexError::Sbom("cannot locate the document's top-level members".to_owned())
    })?;
    // serde_json keeps the last of duplicated keys; so do we.
    let span = |key: &str| {
        members
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, r)| r.clone())
    };
    let array = serde_json::to_string_pretty(&vulnerabilities)
        .map_err(|e| VexError::Json(e.to_string()))?
        .replace('\n', "\n  ");
    let version = sbom
        .version
        .checked_add(1)
        .ok_or_else(|| VexError::Sbom("version is too large to increment".to_owned()))?
        .to_string();

    let mut edits: Vec<(Range<usize>, String)> = Vec::new();
    let mut appended: Vec<String> = Vec::new();
    match span("version") {
        Some(range) => edits.push((range, version)),
        None => appended.push(format!("\"version\": {version}")),
    }
    match span("vulnerabilities") {
        Some(range) => edits.push((range, array)),
        None => appended.push(format!("\"vulnerabilities\": {array}")),
    }
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    let mut out = text.to_owned();
    for (range, replacement) in edits {
        if out.get(range.clone()).is_none() {
            return Err(VexError::Sbom("cannot rewrite the document".to_owned()));
        }
        out.replace_range(range, &replacement);
    }
    if !appended.is_empty() {
        let Some(open) = out.trim_end().strip_suffix('}') else {
            return Err(VexError::Sbom(
                "the document does not end with `}`".to_owned(),
            ));
        };
        let open = open.trim_end();
        let mut joined = String::from(open);
        for (i, member) in appended.iter().enumerate() {
            if i > 0 || !open.ends_with('{') {
                joined.push(',');
            }
            joined.push_str("\n  ");
            joined.push_str(member);
        }
        joined.push_str("\n}\n");
        out = joined;
    }
    // The splice must leave valid JSON; check rather than trust.
    serde_json::from_str::<Value>(&out)
        .map_err(|e| VexError::Sbom(format!("cannot embed into this document: {e}")))?;
    Ok(Rendered {
        text: out,
        warnings: Vec::new(),
    })
}

/// Each top-level member of the JSON object in `text`: its decoded key and the byte range of
/// its value. `None` if `text` is not an object.
fn top_level_members(text: &str) -> Option<Vec<(String, Range<usize>)>> {
    let b = text.as_bytes();
    let mut i = skip_ws(b, 0);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    let mut out = Vec::new();
    loop {
        i = skip_ws(b, i);
        match b.get(i)? {
            b'}' => return Some(out),
            b',' if !out.is_empty() => i = skip_ws(b, i + 1),
            b'"' => {}
            _ => return None,
        }
        let key_start = i;
        let key_end = skip_string(b, i)?;
        let key: String = serde_json::from_str(text.get(key_start..key_end)?).ok()?;
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(b, i + 1);
        let end = skip_value(b, i)?;
        out.push((key, i..end));
        i = end;
    }
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// The index just past the string starting at `i` (which must be `"`).
fn skip_string(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    loop {
        match b.get(j)? {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
}

/// The index just past the JSON value starting at `i`.
fn skip_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => skip_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            loop {
                match b.get(j)? {
                    b'"' => {
                        j = skip_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        _ => {
            let mut j = i;
            while b
                .get(j)
                .is_some_and(|c| !matches!(c, b',' | b'}' | b']') && !c.is_ascii_whitespace())
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::top_level_members;

    #[test]
    fn top_level_members_locate_values() {
        let text = r#" { "a" : [1, {"x": "]}"}], "v\u0065rsion": 7 ,"s":"q\"}" } "#;
        let members = top_level_members(text).unwrap();
        let found: Vec<(&str, &str)> = members
            .iter()
            .map(|(k, r)| (k.as_str(), &text[r.clone()]))
            .collect();
        assert_eq!(
            found,
            [
                ("a", r#"[1, {"x": "]}"}]"#),
                ("version", "7"),
                ("s", r#""q\"}""#)
            ]
        );
        assert_eq!(top_level_members("{}").unwrap(), []);
        for bad in [
            "",
            "[]",
            "{",
            "{\"a\"",
            "{\"a\":",
            "{,}",
            "{\"a\":1,,}",
            "{\"a\":\"x}",
        ] {
            assert!(top_level_members(bad).is_none(), "{bad:?}");
        }
    }
}
