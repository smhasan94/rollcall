//! `rollcall csaf`: scan and VEX results for an SBOM as a CSAF 2.0 document with the VEX
//! profile (`csaf_vex`).
//!
//! [`build`] takes the inputs `rollcall report` takes (a CycloneDX 1.6 SBOM, scanner output,
//! VEX documents) and runs them through `rollcall scan`'s pipeline
//! ([`scan::normalise`], then [`scan::apply`]),
//! so every CSAF product status is the scan's triage of that finding. [`to_json`] renders the
//! document and refuses to return one that fails the vendored CSAF 2.0 schema
//! ([`validate_csaf_2_0`]) or the mandatory tests rollcall's mapping is responsible for
//! ([`check_mandatory`]).
//!
//! # Inputs
//!
//! - **SBOM**: CycloneDX 1.6 JSON. `metadata.component` is the product and needs a
//!   `bom-ref`.
//! - **Scans** (at least one): grype `-o json`, osv-scanner `--format json` or
//!   `rollcall scan --json` (`rollcall-scan/1`, whose findings are re-triaged with `--vex`;
//!   its own triage is not used), told apart by content.
//! - **VEX** (optional): any document `rollcall scan --vex` reads (OpenVEX, CycloneDX VEX
//!   or an SBOM with embedded `vulnerabilities`, `rollcall-vex/1`).
//!
//! # Mapping
//!
//! | CSAF | From |
//! |------|------|
//! | `document.category` | `csaf_vex` |
//! | `document.publisher` | `--publisher` (default: the SBOM's `metadata.component.supplier.name`), `--publisher-namespace` (default: the supplier's first `url`), `--publisher-category` (default `vendor`) |
//! | `document.title` | `--title`, default `VEX for <product> <version>` |
//! | `document.distribution.tlp.label` | `--tlp`; absent by default |
//! | `document.tracking` | `id`: `--id`, default [`document_id`] (content-derived, so it changes with the findings: a series of updates to one advisory must pass a stable `--id`); `status` `final`, `version` always `1` with a single revision (no revision history yet); every date is `--timestamp`; `generator.engine` is rollcall and its version |
//! | `product_tree.branches` | the product: `vendor` (supplier, when given) → `product_name` → `product_version` (when versioned), ending in the product with `product_id` = its `bom-ref` |
//! | `product_tree.full_product_names` | every SBOM component (image or component, at any depth) that a vulnerability names, `product_id` = its `bom-ref`, `product_identification_helper.purl`/`.cpe` = its `purl`/`cpe` byte for byte; sorted by `product_id`. Components no finding names are left out, so every product id is used |
//! | `product_tree.relationships` | each of those components as part of the product (CSAF 2.0 §3.2.3.4): `default_component_of` (`optional_component_of` for CycloneDX scope `optional`) the product, `product_id` `<component bom-ref>@<product bom-ref>` ([`product_id_of`]). Flat, whatever the SBOM's nesting |
//! | `vulnerabilities[]` | one per finding id, sorted by id. `cve` when the id is a CVE; every other id and alias in `ids` (`system_name`: the id's prefix, e.g. `GHSA`) |
//! | `vulnerabilities[].notes` | one `summary`: the ids, the components, the scanners and the highest severity |
//! | product ids in `product_status`, `flags`, `threats`, `remediations` | the relationship product of the finding's component (the claim is about the component *in this product*), or the product's own `bom-ref` for a finding on the product |
//! | `product_status.known_affected` | triage `affected` (VEX `affected`, CycloneDX `exploitable`) |
//! | `product_status.known_not_affected` | triage `suppressed` by `not_affected` or `false_positive` |
//! | `product_status.fixed` | triage `suppressed` by `fixed` (CycloneDX `resolved`, `resolved_with_pedigree`) |
//! | `product_status.under_investigation` | triage `unresolved`: no claim, `under_investigation` (`in_triage`), or conflicting claims |
//! | `flags` | a `known_not_affected` product's justification: OpenVEX words as they are; CycloneDX `code_not_present` → `vulnerable_code_not_present`, `code_not_reachable` → `vulnerable_code_not_in_execute_path`, `requires_*` → `vulnerable_code_cannot_be_controlled_by_adversary`, `protected_*` → `inline_mitigations_already_exist` |
//! | `threats` (`impact`) | a `known_not_affected` product's impact statement (OpenVEX `impact_statement`, CycloneDX `analysis.detail`, `rollcall-vex/1` `detail`); without one, and without a flag, a generated one |
//! | `remediations` | every `known_affected` product gets one. Category from the claim's CycloneDX `analysis.response` ([`remediation_of`]: `update`/`rollback` → `vendor_fix`, `workaround_available` → `workaround`, `will_not_fix`/`can_not_fix` → `no_fix_planned`); with no response, `none_available` (no fixed firmware exists yet), its text naming the version fixed upstream when the scanners know one. Details are the claim's action statement (OpenVEX `action_statement`, CycloneDX `analysis.detail`, `rollcall-vex/1` `detail`), else generated |
//!
//! Not represented: findings on packages the SBOM does not list, on components outside its
//! product tree, and on components of scope `excluded` (no product to name, or not part of
//! the product; each left out with a warning), severities and CVSS scores (scanners' words
//! are not CVSS), licences, hashes and evidence.
//!
//! # Determinism
//!
//! The document depends only on the inputs' contents, the input file names (generated
//! texts cite a VEX document by its name), the options and the rollcall version: every list
//! is sorted, the default `tracking.id` is derived from content, and every date is the
//! `--timestamp`. The JSON is two-space-indented with keys in alphabetical order.

mod checks;
mod product_tree;
mod schema;
mod vulnerabilities;

use std::fmt;
use std::str::FromStr;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use checks::check_mandatory;
pub use product_tree::{
    Branch, FullProductName, IdentificationHelper, ProductTree, Relationship, SbomTree,
    build as build_product_tree, read_tree,
};
pub use schema::{
    CSAF_2_0_SCHEMA, CSAF_2_0_SCHEMA_SHA256, CVSS_V2_0_SCHEMA, CVSS_V2_0_SCHEMA_SHA256,
    CVSS_V3_0_SCHEMA, CVSS_V3_0_SCHEMA_SHA256, CVSS_V3_1_SCHEMA, CVSS_V3_1_SCHEMA_SHA256, is_csaf,
    validate_csaf_2_0,
};
pub use vulnerabilities::{
    Built, ConflictingStatus, Flag, Id, Note, ProductStatus, Remediation, Threat, Vulnerability,
    flag_of, is_cve, product_id_of, remediation_of,
};

use crate::cyclonedx::{SchemaViolation, Timestamp};
use crate::model::to_canonical_json;
use crate::report::Input;
use crate::report::scan_input;
use crate::scan::{self, Sbom, ScanFinding, VexDocError, parse_vex};
use crate::vex::{self, FindingsError};
use crate::warning::Warning;

/// The publisher's role (`document.publisher.category`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PublisherCategory {
    /// `coordinator`.
    Coordinator,
    /// `discoverer`.
    Discoverer,
    /// `other`.
    Other,
    /// `translator`.
    Translator,
    /// `user`.
    User,
    /// `vendor` (the default).
    #[default]
    Vendor,
}

impl PublisherCategory {
    /// The CSAF word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Discoverer => "discoverer",
            Self::Other => "other",
            Self::Translator => "translator",
            Self::User => "user",
            Self::Vendor => "vendor",
        }
    }
}

impl Serialize for PublisherCategory {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A Traffic Light Protocol label (`document.distribution.tlp.label`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tlp {
    /// `WHITE`.
    White,
    /// `GREEN`.
    Green,
    /// `AMBER`.
    Amber,
    /// `RED`.
    Red,
}

impl Tlp {
    /// The CSAF word.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::White => "WHITE",
            Self::Green => "GREEN",
            Self::Amber => "AMBER",
            Self::Red => "RED",
        }
    }
}

impl Serialize for Tlp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Why an option value is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct OptionError(String);

/// `document.publisher`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Publisher {
    /// The publisher's role.
    pub category: PublisherCategory,
    /// Its name.
    pub name: String,
    /// A URL under its control that identifies it.
    pub namespace: String,
}

/// Whether `text` looks like an absolute URI: a scheme, `:`, and no whitespace or control
/// characters. (The schema checks the rest.)
fn is_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !text.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl Publisher {
    /// A publisher. The name must not be blank and the namespace must be an absolute URI.
    pub fn new(
        category: PublisherCategory,
        name: &str,
        namespace: &str,
    ) -> Result<Self, OptionError> {
        if name.trim().is_empty() {
            return Err(OptionError("the publisher name is empty".to_owned()));
        }
        if !is_uri(namespace) {
            return Err(OptionError(format!(
                "the publisher namespace {namespace:?} is not an absolute URI (e.g. \
                 https://example.com)"
            )));
        }
        Ok(Self {
            category,
            name: name.to_owned(),
            namespace: namespace.to_owned(),
        })
    }
}

/// `document.tracking.id`: non-empty, without leading or trailing whitespace or any control
/// character (the schema's `^[\S](.*[\S])?$`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrackingId(String);

impl TrackingId {
    /// Parses a tracking id.
    pub fn parse(input: &str) -> Result<Self, OptionError> {
        if input.is_empty()
            || input.starts_with(char::is_whitespace)
            || input.ends_with(char::is_whitespace)
            || input.chars().any(char::is_control)
        {
            return Err(OptionError(format!(
                "{input:?} is not a CSAF tracking id: it must be non-empty, without leading or \
                 trailing whitespace or control characters"
            )));
        }
        Ok(Self(input.to_owned()))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for TrackingId {
    type Err = OptionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for TrackingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What [`build`] needs besides the inputs.
#[derive(Debug, Clone)]
pub struct CsafOptions {
    /// Every date in `document.tracking`.
    pub timestamp: Timestamp,
    /// `document.tracking.id`; default [`document_id`].
    pub id: Option<TrackingId>,
    /// The publisher's name; `None`: the SBOM's `metadata.component.supplier.name`.
    pub publisher_name: Option<String>,
    /// The publisher's namespace; `None`: the first URL of the SBOM product's supplier.
    pub publisher_namespace: Option<String>,
    /// The publisher's category.
    pub publisher_category: PublisherCategory,
    /// `document.title`; default `VEX for <product> <version>`.
    pub title: Option<String>,
    /// `document.distribution.tlp.label`; none by default.
    pub tlp: Option<Tlp>,
}

impl CsafOptions {
    /// Options with only the timestamp set.
    pub fn new(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            id: None,
            publisher_name: None,
            publisher_namespace: None,
            publisher_category: PublisherCategory::default(),
            title: None,
            tlp: None,
        }
    }
}

/// Why a CSAF document could not be built or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CsafError {
    /// The SBOM cannot be read.
    #[error("{name}: {message}")]
    Sbom {
        /// The SBOM's name.
        name: String,
        /// Why.
        message: String,
    },
    /// A scan cannot be read.
    #[error("{name}: {source}")]
    Scan {
        /// The scan's name.
        name: String,
        /// Why.
        source: FindingsError,
    },
    /// A VEX document cannot be read.
    #[error("{name}: {source}")]
    Vex {
        /// The VEX document's name.
        name: String,
        /// Why.
        source: VexDocError,
    },
    /// No publisher given, and the SBOM's product names no usable supplier.
    #[error("{0}")]
    Publisher(String),
    /// The findings give one product two statuses for one vulnerability.
    /// Carries the warnings gathered up to then.
    #[error("{conflict}")]
    Conflict {
        /// The conflict.
        conflict: ConflictingStatus,
        /// The inputs' warnings and left-out findings, sorted.
        warnings: Vec<Warning>,
    },
    /// No finding about a component of the product: CSAF needs at least one vulnerability.
    /// Carries the warnings that say what was left out and why.
    #[error("no finding about a component of the SBOM's product, so there is nothing to export")]
    NoFindings(Vec<Warning>),
    /// The document fails the CSAF 2.0 schema or a mandatory test (a rollcall bug, or an
    /// SBOM identifier CSAF's stricter patterns reject).
    #[error("the CSAF document is invalid: {}", list(.0))]
    Invalid(Vec<SchemaViolation>),
    /// The document cannot be serialised.
    #[error("cannot serialise the CSAF document: {0}")]
    Json(String),
}

fn list(violations: &[SchemaViolation]) -> String {
    violations
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// `document.distribution`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Distribution {
    /// The TLP label.
    pub tlp: TlpLabel,
}

/// `document.distribution.tlp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlpLabel {
    /// The label.
    pub label: Tlp,
}

/// `document.tracking.revision_history[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Revision {
    /// The timestamp.
    pub date: String,
    /// `1`.
    pub number: &'static str,
    /// `Initial version.`
    pub summary: &'static str,
}

/// `document.tracking.generator.engine`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Engine {
    /// `rollcall`.
    pub name: &'static str,
    /// rollcall's version.
    pub version: &'static str,
}

/// `document.tracking.generator`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Generator {
    /// The timestamp.
    pub date: String,
    /// rollcall.
    pub engine: Engine,
}

/// `document.tracking`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Tracking {
    /// The timestamp.
    pub current_release_date: String,
    /// rollcall and its version.
    pub generator: Generator,
    /// The tracking id.
    pub id: String,
    /// The timestamp.
    pub initial_release_date: String,
    /// One revision.
    pub revision_history: Vec<Revision>,
    /// `final`.
    pub status: &'static str,
    /// `1`.
    pub version: &'static str,
}

/// `document`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocumentMeta {
    /// `csaf_vex`.
    pub category: &'static str,
    /// `2.0`.
    pub csaf_version: &'static str,
    /// The TLP label, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Distribution>,
    /// `en`.
    pub lang: &'static str,
    /// The publisher.
    pub publisher: Publisher,
    /// The title.
    pub title: String,
    /// Tracking.
    pub tracking: Tracking,
}

/// A CSAF 2.0 VEX document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Csaf {
    /// `document`.
    pub document: DocumentMeta,
    /// `product_tree`.
    pub product_tree: ProductTree,
    /// `vulnerabilities`.
    pub vulnerabilities: Vec<Vulnerability>,
}

/// The result of [`build`]: the document and what was skipped or could not be read.
#[derive(Debug, Clone)]
pub struct Export {
    /// The document.
    pub csaf: Csaf,
    /// The inputs' warnings and left-out findings, sorted.
    pub warnings: Vec<Warning>,
    /// The triaged findings the document was built from (the scan pipeline's output).
    pub findings: Vec<ScanFinding>,
}

/// Domain-separation prefix of [`document_id`].
const ID_DOMAIN: &[u8] = b"rollcall-csaf-id/1\n";

/// The default `tracking.id`: `rollcall-csaf-` followed by the first 16 hex digits of
/// SHA-256 over `rollcall-csaf-id/1\n` and the canonical JSON of the product tree and
/// vulnerabilities. Depends on content alone (not the timestamp or the publisher).
pub fn document_id(
    product_tree: &ProductTree,
    vulnerabilities: &[Vulnerability],
) -> Result<TrackingId, CsafError> {
    let content = serde_json::to_vec(&(product_tree, vulnerabilities))
        .map_err(|e| CsafError::Json(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(ID_DOMAIN);
    hasher.update(&content);
    let hex: String = hasher
        .finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(TrackingId(format!("rollcall-csaf-{hex}")))
}

fn publisher(options: &CsafOptions, sbom: &Value) -> Result<Publisher, CsafError> {
    let supplier = sbom
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("supplier"));
    let supplier_name = supplier
        .and_then(|s| s.get("name"))
        .and_then(Value::as_str)
        .filter(|n| !n.trim().is_empty());
    let supplier_url = supplier
        .and_then(|s| s.get("url"))
        .and_then(Value::as_array)
        .and_then(|urls| urls.iter().filter_map(Value::as_str).find(|u| is_uri(u)));
    let name = options.publisher_name.as_deref().or(supplier_name);
    let namespace = options.publisher_namespace.as_deref().or(supplier_url);
    match (name, namespace) {
        (Some(name), Some(namespace)) => {
            Publisher::new(options.publisher_category, name, namespace)
                .map_err(|e| CsafError::Publisher(e.to_string()))
        }
        (None, _) => Err(CsafError::Publisher(
            "no publisher: pass --publisher, or give the SBOM's product a supplier name".to_owned(),
        )),
        (Some(_), None) => Err(CsafError::Publisher(
            "no publisher namespace: pass --publisher-namespace, or give the SBOM's product \
             supplier a url"
                .to_owned(),
        )),
    }
}

/// Builds the CSAF document for `sbom` from `scans` and `vex` documents (see the
/// [module docs](self)). Never panics; a malformed input is a [`CsafError`].
pub fn build(
    sbom: Input<'_>,
    scans: &[Input<'_>],
    vex: &[Input<'_>],
    options: &CsafOptions,
) -> Result<Export, CsafError> {
    let sbom_err = |message: String| CsafError::Sbom {
        name: sbom.name.to_owned(),
        message,
    };
    let document: Value =
        serde_json::from_slice(sbom.bytes).map_err(|e| sbom_err(format!("not valid JSON: {e}")))?;
    let scanned = Sbom::from_bytes(sbom.bytes).map_err(|e| sbom_err(e.to_string()))?;
    let tree = read_tree(&document).map_err(sbom_err)?;
    let publisher = publisher(options, &document)?;

    let mut warnings: Vec<Warning> = Vec::new();
    let mut findings = Vec::new();
    for input in scans {
        let parsed = match serde_json::from_slice::<Value>(input.bytes) {
            Ok(value) if scan_input::is_scan_report(&value) => {
                scan_input::parse_scan_report(&value)
            }
            _ => vex::parse_findings(input.bytes).map(|f| (f.findings, f.warnings)),
        };
        let (found, found_warnings) = parsed.map_err(|source| CsafError::Scan {
            name: input.name.to_owned(),
            source,
        })?;
        warnings.extend(
            found_warnings
                .into_iter()
                .map(|w| Warning::new(format!("{}: {}", input.name, w.location), w.message)),
        );
        findings.extend(found);
    }
    let mut documents = Vec::with_capacity(vex.len());
    for input in vex {
        let parsed = parse_vex(input.bytes).map_err(|source| CsafError::Vex {
            name: input.name.to_owned(),
            source,
        })?;
        documents.push((input.name.to_owned(), parsed));
    }

    let normalised = scan::normalise(&scanned, &findings);
    let applied = scan::apply(normalised.findings, &documents, &scanned);
    warnings.extend(scanned.warnings.iter().cloned());
    warnings.extend(normalised.warnings);
    warnings.extend(applied.warnings);

    let built = match vulnerabilities::build(&applied.findings, &tree, &mut warnings) {
        Ok(built) => built,
        Err(conflict) => {
            warnings.sort();
            warnings.dedup();
            return Err(CsafError::Conflict { conflict, warnings });
        }
    };
    let vulnerabilities = built.vulnerabilities;
    if vulnerabilities.is_empty() {
        warnings.sort();
        warnings.dedup();
        return Err(CsafError::NoFindings(warnings));
    }
    let product_tree = product_tree::build(&tree, &built.components);
    let id = match &options.id {
        Some(id) => id.clone(),
        None => document_id(&product_tree, &vulnerabilities)?,
    };
    let date = options.timestamp.as_str().to_owned();
    let title = options
        .title
        .clone()
        .unwrap_or_else(|| format!("VEX for {}", tree.product.label()));
    warnings.sort();
    warnings.dedup();
    Ok(Export {
        csaf: Csaf {
            document: DocumentMeta {
                category: "csaf_vex",
                csaf_version: "2.0",
                distribution: options.tlp.map(|label| Distribution {
                    tlp: TlpLabel { label },
                }),
                lang: "en",
                publisher,
                title,
                tracking: Tracking {
                    current_release_date: date.clone(),
                    generator: Generator {
                        date: date.clone(),
                        engine: Engine {
                            name: "rollcall",
                            version: env!("CARGO_PKG_VERSION"),
                        },
                    },
                    id: id.0,
                    initial_release_date: date.clone(),
                    revision_history: vec![Revision {
                        date,
                        number: "1",
                        summary: "Initial version.",
                    }],
                    status: "final",
                    version: "1",
                },
            },
            product_tree,
            vulnerabilities,
        },
        warnings,
        findings: applied.findings,
    })
}

/// Checks a CSAF document: the vendored CSAF 2.0 schema, then (if it passes) the mandatory
/// tests of [`check_mandatory`]. Returns every failure, sorted.
pub fn validate(document: &Value) -> Result<(), Vec<SchemaViolation>> {
    validate_csaf_2_0(document)?;
    let failures = check_mandatory(document);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

/// Renders `csaf` as canonical JSON (two-space-indented, keys in a fixed order, a final
/// newline), after checking it with [`validate`]: a document that fails is
/// [`CsafError::Invalid`] and is not returned.
pub fn to_json(csaf: &Csaf) -> Result<String, CsafError> {
    let value = serde_json::to_value(csaf).map_err(|e| CsafError::Json(e.to_string()))?;
    validate(&value).map_err(CsafError::Invalid)?;
    to_canonical_json(csaf).map_err(|e| CsafError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_id_parse_rejects_blank_padded_and_control() {
        for good in ["rollcall-csaf-0123", "ACME-2026-001", "a", "a b"] {
            assert_eq!(TrackingId::parse(good).unwrap().as_str(), good);
        }
        for bad in ["", " ", " a", "a ", "a\nb", "a\tb", "\u{7f}"] {
            assert!(TrackingId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn publisher_needs_a_name_and_an_absolute_uri() {
        let ok = Publisher::new(
            PublisherCategory::Vendor,
            "Example",
            "https://devices.example",
        )
        .unwrap();
        assert_eq!(ok.namespace, "https://devices.example");
        for (name, namespace) in [
            ("", "https://x.example"),
            ("  ", "https://x.example"),
            ("x", ""),
            ("x", "devices.example"),
            ("x", "https://x.example/a b"),
            ("x", "1http://x"),
            ("x", "https:"),
        ] {
            assert!(
                Publisher::new(PublisherCategory::Vendor, name, namespace).is_err(),
                "{name:?} {namespace:?}"
            );
        }
    }
}
