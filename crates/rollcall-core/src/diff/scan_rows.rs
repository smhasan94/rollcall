//! Reading the diff's inputs: the findings of a `rollcall-scan/1` report and the summary of a
//! `rollcall-report/1` report.
//!
//! Both readers never panic. A scan field read with the wrong JSON type, or a required one
//! that is missing, is a [`DiffError::Shape`] naming its path; the report's summary and
//! score are optional, so a missing or mistyped one is read as `None`.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::DiffError;
use crate::report::{Input, REPORT_SCHEMA};
use crate::scan::SCAN_SCHEMA;
use crate::severity::Severity;

/// One finding of a `rollcall-scan/1` report.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScanRow {
    /// The vulnerability id.
    pub id: String,
    /// Its other ids, sorted, without `id`.
    pub aliases: BTreeSet<String>,
    /// The component's name (or the reported package's, when the SBOM does not list it).
    pub component_name: String,
    /// The component's `bom-ref`, when the finding is on a component of the SBOM.
    pub bom_ref: Option<String>,
    /// The component's (or package's) version.
    pub version: Option<String>,
    /// The normalised severity.
    pub severity: Severity,
    /// The fixed versions, sorted.
    pub fixed_versions: BTreeSet<String>,
    /// `suppressed`, `affected` or `unresolved`.
    pub triage: String,
}

impl ScanRow {
    /// The id and every alias.
    pub fn ids(&self) -> BTreeSet<&str> {
        std::iter::once(self.id.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .collect()
    }

    /// Whether VEX suppressed it (it never counts toward a gate).
    pub fn is_suppressed(&self) -> bool {
        self.triage == "suppressed"
    }
}

/// The parts of a `rollcall-report/1` report the diff shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportSummary {
    /// `score.value`, if present and an integer from 0 to 100.
    pub score: Option<u32>,
    /// `summary`, if present and a string.
    pub summary: Option<String>,
}

fn shape(input: &str, path: impl Into<String>, expected: &'static str) -> DiffError {
    DiffError::Shape {
        name: input.to_owned(),
        path: path.into(),
        expected,
    }
}

fn get<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn json(input: Input<'_>) -> Result<Value, DiffError> {
    serde_json::from_slice(input.bytes).map_err(|e| DiffError::Json {
        name: input.name.to_owned(),
        message: e.to_string(),
    })
}

/// A JSON document's `schema`, which must be `want`.
fn check_schema<'a>(
    input: &str,
    value: &'a Value,
    want: &'static str,
) -> Result<&'a Map<String, Value>, DiffError> {
    let root = value
        .as_object()
        .ok_or_else(|| shape(input, "$", "an object"))?;
    let found = root.get("schema").and_then(Value::as_str);
    if found != Some(want) {
        return Err(DiffError::Schema {
            name: input.to_owned(),
            expected: want,
            found: found.map(str::to_owned),
        });
    }
    Ok(root)
}

struct Reader<'a> {
    input: &'a str,
}

impl Reader<'_> {
    fn object<'v>(
        &self,
        value: &'v Value,
        path: &str,
    ) -> Result<&'v Map<String, Value>, DiffError> {
        value
            .as_object()
            .ok_or_else(|| shape(self.input, path, "an object"))
    }

    fn opt_str<'v>(
        &self,
        obj: &'v Map<String, Value>,
        key: &str,
        path: &str,
    ) -> Result<Option<&'v str>, DiffError> {
        match get(obj, key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(shape(self.input, format!("{path}.{key}"), "a string")),
        }
    }

    fn req_str<'v>(
        &self,
        obj: &'v Map<String, Value>,
        key: &str,
        path: &str,
    ) -> Result<&'v str, DiffError> {
        self.opt_str(obj, key, path)?
            .ok_or_else(|| shape(self.input, format!("{path}.{key}"), "a string"))
    }

    fn strings(
        &self,
        obj: &Map<String, Value>,
        key: &str,
        path: &str,
    ) -> Result<BTreeSet<String>, DiffError> {
        let items = match get(obj, key) {
            None => return Ok(BTreeSet::new()),
            Some(Value::Array(items)) => items,
            Some(_) => return Err(shape(self.input, format!("{path}.{key}"), "an array")),
        };
        items
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| shape(self.input, format!("{path}.{key}[{i}]"), "a string"))
            })
            .collect()
    }
}

/// Reads every finding of a `rollcall-scan/1` report (`rollcall scan --json`), in the
/// report's order.
pub fn read_scan_rows(input: Input<'_>) -> Result<Vec<ScanRow>, DiffError> {
    let value = json(input)?;
    let root = check_schema(input.name, &value, SCAN_SCHEMA)?;
    let r = Reader { input: input.name };
    let findings = match get(root, "findings") {
        Some(Value::Array(items)) => items,
        _ => return Err(shape(input.name, "$.findings", "an array")),
    };
    let mut rows = Vec::with_capacity(findings.len());
    for (i, finding) in findings.iter().enumerate() {
        let path = format!("findings[{i}]");
        let f = r.object(finding, &path)?;
        let id = r.req_str(f, "id", &path)?.to_owned();
        let aliases = r
            .strings(f, "aliases", &path)?
            .into_iter()
            .filter(|a| *a != id)
            .collect();
        let severity: Severity = r.req_str(f, "severity", &path)?.parse().map_err(|_| {
            shape(
                input.name,
                format!("{path}.severity"),
                "a rollcall severity",
            )
        })?;
        let triage = r.req_str(f, "triage", &path)?;
        if !matches!(triage, "suppressed" | "affected" | "unresolved") {
            return Err(shape(
                input.name,
                format!("{path}.triage"),
                "suppressed, affected or unresolved",
            ));
        }
        let fixed_versions = r.strings(f, "fixed_versions", &path)?;
        // The component it was joined to, else the package as reported.
        let (target, tpath, bom_ref) = match get(f, "component") {
            Some(c) => {
                let tpath = format!("{path}.component");
                let target = r.object(c, &tpath)?;
                let bom_ref = r.opt_str(target, "bom-ref", &tpath)?.map(str::to_owned);
                (target, tpath, bom_ref)
            }
            None => {
                let tpath = format!("{path}.package");
                match get(f, "package") {
                    Some(p) => (r.object(p, &tpath)?, tpath, None),
                    None => return Err(shape(input.name, tpath, "an object")),
                }
            }
        };
        let component_name = r.req_str(target, "name", &tpath)?.to_owned();
        let version = r
            .opt_str(target, "version", &tpath)?
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        rows.push(ScanRow {
            id,
            aliases,
            component_name,
            bom_ref,
            version,
            severity,
            fixed_versions,
            triage: triage.to_owned(),
        });
    }
    Ok(rows)
}

/// Reads the score and summary of a `rollcall-report/1` report (`rollcall report --format
/// json`). The document must be JSON with that `schema`; a missing or mistyped score or
/// summary is `None`.
pub fn read_report_summary(input: Input<'_>) -> Result<ReportSummary, DiffError> {
    let value = json(input)?;
    let root = check_schema(input.name, &value, REPORT_SCHEMA)?;
    let score = root
        .get("score")
        .and_then(|s| s.get("value"))
        .and_then(Value::as_u64)
        .filter(|v| *v <= 100)
        .and_then(|v| u32::try_from(v).ok());
    let summary = root
        .get("summary")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(ReportSummary { score, summary })
}
