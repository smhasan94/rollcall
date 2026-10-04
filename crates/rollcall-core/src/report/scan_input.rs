//! `rollcall scan --json` output (`rollcall-scan/1`) as a `--scan` input.
//!
//! Each normalised finding becomes one scanner [`Finding`], which the report then joins and
//! merges like raw grype or osv-scanner findings:
//!
//! - its id, aliases and fixed versions are kept;
//! - its package is the SBOM component it was joined to (name, version, purl), so the report
//!   joins it to that component again; a finding with no component keeps the package the
//!   scanner reported (and stays `not-in-sbom`);
//! - its severity is the scanner's own word for the normalised (highest) severity: the
//!   severity of the first source whose word normalises to it, else the normalised name
//!   itself, so the report shows what the scanner wrote, as with raw scanner output.
//!
//! The scan's VEX triage (`triage`, `vex`) is **not** used: the report closes findings only
//! with its own `--vex` documents, so its VEX coverage counts statements it can see. When the
//! scan was triaged, a warning says how many findings it suppressed and asks for the same
//! documents with `--vex`. A scanner the scan records as `failed` or `skipped` is warned
//! about too: the scan's findings are incomplete.
//!
//! The parser never panics: a field it reads with the wrong JSON type is a
//! [`FindingsError::Shape`] naming its path; an unusable purl is dropped with a warning.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::model::Purl;
use crate::scan::SCAN_SCHEMA;
use crate::severity::{Severity, normalise_severity};
use crate::vex::{Finding, FindingsError, Scanner};
use crate::warning::Warning;

/// Whether `value` is a `rollcall-scan/1` document.
pub(crate) fn is_scan_report(value: &Value) -> bool {
    value.get("schema").and_then(Value::as_str) == Some(SCAN_SCHEMA)
}

fn shape(path: impl Into<String>, expected: &'static str) -> FindingsError {
    FindingsError::Shape {
        path: path.into(),
        expected,
    }
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, FindingsError> {
    value.as_object().ok_or_else(|| shape(path, "an object"))
}

fn get<'a>(obj: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    obj.get(key).filter(|v| !v.is_null())
}

fn opt_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<&'a str>, FindingsError> {
    match get(obj, key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(shape(format!("{path}.{key}"), "a string")),
    }
}

fn req_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a str, FindingsError> {
    opt_str(obj, key, path)?.ok_or_else(|| shape(format!("{path}.{key}"), "a string"))
}

fn opt_array<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a [Value], FindingsError> {
    match get(obj, key) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(shape(format!("{path}.{key}"), "an array")),
    }
}

fn strings(
    obj: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<BTreeSet<String>, FindingsError> {
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

fn scanner_of(name: &str) -> Option<Scanner> {
    match name {
        "grype" => Some(Scanner::Grype),
        "osv-scanner" => Some(Scanner::Osv),
        _ => None,
    }
}

/// Reads a `rollcall-scan/1` document's findings (see the [module docs](self)).
pub(crate) fn parse_scan_report(
    value: &Value,
) -> Result<(Vec<Finding>, Vec<Warning>), FindingsError> {
    let root = object(value, "$")?;
    let mut warnings = Vec::new();

    for (i, run) in opt_array(root, "scanners", "$")?.iter().enumerate() {
        let path = format!("scanners[{i}]");
        let run = object(run, &path)?;
        let name = req_str(run, "name", &path)?;
        let status = req_str(run, "status", &path)?;
        if status != "ok" {
            warnings.push(Warning::new(
                path,
                format!(
                    "{name} was {status} in this scan, so its findings are missing from the \
                     report"
                ),
            ));
        }
    }

    let findings = match get(root, "findings") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => return Err(shape("$.findings", "an array")),
    };
    let mut out = Vec::with_capacity(findings.len());
    let mut suppressed = 0usize;
    for (i, finding) in findings.iter().enumerate() {
        let path = format!("findings[{i}]");
        let f = object(finding, &path)?;
        let id = req_str(f, "id", &path)?.to_owned();
        let aliases: BTreeSet<String> = strings(f, "aliases", &path)?
            .into_iter()
            .filter(|a| *a != id)
            .collect();
        let fixed_in = strings(f, "fixed_versions", &path)?;
        let severity_word = req_str(f, "severity", &path)?;
        let severity: Severity = severity_word
            .parse()
            .map_err(|_| shape(format!("{path}.severity"), "a rollcall severity name"))?;
        if opt_str(f, "triage", &path)? == Some("suppressed") {
            suppressed += 1;
        }

        // The sources: the scanner and its own severity word.
        let mut scanner = None;
        let mut raw_severity = None;
        for (s, source) in opt_array(f, "sources", &path)?.iter().enumerate() {
            let spath = format!("{path}.sources[{s}]");
            let source = object(source, &spath)?;
            let name = req_str(source, "scanner", &spath)?;
            let word = opt_str(source, "severity", &spath)?;
            scanner = scanner.or_else(|| scanner_of(name));
            if raw_severity.is_none() && word.is_some() && normalise_severity(word) == severity {
                raw_severity = word.map(str::to_owned);
            }
        }
        let severity_text = raw_severity
            .or_else(|| (severity != Severity::Unknown).then(|| severity.as_str().to_owned()));

        // The component it was joined to, else the package as reported.
        let (target, tpath) = match get(f, "component") {
            Some(c) => (
                object(c, &format!("{path}.component"))?,
                format!("{path}.component"),
            ),
            None => match get(f, "package") {
                Some(p) => (
                    object(p, &format!("{path}.package"))?,
                    format!("{path}.package"),
                ),
                None => return Err(shape(format!("{path}.package"), "an object")),
            },
        };
        let name = req_str(target, "name", &tpath)?.to_owned();
        let version = opt_str(target, "version", &tpath)?
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        let purl = match opt_str(target, "purl", &tpath)?.filter(|p| !p.is_empty()) {
            None => None,
            Some(text) => match Purl::new(text) {
                Ok(p) => Some(p),
                Err(e) => {
                    warnings.push(Warning::new(
                        format!("{tpath}.purl"),
                        format!("unusable purl dropped: {e}"),
                    ));
                    None
                }
            },
        };
        out.push(Finding {
            id,
            purl,
            name,
            version,
            aliases,
            cpes: BTreeSet::new(),
            severity: severity_text,
            fixed_in,
            scanner: scanner.unwrap_or(Scanner::Grype),
        });
    }
    if suppressed > 0 {
        warnings.push(Warning::new(
            "$",
            format!(
                "the scan suppressed {suppressed} finding(s) with VEX; the report ignores the \
                 scan's triage and closes findings only with --vex, so pass the same VEX \
                 documents with --vex"
            ),
        ));
    }
    out.sort();
    out.dedup();
    Ok((out, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn doc(findings: Value) -> Value {
        json!({"schema": "rollcall-scan/1", "scanners": [], "findings": findings})
    }

    fn finding() -> Value {
        json!({
            "id": "CVE-1", "aliases": ["GHSA-1"],
            "component": {"bom-ref": "c:1", "name": "mbedtls", "version": "2.28.0",
                          "purl": "pkg:github/mbed-tls/mbedtls@v2.28.0"},
            "package": {"name": "mbedtls"},
            "severity": "high", "fixed_versions": ["2.28.1"],
            "sources": [{"scanner": "osv-scanner", "id": "GHSA-1", "severity": "MODERATE"},
                        {"scanner": "grype", "id": "CVE-1", "severity": "High"}],
            "triage": "unresolved", "vex": []
        })
    }

    #[test]
    fn maps_component_severity_and_sources() {
        let (findings, warnings) = parse_scan_report(&doc(json!([finding()]))).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let [f] = findings.as_slice() else {
            panic!("{findings:?}")
        };
        assert_eq!(f.id, "CVE-1");
        assert_eq!(f.name, "mbedtls");
        assert_eq!(f.version.as_deref(), Some("2.28.0"));
        assert_eq!(
            f.purl.as_ref().map(Purl::as_str),
            Some("pkg:github/mbed-tls/mbedtls@v2.28.0")
        );
        assert_eq!(f.severity.as_deref(), Some("High"));
        assert_eq!(f.scanner, Scanner::Osv);
        assert_eq!(f.fixed_in, BTreeSet::from(["2.28.1".to_owned()]));
    }

    #[test]
    fn unlisted_package_triage_and_failed_scanners_warn() {
        let mut unlisted = finding();
        unlisted["component"] = Value::Null;
        unlisted["package"] = json!({"name": "heapless", "version": "0.5.0", "purl": "nope"});
        unlisted["triage"] = json!("suppressed");
        unlisted["severity"] = json!("unknown");
        unlisted["sources"] = json!([]);
        let mut value = doc(json!([unlisted]));
        value["scanners"] = json!([{"name": "grype", "status": "failed"},
                                   {"name": "osv-scanner", "status": "ok"}]);
        let (findings, warnings) = parse_scan_report(&value).unwrap();
        assert_eq!(findings[0].name, "heapless");
        assert_eq!(findings[0].purl, None);
        assert_eq!(findings[0].severity, None);
        let locations: Vec<&str> = warnings.iter().map(|w| w.location.as_str()).collect();
        assert_eq!(locations, ["scanners[0]", "findings[0].package.purl", "$"]);
    }

    #[test]
    fn malformed_scan_report_is_a_shape_error() {
        let with = |key: &str, v: Value| {
            let mut f = finding();
            f[key] = v;
            doc(json!([f]))
        };
        let cases = [
            (json!({"schema": "rollcall-scan/1"}), "$.findings"),
            (
                json!({"schema": "rollcall-scan/1", "findings": {}}),
                "$.findings",
            ),
            (doc(json!([1])), "findings[0]"),
            (with("id", json!(1)), "findings[0].id"),
            (with("aliases", json!("x")), "findings[0].aliases"),
            (with("severity", json!("severe")), "findings[0].severity"),
            (with("severity", Value::Null), "findings[0].severity"),
            (
                with("sources", json!([{"id": "x"}])),
                "findings[0].sources[0].scanner",
            ),
            (with("component", json!(5)), "findings[0].component"),
            (
                with("component", json!({"bom-ref": "c"})),
                "findings[0].component.name",
            ),
            (
                with("fixed_versions", json!([1])),
                "findings[0].fixed_versions[0]",
            ),
            (
                json!({"schema": "rollcall-scan/1", "scanners": [{"name": "grype"}], "findings": []}),
                "scanners[0].status",
            ),
        ];
        for (value, want) in cases {
            match parse_scan_report(&value) {
                Err(FindingsError::Shape { path, .. }) => assert_eq!(path, want, "{value}"),
                other => panic!("{value}: {other:?}"),
            }
        }
        let mut no_target = finding();
        no_target["component"] = Value::Null;
        no_target["package"] = Value::Null;
        assert!(parse_scan_report(&doc(json!([no_target]))).is_err());
    }

    proptest! {
        #[test]
        fn scan_report_parser_never_panics(tail in r#"[\[\]\{\}",:a-z0-9_ -]{0,80}"#) {
            let text = format!(r#"{{"schema":"rollcall-scan/1","findings":{tail}"#);
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                let _ = parse_scan_report(&value);
            }
            let text = format!(r#"{{"schema":"rollcall-scan/1","findings":[{{"id":"C","severity":"high",{tail}"#);
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                let _ = parse_scan_report(&value);
            }
        }
    }
}
