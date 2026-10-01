//! Scanner findings: just enough of grype and osv-scanner JSON to join a finding to a
//! component and to match rules (id, aliases, package name/version/purl/cpe, severity and
//! fixed versions). Normalising scanner output in full is SHA-117's job.
//!
//! The parsers never panic. A field rollcall needs that has the wrong JSON type is a
//! [`FindingsError::Shape`] naming its path; an unusable purl or cpe is dropped with a
//! [`Warning`]; fields rollcall does not read are ignored.

use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Map, Value};

use crate::model::{Cpe, Purl};
use crate::warning::Warning;

/// Which scanner produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scanner {
    /// Anchore grype (`-o json`).
    Grype,
    /// Google osv-scanner (`--format json`).
    Osv,
}

impl fmt::Display for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Grype => "grype",
            Self::Osv => "osv-scanner",
        })
    }
}

/// One vulnerability reported against one package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Finding {
    /// The vulnerability id, e.g. `CVE-2022-35409` or `RUSTSEC-2020-0145`.
    pub id: String,
    /// The package's purl, if the scanner gave a usable one.
    pub purl: Option<Purl>,
    /// The package's name.
    pub name: String,
    /// The package's version.
    pub version: Option<String>,
    /// Other ids for the same vulnerability (never including `id`).
    pub aliases: BTreeSet<String>,
    /// The package's CPEs.
    pub cpes: BTreeSet<Cpe>,
    /// The scanner's severity, as it wrote it.
    pub severity: Option<String>,
    /// Versions the vulnerability is fixed in.
    pub fixed_in: BTreeSet<String>,
    /// The scanner.
    pub scanner: Scanner,
}

/// The result of parsing one scanner report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    /// The scanner.
    pub scanner: Scanner,
    /// The findings, sorted and de-duplicated.
    pub findings: Vec<Finding>,
    /// Non-fatal problems, located by JSON path.
    pub warnings: Vec<Warning>,
}

/// Why a scanner report could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FindingsError {
    /// Not JSON (including empty, truncated or not UTF-8).
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Neither grype nor osv-scanner output.
    #[error("not grype or osv-scanner JSON: {0}")]
    UnknownFormat(String),
    /// A field rollcall reads is missing or has the wrong type.
    #[error("{path}: expected {expected}")]
    Shape {
        /// The JSON path, e.g. `matches[3].vulnerability.id`.
        path: String,
        /// What was expected there.
        expected: &'static str,
    },
}

/// Parses grype or osv-scanner JSON, telling them apart by shape: grype's top level has
/// `matches` (and `descriptor.name` = `grype`), osv-scanner's has `results`.
pub fn parse_findings(bytes: &[u8]) -> Result<Findings, FindingsError> {
    let value: Value = serde_json::from_slice(bytes)?;
    let Some(root) = value.as_object() else {
        return Err(FindingsError::UnknownFormat(
            "the top level is not a JSON object".to_owned(),
        ));
    };
    let descriptor = root
        .get("descriptor")
        .and_then(|d| d.get("name"))
        .and_then(Value::as_str);
    if descriptor == Some("grype") || root.contains_key("matches") {
        parse_grype(&value)
    } else if root.contains_key("results") {
        parse_osv(&value)
    } else {
        Err(FindingsError::UnknownFormat(
            "no `matches` (grype) or `results` (osv-scanner) at the top level".to_owned(),
        ))
    }
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

/// `key` in `obj`, treating `null` as absent.
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

fn opt_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<&'a Map<String, Value>>, FindingsError> {
    match get(obj, key) {
        None => Ok(None),
        Some(v) => object(v, &format!("{path}.{key}")).map(Some),
    }
}

fn req_object<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Map<String, Value>, FindingsError> {
    opt_object(obj, key, path)?.ok_or_else(|| shape(format!("{path}.{key}"), "an object"))
}

fn strings(obj: &Map<String, Value>, key: &str, path: &str) -> Result<Vec<String>, FindingsError> {
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

fn purl_or_warn(text: Option<&str>, path: String, warnings: &mut Vec<Warning>) -> Option<Purl> {
    let text = text?;
    match Purl::new(text) {
        Ok(purl) => Some(purl),
        Err(e) => {
            warnings.push(Warning::new(path, format!("unusable purl dropped: {e}")));
            None
        }
    }
}

fn finish(scanner: Scanner, mut findings: Vec<Finding>, warnings: Vec<Warning>) -> Findings {
    findings.sort();
    findings.dedup();
    Findings {
        scanner,
        findings,
        warnings,
    }
}

/// Parses grype JSON (`grype -o json`): one finding per `matches[]` entry.
pub fn parse_grype(value: &Value) -> Result<Findings, FindingsError> {
    let root = object(value, "$")?;
    let matches = match get(root, "matches") {
        Some(Value::Array(items)) => items.as_slice(),
        _ => return Err(shape("matches", "an array")),
    };
    let mut findings = Vec::with_capacity(matches.len());
    let mut warnings = Vec::new();
    for (i, entry) in matches.iter().enumerate() {
        let path = format!("matches[{i}]");
        let m = object(entry, &path)?;
        let vpath = format!("{path}.vulnerability");
        let vulnerability = req_object(m, "vulnerability", &path)?;
        let id = req_str(vulnerability, "id", &vpath)?.to_owned();
        let severity = opt_str(vulnerability, "severity", &vpath)?.map(str::to_owned);
        let fixed_in = match opt_object(vulnerability, "fix", &vpath)? {
            Some(fix) => strings(fix, "versions", &format!("{vpath}.fix"))?,
            None => Vec::new(),
        };
        let mut aliases = BTreeSet::new();
        for (j, related) in opt_array(m, "relatedVulnerabilities", &path)?
            .iter()
            .enumerate()
        {
            let rpath = format!("{path}.relatedVulnerabilities[{j}]");
            let alias = req_str(object(related, &rpath)?, "id", &rpath)?;
            if alias != id {
                aliases.insert(alias.to_owned());
            }
        }
        let apath = format!("{path}.artifact");
        let artifact = req_object(m, "artifact", &path)?;
        let name = req_str(artifact, "name", &apath)?.to_owned();
        let version = opt_str(artifact, "version", &apath)?
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        let purl = purl_or_warn(
            opt_str(artifact, "purl", &apath)?.filter(|p| !p.is_empty()),
            format!("{apath}.purl"),
            &mut warnings,
        );
        let mut cpes = BTreeSet::new();
        for (j, text) in strings(artifact, "cpes", &apath)?.into_iter().enumerate() {
            match Cpe::new(&text) {
                Ok(cpe) => {
                    cpes.insert(cpe);
                }
                Err(e) => warnings.push(Warning::new(
                    format!("{apath}.cpes[{j}]"),
                    format!("unusable cpe dropped: {e}"),
                )),
            }
        }
        findings.push(Finding {
            id,
            purl,
            name,
            version,
            aliases,
            cpes,
            severity,
            fixed_in: fixed_in.into_iter().collect(),
            scanner: Scanner::Grype,
        });
    }
    Ok(finish(Scanner::Grype, findings, warnings))
}

/// Parses osv-scanner JSON (`--format json`): one finding per vulnerability per package.
pub fn parse_osv(value: &Value) -> Result<Findings, FindingsError> {
    let root = object(value, "$")?;
    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for (r, result) in opt_array(root, "results", "$")?.iter().enumerate() {
        let rpath = format!("results[{r}]");
        let result = object(result, &rpath)?;
        for (p, package) in opt_array(result, "packages", &rpath)?.iter().enumerate() {
            let ppath = format!("{rpath}.packages[{p}]");
            let package = object(package, &ppath)?;
            let info_path = format!("{ppath}.package");
            let info = req_object(package, "package", &ppath)?;
            let name = req_str(info, "name", &info_path)?.to_owned();
            let ecosystem = opt_str(info, "ecosystem", &info_path)?;
            let version = opt_str(info, "version", &info_path)?
                .filter(|v| !v.is_empty())
                .map(str::to_owned);
            let purl = purl_or_warn(
                opt_str(info, "purl", &info_path)?.filter(|p| !p.is_empty()),
                format!("{info_path}.purl"),
                &mut warnings,
            );
            for (v, vuln) in opt_array(package, "vulnerabilities", &ppath)?
                .iter()
                .enumerate()
            {
                let vpath = format!("{ppath}.vulnerabilities[{v}]");
                let vuln = object(vuln, &vpath)?;
                let id = req_str(vuln, "id", &vpath)?.to_owned();
                let aliases = strings(vuln, "aliases", &vpath)?
                    .into_iter()
                    .filter(|a| *a != id)
                    .collect();
                // Fixed versions come only from the `affected[]` entries for this package
                // (an advisory may list several packages), and never from `GIT` ranges,
                // whose events are commit hashes rather than versions.
                let mut fixed_in = BTreeSet::new();
                for (a, affected) in opt_array(vuln, "affected", &vpath)?.iter().enumerate() {
                    let apath = format!("{vpath}.affected[{a}]");
                    let affected = object(affected, &apath)?;
                    if let Some(pkg) = opt_object(affected, "package", &apath)? {
                        let ppath = format!("{apath}.package");
                        let same_name = opt_str(pkg, "name", &ppath)?.is_none_or(|n| n == name);
                        let same_ecosystem = match (opt_str(pkg, "ecosystem", &ppath)?, ecosystem) {
                            (Some(a), Some(b)) => a == b,
                            _ => true,
                        };
                        if !(same_name && same_ecosystem) {
                            continue;
                        }
                    }
                    for (g, range) in opt_array(affected, "ranges", &apath)?.iter().enumerate() {
                        let gpath = format!("{apath}.ranges[{g}]");
                        let range = object(range, &gpath)?;
                        if opt_str(range, "type", &gpath)? == Some("GIT") {
                            continue;
                        }
                        for (e, event) in opt_array(range, "events", &gpath)?.iter().enumerate() {
                            let epath = format!("{gpath}.events[{e}]");
                            if let Some(fixed) = opt_str(object(event, &epath)?, "fixed", &epath)? {
                                fixed_in.insert(fixed.to_owned());
                            }
                        }
                    }
                }
                // `database_specific` is free-form in the OSV schema; only a string severity
                // is read.
                let severity = get(vuln, "database_specific")
                    .and_then(|d| d.get("severity"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                findings.push(Finding {
                    id,
                    purl: purl.clone(),
                    name: name.clone(),
                    version: version.clone(),
                    aliases,
                    cpes: BTreeSet::new(),
                    severity,
                    fixed_in,
                    scanner: Scanner::Osv,
                });
            }
        }
    }
    Ok(finish(Scanner::Osv, findings, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn grype_doc(matches: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({"descriptor": {"name": "grype"}, "matches": matches})).unwrap()
    }

    fn grype_match() -> Value {
        json!({
            "vulnerability": {"id": "CVE-2022-35409", "severity": "Critical",
                              "fix": {"versions": ["2.28.1"], "state": "fixed"}},
            "relatedVulnerabilities": [{"id": "GHSA-xxxx"}, {"id": "CVE-2022-35409"}],
            "artifact": {"name": "mbedtls", "version": "2.28.0",
                         "purl": "pkg:github/mbed-tls/mbedtls@v2.28.0",
                         "cpes": ["cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*"]}
        })
    }

    #[test]
    fn grype_reads_ids_package_and_fix() {
        let f = parse_findings(&grype_doc(json!([grype_match()]))).unwrap();
        assert_eq!(f.scanner, Scanner::Grype);
        assert!(f.warnings.is_empty());
        let [one] = f.findings.as_slice() else {
            panic!("{f:?}")
        };
        assert_eq!(one.id, "CVE-2022-35409");
        assert_eq!(one.aliases, BTreeSet::from(["GHSA-xxxx".to_owned()]));
        assert_eq!(one.name, "mbedtls");
        assert_eq!(one.version.as_deref(), Some("2.28.0"));
        assert_eq!(
            one.purl.as_ref().map(Purl::as_str),
            Some("pkg:github/mbed-tls/mbedtls@v2.28.0")
        );
        assert_eq!(one.cpes.len(), 1);
        assert_eq!(one.severity.as_deref(), Some("Critical"));
        assert_eq!(one.fixed_in, BTreeSet::from(["2.28.1".to_owned()]));
    }

    #[test]
    fn grype_duplicates_collapse_and_bad_ids_warn() {
        let mut bad = grype_match();
        bad["artifact"]["purl"] = json!("not a purl");
        bad["artifact"]["cpes"] = json!(["cpe:nope"]);
        let f = parse_findings(&grype_doc(json!([grype_match(), grype_match(), bad]))).unwrap();
        assert_eq!(f.findings.len(), 2);
        assert_eq!(f.warnings.len(), 2, "{:?}", f.warnings);
        assert_eq!(f.warnings[0].location, "matches[2].artifact.purl");
        assert_eq!(f.warnings[1].location, "matches[2].artifact.cpes[0]");
    }

    #[test]
    fn grype_wrong_types_are_shape_errors() {
        let cases = [
            (
                json!({"descriptor": {"name": "grype"}, "matches": 5}),
                "matches",
            ),
            (json!({"matches": [5]}), "matches[0]"),
            (
                json!({"matches": [{"artifact": {"name": "x"}}]}),
                "matches[0].vulnerability",
            ),
            (
                json!({"matches": [{"vulnerability": {}, "artifact": {"name": "x"}}]}),
                "matches[0].vulnerability.id",
            ),
            (
                json!({"matches": [{"vulnerability": {"id": 7}, "artifact": {"name": "x"}}]}),
                "matches[0].vulnerability.id",
            ),
            (
                json!({"matches": [{"vulnerability": {"id": "C"}, "artifact": {"name": "x", "cpes": [1]}}]}),
                "matches[0].artifact.cpes[0]",
            ),
            (
                json!({"matches": [{"vulnerability": {"id": "C", "fix": {"versions": "1"}}, "artifact": {"name": "x"}}]}),
                "matches[0].vulnerability.fix.versions",
            ),
        ];
        for (doc, want) in cases {
            match parse_findings(&serde_json::to_vec(&doc).unwrap()) {
                Err(FindingsError::Shape { path, .. }) => assert_eq!(path, want, "{doc}"),
                other => panic!("{doc}: {other:?}"),
            }
        }
    }

    fn osv_doc() -> Value {
        json!({"results": [{"packages": [{
            "package": {"name": "heapless", "version": "0.5.0", "ecosystem": "crates.io"},
            "vulnerabilities": [{
                "id": "RUSTSEC-2020-0145",
                "aliases": ["CVE-2020-36464", "GHSA-qgwf-r2jj-2ccv"],
                "affected": [{"ranges": [{"type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "0.6.1"}]}]}],
                "database_specific": {"severity": "HIGH"}
            }, {
                "id": "GHSA-qgwf-r2jj-2ccv",
                "aliases": ["CVE-2020-36464", "RUSTSEC-2020-0145"],
                "database_specific": {"severity": 7.5}
            }]
        }, {
            "package": {"name": "zephyr", "version": "3.7.0", "ecosystem": "GitHub Actions"}
        }]}]})
    }

    #[test]
    fn osv_reads_vulnerabilities_per_package() {
        let f = parse_findings(&serde_json::to_vec(&osv_doc()).unwrap()).unwrap();
        assert_eq!(f.scanner, Scanner::Osv);
        assert_eq!(f.findings.len(), 2);
        let ghsa = &f.findings[0];
        assert_eq!(ghsa.id, "GHSA-qgwf-r2jj-2ccv");
        assert_eq!(ghsa.severity, None);
        let rustsec = &f.findings[1];
        assert_eq!(rustsec.id, "RUSTSEC-2020-0145");
        assert!(rustsec.aliases.contains("CVE-2020-36464"));
        assert_eq!(rustsec.fixed_in, BTreeSet::from(["0.6.1".to_owned()]));
        assert_eq!(rustsec.severity.as_deref(), Some("HIGH"));
        assert_eq!(rustsec.version.as_deref(), Some("0.5.0"));
        assert_eq!(rustsec.purl, None);
    }

    #[test]
    fn osv_fixed_only_from_this_package_and_not_git() {
        let doc = json!({"results": [{"packages": [{
            "package": {"name": "heapless", "version": "0.5.0", "ecosystem": "crates.io"},
            "vulnerabilities": [{
                "id": "RUSTSEC-1",
                "affected": [
                    {"package": {"name": "heapless", "ecosystem": "crates.io"},
                     "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.6.1"}]},
                        {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123def"}]}
                     ]},
                    {"package": {"name": "other-crate", "ecosystem": "crates.io"},
                     "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}]},
                    {"package": {"name": "heapless", "ecosystem": "npm"},
                     "ranges": [{"type": "SEMVER", "events": [{"fixed": "7.7.7"}]}]}
                ]
            }]
        }]}]});
        let f = parse_findings(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(f.findings[0].fixed_in, BTreeSet::from(["0.6.1".to_owned()]));
    }

    #[test]
    fn osv_wrong_types_are_shape_errors() {
        let cases = [
            (json!({"results": 1}), "$.results"),
            (
                json!({"results": [{"packages": [{}]}]}),
                "results[0].packages[0].package",
            ),
            (
                json!({"results": [{"packages": [{"package": {"name": "x"}, "vulnerabilities": [{"id": 1}]}]}]}),
                "results[0].packages[0].vulnerabilities[0].id",
            ),
            (
                json!({"results": [{"packages": [{"package": {"name": "x"}, "vulnerabilities": [{"id": "A", "aliases": "B"}]}]}]}),
                "results[0].packages[0].vulnerabilities[0].aliases",
            ),
        ];
        for (doc, want) in cases {
            match parse_findings(&serde_json::to_vec(&doc).unwrap()) {
                Err(FindingsError::Shape { path, .. }) => assert_eq!(path, want, "{doc}"),
                other => panic!("{doc}: {other:?}"),
            }
        }
    }

    #[test]
    fn autodetect_rejects_other_json() {
        for doc in [
            &b"[]"[..],
            b"{}",
            b"{\"bomFormat\": \"CycloneDX\"}",
            b"\"grype\"",
        ] {
            assert!(
                matches!(parse_findings(doc), Err(FindingsError::UnknownFormat(_))),
                "{}",
                String::from_utf8_lossy(doc)
            );
        }
    }

    #[test]
    fn autodetect_malformed_input_is_an_error() {
        let full = grype_doc(json!([grype_match()]));
        for bytes in [
            &b""[..],
            b"   ",
            &full[..full.len() / 2],
            b"\xff\xfe{}",
            b"{\"matches\": [}",
        ] {
            assert!(
                matches!(parse_findings(bytes), Err(FindingsError::Json(_))),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_findings(&bytes);
        }

        #[test]
        fn arbitrary_json_never_panics(
            text in r#"\{"(matches|results)": ?(\[|\{|"|1|null)[\[\]\{\}",:a-z0-9 ]{0,60}"#
        ) {
            let _ = parse_findings(text.as_bytes());
        }
    }
}
