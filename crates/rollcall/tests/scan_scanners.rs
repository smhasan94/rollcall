//! `rollcall scan` against the real, pinned scanners (grype 0.119.0, osv-scanner 2.6.0).
//! Every test here is `#[ignore]`d: they need the scanners and, except the offline one, the
//! network. CI runs them in the `scan` job (`.github/workflows/ci.yml`):
//!
//! ```sh
//! scripts/smoke-scan.sh --install --only minimal   # installs the pinned scanners
//! ROLLCALL_TOOLS_DIR=$PWD/.cache/tools cargo test -p rollcall --test scan_scanners \
//!     -- --ignored --skip offline
//! # then, with the databases primed in DIR and the network blocked:
//! ROLLCALL_TOOLS_DIR=… ROLLCALL_SCAN_DB_DIR=DIR <test binary> --ignored --exact \
//!     offline_db_path_scan_without_network
//! ```
//!
//! `ROLLCALL_TOOLS_DIR` (optional) is put first on `PATH`. SBOMs are the committed goldens
//! (`crates/rollcall-core/tests/golden/**.cdx.json`) and ones generated into temporary
//! directories from `fixtures/` and `crates/rollcall-core/tests/data/`; nothing under
//! `fixtures/` is modified.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const GRYPE_VERSION: &str = "0.119.0";
const OSV_SCANNER_VERSION: &str = "2.6.0";

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn rollcall() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rollcall"));
    if let Some(tools) = std::env::var_os("ROLLCALL_TOOLS_DIR") {
        let mut path = tools;
        if let Some(rest) = std::env::var_os("PATH") {
            path.push(":");
            path.push(rest);
        }
        cmd.env("PATH", path);
    }
    cmd
}

fn scan(sbom: &Path, args: &[&str]) -> (Output, Value) {
    let output = rollcall()
        .arg("scan")
        .arg(sbom)
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{}: stdout is not JSON ({e}); stderr:\n{}",
            sbom.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, report)
}

fn generate(args: &[&str], out: &Path) {
    let output = rollcall()
        .arg("generate")
        .args(args)
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

/// The real Zephyr v4.2.0 old-mbedTLS build, generated as `scripts/smoke-scan.sh` does.
fn old_mbedtls_build(dir: &Path) -> PathBuf {
    let variant = "fixtures/zephyr-old-mbedtls/old-mbedtls";
    let out = dir.join("old-mbedtls.cdx.json");
    let build = repo(&format!("{variant}/mbedtls"));
    let west_list = repo(&format!("{variant}/west-list.txt"));
    let db = repo("crates/rollcall-identifiers/db/identifiers.yaml");
    generate(
        &[
            "--zephyr",
            build.to_str().unwrap(),
            "--west-list",
            west_list.to_str().unwrap(),
            "--identifier-db",
            db.to_str().unwrap(),
        ],
        &out,
    );
    out
}

fn expected_cves() -> Vec<String> {
    std::fs::read_to_string(repo(
        "crates/rollcall-core/tests/data/old-mbedtls-expected-cves.txt",
    ))
    .unwrap()
    .lines()
    .map(str::trim)
    .filter(|l| !l.is_empty() && !l.starts_with('#'))
    .map(str::to_owned)
    .collect()
}

fn ids(finding: &Value) -> Vec<String> {
    let mut ids = vec![finding["id"].as_str().unwrap().to_ascii_uppercase()];
    ids.extend(
        finding["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().to_ascii_uppercase()),
    );
    ids
}

/// The finding's target: its component's bom-ref, else the package's name and version.
fn target(finding: &Value) -> String {
    match finding["component"]["bom-ref"].as_str() {
        Some(r) => r.to_owned(),
        None => format!(
            "package {}@{}",
            finding["package"]["name"], finding["package"]["version"]
        ),
    }
}

fn assert_scanner(report: &Value, name: &str, version: &str, offline: bool) {
    let run = report["scanners"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {}", report["scanners"]));
    assert_eq!(run["status"], "ok", "{run}");
    assert_eq!(run["version"], version, "{run}");
    assert_eq!(run["offline"], offline, "{run}");
}

/// Every expected CVE is a finding on the mbedtls component.
fn assert_known_cve_set(report: &Value) {
    let findings = report["findings"].as_array().unwrap();
    for cve in expected_cves() {
        let hit = findings
            .iter()
            .find(|f| ids(f).contains(&cve) && f["component"]["name"].as_str() == Some("mbedtls"));
        assert!(hit.is_some(), "{cve} not reported on mbedtls");
    }
}

/// Golden SBOMs, the generated old-mbedTLS build, and old-heapless.
fn every_fixture(dir: &Path) -> Vec<PathBuf> {
    let mut sboms = Vec::new();
    for sub in [
        "crates/rollcall-core/tests/golden",
        "crates/rollcall-core/tests/golden/zephyr",
    ] {
        for entry in std::fs::read_dir(repo(sub)).unwrap() {
            let path = entry.unwrap().path();
            if path.to_string_lossy().ends_with(".cdx.json") {
                sboms.push(path);
            }
        }
    }
    sboms.sort();
    sboms.push(old_mbedtls_build(dir));
    let heapless = dir.join("old-heapless.cdx.json");
    let model = repo("crates/rollcall-core/tests/data/old-heapless.model.json");
    generate(&["--model", model.to_str().unwrap()], &heapless);
    sboms.push(heapless);
    sboms
}

#[test]
#[ignore = "needs the pinned grype and osv-scanner and the network; run in CI job `scan`"]
fn every_fixture_overlap_identical_between_grype_and_osv() {
    let dir = tempfile::tempdir().unwrap();
    let mut heapless_overlap = 0;
    for sbom in every_fixture(dir.path()) {
        let (g_out, grype) = scan(&sbom, &["--scanner", "grype"]);
        let (o_out, osv) = scan(&sbom, &["--scanner", "osv"]);
        for (out, name) in [(&g_out, "grype"), (&o_out, "osv")] {
            assert_eq!(
                out.status.code(),
                Some(0),
                "{} --scanner {name}: {}",
                sbom.display(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        // Pair by shared id or alias only, whatever the target: for every id both report,
        // both must give it the same (canonical id, component) set.
        let by_id = |report: &Value| {
            let mut map: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
            for f in report["findings"].as_array().unwrap() {
                for id in ids(f) {
                    map.entry(id)
                        .or_default()
                        .insert((f["id"].as_str().unwrap().to_owned(), target(f)));
                }
            }
            map
        };
        let (g, o) = (by_id(&grype), by_id(&osv));
        let mut shared = BTreeSet::new();
        for (id, g_set) in &g {
            if let Some(o_set) = o.get(id) {
                assert_eq!(
                    g_set,
                    o_set,
                    "{}: {id}: grype and osv-scanner disagree",
                    sbom.display()
                );
                shared.extend(g_set.iter().cloned());
            }
        }
        let overlap = shared.len();
        let name = sbom.file_name().unwrap().to_string_lossy().into_owned();
        eprintln!(
            "{name}: grype {} finding(s), osv-scanner {}, overlap {overlap}",
            grype["findings"].as_array().unwrap().len(),
            osv["findings"].as_array().unwrap().len()
        );
        if name == "old-heapless.cdx.json" {
            heapless_overlap = overlap;
            assert_eq!(overlap, 1, "{shared:?}");
            assert!(
                grype["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f["id"] == "CVE-2020-36464"),
                "{grype}"
            );
        }
    }
    assert!(
        heapless_overlap > 0,
        "no grype/osv-scanner overlap on old-heapless"
    );
}

#[test]
#[ignore = "needs the pinned grype and osv-scanner and the network; run in CI job `scan`"]
fn old_mbedtls_fixture_reports_known_cve_set() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = old_mbedtls_build(dir.path());
    let (out, report) = scan(&sbom, &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_scanner(&report, "grype", GRYPE_VERSION, false);
    assert_scanner(&report, "osv-scanner", OSV_SCANNER_VERSION, false);
    assert_known_cve_set(&report);
}

/// Whether any TCP connection out is possible: to the scanners' servers (DNS failing counts
/// as unreachable) and to public resolvers by address.
fn network_reachable() -> Option<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = ["1.1.1.1:443", "8.8.8.8:443", "[2606:4700:4700::1111]:443"]
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();
    for host in ["api.osv.dev:443", "grype.anchore.io:443", "github.com:443"] {
        if let Ok(resolved) = host.to_socket_addrs() {
            addrs.extend(resolved);
        }
    }
    addrs
        .into_iter()
        .find(|a| TcpStream::connect_timeout(a, Duration::from_secs(5)).is_ok())
}

#[test]
#[ignore = "needs ROLLCALL_SCAN_DB_DIR primed and the network blocked; run in CI job `scan`"]
fn offline_db_path_scan_without_network() {
    let db = std::env::var("ROLLCALL_SCAN_DB_DIR")
        .expect("set ROLLCALL_SCAN_DB_DIR to the primed --db-path directory");
    if let Some(addr) = network_reachable() {
        panic!("the network is not blocked: connected to {addr}");
    }
    let dir = tempfile::tempdir().unwrap();
    let sbom = old_mbedtls_build(dir.path());

    // Control: online, osv-scanner cannot reach osv.dev.
    let (control, _) = scan(&sbom, &["--scanner", "osv"]);
    assert_eq!(control.status.code(), Some(3), "{control:?}");

    let (out, report) = scan(&sbom, &["--db-path", &db]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_scanner(&report, "grype", GRYPE_VERSION, true);
    assert_scanner(&report, "osv-scanner", OSV_SCANNER_VERSION, true);
    assert_known_cve_set(&report);
}

#[test]
#[ignore = "needs the pinned grype and the network; run in CI job `scan`"]
fn grype_config_in_working_directory_has_no_effect() {
    let dir = tempfile::tempdir().unwrap();
    let heapless = dir.path().join("old-heapless.cdx.json");
    let model = repo("crates/rollcall-core/tests/data/old-heapless.model.json");
    generate(&["--model", model.to_str().unwrap()], &heapless);
    // Would hide the only finding, and make grype itself exit 2.
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    for config in [
        project.join(".grype.yaml"),
        project.join(".grype/config.yaml"),
    ] {
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "ignore:\n  - vulnerability: GHSA-qgwf-r2jj-2ccv\nfail-on-severity: low\n",
        )
        .unwrap();
    }
    let output = rollcall()
        .current_dir(&project)
        .args(["scan", "--scanner", "grype", "--json"])
        .arg(&heapless)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["CVE-2020-36464"]);
}
