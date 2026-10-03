//! Hermetic end-to-end tests for `rollcall scan`: fake `grype` and `osv-scanner` scripts on
//! `PATH` print the captured scanner output in `crates/rollcall-core/tests/data/findings/`
//! (from `scripts/capture-findings.sh`), or fail on purpose. The real pinned scanners are
//! exercised by `tests/scan_scanners.rs` in CI.
//!
//! SBOMs are rendered from the hand-written `crates/rollcall-core/tests/data/*.model.json`
//! into temporary directories; nothing under `fixtures/` is touched. Unix only (the fakes are
//! shell scripts).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const LEVELS: [&str; 5] = ["unknown", "low", "medium", "high", "critical"];

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core")
        .join(path)
}

fn capture(file: &str) -> Value {
    let path = core("tests/data/findings").join(file);
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

/// A temporary directory with fake scanners in `bin/` and an SBOM rendered from a model.
struct Env {
    dir: TempDir,
}

/// What a fake scanner does when it scans.
enum Fake {
    /// Prints this JSON and exits with this code.
    Prints(Value, i32),
    /// Prints this text (not JSON) and exits 0.
    Garbage(&'static str),
    /// Prints to stderr and exits with this code.
    Fails(i32),
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bin")).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn bin(&self) -> PathBuf {
        self.path("bin")
    }

    /// `rollcall generate --model tests/data/<model>.model.json`, written to `<model>.cdx.json`.
    fn sbom(&self, model: &str) -> PathBuf {
        let out = self.path(&format!("{model}.cdx.json"));
        let model_path = core(&format!("tests/data/{model}.model.json"));
        rollcall()
            .args(["generate", "--model"])
            .arg(&model_path)
            .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
            .arg(&out)
            .assert()
            .code(0);
        out
    }

    fn write_json(&self, name: &str, value: &Value) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path
    }

    /// Installs a fake `grype` or `osv-scanner`. It answers the version command, records
    /// its arguments and `GRYPE_*`/`OSV_*` environment in `bin/<name>.args` and
    /// `bin/<name>.env`, then behaves as `fake` says.
    fn fake(&self, name: &str, fake: Fake) {
        let (version_arg, version_text) = match name {
            "grype" => ("version", "Application: grype\nVersion: 0.119.0"),
            _ => (
                "--version",
                "osv-scanner version: 2.6.0\nosv-scalibr version: 0.5.2",
            ),
        };
        let body = match fake {
            Fake::Prints(value, code) => {
                let file = self.write_json(&format!("{name}.output.json"), &value);
                format!("cat '{}'\nexit {code}", file.display())
            }
            Fake::Garbage(text) => format!("printf '%s' '{text}'\nexit 0"),
            Fake::Fails(code) => format!("echo '{name}: simulated failure' >&2\nexit {code}"),
        };
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = '{version_arg}' ]; then\n  printf '%s\\n' '{version_text}'\n  exit 0\nfi\n\
             printf '%s\\n' \"$@\" > \"$0.args\"\nenv | grep -E '^(GRYPE|OSV)_' | sort > \"$0.env\"\n\
             if [ \"$1\" = '-c' ]; then cp \"$2\" \"$0.config\"; fi\n{body}\n"
        );
        let path = self.bin().join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn args_of(&self, name: &str) -> Vec<String> {
        std::fs::read_to_string(self.bin().join(format!("{name}.args")))
            .unwrap_or_else(|e| panic!("{name} was not run: {e}"))
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn env_of(&self, name: &str) -> String {
        std::fs::read_to_string(self.bin().join(format!("{name}.env"))).unwrap()
    }

    /// `rollcall scan` with only the fake scanners (and the shell's tools) on PATH, and no
    /// inherited GRYPE_/OSV_ variables.
    fn scan(&self, sbom: &Path, args: &[&str]) -> Output {
        let mut cmd = rollcall();
        cmd.arg("scan").arg(sbom).args(args);
        for (key, _) in std::env::vars_os() {
            let key = key.to_string_lossy().into_owned();
            if key.starts_with("GRYPE_") || key.starts_with("OSV_") {
                cmd.env_remove(&key);
            }
        }
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.bin().display()));
        cmd.output().unwrap()
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", stdout(output)))
}

/// Both fakes printing the old-mbedTLS captures (grype: 5 critical, 9 high, 9 medium;
/// osv-scanner: nothing).
fn old_mbedtls_env() -> (Env, PathBuf) {
    let env = Env::new();
    let sbom = env.sbom("old-mbedtls");
    env.fake("grype", Fake::Prints(capture("old-mbedtls.grype.json"), 0));
    env.fake(
        "osv-scanner",
        Fake::Prints(capture("old-mbedtls.osv.json"), 0),
    );
    (env, sbom)
}

/// The grype capture with every match's severity replaced by `severity`.
fn grype_all(severity: &str) -> Value {
    let mut value = capture("old-mbedtls.grype.json");
    for m in value["matches"].as_array_mut().unwrap() {
        m["vulnerability"]["severity"] = json!(severity);
    }
    value
}

/// An OpenVEX document marking `status` each captured old-mbedTLS grype finding whose
/// severity is in `severities`.
fn openvex_for(severities: &[&str], status: &str) -> Value {
    let statements: Vec<Value> = capture("old-mbedtls.grype.json")["matches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|m| severities.contains(&m["vulnerability"]["severity"].as_str().unwrap()))
        .map(|m| {
            let mut s = json!({
                "vulnerability": {"name": m["vulnerability"]["id"]},
                "products": [{"@id": m["artifact"]["purl"]}],
                "status": status,
            });
            if status == "not_affected" {
                s["justification"] = json!("vulnerable_code_not_present");
            }
            s
        })
        .collect();
    json!({"@context": "https://openvex.dev/ns/v0.2.0", "statements": statements})
}

fn golden_openvex() -> String {
    core("tests/golden/vex/old-mbedtls.openvex.json")
        .display()
        .to_string()
}

#[test]
fn scan_exit_0_clean() {
    let env = Env::new();
    let sbom = env.sbom("minimal");
    let empty = json!({"descriptor": {"name": "grype", "version": "0.119.0"}, "matches": []});
    env.fake("grype", Fake::Prints(empty, 0));
    env.fake("osv-scanner", Fake::Prints(json!({"results": []}), 0));
    let out = env.scan(&sbom, &["--fail-on", "unknown", "--fail-on-unresolved"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("no findings\n"),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).is_empty(), "{}", stderr(&out));
    // Findings without a gate are also exit 0.
    let (env, sbom) = old_mbedtls_env();
    assert_eq!(code(&env.scan(&sbom, &[])), 0);
}

#[test]
fn scan_exit_1_fail_on_threshold() {
    let (env, sbom) = old_mbedtls_env();
    let out = env.scan(&sbom, &["--fail-on", "critical"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    // Only medium findings: --fail-on high passes, medium fails.
    env.fake("grype", Fake::Prints(grype_all("Medium"), 0));
    assert_eq!(code(&env.scan(&sbom, &["--fail-on", "high"])), 0);
    assert_eq!(code(&env.scan(&sbom, &["--fail-on", "medium"])), 1);
}

#[test]
fn scan_exit_2_fail_on_unresolved() {
    let (env, sbom) = old_mbedtls_env();
    // Without VEX every finding is unresolved.
    assert_eq!(code(&env.scan(&sbom, &["--fail-on-unresolved"])), 2);
    // Every finding suppressed or affected: nothing unresolved.
    let all = ["Critical", "High", "Medium"];
    let docs = [
        env.write_json(
            "crit-high.openvex.json",
            &openvex_for(&all[..2], "not_affected"),
        ),
        env.write_json("medium.openvex.json", &openvex_for(&all[2..], "affected")),
    ];
    let args = [
        "--fail-on-unresolved",
        "--vex",
        docs[0].to_str().unwrap(),
        "--vex",
        docs[1].to_str().unwrap(),
    ];
    let out = env.scan(&sbom, &args);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    // under_investigation is unresolved.
    let triage = env.write_json(
        "triage.openvex.json",
        &openvex_for(&all, "under_investigation"),
    );
    let out = env.scan(
        &sbom,
        &["--fail-on-unresolved", "--vex", triage.to_str().unwrap()],
    );
    assert_eq!(code(&out), 2);
}

#[test]
fn scan_exit_3_scanner_missing() {
    let env = Env::new();
    let sbom = env.sbom("old-mbedtls");
    for scanner in ["grype", "osv"] {
        let out = env.scan(&sbom, &["--scanner", scanner]);
        assert_eq!(code(&out), 3, "{scanner}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("not found on PATH"),
            "{}",
            stderr(&out)
        );
    }
    // auto with neither installed.
    let out = env.scan(&sbom, &["--json"]);
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("no scanner found on PATH"),
        "{}",
        stderr(&out)
    );
    let report = report(&out);
    let statuses: Vec<&str> = report["scanners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["skipped", "skipped"]);
}

#[test]
fn scan_exit_3_scanner_failed() {
    let (env, sbom) = old_mbedtls_env();
    env.fake("osv-scanner", Fake::Fails(127));
    let out = env.scan(&sbom, &["--json"]);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("osv-scanner failed") && stderr(&out).contains("simulated failure"),
        "{}",
        stderr(&out)
    );
    // Partial results are still printed.
    let report = report(&out);
    assert_eq!(report["summary"]["total"], 23);
    assert_eq!(report["scanners"][1]["status"], "failed");
    // grype's only success code is 0.
    env.fake(
        "osv-scanner",
        Fake::Prints(capture("old-mbedtls.osv.json"), 0),
    );
    env.fake("grype", Fake::Fails(1));
    assert_eq!(code(&env.scan(&sbom, &[])), 3);
}

#[test]
fn scan_exit_3_scanner_output_unreadable() {
    let (env, sbom) = old_mbedtls_env();
    env.fake("grype", Fake::Garbage("{\"matches\": [tru"));
    let out = env.scan(&sbom, &["--scanner", "grype"]);
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("cannot read grype's output"),
        "{}",
        stderr(&out)
    );
    // grype printing osv-scanner JSON is not grype output.
    env.fake("grype", Fake::Prints(capture("old-heapless.osv.json"), 0));
    let out = env.scan(&sbom, &["--scanner", "grype"]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("not its own"), "{}", stderr(&out));
}

#[test]
fn scan_exit_precedence_3_over_1_over_2() {
    let (env, sbom) = old_mbedtls_env();
    let all = ["--fail-on", "low", "--fail-on-unresolved"];
    assert_eq!(code(&env.scan(&sbom, &all)), 1, "1 over 2");
    env.fake("osv-scanner", Fake::Fails(2));
    assert_eq!(code(&env.scan(&sbom, &all)), 3, "3 over 1 and 2");
    env.fake(
        "osv-scanner",
        Fake::Prints(capture("old-mbedtls.osv.json"), 0),
    );
    assert_eq!(
        code(&env.scan(&sbom, &["--fail-on", "critical", "--fail-on-unresolved"])),
        1
    );
    env.fake("grype", Fake::Prints(grype_all("Low"), 0));
    assert_eq!(
        code(&env.scan(&sbom, &["--fail-on", "critical", "--fail-on-unresolved"])),
        2,
        "2 when 1 does not apply"
    );
}

/// `--fail-on LEVEL` exit code when the open findings' highest severity is `highest`.
fn expected(highest: Option<&str>, level: &str) -> i32 {
    let rank = |s: &str| LEVELS.iter().position(|l| *l == s).unwrap();
    match highest {
        Some(h) if rank(h) >= rank(level) => 1,
        _ => 0,
    }
}

#[test]
fn fail_on_each_level_without_vex() {
    let (env, sbom) = old_mbedtls_env();
    // Every finding at one severity (grype's words), for each severity.
    let grype_words = ["Unknown", "Negligible", "Medium", "High", "Critical"];
    for (word, highest) in grype_words.iter().zip(LEVELS) {
        env.fake("grype", Fake::Prints(grype_all(word), 0));
        for level in LEVELS {
            let out = env.scan(&sbom, &["--fail-on", level]);
            assert_eq!(
                code(&out),
                expected(Some(highest), level),
                "all findings {word}, --fail-on {level}: {}",
                stderr(&out)
            );
        }
    }
    // The real capture (5 critical, 9 high, 9 medium) fails every level.
    env.fake("grype", Fake::Prints(capture("old-mbedtls.grype.json"), 0));
    for level in LEVELS {
        assert_eq!(code(&env.scan(&sbom, &["--fail-on", level])), 1, "{level}");
    }
}

#[test]
fn fail_on_each_level_with_vex() {
    let (env, sbom) = old_mbedtls_env();
    // (what the VEX suppresses, the highest open severity left)
    let cases: [(&[&str], Option<&str>); 4] = [
        (&[], Some("critical")),
        (&["Critical"], Some("high")),
        (&["Critical", "High"], Some("medium")),
        (&["Critical", "High", "Medium"], None),
    ];
    for (suppressed, highest) in cases {
        let doc = env.write_json("v.openvex.json", &openvex_for(suppressed, "not_affected"));
        for level in LEVELS {
            let out = env.scan(&sbom, &["--fail-on", level, "--vex", doc.to_str().unwrap()]);
            assert_eq!(
                code(&out),
                expected(highest, level),
                "suppressing {suppressed:?}, --fail-on {level}: {}",
                stderr(&out)
            );
        }
    }
    // The committed OpenVEX rendering leaves 3 criticals under investigation: every level
    // fails.
    for level in LEVELS {
        let out = env.scan(&sbom, &["--fail-on", level, "--vex", &golden_openvex()]);
        assert_eq!(code(&out), 1, "{level}");
    }
}

#[test]
fn vex_suppressed_findings_shown_in_table_and_json() {
    let (env, sbom) = old_mbedtls_env();
    let table = env.scan(&sbom, &["--vex", &golden_openvex()]);
    assert_eq!(code(&table), 0, "{}", stderr(&table));
    let text = stdout(&table);
    for id in ["CVE-2022-35409", "CVE-2022-46393", "CVE-2024-23775"] {
        let row = text
            .lines()
            .find(|l| l.contains(id))
            .unwrap_or_else(|| panic!("{id} missing from the table:\n{text}"));
        assert!(
            row.contains("suppressed") && row.contains("not_affected"),
            "{row}"
        );
    }
    assert!(
        text.contains("23 finding(s): 3 suppressed, 1 affected, 19 unresolved"),
        "{text}"
    );

    let json = report(&env.scan(&sbom, &["--vex", &golden_openvex(), "--json"]));
    assert_eq!(json["schema"], "rollcall-scan/1");
    let findings = json["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 23);
    let suppressed: Vec<&Value> = findings
        .iter()
        .filter(|f| f["triage"] == "suppressed")
        .collect();
    assert_eq!(suppressed.len(), 3);
    for f in suppressed {
        assert_eq!(f["vex"][0]["status"], "not_affected", "{f}");
        assert_eq!(f["vex"][0]["document"], "old-mbedtls.openvex.json", "{f}");
    }
    assert_eq!(json["summary"]["suppressed"], 3);
}

#[test]
fn fail_on_ignores_vex_suppressed_findings() {
    let (env, sbom) = old_mbedtls_env();
    assert_eq!(code(&env.scan(&sbom, &["--fail-on", "critical"])), 1);
    let doc = env.write_json(
        "c.openvex.json",
        &openvex_for(&["Critical"], "not_affected"),
    );
    let out = env.scan(
        &sbom,
        &[
            "--fail-on",
            "critical",
            "--vex",
            doc.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let json = report(&out);
    assert_eq!(json["summary"]["suppressed"], 5);
    assert_eq!(json["summary"]["open_by_severity"]["critical"], 0);
    // Suppressed criticals do not count toward --fail-on-unresolved either; the rest do.
    let out = env.scan(
        &sbom,
        &[
            "--fail-on",
            "critical",
            "--fail-on-unresolved",
            "--vex",
            doc.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&out), 2);
}

#[test]
fn db_path_passes_offline_flags_and_env() {
    let (env, sbom) = old_mbedtls_env();
    let db = env.path("scan-db");
    std::fs::create_dir(&db).unwrap();
    let out = env.scan(&sbom, &["--db-path", db.to_str().unwrap(), "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let grype_args = env.args_of("grype");
    assert_eq!(grype_args[0], "-c");
    assert!(grype_args[1].ends_with("grype.yaml"), "{grype_args:?}");
    assert!(grype_args[2].starts_with("sbom:") && grype_args[2].ends_with("sbom.cdx.json"));
    assert_eq!(&grype_args[3..], ["-o", "json"]);
    let grype_env = env.env_of("grype");
    for line in [
        format!("GRYPE_DB_CACHE_DIR={}", db.join("grype").display()),
        "GRYPE_DB_AUTO_UPDATE=false".to_owned(),
        "GRYPE_CHECK_FOR_APP_UPDATE=false".to_owned(),
    ] {
        assert!(
            grype_env.lines().any(|l| l == line),
            "{line} not in:\n{grype_env}"
        );
    }
    // The age check is left on.
    assert!(!grype_env.contains("GRYPE_DB_VALIDATE_AGE"), "{grype_env}");

    let osv_args = env.args_of("osv-scanner");
    assert_eq!(&osv_args[..3], ["scan", "source", "-L"]);
    assert!(osv_args[3].ends_with("sbom.cdx.json"));
    for flag in ["--offline", "--offline-vulnerabilities"] {
        assert!(osv_args.iter().any(|a| a == flag), "{flag}: {osv_args:?}");
    }
    let osv_env = env.env_of("osv-scanner");
    let want = format!(
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY={}",
        db.join("osv-scanner").display()
    );
    assert!(
        osv_env.lines().any(|l| l == want),
        "{want} not in:\n{osv_env}"
    );

    let json = report(&out);
    for scanner in json["scanners"].as_array().unwrap() {
        assert_eq!(scanner["offline"], true, "{scanner}");
        assert_eq!(scanner["status"], "ok", "{scanner}");
    }

    // Without --db-path: online, no offline flags or database overrides.
    let out = env.scan(&sbom, &[]);
    assert_eq!(code(&out), 0);
    assert!(!env.env_of("grype").contains("GRYPE_DB_CACHE_DIR"));
    assert!(
        !env.args_of("osv-scanner")
            .iter()
            .any(|a| a.starts_with("--offline"))
    );
    assert!(env.env_of("osv-scanner").is_empty());

    // A --db-path that does not exist is exit 66, before any scanner runs.
    let out = env.scan(&sbom, &["--db-path", env.path("missing").to_str().unwrap()]);
    assert_eq!(code(&out), 66, "{}", stderr(&out));
}

#[test]
fn malformed_vex_is_exit_65() {
    let (env, sbom) = old_mbedtls_env();
    let bad = [
        ("empty.json", &b""[..]),
        ("truncated.json", b"{\"@context\": \"https://openvex.dev/ns/v0.2.0\", \"statements\": ["),
        ("latin1.json", b"\xff\xfe{}"),
        ("other.json", b"{\"hello\": 1}"),
        (
            "bad-status.json",
            b"{\"@context\": \"https://openvex.dev/ns/v0.2.0\", \"statements\": [{\"vulnerability\": \"CVE-1\", \"status\": \"maybe\"}]}",
        ),
    ];
    for (name, bytes) in bad {
        let path = env.path(name);
        std::fs::write(&path, bytes).unwrap();
        let out = env.scan(&sbom, &["--vex", path.to_str().unwrap()]);
        assert_eq!(code(&out), 65, "{name}: {}", stderr(&out));
        assert!(stderr(&out).contains(name), "{}", stderr(&out));
        assert!(stdout(&out).is_empty());
    }
    let out = env.scan(&sbom, &["--vex", env.path("absent.json").to_str().unwrap()]);
    assert_eq!(code(&out), 66);
}

#[test]
fn malformed_or_missing_sbom_is_exit_65_or_66() {
    let env = Env::new();
    env.fake("grype", Fake::Prints(capture("old-mbedtls.grype.json"), 0));
    for (name, bytes) in [
        ("empty.cdx.json", &b""[..]),
        (
            "truncated.cdx.json",
            b"{\"bomFormat\": \"CycloneDX\", \"comp",
        ),
        ("spdx.json", b"{\"spdxVersion\": \"SPDX-2.3\"}"),
    ] {
        let path = env.path(name);
        std::fs::write(&path, bytes).unwrap();
        let out = env.scan(&path, &[]);
        assert_eq!(code(&out), 65, "{name}: {}", stderr(&out));
    }
    assert_eq!(code(&env.scan(&env.path("absent.cdx.json"), &[])), 66);
}

#[test]
fn auto_with_one_scanner_skips_other() {
    let env = Env::new();
    let sbom = env.sbom("old-heapless");
    env.fake(
        "osv-scanner",
        Fake::Prints(capture("old-heapless.osv.json"), 1),
    );
    let out = env.scan(&sbom, &["--json", "--fail-on", "high"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("grype: not found on PATH; skipped"),
        "{}",
        stderr(&out)
    );
    let json = report(&out);
    assert_eq!(json["scanners"][0]["name"], "grype");
    assert_eq!(json["scanners"][0]["status"], "skipped");
    assert_eq!(json["scanners"][1]["name"], "osv-scanner");
    assert_eq!(json["scanners"][1]["status"], "ok");
    assert_eq!(json["scanners"][1]["version"], "2.6.0");
    assert_eq!(json["findings"][0]["id"], "CVE-2020-36464");
}

#[test]
fn both_scanners_merge_into_one_finding() {
    let env = Env::new();
    let sbom = env.sbom("old-heapless");
    env.fake("grype", Fake::Prints(capture("old-heapless.grype.json"), 0));
    env.fake(
        "osv-scanner",
        Fake::Prints(capture("old-heapless.osv.json"), 1),
    );
    let out = env.scan(&sbom, &[]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let golden = std::fs::read_to_string(core("tests/golden/scan/old-heapless.scan.txt")).unwrap();
    assert_eq!(stdout(&out), golden);
    let json = env.scan(&sbom, &["--json"]);
    let golden = std::fs::read_to_string(core("tests/golden/scan/old-heapless.scan.json")).unwrap();
    assert_eq!(stdout(&json), golden);
}

#[test]
fn osv_no_packages_exit_128_is_no_findings_with_warning() {
    let env = Env::new();
    let sbom = env.sbom("minimal");
    env.fake("osv-scanner", Fake::Fails(128));
    let out = env.scan(&sbom, &["--scanner", "osv", "--fail-on-unresolved"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("exit 128"), "{}", stderr(&out));
}

#[test]
fn unknown_severity_count_on_stderr() {
    let (env, sbom) = old_mbedtls_env();
    env.fake("grype", Fake::Prints(grype_all("Unknown"), 0));
    let out = env.scan(&sbom, &["--fail-on", "low"]);
    assert_eq!(code(&out), 0);
    assert!(
        stderr(&out).contains("23 open finding(s) have unknown severity"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn scan_json_output_deterministic() {
    let (env, sbom) = old_mbedtls_env();
    let args = ["--json", "--vex", &golden_openvex()];
    let a = env.scan(&sbom, &args);
    let b = env.scan(&sbom, &args);
    assert_eq!(code(&a), 0);
    assert_eq!(a.stdout, b.stdout);
    let golden =
        std::fs::read_to_string(core("tests/golden/scan/old-mbedtls.openvex.scan.json")).unwrap();
    assert_eq!(stdout(&a), golden);
    // No host paths.
    assert!(!stdout(&a).contains(env.dir.path().to_str().unwrap()));
}

/// The rows of the `## Exit codes` table in docs/scan.md: (code, meaning).
fn documented_exit_codes() -> Vec<(i32, String)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/scan.md");
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split_once("\n## Exit codes\n")
        .map(|(_, rest)| rest.split("\n## ").next().unwrap_or(rest))
        .expect("docs/scan.md has an ## Exit codes section");
    section
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let code = cells.get(1)?.parse().ok()?;
            Some((code, cells.get(2)?.to_string()))
        })
        .collect()
}

#[test]
fn exit_code_table_in_docs_matches_behaviour() {
    let table = documented_exit_codes();
    let codes: Vec<i32> = table.iter().map(|(c, _)| *c).collect();
    assert_eq!(codes, [0, 1, 2, 3, 64, 65, 66, 70, 74]);
    let meaning = |c: i32| table.iter().find(|(code, _)| *code == c).unwrap().1.clone();
    assert!(meaning(1).contains("--fail-on"));
    assert!(meaning(2).contains("--fail-on-unresolved"));
    assert!(meaning(3).contains("scanner"));

    // Each documented scan code, produced by the behaviour the row describes.
    let (env, sbom) = old_mbedtls_env();
    assert_eq!(code(&env.scan(&sbom, &[])), 0, "{}", meaning(0));
    assert_eq!(
        code(&env.scan(&sbom, &["--fail-on", "high"])),
        1,
        "{}",
        meaning(1)
    );
    assert_eq!(
        code(&env.scan(&sbom, &["--fail-on-unresolved"])),
        2,
        "{}",
        meaning(2)
    );
    assert_eq!(
        code(&env.scan(&sbom, &["--fail-on", "bogus"])),
        64,
        "{}",
        meaning(64)
    );
    let bad = env.path("bad.json");
    std::fs::write(&bad, "{").unwrap();
    assert_eq!(
        code(&env.scan(&sbom, &["--vex", bad.to_str().unwrap()])),
        65
    );
    assert_eq!(code(&env.scan(&env.path("absent.json"), &[])), 66);
    env.fake("grype", Fake::Fails(1));
    assert_eq!(code(&env.scan(&sbom, &[])), 3, "{}", meaning(3));

    // The README's exit-code table lists the scan codes too.
    let readme =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .unwrap();
    for row in ["| 2    |", "| 3    |"] {
        assert!(
            readme
                .lines()
                .any(|l| l.starts_with(row) && l.contains("scan")),
            "README exit-code table lacks a scan row {row:?}"
        );
    }
}

#[test]
fn grype_runs_with_an_empty_config_not_the_callers() {
    let (env, sbom) = old_mbedtls_env();
    // A config in the working directory that would hide every finding and fail grype.
    let cwd = env.path("project");
    std::fs::create_dir(&cwd).unwrap();
    std::fs::write(
        cwd.join(".grype.yaml"),
        "ignore:\n  - vulnerability: CVE-2022-35409\nfail-on-severity: low\n",
    )
    .unwrap();
    let mut cmd = rollcall();
    cmd.current_dir(&cwd)
        .arg("scan")
        .arg(&sbom)
        .env("PATH", format!("{}:/usr/bin:/bin", env.bin().display()));
    let out = cmd.output().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let args = env.args_of("grype");
    assert_eq!(args[0], "-c", "{args:?}");
    let config = std::fs::read_to_string(env.bin().join("grype.config")).unwrap();
    assert_eq!(config, "{}\n");
}

/// A pipe whose read end is already closed, so every write to it fails.
fn closed_pipe() -> std::process::Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

#[test]
fn scan_unwritable_stdout_exit_74() {
    let (env, sbom) = old_mbedtls_env();
    for json in [false, true] {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_rollcall"));
        cmd.arg("scan").arg(&sbom);
        if json {
            cmd.arg("--json");
        }
        let out = cmd
            .env("PATH", format!("{}:/usr/bin:/bin", env.bin().display()))
            .stdout(closed_pipe())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(74),
            "json={json}: {:?} {err}",
            out.status
        );
        assert!(err.contains("stdout"), "{err}");
        assert!(!err.contains("panicked"), "{err}");
    }
}

#[test]
fn no_scanner_message_only_when_none_is_installed() {
    let (env, sbom) = old_mbedtls_env();
    env.fake("grype", Fake::Fails(1));
    env.fake("osv-scanner", Fake::Fails(127));
    let out = env.scan(&sbom, &[]);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("grype failed"), "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("no scanner found"),
        "{}",
        stderr(&out)
    );

    let empty = Env::new();
    let sbom = empty.sbom("old-mbedtls");
    let out = empty.scan(&sbom, &[]);
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("no scanner found on PATH"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn table_escapes_control_characters_from_scanner_output() {
    let (env, sbom) = old_mbedtls_env();
    let mut grype = capture("old-mbedtls.grype.json");
    grype["matches"][0]["vulnerability"]["fix"]["versions"] = json!(["9.9\u{1b}[2J"]);
    env.fake("grype", Fake::Prints(grype, 0));
    let out = env.scan(&sbom, &[]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("9.9\\u{1b}[2J"), "{text}");
}
