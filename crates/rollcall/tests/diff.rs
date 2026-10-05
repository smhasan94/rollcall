//! End-to-end tests for `rollcall diff`: the head and base builds are the committed Zephyr
//! goldens (`crates/rollcall-core/tests/golden/zephyr/{tls,old-mbedtls}.cdx.json`), scanned by
//! `rollcall scan --scanner grype --json` with a fake `grype` on `PATH` that prints the real
//! capture `crates/rollcall-core/tests/data/findings/zephyr-old-mbedtls.grype.json` (or
//! nothing), and reported by `rollcall report --format json`. Everything is written to
//! temporary directories; nothing under `fixtures/` is touched. Unix only (the fake is a
//! shell script).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn core(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core")
        .join(path)
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// A built side: its SBOM, scan and report on disk.
struct Built {
    sbom: PathBuf,
    scan: PathBuf,
    report: PathBuf,
}

struct Env {
    dir: TempDir,
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

    /// Scans `sbom` with a fake grype printing `grype` (JSON), then reports on it; files are
    /// named after `name`.
    fn build(&self, name: &str, sbom: &Path, grype: &Value) -> Built {
        let capture = self.path(&format!("{name}.grype.json"));
        std::fs::write(&capture, serde_json::to_vec(grype).unwrap()).unwrap();
        let fake = self.path("bin/grype");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Version: 0.119.0'; exit 0; fi\ncat '{}'\n",
                capture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let scan = self.path(&format!("{name}.scan.json"));
        let out = rollcall()
            .arg("scan")
            .arg(sbom)
            .args(["--scanner", "grype", "--json"])
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .output()
            .unwrap();
        assert!(
            matches!(out.status.code(), Some(0 | 1)),
            "scan: {}",
            stderr(&out)
        );
        std::fs::write(&scan, &out.stdout).unwrap();
        let report = self.path(&format!("{name}.report.json"));
        rollcall()
            .arg("report")
            .arg(sbom)
            .arg("--scan")
            .arg(&scan)
            .args(["--format", "json", "--timestamp", GOLDEN_TIMESTAMP, "-o"])
            .arg(&report)
            .assert()
            .code(0);
        Built {
            sbom: sbom.to_path_buf(),
            scan,
            report,
        }
    }

    fn head(&self) -> Built {
        self.build(
            "head",
            &core("tests/golden/zephyr/old-mbedtls.cdx.json"),
            &capture(),
        )
    }

    fn base(&self) -> Built {
        self.build(
            "base",
            &core("tests/golden/zephyr/tls.cdx.json"),
            &json!({"matches": []}),
        )
    }
}

fn capture() -> Value {
    let path = core("tests/data/findings/zephyr-old-mbedtls.grype.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// `rollcall diff` of `head` against `base` with these extra arguments.
fn diff(head: &Built, base: Option<&Built>, extra: &[&str]) -> Output {
    let mut cmd = rollcall();
    cmd.arg("diff")
        .arg("--sbom")
        .arg(&head.sbom)
        .arg("--scan")
        .arg(&head.scan)
        .arg("--report")
        .arg(&head.report);
    if let Some(base) = base {
        cmd.arg("--base-sbom")
            .arg(&base.sbom)
            .arg("--base-scan")
            .arg(&base.scan)
            .arg("--base-report")
            .arg(&base.report);
    }
    cmd.args(extra).output().unwrap()
}

/// AC2 / TP2: an old Mbed TLS on the branch turns the check red (exit 1) and the comment
/// names the new CVEs at or above `high`.
#[test]
fn old_mbedtls_head_fails_high_gate_and_names_new_cves() {
    let env = Env::new();
    let (head, base) = (env.head(), env.base());
    let out = diff(&head, Some(&base), &["--fail-on", "high", "--format", "md"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let md = stdout(&out);
    assert!(
        md.contains("❌ **8 new open findings at or above high**"),
        "{md}"
    );
    for cve in [
        "CVE-2026-34872",
        "CVE-2026-34875",
        "CVE-2026-34877",
        "CVE-2026-25833",
        "CVE-2026-25835",
    ] {
        assert!(
            md.contains(&format!("| {cve} | mbedtls / mbedtls |")),
            "{cve}\n{md}"
        );
    }
    let out = diff(
        &head,
        Some(&base),
        &["--fail-on", "high", "--format", "json"],
    );
    assert_eq!(out.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["gate"]["outcome"], "findings");
    assert_eq!(value["gate"]["new_open_at_or_above"], 8);
    // The same build on both sides: nothing new, green.
    let out = diff(&head, Some(&head), &["--fail-on", "high", "--format", "md"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("✅ **No new open findings at or above high.**"));
}

/// TP3: `--fail-on critical` lets a new `high` finding pass (exit 0) but still lists it.
#[test]
fn fail_on_critical_passes_new_high_but_lists_it() {
    let env = Env::new();
    let base = env.base();
    // Only the high findings of the capture.
    let mut only_high = capture();
    only_high["matches"]
        .as_array_mut()
        .unwrap()
        .retain(|m| m["vulnerability"]["severity"] == "High");
    assert!(!only_high["matches"].as_array().unwrap().is_empty());
    let head = env.build(
        "high",
        &core("tests/golden/zephyr/old-mbedtls.cdx.json"),
        &only_high,
    );
    let out = diff(
        &head,
        Some(&base),
        &["--fail-on", "critical", "--format", "md"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let md = stdout(&out);
    assert!(
        md.contains("✅ **No new open findings at or above critical.**"),
        "{md}"
    );
    for cve in [
        "CVE-2026-25833",
        "CVE-2026-25835",
        "CVE-2026-34874",
        "CVE-2026-34876",
    ] {
        assert!(md.contains(&format!("| high | {cve} |")), "{cve}\n{md}");
    }
    // The same head at --fail-on high fails.
    let out = diff(&head, Some(&base), &["--fail-on", "high", "--format", "md"]);
    assert_eq!(out.status.code(), Some(1));
    // With the full capture (which has criticals), critical fails too.
    let full = env.head();
    let out = diff(
        &full,
        Some(&base),
        &["--fail-on", "critical", "--format", "json"],
    );
    assert_eq!(out.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["gate"]["new_open_at_or_above"], 4);
}

/// TP2: missing inputs exit 66, malformed ones 65, bad flags 64, an unwritable output 74;
/// the message names the input.
#[test]
fn exit_codes_for_missing_and_malformed_inputs() {
    let env = Env::new();
    let head = env.head();
    let missing = env.path("missing.json");
    let garbage = env.path("garbage.json");
    std::fs::write(
        &garbage,
        "{\"schema\": \"rollcall-scan/1\", \"findings\": [tru",
    )
    .unwrap();
    let wrong = env.path("wrong.json");
    std::fs::write(&wrong, r#"{"schema": "rollcall-report/1"}"#).unwrap();

    let run = |args: &[&std::ffi::OsStr]| rollcall().arg("diff").args(args).output().unwrap();
    let os = |s: &str| std::ffi::OsString::from(s);
    let fmt = [os("--format"), os("md")];
    let with = |pairs: &[(&str, &Path)]| {
        let mut v: Vec<std::ffi::OsString> = fmt.to_vec();
        for (flag, path) in pairs {
            v.push(os(flag));
            v.push(path.as_os_str().to_owned());
        }
        v
    };
    let cases: Vec<(Vec<std::ffi::OsString>, i32, &str)> = vec![
        (with(&[("--sbom", &missing)]), 66, "missing.json"),
        (
            with(&[("--sbom", &head.sbom), ("--scan", &missing)]),
            66,
            "missing.json",
        ),
        (
            with(&[("--sbom", &head.sbom), ("--base-sbom", &missing)]),
            66,
            "missing.json",
        ),
        (with(&[("--sbom", &garbage)]), 65, "garbage.json"),
        (
            with(&[("--sbom", &head.sbom), ("--scan", &garbage)]),
            65,
            "garbage.json",
        ),
        (
            with(&[("--sbom", &head.sbom), ("--scan", &wrong)]),
            65,
            "wrong.json",
        ),
        (
            with(&[("--sbom", &head.sbom), ("--report", &head.scan)]),
            65,
            "head.scan.json",
        ),
        (
            with(&[
                ("--sbom", &head.sbom),
                ("--base-sbom", &head.sbom),
                ("--base-scan", &garbage),
            ]),
            65,
            "garbage.json",
        ),
        // --base-scan needs --base-sbom; --format is required; unknown severity.
        (
            with(&[("--sbom", &head.sbom), ("--base-scan", &head.scan)]),
            64,
            "--base-sbom",
        ),
        (
            vec![os("--sbom"), head.sbom.as_os_str().to_owned()],
            64,
            "--format",
        ),
        (
            {
                let mut v = with(&[("--sbom", &head.sbom)]);
                v.extend([os("--fail-on"), os("severe")]);
                v
            },
            64,
            "severe",
        ),
        (
            with(&[
                ("--sbom", &head.sbom),
                ("-o", &env.path("no-such-dir/out.md")),
            ]),
            74,
            "out.md",
        ),
    ];
    for (args, code, needle) in cases {
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let out = run(&refs);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains(needle), "{args:?}: {}", stderr(&out));
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

/// The CLI writes exactly the core goldens (`crates/rollcall-core/tests/golden/diff/`), to
/// stdout and with `-o`.
#[test]
fn output_matches_core_golden() {
    let env = Env::new();
    let (head, base) = (env.head(), env.base());
    let golden = |name: &str| {
        std::fs::read_to_string(core("tests/golden/diff").join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}; run scripts/regen-golden.sh"))
    };
    let cases: [(&str, Option<&Built>, i32); 3] = [
        ("tls-to-old-mbedtls", Some(&base), 1),
        ("old-mbedtls-no-base", None, 1),
        ("identical", Some(&head), 0),
    ];
    for (name, base, code) in cases {
        for format in ["md", "json"] {
            let out = diff(&head, base, &["--fail-on", "high", "--format", format]);
            assert_eq!(out.status.code(), Some(code), "{name}: {}", stderr(&out));
            let expected = golden(&format!("{name}.diff.{format}"));
            assert!(
                stdout(&out) == expected,
                "{name}.{format} differs from the core golden\n--- expected\n{expected}\n--- actual\n{}",
                stdout(&out)
            );
            let file = env.path(&format!("{name}.{format}"));
            let out = diff(
                &head,
                base,
                &[
                    "--fail-on",
                    "high",
                    "--format",
                    format,
                    "-o",
                    file.to_str().unwrap(),
                ],
            );
            assert_eq!(out.status.code(), Some(code));
            assert!(out.stdout.is_empty());
            assert_eq!(std::fs::read_to_string(&file).unwrap(), expected);
        }
    }
}
