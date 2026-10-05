//! End-to-end tests for `rollcall vex --starter-rules` and `rollcall vex lint` (SHA-115), on
//! the real builds under `fixtures/` (only read), the captured grype output
//! `crates/rollcall-core/tests/data/findings/zephyr-old-mbedtls.grype.json` (written by
//! `scripts/capture-findings.sh`) and the hand-written `typo.rules.yml` and
//! `bad-status.rules.yml` in `crates/rollcall-core/tests/data/vex/`. Outputs and the small
//! hand-written trees, configs and rules made here go to temporary directories.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn repo(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn arg(path: &str) -> String {
    repo(path).display().to_string()
}

fn vex_data(file: &str) -> String {
    arg(&format!("crates/rollcall-core/tests/data/vex/{file}"))
}

/// Every image `.config` of every real build, as `--kconfig` arguments.
fn all_fixture_configs() -> Vec<String> {
    let mut configs = Vec::new();
    for variant in [
        "zephyr/baseline",
        "zephyr/bt",
        "zephyr/tls",
        "zephyr-old-mbedtls/old-mbedtls",
        "zephyr-smp/smp-serial",
        "zephyr-smp/smp-bt",
    ] {
        let dir = repo(&format!("fixtures/{variant}"));
        let mut images: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.join("zephyr/.config").is_file() && p.join("build_info.yml").is_file())
            .collect();
        images.sort();
        for image in images {
            configs.push("--kconfig".to_owned());
            configs.push(image.join("zephyr/.config").display().to_string());
        }
    }
    configs
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// A Zephyr tree with a VERSION file and one Kconfig file defining `symbols`.
fn tree(dir: &Path, symbols: &[&str]) -> String {
    std::fs::write(
        dir.join("VERSION"),
        "VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 2\nEXTRAVERSION =\n",
    )
    .unwrap();
    let body: String = symbols
        .iter()
        .map(|s| format!("config {s}\n\tbool \"{s}\"\n"))
        .collect();
    std::fs::write(dir.join("Kconfig"), body).unwrap();
    dir.display().to_string()
}

#[test]
fn vex_lint_warns_unknown_symbol_exit_1() {
    let output = rollcall()
        .args(["vex", "lint", &vex_data("typo.rules.yml")])
        .args([
            "--kconfig",
            &format!(
                "with_mcuboot={}",
                arg("fixtures/zephyr/baseline/with_mcuboot/zephyr/.config")
            ),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = text(&output.stderr);
    let [line] = stderr.lines().collect::<Vec<_>>()[..] else {
        panic!("{stderr}")
    };
    assert!(
        line.ends_with(
            "typo.rules.yml: rule zephyr-bluetooth-off-typo: unknown-kconfig-symbol: unknown \
             Kconfig symbol CONFIG_BTT: not in the given .config files (misspelt, renamed, or \
             hidden by an unmet dependency), so this condition is never true and the rule \
             never applies"
        ),
        "{line}"
    );
    assert_eq!(
        text(&output.stdout),
        "1 rules file(s), 1 rule(s), checked against 1 .config file(s); 1 finding(s)\n"
    );
}

#[test]
fn vex_lint_starter_rules_clean_against_fixture_configs_exit_0() {
    rollcall()
        .args(["vex", "lint", "--starter-rules", "--lint-starter-symbols"])
        .args(all_fixture_configs())
        .assert()
        .code(0)
        .stderr("")
        .stdout("1 rules file(s), 7 rule(s), checked against 12 .config file(s); 0 finding(s)\n");
}

/// The recommended command, linting your own rules with the starter pack loaded against one
/// build's `.config`, does not report the pack's symbols (hidden in a build without Mbed
/// TLS), only yours; asking for them reports the hidden ones.
#[test]
fn vex_lint_starter_symbols_only_on_request_with_kconfig() {
    let dir = tempfile::tempdir().unwrap();
    let mine = dir.path().join("mine.yml");
    std::fs::write(
        &mine,
        "version: 1\nrules:\n  - {id: my-bt, match: {name: zephyr}, when: [{kconfig_off: CONFIG_BT}], status: not_affected, justification: code_not_present}\n",
    )
    .unwrap();
    let config = arg("fixtures/zephyr/baseline/with_mcuboot/zephyr/.config");
    let output = rollcall()
        .args(["vex", "lint", "--starter-rules", "--kconfig", &config])
        .arg(&mine)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        text(&output.stdout),
        "2 rules file(s), 8 rule(s), checked against 1 .config file(s) (the starter pack's 7 \
         rule(s) for duplicate ids only; add --lint-starter-symbols to check their symbols \
         too); 0 finding(s)\n"
    );
    let output = rollcall()
        .args(["vex", "lint", "--starter-rules", "--lint-starter-symbols"])
        .args(["--kconfig", &config])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("CONFIG_MBEDTLS_TLS_VERSION_1_3"),
        "{stderr}"
    );
    assert!(stderr.contains("hidden by an unmet dependency"), "{stderr}");
    // --lint-starter-symbols needs --starter-rules.
    let output = rollcall()
        .args([
            "vex",
            "lint",
            "--lint-starter-symbols",
            "--kconfig",
            &config,
        ])
        .arg(&mine)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");
}

/// A rule id that the starter pack (or an earlier file) already uses is a finding.
#[test]
fn vex_lint_reports_duplicate_ids_across_files() {
    let dir = tempfile::tempdir().unwrap();
    let mine = dir.path().join("mine.yml");
    std::fs::write(
        &mine,
        "version: 1\nrules:\n  - {id: zephyr-bluetooth-off, match: {name: zephyr}, status: affected}\n",
    )
    .unwrap();
    let config = arg("fixtures/zephyr/baseline/with_mcuboot/zephyr/.config");
    let output = rollcall()
        .args(["vex", "lint", "--starter-rules", "--kconfig", &config])
        .arg(&mine)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(
            "rule zephyr-bluetooth-off: duplicate-rule-id: rule id zephyr-bluetooth-off is \
             already defined in vex-rules.yaml (starter rules)"
        ),
        "{stderr}"
    );
}

#[test]
fn vex_lint_zephyr_tree_reference() {
    let dir = tempfile::tempdir().unwrap();
    // The tree defines the misspelt symbol, so with the tree the typo is "known".
    let with_typo = tree(dir.path(), &["BTT"]);
    let output = rollcall()
        .args(["vex", "lint", &vex_data("typo.rules.yml")])
        .args(["--zephyr-tree", &with_typo])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        text(&output.stdout).contains("checked against the Zephyr v4.4.2 tree at"),
        "{output:?}"
    );

    let other = tempfile::tempdir().unwrap();
    let without = tree(other.path(), &["BT"]);
    let output = rollcall()
        .args(["vex", "lint", &vex_data("typo.rules.yml")])
        .args(["--zephyr-tree", &without])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("unknown Kconfig symbol CONFIG_BTT: not defined by the Zephyr v4.4.2 tree"),
        "{stderr}"
    );

    // --kconfig and --zephyr-tree together are a usage error.
    let config = arg("fixtures/zephyr/baseline/with_mcuboot/zephyr/.config");
    let output = rollcall()
        .args([
            "vex",
            "lint",
            &vex_data("typo.rules.yml"),
            "--kconfig",
            &config,
        ])
        .args(["--zephyr-tree", &without])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");
    assert!(
        text(&output.stderr).contains("cannot be used with"),
        "{output:?}"
    );

    // --lint-starter-symbols means nothing with a tree: a usage error.
    let output = rollcall()
        .args(["vex", "lint", "--starter-rules", "--lint-starter-symbols"])
        .args(["--zephyr-tree", &without])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");

    // A tree whose VERSION is not a Zephyr VERSION file is malformed (65).
    std::fs::write(other.path().join("VERSION"), "not a version\n").unwrap();
    let output = rollcall()
        .args(["vex", "lint", &vex_data("typo.rules.yml")])
        .args(["--zephyr-tree", &without])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(65), "{output:?}");
}

#[test]
fn vex_lint_usage_and_input_errors() {
    // No reference.
    let output = rollcall()
        .args(["vex", "lint", &vex_data("typo.rules.yml")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");
    assert!(
        text(&output.stderr).contains("--zephyr-tree DIR"),
        "{output:?}"
    );
    // No rules.
    let config = arg("fixtures/zephyr/baseline/with_mcuboot/zephyr/.config");
    let output = rollcall()
        .args(["vex", "lint", "--kconfig", &config])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{output:?}");
    // A malformed rules file, even without a reference.
    let output = rollcall()
        .args(["vex", "lint", &vex_data("bad-status.rules.yml")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(65), "{output:?}");
    assert!(
        text(&output.stderr).contains("bad-status.rules.yml:7"),
        "{output:?}"
    );
    // A malformed, a non-UTF-8 and a missing .config; a missing tree.
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.config");
    std::fs::write(&bad, "CONFIG_BT=y\nnot a kconfig line\n").unwrap();
    let latin = dir.path().join("latin.config");
    std::fs::write(&latin, b"CONFIG_X=\"\xe9\"\n").unwrap();
    let truncated = dir.path().join("truncated.config");
    std::fs::write(&truncated, "CONFIG_BT=y\nCONFIG_NAME=\"abc").unwrap();
    for (path, code) in [
        (bad.display().to_string(), 65),
        (latin.display().to_string(), 65),
        (truncated.display().to_string(), 65),
        (dir.path().join("missing").display().to_string(), 66),
    ] {
        let output = rollcall()
            .args(["vex", "lint", "--starter-rules", "--kconfig", &path])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{path}: {output:?}");
        assert!(
            text(&output.stderr).starts_with("rollcall vex lint: "),
            "{output:?}"
        );
    }
    let output = rollcall()
        .args(["vex", "lint", "--starter-rules", "--zephyr-tree"])
        .arg(dir.path().join("no-tree"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(66), "{output:?}");
    // A missing rules file.
    let output = rollcall()
        .args(["vex", "lint", "--kconfig", &config])
        .arg(dir.path().join("missing.yml"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(66), "{output:?}");
}

/// `rollcall vex --starter-rules` on the real old-mbedTLS build's generated SBOM and real
/// grype output: CVE-2026-34873 is `not_affected` / `code_not_present` with
/// CONFIG_MBEDTLS_TLS_VERSION_1_3 quoted in the detail, in the CycloneDX VEX document and the
/// rollcall report.
#[test]
fn vex_starter_rules_old_mbedtls_cli_statement() {
    let dir = tempfile::tempdir().unwrap();
    let sbom = dir.path().join("old-mbedtls.cdx.json");
    let variant = "fixtures/zephyr-old-mbedtls/old-mbedtls";
    rollcall()
        .args(["generate", "--zephyr", &arg(variant), "--sysbuild"])
        .args(["--west-list", &arg(&format!("{variant}/west-list.txt"))])
        .args([
            "--identifier-db",
            &arg("crates/rollcall-identifiers/db/identifiers.yaml"),
        ])
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&sbom)
        .assert()
        .code(0);
    let vex = |format: &str| {
        let mut cmd = rollcall();
        cmd.args(["vex", "--sbom"])
            .arg(&sbom)
            .args([
                "--kconfig",
                &format!(
                    "mbedtls={}",
                    arg(&format!("{variant}/mbedtls/zephyr/.config"))
                ),
            ])
            .args([
                "--kconfig",
                &format!(
                    "mcuboot={}",
                    arg(&format!("{variant}/mcuboot/zephyr/.config"))
                ),
            ])
            .args([
                "--findings",
                &arg("crates/rollcall-core/tests/data/findings/zephyr-old-mbedtls.grype.json"),
            ])
            .args(["--starter-rules", "--format", format]);
        if format != "rollcall" {
            cmd.args(["--timestamp", GOLDEN_TIMESTAMP]);
        }
        let output = cmd.output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };

    let cdx = vex("cyclonedx");
    let tls13 = cdx["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "CVE-2026-34873")
        .unwrap_or_else(|| panic!("{cdx:#}"));
    assert_eq!(tls13["analysis"]["state"], "not_affected");
    assert_eq!(tls13["analysis"]["justification"], "code_not_present");
    assert!(
        tls13["analysis"]["detail"]
            .as_str()
            .unwrap()
            .contains("CONFIG_MBEDTLS_TLS_VERSION_1_3"),
        "{tls13:#}"
    );
    assert_eq!(tls13["affects"].as_array().unwrap().len(), 2, "both images");

    let report = vex("rollcall");
    let statements: Vec<&Value> = report["statements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["vulnerability"] == "CVE-2026-34873")
        .collect();
    assert_eq!(statements.len(), 2);
    for s in statements {
        assert_eq!(s["status"], "not_affected");
        assert_eq!(s["justification"], "code_not_present");
        assert_eq!(s["rules"][0], "mbedtls-tls13-compiled-out");
        assert!(
            s["detail"]
                .as_str()
                .unwrap()
                .contains("CONFIG_MBEDTLS_TLS_VERSION_1_3")
        );
    }
}

/// A `--rules` file reusing a starter rule id is refused, naming the id.
#[test]
fn vex_starter_rules_duplicate_id_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("mine.yml");
    std::fs::write(
        &rules,
        "version: 1\nrules:\n  - {id: zephyr-bluetooth-off, match: {name: zephyr}, status: affected}\n",
    )
    .unwrap();
    let output = rollcall()
        .args(["vex", "--model"])
        .arg(arg(
            "crates/rollcall-core/tests/data/old-mbedtls.model.json",
        ))
        .args([
            "--findings",
            &arg("crates/rollcall-core/tests/data/findings/old-mbedtls.grype.json"),
        ])
        .arg("--starter-rules")
        .arg("--rules")
        .arg(&rules)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(65), "{output:?}");
    assert!(
        text(&output.stderr).contains("duplicate rule id `zephyr-bluetooth-off`"),
        "{output:?}"
    );
}
