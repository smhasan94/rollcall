//! End-to-end tests for the `rollcall` binary skeleton.

use assert_cmd::Command;
use predicates::prelude::*;

/// Every subcommand with its one-line `--help` description.
const SUBCOMMANDS: [(&str, &str); 6] = [
    (
        "generate",
        "Generate a CycloneDX SBOM from firmware build metadata",
    ),
    (
        "validate",
        "Validate an SBOM against the CycloneDX schema and rollcall's rules",
    ),
    (
        "merge",
        "Merge bootloader, application and blob SBOMs into one product hierarchy",
    ),
    ("vex", "Emit VEX statements for an SBOM"),
    ("scan", "Scan an SBOM for known vulnerabilities"),
    (
        "assay",
        "Produce a CycloneDX CBOM (cryptographic inventory) for a build",
    ),
];

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn workspace_version() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let text = std::fs::read_to_string(path).expect("read workspace Cargo.toml");
    let manifest: toml::Table = text.parse().expect("parse workspace Cargo.toml");
    manifest["workspace"]["package"]["version"]
        .as_str()
        .expect("workspace.package.version is a string")
        .to_owned()
}

#[test]
fn help_lists_every_subcommand_with_description() {
    let output = rollcall().arg("--help").output().expect("run rollcall");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 help");
    for (name, about) in SUBCOMMANDS {
        let line = stdout
            .lines()
            .find(|l| l.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no help line for `{name}` in:\n{stdout}"));
        assert!(
            line.contains(about),
            "help line for `{name}` lacks description {about:?}: {line:?}"
        );
    }

    // The "Commands:" section lists exactly our six subcommands plus clap's own `help`.
    let listed: Vec<&str> = stdout
        .lines()
        .skip_while(|l| l.trim_end() != "Commands:")
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let mut expected: Vec<&str> = SUBCOMMANDS.iter().map(|(name, _)| *name).collect();
    expected.push("help");
    assert_eq!(listed, expected, "unexpected subcommand list in:\n{stdout}");
}

#[test]
fn subcommand_help_exits_zero() {
    for (name, _) in SUBCOMMANDS {
        rollcall().args([name, "--help"]).assert().code(0);
    }
}

#[test]
fn version_prints_workspace_version() {
    let v = workspace_version();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
    rollcall()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("rollcall {v}\n"));
}

fn assert_not_implemented(sub: &str) {
    rollcall()
        .arg(sub)
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(format!(
            "rollcall {sub}: not implemented"
        )));
}

#[test]
fn generate_without_model_is_usage_error_exit_64() {
    rollcall()
        .arg("generate")
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--model <FILE>"));
}

#[test]
fn validate_without_schema_flag_is_usage_error_exit_64() {
    rollcall()
        .args(["validate", "sbom.cdx.json"])
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("--schema"));
}

#[test]
fn validate_without_file_is_usage_error_exit_64() {
    rollcall()
        .args(["validate", "--schema"])
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("<FILE>"));
}

#[test]
fn merge_exits_64_not_implemented() {
    assert_not_implemented("merge");
}

#[test]
fn vex_exits_64_not_implemented() {
    assert_not_implemented("vex");
}

#[test]
fn scan_exits_64_not_implemented() {
    assert_not_implemented("scan");
}

#[test]
fn assay_exits_64_not_implemented() {
    assert_not_implemented("assay");
}

#[test]
fn unknown_subcommand_is_usage_error_exit_64() {
    rollcall()
        .arg("bogus")
        .assert()
        .code(64)
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

#[test]
fn no_subcommand_prints_usage_exit_64() {
    rollcall()
        .assert()
        .code(64)
        .stderr(predicate::str::contains("Usage:"));
}

#[test]
fn help_and_version_exit_zero() {
    for flag in ["--help", "--version"] {
        rollcall()
            .arg(flag)
            .assert()
            .code(0)
            .stderr(predicate::str::is_empty());
    }
}
