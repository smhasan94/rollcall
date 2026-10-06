//! SHA-139 (TP3): `scripts/check-catalogue-sync.sh` checks a cbom-infra copy of the algorithm
//! catalogue against rollcall's. cbom-infra is not built yet, so it runs against the
//! hand-written stand-ins in `tests/data/cbom-infra-standin/` (see the README there): one that
//! agrees and one that disagrees on two fields.
//!
//! The script runs the `catalogue-sync` example with `cargo run`, using the `cargo` that runs
//! these tests (`CARGO`). Unix only (a bash script).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    crate_dir().join("../../scripts/check-catalogue-sync.sh")
}

fn standin(name: &str) -> PathBuf {
    crate_dir().join("tests/data/cbom-infra-standin").join(name)
}

fn run(args: &[&Path]) -> Output {
    let mut command = Command::new("bash");
    command.arg(script()).args(args);
    if let Some(cargo) = std::env::var_os("CARGO") {
        command.env("CARGO", cargo);
    }
    command.output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// TP3: the agreeing stand-in passes: exit 0, the shared count, and the cbom-infra-only entry
/// reported without failing.
#[test]
fn sync_check_passes_on_the_agreeing_standin() {
    let out = run(&[&standin("agrees.yaml")]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stdout = stdout(&out);
    for line in [
        "shared: 9 parameter sets",
        "only in theirs: 1 parameter set",
        "  Camellia-CBC/128",
        "disagreements: 0",
        "agree: every shared entry matches",
    ] {
        assert!(
            stdout.lines().any(|l| l == line),
            "missing {line:?}\n{}",
            text(&out)
        );
    }
    // OURS given explicitly, as a relative path from another directory, gives the same result.
    let out = Command::new("bash")
        .current_dir(crate_dir())
        .arg(script())
        .arg("tests/data/cbom-infra-standin/agrees.yaml")
        .arg("db/algorithms.yaml")
        .envs(std::env::var_os("CARGO").map(|c| ("CARGO", c)))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// TP3: the disagreeing stand-in fails with exit 1 and names each entry and field that differs.
#[test]
fn sync_check_fails_on_the_disagreeing_standin_naming_entry_and_field() {
    let out = run(&[&standin("disagrees.yaml")]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let stdout = stdout(&out);
    let disagreements: Vec<&str> = stdout
        .lines()
        .skip_while(|l| !l.starts_with("disagreements: "))
        .collect();
    assert_eq!(
        disagreements,
        vec![
            "disagreements: 2",
            "  AES-GCM/128 nist_quantum_security_level: ours 1, theirs 3",
            "  ML-KEM quantum_risk: ours pq-safe, theirs grover-weakened",
            "disagree: fix the copy, or change rollcall's catalogue first",
        ],
        "{}",
        text(&out)
    );
}

/// TP3: a missing copy exits 66, one that does not load (malformed YAML, or lint findings)
/// exits 65, and a usage error exits 64; each with a message on stderr.
#[test]
fn sync_check_exit_codes_for_missing_and_malformed_copies() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.yaml");
    let out = run(&[&missing]);
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nope.yaml"),
        "{}",
        text(&out)
    );

    let malformed = dir.path().join("malformed.yaml");
    std::fs::write(&malformed, "format: [\n").unwrap();
    let out = run(&[&malformed]);
    assert_eq!(out.status.code(), Some(65), "{}", text(&out));

    // Valid YAML, but out of order: a lint finding.
    let unsorted = dir.path().join("unsorted.yaml");
    let agrees = std::fs::read_to_string(standin("agrees.yaml")).unwrap();
    std::fs::write(
        &unsorted,
        agrees.replacen("name: Camellia-CBC", "name: Zzz-CBC", 1),
    )
    .unwrap();
    let out = run(&[&unsorted]);
    assert_eq!(out.status.code(), Some(65), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("[unsorted]"),
        "{}",
        text(&out)
    );

    // OURS missing is also 66.
    let out = run(&[&standin("agrees.yaml"), &missing]);
    assert_eq!(out.status.code(), Some(66), "{}", text(&out));

    let out = run(&[]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
    let a = standin("agrees.yaml");
    let out = run(&[&a, &a, &a]);
    assert_eq!(out.status.code(), Some(64), "{}", text(&out));
}
