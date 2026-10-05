//! End-to-end tests for `rollcall generate --cargo` / `--cargo-metadata` on the real
//! `cargo auditable` build fixtures in `fixtures/cargo-*/`.
//!
//! The expected documents are `crates/rollcall-core/tests/golden/cargo/*.cdx.json`, generated
//! only by `scripts/regen-golden.sh`. `--cargo DIR` is tested on a throwaway path-only package
//! written to a temporary directory, so it runs offline; `fixtures/` is never modified.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const TARGET: &str = "thumbv7em-none-eabihf";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn fixture(variant: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(variant)
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/golden/cargo")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn generate(args: &[&std::ffi::OsStr]) -> Output {
    rollcall()
        .arg("generate")
        .args(args)
        .arg("--timestamp")
        .arg(GOLDEN_TIMESTAMP)
        .output()
        .unwrap()
}

fn fixture_args(variant: &str) -> Vec<std::ffi::OsString> {
    vec![
        "--cargo-metadata".into(),
        fixture(variant).join("cargo-metadata.json").into(),
        "--elf".into(),
        fixture(variant).join("firmware.elf").into(),
    ]
}

fn os(args: &[std::ffi::OsString]) -> Vec<&std::ffi::OsStr> {
    args.iter().map(|a| a.as_os_str()).collect()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn assert_exit(out: &Output, code: i32, needles: &[&str]) -> String {
    let stderr = stderr_of(out);
    assert_eq!(out.status.code(), Some(code), "stderr: {stderr}");
    assert!(out.stdout.is_empty(), "stdout not empty");
    assert!(!stderr.contains("panicked"), "{stderr}");
    for needle in needles {
        assert!(stderr.contains(needle), "{stderr:?} lacks {needle:?}");
    }
    stderr
}

fn library_names(doc: &Value) -> BTreeSet<String> {
    doc["components"][0]["components"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .map(|c| c["name"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn generate_cargo_keelsign_matches_golden_and_validates() {
    let out = generate(&os(&fixture_args("cargo-keelsign")));
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(stderr_of(&out), "", "no warnings for the keelsign build");
    let text = stdout_of(&out);
    assert!(
        text == golden("keelsign.cdx.json"),
        "differs from the golden"
    );

    let dir = tempfile::tempdir().unwrap();
    let sbom = dir.path().join("keelsign.cdx.json");
    fs::write(&sbom, &text).unwrap();
    let validate = rollcall()
        .arg("validate")
        .arg("--schema")
        .arg(&sbom)
        .output()
        .unwrap();
    assert_eq!(
        validate.status.code(),
        Some(0),
        "{}{}",
        stdout_of(&validate),
        stderr_of(&validate)
    );
}

#[test]
fn generate_cargo_deps_and_old_heapless_match_goldens() {
    for (variant, name) in [
        ("cargo-deps", "deps.cdx.json"),
        ("cargo-old-heapless", "old-heapless.cdx.json"),
    ] {
        let out = generate(&os(&fixture_args(variant)));
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        assert!(
            stdout_of(&out) == golden(name),
            "{variant} differs from {name}"
        );
    }
}

#[test]
fn include_unlinked_flag_emits_scope_excluded() {
    let mut args = fixture_args("cargo-deps");
    args.push("--include-unlinked".into());
    let out = generate(&os(&args));
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let text = stdout_of(&out);
    assert!(text == golden("deps.include-unlinked.cdx.json"));
    let doc: Value = serde_json::from_str(&text).unwrap();
    let excluded: Vec<&str> = doc["components"][0]["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["scope"] == "excluded")
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(excluded, ["static_assertions"]);

    // Without the flag the dev-dependency is left out entirely.
    let out = generate(&os(&fixture_args("cargo-deps")));
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    assert!(!library_names(&doc).contains("static_assertions"));
}

#[test]
fn include_unlinked_without_elf_is_usage_error() {
    let metadata = fixture("cargo-deps").join("cargo-metadata.json");
    let out = generate(&[
        "--cargo-metadata".as_ref(),
        metadata.as_os_str(),
        "--include-unlinked".as_ref(),
    ]);
    assert_exit(&out, 64, &["--elf"]);
}

#[test]
fn cargo_flags_conflict_with_other_inputs_and_need_their_input() {
    let metadata = fixture("cargo-deps").join("cargo-metadata.json");
    let elf = fixture("cargo-deps").join("firmware.elf");
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data/minimal.model.json");
    let cases: Vec<Vec<&std::ffi::OsStr>> = vec![
        // --target needs --cargo (captured metadata is already resolved).
        vec![
            "--cargo-metadata".as_ref(),
            metadata.as_os_str(),
            "--target".as_ref(),
            TARGET.as_ref(),
        ],
        // --elf needs a cargo input.
        vec![
            "--model".as_ref(),
            model.as_os_str(),
            "--elf".as_ref(),
            elf.as_os_str(),
        ],
        // Two inputs.
        vec![
            "--cargo-metadata".as_ref(),
            metadata.as_os_str(),
            "--model".as_ref(),
            model.as_os_str(),
        ],
        vec![
            "--cargo".as_ref(),
            ".".as_ref(),
            "--cargo-metadata".as_ref(),
            metadata.as_os_str(),
        ],
        vec![
            "--cargo".as_ref(),
            ".".as_ref(),
            "--zephyr".as_ref(),
            ".".as_ref(),
        ],
    ];
    for args in cases {
        let out = generate(&args);
        assert_exit(&out, 64, &[]);
    }
}

#[test]
fn help_lists_the_cargo_flags() {
    let out = rollcall().args(["generate", "--help"]).output().unwrap();
    let help = stdout_of(&out);
    for flag in [
        "--cargo <DIR>",
        "--cargo-metadata <FILE>",
        "--target <TRIPLE>",
        "--elf <FILE>",
        "--include-unlinked",
    ] {
        assert!(help.contains(flag), "--help lacks {flag}");
    }
}

#[test]
fn missing_inputs_exit_66_and_malformed_ones_65() {
    let dir = tempfile::tempdir().unwrap();
    let metadata = fixture("cargo-deps").join("cargo-metadata.json");
    let missing = dir.path().join("missing.json");
    let out = generate(&["--cargo-metadata".as_ref(), missing.as_os_str()]);
    assert_exit(&out, 66, &["missing.json"]);

    let missing_elf = dir.path().join("missing.elf");
    let out = generate(&[
        "--cargo-metadata".as_ref(),
        metadata.as_os_str(),
        "--elf".as_ref(),
        missing_elf.as_os_str(),
    ]);
    assert_exit(&out, 66, &["missing.elf"]);

    let out = generate(&["--cargo".as_ref(), dir.path().as_os_str()]);
    assert_exit(&out, 66, &["Cargo.toml"]);

    let bad = dir.path().join("bad.json");
    fs::write(&bad, "{\"version\": 1, \"packages\": [").unwrap();
    let out = generate(&["--cargo-metadata".as_ref(), bad.as_os_str()]);
    assert_exit(&out, 65, &["bad.json"]);

    let zephyr_elf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zephyr/baseline/mcuboot/zephyr/zephyr.elf");
    let out = generate(&[
        "--cargo-metadata".as_ref(),
        metadata.as_os_str(),
        "--elf".as_ref(),
        zephyr_elf.as_os_str(),
    ]);
    assert_exit(&out, 65, &["zephyr.elf", "cargo auditable"]);

    let other = fixture("cargo-old-heapless").join("firmware.elf");
    let out = generate(&[
        "--cargo-metadata".as_ref(),
        metadata.as_os_str(),
        "--elf".as_ref(),
        other.as_os_str(),
    ]);
    assert_exit(&out, 65, &["rollcall-cargo-old-heapless@0.1.0"]);
}

#[test]
fn without_elf_warns_and_lists_the_resolved_crates() {
    let metadata = fixture("cargo-deps").join("cargo-metadata.json");
    let out = generate(&["--cargo-metadata".as_ref(), metadata.as_os_str()]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = stderr_of(&out);
    assert!(
        stderr.starts_with("rollcall generate: warning: cargo-metadata.json: no ELF given"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    assert!(library_names(&doc).contains("panic-halt"));
    assert!(!library_names(&doc).contains("static_assertions"));
}

// --- `--cargo DIR`: cargo metadata run live ------------------------------------------------

fn cargo_bin() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// A path-only package (no registry, so cargo runs offline): `live-app` depends on
/// `core-dep` everywhere and on `host-dep` only on `cfg(unix)` hosts, with a Cargo.lock.
fn live_package() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let path = dir.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };
    write(
        "app/Cargo.toml",
        "[package]\nname = \"live-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"MIT\"\n\n\
         [workspace]\n\n[dependencies]\ncore-dep = { path = \"../core-dep\" }\n\n\
         [target.'cfg(unix)'.dependencies]\nhost-dep = { path = \"../host-dep\" }\n",
    );
    write("app/src/main.rs", "fn main() {}\n");
    for lib in ["core-dep", "host-dep"] {
        write(
            &format!("{lib}/Cargo.toml"),
            &format!("[package]\nname = \"{lib}\"\nversion = \"0.2.0\"\nedition = \"2021\"\n"),
        );
        write(&format!("{lib}/src/lib.rs"), "\n");
    }
    let status = std::process::Command::new(cargo_bin())
        .args(["generate-lockfile", "--offline", "--manifest-path"])
        .arg(dir.path().join("app/Cargo.toml"))
        .status()
        .unwrap();
    assert!(status.success());
    dir
}

/// Crate names (root included) `cargo tree --target T -e normal,build` lists for `app`.
fn live_cargo_tree(app: &Path, target: Option<&str>) -> BTreeSet<String> {
    let mut command = std::process::Command::new(cargo_bin());
    command
        .args([
            "tree",
            "--offline",
            "--locked",
            "-e",
            "normal,build",
            "--prefix",
            "none",
        ])
        .args(["--format", "{p}", "--manifest-path"])
        .arg(app.join("Cargo.toml"));
    match target {
        Some(t) => command.args(["--target", t]),
        None => command.args(["--target", "all"]),
    };
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect()
}

#[test]
fn target_flag_matches_live_cargo_tree_target() {
    let dir = live_package();
    let app = dir.path().join("app");
    let out = rollcall()
        .arg("generate")
        .arg("--cargo")
        .arg(&app)
        .args(["--target", TARGET, "--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    let mut ours = library_names(&doc);
    ours.insert(
        doc["metadata"]["component"]["name"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let tree = live_cargo_tree(&app, Some(TARGET));
    assert_eq!(ours, tree);
    assert_eq!(
        ours,
        BTreeSet::from(["core-dep".to_owned(), "live-app".to_owned()])
    );
    // No host path anywhere: the occurrence is Cargo.lock, path purls carry no path.
    let text = stdout_of(&out);
    assert!(!text.contains(&*dir.path().to_string_lossy()));
    assert!(text.contains("\"location\": \"Cargo.lock\""));
    assert!(text.contains("pkg:generic/core-dep@0.2.0"));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("no ELF given"), "{stderr}");
    assert!(!stderr.contains("no --target"), "{stderr}");
}

#[test]
fn without_target_every_platform_is_listed_with_a_warning() {
    let dir = live_package();
    let app = dir.path().join("app");
    let out = rollcall()
        .arg("generate")
        .arg("--cargo")
        .arg(&app)
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    let mut ours = library_names(&doc);
    ours.insert("live-app".to_owned());
    assert_eq!(ours, live_cargo_tree(&app, None));
    assert!(library_names(&doc).contains("host-dep"));
    assert!(stderr_of(&out).contains("no --target"));
}

#[test]
fn cargo_not_found_exits_69_and_cargo_failure_65() {
    let dir = live_package();
    let app = dir.path().join("app");
    let out = rollcall()
        .arg("generate")
        .arg("--cargo")
        .arg(&app)
        .env("CARGO", dir.path().join("no-such-cargo"))
        .output()
        .unwrap();
    assert_exit(&out, 69, &["no-such-cargo"]);

    fs::write(app.join("Cargo.toml"), "[package\nname = ").unwrap();
    let out = rollcall()
        .arg("generate")
        .arg("--cargo")
        .arg(&app)
        .output()
        .unwrap();
    assert_exit(&out, 65, &["cargo metadata failed"]);
}

/// A package whose only dependency resolves through its own `.cargo/config.toml`: it depends
/// on `rollcall-vendored-only`, which is on no registry, and the config replaces crates.io
/// with a vendored directory holding it. Cargo finds the config only when it runs in (or
/// below) the package directory; offline, nothing else can resolve the crate.
fn package_with_local_config() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let write = |rel: &str, text: &str| {
        let path = dir.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    };
    write(
        "app/Cargo.toml",
        "[package]\nname = \"vendored-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [workspace]\n\n[dependencies]\nrollcall-vendored-only = \"0.3.0\"\n",
    );
    write("app/src/main.rs", "fn main() {}\n");
    write(
        "app/.cargo/config.toml",
        "[source.crates-io]\nreplace-with = \"vendored\"\n\n[source.vendored]\ndirectory = \"vendor\"\n",
    );
    write(
        "app/vendor/rollcall-vendored-only/Cargo.toml",
        "[package]\nname = \"rollcall-vendored-only\"\nversion = \"0.3.0\"\nedition = \"2021\"\n\
         license = \"MIT\"\n",
    );
    write("app/vendor/rollcall-vendored-only/src/lib.rs", "\n");
    write(
        "app/vendor/rollcall-vendored-only/.cargo-checksum.json",
        &format!("{{\"files\":{{}},\"package\":\"{}\"}}", "ab".repeat(32)),
    );
    let status = std::process::Command::new(cargo_bin())
        .args(["generate-lockfile"])
        .current_dir(dir.path().join("app"))
        .env("CARGO_NET_OFFLINE", "true")
        .status()
        .unwrap();
    assert!(status.success());
    dir
}

#[test]
fn cargo_metadata_runs_in_the_package_directory_so_its_config_applies() {
    let dir = package_with_local_config();
    // Relative --cargo, run from the parent directory: the package's config must still apply.
    let out = rollcall()
        .current_dir(dir.path())
        .args(["generate", "--cargo", "app", "--target", TARGET])
        .args(["--timestamp", GOLDEN_TIMESTAMP])
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let doc: Value = serde_json::from_str(&stdout_of(&out)).unwrap();
    assert_eq!(
        library_names(&doc),
        BTreeSet::from(["rollcall-vendored-only".to_owned()])
    );
    let dep = &doc["components"][0]["components"][0];
    assert_eq!(dep["version"], "0.3.0");
    assert_eq!(dep["licenses"][0]["expression"], "MIT");

    // Without the package's config (as when cargo runs outside the package), the crate
    // cannot be resolved offline: that is what this test guards.
    let config = dir.path().join("app/.cargo/config.toml");
    fs::rename(&config, dir.path().join("config.toml.off")).unwrap();
    let out = rollcall()
        .current_dir(dir.path())
        .args(["generate", "--cargo", "app", "--target", TARGET])
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .unwrap();
    assert_exit(&out, 65, &["cargo metadata failed"]);
}

#[test]
fn same_crate_from_two_sources_exits_65() {
    let dir = tempfile::tempdir().unwrap();
    let crates = "registry+https://github.com/rust-lang/crates.io-index";
    let git = "git+https://github.com/o/a#0123456789abcdef0123456789abcdef01234567";
    let metadata = dir.path().join("dup.json");
    fs::write(
        &metadata,
        format!(
            r#"{{"version": 1, "packages": [
              {{"id": "r", "name": "app", "version": "0.1.0", "source": null}},
              {{"id": "a1", "name": "a", "version": "1.0.0", "source": "{crates}"}},
              {{"id": "a2", "name": "a", "version": "1.0.0", "source": "{git}"}}
            ], "resolve": {{"root": "r", "nodes": [
              {{"id": "r", "deps": [{{"pkg": "a1"}}, {{"pkg": "a2"}}]}}, {{"id": "a1"}}, {{"id": "a2"}}
            ]}}}}"#
        ),
    )
    .unwrap();
    let out = generate(&["--cargo-metadata".as_ref(), metadata.as_os_str()]);
    assert_exit(
        &out,
        65,
        &["a@1.0.0 comes from two sources", "pkg:cargo/a@1.0.0"],
    );
}
