//! End-to-end tests of the identifier database as a versioned artifact (SHA-104): picking up a
//! newer database without a rollcall release, `rollcall --version`, `rollcall identifiers
//! lint`, and the CONTRIBUTING.md walkthrough.
//!
//! Every run gets an empty `$ROLLCALL_CACHE_DIR` unless a test fills one, and no
//! `$ROLLCALL_IDENTIFIERS`, so the developer's real cache never leaks in.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use rollcall_core::identify::{self, Outcome, Query, Resolver};
use tempfile::TempDir;

const TIMESTAMP: &str = "2026-01-02T03:04:05Z";
const SHIPPED: &str = rollcall_identifiers::IDENTIFIERS_YAML;
/// cmsis_6's purl template in the shipped database; the fixtures' cmsis_6 takes its purl
/// from the database (its SPDX gives none).
const CMSIS_6_PURL: &str =
    "'pkg:generic/cmsis@{version}?vcs_url=git+https://github.com/ARM-software/CMSIS_6'";

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn data(name: &str) -> PathBuf {
    workspace()
        .join("crates/rollcall-core/tests/data/identifiers")
        .join(name)
}

/// A hermetic `rollcall`: empty cache directory `cache`, no `$ROLLCALL_IDENTIFIERS`.
fn rollcall(cache: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rollcall"));
    cmd.env("ROLLCALL_CACHE_DIR", cache)
        .env_remove("ROLLCALL_IDENTIFIERS")
        .env_remove("XDG_CACHE_HOME");
    cmd
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

/// stderr without the seed database's one known warning on the fixtures (tf-psa-crypto's
/// SPDX cpe names `arm`, the database's `trustedfirmware`; see docs/identifiers.md).
fn db_stderr(out: &Output) -> String {
    stderr_of(out)
        .lines()
        .filter(|l| !l.contains("module tf-psa-crypto: ") || !l.contains("differs from spdx/"))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// The shipped database as `version`, with cmsis_6's purl renamed to `cmsis_name`.
fn release(version: &str, cmsis_name: &str) -> String {
    let line = format!("db_version: '{}'", rollcall_identifiers::DB_VERSION);
    assert!(SHIPPED.contains(&line) && SHIPPED.contains(CMSIS_6_PURL));
    SHIPPED
        .replace(&line, &format!("db_version: '{version}'"))
        .replace(
            CMSIS_6_PURL,
            &CMSIS_6_PURL.replace("pkg:generic/cmsis@", &format!("pkg:generic/{cmsis_name}@")),
        )
}

/// The embedded database's version with MINOR raised by `n` (`v(0)` is the embedded
/// version): a later database release, whatever the current one is.
fn v(n: u64) -> String {
    let (major, rest) = rollcall_identifiers::DB_VERSION.split_once('.').unwrap();
    let minor: u64 = rest.split_once('.').unwrap().0.parse().unwrap();
    format!("{major}.{}.0", minor + n)
}

/// Installs `text` as `<cache>/rollcall/identifiers/<dir>/identifiers.yaml`, as an unpacked
/// release tarball (`scripts/package-identifiers.sh`) would be.
fn install(cache: &Path, dir: &str, text: &str) -> PathBuf {
    let dir = cache.join("rollcall/identifiers").join(dir);
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("identifiers.yaml");
    fs::write(&file, text).unwrap();
    file
}

/// `generate --zephyr` of the baseline application build with its west list, plus `extra`.
fn generate(cmd: &mut Command, extra: &[&str]) -> Output {
    let variant = workspace().join("fixtures/zephyr/baseline");
    cmd.arg("generate")
        .arg("--zephyr")
        .arg(variant.join("with_mcuboot"))
        .arg("--west-list")
        .arg(variant.join("west-list.txt"))
        .args(["--timestamp", TIMESTAMP])
        .args(extra)
        .output()
        .unwrap()
}

/// The purl the baseline build's cmsis_6 component gets.
fn cmsis_6_purl(sbom: &str) -> String {
    let doc: serde_json::Value = serde_json::from_str(sbom).unwrap();
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        for c in v["components"].as_array().into_iter().flatten() {
            if c["name"] == "cmsis_6" {
                out.push(c["purl"].as_str().unwrap_or_default().to_owned());
            }
            walk(c, out);
        }
    }
    let mut found = Vec::new();
    walk(&doc, &mut found);
    assert_eq!(found.len(), 1, "{found:?}");
    found.remove(0)
}

// --- Bumping the DB version makes the tool pick it up without a tool release -------------

#[test]
fn newer_db_in_cache_is_active_without_rebuild() {
    let cache = TempDir::new().unwrap();
    // Before: the embedded database.
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis@6.1.0?"),
        "{}",
        cmsis_6_purl(&stdout_of(&out))
    );
    // A database release 1.1.0 is dropped into the cache: the same binary uses it.
    let file = install(cache.path(), &v(1), &release(&v(1), "cmsis-v110"));
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-v110@6.1.0?"),
        "{}",
        cmsis_6_purl(&stdout_of(&out))
    );
    assert_eq!(
        db_stderr(&out),
        format!(
            "rollcall generate: note: identifier database {} from the cache ({})\n",
            v(1),
            file.display()
        )
    );
    // Deterministic: the same inputs give the same bytes.
    let again = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(again.stdout, out.stdout);
    // A later 1.2.0 next to it wins over 1.1.0.
    install(cache.path(), &v(2), &release(&v(2), "cmsis-v120"));
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-v120@"));
    // Without --identify (or --identifier-db/--identifiers) nothing is resolved, as before.
    let out = generate(&mut rollcall(cache.path()), &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(!stdout_of(&out).contains("pkg:generic/"));
    assert_eq!(stderr_of(&out), "");
}

#[test]
fn identifiers_flag_overrides_cache_and_embedded() {
    let cache = TempDir::new().unwrap();
    install(cache.path(), &v(1), &release(&v(1), "cmsis-cache"));
    let flag = cache.path().join("flag.yaml");
    fs::write(&flag, release(&v(2), "cmsis-flag")).unwrap();
    // The global flag, before or after the subcommand; it turns resolution on by itself.
    for args in [
        vec!["--identifiers", flag.to_str().unwrap(), "generate"],
        vec!["generate", "--identifiers", flag.to_str().unwrap()],
    ] {
        let mut cmd = rollcall(cache.path());
        let variant = workspace().join("fixtures/zephyr/baseline");
        let out = cmd
            .args(&args)
            .arg("--zephyr")
            .arg(variant.join("with_mcuboot"))
            .arg("--west-list")
            .arg(variant.join("west-list.txt"))
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr_of(&out));
        assert!(
            cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-flag@"),
            "{args:?}"
        );
        assert_eq!(db_stderr(&out), "", "{args:?}");
    }
    // generate --identifier-db FILE is the same, and wins over --identifiers.
    let other = cache.path().join("other.yaml");
    fs::write(&other, release(&v(3), "cmsis-db")).unwrap();
    let out = generate(
        rollcall(cache.path()).args(["--identifiers", flag.to_str().unwrap()]),
        &["--identifier-db", other.to_str().unwrap()],
    );
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-db@"));
    // A directory holding identifiers.yaml works too.
    let dir = cache.path().join("checkout");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("identifiers.yaml"), release(&v(4), "cmsis-dir")).unwrap();
    let out = generate(
        rollcall(cache.path()).args(["--identifiers", dir.to_str().unwrap()]),
        &[],
    );
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-dir@"));
    // --version names it.
    let out = rollcall(cache.path())
        .args(["--identifiers", flag.to_str().unwrap(), "--version"])
        .output()
        .unwrap();
    assert_eq!(
        stdout_of(&out),
        format!(
            "rollcall {}\nidentifiers {} (flag {})\nidentifiers {} (embedded, minimum 1.0.0)\n",
            env!("CARGO_PKG_VERSION"),
            v(2),
            flag.display(),
            rollcall_identifiers::DB_VERSION
        )
    );
}

#[test]
fn env_var_overrides_cache() {
    let cache = TempDir::new().unwrap();
    install(cache.path(), &v(1), &release(&v(1), "cmsis-cache"));
    let file = cache.path().join("env.yaml");
    fs::write(&file, release(&v(2), "cmsis-env")).unwrap();
    let out = generate(
        rollcall(cache.path()).env("ROLLCALL_IDENTIFIERS", &file),
        &["--identify"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-env@"));
    // The variable alone does not turn resolution on.
    let out = generate(
        rollcall(cache.path()).env("ROLLCALL_IDENTIFIERS", &file),
        &[],
    );
    assert!(!stdout_of(&out).contains("pkg:generic/"));
    // A flag beats it.
    let flag = cache.path().join("flag.yaml");
    fs::write(&flag, release(&v(3), "cmsis-flag")).unwrap();
    let out = generate(
        rollcall(cache.path()).env("ROLLCALL_IDENTIFIERS", &file),
        &["--identifier-db", flag.to_str().unwrap()],
    );
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis-flag@"));
    let out = rollcall(cache.path())
        .env("ROLLCALL_IDENTIFIERS", &file)
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        stdout_of(&out).contains(&format!(
            "identifiers {} (ROLLCALL_IDENTIFIERS {})\n",
            v(2),
            file.display()
        )),
        "{}",
        stdout_of(&out)
    );
}

#[test]
fn older_cache_entry_is_skipped_with_warning() {
    let cache = TempDir::new().unwrap();
    install(cache.path(), "0.9.0", &release("0.9.0", "cmsis-old"));
    install(cache.path(), &v(0), &release(&v(0), "cmsis-same"));
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    // The embedded database is used: neither the too-old entry nor a copy of the embedded
    // version replaces it.
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis@"));
    let root = cache.path().join("rollcall/identifiers");
    assert_eq!(
        db_stderr(&out),
        format!(
            "rollcall generate: warning: identifiers: {}: skipped: db_version 0.9.0 is older than 1.0.0, the minimum this rollcall accepts\n",
            root.join("0.9.0").display()
        )
    );
}

#[test]
fn too_old_explicit_db_is_exit_65() {
    let cache = TempDir::new().unwrap();
    let dir = data("too-old");
    let file = dir.join("identifiers.yaml");
    let expected = format!(
        "rollcall generate: {}: db_version 0.9.0 is older than 1.0.0, the minimum this rollcall accepts\n",
        file.display()
    );
    for extra in [
        vec!["--identifier-db", file.to_str().unwrap()],
        vec!["--identifiers", dir.to_str().unwrap()],
    ] {
        let out = generate(&mut rollcall(cache.path()), &extra);
        assert_eq!(out.status.code(), Some(65), "{extra:?}");
        assert!(out.stdout.is_empty());
        assert_eq!(stderr_of(&out), expected, "{extra:?}");
    }
    let out = generate(
        rollcall(cache.path()).env("ROLLCALL_IDENTIFIERS", &file),
        &["--identify"],
    );
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(stderr_of(&out), expected);
    // --version still prints the tool version, then fails the same way.
    let out = rollcall(cache.path())
        .env("ROLLCALL_IDENTIFIERS", &file)
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(
        stdout_of(&out),
        format!("rollcall {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr_of(&out).contains("older than 1.0.0"));
    // A missing database is "no input".
    let out = generate(
        &mut rollcall(cache.path()),
        &[
            "--identifiers",
            cache.path().join("absent.yaml").to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(66), "{}", stderr_of(&out));
}

#[test]
fn schema_major_2_explicit_db_is_exit_65() {
    let cache = TempDir::new().unwrap();
    let file = data("schema-2").join("identifiers.yaml");
    let out = generate(
        &mut rollcall(cache.path()),
        &["--identifier-db", file.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(
        stderr_of(&out),
        format!(
            "rollcall generate: {}: db_version 2.0.0 is major version 2; this rollcall reads major version 1 (a newer rollcall is needed)\n",
            file.display()
        )
    );
    // In the cache, the same release is skipped, not fatal.
    install(cache.path(), "2.0.0", &fs::read_to_string(&file).unwrap());
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr_of(&out).contains("2.0.0: skipped: db_version 2.0.0 is major version 2"));
}

#[test]
fn identify_flag_needs_zephyr_and_excludes_identifier_db_exit_64() {
    let cache = TempDir::new().unwrap();
    let model = workspace().join("crates/rollcall-core/tests/data/minimal.model.json");
    let out = rollcall(cache.path())
        .arg("generate")
        .arg("--model")
        .arg(&model)
        .arg("--identify")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", stderr_of(&out));
    let shipped = workspace().join("crates/rollcall-identifiers/db/identifiers.yaml");
    let out = generate(
        &mut rollcall(cache.path()),
        &["--identify", "--identifier-db", shipped.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(64), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("cannot be used with"));
    // --workspace accepts --identify as its database.
    let ws = TempDir::new().unwrap();
    let out = generate(
        &mut rollcall(cache.path()),
        &["--identify", "--workspace", ws.path().to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
}

// --- rollcall --version reports both databases --------------------------------------------

#[test]
fn version_reports_embedded_and_active_db() {
    let cache = TempDir::new().unwrap();
    let file = install(cache.path(), &v(1), &release(&v(1), "cmsis"));
    let out = rollcall(cache.path()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stderr_of(&out), "");
    assert_eq!(
        stdout_of(&out),
        format!(
            "rollcall {}\nidentifiers {} (cache {})\nidentifiers {} (embedded, minimum 1.0.0)\n",
            env!("CARGO_PKG_VERSION"),
            v(1),
            file.display(),
            rollcall_identifiers::DB_VERSION
        )
    );
    // -V is the same.
    let short = rollcall(cache.path()).arg("-V").output().unwrap();
    assert_eq!(short.stdout, out.stdout);
}

#[test]
fn version_with_only_embedded_prints_one_db_line() {
    let cache = TempDir::new().unwrap();
    let out = rollcall(cache.path()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        stdout_of(&out),
        format!(
            "rollcall {}\nidentifiers {} (embedded, minimum 1.0.0)\n",
            env!("CARGO_PKG_VERSION"),
            rollcall_identifiers::DB_VERSION
        )
    );
    assert_eq!(stderr_of(&out), "");
}

#[test]
fn version_survives_corrupt_cache_entry() {
    let cache = TempDir::new().unwrap();
    install(cache.path(), &v(1), "schema: 1\nmodules: [\n");
    install(cache.path(), &v(2), &release(&v(3), "cmsis"));
    let out = rollcall(cache.path()).arg("--version").output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout_of(&out).lines().count(), 2, "{}", stdout_of(&out));
    let stderr = stderr_of(&out);
    let root = cache.path().join("rollcall/identifiers");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "{stderr}");
    assert!(lines[0].starts_with(&format!(
        "rollcall: warning: identifiers: {}: skipped: ",
        root.join(v(1)).display()
    )));
    assert!(
        lines[1].ends_with(&format!("declares db_version {}, not {}", v(3), v(2))),
        "{stderr}"
    );
}

// --- rollcall identifiers lint -------------------------------------------------------------

#[test]
fn lint_bad_purl_exits_1_with_message() {
    let cache = TempDir::new().unwrap();
    let dir = data("bad-purl");
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let file = dir.join("identifiers.yaml");
    assert_eq!(
        stderr_of(&out),
        format!(
            "{}:17: purl: modules.beta.purl: template has no {{version}} placeholder\n",
            file.display()
        )
    );
    assert_eq!(
        stdout_of(&out),
        format!("{}: does not load; 1 finding(s)\n", file.display())
    );
}

#[test]
fn lint_duplicate_exits_1_naming_both_lines() {
    let cache = TempDir::new().unwrap();
    let file = data("duplicate-name").join("identifiers.yaml");
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr_of(&out),
        format!(
            "{}:22: duplicate: module alpha is listed twice (lines 6 and 22)\n",
            file.display()
        )
    );
}

#[test]
fn lint_shipped_db_is_clean() {
    let cache = TempDir::new().unwrap();
    // The embedded database, checked against the rollcall-identifiers version.
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(
        stdout_of(&out),
        format!(
            "embedded identifiers.yaml: db_version {}, {} modules; 0 finding(s)\n",
            rollcall_identifiers::DB_VERSION,
            rollcall_core::identify::builtin()
                .unwrap()
                .modules()
                .count()
        )
    );
    // The file in the tree, as CI lints it, with the fixtures.
    let shipped = workspace().join("crates/rollcall-identifiers/db/identifiers.yaml");
    let fixtures = workspace().join("fixtures/zephyr");
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .arg(&shipped)
        .args([
            "--expect-version",
            rollcall_identifiers::DB_VERSION,
            "--fixtures",
        ])
        .arg(&fixtures)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        stdout_of(&out).ends_with(&format!(
            "; {}: 3 build(s), 36 module component(s); 0 finding(s)\n",
            fixtures.display()
        )),
        "{}",
        stdout_of(&out)
    );
    // The wrong expected version is a finding.
    let out = rollcall(cache.path())
        .args(["identifiers", "lint", "--expect-version", "9.9.9"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr_of(&out).contains("version-mismatch: db_version"));
    // Unreadable and non-UTF-8 databases.
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .arg(cache.path().join("absent.yaml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(66));
    let bad = cache.path().join("bad.yaml");
    fs::write(&bad, b"schema: 1\n\xff").unwrap();
    let out = rollcall(cache.path())
        .args(["identifiers", "lint"])
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert!(stderr_of(&out).contains("not valid UTF-8"));
    // A bad --expect-version is a usage error.
    let out = rollcall(cache.path())
        .args(["identifiers", "lint", "--expect-version", "1.0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
}

// --- The CONTRIBUTING.md walkthrough ------------------------------------------------------

/// The module CONTRIBUTING.md's example adds.
const EXAMPLE_MODULE: &str = "trusted-firmware-a";

/// The YAML between `<!-- example:start -->` and `<!-- example:end -->` in CONTRIBUTING.md,
/// without its code fence.
fn contributing_example() -> String {
    let guide = fs::read_to_string(workspace().join("CONTRIBUTING.md")).unwrap();
    let (_, rest) = guide
        .split_once("<!-- example:start -->\n")
        .expect("CONTRIBUTING.md has an example:start marker");
    let (block, _) = rest
        .split_once("<!-- example:end -->")
        .expect("CONTRIBUTING.md has an example:end marker");
    let body = block
        .strip_prefix("```yaml\n")
        .and_then(|b| b.strip_suffix("```\n"))
        .expect("the example is one ```yaml block");
    body.to_owned()
}

/// `text` with `entry` inserted under `modules:` in name order (as step 4 says).
fn insert_sorted(text: &str, name: &str, entry: &str) -> String {
    let mut out = String::new();
    let mut inserted = false;
    let mut in_modules = false;
    for line in text.split_inclusive('\n') {
        if line.starts_with("modules:") {
            in_modules = true;
        } else if in_modules && !inserted {
            let key = line
                .strip_prefix("  ")
                .filter(|l| !l.starts_with(' ') && !l.starts_with('#'))
                .and_then(|l| l.trim_end().strip_suffix(':'));
            if key.is_some_and(|key| key > name) {
                out.push_str(entry);
                inserted = true;
            }
        }
        out.push_str(line);
    }
    if !inserted {
        out.push_str(entry);
    }
    out
}

#[test]
fn contributing_example_is_between_markers() {
    let example = contributing_example();
    let first = example.lines().next().unwrap();
    assert_eq!(first, format!("  {EXAMPLE_MODULE}:"));
    // One module, in the database's indentation, with the generated-row markers.
    let keys: Vec<&str> = example
        .lines()
        .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
        .collect();
    assert_eq!(keys, [first]);
    assert!(example.contains("# BEGIN generated by scripts/regen-version-tables.sh; do not edit"));
    assert!(example.contains("# END generated"));
    // The walkthrough adds a module the shipped database does not have yet; if it is ever
    // added for real, pick another module for the guide's example.
    let shipped = identify::builtin().unwrap();
    assert!(
        shipped.get(EXAMPLE_MODULE).is_none(),
        "{EXAMPLE_MODULE} is now shipped; walk CONTRIBUTING.md with another module"
    );
}

#[test]
fn contributing_walkthrough_adds_trusted_firmware_a_and_resolves() {
    let example = contributing_example();
    let dir = TempDir::new().unwrap();
    let cache = dir.path().join("cache");
    // Steps 4 and 8: the entry in name order, and a MINOR bump of db_version.
    let bumped = v(1);
    let text = insert_sorted(SHIPPED, EXAMPLE_MODULE, &example).replace(
        &format!("db_version: '{}'", rollcall_identifiers::DB_VERSION),
        &format!("db_version: '{bumped}'"),
    );
    let db_dir = dir.path().join("db");
    fs::create_dir(&db_dir).unwrap();
    fs::write(db_dir.join("identifiers.yaml"), &text).unwrap();

    // Step 9: the lint, as scripts/lint-identifiers.sh runs it, is clean.
    let out = rollcall(&cache)
        .args(["identifiers", "lint"])
        .arg(&db_dir)
        .args(["--expect-version", &bumped, "--fixtures"])
        .arg(workspace().join("fixtures/zephyr"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let modules = identify::builtin().unwrap().modules().count() + 1;
    assert!(
        stdout_of(&out).contains(&format!("db_version {bumped}, {modules} modules;"))
            && stdout_of(&out).ends_with("; 0 finding(s)\n"),
        "{}",
        stdout_of(&out)
    );

    // Every row resolves: each revision is one Zephyr really pins for the module, and gives
    // the upstream purl and CPE.
    let (db, _) = identify::source::load_path(&db_dir).unwrap();
    let pins = fs::read_to_string(
        workspace().join("crates/rollcall-core/tests/data/zephyr-manifest-pins.txt"),
    )
    .unwrap();
    let pinned: Vec<&str> = pins
        .lines()
        .filter_map(|l| l.strip_prefix(&format!("{EXAMPLE_MODULE} ")))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    let identify::VersionRule::Manual { table } = &db.get(EXAMPLE_MODULE).unwrap().version_rule
    else {
        panic!("the example uses a manual table");
    };
    let rows: Vec<&str> = table.iter().map(|(rev, _)| rev.as_str()).collect();
    assert_eq!(rows, pinned, "one row per pinned commit");
    let mut resolver = Resolver::new(&db);
    for (revision, version) in table.iter() {
        let query = Query {
            module: EXAMPLE_MODULE,
            revision: Some(revision),
            path: None,
        };
        let Outcome::Identified(id) = resolver.resolve(&query, None) else {
            panic!("{EXAMPLE_MODULE} is in the database");
        };
        assert_eq!(id.version.as_deref(), Some(version.as_str()));
        assert_eq!(
            id.purl.unwrap().as_str(),
            format!(
                "pkg:generic/trusted-firmware-a@{version}?vcs_url=git%2Bhttps:%2F%2Fgit.trustedfirmware.org%2FTF-A%2Ftrusted-firmware-a.git"
            )
        );
        assert_eq!(
            id.cpe.unwrap().as_str(),
            format!("cpe:2.3:o:trustedfirmware:trusted_firmware-a:{version}:*:*:*:*:*:*:*")
        );
    }

    // And the bumped database is picked up without a rollcall release.
    let out = rollcall(&cache)
        .args(["--identifiers"])
        .arg(&db_dir)
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        stdout_of(&out).contains(&format!("identifiers {bumped} (flag ")),
        "{}",
        stdout_of(&out)
    );
}

// --- Provenance in the SBOM, pinning, cache trust -----------------------------------------

/// `metadata.properties` of a CycloneDX text, as `(name, value)` pairs.
fn metadata_properties(sbom: &str) -> Vec<(String, String)> {
    let doc: serde_json::Value = serde_json::from_str(sbom).unwrap();
    doc["metadata"]["properties"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_owned(),
                p["value"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn provenance(version: &str, source: &str) -> Vec<(String, String)> {
    vec![
        (
            "rollcall:identifiers:db-version".to_owned(),
            version.to_owned(),
        ),
        ("rollcall:identifiers:source".to_owned(), source.to_owned()),
    ]
}

#[test]
fn sbom_records_which_identifier_db_resolved_it() {
    let cache = TempDir::new().unwrap();
    let embedded = rollcall_identifiers::DB_VERSION;
    // No resolution: no properties (the output is unchanged).
    let out = generate(&mut rollcall(cache.path()), &[]);
    assert_eq!(metadata_properties(&stdout_of(&out)), []);
    // Embedded, explicitly pinned embedded, a flag, an unversioned file, the environment.
    let flag = cache.path().join("flag.yaml");
    fs::write(&flag, release(&v(2), "cmsis")).unwrap();
    let own = cache.path().join("own.yaml");
    fs::write(
        &own,
        release(&v(2), "cmsis").replace(&format!("db_version: '{}'\n", v(2)), ""),
    )
    .unwrap();
    for (extra, env_db, want) in [
        (vec!["--identify"], None, provenance(embedded, "embedded")),
        (
            vec!["--identifiers", "embedded"],
            None,
            provenance(embedded, "embedded"),
        ),
        (
            vec!["--identifier-db", flag.to_str().unwrap()],
            None,
            provenance(&v(2), "flag"),
        ),
        (
            vec!["--identifiers", own.to_str().unwrap()],
            None,
            provenance("unversioned", "flag"),
        ),
        (vec!["--identify"], Some(&flag), provenance(&v(2), "env")),
    ] {
        let mut cmd = rollcall(cache.path());
        if let Some(file) = env_db {
            cmd.env("ROLLCALL_IDENTIFIERS", file);
        }
        let out = generate(&mut cmd, &extra);
        assert_eq!(out.status.code(), Some(0), "{extra:?}: {}", stderr_of(&out));
        let text = stdout_of(&out);
        assert_eq!(metadata_properties(&text), want, "{extra:?}");
        // No path of the database is recorded.
        assert!(
            !text.contains(&*cache.path().to_string_lossy()),
            "{extra:?}"
        );
    }
    // From the cache: the same bytes wherever the cache directory is.
    let mut texts = Vec::new();
    for _ in 0..2 {
        let other = TempDir::new().unwrap();
        install(other.path(), &v(1), &release(&v(1), "cmsis"));
        let out = generate(&mut rollcall(other.path()), &["--identify"]);
        let text = stdout_of(&out);
        assert_eq!(metadata_properties(&text), provenance(&v(1), "cache"));
        texts.push(text);
    }
    assert_eq!(texts[0], texts[1]);
}

#[test]
fn merge_keeps_identifier_db_provenance() {
    let cache = TempDir::new().unwrap();
    let variant = workspace().join("fixtures/zephyr/baseline");
    let app = cache.path().join("app.cdx.json");
    let boot = cache.path().join("mcuboot.cdx.json");
    let flag = cache.path().join("flag.yaml");
    fs::write(&flag, release(&v(2), "cmsis")).unwrap();
    for (image, out, extra) in [
        ("with_mcuboot", &app, vec!["--identify"]),
        (
            "mcuboot",
            &boot,
            vec!["--identifier-db", flag.to_str().unwrap()],
        ),
    ] {
        rollcall(cache.path())
            .arg("generate")
            .arg("--zephyr")
            .arg(variant.join(image))
            .arg("--west-list")
            .arg(variant.join("west-list.txt"))
            .args(["--timestamp", TIMESTAMP])
            .args(&extra)
            .arg("-o")
            .arg(out)
            .assert()
            .code(0);
    }
    // One input: carried over as is.
    let out = rollcall(cache.path())
        .arg("merge")
        .arg(&app)
        .args(["--timestamp", TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert_eq!(
        metadata_properties(&stdout_of(&out)),
        provenance(rollcall_identifiers::DB_VERSION, "embedded")
    );
    // Inputs resolved differently: every distinct value is kept, sorted.
    let out = rollcall(cache.path())
        .arg("merge")
        .arg(&app)
        .arg(&boot)
        .args(["--product", "widget", "--timestamp", TIMESTAMP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let mut want = provenance(rollcall_identifiers::DB_VERSION, "embedded");
    want.extend(provenance(&v(2), "flag"));
    want.sort();
    assert_eq!(metadata_properties(&stdout_of(&out)), want);
}

#[test]
fn embedded_keyword_pins_the_embedded_db() {
    let cache = TempDir::new().unwrap();
    install(cache.path(), &v(1), &release(&v(1), "cmsis-cache"));
    // The flag and the variable both ignore the newer cached database.
    for cmd in [
        rollcall(cache.path()).args(["--identifiers", "embedded"]),
        rollcall(cache.path()).env("ROLLCALL_IDENTIFIERS", "embedded"),
    ] {
        let out = cmd.arg("--version").output().unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            stdout_of(&out),
            format!(
                "rollcall {}\nidentifiers {} (embedded, minimum 1.0.0)\n",
                env!("CARGO_PKG_VERSION"),
                rollcall_identifiers::DB_VERSION
            )
        );
        assert_eq!(stderr_of(&out), "");
    }
    let out = generate(
        rollcall(cache.path()).args(["--identifiers", "embedded"]),
        &[],
    );
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis@"));
    assert!(!db_stderr(&out).contains("note:"), "{}", stderr_of(&out));
}

#[cfg(unix)]
#[test]
fn world_writable_cache_entry_is_skipped_with_warning() {
    use std::os::unix::fs::PermissionsExt;
    let cache = TempDir::new().unwrap();
    let file = install(cache.path(), &v(1), &release(&v(1), "cmsis-writable"));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).unwrap();
    // Noise next to it is ignored silently.
    let root = cache.path().join("rollcall/identifiers");
    fs::write(root.join(".DS_Store"), "x").unwrap();
    fs::write(root.join("README"), "x").unwrap();
    let out = generate(&mut rollcall(cache.path()), &["--identify"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(cmsis_6_purl(&stdout_of(&out)).starts_with("pkg:generic/cmsis@"));
    assert_eq!(
        db_stderr(&out),
        format!(
            "rollcall generate: warning: identifiers: {}: skipped: {} is writable by group or others (mode 666)\n",
            root.join(v(1)).display(),
            file.display()
        )
    );
    let out = rollcall(cache.path()).arg("--version").output().unwrap();
    assert_eq!(stdout_of(&out).lines().count(), 2);
    assert!(stderr_of(&out).contains("is writable by group or others"));
}

#[test]
fn unknown_module_with_embedded_db_points_to_identifiers_flag() {
    let cache = TempDir::new().unwrap();
    // The old-mbedtls build has modules the seed does not know by name (issue #12).
    let variant = workspace().join("fixtures/zephyr-old-mbedtls/old-mbedtls");
    let out = rollcall(cache.path())
        .arg("generate")
        .arg("--zephyr")
        .arg(&variant)
        .args(["--sysbuild", "--identify"])
        .arg("--west-list")
        .arg(variant.join("west-list.txt"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let stderr = stderr_of(&out);
    assert!(
        stderr.ends_with(
            "rollcall generate: the embedded database is read-only: add the entries to a copy of \
             it and pass that with --identifiers PATH, or contribute them (CONTRIBUTING.md)\n"
        ),
        "{stderr}"
    );
    // With a file, the hint is not needed.
    let file = cache.path().join("db.yaml");
    fs::write(&file, SHIPPED).unwrap();
    let out = rollcall(cache.path())
        .arg("generate")
        .arg("--zephyr")
        .arg(&variant)
        .args(["--sysbuild", "--identifier-db"])
        .arg(&file)
        .arg("--west-list")
        .arg(variant.join("west-list.txt"))
        .output()
        .unwrap();
    assert!(!stderr_of(&out).contains("read-only"));
}
