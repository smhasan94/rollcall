//! Finding and running the scanners: grype and osv-scanner, as installed on PATH.
//!
//! - grype: `grype -c <empty config> sbom:<copy> -o json`, with
//!   `GRYPE_CHECK_FOR_APP_UPDATE=false`. The empty configuration file (next to the copy)
//!   keeps grype from reading `.grype.yaml`, `.grype/config.yaml` or `~/.grype.yaml`, whose
//!   `ignore:` rules would hide findings and whose `fail-on-severity` would make it exit 1;
//!   `GRYPE_*` environment variables still apply. With a
//!   database directory also `GRYPE_DB_CACHE_DIR=<db>/grype` and
//!   `GRYPE_DB_AUTO_UPDATE=false`. grype's database age check stays on (a stale database
//!   fails, exit 1); the caller's `GRYPE_DB_VALIDATE_AGE` or `GRYPE_DB_MAX_ALLOWED_BUILT_AGE`
//!   passes through. Exit 0 is success.
//! - osv-scanner: `osv-scanner scan source -L <copy> --format json --verbosity warn`; with a
//!   database directory also `--offline --offline-vulnerabilities` and
//!   `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<db>/osv-scanner`. Exit 0 (nothing found) and 1
//!   (vulnerabilities found) are success; 128 (no package sources found, and no output) is an
//!   empty result with a warning; anything else (e.g. 127, which includes an ecosystem whose
//!   offline database was not downloaded) is a failure.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rollcall_core::vex::Scanner;

/// The executable's name on PATH.
pub fn executable(scanner: Scanner) -> &'static str {
    match scanner {
        Scanner::Grype => "grype",
        Scanner::Osv => "osv-scanner",
    }
}

/// The first executable file called `name` in a PATH directory. Relative entries
/// (including the empty one, which means the current directory) are skipped.
pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn run(command: &mut Command) -> Result<Output, String> {
    command.output().map_err(|e| format!("cannot run it: {e}"))
}

/// The version the scanner reports (`grype version`, `osv-scanner --version`), if it says.
pub fn version(scanner: Scanner, bin: &Path) -> Option<String> {
    let (args, prefix): (&[&str], &str) = match scanner {
        Scanner::Grype => (&["version"], "Version:"),
        Scanner::Osv => (&["--version"], "osv-scanner version:"),
    };
    let mut command = Command::new(bin);
    command.args(args);
    if scanner == Scanner::Grype {
        command.env("GRYPE_CHECK_FOR_APP_UPDATE", "false");
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// `text` without terminal control sequences: CSI (`ESC [` … final byte), OSC (`ESC ]` …
/// BEL or `ESC \\`), other two-character `ESC` sequences, and every other C0 control
/// character and DEL except `\n` and `\t`. grype colours its log lines, and a scanner's
/// output must not drive the user's terminal.
pub fn strip_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    for d in chars.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(d) = chars.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                // Two-character sequence (or a lone ESC at the end): drop both.
                _ => {}
            },
            '\n' | '\t' => out.push(c),
            c if c.is_ascii_control() || ('\u{80}'..='\u{9f}').contains(&c) => {}
            c => out.push(c),
        }
    }
    out
}

/// The last lines of a scanner's stderr, for an error message.
fn tail(stderr: &[u8]) -> String {
    let text = strip_controls(&String::from_utf8_lossy(stderr));
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(10);
    let kept = lines.get(start..).unwrap_or_default();
    if kept.is_empty() {
        "(no output on stderr)".to_owned()
    } else {
        kept.join("\n  ")
    }
}

fn status_text(output: &Output) -> String {
    match output.status.code() {
        Some(code) => format!("exit {code}"),
        None => "killed by a signal".to_owned(),
    }
}

/// What a successful run produced.
pub enum Report {
    /// The scanner's JSON.
    Json(Vec<u8>),
    /// osv-scanner found no package it can identify (exit 128) and wrote nothing.
    NoPackages,
}

/// Runs `scanner` on `sbom` (a copy whose name ends in `.cdx.json`), offline with the
/// databases under `db` if given.
pub fn scan(
    scanner: Scanner,
    bin: &Path,
    sbom: &Path,
    db: Option<&Path>,
) -> Result<Report, String> {
    let mut command = Command::new(bin);
    match scanner {
        Scanner::Grype => {
            // An empty configuration, so grype reads none of the caller's files.
            let config = sbom.with_file_name("grype.yaml");
            std::fs::write(&config, "{}\n")
                .map_err(|e| format!("cannot write {}: {e}", config.display()))?;
            let mut target = std::ffi::OsString::from("sbom:");
            target.push(sbom.as_os_str());
            command
                .arg("-c")
                .arg(&config)
                .arg(target)
                .args(["-o", "json"])
                .env("GRYPE_CHECK_FOR_APP_UPDATE", "false");
            if let Some(db) = db {
                command
                    .env("GRYPE_DB_CACHE_DIR", db.join("grype"))
                    .env("GRYPE_DB_AUTO_UPDATE", "false");
            }
        }
        Scanner::Osv => {
            command.args(["scan", "source", "-L"]).arg(sbom).args([
                "--format",
                "json",
                "--verbosity",
                "warn",
            ]);
            if let Some(db) = db {
                command
                    .args(["--offline", "--offline-vulnerabilities"])
                    .env(
                        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
                        db.join("osv-scanner"),
                    );
            }
        }
    }
    let output = run(&mut command)?;
    let code = output.status.code();
    let ok = match scanner {
        Scanner::Grype => code == Some(0),
        Scanner::Osv => matches!(code, Some(0 | 1)),
    };
    if ok {
        return Ok(Report::Json(output.stdout));
    }
    if scanner == Scanner::Osv && code == Some(128) {
        return Ok(Report::NoPackages);
    }
    Err(format!(
        "{} ({}):\n  {}",
        display(bin),
        status_text(&output),
        tail(&output.stderr)
    ))
}

fn display(bin: &Path) -> String {
    bin.file_name().map_or_else(
        || bin.display().to_string(),
        |n| OsStr::to_string_lossy(n).into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::{strip_controls, tail};

    #[test]
    fn stderr_tail_strips_colours_and_keeps_the_last_lines() {
        assert_eq!(
            strip_controls("\u{1b}[31mfailed\u{1b}[0m to load\u{1b}"),
            "failed to load"
        );
        assert_eq!(
            strip_controls(
                "a\u{1b}]0;title\u{7}b\u{1b}]8;;http://x\u{1b}\\c\u{1b}Md\re\u{8}f\u{7f}\u{9b}g\tz\n"
            ),
            "abcdefg\tz\n"
        );
        let many: String = (0..30).map(|i| format!("line {i}\n\n")).collect();
        let kept = tail(many.as_bytes());
        assert!(
            kept.starts_with("line 20\n") && kept.ends_with("line 29"),
            "{kept}"
        );
        assert_eq!(tail(b""), "(no output on stderr)");
        assert_eq!(tail(b"\xff\xfe oops"), "\u{fffd}\u{fffd} oops");
    }
}
