//! `rollcall validate`: check a document against the CycloneDX 1.6 JSON schema (`--schema`)
//! and/or regulator profiles (`--profile cisa-2026|cra|all|PATH`).
//!
//! `--schema` tells a CSAF document (one with `document.csaf_version`) from CycloneDX by
//! content, and checks it against the vendored CSAF 2.0 schema and the mandatory tests
//! rollcall implements ([`rollcall_core::csaf::validate`]) instead.

use std::io::Write;
use std::path::Path;

use rollcall_core::SchemaViolation;
use rollcall_core::csaf;
use rollcall_core::cyclonedx::validate_cyclonedx_1_6;
use rollcall_core::validate::{
    Profile, ProfileError, Report, builtin_ids, builtin_profiles, validate_profiles,
};
use serde_json::{Value, json};

use crate::cli::{
    EXIT_DATAERR, EXIT_INVALID, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, EXIT_USAGE, ValidateArgs,
};

/// The version of the `--json` output's shape.
const JSON_VERSION: u32 = 1;

/// Whether a `--profile` value names a file rather than a built-in profile.
fn is_path(value: &str) -> bool {
    value.contains('/')
        || value.contains(std::path::MAIN_SEPARATOR)
        || value.ends_with(".yaml")
        || value.ends_with(".yml")
}

/// Resolves `--profile`, or returns the exit code and message.
fn load_profiles(value: &str) -> Result<Vec<Profile>, (u8, String)> {
    if value == "all" {
        return Ok(builtin_profiles());
    }
    if is_path(value) {
        return Profile::from_path(Path::new(value))
            .map(|p| vec![p])
            .map_err(|e| match e {
                ProfileError::Io { .. } => (EXIT_NOINPUT, e.to_string()),
                e => (EXIT_DATAERR, format!("{value}: {e}")),
            });
    }
    Profile::builtin(value).map(|p| vec![p]).ok_or_else(|| {
        (
            EXIT_USAGE,
            format!(
                "unknown profile {value:?}: use {}, all, or the path of a profile YAML file",
                builtin_ids().join(", ")
            ),
        )
    })
}

/// Runs `rollcall validate`, returning the exit code.
pub fn run(args: ValidateArgs) -> u8 {
    let file = args.file.display().to_string();
    let fail = |code: u8, message: &str| {
        let _ = writeln!(std::io::stderr(), "rollcall validate: {message}");
        code
    };
    // Resolve the profile first: a usage error should not depend on the document.
    let profiles = match args.profile.as_deref().map(load_profiles).transpose() {
        Ok(profiles) => profiles,
        Err((code, message)) => return fail(code, &message),
    };
    let bytes = match std::fs::read(&args.file) {
        Ok(bytes) => bytes,
        Err(e) => return fail(EXIT_NOINPUT, &format!("{file}: {e}")),
    };
    // serde_json rejects empty input, invalid UTF-8 and nesting beyond its recursion limit.
    let document: Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(e) => return fail(EXIT_DATAERR, &format!("{file}: not valid JSON: {e}")),
    };
    let is_csaf = csaf::is_csaf(&document);
    let schema_name = if is_csaf { "CSAF 2.0" } else { "CycloneDX 1.6" };
    let violations = args.schema.then(|| {
        if is_csaf {
            csaf::validate(&document).err().unwrap_or_default()
        } else {
            validate_cyclonedx_1_6(&document).err().unwrap_or_default()
        }
    });
    let report = profiles.map(|p| validate_profiles(&document, &p));
    let failed = violations.as_ref().is_some_and(|v| !v.is_empty())
        || report.as_ref().is_some_and(|r| !r.passed());
    let code = if failed { EXIT_INVALID } else { 0 };
    let written = if args.json {
        write_json(&file, violations.as_deref(), report.as_ref())
    } else {
        write_text(&file, schema_name, violations.as_deref(), report.as_ref())
    };
    match written {
        Ok(()) => code,
        Err(e) => e,
    }
}

/// `--json`: one object on stdout, nothing on stderr.
fn write_json(
    file: &str,
    violations: Option<&[SchemaViolation]>,
    report: Option<&Report>,
) -> Result<(), u8> {
    let profile = match report.map(serde_json::to_value).transpose() {
        Ok(profile) => profile,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rollcall validate: {e}");
            return Err(EXIT_SOFTWARE);
        }
    };
    let output = json!({
        "rollcall-validate": JSON_VERSION,
        "file": file,
        "schema": {
            "checked": violations.is_some(),
            "violations": violations.unwrap_or_default().iter()
                .map(|v| json!({"path": v.path, "message": v.message}))
                .collect::<Vec<_>>(),
        },
        "profile": profile,
    });
    let text = match serde_json::to_string_pretty(&output) {
        Ok(text) => text,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rollcall validate: {e}");
            return Err(EXIT_SOFTWARE);
        }
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(|_| EXIT_IOERR)
}

/// `1 check`, `12 checks`.
fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Text: passes on stdout; violations, findings and warnings on stderr.
fn write_text(
    file: &str,
    schema_name: &str,
    violations: Option<&[SchemaViolation]>,
    report: Option<&Report>,
) -> Result<(), u8> {
    let mut out = Vec::new();
    // A closed stderr must not turn a validation failure into a panic; the exit code still
    // carries the result.
    let mut stderr = std::io::stderr().lock();
    match violations {
        Some([]) => out.push(format!("{file}: valid {schema_name}")),
        Some(violations) => {
            let _ = writeln!(stderr, "{file}: {} schema violation(s)", violations.len());
            for violation in violations {
                let _ = writeln!(stderr, "  {violation}");
            }
        }
        None => {}
    }
    if let Some(report) = report {
        let profiles = report.profiles.join(", ");
        if report.passed() {
            out.push(format!(
                "{file}: passes {profiles} ({}, {})",
                plural(report.checks_run, "check"),
                plural(report.warnings, "warning")
            ));
        } else {
            let _ = writeln!(
                stderr,
                "{file}: {} error(s), {} warning(s) against {profiles}",
                report.errors, report.warnings
            );
        }
        for finding in &report.findings {
            let _ = writeln!(stderr, "  {finding}");
        }
    }
    if out.is_empty() {
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    out.iter()
        .try_for_each(|line| writeln!(stdout, "{line}"))
        .and_then(|()| stdout.flush())
        // Nowhere left to report it; the exit code says the result was not delivered.
        .map_err(|_| EXIT_IOERR)
}
