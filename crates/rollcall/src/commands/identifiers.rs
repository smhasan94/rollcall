//! `rollcall identifiers lint`: the identifier database lint
//! ([`rollcall_core::identify::lint`]).
//!
//! Findings go to stderr, one per line (`<file>:<line>: <rule>: <message>`), sorted; a summary
//! line goes to stdout. Exit 0 when there is no finding, 1 when there is any, 66 when the
//! database cannot be read and 65 when it is not UTF-8.

use std::io::Write;

use rollcall_core::identify::lint::{self, Finding};
use rollcall_core::identify::source::db_file;
use rollcall_core::identify::{BUILTIN_DB_VERSION, BUILTIN_NAME, DbVersion};

use crate::cli::{
    EXIT_DATAERR, EXIT_INVALID, EXIT_NOINPUT, EXIT_SOFTWARE, IdentifiersArgs, IdentifiersCommand,
    LintArgs,
};

/// Runs `rollcall identifiers …`.
pub fn run(args: IdentifiersArgs) -> u8 {
    match args.command {
        IdentifiersCommand::Lint(args) => run_lint(args),
    }
}

fn run_lint(args: LintArgs) -> u8 {
    let (label, text, expected, what) = match args.path.as_deref() {
        None => {
            // The embedded database must carry the crate version it was released as.
            let Ok(expected) = BUILTIN_DB_VERSION.parse::<DbVersion>() else {
                eprintln!(
                    "rollcall identifiers lint: rollcall-identifiers version {BUILTIN_DB_VERSION} is not semver"
                );
                return EXIT_SOFTWARE;
            };
            (
                BUILTIN_NAME.to_owned(),
                rollcall_identifiers::IDENTIFIERS_YAML.to_owned(),
                Some(args.expect_version.unwrap_or(expected)),
                format!("embedded {BUILTIN_NAME}"),
            )
        }
        Some(path) => {
            let file = db_file(path);
            let bytes = match std::fs::read(&file) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("rollcall identifiers lint: {}: {e}", file.display());
                    return EXIT_NOINPUT;
                }
            };
            let Ok(text) = String::from_utf8(bytes) else {
                eprintln!(
                    "rollcall identifiers lint: {}: not valid UTF-8",
                    file.display()
                );
                return EXIT_DATAERR;
            };
            let label = file.display().to_string();
            (label.clone(), text, args.expect_version, label)
        }
    };

    let text_lint = lint::lint_text(&label, &text, expected.as_ref());
    let mut findings: Vec<Finding> = text_lint.findings;
    let mut summary = match &text_lint.db {
        Some(db) => format!(
            "{what}: db_version {}, {} modules",
            db.db_version()
                .map_or_else(|| "none".to_owned(), ToString::to_string),
            db.modules().count()
        ),
        None => format!("{what}: does not load"),
    };
    for root in &args.fixtures {
        match &text_lint.db {
            Some(db) => {
                let fixtures = lint::lint_fixtures(db, &label, root);
                summary.push_str(&format!(
                    "; {}: {} build(s), {} module component(s)",
                    root.display(),
                    fixtures.builds.len(),
                    fixtures.modules
                ));
                findings.extend(fixtures.findings);
            }
            None => summary.push_str(&format!("; {}: not checked", root.display())),
        }
    }
    findings.sort();
    findings.dedup();

    let mut stderr = std::io::stderr().lock();
    for finding in &findings {
        let _ = writeln!(stderr, "{finding}");
    }
    let _ = writeln!(
        std::io::stdout().lock(),
        "{summary}; {} finding(s)",
        findings.len()
    );
    if findings.is_empty() { 0 } else { EXIT_INVALID }
}
