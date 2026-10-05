//! `rollcall scan`: run grype and/or osv-scanner on an SBOM, normalise and VEX-triage their
//! findings (`rollcall_core::scan`), print a table or `rollcall-scan/1` JSON, and exit 0, 1,
//! 2 or 3 (see docs/scan.md).

mod runner;

use std::io::Write;
use std::path::{Path, PathBuf};

use rollcall_core::scan::{
    self, Gate, LabelledVex, Sbom, ScanReport, ScannerRun, ScannerStatus, parse_vex,
};
use rollcall_core::vex::{self, Finding, Scanner};
use rollcall_core::warning::Warning;

use crate::cli::{
    EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SCAN_FINDINGS, EXIT_SCAN_SCANNER,
    EXIT_SCAN_UNRESOLVED, EXIT_SOFTWARE, ScanArgs, ScannerChoice,
};

type Failure = (u8, String);

/// Runs `rollcall scan`, returning the exit code.
pub fn run(args: ScanArgs) -> u8 {
    match scan_command(&args) {
        Ok(code) => code,
        Err((code, message)) => {
            let _ = writeln!(std::io::stderr(), "rollcall scan: {message}");
            code
        }
    }
}

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", path.display())))
}

/// A VEX file's label in the report: its file name, so reports carry no host paths.
fn label(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn load_vex(paths: &[PathBuf]) -> Result<Vec<LabelledVex>, Failure> {
    let mut documents = Vec::with_capacity(paths.len());
    for path in paths {
        let document = parse_vex(&read(path)?)
            .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", path.display())))?;
        documents.push((label(path), document));
    }
    Ok(documents)
}

fn stderr_line(text: &str) {
    let _ = writeln!(std::io::stderr(), "rollcall scan: {text}");
}

/// Runs one scanner, returning its run record and findings.
fn run_scanner(
    scanner: Scanner,
    asked_by_name: bool,
    copy: &Path,
    db: Option<&Path>,
    warnings: &mut Vec<Warning>,
) -> (ScannerRun, Vec<Finding>) {
    let name = runner::executable(scanner);
    let mut record = ScannerRun {
        scanner,
        version: None,
        status: ScannerStatus::Failed,
        offline: db.is_some(),
    };
    let Some(bin) = runner::find_in_path(name) else {
        if asked_by_name {
            stderr_line(&format!("error: {name} not found on PATH"));
        } else {
            record.status = ScannerStatus::Skipped;
            warnings.push(Warning::new(
                name,
                "not found on PATH; skipped (--scanner auto)",
            ));
        }
        return (record, Vec::new());
    };
    record.version = runner::version(scanner, &bin);
    let output = match runner::scan(scanner, &bin, copy, db) {
        Ok(runner::Report::Json(json)) => json,
        Ok(runner::Report::NoPackages) => {
            record.status = ScannerStatus::Ok;
            warnings.push(Warning::new(
                name,
                "found no package it can identify in the SBOM (exit 128); no findings",
            ));
            return (record, Vec::new());
        }
        Err(message) => {
            stderr_line(&format!("error: {name} failed: {message}"));
            return (record, Vec::new());
        }
    };
    match vex::parse_findings(&output) {
        Ok(parsed) if parsed.scanner == scanner => {
            record.status = ScannerStatus::Ok;
            warnings.extend(
                parsed
                    .warnings
                    .into_iter()
                    .map(|w| Warning::new(format!("{name}: {}", w.location), w.message)),
            );
            (record, parsed.findings)
        }
        Ok(parsed) => {
            stderr_line(&format!(
                "error: {name}'s output is {} JSON, not its own",
                parsed.scanner
            ));
            (record, Vec::new())
        }
        Err(e) => {
            stderr_line(&format!("error: cannot read {name}'s output: {e}"));
            (record, Vec::new())
        }
    }
}

fn scan_command(args: &ScanArgs) -> Result<u8, Failure> {
    let sbom_bytes = read(&args.sbom)?;
    let sbom = Sbom::from_bytes(&sbom_bytes)
        .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", args.sbom.display())))?;
    let documents = load_vex(&args.vex)?;
    if let Some(db) = &args.db_path
        && !db.is_dir()
    {
        return Err((
            EXIT_NOINPUT,
            format!("--db-path {}: not a directory", db.display()),
        ));
    }

    // The scanners read a copy named *.cdx.json: osv-scanner recognises CycloneDX by name.
    let work = tempfile::tempdir().map_err(|e| {
        (
            EXIT_IOERR,
            format!("cannot create a temporary directory: {e}"),
        )
    })?;
    let copy = work.path().join("sbom.cdx.json");
    std::fs::write(&copy, &sbom_bytes)
        .map_err(|e| (EXIT_IOERR, format!("{}: {e}", copy.display())))?;

    let scanners: &[Scanner] = match args.scanner {
        ScannerChoice::Grype => &[Scanner::Grype],
        ScannerChoice::Osv => &[Scanner::Osv],
        ScannerChoice::Auto => &[Scanner::Grype, Scanner::Osv],
    };
    let asked_by_name = args.scanner != ScannerChoice::Auto;
    let mut warnings = Vec::new();
    let mut runs = Vec::new();
    let mut findings = Vec::new();
    for &scanner in scanners {
        let (run, found) = run_scanner(
            scanner,
            asked_by_name,
            &copy,
            args.db_path.as_deref(),
            &mut warnings,
        );
        runs.push(run);
        findings.extend(found);
    }
    if runs.iter().all(|r| r.status == ScannerStatus::Skipped) {
        stderr_line("error: no scanner found on PATH (install grype or osv-scanner)");
    }

    let report = scan::scan(&sbom, runs, &findings, &documents, warnings);
    for warning in &report.warnings {
        stderr_line(&format!("warning: {warning}"));
    }
    let unknown = report.open_unknown_severity();
    if unknown > 0 {
        stderr_line(&format!(
            "{unknown} open finding(s) have unknown severity; only --fail-on unknown fails on \
             them"
        ));
    }
    let text = if args.json {
        report
            .to_json()
            .map_err(|e| (EXIT_SOFTWARE, format!("cannot serialise the report: {e}")))?
    } else {
        report.to_table()
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| (EXIT_IOERR, format!("stdout: {e}")))?;
    Ok(exit_code(&report, args))
}

fn exit_code(report: &ScanReport, args: &ScanArgs) -> u8 {
    let gate = Gate {
        fail_on: args.fail_on.map(Into::into),
        fail_on_unresolved: args.fail_on_unresolved,
    };
    match gate.decide(report) {
        scan::Outcome::Clean => 0,
        scan::Outcome::Findings => EXIT_SCAN_FINDINGS,
        scan::Outcome::Unresolved => EXIT_SCAN_UNRESOLVED,
        scan::Outcome::ScannerFailed => EXIT_SCAN_SCANNER,
    }
}
