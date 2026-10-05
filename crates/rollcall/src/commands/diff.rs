//! `rollcall diff`: a build's SBOM and findings compared with its base branch's, as Markdown
//! (the pull-request comment) or `rollcall-diff/1` JSON, gated on new findings.

use std::io::Write;
use std::path::Path;

use rollcall_core::diff::{self, GateOutcome, Side};
use rollcall_core::report::Input;

use super::output::write_atomically;
use crate::cli::{
    DiffArgs, DiffFormat, EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SCAN_FINDINGS, EXIT_SOFTWARE,
};

type Failure = (u8, String);

/// Runs `rollcall diff`, returning the exit code: 1 when a new open finding reaches
/// `--fail-on` (the diff is still written), else 0.
pub fn run(args: DiffArgs) -> u8 {
    match produce(&args) {
        Ok(GateOutcome::Clean) => 0,
        Ok(GateOutcome::Findings) => EXIT_SCAN_FINDINGS,
        Err((code, message)) => {
            // Nothing more to do if stderr is gone; the exit code still says it failed.
            let _ = writeln!(std::io::stderr(), "rollcall diff: {message}");
            code
        }
    }
}

/// The name the diff gives an input in messages: its file name.
fn name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

fn read(path: &Path) -> Result<(String, Vec<u8>), Failure> {
    std::fs::read(path)
        .map(|bytes| (name(path), bytes))
        .map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", path.display())))
}

fn read_opt(path: Option<&Path>) -> Result<Option<(String, Vec<u8>)>, Failure> {
    path.map(read).transpose()
}

fn input((name, bytes): &(String, Vec<u8>)) -> Input<'_> {
    Input {
        name: name.as_str(),
        bytes: bytes.as_slice(),
    }
}

fn produce(args: &DiffArgs) -> Result<GateOutcome, Failure> {
    let sbom = read(&args.sbom)?;
    let scan = read_opt(args.scan.as_deref())?;
    let report = read_opt(args.report.as_deref())?;
    let base_sbom = read_opt(args.base_sbom.as_deref())?;
    let base_scan = read_opt(args.base_scan.as_deref())?;
    let base_report = read_opt(args.base_report.as_deref())?;

    let head = Side {
        sbom: input(&sbom),
        scan: scan.as_ref().map(input),
        report: report.as_ref().map(input),
    };
    let base = base_sbom.as_ref().map(|sbom| Side {
        sbom: input(sbom),
        scan: base_scan.as_ref().map(input),
        report: base_report.as_ref().map(input),
    });
    let built = diff::build(head, base, args.fail_on.map(Into::into))
        .map_err(|e| (EXIT_DATAERR, e.to_string()))?;
    let text = match args.format {
        DiffFormat::Md => diff::to_markdown(&built),
        DiffFormat::Json => diff::to_json(&built)
            .map_err(|e| (EXIT_SOFTWARE, format!("cannot serialise the diff: {e}")))?,
    };
    match &args.output {
        Some(path) => write_atomically(path, text.as_bytes())
            .map_err(|e| (EXIT_IOERR, format!("{}: {e}", path.display())))?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| (EXIT_IOERR, format!("stdout: {e}")))?;
        }
    }
    Ok(built.gate.outcome)
}
