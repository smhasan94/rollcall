//! `rollcall report`: a readiness report for an SBOM, with optional scanner output and VEX,
//! as Markdown or `rollcall-report/1` JSON.

use std::io::Write;
use std::path::Path;

use rollcall_core::cyclonedx::Timestamp;
use rollcall_core::report::{self, Input};

use super::output::write_atomically;
use crate::cli::{EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, ReportArgs, ReportFormat};

type Failure = (u8, String);

/// Runs `rollcall report`, returning the exit code: 0 whenever a report is written, whatever
/// its score.
pub fn run(args: ReportArgs) -> u8 {
    match produce(&args) {
        Ok(()) => 0,
        Err((code, message)) => {
            // Nothing more to do if stderr is gone; the exit code still says it failed.
            let _ = writeln!(std::io::stderr(), "rollcall report: {message}");
            code
        }
    }
}

/// The name the report gives an input: its file name, so the report does not depend on
/// where the inputs were read from.
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

fn input((name, bytes): &(String, Vec<u8>)) -> Input<'_> {
    Input {
        name: name.as_str(),
        bytes: bytes.as_slice(),
    }
}

fn produce(args: &ReportArgs) -> Result<(), Failure> {
    let sbom = read(&args.file)?;
    let scans = args
        .scan
        .iter()
        .map(|p| read(p))
        .collect::<Result<Vec<_>, _>>()?;
    let vex = args
        .vex
        .iter()
        .map(|p| read(p))
        .collect::<Result<Vec<_>, _>>()?;
    let scans: Vec<Input<'_>> = scans.iter().map(input).collect();
    let vex: Vec<Input<'_>> = vex.iter().map(input).collect();
    let timestamp = args.timestamp.clone().unwrap_or_else(Timestamp::now);
    let built = report::build(input(&sbom), &scans, &vex, &timestamp)
        .map_err(|e| (EXIT_DATAERR, e.to_string()))?;
    let text = match args.format {
        ReportFormat::Md => report::to_markdown(&built),
        ReportFormat::Json => report::to_json(&built)
            .map_err(|e| (EXIT_SOFTWARE, format!("cannot serialise the report: {e}")))?,
    };
    match &args.output {
        Some(path) => write_atomically(path, text.as_bytes())
            .map_err(|e| (EXIT_IOERR, format!("{}: {e}", path.display()))),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| (EXIT_IOERR, format!("stdout: {e}")))
        }
    }
}
