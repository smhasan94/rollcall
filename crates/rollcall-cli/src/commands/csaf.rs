//! `rollcall csaf`: an SBOM's scan and VEX results as a CSAF 2.0 VEX document.

use std::io::Write;
use std::path::Path;

use rollcall_core::csaf::{self, CsafError, CsafOptions};
use rollcall_core::cyclonedx::Timestamp;
use rollcall_core::report::Input;
use rollcall_core::warning::Warning;

use super::output::write_atomically;
use crate::cli::{
    CsafArgs, EXIT_CSAF_EMPTY, EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_SOFTWARE, EXIT_USAGE,
};

type Failure = (u8, String);

/// Runs `rollcall csaf`, returning the exit code:
///
/// | Exit | Meaning |
/// |------|---------|
/// | 0 | the document was written |
/// | 1 | no finding about an SBOM component: nothing to export, nothing written |
/// | 64 | no publisher: neither `--publisher`/`--publisher-namespace` nor an SBOM supplier |
/// | 65 | an input is malformed |
/// | 66 | an input is missing or unreadable |
/// | 70 | the document fails the CSAF 2.0 schema or a mandatory test (nothing written) |
/// | 74 | the output cannot be written |
pub fn run(args: CsafArgs) -> u8 {
    match produce(&args) {
        Ok(()) => 0,
        Err((code, message)) => {
            // Nothing more to do if stderr is gone; the exit code still says it failed.
            let _ = writeln!(std::io::stderr(), "rollcall csaf: {message}");
            code
        }
    }
}

/// The name an input goes by in messages: its file name.
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

fn print_warnings(warnings: &[Warning]) {
    // Nothing more to do if stderr is gone.
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = writeln!(stderr, "rollcall csaf: warning: {warning}");
    }
}

fn exit_code(e: &CsafError) -> u8 {
    match e {
        CsafError::NoFindings(_) => EXIT_CSAF_EMPTY,
        CsafError::Publisher(_) => EXIT_USAGE,
        CsafError::Invalid(_) | CsafError::Json(_) => EXIT_SOFTWARE,
        _ => EXIT_DATAERR,
    }
}

fn produce(args: &CsafArgs) -> Result<(), Failure> {
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

    let mut options = CsafOptions::new(args.timestamp.clone().unwrap_or_else(Timestamp::now));
    options.id = args.id.clone();
    options.publisher_name = args.publisher.clone();
    options.publisher_namespace = args.publisher_namespace.clone();
    options.publisher_category = args.publisher_category.into();
    options.title = args.title.clone();
    options.tlp = args.tlp.map(Into::into);

    // The warnings come first, also when nothing is written, so an exit 1 (nothing to
    // export), 65 (conflicting statuses) or 70 (invalid document) says what was left out
    // and why.
    let export = match csaf::build(input(&sbom), &scans, &vex, &options) {
        Ok(export) => export,
        Err(CsafError::NoFindings(warnings)) => {
            print_warnings(&warnings);
            let e = CsafError::NoFindings(Vec::new());
            return Err((exit_code(&e), e.to_string()));
        }
        Err(CsafError::Conflict { conflict, warnings }) => {
            print_warnings(&warnings);
            let e = CsafError::Conflict {
                conflict,
                warnings: Vec::new(),
            };
            return Err((exit_code(&e), e.to_string()));
        }
        Err(e) => return Err((exit_code(&e), e.to_string())),
    };
    print_warnings(&export.warnings);
    let text = csaf::to_json(&export.csaf).map_err(|e| (exit_code(&e), e.to_string()))?;
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
