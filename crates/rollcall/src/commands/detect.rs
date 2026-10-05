//! `rollcall detect`: print which ecosystem a directory is, as `rollcall generate DIR` tells it
//! ([`rollcall_core::detect`]). The Action's `ecosystem: auto` runs it.

use std::io::Write;

use rollcall_core::detect::{self, DetectError, DetectOptions};

use crate::cli::{DetectArgs, EXIT_NOINPUT, EXIT_USAGE};

/// The exit code for a detection error: 64 when several ecosystems match (pass
/// `--ecosystem`), 66 when none does or the path is not a directory.
pub fn exit_code(error: &DetectError) -> u8 {
    match error {
        DetectError::Ambiguous { .. } => EXIT_USAGE,
        _ => EXIT_NOINPUT,
    }
}

/// Runs `rollcall detect`, returning the exit code.
pub fn run(args: DetectArgs) -> u8 {
    let options = DetectOptions {
        build_dir: args.build.clone(),
    };
    match detect::detect(&args.dir, &options) {
        Ok(detection) => {
            let mut stdout = std::io::stdout().lock();
            match writeln!(stdout, "{}", detection.ecosystem) {
                Ok(()) => 0,
                Err(_) => crate::cli::EXIT_IOERR,
            }
        }
        Err(e) => {
            eprintln!("rollcall detect: {e}");
            exit_code(&e)
        }
    }
}
