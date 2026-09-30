//! `rollcall validate --schema`: check a document against the CycloneDX 1.6 JSON schema.

use std::io::Write;

use rollcall_core::cyclonedx::validate_cyclonedx_1_6;
use serde_json::Value;

use crate::cli::{EXIT_DATAERR, EXIT_INVALID, EXIT_IOERR, EXIT_NOINPUT, ValidateArgs};

/// Runs `rollcall validate`, returning the exit code.
pub fn run(args: ValidateArgs) -> u8 {
    // `--schema` is required by the parser; it is the only check there is so far.
    debug_assert!(args.schema);
    let file = args.file.display();
    let bytes = match std::fs::read(&args.file) {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "rollcall validate: {file}: {e}");
            return EXIT_NOINPUT;
        }
    };
    // serde_json rejects empty input, invalid UTF-8 and nesting beyond its recursion limit.
    let document: Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "rollcall validate: {file}: not valid JSON: {e}"
            );
            return EXIT_DATAERR;
        }
    };
    match validate_cyclonedx_1_6(&document) {
        Ok(()) => {
            let mut stdout = std::io::stdout().lock();
            match writeln!(stdout, "{file}: valid CycloneDX 1.6").and_then(|()| stdout.flush()) {
                Ok(()) => 0,
                // Nowhere left to report it; the exit code says the result was not delivered.
                Err(_) => EXIT_IOERR,
            }
        }
        Err(violations) => {
            // A closed stderr must not turn a validation failure into a panic; the exit code
            // still carries the result.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{file}: {} schema violation(s)", violations.len());
            for violation in &violations {
                let _ = writeln!(stderr, "  {violation}");
            }
            EXIT_INVALID
        }
    }
}
