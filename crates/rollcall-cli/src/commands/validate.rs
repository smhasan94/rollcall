//! `rollcall validate --schema`: check a document against the CycloneDX 1.6 JSON schema.

use rollcall_core::cyclonedx::validate_cyclonedx_1_6;
use serde_json::Value;

use crate::cli::{EXIT_DATAERR, EXIT_INVALID, EXIT_NOINPUT, ValidateArgs};

/// Runs `rollcall validate`, returning the exit code.
pub fn run(args: ValidateArgs) -> u8 {
    // `--schema` is required by the parser; it is the only check there is so far.
    debug_assert!(args.schema);
    let file = args.file.display();
    let bytes = match std::fs::read(&args.file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("rollcall validate: {file}: {e}");
            return EXIT_NOINPUT;
        }
    };
    // serde_json rejects empty input, invalid UTF-8 and nesting beyond its recursion limit.
    let document: Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(e) => {
            eprintln!("rollcall validate: {file}: not valid JSON: {e}");
            return EXIT_DATAERR;
        }
    };
    match validate_cyclonedx_1_6(&document) {
        Ok(()) => {
            println!("{file}: valid CycloneDX 1.6");
            0
        }
        Err(violations) => {
            eprintln!("{file}: {} schema violation(s)", violations.len());
            for violation in &violations {
                eprintln!("  {violation}");
            }
            EXIT_INVALID
        }
    }
}
