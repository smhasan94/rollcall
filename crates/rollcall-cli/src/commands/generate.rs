//! `rollcall generate`: render a model as CycloneDX 1.6 JSON.

use std::io::Write;

use rollcall_core::cyclonedx::{self, Timestamp, WriteError, WriteOptions};
use rollcall_core::model::Product;

use crate::cli::{EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_USAGE, Format, GenerateArgs};

/// Runs `rollcall generate`, returning the exit code.
pub fn run(args: GenerateArgs) -> u8 {
    if args.format == Format::Spdx {
        eprintln!("rollcall generate --format spdx: not implemented");
        return EXIT_USAGE;
    }
    let bytes = match std::fs::read(&args.model) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("rollcall generate: {}: {e}", args.model.display());
            return EXIT_NOINPUT;
        }
    };
    let product = match Product::from_json_bytes(&bytes) {
        Ok(product) => product,
        Err(e) => {
            eprintln!("rollcall generate: {e}");
            return EXIT_DATAERR;
        }
    };
    let mut options = WriteOptions::new(args.timestamp.unwrap_or_else(Timestamp::now));
    if let Some(serial) = args.serial_number {
        options = options.with_serial_number(serial);
    }
    let text = match cyclonedx::write(&product, &options) {
        Ok(text) => text,
        Err(e @ WriteError::Invalid(_)) => {
            eprintln!("rollcall generate: {e}");
            return EXIT_DATAERR;
        }
        Err(e) => {
            eprintln!("rollcall generate: {e}");
            return EXIT_IOERR;
        }
    };
    let written = match &args.output {
        Some(path) => std::fs::write(path, &text).map_err(|e| format!("{}: {e}", path.display())),
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("stdout: {e}"))
        }
    };
    match written {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rollcall generate: {e}");
            EXIT_IOERR
        }
    }
}
