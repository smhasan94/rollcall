//! `rollcall generate`: render a model, or a Zephyr image or sysbuild build directory, as
//! CycloneDX 1.6 JSON.

use std::io::Write;

use rollcall_core::model::Product;
use rollcall_core::zephyr::{self, IngestOptions, Warning};

use super::output::write_document;
use crate::cli::{EXIT_DATAERR, EXIT_NOINPUT, EXIT_USAGE, Format, GenerateArgs};

/// Runs `rollcall generate`, returning the exit code.
pub fn run(args: GenerateArgs) -> u8 {
    if args.format == Format::Spdx {
        eprintln!("rollcall generate --format spdx: not implemented");
        return EXIT_USAGE;
    }
    let product = match load_product(&args) {
        Ok((product, warnings)) => {
            print_warnings(&warnings);
            product
        }
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    match write_document(
        &product,
        args.timestamp,
        args.serial_number,
        args.output.as_deref(),
    ) {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            code
        }
    }
}

/// Reads the input named by `--model` or `--zephyr`: the product and any warnings, or the
/// exit code and message to fail with.
fn load_product(args: &GenerateArgs) -> Result<(Product, Vec<Warning>), (u8, String)> {
    if let Some(dir) = &args.zephyr {
        let mut options = IngestOptions::new(dir)
            .with_include_sdk(args.include_sdk)
            .with_sysbuild(args.sysbuild);
        if let Some(west_list) = &args.west_list {
            options = options.with_west_list(west_list);
        }
        return match zephyr::ingest(&options) {
            Ok(ingest) => Ok((ingest.product, ingest.warnings)),
            // Missing or unreadable input (including a directory where a file should be).
            Err(e) if e.is_read_error() => Err((EXIT_NOINPUT, e.to_string())),
            Err(e) => Err((EXIT_DATAERR, e.to_string())),
        };
    }
    // clap guarantees exactly one of --model / --zephyr.
    let Some(model) = &args.model else {
        return Err((
            EXIT_USAGE,
            "one of --model or --zephyr is required".to_owned(),
        ));
    };
    let bytes =
        std::fs::read(model).map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", model.display())))?;
    let product = Product::from_json_bytes(&bytes).map_err(|e| (EXIT_DATAERR, e.to_string()))?;
    Ok((product, Vec::new()))
}

/// One `rollcall generate: warning: …` line per warning on stderr. A closed stderr is not an
/// error: the warnings are advisory.
fn print_warnings(warnings: &[Warning]) {
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = writeln!(stderr, "rollcall generate: warning: {warning}");
    }
}
