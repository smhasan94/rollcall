//! `rollcall generate`: render a model, or a Zephyr image or sysbuild build directory, as
//! CycloneDX 1.6 JSON.

use std::io::Write;

use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::Product;
use rollcall_core::zephyr::{self, IngestOptions, UnknownModule, Warning};

use super::output::write_document;
use crate::cli::{EXIT_DATAERR, EXIT_NOINPUT, EXIT_USAGE, Format, GenerateArgs};

/// Runs `rollcall generate`, returning the exit code.
pub fn run(args: GenerateArgs) -> u8 {
    if args.format == Format::Spdx {
        eprintln!("rollcall generate --format spdx: not implemented");
        return EXIT_USAGE;
    }
    let product = match load_product(&args) {
        Ok(Loaded {
            product,
            warnings,
            unknown_modules,
        }) => {
            print_warnings(&warnings);
            print_stubs(&args, &unknown_modules);
            product
        }
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    let product = match apply_product(product, args.product.as_ref()) {
        Ok(product) => product,
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

/// With `--product`, puts `product` under the spec exactly as `merge --product` does, so the
/// output is byte-identical to `generate` followed by `merge --product`. Without it, returns
/// `product` unchanged.
fn apply_product(product: Product, spec: Option<&ProductSpec>) -> Result<Product, (u8, String)> {
    let Some(spec) = spec else {
        return Ok(product);
    };
    merge::merge(vec![product], Some(spec))
        .map_err(|e| (EXIT_DATAERR, format!("cannot apply --product {spec}: {e}")))
}

/// What `--model` or `--zephyr` gave.
struct Loaded {
    product: Product,
    warnings: Vec<Warning>,
    unknown_modules: Vec<UnknownModule>,
}

/// Reads the input named by `--model` or `--zephyr`: the product, any warnings and modules
/// missing from the identifier database, or the exit code and message to fail with.
fn load_product(args: &GenerateArgs) -> Result<Loaded, (u8, String)> {
    if let Some(dir) = &args.zephyr {
        let mut options = IngestOptions::new(dir)
            .with_include_sdk(args.include_sdk)
            .with_sysbuild(args.sysbuild);
        if let Some(west_list) = &args.west_list {
            options = options.with_west_list(west_list);
        }
        if let Some(db) = &args.identifier_db {
            options = options.with_identifier_db(db);
        }
        if let Some(workspace) = &args.workspace {
            options = options.with_workspace(workspace);
        }
        return match zephyr::ingest(&options) {
            Ok(ingest) => Ok(Loaded {
                product: ingest.product,
                warnings: ingest.warnings,
                unknown_modules: ingest.unknown_modules,
            }),
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
    Ok(Loaded {
        product,
        warnings: Vec::new(),
        unknown_modules: Vec::new(),
    })
}

/// One `rollcall generate: warning: …` line per warning on stderr. A closed stderr is not an
/// error: the warnings are advisory.
fn print_warnings(warnings: &[Warning]) {
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = writeln!(stderr, "rollcall generate: warning: {warning}");
    }
}

/// After the warnings, the stub entries for modules missing from the identifier database, on
/// stderr, ready to paste under its `modules:` mapping.
fn print_stubs(args: &GenerateArgs, unknown: &[UnknownModule]) {
    if unknown.is_empty() {
        return;
    }
    let db = args
        .identifier_db
        .as_deref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "the identifier database".to_owned());
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rollcall generate: {} module(s) not in {db}; paste and fill in:",
        unknown.len()
    );
    for module in unknown {
        let _ = write!(stderr, "{}", module.stub);
    }
}
