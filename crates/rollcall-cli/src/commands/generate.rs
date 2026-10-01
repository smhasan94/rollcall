//! `rollcall generate`: render a model, or a Zephyr image or sysbuild build directory, as
//! CycloneDX 1.6 JSON.

use std::io::Write;
use std::path::Path;

use rollcall_core::identify::{self, DbSource, LoadedDbs};
use rollcall_core::merge::{self, ProductSpec};
use rollcall_core::model::Product;
use rollcall_core::zephyr::{self, IngestOptions, UnknownModule, Warning};

use super::output::write_document;
use crate::cli::{EXIT_DATAERR, EXIT_NOINPUT, EXIT_USAGE, Format, GenerateArgs};

/// Runs `rollcall generate`, returning the exit code. `identifiers` is the global
/// `--identifiers` path.
pub fn run(args: GenerateArgs, identifiers: Option<&Path>) -> u8 {
    if args.format == Format::Spdx {
        eprintln!("rollcall generate --format spdx: not implemented");
        return EXIT_USAGE;
    }
    let dbs = match select_db(&args, identifiers) {
        Ok(dbs) => dbs,
        Err((code, message)) => {
            eprintln!("rollcall generate: {message}");
            return code;
        }
    };
    let product = match load_product(&args, dbs.as_ref()) {
        Ok(Loaded {
            product,
            warnings,
            unknown_modules,
        }) => {
            print_warnings(&warnings);
            print_stubs(dbs.as_ref(), &unknown_modules);
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
    // Which identifier database resolved the modules, if any (no paths: deterministic).
    let properties = dbs
        .as_ref()
        .map(|d| identify::provenance(&d.active, &d.source))
        .unwrap_or_default();
    match write_document(
        &product,
        properties,
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

/// The identifier database to resolve modules with, if module resolution is on: with
/// `--zephyr` and any of `--identifier-db FILE` (that file), `--identify` or the global
/// `--identifiers PATH` (the active database, [`identify::select`]). Skipped cache entries
/// are printed as warnings, and a database picked up from the cache is named on stderr.
fn select_db(
    args: &GenerateArgs,
    identifiers: Option<&Path>,
) -> Result<Option<LoadedDbs>, (u8, String)> {
    let wanted = args.zephyr.is_some()
        && (args.identify || args.identifier_db.is_some() || identifiers.is_some());
    if !wanted {
        return Ok(None);
    }
    let explicit = args.identifier_db.as_deref().or(identifiers);
    let loaded = identify::select(explicit, &|name| std::env::var_os(name)).map_err(|e| {
        let code = if e.is_read_error() {
            EXIT_NOINPUT
        } else {
            EXIT_DATAERR
        };
        (code, e.to_string())
    })?;
    let mut stderr = std::io::stderr().lock();
    for warning in &loaded.warnings {
        let _ = writeln!(stderr, "rollcall generate: warning: identifiers: {warning}");
    }
    if let DbSource::Cache(path) = &loaded.source {
        let version = loaded
            .active
            .db_version()
            .map_or_else(String::new, ToString::to_string);
        let _ = writeln!(
            stderr,
            "rollcall generate: note: identifier database {version} from the cache ({})",
            path.display()
        );
    }
    Ok(Some(loaded))
}

/// Reads the input named by `--model` or `--zephyr`, resolving modules with `dbs` if given:
/// the product, any warnings and modules missing from the identifier database, or the exit
/// code and message to fail with.
fn load_product(args: &GenerateArgs, dbs: Option<&LoadedDbs>) -> Result<Loaded, (u8, String)> {
    if let Some(dir) = &args.zephyr {
        let mut options = IngestOptions::new(dir)
            .with_include_sdk(args.include_sdk)
            .with_sysbuild(args.sysbuild);
        if let Some(west_list) = &args.west_list {
            options = options.with_west_list(west_list);
        }
        // The database's file, if it has one, locates errors in its values.
        if let Some(DbSource::Flag(file) | DbSource::Env(file) | DbSource::Cache(file)) =
            dbs.map(|d| &d.source)
        {
            options = options.with_identifier_db(file);
        }
        if let Some(workspace) = &args.workspace {
            options = options.with_workspace(workspace);
        }
        return match zephyr::ingest_with_db(&options, dbs.map(|d| &d.active)) {
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
fn print_stubs(dbs: Option<&LoadedDbs>, unknown: &[UnknownModule]) {
    if unknown.is_empty() {
        return;
    }
    let db = dbs.map_or_else(
        || "the identifier database".to_owned(),
        |d| d.active.name().to_owned(),
    );
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rollcall generate: {} module(s) not in {db}; paste and fill in:",
        unknown.len()
    );
    for module in unknown {
        let _ = write!(stderr, "{}", module.stub);
    }
    // The embedded database cannot be edited in place.
    if dbs.is_some_and(|d| d.source == DbSource::Embedded) {
        let _ = writeln!(
            stderr,
            "rollcall generate: the embedded database is read-only: add the entries to a copy of \
             it and pass that with --identifiers PATH, or contribute them (CONTRIBUTING.md)"
        );
    }
}
