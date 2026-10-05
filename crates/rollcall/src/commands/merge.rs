//! `rollcall merge`: combine separately generated CycloneDX documents (bootloader,
//! application, blobs) into one product.

use std::io::Write;
use std::path::{Path, PathBuf};

use rollcall_core::blob;
use rollcall_core::cyclonedx::{self, Property};
use rollcall_core::merge;
use rollcall_core::model::Product;
use rollcall_core::warning::Warning;

use super::output::write_document;
use crate::cli::{EXIT_DATAERR, EXIT_NOINPUT, EXIT_USAGE, MergeArgs};

/// Runs `rollcall merge`, returning the exit code.
pub fn run(args: MergeArgs) -> u8 {
    match merged_product(&args) {
        Ok((product, properties)) => match write_document(
            &product,
            properties,
            args.timestamp,
            args.serial_number,
            args.output.as_deref(),
        ) {
            Ok(()) => 0,
            Err((code, message)) => fail(code, &message),
        },
        Err((code, message)) => fail(code, &message),
    }
}

fn fail(code: u8, message: &str) -> u8 {
    let _ = writeln!(std::io::stderr(), "rollcall merge: {message}");
    code
}

/// One `rollcall merge: warning: <file>: …` line per warning on stderr.
fn print_warnings(file: &Path, warnings: &[Warning]) {
    let mut stderr = std::io::stderr().lock();
    for warning in warnings {
        let _ = writeln!(
            stderr,
            "rollcall merge: warning: {}: {warning}",
            file.display()
        );
    }
}

/// Reads one input document: its product and the document properties rollcall carries over
/// (the identifier database provenance).
fn read_input(path: &Path) -> Result<(Product, Vec<Property>), (u8, String)> {
    let bytes =
        std::fs::read(path).map_err(|e| (EXIT_NOINPUT, format!("{}: {e}", path.display())))?;
    let read = cyclonedx::read_bytes(&bytes)
        .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", path.display())))?;
    print_warnings(path, &read.warnings);
    Ok((read.product, read.metadata_properties))
}

/// Without `--product`, every input must name the same product and version as the first;
/// otherwise the error names both files.
fn check_same_product(inputs: &[(PathBuf, Product)]) -> Result<(), (u8, String)> {
    let Some((first_path, first)) = inputs.first() else {
        return Ok(());
    };
    let identity = |p: &Product| match &p.version {
        Some(version) => format!("{}@{version}", p.name),
        None => p.name.clone(),
    };
    for (path, product) in inputs.iter().skip(1) {
        if product.name != first.name || product.version != first.version {
            let field = if product.name != first.name {
                "names"
            } else {
                "versions"
            };
            return Err((
                EXIT_DATAERR,
                format!(
                    "conflicting product {field}: {} is {}, {} is {}; pass --product \
                     NAME[@VERSION] to merge them into one product",
                    first_path.display(),
                    identity(first),
                    path.display(),
                    identity(product),
                ),
            ));
        }
    }
    Ok(())
}

/// Reads every input and the blob manifest and merges them. The merged document keeps every
/// distinct provenance property of the inputs (so inputs resolved with different databases
/// say so), sorted.
fn merged_product(args: &MergeArgs) -> Result<(Product, Vec<Property>), (u8, String)> {
    let mut inputs = Vec::with_capacity(args.inputs.len());
    let mut properties = Vec::new();
    for path in &args.inputs {
        let (product, props) = read_input(path)?;
        properties.extend(props);
        inputs.push((path.clone(), product));
    }
    properties.sort();
    properties.dedup();
    if args.product.is_none() {
        if inputs.is_empty() {
            return Err((
                EXIT_USAGE,
                "--blob-manifest without input documents needs --product NAME[@VERSION]".to_owned(),
            ));
        }
        check_same_product(&inputs)?;
    }
    let blobs = match &args.blob_manifest {
        Some(manifest) => {
            let ingest = blob::load(manifest).map_err(|e| {
                let code = if e.is_read_error() {
                    EXIT_NOINPUT
                } else {
                    EXIT_DATAERR
                };
                (code, format!("{}: {e}", manifest.display()))
            })?;
            print_warnings(manifest, &ingest.warnings);
            ingest.blobs
        }
        None => Vec::new(),
    };
    let files: Vec<String> = inputs
        .iter()
        .map(|(p, _)| p.display().to_string())
        .collect();
    let products = inputs.into_iter().map(|(_, product)| product).collect();
    let mut product = merge::merge(products, args.product.as_ref()).map_err(|e| {
        (
            EXIT_DATAERR,
            format!("cannot merge {}: {e}", files.join(", ")),
        )
    })?;
    if !blobs.is_empty() {
        let manifest = args
            .blob_manifest
            .as_deref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        merge::attach_blobs(&mut product, blobs)
            .map_err(|e| (EXIT_DATAERR, format!("{manifest}: {e}")))?;
    }
    Ok((product, properties))
}
