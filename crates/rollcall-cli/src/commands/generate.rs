//! `rollcall generate`: render a model, or a Zephyr build directory, as CycloneDX 1.6 JSON.

use std::io::Write;
use std::path::Path;

use rollcall_core::cyclonedx::{self, Timestamp, WriteError, WriteOptions};
use rollcall_core::model::Product;
use rollcall_core::zephyr::{self, IngestOptions, Warning};

use crate::cli::{EXIT_DATAERR, EXIT_IOERR, EXIT_NOINPUT, EXIT_USAGE, Format, GenerateArgs};

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
        Some(path) => {
            write_atomically(path, text.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
        }
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

/// Reads the input named by `--model` or `--zephyr`: the product and any warnings, or the
/// exit code and message to fail with.
fn load_product(args: &GenerateArgs) -> Result<(Product, Vec<Warning>), (u8, String)> {
    if let Some(dir) = &args.zephyr {
        let mut options = IngestOptions::new(dir).with_include_sdk(args.include_sdk);
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

/// Writes `bytes` to `path` without ever leaving a partly written file there: the bytes go to
/// a temporary file in the same directory, which is then renamed over `path`. On any error the
/// temporary file is removed and an existing `path` is left untouched.
///
/// An existing file keeps its permissions; a new one gets the same default as
/// `std::fs::write` (0o666 less the umask on Unix).
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut builder = tempfile::Builder::new();
    builder.prefix(".rollcall-").suffix(".tmp");
    let existing = std::fs::metadata(path).ok().filter(|m| m.is_file());
    let permissions = existing
        .map(|m| m.permissions())
        .or_else(default_permissions);
    if let Some(permissions) = &permissions {
        builder.permissions(permissions.clone());
    }
    let mut file = builder.tempfile_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(unix)]
fn default_permissions() -> Option<std::fs::Permissions> {
    use std::os::unix::fs::PermissionsExt;
    Some(std::fs::Permissions::from_mode(0o666))
}

#[cfg(not(unix))]
fn default_permissions() -> Option<std::fs::Permissions> {
    None
}
