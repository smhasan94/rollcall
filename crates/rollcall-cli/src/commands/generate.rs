//! `rollcall generate`: render a model as CycloneDX 1.6 JSON.

use std::io::Write;
use std::path::Path;

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
