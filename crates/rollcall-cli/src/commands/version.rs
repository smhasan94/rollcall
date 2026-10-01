//! `rollcall --version`: the tool version, then the identifier databases loaded side by side.
//!
//! ```text
//! rollcall 0.0.1
//! identifiers 1.1.0 (cache /home/u/.cache/rollcall/identifiers/1.1.0/identifiers.yaml)
//! identifiers 1.0.0 (embedded, minimum 1.0.0)
//! ```
//!
//! The first line is unchanged from a plain clap version line. The active database comes
//! next when it is not the embedded one; the embedded database is always last, with the
//! minimum `db_version` this rollcall accepts. Skipped cache entries are warnings on stderr.

use std::io::Write;
use std::path::Path;

use rollcall_core::identify::{self, DbSource, IdentifierDb, LoadedDbs, MIN_DB_VERSION};

use crate::cli::{EXIT_DATAERR, EXIT_NOINPUT};

/// `identifiers <db_version> (<source>)`, or `unversioned` for a database without one.
fn db_line(db: &IdentifierDb, source: &str) -> String {
    match db.db_version() {
        Some(version) => format!("identifiers {version} ({source})"),
        None => format!("identifiers unversioned ({source})"),
    }
}

/// The version block for `loaded`.
pub fn render(loaded: &LoadedDbs) -> String {
    let mut out = format!("rollcall {}\n", env!("CARGO_PKG_VERSION"));
    if loaded.source != DbSource::Embedded {
        out.push_str(&db_line(&loaded.active, &loaded.source.to_string()));
        out.push('\n');
    }
    out.push_str(&db_line(
        &loaded.embedded,
        &format!("embedded, minimum {MIN_DB_VERSION}"),
    ));
    out.push('\n');
    out
}

/// Prints the version block, returning the exit code: 0, or 65/66 when the database named
/// by `--identifiers` or `$ROLLCALL_IDENTIFIERS` cannot be used (the tool version is still
/// printed first).
pub fn run(identifiers: Option<&Path>) -> u8 {
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    match identify::select(identifiers, &|name| std::env::var_os(name)) {
        Ok(loaded) => {
            for warning in &loaded.warnings {
                let _ = writeln!(stderr, "rollcall: warning: identifiers: {warning}");
            }
            let _ = stdout.write_all(render(&loaded).as_bytes());
            0
        }
        Err(e) => {
            let _ = writeln!(stdout, "rollcall {}", env!("CARGO_PKG_VERSION"));
            let _ = writeln!(stderr, "rollcall: identifiers: {e}");
            if e.is_read_error() {
                EXIT_NOINPUT
            } else {
                EXIT_DATAERR
            }
        }
    }
}
