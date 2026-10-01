//! Which identifier database is active: the embedded one, or a newer one picked up at run time
//! without a rollcall release.
//!
//! In order of precedence:
//!
//! 1. an explicit path (`--identifiers PATH`, or `generate --identifier-db FILE`);
//! 2. `$ROLLCALL_IDENTIFIERS`;
//!
//! (either may be the word `embedded`, which pins the embedded database and skips the cache);
//! 3. the newest compatible database in the cache directory that is newer than the embedded
//!    one: `<cache>/rollcall/identifiers/<db_version>/identifiers.yaml`, where `<cache>` is
//!    `$ROLLCALL_CACHE_DIR`, else `$XDG_CACHE_HOME` (if absolute), else `$HOME/.cache`
//!    (`%LOCALAPPDATA%` on Windows);
//! 4. the database embedded in rollcall (the `rollcall-identifiers` crate).
//!
//! A path may name the YAML file or a directory holding `identifiers.yaml` (an unpacked
//! release tarball or a checkout of `crates/rollcall-identifiers/db`).
//!
//! An explicit database (1 or 2) that declares a `db_version` this rollcall does not accept
//! ([`check_compatible`]) is an error; one that declares none (a user's own database built
//! from stub entries) is used as is. A cache entry is only used when it declares a compatible
//! `db_version` equal to its directory name, and (on Unix) only when neither the cache root,
//! the entry directory nor its file is writable by group or others, and no symlink leads
//! out of the root; any other version-named entry is skipped with a warning, so a stale or
//! broken cache never stops rollcall. Dotfiles and other names are ignored. Relative cache
//! variables are ignored. Nothing here touches the network.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use super::version::{DbVersion, Incompatible, check_compatible};
use super::{BUILTIN_NAME, IdentifierDb, LoadError, builtin, load};
use crate::cyclonedx::Property;

/// The environment variable naming an identifier database (precedence 2).
pub const ENV_IDENTIFIERS: &str = "ROLLCALL_IDENTIFIERS";
/// The value of `--identifiers` or `$ROLLCALL_IDENTIFIERS` that pins the embedded database
/// (no file is read and the cache is not consulted).
pub const EMBEDDED: &str = "embedded";
/// The environment variable naming rollcall's cache directory.
pub const ENV_CACHE_DIR: &str = "ROLLCALL_CACHE_DIR";

/// Where the active database came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbSource {
    /// Embedded in rollcall.
    Embedded,
    /// An explicit path on the command line; the file read.
    Flag(PathBuf),
    /// `$ROLLCALL_IDENTIFIERS`; the file read.
    Env(PathBuf),
    /// The cache directory; the file read.
    Cache(PathBuf),
}

impl DbSource {
    /// The kind of source, without its path: `embedded`, `flag`, `env` or `cache`. This is
    /// what an SBOM records ([`provenance`]), so the output does not depend on where files
    /// live.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Flag(_) => "flag",
            Self::Env(_) => "env",
            Self::Cache(_) => "cache",
        }
    }
}

/// `metadata.properties` name: the `db_version` of the database that resolved the modules, or
/// `unversioned`.
pub const PROP_DB_VERSION: &str = "rollcall:identifiers:db-version";
/// `metadata.properties` name: where that database came from ([`DbSource::kind`]).
pub const PROP_SOURCE: &str = "rollcall:identifiers:source";
/// Every provenance property name, in order.
pub const PROVENANCE_PROPERTIES: [&str; 2] = [PROP_DB_VERSION, PROP_SOURCE];

/// The document properties recording which database resolved the modules: its
/// `db_version` (or `unversioned`) and its source kind. No path, so output stays the same
/// wherever the database lives.
pub fn provenance(db: &IdentifierDb, source: &DbSource) -> Vec<Property> {
    vec![
        Property {
            name: PROP_DB_VERSION,
            value: db
                .db_version()
                .map_or_else(|| "unversioned".to_owned(), ToString::to_string),
        },
        Property {
            name: PROP_SOURCE,
            value: source.kind().to_owned(),
        },
    ]
}

impl fmt::Display for DbSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Embedded => f.write_str("embedded"),
            Self::Flag(path) => write!(f, "flag {}", path.display()),
            Self::Env(path) => write!(f, "{ENV_IDENTIFIERS} {}", path.display()),
            Self::Cache(path) => write!(f, "cache {}", path.display()),
        }
    }
}

/// The active database and the embedded one, loaded side by side.
#[derive(Debug, Clone)]
pub struct LoadedDbs {
    /// The database to resolve modules with.
    pub active: IdentifierDb,
    /// Where it came from.
    pub source: DbSource,
    /// The database embedded in rollcall (the same as `active` when `source` is
    /// [`DbSource::Embedded`]).
    pub embedded: IdentifierDb,
    /// Cache entries skipped, one line each (`<path>: skipped: <why>`), sorted by path.
    pub warnings: Vec<String>,
}

/// Why no database could be selected.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
    /// An explicit database is missing, unreadable or malformed.
    #[error("{0}")]
    Load(#[from] LoadError),
    /// An explicit database declares a `db_version` this rollcall does not accept.
    #[error("{}: {error}", path.display())]
    Incompatible {
        /// The file.
        path: PathBuf,
        /// Why.
        error: Incompatible,
    },
}

impl SourceError {
    /// True when the database could not be read (missing, unreadable): exit 66 rather than 65.
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Load(e) if e.is_read_error())
    }
}

/// The YAML file a database path names: the path itself, or `identifiers.yaml` inside it when
/// it is a directory.
pub fn db_file(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join(BUILTIN_NAME)
    } else {
        path.to_owned()
    }
}

/// Loads the database a path names ([`db_file`]).
pub fn load_path(path: &Path) -> Result<(IdentifierDb, PathBuf), LoadError> {
    let file = db_file(path);
    load(&file).map(|db| (db, file))
}

/// `<cache>/rollcall/identifiers`, from the environment `env`, or `None` when no variable
/// names a usable directory. `windows` selects `%LOCALAPPDATA%` instead of the XDG rules.
pub fn cache_root(env: &dyn Fn(&str) -> Option<OsString>, windows: bool) -> Option<PathBuf> {
    // Relative values are ignored, as the XDG base directory spec says for XDG_CACHE_HOME: a
    // cache that moves with the working directory is not a cache.
    let var = |name: &str| {
        env(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    let base = match var(ENV_CACHE_DIR) {
        Some(dir) => dir,
        None if windows => var("LOCALAPPDATA")?,
        None => match var("XDG_CACHE_HOME") {
            Some(dir) => dir,
            None => var("HOME")?.join(".cache"),
        },
    };
    Some(base.join("rollcall").join("identifiers"))
}

/// Why a path in the cache is not trusted: on Unix, writable by group or others (mode
/// `0o022`), since anyone who can write it could change the SBOMs rollcall produces.
#[cfg(unix)]
fn untrusted(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o022 != 0).then(|| {
        format!(
            "{} is writable by group or others (mode {:o})",
            path.display(),
            mode & 0o7777
        )
    })
}

#[cfg(not(unix))]
fn untrusted(_path: &Path) -> Option<String> {
    None
}

/// The newest usable database under the cache root `root` that is newer than `embedded`
/// (`None` if there is none), and a warning for every entry skipped for a reason other than
/// being the embedded version. A missing root is an empty cache.
///
/// Dotfiles, files and directories whose names are not versions are ignored silently. A
/// version-named entry is skipped with a warning when it is broken, outside the pin, older
/// than the embedded database, a symlink leading out of the root, or (on Unix) writable by
/// group or others; a root writable by group or others is not read at all.
pub fn scan_cache(
    root: &Path,
    embedded: Option<&DbVersion>,
) -> (Option<(IdentifierDb, PathBuf)>, Vec<String>) {
    let mut warnings = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return (None, warnings);
    };
    if let Some(why) = untrusted(root) {
        warnings.push(format!("{}: skipped: {why}", root.display()));
        return (None, warnings);
    }
    let real_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    let mut best: Option<(DbVersion, IdentifierDb, PathBuf)> = None;
    for dir in dirs {
        match cache_entry(&dir, &real_root, embedded) {
            Ok(Some((version, db, file))) => {
                if best.as_ref().is_none_or(|(v, _, _)| version > *v) {
                    best = Some((version, db, file));
                }
            }
            Ok(None) => {}
            Err(why) => warnings.push(format!("{}: skipped: {why}", dir.display())),
        }
    }
    (best.map(|(_, db, file)| (db, file)), warnings)
}

/// One cache entry: `Ok(Some)` when usable, `Ok(None)` when it is ignored (the embedded
/// version, or not a version-named directory), `Err(why)` otherwise.
#[allow(clippy::type_complexity)]
fn cache_entry(
    dir: &Path,
    real_root: &Path,
    embedded: Option<&DbVersion>,
) -> Result<Option<(DbVersion, IdentifierDb, PathBuf)>, String> {
    // Not a version: not ours (a README, a stray directory); say nothing.
    let Some(named) = dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.parse::<DbVersion>().ok())
    else {
        return Ok(None);
    };
    if !dir.is_dir() {
        return Ok(None);
    }
    let file = dir.join(BUILTIN_NAME);
    // Symlinks may only lead to somewhere inside the cache root.
    for path in [dir, file.as_path()] {
        let is_link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
        if is_link {
            let target =
                std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
            if !target.starts_with(real_root) {
                return Err(format!(
                    "{} is a symlink out of the cache root (to {})",
                    path.display(),
                    target.display()
                ));
            }
        }
    }
    for path in [dir, file.as_path()] {
        if let Some(why) = untrusted(path) {
            return Err(why);
        }
    }
    let db = load(&file).map_err(|e| e.to_string())?;
    let Some(version) = db.db_version().cloned() else {
        return Err(format!("{} declares no db_version", file.display()));
    };
    if version != named {
        return Err(format!(
            "{} declares db_version {version}, not {named}",
            file.display()
        ));
    }
    check_compatible(&version).map_err(|e| e.to_string())?;
    match embedded {
        Some(embedded) if version == *embedded => Ok(None),
        Some(embedded) if version < *embedded => Err(format!(
            "db_version {version} is older than the embedded {embedded}"
        )),
        _ => Ok(Some((version, db, file))),
    }
}

/// Selects the active database: `explicit` (a command-line path) if given, else
/// `$ROLLCALL_IDENTIFIERS`, else the newest newer-than-embedded cache entry, else the
/// embedded database. `env` reads environment variables (`std::env::var_os` in the binary).
pub fn select(
    explicit: Option<&Path>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<LoadedDbs, SourceError> {
    select_with(explicit, env, cfg!(windows))
}

fn select_with(
    explicit: Option<&Path>,
    env: &dyn Fn(&str) -> Option<OsString>,
    windows: bool,
) -> Result<LoadedDbs, SourceError> {
    let embedded = builtin()?;
    let from_env = env(ENV_IDENTIFIERS)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let chosen = match (explicit, from_env) {
        (Some(path), _) => Some((path.to_owned(), true)),
        (None, Some(path)) => Some((path, false)),
        (None, None) => None,
    };
    if let Some((path, is_flag)) = chosen {
        // `embedded` pins the embedded database: no file, no cache. (A file of that name is
        // `./embedded`.)
        if path.as_os_str() == EMBEDDED {
            return Ok(LoadedDbs {
                active: embedded.clone(),
                source: DbSource::Embedded,
                embedded,
                warnings: Vec::new(),
            });
        }
        let (db, file) = load_path(&path)?;
        if let Some(version) = db.db_version() {
            check_compatible(version).map_err(|error| SourceError::Incompatible {
                path: file.clone(),
                error,
            })?;
        }
        let source = if is_flag {
            DbSource::Flag(file)
        } else {
            DbSource::Env(file)
        };
        return Ok(LoadedDbs {
            active: db,
            source,
            embedded,
            warnings: Vec::new(),
        });
    }
    let (found, warnings) = match cache_root(env, windows) {
        Some(root) => scan_cache(&root, embedded.db_version()),
        None => (None, Vec::new()),
    };
    let (active, source) = match found {
        Some((db, file)) => (db, DbSource::Cache(file)),
        None => (embedded.clone(), DbSource::Embedded),
    };
    Ok(LoadedDbs {
        active,
        source,
        embedded,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    #[test]
    fn cache_root_follows_rollcall_then_xdg_then_home() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                vars.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let all = env(&[
            (ENV_CACHE_DIR, "/r"),
            ("XDG_CACHE_HOME", "/x"),
            ("HOME", "/h"),
            ("LOCALAPPDATA", "/l"),
        ]);
        let tail = Path::new("rollcall").join("identifiers");
        assert_eq!(cache_root(&all, false), Some(Path::new("/r").join(&tail)));
        assert_eq!(cache_root(&all, true), Some(Path::new("/r").join(&tail)));
        let xdg = env(&[
            ("XDG_CACHE_HOME", "/x"),
            ("HOME", "/h"),
            ("LOCALAPPDATA", "/l"),
        ]);
        assert_eq!(cache_root(&xdg, false), Some(Path::new("/x").join(&tail)));
        assert_eq!(cache_root(&xdg, true), Some(Path::new("/l").join(&tail)));
        // A relative XDG_CACHE_HOME is ignored (XDG base directory spec), as is an empty one.
        let rel = env(&[(ENV_CACHE_DIR, ""), ("XDG_CACHE_HOME", "x"), ("HOME", "/h")]);
        assert_eq!(
            cache_root(&rel, false),
            Some(Path::new("/h/.cache").join(&tail))
        );
        assert_eq!(cache_root(&no_env, false), None);
        assert_eq!(cache_root(&no_env, true), None);
    }

    #[test]
    fn without_any_source_the_embedded_database_is_active() {
        let loaded = select_with(None, &no_env, false).unwrap();
        assert_eq!(loaded.source, DbSource::Embedded);
        assert_eq!(loaded.active, loaded.embedded);
        assert!(loaded.warnings.is_empty());
        assert_eq!(
            loaded.embedded.db_version().map(ToString::to_string),
            Some(crate::identify::BUILTIN_DB_VERSION.to_owned())
        );
    }
}
