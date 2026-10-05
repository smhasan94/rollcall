//! PlatformIO ingestion: a PlatformIO project after `pio run` (or `pio pkg install`) → the
//! component graph.
//!
//! [`ingest`] reads one environment of a project: its `platformio.ini`, the libraries
//! PlatformIO installed for it under `.pio/libdeps/<env>/`, and, from the PlatformIO core
//! directory when given ([`PlatformIoOptions::with_core_dir`]; the CLI's `--pio-core`, else
//! `$PLATFORMIO_CORE_DIR`), the installed platform and framework packages.
//! `docs/platformio.md` is the user guide.
//!
//! ```no_run
//! use rollcall_core::platformio::{self, PlatformIoOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let options = PlatformIoOptions::new("my-project")
//!     .with_env("esp32dev")
//!     .with_core_dir("/home/me/.platformio");
//! let ingest = platformio::ingest(&options)?;
//! for warning in &ingest.warnings {
//!     eprintln!("warning: {warning}");
//! }
//! println!("{}", ingest.product.to_json()?);
//! # Ok(())
//! # }
//! ```
//!
//! # Inputs
//!
//! Paths are relative to the project directory; `<env>` is the environment ingested and
//! `<core>` the core directory, cited as `pio-core/` whatever its real path.
//!
//! | Input | Required | Used for |
//! |-------|----------|----------|
//! | `platformio.ini` | yes | the environments, and the chosen one's `platform`, `framework`, `lib_deps` and `platform_packages` ([`ini`]: `[env]`, `extends` and `${section.option}` resolved) |
//! | `.pio/libdeps/<env>/<library>/.piopm` | no (a warning when `lib_deps` is set but nothing is installed) | each installed library's name, owner, version and source |
//! | `.pio/libdeps/<env>/<library>/library.json` | no | its version as published, repository, licence and dependencies |
//! | `<core>/platforms/<platform>/.piopm`, `platform.json` | no | the platform's installed version and licence, and which package each framework is |
//! | `<core>/packages/<framework package>/.piopm`, `package.json` | no | the framework package's installed version and licence |
//!
//! The environment is [`PlatformIoOptions::with_env`], else the one `default_envs` names,
//! else the project's only environment; otherwise [`PlatformIoError::EnvNotChosen`] lists
//! them. Without a core directory, the platform's and the framework's versions come from
//! exact pins in `platformio.ini` (`platform = espressif32 @ 6.10.0`, `platform_packages =
//! platformio/framework-arduinoespressif32 @ 3.20017.241212`); a range pins nothing, and
//! the version is then unknown (a warning).
//!
//! # Mapping
//!
//! | Input | Model |
//! |-------|-------|
//! | the project directory's name | the [`Product`] and its one `application` [`Image`], purl `pkg:generic/<name>` |
//! | each `framework` value | a `framework` component: for a package in rollcall's table ([`table`]), the upstream project (`arduino-esp32` 2.0.17 for `framework-arduinoespressif32` 3.20017.241212) with its purl, CPE (for an `X.Y.Z` release the table lists, never a decoded one), supplier and licence; otherwise the package itself, with its registry purl |
//! | `platform` | a `platform` component with CycloneDX `scope: excluded` (build tooling, not shipped): its version, registry purl and licence |
//! | each installed library | a `library` component named `<owner>/<name>` (as in `lib_deps`): version from `library.json` when it agrees with `.piopm`, else `.piopm`'s; purl per [`purl`]; licence from `library.json` |
//! | `lib_deps`, each `library.json` `dependencies` | edges: image → each framework and each `lib_deps` library; library → library; product → image |
//!
//! Evidence, located at the project-relative input (never an absolute path): `platformio-ini`
//! (the environment, each `lib_deps` entry and pin, with its line), `piopm` (installed names
//! and versions), `library-json` (versions, licences, and the upstream purl
//! `pkg:generic/<name>@<version>?vcs_url=git+<repository>`), `platform-json` and
//! `package-json` (versions and licences), `platformio-table` (a framework's upstream
//! version, purl and CPE).
//!
//! # Package URLs
//!
//! See [`purl`]: `pkg:generic/<owner>/<name>@<version>?repository_url=https://registry.platformio.org`
//! for a registry package; a framework in the table gets its upstream purl.
//!
//! # Warnings
//!
//! Non-fatal problems are [`Warning`]s, sorted and deduplicated: no library installed for the
//! environment; a `lib_deps` entry with no installed library (not installed, or a framework's
//! built-in library); a `library.json` dependency that is not installed; `.piopm` and
//! `library.json` disagreeing about a version; a library with no licence, or one that is not
//! an SPDX expression; an unreadable `library.json` `dependencies` entry (skipped); a library
//! installed from a local path (no purl: a host path is not an identifier); `[platformio]
//! core_dir`, `libdeps_dir` or `extra_configs` set (not followed); an `extends` naming no
//! section (skipped, as PlatformIO skips it); a
//! platform or framework whose version is unknown, or a framework package not in the table
//! (no upstream identifiers) or whose upstream version was decoded rather than checked; a
//! core directory without the platform or package; `${sysenv.…}`, a built-in or a SCons
//! variable left as written. A missing
//! `platformio.ini` is [`PlatformIoError::Read`]; a malformed input is a
//! [`PlatformIoError`] naming the file (and, for `platformio.ini`, the line).
//!
//! # Determinism
//!
//! The same inputs give the same [`Product`]: directories are read in name order, every
//! collection is sorted, and no absolute path, clock, environment variable or iteration order
//! reaches the output (the core directory is cited as `pio-core/`).

pub mod ini;
pub mod library_json;
pub mod package_json;
pub mod piopm;
pub mod purl;
pub mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use crate::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, IdError, Image,
    ImageKind, License, Occurrence, PathSegment, Product, Purl, Scope, Technique,
};
pub use crate::warning::Warning;
pub use ini::{IniError, PackageSpec, ProjectConfig};
pub use library_json::{LibraryJson, LibraryJsonError};
pub use package_json::{PackageJson, PackageJsonError};
pub use piopm::{Piopm, PiopmError};
pub use table::{PlatformIoTable, TableError};

/// The largest input file read: 16 MiB.
pub const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;
/// The project file.
pub const PROJECT_FILE: &str = "platformio.ini";
/// How evidence cites the core directory.
pub const CORE_LABEL: &str = "pio-core";

/// Evidence sources.
const INI: &str = "platformio-ini";
const PIOPM: &str = "piopm";
const LIBRARY_JSON: &str = "library-json";
const PLATFORM_JSON: &str = "platform-json";
const PACKAGE_JSON: &str = "package-json";
const TABLE: &str = "platformio-table";

/// One evidence fact: field, source, value, confidence, location and line.
type Fact<'a> = (EvidenceField, &'a str, String, u16, String, Option<u32>);

/// A fact from the PlatformIO table.
fn table_fact(field: EvidenceField, value: &str) -> Fact<'static> {
    (
        field,
        TABLE,
        value.to_owned(),
        TABLE_CONFIDENCE,
        table::BUILTIN_NAME.to_owned(),
        None,
    )
}

/// Confidences, in basis points.
const PIOPM_CONFIDENCE: u16 = 9500;
const MANIFEST_CONFIDENCE: u16 = 9000;
const INI_CONFIDENCE: u16 = 8000;
const TABLE_CONFIDENCE: u16 = 9000;
const UPSTREAM_CONFIDENCE: u16 = 7000;

/// What to ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIoOptions {
    /// The project directory (holding `platformio.ini`).
    pub project_dir: PathBuf,
    /// The environment, when not the default.
    pub env: Option<String>,
    /// The PlatformIO core directory, for the installed platform and framework packages.
    pub core_dir: Option<PathBuf>,
}

impl PlatformIoOptions {
    /// Options for the project in `project_dir`.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            env: None,
            core_dir: None,
        }
    }

    /// Ingests environment `env`.
    pub fn with_env(mut self, env: impl Into<String>) -> Self {
        self.env = Some(env.into());
        self
    }

    /// Reads the platform and framework packages from the core directory `core_dir`.
    pub fn with_core_dir(mut self, core_dir: impl Into<PathBuf>) -> Self {
        self.core_dir = Some(core_dir.into());
        self
    }
}

/// The result of [`ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIoIngest {
    /// The product.
    pub product: Product,
    /// The environment ingested.
    pub env: String,
    /// Non-fatal problems, sorted.
    pub warnings: Vec<Warning>,
}

/// Why a project could not be ingested. Every variant names its file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformIoError {
    /// A file or directory could not be read.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// A file is larger than [`MAX_INPUT_BYTES`].
    #[error("{}: larger than {MAX_INPUT_BYTES} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// A text input is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// `platformio.ini` is malformed.
    #[error("{}: {source}", path.display())]
    Ini {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: IniError,
    },
    /// A `library.json` is malformed.
    #[error("{}: {source}", path.display())]
    LibraryJson {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: LibraryJsonError,
    },
    /// A `.piopm` is malformed.
    #[error("{}: {source}", path.display())]
    Piopm {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: PiopmError,
    },
    /// A `platform.json` or `package.json` is malformed.
    #[error("{}: {source}", path.display())]
    PackageJson {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: PackageJsonError,
    },
    /// `platformio.ini` has no `[env:NAME]` section.
    #[error("{}: no [env:NAME] section", path.display())]
    NoEnvironments {
        /// The file.
        path: PathBuf,
    },
    /// The environment asked for (or named by `default_envs`) does not exist.
    #[error("{}: no environment {env:?} (environments: {})", path.display(), envs.join(", "))]
    UnknownEnv {
        /// The file.
        path: PathBuf,
        /// The environment asked for.
        env: String,
        /// The environments there are.
        envs: Vec<String>,
    },
    /// Several environments and no single default: one must be chosen.
    #[error("{}: {} environments and no single default_envs; choose one with --env: {}", path.display(), envs.len(), envs.join(", "))]
    EnvNotChosen {
        /// The file.
        path: PathBuf,
        /// The environments there are.
        envs: Vec<String>,
    },
    /// The built-in PlatformIO table is broken (a rollcall bug).
    #[error(transparent)]
    Table(#[from] TableError),
    /// A value is rejected by the model.
    #[error("{input}: {message}")]
    Model {
        /// The input the value came from.
        input: String,
        /// The model's objection.
        message: String,
    },
}

impl PlatformIoError {
    /// Whether this is a missing or unreadable input, rather than a malformed one.
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Read { .. })
    }

    /// Whether this is about the environment chosen (a usage error), rather than the input.
    pub fn is_usage_error(&self) -> bool {
        matches!(self, Self::UnknownEnv { .. } | Self::EnvNotChosen { .. })
    }
}

/// One installed library: its directory under `.pio/libdeps/<env>/`, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledLibrary {
    /// Its directory, relative to the project (`.pio/libdeps/esp32dev/ArduinoJson`).
    pub location: String,
    /// `.piopm`, if present.
    pub piopm: Option<Piopm>,
    /// `library.json`, if present.
    pub manifest: Option<LibraryJson>,
}

/// One package from the core directory, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePackage {
    /// Its directory as cited (`pio-core/platforms/espressif32`).
    pub location: String,
    /// `.piopm`, if present.
    pub piopm: Option<Piopm>,
    /// `platform.json` or `package.json`, if present.
    pub manifest: Option<PackageJson>,
}

impl CorePackage {
    /// The installed version: `.piopm`'s, else the manifest's.
    pub fn version(&self) -> Option<&str> {
        self.piopm
            .as_ref()
            .map(|p| p.version.as_str())
            .or_else(|| self.manifest.as_ref().map(|m| m.version.as_str()))
    }
}

/// The inputs, read and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIoProject {
    /// The project's name (its directory's).
    pub name: String,
    /// `platformio.ini`.
    pub config: ProjectConfig,
    /// The environment ingested.
    pub env: String,
    /// The installed libraries, in directory order.
    pub libraries: Vec<InstalledLibrary>,
    /// Whether `.pio/libdeps/<env>/` exists.
    pub libdeps_present: bool,
    /// The platform from the core directory, if found.
    pub platform: Option<CorePackage>,
    /// Framework packages from the core directory, by package name.
    pub packages: BTreeMap<String, CorePackage>,
    /// Problems found while loading.
    pub warnings: Vec<Warning>,
}

/// Reads `path` as UTF-8 text; `Ok(None)` when it does not exist and `optional`.
fn read_text(path: &Path, optional: bool) -> Result<Option<String>, PlatformIoError> {
    let read_err = |source| PlatformIoError::Read {
        path: path.to_owned(),
        source,
    };
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if optional && e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(read_err(e)),
    };
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(PlatformIoError::TooLarge {
            path: path.to_owned(),
        });
    }
    let bytes = std::fs::read(path).map_err(read_err)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| PlatformIoError::NotUtf8 {
            path: path.to_owned(),
        })
}

/// The names of the subdirectories of `dir`, sorted; empty when it does not exist.
fn subdirs(dir: &Path) -> Result<Vec<String>, PlatformIoError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(PlatformIoError::Read {
                path: dir.to_owned(),
                source,
            });
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| PlatformIoError::Read {
            path: dir.to_owned(),
            source,
        })?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

fn read_piopm(path: &Path) -> Result<Option<Piopm>, PlatformIoError> {
    match read_text(path, true)? {
        Some(text) => piopm::parse(&text)
            .map(Some)
            .map_err(|source| PlatformIoError::Piopm {
                path: path.to_owned(),
                source,
            }),
        None => Ok(None),
    }
}

fn read_package_json(path: &Path) -> Result<Option<PackageJson>, PlatformIoError> {
    match read_text(path, true)? {
        Some(text) => {
            package_json::parse(&text)
                .map(Some)
                .map_err(|source| PlatformIoError::PackageJson {
                    path: path.to_owned(),
                    source,
                })
        }
        None => Ok(None),
    }
}

/// Warnings for what resolving `key` left as written or skipped, located at their lines.
fn value_warnings(key: &str, found: &[(u32, String)], warnings: &mut Vec<Warning>) {
    for (line, message) in found {
        let location = if *line == 0 {
            PROJECT_FILE.to_owned()
        } else {
            format!("{PROJECT_FILE}:{line}")
        };
        warnings.push(Warning::new(location, format!("{key}: {message}")));
    }
}

/// The env option `key` as a list, with what it left as written reported.
fn env_list(
    config: &ProjectConfig,
    env: &str,
    key: &str,
    warnings: &mut Vec<Warning>,
) -> Result<Vec<ini::Item>, IniError> {
    let (items, found) = config.list(&format!("env:{env}"), key)?;
    value_warnings(key, &found, warnings);
    Ok(items)
}

/// The options rollcall reads whose values are checked for configparser's `%`-interpolation.
const PERCENT_CHECKED: [&str; 6] = [
    "default_envs",
    "extends",
    "framework",
    "lib_deps",
    "platform",
    "platform_packages",
];

/// `[platformio]` options that move inputs rollcall reads from their default places; rollcall
/// does not follow them, so each one set is a warning.
const UNFOLLOWED: [(&str, &str); 3] = [
    (
        "core_dir",
        "the core directory is read only from --pio-core or $PLATFORMIO_CORE_DIR",
    ),
    (
        "extra_configs",
        "the extra configuration files are not read; options they set are missed",
    ),
    (
        "libdeps_dir",
        "libraries are read only from .pio/libdeps/<env>/",
    ),
];

/// The environment to ingest (see the module docs).
fn choose_env(
    config: &ProjectConfig,
    asked: Option<&str>,
    path: &Path,
) -> Result<String, PlatformIoError> {
    let envs = config.envs();
    if envs.is_empty() {
        return Err(PlatformIoError::NoEnvironments {
            path: path.to_owned(),
        });
    }
    let unknown = |env: &str| PlatformIoError::UnknownEnv {
        path: path.to_owned(),
        env: env.to_owned(),
        envs: envs.clone(),
    };
    if let Some(env) = asked {
        return if envs.iter().any(|e| e == env) {
            Ok(env.to_owned())
        } else {
            Err(unknown(env))
        };
    }
    let defaults = config
        .default_envs()
        .map_err(|source| PlatformIoError::Ini {
            path: path.to_owned(),
            source,
        })?;
    match defaults.as_slice() {
        [one] if envs.contains(&one.text) => Ok(one.text.clone()),
        [one] => Err(unknown(&one.text)),
        [] if envs.len() == 1 => Ok(envs.into_iter().next().unwrap_or_default()),
        _ => Err(PlatformIoError::EnvNotChosen {
            path: path.to_owned(),
            envs,
        }),
    }
}

/// The platform's name and exact version pin from the `platform` option.
fn platform_spec(
    config: &ProjectConfig,
    env: &str,
) -> Result<Option<(PackageSpec, u32)>, IniError> {
    Ok(config
        .get(&format!("env:{env}"), "platform")?
        .map(|v| (ini::parse_spec(&v.text()), v.line)))
}

/// The core-directory package named `name` under `<core>/<kind>/`: the directory `name` or
/// `name@…`, chosen by `pin` when several are installed.
fn find_core_package(
    core: &Path,
    kind: &str,
    name: &str,
    manifest_file: &str,
    pin: Option<&str>,
    warnings: &mut Vec<Warning>,
) -> Result<Option<CorePackage>, PlatformIoError> {
    let dir = core.join(kind);
    let mut candidates = Vec::new();
    for sub in subdirs(&dir)? {
        if sub != name && !sub.starts_with(&format!("{name}@")) {
            continue;
        }
        let path = dir.join(&sub);
        let package = CorePackage {
            location: format!("{CORE_LABEL}/{kind}/{sub}"),
            piopm: read_piopm(&path.join(".piopm"))?,
            manifest: read_package_json(&path.join(manifest_file))?,
        };
        candidates.push(package);
    }
    let plain = |v: &str| v.split('+').next().unwrap_or(v).to_owned();
    let chosen = match pin {
        Some(pin) => candidates
            .into_iter()
            .find(|c| c.version().is_some_and(|v| plain(v) == plain(pin))),
        None if candidates.len() == 1 => candidates.into_iter().next(),
        None if candidates.is_empty() => None,
        None => {
            warnings.push(Warning::new(
                format!("{CORE_LABEL}/{kind}"),
                format!(
                    "{} versions of {name} are installed and platformio.ini pins none exactly; its version is not known",
                    candidates.len()
                ),
            ));
            return Ok(None);
        }
    };
    if chosen.is_none() {
        warnings.push(Warning::new(
            format!("{CORE_LABEL}/{kind}"),
            match pin {
                Some(pin) => format!("{name} {pin} is not installed in the core directory"),
                None => format!("{name} is not installed in the core directory"),
            },
        ));
    }
    Ok(chosen)
}

/// The `platform_packages` entry for `package`: its exact version pin, or source URL, and
/// line.
fn package_pin(items: &[ini::Item], package: &str) -> Option<(PackageSpec, u32)> {
    items.iter().find_map(|item| {
        let spec = ini::parse_spec(&item.text);
        let matches = match &spec {
            PackageSpec::Registry { name, .. } => name == package,
            PackageSpec::Vcs { name, .. }
            | PackageSpec::Archive { name, .. }
            | PackageSpec::Local { name, .. } => name.as_deref() == Some(package),
            PackageSpec::Unknown(_) => false,
        };
        matches.then_some((spec, item.line))
    })
}

fn exact_pin(spec: &PackageSpec) -> Option<String> {
    match spec {
        PackageSpec::Registry {
            requirement: Some(r),
            ..
        } => ini::exact_version(r),
        _ => None,
    }
}

/// The project's name: its directory's (resolved, so `.` works).
fn project_name(dir: &Path, warnings: &mut Vec<Warning>) -> String {
    let resolved = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_owned());
    match resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
    {
        Some(name) => name,
        None => {
            warnings.push(Warning::new(
                PROJECT_FILE,
                "the project directory has no name; the product is called platformio-project",
            ));
            "platformio-project".to_owned()
        }
    }
}

/// Reads every input (see the module docs), in a fixed order.
pub fn load(options: &PlatformIoOptions) -> Result<PlatformIoProject, PlatformIoError> {
    let project = &options.project_dir;
    let mut warnings = Vec::new();
    let ini_path = project.join(PROJECT_FILE);
    let text = read_text(&ini_path, false)?.unwrap_or_default();
    let ini_err = |source| PlatformIoError::Ini {
        path: ini_path.clone(),
        source,
    };
    let config = ini::parse(&text).map_err(ini_err)?;
    let env = choose_env(&config, options.env.as_deref(), &ini_path)?;
    let name = project_name(project, &mut warnings);

    // Installed libraries.
    let libdeps_rel = format!(".pio/libdeps/{env}");
    let libdeps = project.join(&libdeps_rel);
    let libdeps_present = libdeps.is_dir();
    let mut libraries = Vec::new();
    for sub in subdirs(&libdeps)? {
        let dir = libdeps.join(&sub);
        let piopm = read_piopm(&dir.join(".piopm"))?;
        let path = dir.join("library.json");
        let manifest = match read_text(&path, true)? {
            Some(text) => Some(
                library_json::parse(&text)
                    .map_err(|source| PlatformIoError::LibraryJson { path, source })?,
            ),
            None => None,
        };
        if piopm.is_none() && manifest.is_none() {
            continue;
        }
        libraries.push(InstalledLibrary {
            location: format!("{libdeps_rel}/{sub}"),
            piopm,
            manifest,
        });
    }

    // The platform and framework packages from the core directory.
    let mut platform = None;
    let mut packages = BTreeMap::new();
    if let Some(core) = &options.core_dir {
        let spec = platform_spec(&config, &env).map_err(ini_err)?;
        if let Some((spec @ PackageSpec::Registry { .. }, _)) = &spec
            && let PackageSpec::Registry { name, .. } = spec
        {
            platform = find_core_package(
                core,
                "platforms",
                name,
                "platform.json",
                exact_pin(spec).as_deref(),
                &mut warnings,
            )?;
        }
        let platform_name = match &spec {
            Some((PackageSpec::Registry { name, .. }, _)) => name.clone(),
            _ => String::new(),
        };
        let mut scratch = Vec::new();
        let frameworks = env_list(&config, &env, "framework", &mut scratch).map_err(ini_err)?;
        let pins = env_list(&config, &env, "platform_packages", &mut scratch).map_err(ini_err)?;
        let table = table::builtin()?;
        for framework in frameworks {
            let package = platform
                .as_ref()
                .and_then(|p| p.manifest.as_ref())
                .and_then(|m| m.frameworks.get(&framework.text).cloned())
                .or_else(|| {
                    table
                        .by_framework(&framework.text, &platform_name)
                        .map(|f| f.package.clone())
                });
            let Some(package) = package else {
                continue;
            };
            let pin = package_pin(&pins, &package).and_then(|(spec, _)| exact_pin(&spec));
            if let Some(found) = find_core_package(
                core,
                "packages",
                &package,
                "package.json",
                pin.as_deref(),
                &mut warnings,
            )? {
                packages.insert(package, found);
            }
        }
    }

    Ok(PlatformIoProject {
        name,
        config,
        env,
        libraries,
        libdeps_present,
        platform,
        packages,
        warnings,
    })
}

/// Reads the inputs and maps them into a product (see the module docs).
pub fn ingest(options: &PlatformIoOptions) -> Result<PlatformIoIngest, PlatformIoError> {
    let project = load(options)?;
    let table = table::builtin()?;
    map(&project, &table)
}

/// Builds evidence with a located occurrence.
fn evidence(
    field: EvidenceField,
    source: &str,
    value: &str,
    bp: u16,
    location: &str,
    line: Option<u32>,
) -> Result<Evidence, IdError> {
    Ok(Evidence::new(
        field,
        Technique::ManifestAnalysis,
        source,
        value,
        Confidence::new(bp)?,
    )?
    .at(Occurrence::new(location, line)?))
}

/// Whether `version` is a plain `X.Y.Z` release (a CPE is only emitted for one).
fn is_release(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `version` as semver for comparison: `2.8` → `2.8.0`.
fn padded(version: &str) -> String {
    let plain = version.split('+').next().unwrap_or(version);
    let dots = plain.matches('.').count();
    match dots {
        0 => format!("{plain}.0.0"),
        1 => format!("{plain}.0"),
        _ => plain.to_owned(),
    }
}

/// The last path segment of a repository URL, without `.git` and any `#ref`.
fn repo_name(url: &str) -> Option<String> {
    let base = url.split(['#', '?']).next().unwrap_or(url);
    let last = base.trim_end_matches('/').rsplit(['/', ':']).next()?;
    let name = last.strip_suffix(".git").unwrap_or(last);
    (!name.is_empty()).then(|| name.to_lowercase())
}

struct Mapper<'a> {
    project: &'a PlatformIoProject,
    table: &'a PlatformIoTable,
    warnings: Vec<Warning>,
}

impl Mapper<'_> {
    fn model_err(&self, input: &str, e: impl std::fmt::Display) -> PlatformIoError {
        PlatformIoError::Model {
            input: input.to_owned(),
            message: e.to_string(),
        }
    }

    fn warn(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(Warning::new(location, message));
    }

    /// Evidence for a component, located.
    fn ev(
        &self,
        field: EvidenceField,
        source: &str,
        value: &str,
        bp: u16,
        location: &str,
        line: Option<u32>,
    ) -> Result<Evidence, PlatformIoError> {
        evidence(field, source, value, bp, location, line).map_err(|e| self.model_err(location, e))
    }

    fn ini_err(&self, source: IniError) -> PlatformIoError {
        PlatformIoError::Ini {
            path: PathBuf::from(PROJECT_FILE),
            source,
        }
    }

    fn licence(
        &mut self,
        c: &mut Component,
        raw: &str,
        source: &str,
        location: &str,
    ) -> Result<(), PlatformIoError> {
        c.evidence.insert(self.ev(
            EvidenceField::Licence,
            source,
            raw,
            MANIFEST_CONFIDENCE,
            location,
            None,
        )?);
        match License::new(raw.trim()) {
            Ok(l) => c.licence = Some(l),
            Err(_) => self.warn(
                location,
                format!(
                    "{}: license {raw:?} is not an SPDX expression; licence omitted",
                    c.name
                ),
            ),
        }
        Ok(())
    }

    /// The `platform` component.
    fn platform(&mut self) -> Result<Option<Component>, PlatformIoError> {
        let p = self.project;
        let Some((spec, line)) = platform_spec(&p.config, &p.env).map_err(|e| self.ini_err(e))?
        else {
            self.warn(PROJECT_FILE, format!("[env:{}] sets no platform", p.env));
            return Ok(None);
        };
        let (name, owner, source_url) = match &spec {
            PackageSpec::Registry { owner, name, .. } => (name.clone(), owner.clone(), None),
            PackageSpec::Vcs { name, url } | PackageSpec::Archive { name, url } => (
                name.clone()
                    .or_else(|| repo_name(url))
                    .unwrap_or_else(|| "platform".to_owned()),
                None,
                Some(url.clone()),
            ),
            PackageSpec::Local { name, path } => (
                name.clone()
                    .or_else(|| repo_name(path))
                    .unwrap_or_else(|| "platform".to_owned()),
                None,
                None,
            ),
            PackageSpec::Unknown(raw) => {
                self.warn(
                    format!("{PROJECT_FILE}:{line}"),
                    format!(
                        "platform {raw:?} is not a package specification; no platform component"
                    ),
                );
                return Ok(None);
            }
        };
        let mut c = Component::new(ComponentKind::Platform, &name)
            .map_err(|e| self.model_err(PROJECT_FILE, e))?;
        c.scope = Some(Scope::Excluded);
        // A local path is the build machine's: cite the platform's name instead.
        let cited = match &spec {
            PackageSpec::Local { .. } => format!("local:{name}"),
            _ => spec.to_string(),
        };
        c.evidence.insert(self.ev(
            EvidenceField::Name,
            INI,
            &cited,
            INI_CONFIDENCE,
            PROJECT_FILE,
            Some(line),
        )?);
        let core = p.platform.clone();
        let mut owner = owner;
        if let Some(core) = &core {
            if let Some(piopm) = &core.piopm {
                let loc = format!("{}/.piopm", core.location);
                c.evidence.insert(self.ev(
                    EvidenceField::Version,
                    PIOPM,
                    &piopm.version,
                    PIOPM_CONFIDENCE,
                    &loc,
                    None,
                )?);
                owner = owner.or_else(|| piopm.owner.clone());
            }
            if let Some(m) = &core.manifest {
                let loc = format!("{}/platform.json", core.location);
                c.evidence.insert(self.ev(
                    EvidenceField::Version,
                    PLATFORM_JSON,
                    &m.version,
                    MANIFEST_CONFIDENCE,
                    &loc,
                    None,
                )?);
                if let Some(raw) = &m.license {
                    self.licence(&mut c, raw, PLATFORM_JSON, &loc)?;
                }
            }
            c.version = core.version().map(str::to_owned);
        }
        if c.version.is_none() {
            match exact_pin(&spec) {
                Some(v) => {
                    c.evidence.insert(self.ev(
                        EvidenceField::Version,
                        INI,
                        &v,
                        INI_CONFIDENCE,
                        PROJECT_FILE,
                        Some(line),
                    )?);
                    c.version = Some(v);
                }
                None => self.warn(
                    format!("{PROJECT_FILE}:{line}"),
                    format!(
                        "platform {name}: version unknown (no core directory with it, and no exact pin such as {name} @ 6.10.0)"
                    ),
                ),
            }
        }
        c.purl = match (&source_url, &spec) {
            (Some(url), _) => match purl::source_purl(&name, c.version.as_deref(), url) {
                Ok(p) => Some(p),
                Err(why) => {
                    self.warn(
                        format!("{PROJECT_FILE}:{line}"),
                        format!("platform {name}: {}; no purl", purl::no_purl_reason(&why)),
                    );
                    None
                }
            },
            (None, PackageSpec::Registry { .. }) => purl::registry_purl(
                owner.as_deref().unwrap_or("platformio"),
                &name,
                c.version.as_deref(),
                &self.table.registry,
            )
            .ok(),
            _ => None,
        };
        Ok(Some(c))
    }

    /// One `framework` component.
    fn framework(
        &mut self,
        framework: &ini::Item,
        platform_name: &str,
        pins: &[ini::Item],
    ) -> Result<Component, PlatformIoError> {
        let p = self.project;
        let table = self.table;
        let location = format!("{PROJECT_FILE}:{}", framework.line);
        let package = p
            .platform
            .as_ref()
            .and_then(|c| c.manifest.as_ref())
            .and_then(|m| m.frameworks.get(&framework.text).cloned())
            .or_else(|| {
                table
                    .by_framework(&framework.text, platform_name)
                    .map(|f| f.package.clone())
            });
        let entry = package.as_deref().and_then(|pkg| table.by_package(pkg));
        let core = package.as_deref().and_then(|pkg| p.packages.get(pkg));
        let pin = package.as_deref().and_then(|pkg| package_pin(pins, pkg));

        // The package's own version and evidence.
        let mut facts: Vec<Fact<'_>> = vec![(
            EvidenceField::Name,
            INI,
            format!("framework:{}", framework.text),
            INI_CONFIDENCE,
            PROJECT_FILE.to_owned(),
            Some(framework.line),
        )];
        let mut package_version = None;
        let mut owner = None;
        let mut package_licence = None;
        if let Some(core) = core {
            if let Some(piopm) = &core.piopm {
                facts.push((
                    EvidenceField::Version,
                    PIOPM,
                    piopm.version.clone(),
                    PIOPM_CONFIDENCE,
                    format!("{}/.piopm", core.location),
                    None,
                ));
                owner = piopm.owner.clone();
            }
            if let Some(m) = &core.manifest {
                let loc = format!("{}/package.json", core.location);
                facts.push((
                    EvidenceField::Version,
                    PACKAGE_JSON,
                    m.version.clone(),
                    MANIFEST_CONFIDENCE,
                    loc.clone(),
                    None,
                ));
                package_licence = m.license.clone().map(|l| (l, loc));
            }
            package_version = core.version().map(str::to_owned);
        }
        if package_version.is_none()
            && let Some((spec, line)) = &pin
            && let Some(v) = exact_pin(spec)
        {
            facts.push((
                EvidenceField::Version,
                INI,
                v.clone(),
                INI_CONFIDENCE,
                PROJECT_FILE.to_owned(),
                Some(*line),
            ));
            package_version = Some(v);
            if let PackageSpec::Registry { owner: o, .. } = spec {
                owner = owner.or_else(|| o.clone());
            }
        }

        let mut c;
        match (entry, &package) {
            (Some(entry), _) => {
                c = Component::new(ComponentKind::Framework, &entry.name)
                    .map_err(|e| self.model_err(&location, e))?;
                c.supplier = Some(entry.supplier.clone());
                c.licence = Some(entry.licence.clone());
                let upstream = package_version
                    .as_deref()
                    .and_then(|v| entry.upstream_version(v).map(|u| (v, u)));
                match upstream {
                    Some((pv, (upstream, source))) => {
                        if source == table::VersionSource::Decoded {
                            self.warn(
                                location.clone(),
                                format!(
                                    "{} {pv}: not in rollcall's PlatformIO table; {} {upstream} was decoded from the package version",
                                    entry.package, entry.name
                                ),
                            );
                        }
                        let filled = table::fill(&entry.purl, &upstream);
                        match Purl::new(&filled) {
                            Ok(purl) => {
                                facts.push(table_fact(EvidenceField::Purl, purl.as_str()));
                                c.purl = Some(purl);
                            }
                            Err(e) => {
                                self.warn(location.clone(), format!("{}: no purl ({e})", entry.name));
                            }
                        }
                        // A CPE only for a release checked by hand, never a decoded one.
                        if let Some(template) = &entry.cpe
                            && source == table::VersionSource::Table
                            && is_release(&upstream)
                            && let Ok(cpe) = Cpe::new(&table::fill(template, &upstream))
                        {
                            facts.push(table_fact(EvidenceField::Cpe, cpe.as_str()));
                            c.cpe = Some(cpe);
                        }
                        facts.push(table_fact(EvidenceField::Version, &upstream));
                        c.version = Some(upstream);
                    }
                    None => self.warn(
                        location.clone(),
                        format!(
                            "framework {}: the version of {} is unknown (give the core directory, or pin it exactly in platform_packages); {} has no version, purl or CPE",
                            framework.text, entry.package, entry.name
                        ),
                    ),
                }
            }
            (None, Some(package)) => {
                c = Component::new(ComponentKind::Framework, package)
                    .map_err(|e| self.model_err(&location, e))?;
                c.version = package_version.clone();
                self.warn(
                    location.clone(),
                    format!("framework package {package} is not in rollcall's PlatformIO table; it has no upstream purl or CPE"),
                );
                c.purl = purl::registry_purl(
                    owner.as_deref().unwrap_or("platformio"),
                    package,
                    package_version.as_deref(),
                    &table.registry,
                )
                .ok();
                if let Some((raw, loc)) = &package_licence {
                    self.licence(&mut c, raw, PACKAGE_JSON, loc)?;
                }
            }
            (None, None) => {
                c = Component::new(ComponentKind::Framework, &framework.text)
                    .map_err(|e| self.model_err(&location, e))?;
                self.warn(
                    location.clone(),
                    format!(
                        "framework {}: its package is not known for platform {platform_name:?} (no core directory, and not in rollcall's table); no version or identifiers",
                        framework.text
                    ),
                );
            }
        }
        // The package's licence is evidence even where the table's is used.
        if entry.is_some()
            && let Some((raw, loc)) = &package_licence
        {
            facts.push((
                EvidenceField::Licence,
                PACKAGE_JSON,
                raw.clone(),
                MANIFEST_CONFIDENCE,
                loc.clone(),
                None,
            ));
        }
        for (field, source, value, bp, loc, line) in facts {
            c.evidence
                .insert(self.ev(field, source, &value, bp, &loc, line)?);
        }
        Ok(c)
    }

    /// One installed library's component, and its key for matching.
    fn library(&mut self, lib: &InstalledLibrary) -> Result<Component, PlatformIoError> {
        let piopm_loc = format!("{}/.piopm", lib.location);
        let manifest_loc = format!("{}/library.json", lib.location);
        let dir_name = lib.location.rsplit('/').next().unwrap_or(&lib.location);
        let name = lib
            .piopm
            .as_ref()
            .map(|p| p.name.clone())
            .or_else(|| lib.manifest.as_ref().and_then(|m| m.name.clone()))
            .unwrap_or_else(|| dir_name.to_owned());
        let owner = lib.piopm.as_ref().and_then(|p| p.owner.clone());
        let full = match &owner {
            Some(o) => format!("{o}/{name}"),
            None => name.clone(),
        };
        let mut c = Component::new(ComponentKind::Library, &full)
            .map_err(|e| self.model_err(&lib.location, e))?;
        let installed = lib.piopm.as_ref().map(|p| p.version.clone());
        let published = lib.manifest.as_ref().and_then(|m| m.version.clone());
        c.version = match (&installed, &published) {
            (Some(i), Some(p)) if padded(i) == padded(p) => Some(p.clone()),
            (Some(i), Some(p)) => {
                self.warn(
                    manifest_loc.clone(),
                    format!("{full}: library.json says version {p}, .piopm {i}; {i} is used"),
                );
                Some(i.clone())
            }
            (Some(v), None) | (None, Some(v)) => Some(v.clone()),
            (None, None) => None,
        };
        if let Some(piopm) = &lib.piopm {
            c.evidence.insert(self.ev(
                EvidenceField::Name,
                PIOPM,
                &full,
                PIOPM_CONFIDENCE,
                &piopm_loc,
                None,
            )?);
            c.evidence.insert(self.ev(
                EvidenceField::Version,
                PIOPM,
                &piopm.version,
                PIOPM_CONFIDENCE,
                &piopm_loc,
                None,
            )?);
        }
        let uri = lib.piopm.as_ref().and_then(|p| p.uri.clone());
        let mut warned = false;
        c.purl = match (&owner, &uri) {
            (_, Some(uri)) => match purl::source_purl(&name, c.version.as_deref(), uri) {
                Ok(p) => Some(p),
                Err(why) => {
                    self.warn(
                        piopm_loc.clone(),
                        format!("{full}: {}; no purl", purl::no_purl_reason(&why)),
                    );
                    warned = true;
                    None
                }
            },
            (Some(owner), None) => {
                purl::registry_purl(owner, &name, c.version.as_deref(), &self.table.registry).ok()
            }
            (None, None) => None,
        };
        if c.purl.is_none() && !warned {
            self.warn(
                lib.location.clone(),
                format!("{full}: no registry owner or source URL in .piopm; no purl"),
            );
        }
        if let Some(m) = &lib.manifest {
            for w in &m.warnings {
                self.warn(manifest_loc.clone(), format!("{full}: {w}"));
            }
            if let Some(v) = &m.version {
                c.evidence.insert(self.ev(
                    EvidenceField::Version,
                    LIBRARY_JSON,
                    v,
                    MANIFEST_CONFIDENCE,
                    &manifest_loc,
                    None,
                )?);
            }
            if let Some(raw) = &m.license {
                self.licence(&mut c, raw, LIBRARY_JSON, &manifest_loc)?;
            }
            if let (Some(repo), Some(version)) = (&m.repository, &c.version)
                && let Some(upstream) = purl::upstream_purl(&name, version, repo)
            {
                c.evidence.insert(self.ev(
                    EvidenceField::Purl,
                    LIBRARY_JSON,
                    upstream.as_str(),
                    UPSTREAM_CONFIDENCE,
                    &manifest_loc,
                    None,
                )?);
            }
        }
        if c.licence.is_none() {
            match &lib.manifest {
                Some(m) if m.license.is_none() => self.warn(
                    manifest_loc.clone(),
                    format!("{full}: no license in library.json; the component has no licence"),
                ),
                Some(_) => {}
                None => self.warn(
                    lib.location.clone(),
                    format!("{full}: no library.json; the component has no licence"),
                ),
            }
        }
        Ok(c)
    }
}

/// The installed library a `lib_deps` (or `library.json` dependency) entry names, by index.
/// A source entry (a URL or a local path, spelt as any of `sources`) is matched against each
/// library's `.piopm` `spec.uri`: the identical string first, across every library, then
/// ignoring a `git+` prefix, a trailing `/` and case; only then by name (and owner).
fn match_library(
    libraries: &[InstalledLibrary],
    owner: Option<&str>,
    name: Option<&str>,
    sources: &[String],
) -> Option<usize> {
    let lower = |s: &str| s.to_lowercase();
    let uri = |lib: &InstalledLibrary| lib.piopm.as_ref().and_then(|p| p.uri.clone());
    let normal = |u: &str| {
        u.trim()
            .trim_start_matches("git+")
            .trim_end_matches('/')
            .to_lowercase()
    };
    if let Some(i) = libraries
        .iter()
        .position(|lib| uri(lib).is_some_and(|u| sources.iter().any(|s| s.trim() == u.trim())))
    {
        return Some(i);
    }
    if let Some(i) = libraries
        .iter()
        .position(|lib| uri(lib).is_some_and(|u| sources.iter().any(|s| normal(s) == normal(&u))))
    {
        return Some(i);
    }
    let name = name?;
    libraries.iter().position(|lib| {
        let piopm = lib.piopm.as_ref();
        let lib_name = piopm
            .map(|p| p.name.clone())
            .or_else(|| lib.manifest.as_ref().and_then(|m| m.name.clone()))
            .unwrap_or_default();
        if lower(&lib_name) != lower(name) {
            return false;
        }
        match owner {
            Some(owner) => piopm
                .and_then(|p| p.owner.as_deref())
                .is_none_or(|o| lower(o) == lower(owner)),
            None => true,
        }
    })
}

/// The spellings a source `lib_deps` entry's `.piopm` `spec.uri` may have: the entry as
/// written (without a `name=` or `name @ ` prefix), its URL, and a local path with and without
/// its `file://` or `symlink://` scheme.
fn source_spellings(raw: &str, spec: &PackageSpec) -> Vec<String> {
    let mut out = vec![raw.trim().to_owned()];
    if let Some((_, rest)) = raw.split_once('=') {
        out.push(rest.trim().to_owned());
    }
    if let Some((_, rest)) = raw.split_once('@') {
        out.push(rest.trim().to_owned());
    }
    match spec {
        PackageSpec::Vcs { url, .. } | PackageSpec::Archive { url, .. } => out.push(url.clone()),
        PackageSpec::Local { path, .. } => {
            out.push(path.clone());
            out.push(format!("file://{path}"));
            out.push(format!("symlink://{path}"));
        }
        PackageSpec::Registry { .. } | PackageSpec::Unknown(_) => {}
    }
    out.retain(|s| !s.is_empty());
    out
}

/// Maps loaded inputs to a product (no I/O).
pub fn map(
    project: &PlatformIoProject,
    table: &PlatformIoTable,
) -> Result<PlatformIoIngest, PlatformIoError> {
    let mut m = Mapper {
        project,
        table,
        warnings: project.warnings.clone(),
    };
    let env_section = format!("env:{}", project.env);
    let env_line = project.config.sections.get(&env_section).map(|s| s.line);

    // The product and its application image.
    let product = Product::new(&project.name).map_err(|e| m.model_err(PROJECT_FILE, e))?;
    let mut image = Image::new(ImageKind::Application, &project.name)
        .map_err(|e| m.model_err(PROJECT_FILE, e))?;
    let app_purl = packageurl::PackageUrl::new("generic", project.name.as_str())
        .map_err(|e| m.model_err(PROJECT_FILE, e))
        .and_then(|p| Purl::new(&p.to_string()).map_err(|e| m.model_err(PROJECT_FILE, e)))?;
    image.purl = Some(app_purl);
    for (value, line) in [
        (project.name.clone(), None),
        (format!("env:{}", project.env), env_line),
    ] {
        image.evidence.insert(
            evidence(
                EvidenceField::Name,
                INI,
                &value,
                INI_CONFIDENCE,
                PROJECT_FILE,
                line,
            )
            .map_err(|e| m.model_err(PROJECT_FILE, e))?,
        );
    }

    let config = &project.config;
    let mut scratch = Vec::new();
    let frameworks =
        env_list(config, &project.env, "framework", &mut scratch).map_err(|e| m.ini_err(e))?;
    let pins = env_list(config, &project.env, "platform_packages", &mut scratch)
        .map_err(|e| m.ini_err(e))?;
    let lib_deps =
        env_list(config, &project.env, "lib_deps", &mut scratch).map_err(|e| m.ini_err(e))?;
    if let Some(value) = config
        .get(&env_section, "platform")
        .map_err(|e| m.ini_err(e))?
    {
        value_warnings("platform", &value.warnings, &mut scratch);
    }
    // configparser features rollcall does not model (see the `ini` module docs).
    if let Some(section) = config.sections.get("DEFAULT") {
        scratch.push(Warning::new(
            format!("{PROJECT_FILE}:{}", section.line),
            "[DEFAULT] is configparser's defaults section: PlatformIO applies its options to every section, but rollcall does not; options set only there are missed",
        ));
    }
    for section in config.sections.values() {
        for (key, opt) in &section.options {
            if !PERCENT_CHECKED.contains(&key.as_str()) {
                continue;
            }
            for (text, line) in &opt.lines {
                if text.contains('%') {
                    scratch.push(Warning::new(
                        format!("{PROJECT_FILE}:{line}"),
                        format!(
                            "{key} contains %: configparser's %-interpolation (%%, %(name)s), which PlatformIO applies, is not applied by rollcall; read as written"
                        ),
                    ));
                }
            }
        }
    }
    if let Some(section) = config.sections.get("platformio") {
        for (key, why) in UNFOLLOWED {
            if let Some(opt) = section.options.get(key) {
                scratch.push(Warning::new(
                    format!("{PROJECT_FILE}:{}", opt.line),
                    format!("[platformio] {key} is set, but rollcall does not follow it: {why}"),
                ));
            }
        }
    }
    m.warnings.extend(scratch);

    // The platform and the frameworks.
    let platform = m.platform()?;
    let platform_name = match platform_spec(config, &project.env).map_err(|e| m.ini_err(e))? {
        Some((PackageSpec::Registry { name, .. }, _)) => name,
        _ => String::new(),
    };
    let mut framework_components = Vec::new();
    for framework in &frameworks {
        framework_components.push(m.framework(framework, &platform_name, &pins)?);
    }

    // The libraries.
    let mut libraries = Vec::with_capacity(project.libraries.len());
    for lib in &project.libraries {
        libraries.push(m.library(lib)?);
    }
    if !project.libdeps_present && !lib_deps.is_empty() {
        m.warn(
            format!(".pio/libdeps/{}", project.env),
            format!(
                "no library is installed for environment {}: run `pio pkg install -e {}` (or `pio run`) first",
                project.env, project.env
            ),
        );
    }

    // lib_deps → installed libraries.
    let mut direct: BTreeSet<usize> = BTreeSet::new();
    for item in &lib_deps {
        let spec = ini::parse_spec(&item.text);
        let found = match &spec {
            PackageSpec::Registry { owner, name, .. } => {
                match_library(&project.libraries, owner.as_deref(), Some(name), &[])
            }
            PackageSpec::Vcs { name, url } | PackageSpec::Archive { name, url } => {
                let derived = name.clone().or_else(|| repo_name(url));
                let sources = source_spellings(&item.text, &spec);
                match_library(&project.libraries, None, derived.as_deref(), &sources)
            }
            PackageSpec::Local { name, path } => {
                let derived = name.clone().or_else(|| repo_name(path));
                let sources = source_spellings(&item.text, &spec);
                match_library(&project.libraries, None, derived.as_deref(), &sources)
            }
            PackageSpec::Unknown(_) => None,
        };
        match found {
            Some(i) => {
                direct.insert(i);
                if let Some(c) = libraries.get_mut(i) {
                    // A local path is the build machine's: cite the library's name instead.
                    let value = match &spec {
                        PackageSpec::Local { .. } => format!("local:{}", c.name),
                        _ => spec.to_string(),
                    };
                    let fact = evidence(
                        EvidenceField::Name,
                        INI,
                        &value,
                        INI_CONFIDENCE,
                        PROJECT_FILE,
                        Some(item.line),
                    )
                    .map_err(|e| m.model_err(PROJECT_FILE, e))?;
                    c.evidence.insert(fact);
                }
            }
            None if project.libdeps_present => m.warn(
                format!("{PROJECT_FILE}:{}", item.line),
                format!(
                    "lib_deps {} is not installed under .pio/libdeps/{} (a framework's built-in library, or not yet installed); not listed",
                    item.text, project.env
                ),
            ),
            None => {}
        }
    }

    // Edges.
    let product_path = product.path();
    let image_path = product_path.child(PathSegment::of_image(&image));
    let image_ref = BomRef::derive(&image_path);
    let lib_refs: Vec<BomRef> = libraries
        .iter()
        .map(|c| BomRef::derive(&image_path.child(PathSegment::of_component(c))))
        .collect();
    let mut edges: BTreeSet<(BomRef, BomRef)> = BTreeSet::new();
    edges.insert((BomRef::derive(&product_path), image_ref.clone()));
    for c in &framework_components {
        edges.insert((
            image_ref.clone(),
            BomRef::derive(&image_path.child(PathSegment::of_component(c))),
        ));
    }
    for i in &direct {
        if let Some(to) = lib_refs.get(*i) {
            edges.insert((image_ref.clone(), to.clone()));
        }
    }
    for (i, lib) in project.libraries.iter().enumerate() {
        let Some(manifest) = &lib.manifest else {
            continue;
        };
        let (Some(from), Some(from_c)) = (lib_refs.get(i), libraries.get(i)) else {
            continue;
        };
        for dep in &manifest.dependencies {
            match match_library(
                &project.libraries,
                dep.owner.as_deref(),
                Some(&dep.name),
                &[],
            ) {
                Some(j) if j != i => {
                    if let Some(to) = lib_refs.get(j) {
                        edges.insert((from.clone(), to.clone()));
                    }
                }
                Some(_) => {}
                None => m.warn(
                    format!("{}/library.json", lib.location),
                    format!(
                        "{} depends on {}, which is not installed; no edge to it",
                        from_c.name, dep.name
                    ),
                ),
            }
        }
    }

    let mut product = product;
    if let Some(platform) = platform {
        image
            .add_component(platform)
            .map_err(|e| m.model_err(PROJECT_FILE, e))?;
    }
    for c in framework_components {
        image
            .add_component(c)
            .map_err(|e| m.model_err(PROJECT_FILE, e))?;
    }
    for c in libraries {
        image
            .add_component(c)
            .map_err(|e| m.model_err(PROJECT_FILE, e))?;
    }
    product
        .add_image(image)
        .map_err(|e| m.model_err(PROJECT_FILE, e))?;
    for (from, to) in edges {
        if from != to {
            product.add_dependency(from, to);
        }
    }
    product
        .validate()
        .map_err(|e| m.model_err(PROJECT_FILE, e))?;

    let mut warnings = m.warnings;
    warnings.sort();
    warnings.dedup();
    Ok(PlatformIoIngest {
        product,
        env: project.env.clone(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(ini_text: &str) -> PlatformIoProject {
        PlatformIoProject {
            name: "demo".into(),
            config: ini::parse(ini_text).unwrap(),
            env: "e".into(),
            libraries: vec![InstalledLibrary {
                location: ".pio/libdeps/e/ArduinoJson".into(),
                piopm: Some(piopm::parse(r#"{"type": "library", "name": "ArduinoJson", "version": "7.2.1", "spec": {"owner": "bblanchon"}}"#).unwrap()),
                manifest: Some(library_json::parse(r#"{"name": "ArduinoJson", "version": "7.2.1", "repository": {"url": "https://github.com/bblanchon/ArduinoJson.git"}}"#).unwrap()),
            }],
            libdeps_present: true,
            platform: None,
            packages: BTreeMap::new(),
            warnings: Vec::new(),
        }
    }

    fn component<'a>(p: &'a Product, name: &str) -> &'a Component {
        p.images
            .iter()
            .flat_map(|i| &i.components)
            .find(|c| c.name == name)
            .unwrap()
    }

    #[test]
    fn exact_pins_identify_platform_and_framework_without_a_core_directory() {
        let out = map(
            &project("[env:e]\nplatform = espressif32 @ 6.10.0\nplatform_packages = platformio/framework-arduinoespressif32 @ 3.20017.241212\nframework = arduino\nlib_deps = bblanchon/ArduinoJson @ 7.2.1\n"),
            &table::builtin().unwrap(),
        )
        .unwrap();
        let p = &out.product;
        let fw = component(p, "arduino-esp32");
        assert_eq!(fw.version.as_deref(), Some("2.0.17"));
        assert_eq!(
            fw.cpe.as_ref().map(Cpe::as_str),
            Some("cpe:2.3:a:espressif:arduino-esp32:2.0.17:*:*:*:*:*:*:*")
        );
        let platform = component(p, "espressif32");
        assert_eq!(platform.version.as_deref(), Some("6.10.0"));
        assert_eq!(platform.scope, Some(Scope::Excluded));
        assert_eq!(platform.kind, ComponentKind::Platform);
        let lib = component(p, "bblanchon/ArduinoJson");
        assert!(
            lib.purl
                .as_ref()
                .unwrap()
                .as_str()
                .starts_with("pkg:generic/bblanchon/ArduinoJson@7.2.1?repository_url=")
        );
        let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            [
                ".pio/libdeps/e/ArduinoJson/library.json: bblanchon/ArduinoJson: no license in library.json; the component has no licence"
            ]
        );
    }

    #[test]
    fn unpinned_versions_and_unknown_frameworks_warn() {
        let out = map(
            &project(
                "[env:e]\nplatform = espressif32\nframework = arduino, mystery\nlib_deps = WiFi\n",
            ),
            &table::builtin().unwrap(),
        )
        .unwrap();
        let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
        for needle in [
            "platform espressif32: version unknown",
            "framework arduino: the version of framework-arduinoespressif32 is unknown",
            "framework mystery: its package is not known",
            "lib_deps WiFi is not installed",
        ] {
            assert!(
                text.iter().any(|w| w.contains(needle)),
                "{needle}: {text:?}"
            );
        }
        assert_eq!(component(&out.product, "arduino-esp32").purl, None);
    }

    #[test]
    fn version_helpers() {
        assert_eq!(padded("2.8"), "2.8.0");
        assert_eq!(padded("7"), "7.0.0");
        assert_eq!(padded("3.20017.241212+sha.x"), "3.20017.241212");
        assert_eq!(
            repo_name("https://github.com/me/My-Lib.git#v1").as_deref(),
            Some("my-lib")
        );
        assert_eq!(repo_name("git@github.com:me/x.git").as_deref(), Some("x"));
        assert!(is_release("2.0.17") && !is_release("2.0") && !is_release("2.0.x"));
    }
}
