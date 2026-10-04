//! ESP-IDF ingestion: an ESP-IDF project and its build directory → the component graph.
//!
//! [`ingest`] reads what `idf.py build` leaves in a project, splits the subsystems the
//! `sdkconfig` enables and the link map shows linked out of the `esp-idf` component, and
//! attaches Espressif's prebuilt Wi-Fi, PHY and Bluetooth libraries as opaque blob images.
//! `docs/esp-idf.md` is the user guide.
//!
//! ```no_run
//! use rollcall_core::esp_idf::{self, EspIdfOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let options = EspIdfOptions::new("my-project").with_idf_path("/opt/esp/idf");
//! let ingest = esp_idf::ingest(&options)?;
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
//! Paths are relative to the project directory; `build/` is the build directory
//! ([`EspIdfOptions::with_build_dir`], default `<project>/build`) and `<idf>` the ESP-IDF tree
//! ([`EspIdfOptions::with_idf_path`]).
//!
//! | Input | Required | Used for |
//! |-------|----------|----------|
//! | `build/project_description.json` | yes | project name and version (the product and its application image), `git_revision` (the ESP-IDF version), `target`, and the `idf_path` and `build_dir` the build saw (to read the map's paths) |
//! | `sdkconfig` | yes | which subsystems are enabled; the ESP-IDF version in its header comment; `CONFIG_IDF_TARGET` |
//! | `dependencies.lock` | no (a warning when `main/idf_component.yml` exists) | every managed component: version, source, component hash, and the edges between them |
//! | `main/idf_component.yml` | no | the project's direct dependencies when the lock does not list them (lock format 1) |
//! | `managed_components/<namespace>__<name>/idf_component.yml` | no (a warning) | a registry or git component's licence and repository |
//! | `build/<project_name>.map` | no (a warning: no split, no blobs) | which subsystems and blobs are linked |
//! | `<idf>/components/esp_common/include/esp_idf_version.h`, `<idf>/version.txt` | no | the ESP-IDF version file(s), cross-checked |
//! | `<idf>/<blob path>` | no (a warning: blobs without hashes) | each linked blob's SHA-256 |
//!
//! # Mapping
//!
//! | Input | Model |
//! |-------|-------|
//! | `project_name`, `project_version` | the [`Product`] and its one `application` [`Image`], whose purl is `pkg:generic/<project_name>@<project_version>` (as for a Cargo path package) |
//! | ESP-IDF (`git_revision`, else the lock's `idf` entry, else the `sdkconfig` header) | a `framework` component `esp-idf` (a `framework`, not an `operating-system`: scanners skip operating-system components), its version without the leading `v`, the table's purl and, for a release `X.Y.Z`, CPE; supplier Espressif Systems, licence Apache-2.0 |
//! | each subsystem the split emits ([`split`]) | a `library` subcomponent of `esp-idf`: its upstream version for this ESP-IDF tag when the table has one (else ESP-IDF's), when the upstream version is known, the table's upstream purl (`pkg:generic/mbedtls@3.6.4?vcs_url=git+https://github.com/espressif/mbedtls`), CPE and `cpe_aliases` (as additional CPEs), else the `esp-idf` purl with its directory as subpath and no CPE; its licence (else ESP-IDF's), ESP-IDF's supplier |
//! | each `dependencies.lock` entry other than `idf` | a `library` component of the image named as in the lock (`espressif/mdns`); purl per [`purl`]; version from the lock (a git source's commit; a `local` component inside the ESP-IDF tree takes ESP-IDF's version, since the lock records `*`); supplier Espressif Systems for the `espressif` namespace and for components inside the ESP-IDF tree; licence from its `idf_component.yml` |
//! | each linked blob | a `blob` image (CycloneDX `library`, marked opaque by the writer) named after the file (`libnet80211`), version ESP-IDF's, the `esp-idf` purl with the file as subpath, supplier Espressif Systems, the table's licence, and its SHA-256 when `<idf>` is given; the application image depends on it |
//! | lock `direct_dependencies` (else `main/idf_component.yml`) and each entry's `dependencies` | edges: image → `esp-idf` and each direct dependency; component → component; `idf` → `esp-idf`; product → image |
//!
//! Evidence, located at the input's project-relative path (never a build-machine path):
//! `project-description` (name, version, the ESP-IDF version), `sdkconfig` (enabling symbols,
//! with their lines; the header version), `dependencies-lock` (names, versions, the
//! component hash as `hash` evidence), `idf-component-yml` (licences), `linker-map` (the
//! first linked object of each subsystem and blob, with its line, cited by its build-relative
//! archive or, for a blob, as `esp-idf/<path in the tree>(<member>)`), `esp-idf-table` (a
//! subsystem's upstream purl and CPEs), `idf-version-file`
//! (`esp_idf_version.h`, `version.txt`), `idf-blob` (each blob's SHA-256, `binary-analysis`).
//!
//! # Warnings
//!
//! Non-fatal problems are [`Warning`]s, sorted and deduplicated: a missing optional input; an
//! ESP-IDF version that is not a release (`-dirty`, commits after the tag) or that two
//! sources disagree about; a build of another ESP-IDF tag than the table was checked against;
//! a `project_description.json` without `idf_path` (no blob can be recognised); a dependency
//! name with no lock entry; a managed component with no purl (a local one outside the ESP-IDF
//! tree, an unknown source type), a git source without a full commit, an invalid licence, a manifest whose version
//! disagrees with the lock; a blob whose file cannot be hashed. A missing required input is
//! [`EspIdfError::Read`]; a malformed input (any parser error) is an [`EspIdfError`] naming
//! the file. Decisions that are not problems (a subsystem enabled but not linked) are
//! [`Note`]s, printed by `rollcall generate --verbose`.
//!
//! # Determinism
//!
//! The same inputs give the same [`Product`]: components, evidence and edges live in sorted
//! sets, the lock is read into a sorted map, the split follows the table's order and the
//! map's sorted objects, and no absolute path, clock or iteration order reaches the output.

pub mod dependencies_lock;
pub mod idf_component;
pub mod project_description;
pub mod purl;
pub mod sdkconfig;
pub mod split;
pub mod table;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use crate::blob::{BlobImage, sha256_file};
use crate::linker_map::{self, LinkerMap, LinkerMapError};
use crate::merge;
use crate::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, Hash,
    HashAlgorithm, IdError, Image, ImageKind, ImageType, License, Occurrence, PathSegment, Product,
    Purl, Supplier, Technique,
};
pub use crate::warning::Warning;
use crate::zephyr::KconfigError;
pub use crate::zephyr::Note;
pub use dependencies_lock::{Lock, LockEntry, LockError, LockSource};
pub use idf_component::{Manifest, ManifestError};
pub use project_description::{ProjectDescription, ProjectDescriptionError};
pub use sdkconfig::SdkConfig;
pub use table::{EspIdfTable, TableError};

/// The name of the ESP-IDF component.
pub const IDF_COMPONENT: &str = "esp-idf";
/// The largest input file read: 256 MiB.
pub const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

/// Evidence sources.
const PROJECT_DESCRIPTION: &str = "project-description";
const SDKCONFIG: &str = "sdkconfig";
const LOCK: &str = "dependencies-lock";
const MANIFEST: &str = "idf-component-yml";
const LINKER_MAP: &str = "linker-map";
const VERSION_FILE: &str = "idf-version-file";
const BLOB_FILE: &str = "idf-blob";
const TABLE: &str = "esp-idf-table";

/// Confidences, in basis points.
const DESCRIPTION_CONFIDENCE: u16 = 9000;
const LOCK_CONFIDENCE: u16 = 9000;
const MANIFEST_CONFIDENCE: u16 = 8500;
const VERSION_FILE_CONFIDENCE: u16 = 9000;
const HEADER_CONFIDENCE: u16 = 7000;
const SYMBOL_CONFIDENCE: u16 = 6000;
const LINKED_CONFIDENCE: u16 = 8000;
const TABLE_CONFIDENCE: u16 = 9000;

/// Project-relative file names.
const DESCRIPTION_FILE: &str = "project_description.json";
const SDKCONFIG_FILE: &str = "sdkconfig";
const LOCK_FILE: &str = "dependencies.lock";
const MAIN_MANIFEST: &str = "main/idf_component.yml";
const VERSION_HEADER: &str = "components/esp_common/include/esp_idf_version.h";
const VERSION_TXT: &str = "version.txt";

/// What to ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspIdfOptions {
    /// The project directory (holding `sdkconfig`).
    pub project_dir: PathBuf,
    /// The build directory, when not `<project>/build`.
    pub build_dir: Option<PathBuf>,
    /// The ESP-IDF tree, for blob hashes and the version file.
    pub idf_path: Option<PathBuf>,
}

impl EspIdfOptions {
    /// Options for the project in `project_dir`, built in `<project_dir>/build`.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        Self {
            project_dir: project_dir.into(),
            build_dir: None,
            idf_path: None,
        }
    }

    /// Reads the build from `build_dir`.
    pub fn with_build_dir(mut self, build_dir: impl Into<PathBuf>) -> Self {
        self.build_dir = Some(build_dir.into());
        self
    }

    /// Reads blobs and the version file from the ESP-IDF tree at `idf_path`.
    pub fn with_idf_path(mut self, idf_path: impl Into<PathBuf>) -> Self {
        self.idf_path = Some(idf_path.into());
        self
    }

    fn build_dir(&self) -> PathBuf {
        self.build_dir
            .clone()
            .unwrap_or_else(|| self.project_dir.join("build"))
    }
}

/// The result of [`ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspIdfIngest {
    /// The product.
    pub product: Product,
    /// Non-fatal problems, sorted.
    pub warnings: Vec<Warning>,
    /// Decisions that are not problems, sorted.
    pub notes: Vec<Note>,
}

/// Why a build could not be ingested. Every variant names its file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EspIdfError {
    /// A file could not be read (missing, a directory, no permission, …).
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
    /// `project_description.json` is malformed.
    #[error("{}: {source}", path.display())]
    ProjectDescription {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: ProjectDescriptionError,
    },
    /// `sdkconfig` is malformed.
    #[error("{}: {source}", path.display())]
    Sdkconfig {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: KconfigError,
    },
    /// `dependencies.lock` is malformed.
    #[error("{}: {source}", path.display())]
    Lock {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: LockError,
    },
    /// An `idf_component.yml` is malformed.
    #[error("{}: {source}", path.display())]
    Manifest {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: ManifestError,
    },
    /// The link map is not a GNU ld map, or malformed.
    #[error("{}: {source}", path.display())]
    LinkMap {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: LinkerMapError,
    },
    /// The built-in ESP-IDF table is broken (a rollcall bug).
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

impl EspIdfError {
    /// Whether this is a missing or unreadable input, rather than a malformed one.
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Read { .. })
    }
}

/// The inputs, read and parsed.
#[derive(Debug)]
pub struct EspIdfBuild {
    /// `project_description.json`.
    pub description: ProjectDescription,
    /// `sdkconfig`.
    pub sdkconfig: SdkConfig,
    /// `dependencies.lock`, if present.
    pub lock: Option<Lock>,
    /// `main/idf_component.yml`, if present.
    pub main_manifest: Option<Manifest>,
    /// Each managed component's `idf_component.yml`, by lock name, with its location.
    pub manifests: BTreeMap<String, (Manifest, String)>,
    /// The link map, if present, with its location.
    pub map: Option<(LinkerMap, String)>,
    /// The ESP-IDF version file(s): (location, version).
    pub version_files: Vec<(String, String)>,
    /// The ESP-IDF tree given, for hashing blobs.
    pub idf_path: Option<PathBuf>,
    /// Problems found while loading.
    pub warnings: Vec<Warning>,
}

/// Reads `path` as UTF-8 text; `Ok(None)` when it does not exist and `optional`.
fn read_text(path: &Path, optional: bool) -> Result<Option<String>, EspIdfError> {
    let read_err = |source| EspIdfError::Read {
        path: path.to_owned(),
        source,
    };
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if optional && e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(read_err(e)),
    };
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(EspIdfError::TooLarge {
            path: path.to_owned(),
        });
    }
    let bytes = std::fs::read(path).map_err(read_err)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| EspIdfError::NotUtf8 {
            path: path.to_owned(),
        })
}

/// The last path component of `dir`, for citing files under it (`build`).
fn dir_label(dir: &Path) -> String {
    dir.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty() && n != "." && n != "..")
        .unwrap_or_else(|| "build".to_owned())
}

/// The managed-component directory name of a lock name: `espressif/mdns` →
/// `espressif__mdns`.
pub fn managed_dir_name(name: &str) -> String {
    name.replace('/', "__")
}

/// `ESP_IDF_VERSION_MAJOR/MINOR/PATCH` from `esp_idf_version.h`, as `X.Y.Z`.
pub fn version_from_header(text: &str) -> Option<String> {
    let number = |macro_name: &str| {
        text.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("#define") && words.next() == Some(macro_name))
                .then(|| words.next())
                .flatten()
                .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                .map(str::to_owned)
        })
    };
    Some(format!(
        "{}.{}.{}",
        number("ESP_IDF_VERSION_MAJOR")?,
        number("ESP_IDF_VERSION_MINOR")?,
        number("ESP_IDF_VERSION_PATCH")?
    ))
}

/// Reads every input (see the module docs), in a fixed order.
pub fn load(options: &EspIdfOptions) -> Result<EspIdfBuild, EspIdfError> {
    let project = &options.project_dir;
    let build_dir = options.build_dir();
    let build_label = dir_label(&build_dir);
    let mut warnings = Vec::new();

    let path = build_dir.join(DESCRIPTION_FILE);
    let text = read_text(&path, false)?.unwrap_or_default();
    let description = project_description::parse(&text)
        .map_err(|source| EspIdfError::ProjectDescription { path, source })?;

    let path = project.join(SDKCONFIG_FILE);
    let text = read_text(&path, false)?.unwrap_or_default();
    let sdkconfig =
        sdkconfig::parse(&text).map_err(|source| EspIdfError::Sdkconfig { path, source })?;

    let path = project.join(MAIN_MANIFEST);
    let main_manifest = match read_text(&path, true)? {
        Some(text) => Some(
            idf_component::parse(&text).map_err(|source| EspIdfError::Manifest { path, source })?,
        ),
        None => None,
    };

    let path = project.join(LOCK_FILE);
    let lock = match read_text(&path, true)? {
        Some(text) => Some(
            dependencies_lock::parse(&text).map_err(|source| EspIdfError::Lock { path, source })?,
        ),
        None => {
            if main_manifest.is_some() {
                warnings.push(Warning::new(
                    LOCK_FILE,
                    format!(
                        "missing although {MAIN_MANIFEST} exists: managed components are not listed (run idf.py reconfigure)"
                    ),
                ));
            }
            None
        }
    };

    let mut manifests = BTreeMap::new();
    if let Some(lock) = &lock {
        for (name, entry) in &lock.dependencies {
            if !matches!(
                entry.source,
                LockSource::Service { .. } | LockSource::Git { .. }
            ) {
                continue;
            }
            let location = format!(
                "managed_components/{}/idf_component.yml",
                managed_dir_name(name)
            );
            let path = project.join(&location);
            match read_text(&path, true)? {
                Some(text) => {
                    let manifest = idf_component::parse(&text)
                        .map_err(|source| EspIdfError::Manifest { path, source })?;
                    manifests.insert(name.clone(), (manifest, location));
                }
                None => warnings.push(Warning::new(
                    location,
                    format!("{name}: missing; its licence is not known"),
                )),
            }
        }
    }

    let map_location = format!("{build_label}/{}.map", description.project_name);
    let path = build_dir.join(format!("{}.map", description.project_name));
    let map = match read_text(&path, true)? {
        Some(text) => Some((
            linker_map::parse(&text).map_err(|source| EspIdfError::LinkMap { path, source })?,
            map_location,
        )),
        None => {
            warnings.push(Warning::new(
                map_location,
                "no link map: esp-idf is not split into subsystems and no blob is listed",
            ));
            None
        }
    };

    let mut version_files = Vec::new();
    if let Some(idf) = &options.idf_path {
        let header = idf.join(VERSION_HEADER);
        if let Some(text) = read_text(&header, true)? {
            match version_from_header(&text) {
                Some(version) => version_files.push((format!("esp-idf/{VERSION_HEADER}"), version)),
                None => warnings.push(Warning::new(
                    format!("esp-idf/{VERSION_HEADER}"),
                    "no ESP_IDF_VERSION_MAJOR/MINOR/PATCH; ignored",
                )),
            }
        }
        if let Some(text) = read_text(&idf.join(VERSION_TXT), true)? {
            let version = text.trim();
            if let Some((release, _)) = project_description::release_version(version) {
                version_files.push((format!("esp-idf/{VERSION_TXT}"), release));
            }
        }
    }

    Ok(EspIdfBuild {
        description,
        sdkconfig,
        lock,
        main_manifest,
        manifests,
        map,
        version_files,
        idf_path: options.idf_path.clone(),
        warnings,
    })
}

/// Reads the inputs and maps them into a product (see the module docs).
pub fn ingest(options: &EspIdfOptions) -> Result<EspIdfIngest, EspIdfError> {
    let build = load(options)?;
    let table = table::builtin()?;
    map(&build, &table)
}

/// Builds evidence with a located occurrence.
fn evidence(
    field: EvidenceField,
    technique: Technique,
    source: &str,
    value: &str,
    bp: u16,
    location: &str,
    line: Option<u32>,
) -> Result<Evidence, IdError> {
    Ok(
        Evidence::new(field, technique, source, value, Confidence::new(bp)?)?
            .at(Occurrence::new(location, line)?),
    )
}

/// Whether `version` is a plain `X.Y.Z` release (a CPE is only emitted for one).
fn is_release(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

struct Mapper<'a> {
    build: &'a EspIdfBuild,
    table: &'a EspIdfTable,
    warnings: Vec<Warning>,
    description_location: String,
}

impl Mapper<'_> {
    fn model_err(&self, e: impl std::fmt::Display) -> EspIdfError {
        EspIdfError::Model {
            input: self.description_location.clone(),
            message: e.to_string(),
        }
    }

    fn warn(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(Warning::new(location, message));
    }

    /// The ESP-IDF version and its evidence: `git_revision`, else the lock's `idf`, else the
    /// sdkconfig header, else a version file. Every other source that disagrees is a warning.
    fn idf_version(&mut self) -> Result<(Option<String>, Vec<Evidence>), EspIdfError> {
        let b = self.build;
        let mut sources: Vec<(String, String, Evidence)> = Vec::new();
        if let Some(rev) = &b.description.git_revision {
            match project_description::release_version(rev) {
                Some((version, extra)) => {
                    if let Some(extra) = extra {
                        self.warn(
                            self.description_location.clone(),
                            format!(
                                "ESP-IDF is {rev}, not the release {version} ({extra}): the tree has local changes or commits after the tag; identifiers name the release"
                            ),
                        );
                    }
                    let e = evidence(
                        EvidenceField::Version,
                        Technique::ManifestAnalysis,
                        PROJECT_DESCRIPTION,
                        rev,
                        DESCRIPTION_CONFIDENCE,
                        &self.description_location,
                        None,
                    )
                    .map_err(|e| self.model_err(e))?;
                    sources.push((version, self.description_location.clone(), e));
                }
                None => self.warn(
                    self.description_location.clone(),
                    format!("git_revision {rev:?} is not an ESP-IDF version; ignored"),
                ),
            }
        }
        if let Some(version) = b.lock.as_ref().and_then(Lock::idf_version) {
            let e = evidence(
                EvidenceField::Version,
                Technique::ManifestAnalysis,
                LOCK,
                version,
                LOCK_CONFIDENCE,
                LOCK_FILE,
                None,
            )
            .map_err(|e| self.model_err(e))?;
            sources.push((version.to_owned(), LOCK_FILE.to_owned(), e));
        }
        if let Some((version, line)) = b.sdkconfig.header_version() {
            let e = evidence(
                EvidenceField::Version,
                Technique::ManifestAnalysis,
                SDKCONFIG,
                version,
                HEADER_CONFIDENCE,
                SDKCONFIG_FILE,
                Some(line),
            )
            .map_err(|e| self.model_err(e))?;
            sources.push((version.to_owned(), format!("{SDKCONFIG_FILE}:{line}"), e));
        }
        for (location, version) in &b.version_files {
            let e = evidence(
                EvidenceField::Version,
                Technique::ManifestAnalysis,
                VERSION_FILE,
                version,
                VERSION_FILE_CONFIDENCE,
                location,
                None,
            )
            .map_err(|e| self.model_err(e))?;
            sources.push((version.clone(), location.clone(), e));
        }
        let chosen = sources.first().map(|(v, _, _)| v.clone());
        if let Some(chosen) = &chosen {
            for (version, location, _) in sources.iter().skip(1) {
                if version != chosen {
                    self.warn(
                        location.clone(),
                        format!(
                            "says ESP-IDF {version}, but the build is {chosen}; {chosen} is used"
                        ),
                    );
                }
            }
        } else {
            self.warn(
                self.description_location.clone(),
                "no ESP-IDF version (no git_revision, no idf entry in dependencies.lock, no sdkconfig header): esp-idf has no version, purl or CPE",
            );
        }
        Ok((chosen, sources.into_iter().map(|(_, _, e)| e).collect()))
    }

    fn supplier(&self) -> Result<Supplier, EspIdfError> {
        Supplier::new(&self.table.idf.supplier)
            .and_then(|s| s.with_url(&self.table.idf.supplier_url))
            .map_err(|e| self.model_err(e))
    }
}

/// The ESP-IDF tag of `version` (`5.5.1` → `v5.5.1`).
fn tag_of(version: &str) -> String {
    format!("v{version}")
}

/// Maps loaded inputs to a product (no I/O except hashing blobs under the given ESP-IDF
/// tree).
pub fn map(build: &EspIdfBuild, table: &EspIdfTable) -> Result<EspIdfIngest, EspIdfError> {
    let build_label = build
        .map
        .as_ref()
        .and_then(|(_, l)| l.split('/').next())
        .unwrap_or("build")
        .to_owned();
    let mut m = Mapper {
        build,
        table,
        warnings: build.warnings.clone(),
        description_location: format!("{build_label}/{DESCRIPTION_FILE}"),
    };
    let d = &build.description;

    // The product and its application image.
    let mut product = Product::new(&d.project_name).map_err(|e| m.model_err(e))?;
    let mut image =
        Image::new(ImageKind::Application, &d.project_name).map_err(|e| m.model_err(e))?;
    if let Some(version) = &d.project_version {
        product = product.with_version(version);
        image = image.with_version(version);
    }
    // As for a Cargo path package: a local project's purl is `pkg:generic/<name>@<version>`.
    let app_purl = {
        let mut p = packageurl::PackageUrl::new("generic", d.project_name.as_str())
            .map_err(|e| m.model_err(e))?;
        if let Some(version) = &d.project_version {
            p.with_version(version.as_str())
                .map_err(|e| m.model_err(e))?;
        }
        Purl::new(&p.to_string()).map_err(|e| m.model_err(e))?
    };
    image.purl = Some(app_purl.clone());
    for (field, value) in [
        (EvidenceField::Name, Some(d.project_name.as_str())),
        (EvidenceField::Version, d.project_version.as_deref()),
        (EvidenceField::Purl, Some(app_purl.as_str())),
    ] {
        if let Some(value) = value {
            image.evidence.insert(
                evidence(
                    field,
                    Technique::ManifestAnalysis,
                    PROJECT_DESCRIPTION,
                    value,
                    DESCRIPTION_CONFIDENCE,
                    &m.description_location,
                    None,
                )
                .map_err(|e| m.model_err(e))?,
            );
        }
    }

    // The esp-idf component.
    let (idf_version, idf_evidence) = m.idf_version()?;
    let supplier = m.supplier()?;
    let mut idf =
        Component::new(ComponentKind::Framework, IDF_COMPONENT).map_err(|e| m.model_err(e))?;
    idf.supplier = Some(supplier.clone());
    idf.licence = Some(table.idf.licence.clone());
    idf.evidence = idf_evidence.into_iter().collect();
    if let Some(version) = &idf_version {
        idf.version = Some(version.clone());
        match Purl::new(&table::fill(&table.idf.purl, version)) {
            Ok(purl) => idf.purl = Some(purl),
            Err(e) => m.warn(
                m.description_location.clone(),
                format!("esp-idf: no purl ({e})"),
            ),
        }
        if is_release(version) {
            idf.cpe = Cpe::new(&table::fill(&table.idf.cpe, version)).ok();
        }
        if tag_of(version) != table.idf.tag {
            m.warn(
                m.description_location.clone(),
                format!(
                    "ESP-IDF {version}: rollcall's ESP-IDF table was checked against {}; subsystem archives and upstream versions may differ",
                    table.idf.tag
                ),
            );
        }
    }
    if let Some((target, line)) = build.sdkconfig.target() {
        idf.evidence.insert(
            evidence(
                EvidenceField::Name,
                Technique::ManifestAnalysis,
                SDKCONFIG,
                &format!("target:{target}"),
                SYMBOL_CONFIDENCE,
                SDKCONFIG_FILE,
                Some(line),
            )
            .map_err(|e| m.model_err(e))?,
        );
    }

    // The split.
    let mut notes = Vec::new();
    let mut blobs: Vec<BlobImage> = Vec::new();
    if let Some((linker_map, map_location)) = &build.map {
        if d.idf_path.is_none() {
            m.warn(
                m.description_location.clone(),
                "no idf_path: the map's ESP-IDF archives cannot be recognised, so no blob is listed",
            );
        }
        let outcome = split::split(
            table,
            &build.sdkconfig,
            linker_map,
            d.idf_path.as_deref(),
            d.build_dir.as_deref(),
            map_location,
        );
        notes = outcome.notes;
        for found in &outcome.subsystems {
            let s = found.subsystem;
            let mut c =
                Component::new(ComponentKind::Library, &s.name).map_err(|e| m.model_err(e))?;
            let upstream = idf_version
                .as_ref()
                .and_then(|v| s.upstream_versions.get(&tag_of(v)));
            c.version = upstream.cloned().or_else(|| idf_version.clone());
            c.supplier = Some(supplier.clone());
            c.licence = Some(
                s.licence
                    .clone()
                    .unwrap_or_else(|| table.idf.licence.clone()),
            );
            // With a known upstream version, the upstream project's own identifiers (the
            // identifier database's `pkg:generic/<name>@<version>?vcs_url=…` form, naming the
            // Espressif fork), so VEX rules keyed on them match across ecosystems; else the
            // esp-idf purl with the subsystem's directory as subpath.
            c.purl = match (&s.purl, upstream) {
                (Some(template), Some(version)) => Purl::new(&table::fill(template, version)).ok(),
                _ => None,
            }
            .or_else(|| {
                idf.purl
                    .as_ref()
                    .and_then(|p| purl::with_subpath(p, &s.subpath))
            });
            let table_fact = |field: EvidenceField, value: &str| {
                evidence(
                    field,
                    Technique::ManifestAnalysis,
                    TABLE,
                    value,
                    TABLE_CONFIDENCE,
                    table::BUILTIN_NAME,
                    None,
                )
            };
            if let (Some(purl), Some(_)) = (&c.purl, upstream) {
                c.evidence.insert(
                    table_fact(EvidenceField::Purl, purl.as_str()).map_err(|e| m.model_err(e))?,
                );
            }
            match (&s.cpe, upstream) {
                (Some(template), Some(version)) => {
                    c.cpe = Cpe::new(&table::fill(template, version)).ok();
                    if let Some(cpe) = &c.cpe {
                        c.evidence.insert(
                            table_fact(EvidenceField::Cpe, cpe.as_str())
                                .map_err(|e| m.model_err(e))?,
                        );
                    }
                    // Other vendor:products NVD files its CVEs under, as the identify path
                    // records a database entry's `cpe_aliases`: additional CPEs, each with
                    // `cpe` evidence, only beside a primary CPE.
                    for alias in &s.cpe_aliases {
                        let Ok(alias) = Cpe::new(&table::fill(alias, version)) else {
                            continue;
                        };
                        c.evidence.insert(
                            table_fact(EvidenceField::Cpe, alias.as_str())
                                .map_err(|e| m.model_err(e))?,
                        );
                        if c.cpe.as_ref().is_some_and(|primary| *primary != alias) {
                            c.additional_cpes.insert(alias);
                        }
                    }
                }
                (Some(_), None) => m.warn(
                    map_location.clone(),
                    format!(
                        "subsystem {}: its upstream version for ESP-IDF {} is not in rollcall's table; no CPE",
                        s.name,
                        idf_version.as_deref().unwrap_or("(unknown)")
                    ),
                ),
                (None, _) => {}
            }
            for (symbol, line) in &found.symbols {
                c.evidence.insert(
                    evidence(
                        EvidenceField::Name,
                        Technique::ManifestAnalysis,
                        SDKCONFIG,
                        symbol,
                        SYMBOL_CONFIDENCE,
                        SDKCONFIG_FILE,
                        *line,
                    )
                    .map_err(|e| m.model_err(e))?,
                );
            }
            c.evidence.insert(
                evidence(
                    EvidenceField::Name,
                    Technique::BinaryAnalysis,
                    LINKER_MAP,
                    &found.object,
                    LINKED_CONFIDENCE,
                    map_location,
                    Some(found.line),
                )
                .map_err(|e| m.model_err(e))?,
            );
            idf.add_component(c).map_err(|e| m.model_err(e))?;
        }
        if !outcome.blobs.is_empty() && build.idf_path.is_none() {
            m.warn(
                map_location.clone(),
                format!(
                    "{} linked blob(s) without SHA-256: pass --idf-path (the ESP-IDF tree the build used) to hash them",
                    outcome.blobs.len()
                ),
            );
        }
        for found in &outcome.blobs {
            let file_name = found.path.rsplit('/').next().unwrap_or(&found.path);
            let name = file_name.strip_suffix(".a").unwrap_or(file_name);
            let mut blob = Image::new(ImageKind::Blob, name).map_err(|e| m.model_err(e))?;
            blob.version = idf_version.clone();
            blob.image_type = ImageType::Library;
            blob.supplier = Some(supplier.clone());
            blob.licence = Some(found.dir.licence.clone());
            blob.purl = idf
                .purl
                .as_ref()
                .and_then(|p| purl::with_subpath(p, &found.path));
            blob.evidence.insert(
                evidence(
                    EvidenceField::Name,
                    Technique::BinaryAnalysis,
                    LINKER_MAP,
                    &found.object,
                    LINKED_CONFIDENCE,
                    map_location,
                    Some(found.line),
                )
                .map_err(|e| m.model_err(e))?,
            );
            if let Some(root) = &build.idf_path {
                let file = root.join(&found.path);
                let location = format!("esp-idf/{}", found.path);
                let digest = match std::fs::metadata(&file) {
                    Ok(meta) if meta.is_file() => sha256_file(&file).map_err(|e| e.to_string()),
                    Ok(_) => Err("not a regular file".to_owned()),
                    Err(e) => Err(e.to_string()),
                };
                match digest {
                    Ok(digest) => {
                        blob.hashes.insert(
                            Hash::new(HashAlgorithm::Sha256, &digest)
                                .map_err(|e| m.model_err(e))?,
                        );
                        blob.evidence.insert(
                            evidence(
                                EvidenceField::Hash,
                                Technique::BinaryAnalysis,
                                BLOB_FILE,
                                &digest,
                                Confidence::FULL.basis_points(),
                                &location,
                                None,
                            )
                            .map_err(|e| m.model_err(e))?,
                        );
                    }
                    Err(e) => m.warn(location, format!("{name}: cannot hash ({e}); no SHA-256")),
                }
            }
            blobs.push(BlobImage {
                image: blob,
                owner: Some(d.project_name.clone()),
            });
        }
    }

    // Managed components.
    let idf_purl = idf.purl.clone();
    let mut managed: BTreeMap<String, Component> = BTreeMap::new();
    if let Some(lock) = &build.lock {
        for (name, entry) in &lock.dependencies {
            if entry.source == LockSource::Idf {
                continue;
            }
            let c = managed_component(
                &mut m,
                name,
                entry,
                idf_purl.as_ref(),
                idf_version.as_deref(),
                &supplier,
            )?;
            managed.insert(name.clone(), c);
        }
    }

    // Edges.
    let product_path = product.path();
    let image_path = product_path.child(PathSegment::of_image(&image));
    let image_ref = BomRef::derive(&image_path);
    let idf_ref = BomRef::derive(&image_path.child(PathSegment::of_component(&idf)));
    let refs: BTreeMap<&str, BomRef> = managed
        .iter()
        .map(|(name, c)| {
            (
                name.as_str(),
                BomRef::derive(&image_path.child(PathSegment::of_component(c))),
            )
        })
        .collect();
    let target = |name: &str| -> Option<BomRef> {
        if name == "idf" {
            return Some(idf_ref.clone());
        }
        refs.get(name).cloned()
    };
    let mut edges: BTreeSet<(BomRef, BomRef)> = BTreeSet::new();
    edges.insert((BomRef::derive(&product_path), image_ref.clone()));
    edges.insert((image_ref.clone(), idf_ref.clone()));
    let direct: Vec<String> = match (&build.lock, &build.main_manifest) {
        (Some(lock), _) if !lock.direct_dependencies.is_empty() => lock.direct_dependencies.clone(),
        (_, Some(manifest)) => manifest.dependencies.clone(),
        _ => Vec::new(),
    };
    // A name the lock has no entry for gets no edge, and a warning (only with a lock: without
    // one, its absence is already warned about).
    let mut unlocked: Vec<Warning> = Vec::new();
    for name in &direct {
        match target(name) {
            Some(to) => {
                edges.insert((image_ref.clone(), to));
            }
            None if build.lock.is_some() => unlocked.push(Warning::new(
                LOCK_FILE,
                format!("direct dependency {name} has no entry in the lock; no edge to it"),
            )),
            None => {}
        }
    }
    if let Some(lock) = &build.lock {
        for (name, entry) in &lock.dependencies {
            let Some(from) = refs.get(name.as_str()) else {
                continue;
            };
            for dep in &entry.dependencies {
                match target(dep) {
                    Some(to) => {
                        edges.insert((from.clone(), to));
                    }
                    None => unlocked.push(Warning::new(
                        LOCK_FILE,
                        format!(
                            "{name} depends on {dep}, which has no entry in the lock; no edge to it"
                        ),
                    )),
                }
            }
        }
    }
    m.warnings.extend(unlocked);

    image.add_component(idf).map_err(|e| m.model_err(e))?;
    for c in managed.into_values() {
        image.add_component(c).map_err(|e| m.model_err(e))?;
    }
    product.add_image(image).map_err(|e| m.model_err(e))?;
    for (from, to) in edges {
        if from != to {
            product.add_dependency(from, to);
        }
    }
    merge::attach_blobs(&mut product, blobs).map_err(|e| m.model_err(e))?;
    product.validate().map_err(|e| m.model_err(e))?;

    let mut warnings = m.warnings;
    warnings.sort();
    warnings.dedup();
    Ok(EspIdfIngest {
        product,
        warnings,
        notes,
    })
}

/// The component for the lock entry `name`.
fn managed_component(
    m: &mut Mapper<'_>,
    name: &str,
    entry: &LockEntry,
    idf_purl: Option<&Purl>,
    idf_version: Option<&str>,
    supplier: &Supplier,
) -> Result<Component, EspIdfError> {
    let idf_path = m.build.description.idf_path.as_deref();
    let in_idf = matches!(&entry.source, LockSource::Local { path: Some(p) }
        if idf_path.and_then(|root| purl::relative_to(p, root)).is_some());
    let mut c = Component::new(ComponentKind::Library, name).map_err(|e| m.model_err(e))?;
    c.version = match &entry.source {
        LockSource::Local { .. } if in_idf => idf_version.map(str::to_owned),
        _ => entry.version.clone().filter(|v| v != "*"),
    };
    let (namespace, _) = dependencies_lock::split_namespace(name);
    if namespace == Some("espressif") || in_idf {
        c.supplier = Some(supplier.clone());
    }
    match purl::managed_purl(name, entry, idf_purl, idf_path) {
        Ok(p) => c.purl = Some(p),
        Err(purl::NoPurl::LocalOutsideIdf) => m.warn(
            LOCK_FILE,
            format!("{name}: a local component outside the ESP-IDF tree has no purl"),
        ),
        Err(purl::NoPurl::UnknownSource(ty)) => m.warn(
            LOCK_FILE,
            format!("{name}: source type {ty:?} is not known to rollcall; no purl"),
        ),
        Err(purl::NoPurl::Invalid(e)) => m.warn(LOCK_FILE, format!("{name}: no purl ({e})")),
    }
    if let LockSource::Git { url, .. } = &entry.source
        && !entry.version.as_deref().is_some_and(purl::is_commit)
    {
        m.warn(
            LOCK_FILE,
            format!(
                "{name}: git source {url} is locked at {:?}, not a full commit; its purl has no version and its vcs_url no revision",
                entry.version.as_deref().unwrap_or("")
            ),
        );
    }
    let mut lock_facts = vec![(EvidenceField::Name, name.to_owned())];
    if let Some(v) = &entry.version {
        lock_facts.push((EvidenceField::Version, v.clone()));
    }
    if let Some(hash) = &entry.component_hash {
        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            lock_facts.push((
                EvidenceField::Hash,
                format!("sha256:{}", hash.to_ascii_lowercase()),
            ));
        } else {
            m.warn(
                LOCK_FILE,
                format!("{name}: component_hash {hash:?} is not a SHA-256; ignored"),
            );
        }
    }
    for (field, value) in lock_facts {
        c.evidence.insert(
            evidence(
                field,
                Technique::ManifestAnalysis,
                LOCK,
                &value,
                LOCK_CONFIDENCE,
                LOCK_FILE,
                None,
            )
            .map_err(|e| m.model_err(e))?,
        );
    }
    if let Some((manifest, location)) = m.build.manifests.get(name) {
        if let Some(raw) = &manifest.license {
            c.evidence.insert(
                evidence(
                    EvidenceField::Licence,
                    Technique::ManifestAnalysis,
                    MANIFEST,
                    raw,
                    MANIFEST_CONFIDENCE,
                    location,
                    None,
                )
                .map_err(|e| m.model_err(e))?,
            );
            match License::new(raw.trim()) {
                Ok(licence) => c.licence = Some(licence),
                Err(_) => m.warn(
                    location.clone(),
                    format!("{name}: license {raw:?} is not an SPDX expression; licence omitted"),
                ),
            }
        }
        if let (Some(theirs), Some(ours)) = (&manifest.version, &entry.version)
            && theirs != ours
            && matches!(entry.source, LockSource::Service { .. })
        {
            m.warn(
                location.clone(),
                format!(
                    "{name}: version {theirs} differs from the lock's {ours}; the lock's is used"
                ),
            );
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(lock: Option<&str>, sdk: &str, map_text: Option<&str>) -> EspIdfBuild {
        EspIdfBuild {
            description: project_description::parse(
                r#"{"project_name": "app", "project_version": "1", "idf_path": "/opt/esp/idf",
                   "git_revision": "v5.5.1", "target": "esp32", "build_dir": "/project/app/build"}"#,
            )
            .unwrap(),
            sdkconfig: sdkconfig::parse(sdk).unwrap(),
            lock: lock.map(|l| dependencies_lock::parse(l).unwrap()),
            main_manifest: None,
            manifests: BTreeMap::new(),
            map: map_text.map(|t| (linker_map::parse(t).unwrap(), "build/app.map".to_owned())),
            version_files: Vec::new(),
            idf_path: None,
            warnings: Vec::new(),
        }
    }

    const SDK: &str = "# Espressif IoT Development Framework (ESP-IDF) 5.5.1 Project Configuration\nCONFIG_IDF_TARGET=\"esp32\"\nCONFIG_LWIP_ENABLE=y\n";

    const MAP: &str = "Linker script and memory map\n\n.flash.text 0x400d0000 0x100\n \
        .text.a 0x400d0000 0x10 esp-idf/lwip/liblwip.a(tcp.c.obj)\n \
        .text.b 0x400d0010 0x10 /opt/esp/idf/components/esp_wifi/lib/esp32/libpp.a(pp.o)\n";

    fn component<'a>(p: &'a Product, name: &str) -> &'a Component {
        p.images
            .iter()
            .flat_map(|i| &i.components)
            .find(|c| c.name == name)
            .unwrap()
    }

    #[test]
    fn esp_idf_component_split_and_blob_are_mapped() {
        let out = map(&build(None, SDK, Some(MAP)), &table::builtin().unwrap()).unwrap();
        let p = &out.product;
        let idf = component(p, IDF_COMPONENT);
        assert_eq!(idf.kind, ComponentKind::Framework);
        assert_eq!(idf.version.as_deref(), Some("5.5.1"));
        assert_eq!(
            idf.cpe.as_ref().map(Cpe::as_str),
            Some("cpe:2.3:a:espressif:esp-idf:5.5.1:*:*:*:*:*:*:*")
        );
        let lwip = idf.components.iter().find(|c| c.name == "lwip").unwrap();
        assert_eq!(lwip.version.as_deref(), Some("2.2.0d"));
        // With an upstream version: the fork's own purl, in the identifier database's form.
        assert_eq!(
            lwip.purl.as_ref().unwrap().as_str(),
            "pkg:generic/lwip@2.2.0d?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-lwip"
        );
        let blob = p.images.iter().find(|i| i.kind == ImageKind::Blob).unwrap();
        assert_eq!(blob.name, "libpp");
        assert!(blob.hashes.is_empty());
        assert!(
            out.warnings
                .iter()
                .any(|w| w.message.contains("--idf-path")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn version_disagreement_and_dirty_tree_warn() {
        let mut b = build(
            Some("dependencies:\n  idf:\n    source: {type: idf}\n    version: 5.4.0\n"),
            SDK,
            None,
        );
        b.description.git_revision = Some("v5.5.1-dirty".into());
        let out = map(&b, &table::builtin().unwrap()).unwrap();
        assert_eq!(
            component(&out.product, IDF_COMPONENT).version.as_deref(),
            Some("5.5.1")
        );
        let text: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
        assert!(text.iter().any(|w| w.contains("-dirty")), "{text:?}");
        assert!(
            text.iter()
                .any(|w| w.starts_with("dependencies.lock: says ESP-IDF 5.4.0")),
            "{text:?}"
        );
    }

    #[test]
    fn other_idf_tag_warns_and_drops_upstream_cpe() {
        let mut b = build(None, "CONFIG_LWIP_ENABLE=y\n", Some(MAP));
        b.description.git_revision = Some("v5.4".into());
        let out = map(&b, &table::builtin().unwrap()).unwrap();
        let idf = component(&out.product, IDF_COMPONENT);
        assert_eq!(idf.version.as_deref(), Some("5.4"));
        assert_eq!(idf.cpe, None, "5.4 is not X.Y.Z");
        let lwip = idf.components.iter().find(|c| c.name == "lwip").unwrap();
        assert_eq!(lwip.version.as_deref(), Some("5.4"));
        assert_eq!(lwip.cpe, None);
        // Without one: the esp-idf purl with its directory as subpath.
        assert!(
            lwip.purl
                .as_ref()
                .unwrap()
                .as_str()
                .ends_with("@5.4?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-idf#components/lwip/lwip"),
            "{:?}",
            lwip.purl
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.message.contains("checked against v5.5.1"))
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.message.contains("upstream version"))
        );
    }

    #[test]
    fn ingesting_twice_is_identical() {
        let t = table::builtin().unwrap();
        let a = map(&build(None, SDK, Some(MAP)), &t).unwrap();
        let b = map(&build(None, SDK, Some(MAP)), &t).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.product.to_json().unwrap(), b.product.to_json().unwrap());
    }

    #[test]
    fn version_header_is_read() {
        assert_eq!(
            version_from_header("#define ESP_IDF_VERSION_MAJOR   5\n#define ESP_IDF_VERSION_MINOR 5\n#define ESP_IDF_VERSION_PATCH 1\n").as_deref(),
            Some("5.5.1")
        );
        assert_eq!(
            version_from_header("#define ESP_IDF_VERSION_MAJOR 5\n"),
            None
        );
        assert_eq!(
            version_from_header(
                "#define ESP_IDF_VERSION_MAJOR x\n#define ESP_IDF_VERSION_MINOR 5\n#define ESP_IDF_VERSION_PATCH 1\n"
            ),
            None
        );
        assert_eq!(managed_dir_name("espressif/mdns"), "espressif__mdns");
    }

    /// The lock's git-sourced component without a commit (unit test of the mapping; the
    /// parser test is `dependencies_lock::tests::git_source_without_commit_is_kept_and_warned`).
    pub(super) fn git_without_commit() -> EspIdfIngest {
        map(
            &build(
                Some("dependencies:\n  esp_jpeg:\n    source:\n      git: https://github.com/espressif/idf-extra-components.git\n      path: esp_jpeg\n      type: git\n    version: main\ndirect_dependencies: [esp_jpeg]\n"),
                SDK,
                None,
            ),
            &table::builtin().unwrap(),
        )
        .unwrap()
    }
}
