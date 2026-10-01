//! Zephyr ingestion: one Zephyr image build directory → the component graph.
//!
//! [`ingest`] reads the build metadata Zephyr and west leave behind, parses each file with a
//! panic-free parser ([`spdx`], [`west_list`], [`kconfig`], [`build_info`]) and maps the
//! result into a [`Product`] with one application [`Image`](crate::model::Image).
//!
//! ```no_run
//! use rollcall_core::zephyr::{self, IngestOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let options = IngestOptions::new("build/app").with_west_list("west-list.txt");
//! let ingest = zephyr::ingest(&options)?;
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
//! The build directory is an *image* build directory, the one holding `build_info.yml` and
//! `spdx/` (with sysbuild, `build/<image>/`, not the top-level `build/`, which is rejected
//! with [`ZephyrError::NotAnImageBuild`] naming the `MAIN` image directory to pass instead).
//!
//! | File | Required | Used for |
//! |------|----------|----------|
//! | `build_info.yml` | yes | application name, Zephyr version fallback, toolchain name |
//! | `spdx/zephyr.spdx` | yes | Zephyr and every module: version, download location, purl, cpe, licence, supplier |
//! | `spdx/app.spdx` | no (warning) | the application's concluded licence |
//! | `spdx/build.spdx` | no (warning) | parsed and checked only |
//! | `spdx/modules-deps.spdx` | no (warning) | upstream module version, purl, cpe, supplier; which modules Zephyr depends on |
//! | `zephyr/.config` | no (warning) | `CONFIG_ZEPHYR_<MODULE>_MODULE=y` name evidence; the SDK version |
//! | `--west-list FILE` | no (warning) | module revisions and URLs from `west list -f "{name} {path} {revision} {url}"` |
//! | `--identifier-db FILE` | no | each module's upstream version, purl, cpe and supplier, from an [identifier database](crate::identify) |
//! | `--workspace DIR` | no | the west workspace, so `file_regex` and `git_tag` rules can read a module's sources at `DIR/<west list path>` |
//!
//! `spdx/` is written by `west spdx` after a build configured with
//! `west spdx --init`; `west list` output has to be captured separately.
//!
//! With [`IngestOptions::sysbuild`] the directory is instead the sysbuild top-level build
//! directory. [`discover`] reads the images from its `build_info.yml` (`cmake.images[]`:
//! `name` is the image's subdirectory, `type` `MAIN` marks the application); `domains.yaml` is
//! not read, because its `build_dir`s are absolute build-machine paths. Each image directory
//! is ingested as above (the `--west-list` file, `--include-sdk` and the identifier database
//! apply to every image, and
//! each warning's location is prefixed with `<image>: `), and the products are merged with
//! [`merge::merge`](crate::merge::merge) under a product named after the `MAIN` image's
//! application, exactly as `rollcall merge --product <app>` would merge separately generated
//! documents.
//!
//! # Mapping
//!
//! | Input | Model |
//! |-------|-------|
//! | last component of `cmake.application.source-dir` | [`Product`] name, and the name of its one `application` image |
//! | `CONFIG_MCUBOOT=y` in `zephyr/.config` (without a `.config`: `cmake.application.source-dir` ending in `mcuboot/boot/zephyr`) | an MCUboot build: product `mcuboot` and one unversioned `bootloader` image named `mcuboot`, with `kconfig` name evidence at the symbol's line and `build-info` name evidence when the source directory is MCUboot's |
//! | `app-sources` `PackageLicenseConcluded` | the image's `licence` |
//! | `zephyr.spdx` package `zephyr` | component `operating-system` `zephyr`: `version` = `PackageVersion` (else `cmake.zephyr.version`), `purl`/`cpe` from `ExternalRef`, `licence`, `supplier`; the commit-pinned `pkg:github/…@<sha>` from `PackageDownloadLocation` is `purl` evidence |
//! | each `zephyr.spdx` `<module>-sources` package (this decides which modules exist) | exactly one `library` component named after the module, `version` = the git revision (its `west list` row first, else SPDX) |
//! | a `west list` row for Zephyr itself (named `zephyr`, or with Zephyr's URL, as in a T2 workspace) | `version` and `purl` evidence on the `zephyr` component, not a module |
//! | any other `west list` row with no `<name>-sources` package | nothing; a [`Warning`] |
//! | `modules-deps.spdx` `<module>-deps` (joined by SPDXID stem) | the module's `purl` (upstream), `cpe`, `supplier`, and its upstream version as `version` evidence |
//! | module with no upstream purl | a derived `pkg:github/<owner>/<repo>@<rev>` (or `pkg:generic/<name>@<rev>?vcs_url=…`) purl |
//! | module `PackageLicenseConcluded` | the module's `licence` when it is an asserted, valid expression |
//! | `CONFIG_ZEPHYR_<MODULE>_MODULE=y` | `name` evidence on that module |
//! | identifier-database entry for the module (only with `--identifier-db`) | `version`, `purl` and `cpe` evidence from source `identifier-db` at the database's file name, with the [`Level`](crate::identify::Level)'s confidence (technique `source-code-analysis` for a `file_regex` rule, else `manifest-analysis`), and `supplier` evidence, which the database asserts outright (`manifest-analysis`, `High`); the module's `purl`, `cpe` and `supplier` when `modules-deps.spdx` gave none (a purl that differs from the `modules-deps.spdx` one is a warning, and the SPDX one is kept; a differing cpe or supplier is not a warning). The module's `version` stays the git revision |
//! | module missing from the identifier database | a warning, once per module per run (across every sysbuild image), and a paste-ready stub entry in [`Ingest::unknown_modules`] |
//! | `--include-sdk` | component `application` `zephyr-sdk` (or `<toolchain>-toolchain`), version `M.N` from `CONFIG_TOOLCHAIN_ZEPHYR_<M>_<N>` |
//! | — | dependencies: product → image; image → `zephyr` (and the SDK); `zephyr` → each module that `modules-deps.spdx` says is a `DEPENDENCY_OF SPDXRef-zephyr-deps` (every module when that file is missing) |
//!
//! Every fact carries evidence with technique `manifest-analysis` (except as noted for the
//! identifier database) and a source of `west-spdx`, `west-list`, `kconfig`, `build-info` or
//! `identifier-db`, located at the file (relative to the
//! build directory, or the `--west-list` file's name) and line it came from.
//!
//! # Warnings
//!
//! Missing optional inputs, and values that cannot be used (an unparsable licence, purl or
//! cpe, a module whose revision differs between `west list` and SPDX, a `west list` project
//! that is not a module of this build, a module the identifier database does not list or
//! cannot version), are reported as [`Warning`]s, never errors. Warnings
//! come in a fixed order: `spdx/app.spdx`, `spdx/build.spdx`, `spdx/modules-deps.spdx`,
//! `zephyr/.config`, the west list, then the mapping's warnings sorted by file, line number
//! and message. Missing or malformed *required* input, a malformed optional file that is
//! present, and a missing or malformed identifier database, is a [`ZephyrError`] naming the
//! file.
//!
//! # Determinism
//!
//! The same files give the same [`Product`]: modules are keyed by name in sorted maps,
//! evidence and components live in sorted sets, and nothing depends on directory iteration
//! order, the absolute build path or the clock.

pub mod build_info;
pub mod kconfig;
mod map;
pub mod spdx;
mod sysbuild;
pub mod west_list;

use std::io;
use std::path::{Path, PathBuf};

use crate::identify::{self, IdentifierDb, LoadError, Resolver};
use crate::model::{ModelError, Product};

pub use crate::warning::Warning;
pub use build_info::{BuildInfo, BuildInfoError};
pub use kconfig::{Kconfig, KconfigError};
pub use spdx::{SpdxDocument, SpdxError};
pub use sysbuild::{SysbuildImage, discover, ingest_sysbuild};
pub use west_list::{WestList, WestListError};

/// What to ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestOptions {
    /// The image build directory (holding `build_info.yml` and `spdx/`).
    pub build_dir: PathBuf,
    /// A file holding `west list -f "{name} {path} {revision} {url}"` output, if any.
    pub west_list: Option<PathBuf>,
    /// Whether to add the SDK / toolchain as a component.
    pub include_sdk: bool,
    /// Whether `build_dir` is a sysbuild top-level build directory whose images (found from
    /// its `build_info.yml`) are ingested and merged into one product.
    pub sysbuild: bool,
    /// An identifier database to resolve modules' upstream identities with, if any.
    pub identifier_db: Option<PathBuf>,
    /// The west workspace (topdir), where module sources live at their `west list` path.
    pub workspace: Option<PathBuf>,
}

impl IngestOptions {
    /// Options for this build directory, with no west list and no SDK component.
    pub fn new(build_dir: impl Into<PathBuf>) -> Self {
        Self {
            build_dir: build_dir.into(),
            west_list: None,
            include_sdk: false,
            sysbuild: false,
            identifier_db: None,
            workspace: None,
        }
    }

    /// Reads `west list` output from `path`.
    pub fn with_west_list(mut self, path: impl Into<PathBuf>) -> Self {
        self.west_list = Some(path.into());
        self
    }

    /// Adds (or not) the SDK / toolchain as a component.
    pub fn with_include_sdk(mut self, include_sdk: bool) -> Self {
        self.include_sdk = include_sdk;
        self
    }

    /// Treats (or not) the build directory as a sysbuild top-level directory.
    pub fn with_sysbuild(mut self, sysbuild: bool) -> Self {
        self.sysbuild = sysbuild;
        self
    }

    /// Resolves modules with the identifier database at `path`.
    pub fn with_identifier_db(mut self, path: impl Into<PathBuf>) -> Self {
        self.identifier_db = Some(path.into());
        self
    }

    /// Reads module sources from the west workspace at `dir`.
    pub fn with_workspace(mut self, dir: impl Into<PathBuf>) -> Self {
        self.workspace = Some(dir.into());
        self
    }
}

/// The result of [`ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingest {
    /// The product: the application as root, one application image, Zephyr and its modules.
    pub product: Product,
    /// Non-fatal problems, in the order described under *Warnings* in the module docs.
    pub warnings: Vec<Warning>,
    /// The modules the identifier database does not list, sorted by name, each once (empty
    /// without an identifier database).
    pub unknown_modules: Vec<UnknownModule>,
}

/// A module the identifier database does not list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnknownModule {
    /// The module name.
    pub name: String,
    /// A ready-to-paste entry for the database's `modules:` mapping.
    pub stub: String,
}

/// Everything read from one build directory, parsed but not yet mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZephyrBuild {
    /// `build_info.yml`.
    pub build_info: BuildInfo,
    /// `spdx/zephyr.spdx`.
    pub zephyr_spdx: SpdxDocument,
    /// `spdx/app.spdx`, if present.
    pub app_spdx: Option<SpdxDocument>,
    /// `spdx/build.spdx`, if present.
    pub build_spdx: Option<SpdxDocument>,
    /// `spdx/modules-deps.spdx`, if present.
    pub modules_deps_spdx: Option<SpdxDocument>,
    /// `zephyr/.config`, if present.
    pub config: Option<Kconfig>,
    /// The `west list` output, if given.
    pub west_list: Option<WestList>,
    /// The name the west list is cited by in evidence (its file name).
    pub west_list_location: Option<String>,
    /// The paths each input was read from, for error messages.
    pub paths: InputPaths,
    /// Warnings from loading, in order.
    pub warnings: Vec<Warning>,
}

/// Where each input lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputPaths {
    /// `build_info.yml`.
    pub build_info: PathBuf,
    /// `spdx/zephyr.spdx`.
    pub zephyr_spdx: PathBuf,
    /// `spdx/app.spdx`.
    pub app_spdx: PathBuf,
    /// `spdx/modules-deps.spdx`.
    pub modules_deps_spdx: PathBuf,
    /// `zephyr/.config`.
    pub config: PathBuf,
    /// The west list file, if given.
    pub west_list: Option<PathBuf>,
}

/// Why a build directory could not be ingested. Every variant names a file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZephyrError {
    /// A file could not be read (missing, a directory, no permission, …).
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// A file is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// An SPDX document is malformed.
    #[error("{}: {source}", path.display())]
    Spdx {
        /// The file.
        path: PathBuf,
        /// What is wrong, with the line.
        source: SpdxError,
    },
    /// The `west list` output is malformed.
    #[error("{}: {source}", path.display())]
    WestList {
        /// The file.
        path: PathBuf,
        /// What is wrong, with the line.
        source: WestListError,
    },
    /// The `.config` is malformed.
    #[error("{}: {source}", path.display())]
    Kconfig {
        /// The file.
        path: PathBuf,
        /// What is wrong, with the line.
        source: KconfigError,
    },
    /// `build_info.yml` is malformed.
    #[error("{}: {source}", path.display())]
    BuildInfo {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: BuildInfoError,
    },
    /// The directory is a sysbuild top-level build, not an image build.
    #[error(
        "{}: this is a sysbuild top-level build directory; pass an image build directory instead{}, or pass --sysbuild",
        path.display(),
        main_image.as_ref().map(|m| format!(" (the main image is in {m}/)")).unwrap_or_default()
    )]
    NotAnImageBuild {
        /// Its `build_info.yml`.
        path: PathBuf,
        /// The `MAIN` image's directory name, if listed.
        main_image: Option<String>,
    },
    /// `--sysbuild` was given but the directory's `build_info.yml` is an image build's.
    #[error("{}: not a sysbuild top-level build directory (no cmake.images); omit --sysbuild", path.display())]
    NotASysbuild {
        /// Its `build_info.yml`.
        path: PathBuf,
    },
    /// The sysbuild `build_info.yml` lists no images.
    #[error("{}: cmake.images lists no images", path.display())]
    NoImages {
        /// Its `build_info.yml`.
        path: PathBuf,
    },
    /// The sysbuild `build_info.yml` lists no image of type `MAIN`.
    #[error("{}: cmake.images has no image of type MAIN", path.display())]
    NoMainImage {
        /// Its `build_info.yml`.
        path: PathBuf,
    },
    /// A sysbuild image name cannot be used as a build subdirectory name.
    #[error("{}: image name {name:?} is not a plain directory name", path.display())]
    InvalidImageName {
        /// Its `build_info.yml`.
        path: PathBuf,
        /// The rejected name.
        name: String,
    },
    /// The sysbuild `build_info.yml` lists two images with the same name.
    #[error("{}: cmake.images lists image {name:?} twice", path.display())]
    DuplicateImageName {
        /// Its `build_info.yml`.
        path: PathBuf,
        /// The repeated name.
        name: String,
    },
    /// Two sysbuild images ingest to the same image identity (kind, name, version), so they
    /// cannot be told apart in one product.
    #[error(
        "{}: images {} and {} both ingest to the image {image}; rollcall cannot tell them apart",
        path.display(),
        first.display(),
        second.display()
    )]
    DuplicateImage {
        /// The top-level `build_info.yml`.
        path: PathBuf,
        /// The shared identity, `kind:name[@version]`.
        image: String,
        /// The first image build directory.
        first: PathBuf,
        /// The second image build directory.
        second: PathBuf,
    },
    /// The images of a sysbuild build could not be merged into one product.
    #[error("{}: {source}", path.display())]
    Merge {
        /// The sysbuild top-level directory.
        path: PathBuf,
        /// Why (boxed to keep the error small).
        source: Box<crate::merge::Error>,
    },
    /// `spdx/zephyr.spdx` has no `zephyr` package.
    #[error("{}: no package named zephyr (SPDXID SPDXRef-zephyr-sources)", path.display())]
    MissingZephyrPackage {
        /// The file.
        path: PathBuf,
    },
    /// The identifier database is missing, unreadable or malformed.
    #[error("{source}")]
    IdentifierDb {
        /// The database file.
        path: PathBuf,
        /// What is wrong, naming the file (and line, where known).
        source: LoadError,
    },
    /// A value read from this file is rejected by the model.
    #[error("{}: {source}", path.display())]
    Model {
        /// The file the value came from.
        path: PathBuf,
        /// The model's objection.
        source: ModelError,
    },
}

impl ZephyrError {
    /// True when a file does not exist (the CLI reports this as "no input", exit 66).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Read { source, .. } if source.kind() == io::ErrorKind::NotFound)
    }

    /// True for any read failure (missing, unreadable, a directory).
    pub fn is_read_error(&self) -> bool {
        match self {
            Self::Read { .. } => true,
            Self::IdentifierDb { source, .. } => source.is_read_error(),
            _ => false,
        }
    }
}

/// Reads a file as UTF-8 text.
fn read_text(path: &Path) -> Result<String, ZephyrError> {
    let bytes = std::fs::read(path).map_err(|source| ZephyrError::Read {
        path: path.to_owned(),
        source,
    })?;
    String::from_utf8(bytes).map_err(|_| ZephyrError::NotUtf8 {
        path: path.to_owned(),
    })
}

/// Reads an optional file: `Ok(None)` (and a warning) when it does not exist.
fn read_optional(
    path: &Path,
    location: &str,
    consequence: &str,
    warnings: &mut Vec<Warning>,
) -> Result<Option<String>, ZephyrError> {
    match read_text(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.is_not_found() => {
            warnings.push(Warning::new(location, format!("not found; {consequence}")));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn parse_spdx(path: &Path, text: &str) -> Result<SpdxDocument, ZephyrError> {
    spdx::parse(text).map_err(|source| ZephyrError::Spdx {
        path: path.to_owned(),
        source,
    })
}

/// Reads and parses every input in the build directory, without mapping.
pub fn load(options: &IngestOptions) -> Result<ZephyrBuild, ZephyrError> {
    let dir = &options.build_dir;
    let paths = InputPaths {
        build_info: dir.join("build_info.yml"),
        zephyr_spdx: dir.join("spdx").join("zephyr.spdx"),
        app_spdx: dir.join("spdx").join("app.spdx"),
        modules_deps_spdx: dir.join("spdx").join("modules-deps.spdx"),
        config: dir.join("zephyr").join(".config"),
        west_list: options.west_list.clone(),
    };
    let build_spdx_path = dir.join("spdx").join("build.spdx");
    let mut warnings = Vec::new();

    let build_info = build_info::parse(&read_text(&paths.build_info)?).map_err(|source| {
        ZephyrError::BuildInfo {
            path: paths.build_info.clone(),
            source,
        }
    })?;
    if build_info.is_sysbuild() {
        return Err(ZephyrError::NotAnImageBuild {
            path: paths.build_info.clone(),
            main_image: build_info.main_image().map(str::to_owned),
        });
    }

    let zephyr_spdx = parse_spdx(&paths.zephyr_spdx, &read_text(&paths.zephyr_spdx)?)?;

    let app_spdx = read_optional(
        &paths.app_spdx,
        "spdx/app.spdx",
        "application licence not recorded",
        &mut warnings,
    )?
    .map(|text| parse_spdx(&paths.app_spdx, &text))
    .transpose()?;
    let build_spdx = read_optional(
        &build_spdx_path,
        "spdx/build.spdx",
        "build document not checked",
        &mut warnings,
    )?
    .map(|text| parse_spdx(&build_spdx_path, &text))
    .transpose()?;
    let modules_deps_spdx = read_optional(
        &paths.modules_deps_spdx,
        "spdx/modules-deps.spdx",
        "no upstream module versions, purls or cpes; Zephyr is taken to depend on every module",
        &mut warnings,
    )?
    .map(|text| parse_spdx(&paths.modules_deps_spdx, &text))
    .transpose()?;
    let config = read_optional(
        &paths.config,
        "zephyr/.config",
        "no Kconfig module evidence or SDK version",
        &mut warnings,
    )?
    .map(|text| {
        kconfig::parse(&text).map_err(|source| ZephyrError::Kconfig {
            path: paths.config.clone(),
            source,
        })
    })
    .transpose()?;

    let (west_list, west_list_location) = match &options.west_list {
        None => {
            warnings.push(Warning::new(
                "west list",
                "not given (--west-list); module revisions come from spdx/zephyr.spdx only",
            ));
            (None, None)
        }
        Some(path) => {
            let list =
                west_list::parse(&read_text(path)?).map_err(|source| ZephyrError::WestList {
                    path: path.clone(),
                    source,
                })?;
            let location = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "west-list".to_owned());
            (Some(list), Some(location))
        }
    };

    Ok(ZephyrBuild {
        build_info,
        zephyr_spdx,
        app_spdx,
        build_spdx,
        modules_deps_spdx,
        config,
        west_list,
        west_list_location,
        paths,
        warnings,
    })
}

/// Loads [`IngestOptions::identifier_db`], if given.
pub fn load_identifier_db(options: &IngestOptions) -> Result<Option<IdentifierDb>, ZephyrError> {
    options
        .identifier_db
        .as_deref()
        .map(|path| {
            identify::load(path).map_err(|source| ZephyrError::IdentifierDb {
                path: path.to_owned(),
                source,
            })
        })
        .transpose()
}

/// Reads, parses and maps one Zephyr image build directory, or, with
/// [`IngestOptions::sysbuild`], every image of a sysbuild top-level build directory merged
/// into one product ([`ingest_sysbuild`]).
pub fn ingest(options: &IngestOptions) -> Result<Ingest, ZephyrError> {
    if options.sysbuild {
        return ingest_sysbuild(options);
    }
    let db = load_identifier_db(options)?;
    let mut resolver = db.as_ref().map(Resolver::new);
    ingest_image(options, resolver.as_mut())
}

/// Reads, parses and maps one image build directory, resolving modules with `resolver`.
fn ingest_image(
    options: &IngestOptions,
    resolver: Option<&mut Resolver<'_>>,
) -> Result<Ingest, ZephyrError> {
    let build = load(options)?;
    map::to_product(&build, options, resolver)
}
