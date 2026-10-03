//! Cargo ingestion: `cargo metadata` and a `cargo auditable` binary → the component graph.
//!
//! [`ingest`] reads the dependency graph `cargo metadata --format-version 1` resolves for one
//! target and, when a binary built with `cargo auditable` is given, the `.dep-v0` section
//! embedded in it, and maps them into a [`Product`] with one application
//! [`Image`] holding one `library` component per crate.
//!
//! ```no_run
//! use rollcall_core::cargo::{self, CargoOptions};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let options = CargoOptions::from_metadata_file("cargo-metadata.json")
//!     .with_elf("target/thumbv7em-none-eabihf/release/app");
//! let ingest = cargo::ingest(&options)?;
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
//! | Input | Required | Used for |
//! |-------|----------|----------|
//! | `cargo metadata --format-version 1 [--filter-platform <target>]` output: a file ([`CargoOptions::from_metadata_file`]), or the output of [`metadata_command`] ([`CargoOptions::from_metadata_text`]) | yes | the root package; every package's name, version, source and `license`; the resolve graph's edges, their kinds and each package's enabled features |
//! | an ELF built with `cargo auditable` ([`CargoOptions::with_elf`]) | no (warning) | its `.dep-v0` section: exactly the crates that went into the binary |
//!
//! [`metadata_command`] runs `cargo metadata` in the package directory, so the package's own
//! `.cargo/config.toml` applies. Cargo may use the network to resolve it (a source it has not
//! cached); it honours `CARGO_NET_OFFLINE`.
//!
//! The metadata should be resolved for the binary's target (`--filter-platform`, which
//! [`metadata_command`] passes for a `target`); unfiltered metadata also lists every other
//! platform's dependencies. A virtual workspace (no `resolve.root`) is an error
//! ([`CargoError::NoRootPackage`]): run `cargo metadata` in the binary's package.
//!
//! # Mapping
//!
//! | Input | Model |
//! |-------|-------|
//! | `resolve.root` | the [`Product`] (name, version, licence) and its one `application` image of the same name and version, with the root's purl and licence |
//! | with an ELF: each `.dep-v0` package other than the root, joined to its metadata package by (name, version, source class) | one `library` component (build-kind entries included, so the components equal the `.dep-v0` list) |
//! | without an ELF: each package the root reaches through normal and build edges (what `cargo tree -e normal,build` lists) | one `library` component, and a warning |
//! | with [`CargoOptions::with_include_unlinked`]: every other resolve package (dev-only crates, crates the binary does not link, other platforms' crates in unfiltered metadata) | one `library` component with [`Scope::Excluded`] |
//! | a `.dep-v0` package with no metadata package | a component from `.dep-v0` alone (purl from its source class), and a warning |
//! | package source | `purl`: crates.io `pkg:cargo/<name>@<version>`; another registry the same with `repository_url`; git `pkg:generic/<name>@<version>?vcs_url=git+<url>@<commit>`; path `pkg:generic/<name>@<version>` (no host path) |
//! | `license` | `licence` when it is an SPDX expression; Cargo's legacy `A/B` form becomes `A OR B` (each part parenthesised when a part holds `AND`, `OR` or `WITH`) |
//! | `resolve.nodes[].deps` | dependency edges between emitted crates along normal and build edges (a dev edge only to a crate emitted as excluded, never to one that ships); the image depends on the root's direct dependencies; product → image |
//! | two emitted crates with the same name and version from different sources | [`CargoError::DuplicateCrate`] |
//!
//! Evidence, all at the input's file name (never a build-machine path):
//!
//! - source `cargo-metadata`, technique `manifest-analysis`, confidence 0.9: `name`,
//!   `version`, `purl` and `licence` (the raw `license` text), and one `name` entry with value
//!   `feature:<feature>` per feature cargo enabled on the crate;
//! - source `cargo-auditable`, technique `binary-analysis`, confidence 0.95: `name` and
//!   `version` for every crate the binary's `.dep-v0` lists.
//!
//! Features are cargo's unified features for the resolve: with resolver 2 a crate built both
//! for the host and the target shows the union of both, not each build's own set.
//!
//! # Warnings
//!
//! Non-fatal problems are [`Warning`]s, sorted by location and message: no ELF given, a
//! `license` that is not an SPDX expression (the licence is omitted), a git source whose
//! revision is not a full 40-hex commit (the purl's `vcs_url` has no revision), and a `.dep-v0` package
//! cargo metadata does not list. A missing or malformed metadata file or ELF, an ELF with no
//! `.dep-v0` section, a `.dep-v0` root that is not the metadata root, and two metadata
//! packages the binary's list cannot tell apart are a [`CargoError`] naming the file.
//!
//! # Determinism
//!
//! The same inputs give the same [`Product`]: packages are keyed by id in sorted maps,
//! components and evidence live in sorted sets, and nothing depends on the absolute build
//! path, the clock or iteration order. Package ids, which hold build-machine paths for path
//! packages, are never written out.

pub mod auditable;
pub mod match_linked;
pub mod metadata;
pub mod purl;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::model::{
    BomRef, Component, ComponentKind, Confidence, Evidence, EvidenceField, Image, ImageKind,
    License, Occurrence, PathSegment, Product, Purl, Scope, Technique,
};
pub use crate::warning::Warning;
pub use auditable::{AuditableError, DepV0};
pub use match_linked::MatchError;
pub use metadata::{Metadata, MetadataError};

/// Evidence source for facts read from `cargo metadata`.
pub const METADATA_SOURCE: &str = "cargo-metadata";
/// Evidence source for facts read from a binary's `.dep-v0` section.
pub const AUDITABLE_SOURCE: &str = "cargo-auditable";
/// The occurrence location of metadata read from `cargo metadata` run in the manifest
/// directory (it resolves `Cargo.lock`).
pub const LOCKFILE_LOCATION: &str = "Cargo.lock";

/// The largest `cargo metadata` file read: 256 MiB.
pub const MAX_METADATA_BYTES: u64 = 256 * 1024 * 1024;

const METADATA_CONFIDENCE: u16 = 9000;
const AUDITABLE_CONFIDENCE: u16 = 9500;

/// Where the `cargo metadata` output comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataInput {
    /// A file holding `cargo metadata --format-version 1` output.
    File(PathBuf),
    /// Output already captured, e.g. from [`metadata_command`]; `location` is how evidence
    /// cites it (a relative path such as [`LOCKFILE_LOCATION`]).
    Text {
        /// The JSON.
        text: String,
        /// How evidence cites it.
        location: String,
    },
}

/// What to ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoOptions {
    /// The `cargo metadata` output.
    pub metadata: MetadataInput,
    /// A binary built with `cargo auditable`, if any.
    pub elf: Option<PathBuf>,
    /// Whether to emit crates that are in the metadata but not linked, as
    /// [`Scope::Excluded`].
    pub include_unlinked: bool,
}

impl CargoOptions {
    /// Options reading `cargo metadata` output from `path`.
    pub fn from_metadata_file(path: impl Into<PathBuf>) -> Self {
        Self {
            metadata: MetadataInput::File(path.into()),
            elf: None,
            include_unlinked: false,
        }
    }

    /// Options for `cargo metadata` output already captured; `location` is how evidence
    /// cites it.
    pub fn from_metadata_text(text: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            metadata: MetadataInput::Text {
                text: text.into(),
                location: location.into(),
            },
            elf: None,
            include_unlinked: false,
        }
    }

    /// Reads the linked crate list from the `.dep-v0` section of the binary at `path`.
    pub fn with_elf(mut self, path: impl Into<PathBuf>) -> Self {
        self.elf = Some(path.into());
        self
    }

    /// Emits (or not) crates that are not linked, with [`Scope::Excluded`].
    pub fn with_include_unlinked(mut self, include_unlinked: bool) -> Self {
        self.include_unlinked = include_unlinked;
        self
    }
}

/// The result of [`ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoIngest {
    /// The product: the root package, one application image and one component per crate.
    pub product: Product,
    /// Non-fatal problems, sorted.
    pub warnings: Vec<Warning>,
}

/// Why the inputs could not be ingested. Every variant names its input.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CargoError {
    /// A file could not be read (missing, a directory, no permission, …).
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// The metadata file is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// The metadata file is larger than [`MAX_METADATA_BYTES`].
    #[error("{}: larger than {MAX_METADATA_BYTES} bytes", path.display())]
    MetadataTooLarge {
        /// The file.
        path: PathBuf,
    },
    /// Two crates with the same name and version, from different sources, are both emitted:
    /// they would be one component.
    #[error(
        "{input}: {name}@{version} comes from two sources ({first}, {second}); rollcall cannot list both as one component"
    )]
    DuplicateCrate {
        /// The metadata.
        input: String,
        /// The crate name.
        name: String,
        /// The crate version.
        version: String,
        /// One source's purl.
        first: String,
        /// The other's.
        second: String,
    },
    /// The metadata is malformed.
    #[error("{input}: {source}")]
    Metadata {
        /// The metadata file, or how the captured text is cited.
        input: String,
        /// What is wrong.
        source: MetadataError,
    },
    /// The ELF's `.dep-v0` section is missing or malformed.
    #[error("{}: {source}", path.display())]
    Auditable {
        /// The ELF.
        path: PathBuf,
        /// What is wrong.
        source: AuditableError,
    },
    /// The metadata has no root package (a virtual workspace).
    #[error(
        "{input}: no root package (resolve.root is null, a virtual workspace); run cargo metadata in the binary's package"
    )]
    NoRootPackage {
        /// The metadata.
        input: String,
    },
    /// The ELF was built from another package than the metadata's root.
    #[error("{}: built from {elf_root}, but the cargo metadata root is {metadata_root}", path.display())]
    RootMismatch {
        /// The ELF.
        path: PathBuf,
        /// The `.dep-v0` root, `name@version`.
        elf_root: String,
        /// The metadata root, `name@version`.
        metadata_root: String,
    },
    /// The `.dep-v0` list cannot be joined with the metadata.
    #[error("{}: {source}", path.display())]
    Match {
        /// The ELF.
        path: PathBuf,
        /// What is ambiguous.
        source: MatchError,
    },
    /// A value is rejected by the model (an invalid name or version, or two crates with the
    /// same name and version that disagree).
    #[error("{input}: {message}")]
    Model {
        /// The metadata.
        input: String,
        /// The model's objection.
        message: String,
    },
}

impl CargoError {
    /// Whether this is a missing or unreadable input, rather than a malformed one.
    pub fn is_read_error(&self) -> bool {
        matches!(self, Self::Read { .. })
    }
}

/// The `cargo metadata` command for the package in `manifest_dir`, resolved for `target`
/// (`--filter-platform`) when given: `<cargo> metadata --format-version 1 --locked
/// --manifest-path <dir>/Cargo.toml [--filter-platform <target>]`, run in `manifest_dir` so
/// the package's own `.cargo/config.toml` (patches, source replacement, registries) applies.
/// `--locked` keeps the resolution the one `Cargo.lock` records. Cargo may use the network
/// (e.g. to download a git or registry source it has not cached); it honours
/// `CARGO_NET_OFFLINE`, which the command inherits.
pub fn metadata_command(cargo: &OsStr, manifest_dir: &Path, target: Option<&str>) -> Command {
    // Absolute, so a relative directory is not resolved twice once it is the working
    // directory.
    let dir = std::path::absolute(manifest_dir).unwrap_or_else(|_| manifest_dir.to_path_buf());
    let mut command = Command::new(cargo);
    command.current_dir(&dir);
    command
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(dir.join("Cargo.toml"));
    if let Some(target) = target {
        command.arg("--filter-platform").arg(target);
    }
    command
}

/// The inputs, read and parsed.
struct CargoBuild {
    metadata: Metadata,
    /// How errors name the metadata.
    metadata_input: String,
    /// How evidence cites the metadata.
    metadata_location: String,
    dep_v0: Option<(DepV0, PathBuf, String)>,
}

/// The file name of `path`, as evidence cites it.
fn file_location(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "input".to_owned())
}

fn load(options: &CargoOptions) -> Result<CargoBuild, CargoError> {
    let (text, metadata_input, metadata_location) = match &options.metadata {
        MetadataInput::File(path) => {
            let read_err = |source| CargoError::Read {
                path: path.clone(),
                source,
            };
            if std::fs::metadata(path).map_err(read_err)?.len() > MAX_METADATA_BYTES {
                return Err(CargoError::MetadataTooLarge { path: path.clone() });
            }
            let bytes = std::fs::read(path).map_err(read_err)?;
            let text =
                String::from_utf8(bytes).map_err(|_| CargoError::NotUtf8 { path: path.clone() })?;
            (text, path.display().to_string(), file_location(path))
        }
        MetadataInput::Text { text, location } => {
            (text.clone(), location.clone(), location.clone())
        }
    };
    let metadata = metadata::parse(&text).map_err(|source| CargoError::Metadata {
        input: metadata_input.clone(),
        source,
    })?;
    let dep_v0 = match &options.elf {
        None => None,
        Some(path) => {
            let read_err = |source| CargoError::Read {
                path: path.clone(),
                source,
            };
            let size = std::fs::metadata(path).map_err(read_err)?.len();
            if size > auditable::MAX_BINARY_BYTES {
                return Err(CargoError::Auditable {
                    path: path.clone(),
                    source: AuditableError::BinaryTooLarge,
                });
            }
            let bytes = std::fs::read(path).map_err(read_err)?;
            let dep_v0 = auditable::read(&bytes).map_err(|source| CargoError::Auditable {
                path: path.clone(),
                source,
            })?;
            Some((dep_v0, path.clone(), file_location(path)))
        }
    };
    Ok(CargoBuild {
        metadata,
        metadata_input,
        metadata_location,
        dep_v0,
    })
}

/// Reads the inputs and maps them into a product (see the module docs).
pub fn ingest(options: &CargoOptions) -> Result<CargoIngest, CargoError> {
    let build = load(options)?;
    to_product(&build, options.include_unlinked)
}

/// Cargo's licence field in SPDX form: as written when valid, else with the legacy `/`
/// separator rewritten to `OR`. When a `/`-separated part holds an operator (`AND`, `OR`,
/// `WITH`), each part is parenthesised, so `A/B AND C` is `(A) OR (B AND C)`, never `A OR B
/// AND C`. `None` when that is not valid either.
fn normalise_licence(raw: &str) -> Option<License> {
    let raw = raw.trim();
    if let Ok(licence) = License::new(raw) {
        return Some(licence);
    }
    if !raw.contains('/') {
        return None;
    }
    let parts: Vec<&str> = raw.split('/').map(str::trim).collect();
    let has_operator = parts.iter().any(|p| {
        p.split_whitespace()
            .any(|w| matches!(w, "AND" | "OR" | "WITH"))
    });
    let rewritten = if has_operator {
        parts
            .iter()
            .map(|p| format!("({p})"))
            .collect::<Vec<_>>()
            .join(" OR ")
    } else {
        parts.join(" OR ")
    };
    License::new(&rewritten).ok()
}

/// One emitted crate: its component and where it came from.
enum Origin<'a> {
    /// A metadata package (and whether `.dep-v0` lists it).
    Metadata { id: &'a str, linked: bool },
    /// A `.dep-v0` package cargo metadata does not list.
    DepV0Only { index: usize },
}

/// A package's purl, licence and evidence.
type PackageFacts = (Option<Purl>, Option<License>, Vec<Evidence>);

struct Mapper<'a> {
    build: &'a CargoBuild,
    warnings: Vec<Warning>,
}

impl<'a> Mapper<'a> {
    fn model_err(&self, e: impl std::fmt::Display) -> CargoError {
        CargoError::Model {
            input: self.build.metadata_input.clone(),
            message: e.to_string(),
        }
    }

    fn evidence(
        &self,
        field: EvidenceField,
        technique: Technique,
        source: &str,
        value: &str,
        bp: u16,
        location: &str,
    ) -> Result<Evidence, CargoError> {
        let confidence = Confidence::new(bp).map_err(|e| self.model_err(e))?;
        let occurrence = Occurrence::new(location, None).map_err(|e| self.model_err(e))?;
        Ok(Evidence::new(field, technique, source, value, confidence)
            .map_err(|e| self.model_err(e))?
            .at(occurrence))
    }

    fn metadata_evidence(&self, field: EvidenceField, value: &str) -> Result<Evidence, CargoError> {
        self.evidence(
            field,
            Technique::ManifestAnalysis,
            METADATA_SOURCE,
            value,
            METADATA_CONFIDENCE,
            &self.build.metadata_location,
        )
    }

    fn auditable_evidence(
        &self,
        field: EvidenceField,
        value: &str,
    ) -> Result<Option<Evidence>, CargoError> {
        let Some((_, _, location)) = &self.build.dep_v0 else {
            return Ok(None);
        };
        self.evidence(
            field,
            Technique::BinaryAnalysis,
            AUDITABLE_SOURCE,
            value,
            AUDITABLE_CONFIDENCE,
            location,
        )
        .map(Some)
    }

    /// The facts of a metadata package: purl, licence and evidence, applied by `apply`.
    fn package_facts(
        &mut self,
        id: &str,
        linked_in_binary: bool,
    ) -> Result<PackageFacts, CargoError> {
        let metadata = &self.build.metadata;
        let package = metadata
            .packages
            .get(id)
            .ok_or_else(|| self.model_err(format!("unknown package id {id:?}")))?;
        let mut evidence = vec![
            self.metadata_evidence(EvidenceField::Name, &package.name)?,
            self.metadata_evidence(EvidenceField::Version, &package.version)?,
        ];
        if let metadata::SourceKind::Git {
            url,
            commit: None,
            reference,
        } = &package.source
        {
            self.warnings.push(Warning::new(
                self.build.metadata_location.clone(),
                format!(
                    "{}: git source {url} is at {:?}, not a full commit sha; its purl's vcs_url has no revision",
                    package.label(),
                    reference.as_deref().unwrap_or("")
                ),
            ));
        }
        let purl = match purl::purl_for(&package.name, &package.version, &package.source) {
            Ok(purl) => {
                evidence.push(self.metadata_evidence(EvidenceField::Purl, purl.as_str())?);
                Some(purl)
            }
            Err(e) => {
                self.warnings.push(Warning::new(
                    self.build.metadata_location.clone(),
                    format!("{}: no purl ({e})", package.label()),
                ));
                None
            }
        };
        let mut licence = None;
        if let Some(raw) = &package.license {
            evidence.push(self.metadata_evidence(EvidenceField::Licence, raw)?);
            licence = normalise_licence(raw);
            if licence.is_none() {
                self.warnings.push(Warning::new(
                    self.build.metadata_location.clone(),
                    format!(
                        "{}: license {raw:?} is not an SPDX expression; licence omitted",
                        package.label()
                    ),
                ));
            }
        }
        if let Some(node) = metadata.nodes.get(id) {
            for feature in &node.features {
                evidence.push(
                    self.metadata_evidence(EvidenceField::Name, &format!("feature:{feature}"))?,
                );
            }
        }
        if linked_in_binary {
            for (field, value) in [
                (EvidenceField::Name, &package.name),
                (EvidenceField::Version, &package.version),
            ] {
                evidence.extend(self.auditable_evidence(field, value)?);
            }
        }
        Ok((purl, licence, evidence))
    }
}

fn to_product(build: &CargoBuild, include_unlinked: bool) -> Result<CargoIngest, CargoError> {
    let metadata = &build.metadata;
    let root_id = metadata
        .root
        .as_deref()
        .ok_or_else(|| CargoError::NoRootPackage {
            input: build.metadata_input.clone(),
        })?;
    let root = metadata
        .packages
        .get(root_id)
        .ok_or_else(|| CargoError::NoRootPackage {
            input: build.metadata_input.clone(),
        })?;
    let mut mapper = Mapper {
        build,
        warnings: Vec::new(),
    };

    // Which metadata packages are linked, and the `.dep-v0`-only packages.
    let reach = metadata.reach(root_id);
    let mut linked: BTreeSet<&str> = BTreeSet::new();
    let mut dep_only: Vec<usize> = Vec::new();
    let mut dep_index_to_id: BTreeMap<usize, &str> = BTreeMap::new();
    match &build.dep_v0 {
        Some((dep_v0, path, location)) => {
            let dep_root = dep_v0.root().ok_or_else(|| CargoError::Auditable {
                path: path.clone(),
                source: AuditableError::NoRoot,
            })?;
            if (dep_root.name.as_str(), dep_root.version.as_str())
                != (root.name.as_str(), root.version.as_str())
            {
                return Err(CargoError::RootMismatch {
                    path: path.clone(),
                    elf_root: format!("{}@{}", dep_root.name, dep_root.version),
                    metadata_root: root.label(),
                });
            }
            let joined = match_linked::match_linked(metadata, dep_v0).map_err(|source| {
                CargoError::Match {
                    path: path.clone(),
                    source,
                }
            })?;
            for (index, id) in &joined.matched {
                if let Some((id, _)) = metadata.packages.get_key_value(id.as_str()) {
                    dep_index_to_id.insert(*index, id.as_str());
                    if id != root_id {
                        linked.insert(id.as_str());
                    }
                }
            }
            for index in joined.unmatched {
                let Some(p) = dep_v0.packages.get(index) else {
                    continue;
                };
                if p.root {
                    continue;
                }
                mapper.warnings.push(Warning::new(
                    location.clone(),
                    format!(
                        "{}@{} ({}) is in .dep-v0 but not in cargo metadata; its purl is derived from .dep-v0 alone",
                        p.name,
                        p.version,
                        p.source.class()
                    ),
                ));
                dep_only.push(index);
            }
        }
        None => {
            mapper.warnings.push(Warning::new(
                build.metadata_location.clone(),
                "no ELF given: the components are the normal and build dependencies cargo \
                 metadata resolves; pass a binary built with `cargo auditable` to list exactly \
                 what was linked",
            ));
            linked.extend(
                reach
                    .iter()
                    .filter(|(_, r)| **r == metadata::Reach::Linked)
                    .map(|(id, _)| id.as_str()),
            );
        }
    }

    let mut origins: Vec<Origin<'_>> = linked
        .iter()
        .map(|id| Origin::Metadata { id, linked: true })
        .collect();
    if include_unlinked {
        for id in metadata.nodes.keys() {
            if id != root_id && !linked.contains(id.as_str()) {
                origins.push(Origin::Metadata { id, linked: false });
            }
        }
    }
    origins.extend(dep_only.iter().map(|&index| Origin::DepV0Only { index }));

    // The product and its image.
    let mut product = Product::new(&root.name)
        .map_err(|e| mapper.model_err(e))?
        .with_version(&root.version);
    let mut image = Image::new(ImageKind::Application, &root.name)
        .map_err(|e| mapper.model_err(e))?
        .with_version(&root.version);
    let in_binary = build.dep_v0.is_some();
    let (purl, licence, evidence) = mapper.package_facts(root_id, in_binary)?;
    image.purl = purl;
    image.licence = licence.clone();
    image.evidence = evidence.into_iter().collect();
    product.licence = licence;

    // The components, and each emitted node's path for its bom-ref.
    let mut components: Vec<(Option<&str>, Option<usize>, Component)> = Vec::new();
    for origin in origins {
        match origin {
            Origin::Metadata { id, linked } => {
                let package = metadata
                    .packages
                    .get(id)
                    .ok_or_else(|| mapper.model_err(format!("unknown package id {id:?}")))?;
                let mut component = Component::new(ComponentKind::Library, &package.name)
                    .map_err(|e| mapper.model_err(e))?
                    .with_version(&package.version);
                let (purl, licence, evidence) = mapper.package_facts(id, linked && in_binary)?;
                component.purl = purl;
                component.licence = licence;
                component.evidence = evidence.into_iter().collect();
                if !linked {
                    component.scope = Some(Scope::Excluded);
                }
                components.push((Some(id), None, component));
            }
            Origin::DepV0Only { index } => {
                let Some((dep_v0, _, _)) = &build.dep_v0 else {
                    continue;
                };
                let Some(p) = dep_v0.packages.get(index) else {
                    continue;
                };
                let mut component = Component::new(ComponentKind::Library, &p.name)
                    .map_err(|e| mapper.model_err(e))?
                    .with_version(&p.version);
                component.purl = purl::purl_for_dep_v0(&p.name, &p.version, &p.source).ok();
                let mut evidence: Vec<Evidence> = Vec::new();
                for (field, value) in [
                    (EvidenceField::Name, &p.name),
                    (EvidenceField::Version, &p.version),
                ] {
                    evidence.extend(mapper.auditable_evidence(field, value)?);
                }
                component.evidence = evidence.into_iter().collect();
                components.push((None, Some(index), component));
            }
        }
    }

    let product_path = product.path();
    let image_path = product_path.child(PathSegment::of_image(&image));
    let image_ref = BomRef::derive(&image_path);
    let mut by_id: BTreeMap<&str, BomRef> = BTreeMap::from([(root_id, image_ref.clone())]);
    let mut by_dep_index: BTreeMap<usize, BomRef> = BTreeMap::new();
    for (id, index, component) in &components {
        let bom_ref = BomRef::derive(&image_path.child(PathSegment::of_component(component)));
        if let Some(id) = id {
            by_id.insert(id, bom_ref.clone());
        }
        if let Some(index) = index {
            by_dep_index.insert(*index, bom_ref);
        }
    }
    for (index, id) in &dep_index_to_id {
        if let Some(bom_ref) = by_id.get(id) {
            by_dep_index.insert(*index, bom_ref.clone());
        }
    }
    // Two crates with the same name and version (say crates.io and a git fork) would merge
    // into one component; refuse that rather than report one of them.
    let mut seen: BTreeMap<(&str, Option<&str>), &Component> = BTreeMap::new();
    for (_, _, component) in &components {
        if let Some(first) = seen.insert((&component.name, component.version.as_deref()), component)
        {
            let purl = |c: &Component| c.purl.as_ref().map_or("no purl", |p| p.as_str()).to_owned();
            return Err(CargoError::DuplicateCrate {
                input: build.metadata_input.clone(),
                name: component.name.clone(),
                version: component.version.clone().unwrap_or_default(),
                first: purl(first),
                second: purl(component),
            });
        }
    }
    let excluded: BTreeSet<&str> = components
        .iter()
        .filter(|(_, _, c)| c.scope == Some(Scope::Excluded))
        .filter_map(|(id, _, _)| *id)
        .collect();
    for (_, _, component) in components {
        image
            .add_component(component)
            .map_err(|e| mapper.model_err(e))?;
    }

    // Edges: product → image; metadata normal and build edges between emitted nodes; a dev
    // edge (workspace members have them) only to a target emitted as excluded, so a
    // dev-dependency is never written as a runtime `dependsOn` of something that ships;
    // `.dep-v0` edges touching a `.dep-v0`-only package.
    let product_ref = BomRef::derive(&product_path);
    let mut edges: BTreeSet<(BomRef, BomRef)> = BTreeSet::new();
    edges.insert((product_ref, image_ref));
    for (id, from) in &by_id {
        let Some(node) = metadata.nodes.get(*id) else {
            continue;
        };
        for (dep, kinds) in &node.deps {
            let runtime = kinds
                .iter()
                .any(|k| matches!(k, metadata::DepKind::Normal | metadata::DepKind::Build));
            let dev_to_excluded =
                kinds.contains(&metadata::DepKind::Dev) && excluded.contains(dep.as_str());
            if !(runtime || dev_to_excluded) {
                continue;
            }
            if let Some(to) = by_id.get(dep.as_str()) {
                edges.insert((from.clone(), to.clone()));
            }
        }
    }
    if let Some((dep_v0, _, _)) = &build.dep_v0 {
        let only: BTreeSet<usize> = dep_only.iter().copied().collect();
        for (index, p) in dep_v0.packages.iter().enumerate() {
            for dep in &p.dependencies {
                if !only.contains(&index) && !only.contains(dep) {
                    continue;
                }
                if let (Some(from), Some(to)) = (by_dep_index.get(&index), by_dep_index.get(dep)) {
                    edges.insert((from.clone(), to.clone()));
                }
            }
        }
    }
    product.add_image(image).map_err(|e| mapper.model_err(e))?;
    for (from, to) in edges {
        if from != to {
            product.add_dependency(from, to);
        }
    }
    product.validate().map_err(|e| mapper.model_err(e))?;

    let mut warnings = mapper.warnings;
    warnings.sort();
    warnings.dedup();
    Ok(CargoIngest { product, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRATES: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn metadata_json(root: Option<&str>) -> String {
        let root = root.map_or("null".to_owned(), |r| format!("\"{r}\""));
        format!(
            r#"{{"version": 1, "packages": [
              {{"id": "app-id", "name": "app", "version": "0.1.0", "source": null, "license": "MIT/Apache-2.0"}},
              {{"id": "a-id", "name": "a", "version": "1.0.0", "source": "{CRATES}", "license": "MIT"}},
              {{"id": "b-id", "name": "b", "version": "2.0.0", "source": "{CRATES}", "license": "Weird Licence"}},
              {{"id": "dev-id", "name": "dev", "version": "3.0.0", "source": "{CRATES}"}},
              {{"id": "p-id", "name": "p", "version": "0.1.0", "source": null}},
              {{"id": "g-id", "name": "g", "version": "0.2.0", "source": "git+https://github.com/o/g#0123456789abcdef0123456789abcdef01234567"}}
            ], "resolve": {{"root": {root}, "nodes": [
              {{"id": "app-id", "deps": [
                {{"pkg": "a-id", "dep_kinds": [{{"kind": null}}]}},
                {{"pkg": "p-id", "dep_kinds": [{{"kind": null}}]}},
                {{"pkg": "g-id", "dep_kinds": [{{"kind": null}}]}},
                {{"pkg": "dev-id", "dep_kinds": [{{"kind": "dev"}}]}}
              ], "features": ["default"]}},
              {{"id": "a-id", "deps": [{{"pkg": "b-id", "dep_kinds": [{{"kind": null}}]}}], "features": ["std"]}},
              {{"id": "b-id", "deps": [], "features": []}},
              {{"id": "dev-id", "deps": [], "features": []}},
              {{"id": "p-id", "deps": [], "features": []}},
              {{"id": "g-id", "deps": [], "features": []}}
            ]}}}}"#
        )
    }

    fn build(dep_v0: Option<&str>) -> CargoBuild {
        CargoBuild {
            metadata: metadata::parse(&metadata_json(Some("app-id"))).unwrap(),
            metadata_input: "cargo-metadata.json".to_owned(),
            metadata_location: "cargo-metadata.json".to_owned(),
            dep_v0: dep_v0.map(|j| {
                (
                    auditable::parse_json(j).unwrap(),
                    PathBuf::from("app.elf"),
                    "app.elf".to_owned(),
                )
            }),
        }
    }

    const DEP_V0: &str = r#"{"packages":[
        {"name":"a","version":"1.0.0","source":"crates.io","dependencies":[1]},
        {"name":"b","version":"2.0.0","source":"crates.io"},
        {"name":"app","version":"0.1.0","source":"local","dependencies":[0,3,4],"root":true},
        {"name":"p","version":"0.1.0","source":"local"},
        {"name":"g","version":"0.2.0","source":"git"},
        {"name":"extra","version":"5.0.0","source":"crates.io","dependencies":[1]}]}"#;

    fn names(product: &Product) -> BTreeMap<String, Option<Scope>> {
        product
            .images
            .iter()
            .flat_map(|i| &i.components)
            .map(|c| {
                (
                    format!("{}@{}", c.name, c.version.as_deref().unwrap_or("")),
                    c.scope,
                )
            })
            .collect()
    }

    #[test]
    fn with_elf_components_are_the_dep_v0_list() {
        let ingest = to_product(&build(Some(DEP_V0)), false).unwrap();
        let got = names(&ingest.product);
        assert_eq!(
            got.keys().cloned().collect::<Vec<_>>(),
            ["a@1.0.0", "b@2.0.0", "extra@5.0.0", "g@0.2.0", "p@0.1.0"]
        );
        assert!(got.values().all(Option::is_none));
        assert!(
            ingest
                .warnings
                .iter()
                .any(|w| w.location == "app.elf" && w.message.contains("extra@5.0.0"))
        );
    }

    #[test]
    fn include_unlinked_marks_the_dev_only_crate_excluded() {
        let ingest = to_product(&build(Some(DEP_V0)), true).unwrap();
        let got = names(&ingest.product);
        assert_eq!(got["dev@3.0.0"], Some(Scope::Excluded));
        assert_eq!(got["a@1.0.0"], None);
    }

    #[test]
    fn without_elf_the_linked_set_is_normal_and_build_reach() {
        let ingest = to_product(&build(None), false).unwrap();
        let got = names(&ingest.product);
        assert_eq!(
            got.keys().cloned().collect::<Vec<_>>(),
            ["a@1.0.0", "b@2.0.0", "g@0.2.0", "p@0.1.0"]
        );
        assert!(ingest.warnings.iter().any(|w| w.message.contains("no ELF")));
    }

    #[test]
    fn licences_are_normalised_or_warned() {
        let ingest = to_product(&build(None), false).unwrap();
        let image = ingest.product.images.first().unwrap();
        assert_eq!(
            image.licence.as_ref().map(License::as_str),
            Some("MIT OR Apache-2.0")
        );
        let b = image.components.iter().find(|c| c.name == "b").unwrap();
        assert!(b.licence.is_none());
        assert!(
            ingest
                .warnings
                .iter()
                .any(|w| w.message.contains("b@2.0.0") && w.message.contains("not an SPDX"))
        );
    }

    #[test]
    fn features_are_name_evidence() {
        let ingest = to_product(&build(None), false).unwrap();
        let image = ingest.product.images.first().unwrap();
        let a = image.components.iter().find(|c| c.name == "a").unwrap();
        assert!(
            a.evidence
                .iter()
                .any(|e| e.field == EvidenceField::Name && e.value == "feature:std")
        );
    }

    #[test]
    fn edges_follow_the_resolve_graph() {
        let ingest = to_product(&build(Some(DEP_V0)), false).unwrap();
        let p = &ingest.product;
        let refs: BTreeMap<String, BomRef> =
            p.walk().map(|(path, r, _)| (path.to_string(), r)).collect();
        let find = |suffix: &str| {
            refs.iter()
                .find(|(k, _)| k.ends_with(suffix))
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        let image = find("application:app@0.1.0");
        let a = find("library:a@1.0.0");
        let b = find("library:b@2.0.0");
        let extra = find("library:extra@5.0.0");
        assert!(p.dependencies[&image].contains(&a));
        assert!(p.dependencies[&a].contains(&b));
        assert!(p.dependencies[&extra].contains(&b));
        assert!(!p.dependencies[&image].iter().any(|r| r == &extra));
    }

    #[test]
    fn root_mismatch_and_virtual_workspace_are_errors() {
        let other =
            r#"{"packages":[{"name":"other","version":"0.1.0","source":"local","root":true}]}"#;
        assert!(matches!(
            to_product(&build(Some(other)), false),
            Err(CargoError::RootMismatch { .. })
        ));
        let mut virtual_ws = build(None);
        virtual_ws.metadata = metadata::parse(&metadata_json(None)).unwrap();
        assert!(matches!(
            to_product(&virtual_ws, false),
            Err(CargoError::NoRootPackage { .. })
        ));
    }

    #[test]
    fn ingesting_twice_is_identical() {
        let a = to_product(&build(Some(DEP_V0)), true).unwrap();
        let b = to_product(&build(Some(DEP_V0)), true).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.product.to_json().unwrap(), b.product.to_json().unwrap());
    }

    /// Root depends on `a` (normal) and dev-depends on `b`; `a` depends on `b`.
    fn dev_edge_build(dep_v0: Option<&str>) -> CargoBuild {
        let json = format!(
            r#"{{"version": 1, "packages": [
              {{"id": "r", "name": "app", "version": "0.1.0", "source": null}},
              {{"id": "a", "name": "a", "version": "1.0.0", "source": "{CRATES}"}},
              {{"id": "b", "name": "b", "version": "1.0.0", "source": "{CRATES}"}},
              {{"id": "c", "name": "c", "version": "1.0.0", "source": "{CRATES}"}}
            ], "resolve": {{"root": "r", "nodes": [
              {{"id": "r", "deps": [
                {{"pkg": "a", "dep_kinds": [{{"kind": null}}]}},
                {{"pkg": "b", "dep_kinds": [{{"kind": "dev"}}]}},
                {{"pkg": "c", "dep_kinds": [{{"kind": "dev"}}]}}
              ]}},
              {{"id": "a", "deps": [{{"pkg": "b", "dep_kinds": [{{"kind": null}}]}}]}},
              {{"id": "b"}}, {{"id": "c"}}
            ]}}}}"#
        );
        CargoBuild {
            metadata: metadata::parse(&json).unwrap(),
            metadata_input: "m.json".to_owned(),
            metadata_location: "m.json".to_owned(),
            dep_v0: dep_v0.map(|j| {
                (
                    auditable::parse_json(j).unwrap(),
                    PathBuf::from("app.elf"),
                    "app.elf".to_owned(),
                )
            }),
        }
    }

    fn edges_by_name(p: &Product) -> BTreeSet<(String, String)> {
        let names: BTreeMap<BomRef, String> = p
            .walk()
            .map(|(_, r, n)| {
                let name = match n {
                    crate::model::NodeRef::Product(_) => "product".to_owned(),
                    crate::model::NodeRef::Image(i) => format!("image:{}", i.name),
                    crate::model::NodeRef::Component(c) => c.name.clone(),
                };
                (r, name)
            })
            .collect();
        p.dependencies
            .iter()
            .flat_map(|(from, tos)| tos.iter().map(move |to| (from, to)))
            .map(|(f, t)| (names[f].clone(), names[t].clone()))
            .collect()
    }

    #[test]
    fn dev_edges_are_never_runtime_depends_on() {
        let dep_v0 = r#"{"packages":[
            {"name":"app","version":"0.1.0","source":"local","dependencies":[1],"root":true},
            {"name":"a","version":"1.0.0","source":"crates.io","dependencies":[2]},
            {"name":"b","version":"1.0.0","source":"crates.io"}]}"#;
        for (elf, include_unlinked) in [(None, false), (Some(dep_v0), false), (Some(dep_v0), true)]
        {
            let ingest = to_product(&dev_edge_build(elf), include_unlinked).unwrap();
            let edges = edges_by_name(&ingest.product);
            assert!(edges.contains(&("image:app".to_owned(), "a".to_owned())));
            assert!(edges.contains(&("a".to_owned(), "b".to_owned())));
            assert!(
                !edges.contains(&("image:app".to_owned(), "b".to_owned())),
                "dev edge to the linked b written as dependsOn ({elf:?}, {include_unlinked}): {edges:?}"
            );
            // c is dev-only: emitted (excluded) only with include_unlinked, and then its dev
            // edge is kept.
            assert_eq!(
                edges.contains(&("image:app".to_owned(), "c".to_owned())),
                include_unlinked
            );
        }
    }

    #[test]
    fn licence_slash_form_is_rewritten_safely() {
        let norm = |raw: &str| normalise_licence(raw).map(|l| l.as_str().to_owned());
        assert_eq!(norm("MIT/Apache-2.0").as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(
            norm(" MIT / Apache-2.0 ").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            norm("MIT/Apache-2.0 AND BSD-3-Clause").as_deref(),
            Some("(MIT) OR (Apache-2.0 AND BSD-3-Clause)")
        );
        assert_eq!(
            norm("Apache-2.0 WITH LLVM-exception/MIT").as_deref(),
            Some("(Apache-2.0 WITH LLVM-exception) OR (MIT)")
        );
        assert_eq!(
            norm("MIT OR Apache-2.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(norm("Weird Licence"), None);
        assert_eq!(norm("MIT//"), None);
    }

    #[test]
    fn same_name_and_version_from_two_sources_is_an_error() {
        let json = format!(
            r#"{{"version": 1, "packages": [
              {{"id": "r", "name": "app", "version": "0.1.0", "source": null}},
              {{"id": "a1", "name": "a", "version": "1.0.0", "source": "{CRATES}"}},
              {{"id": "a2", "name": "a", "version": "1.0.0", "source": "git+https://github.com/o/a#0123456789abcdef0123456789abcdef01234567"}}
            ], "resolve": {{"root": "r", "nodes": [
              {{"id": "r", "deps": [{{"pkg": "a1"}}, {{"pkg": "a2"}}]}}, {{"id": "a1"}}, {{"id": "a2"}}
            ]}}}}"#
        );
        let mut b = build(None);
        b.metadata = metadata::parse(&json).unwrap();
        let err = to_product(&b, false).unwrap_err();
        assert!(matches!(err, CargoError::DuplicateCrate { .. }), "{err}");
        let message = err.to_string();
        assert!(message.contains("a@1.0.0"), "{message}");
        assert!(message.contains("pkg:cargo/a@1.0.0"), "{message}");
    }

    #[test]
    fn git_reference_that_is_not_a_commit_warns() {
        let json = r#"{"version": 1, "packages": [
              {"id": "r", "name": "app", "version": "0.1.0", "source": null},
              {"id": "g", "name": "g", "version": "1.0.0", "source": "git+https://github.com/o/g?branch=main"}
            ], "resolve": {"root": "r", "nodes": [{"id": "r", "deps": [{"pkg": "g"}]}, {"id": "g"}]}}"#;
        let mut b = build(None);
        b.metadata = metadata::parse(json).unwrap();
        let ingest = to_product(&b, false).unwrap();
        let g = ingest
            .product
            .images
            .first()
            .unwrap()
            .components
            .first()
            .unwrap();
        assert_eq!(
            g.purl.as_ref().unwrap().as_str(),
            "pkg:generic/g@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fo%2Fg"
        );
        assert!(
            ingest
                .warnings
                .iter()
                .any(|w| w.message.contains("\"main\"") && w.message.contains("not a full commit")),
            "{:?}",
            ingest.warnings
        );
    }

    #[test]
    fn metadata_command_shape() {
        let c = metadata_command(
            OsStr::new("cargo"),
            Path::new("proj"),
            Some("thumbv7em-none-eabihf"),
        );
        let dir = std::path::absolute("proj").unwrap();
        assert_eq!(c.get_current_dir(), Some(dir.as_path()));
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--manifest-path",
                &dir.join("Cargo.toml").to_string_lossy(),
                "--filter-platform",
                "thumbv7em-none-eabihf"
            ]
        );
    }
}
