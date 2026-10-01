//! Pure mapping from parsed Zephyr inputs to the model. No I/O happens here.
//!
//! See the *Mapping* section of the [module docs](super) for what goes where. Where the
//! identifier database and `modules-deps.spdx` disagree, `modules-deps.spdx` wins and a
//! differing purl or cpe is a warning (not for a purl naming the same GitHub repository, nor
//! for an SPDX cpe that is one of the database's `cpe_aliases`); the database's cpe then
//! becomes an additional CPE, as do its `cpe_aliases`. A differing supplier is kept as evidence without a warning.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use packageurl::PackageUrl;

use super::kconfig::{KconfigEntry, KconfigValue};
use super::spdx::{
    SpdxActor, SpdxActorKind, SpdxDocument, SpdxPackage, assertion, parse_download_location,
    spdx_id_stem,
};
use super::west_list::WestProject;
use super::{Ingest, IngestOptions, UnknownModule, Warning, ZephyrBuild, ZephyrError};
use crate::identify::{Level, Outcome, Query, Resolver, github_repo};
use crate::model::{
    BomRef, Component, ComponentKind, Confidence, Cpe, Evidence, EvidenceField, IdError, Image,
    ImageKind, License, ModelError, Occurrence, PathSegment, Product, Purl, Supplier, Technique,
    ValidationError,
};

/// Evidence sources.
const WEST_SPDX: &str = "west-spdx";
const WEST_LIST: &str = "west-list";
const KCONFIG: &str = "kconfig";
const BUILD_INFO: &str = "build-info";
const IDENTIFIER_DB: &str = "identifier-db";

/// Evidence locations, relative to the build directory.
const ZEPHYR_SPDX: &str = "spdx/zephyr.spdx";
const APP_SPDX: &str = "spdx/app.spdx";
const MODULES_DEPS_SPDX: &str = "spdx/modules-deps.spdx";
const CONFIG: &str = "zephyr/.config";
const BUILD_INFO_YML: &str = "build_info.yml";

/// Confidences, in basis points.
const WEST_LIST_REVISION: u16 = 9500;
const SPDX_REVISION: u16 = 9000;
const UPSTREAM: u16 = 9000;
const DERIVED_PURL: u16 = 7000;
const LICENCE_ANALYZED: u16 = 8000;
const LICENCE_NOT_ANALYZED: u16 = 5000;
const KCONFIG_NAME: u16 = 6000;
const BUILD_INFO_FACT: u16 = 8000;
const KCONFIG_MCUBOOT: u16 = 9000;

/// The name of an MCUboot build's product and bootloader image.
const MCUBOOT: &str = "mcuboot";
/// The Kconfig symbol only an MCUboot build sets.
const MCUBOOT_SYMBOL: &str = "CONFIG_MCUBOOT";
/// The tail of MCUboot's Zephyr application source directory.
const MCUBOOT_SOURCE_DIR: &str = "mcuboot/boot/zephyr";

/// The SPDXID of the Zephyr package in `zephyr.spdx`, and of Zephyr in `modules-deps.spdx`.
const ZEPHYR_SOURCES_ID: &str = "SPDXRef-zephyr-sources";
const ZEPHYR_DEPS_ID: &str = "SPDXRef-zephyr-deps";

/// What each input says about one module.
#[derive(Debug, Default)]
struct ModuleFacts<'a> {
    /// The `<name>-sources` package in `zephyr.spdx`.
    spdx: Option<&'a SpdxPackage>,
    /// The `west list` row.
    west: Option<&'a WestProject>,
    /// The `<stem>-deps` package in `modules-deps.spdx`.
    deps: Option<&'a SpdxPackage>,
}

/// A revision and where it was read.
struct Seen {
    value: String,
    source: &'static str,
    location: Option<String>,
    line: Option<u32>,
    confidence: u16,
}

struct Mapper<'a> {
    build: &'a ZephyrBuild,
    warnings: Vec<Warning>,
    /// For each node name, the file its identity came from (to name it in errors).
    origin: BTreeMap<String, PathBuf>,
    /// The identifier database's path (for errors) and the west workspace, from the options.
    identifier_db: Option<&'a Path>,
    workspace: Option<&'a Path>,
    /// Modules the identifier database does not list, first seen in this image.
    unknown: Vec<UnknownModule>,
}

fn conf(bp: u16) -> Result<Confidence, IdError> {
    Confidence::new(bp)
}

/// Builds a `manifest-analysis` evidence entry, located when the location is a valid
/// relative path.
fn evidence(
    field: EvidenceField,
    source: &str,
    value: &str,
    bp: u16,
    location: Option<&str>,
    line: Option<u32>,
) -> Result<Evidence, IdError> {
    evidence_by(
        Technique::ManifestAnalysis,
        field,
        source,
        value,
        bp,
        location,
        line,
    )
}

/// [`evidence`] with another technique.
fn evidence_by(
    technique: Technique,
    field: EvidenceField,
    source: &str,
    value: &str,
    bp: u16,
    location: Option<&str>,
    line: Option<u32>,
) -> Result<Evidence, IdError> {
    let entry = Evidence::new(field, technique, source, value, conf(bp)?)?;
    Ok(match location.and_then(|l| Occurrence::new(l, line).ok()) {
        Some(occurrence) => entry.at(occurrence),
        None => entry,
    })
}

fn at(location: &str, line: Option<u32>) -> String {
    match line {
        Some(line) => format!("{location}:{line}"),
        None => location.to_owned(),
    }
}

/// The supplier an SPDX actor names (organisations and people; tools are not suppliers).
fn supplier_name(actor: Option<&SpdxActor>) -> Option<&str> {
    actor
        .filter(|a| matches!(a.kind, SpdxActorKind::Organization | SpdxActorKind::Person))
        .map(|a| a.name.as_str())
}

/// The GitHub repository a purl names, lower-cased: `pkg:github/<owner>/<repo>`, or any purl
/// whose `vcs_url` qualifier is a GitHub repository (`git+https://github.com/<owner>/<repo>`,
/// optionally with `@<ref>`).
fn github_repository(purl: &Purl) -> Option<(String, String)> {
    let parsed: PackageUrl<'_> = purl.as_str().parse().ok()?;
    if parsed.ty() == "github" {
        let owner = parsed.namespace()?;
        return Some((owner.to_lowercase(), parsed.name().to_lowercase()));
    }
    let vcs_url = parsed
        .qualifiers()
        .iter()
        .find(|(k, _)| k.as_ref() == "vcs_url")
        .map(|(_, v)| v.as_ref().to_owned())?;
    let url = vcs_url.strip_prefix("git+").unwrap_or(&vcs_url);
    // `https://github.com/o/r@ref`: the ref follows the last `@` after the host.
    let url = match url.rfind('@') {
        Some(at) if url[..at].matches('/').count() >= 4 => &url[..at],
        _ => url,
    };
    let (owner, repo) = github_repo(url)?;
    Some((owner.to_lowercase(), repo.to_lowercase()))
}

/// Whether two purls name the same GitHub repository (see [`github_repository`]).
fn same_repository(a: &Purl, b: &Purl) -> bool {
    matches!((github_repository(a), github_repository(b)), (Some(x), Some(y)) if x == y)
}

/// A purl pinned to the exact revision: `pkg:github/<owner>/<repo>@<rev>` for GitHub, else
/// `pkg:generic/<name>@<rev>?vcs_url=git+<url>@<rev>`.
fn fork_purl(name: &str, url: &str, revision: &str) -> Option<Purl> {
    let text = match github_repo(url) {
        Some((owner, repo)) => {
            let mut purl = PackageUrl::new("github", repo).ok()?;
            purl.with_namespace(owner).ok()?;
            purl.with_version(revision).ok()?;
            purl.to_string()
        }
        None => {
            let mut purl = PackageUrl::new("generic", name).ok()?;
            purl.with_version(revision).ok()?;
            purl.add_qualifier("vcs_url", format!("git+{url}@{revision}"))
                .ok()?;
            purl.to_string()
        }
    };
    Purl::new(&text).ok()
}

/// `hal_nordic` → `CONFIG_ZEPHYR_HAL_NORDIC_MODULE`. Like Zephyr's `zephyr_module.py`, every
/// character outside `[A-Za-z0-9]` becomes `_`.
fn module_symbol(name: &str) -> String {
    let sanitised: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CONFIG_ZEPHYR_{sanitised}_MODULE")
}

/// `hal_nordic` → `hal-nordic`: a module name as `west spdx` writes it into an SPDXID, where
/// every character outside `[A-Za-z0-9.-]` becomes `-`.
fn spdx_stem(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// A repository URL without a trailing `/` or `.git`, for comparing URLs.
fn normalise_url(url: &str) -> &str {
    let url = url.trim_end_matches('/');
    url.strip_suffix(".git").unwrap_or(url)
}

/// The Zephyr package of `zephyr.spdx`.
fn zephyr_package(doc: &SpdxDocument) -> Option<&SpdxPackage> {
    doc.package_by_id(ZEPHYR_SOURCES_ID)
        .or_else(|| doc.package_by_name("zephyr"))
}

/// The modules of the build and how the `west list` rows were used.
#[derive(Debug, Default)]
struct Modules<'a> {
    /// Every module, keyed by name.
    modules: BTreeMap<String, ModuleFacts<'a>>,
    /// The `west list` row for Zephyr itself (a T2 workspace lists `zephyr` as a project).
    zephyr_row: Option<&'a WestProject>,
    /// `west list` rows that are not modules of this build.
    unmatched: Vec<&'a WestProject>,
}

/// Every module, keyed by name. `zephyr.spdx` (a required input) decides which modules exist:
/// its `<name>-sources` packages. `west list` rows and `modules-deps.spdx` packages only add
/// facts to those; a row for Zephyr itself is kept apart, and any other row is unmatched.
fn collect_modules(build: &ZephyrBuild) -> Modules<'_> {
    let mut modules: BTreeMap<String, ModuleFacts<'_>> = BTreeMap::new();
    let mut zephyr_row = None;
    let mut unmatched = Vec::new();
    let zephyr = zephyr_package(&build.zephyr_spdx);
    for package in &build.zephyr_spdx.packages {
        if zephyr.is_some_and(|z| std::ptr::eq(z, package)) {
            continue;
        }
        if let Some(name) = package.name.strip_suffix("-sources") {
            modules.entry(name.to_owned()).or_default().spdx = Some(package);
        }
    }
    let zephyr_url = zephyr
        .and_then(|z| z.download_location.as_deref())
        .and_then(parse_download_location)
        .map(|l| l.url);
    if let Some(list) = &build.west_list {
        for project in list.modules() {
            if let Some(facts) = modules.get_mut(&project.name) {
                facts.west = Some(project);
            } else if zephyr_row.is_none()
                && (project.name == "zephyr"
                    || zephyr_url
                        .as_deref()
                        .is_some_and(|u| normalise_url(u) == normalise_url(&project.url)))
            {
                // The first row for Zephyr wins; any later one is reported as unmatched.
                zephyr_row = Some(project);
            } else {
                unmatched.push(project);
            }
        }
    }
    if let Some(deps) = &build.modules_deps_spdx {
        for (name, facts) in &mut modules {
            let stem = spdx_stem(name);
            facts.deps = deps
                .packages
                .iter()
                .find(|p| p.spdx_id.ends_with("-deps") && spdx_id_stem(&p.spdx_id) == Some(&stem));
        }
    }
    Modules {
        modules,
        zephyr_row,
        unmatched,
    }
}

/// The stems of the modules `modules-deps.spdx` says Zephyr depends on.
fn zephyr_dependency_stems(deps: &SpdxDocument) -> BTreeSet<&str> {
    deps.relationships
        .iter()
        .filter(|r| {
            r.kind == "DEPENDENCY_OF"
                && r.object.document.is_none()
                && r.object.id == ZEPHYR_DEPS_ID
        })
        .filter(|r| r.subject.document.is_none())
        .filter_map(|r| spdx_id_stem(&r.subject.id))
        .collect()
}

/// Whether `source_dir` is MCUboot's Zephyr application directory (`…/mcuboot/boot/zephyr`).
fn is_mcuboot_source_dir(source_dir: &str) -> bool {
    let dir = source_dir.replace('\\', "/");
    let dir = dir.trim_end_matches('/');
    dir == MCUBOOT_SOURCE_DIR || dir.ends_with(&format!("/{MCUBOOT_SOURCE_DIR}"))
}

/// `cmake.application.source-dir`, if present.
fn source_dir(build: &ZephyrBuild) -> Option<&str> {
    build
        .build_info
        .cmake
        .as_ref()?
        .application
        .as_ref()?
        .source_dir
        .as_deref()
}

/// The line `CONFIG_MCUBOOT=y` is on, if the build's `.config` sets it.
fn mcuboot_symbol_line(build: &ZephyrBuild) -> Option<u32> {
    match build.config.as_ref()?.symbols.get(MCUBOOT_SYMBOL)? {
        KconfigEntry {
            value: KconfigValue::Bool(true),
            line,
        } => Some(*line),
        _ => None,
    }
}

/// Whether the build is an MCUboot bootloader build: its `.config` sets `CONFIG_MCUBOOT=y`
/// or, when there is no `.config`, its application source directory is MCUboot's.
pub(super) fn is_mcuboot(build: &ZephyrBuild) -> bool {
    match &build.config {
        Some(_) => mcuboot_symbol_line(build).is_some(),
        None => source_dir(build).is_some_and(is_mcuboot_source_dir),
    }
}

/// Maps a loaded build into a product, resolving modules with `resolver` if given.
pub(super) fn to_product(
    build: &ZephyrBuild,
    options: &IngestOptions,
    resolver: Option<&mut Resolver<'_>>,
) -> Result<Ingest, ZephyrError> {
    let mut mapper = Mapper {
        build,
        warnings: Vec::new(),
        origin: BTreeMap::new(),
        identifier_db: options.identifier_db.as_deref(),
        workspace: options.workspace.as_deref(),
        unknown: Vec::new(),
    };
    let product = mapper.product(options, resolver)?;
    let mut warnings = build.warnings.clone();
    sort_warnings(&mut mapper.warnings);
    mapper.warnings.dedup();
    warnings.extend(mapper.warnings);
    let mut unknown_modules = mapper.unknown;
    unknown_modules.sort();
    Ok(Ingest {
        product,
        warnings,
        unknown_modules,
    })
}

impl<'a> Mapper<'a> {
    fn paths(&self) -> &'a super::InputPaths {
        &self.build.paths
    }

    fn west_list_path(&self) -> PathBuf {
        self.paths().west_list.clone().unwrap_or_default()
    }

    fn west_location(&self) -> Option<&'a str> {
        self.build.west_list_location.as_deref()
    }

    fn warn(&mut self, location: String, message: String) {
        self.warnings.push(Warning { location, message });
    }

    fn model_error(path: &Path) -> impl Fn(IdError) -> ZephyrError + '_ {
        move |e| ZephyrError::Model {
            path: path.to_owned(),
            source: ModelError::Id(e),
        }
    }

    fn product(
        &mut self,
        options: &IngestOptions,
        mut resolver: Option<&mut Resolver<'_>>,
    ) -> Result<Product, ZephyrError> {
        let build = self.build;
        let paths = self.paths();
        let build_info_err = Self::model_error(&paths.build_info);
        let app_name = build
            .build_info
            .app_name()
            .ok_or_else(|| ZephyrError::BuildInfo {
                path: paths.build_info.clone(),
                source: super::BuildInfoError::Missing {
                    key: "cmake.application.source-dir",
                },
            })?;
        let mcuboot = is_mcuboot(build);
        let (name, kind) = if mcuboot {
            (MCUBOOT, ImageKind::Bootloader)
        } else {
            (app_name, ImageKind::Application)
        };
        self.origin
            .insert(name.to_owned(), paths.build_info.clone());

        let mut name_evidence = Vec::new();
        if mcuboot {
            if let Some(line) = mcuboot_symbol_line(build) {
                name_evidence.push(
                    evidence(
                        EvidenceField::Name,
                        KCONFIG,
                        MCUBOOT_SYMBOL,
                        KCONFIG_MCUBOOT,
                        Some(CONFIG),
                        Some(line),
                    )
                    .map_err(Self::model_error(&paths.config))?,
                );
            }
            if source_dir(build).is_some_and(is_mcuboot_source_dir) {
                name_evidence.push(
                    evidence(
                        EvidenceField::Name,
                        BUILD_INFO,
                        MCUBOOT,
                        BUILD_INFO_FACT,
                        Some(BUILD_INFO_YML),
                        None,
                    )
                    .map_err(&build_info_err)?,
                );
            }
        } else {
            name_evidence.push(
                evidence(
                    EvidenceField::Name,
                    BUILD_INFO,
                    app_name,
                    BUILD_INFO_FACT,
                    Some(BUILD_INFO_YML),
                    None,
                )
                .map_err(&build_info_err)?,
            );
        }
        let mut product = Product::new(name).map_err(&build_info_err)?;
        let mut image = Image::new(kind, name).map_err(&build_info_err)?;
        for entry in name_evidence {
            product.evidence.insert(entry.clone());
            image.evidence.insert(entry);
        }
        self.app_licence(&mut image)?;

        let modules = collect_modules(build);
        for row in &modules.unmatched {
            self.warn(
                at(self.west_location().unwrap_or(WEST_LIST), Some(row.line)),
                format!(
                    "west list project {} is not a module of this build (no {}-sources package in {ZEPHYR_SPDX}); ignored",
                    row.name, row.name
                ),
            );
        }
        let zephyr = self.zephyr_component(modules.zephyr_row)?;
        let zephyr_segment = PathSegment::of_component(&zephyr);
        image
            .add_component(zephyr)
            .map_err(|e| ZephyrError::Model {
                path: paths.zephyr_spdx.clone(),
                source: ModelError::Merge(e),
            })?;

        let depends_on: Option<BTreeSet<&str>> = build
            .modules_deps_spdx
            .as_ref()
            .map(zephyr_dependency_stems);
        let mut module_segments = Vec::new();
        for (name, facts) in &modules.modules {
            let component = self.module_component(name, facts, resolver.as_deref_mut())?;
            let origin = self.origin.get(name).cloned().unwrap_or_default();
            let is_dependency = depends_on
                .as_ref()
                .is_none_or(|stems| stems.contains(spdx_stem(name).as_str()));
            if is_dependency {
                module_segments.push(PathSegment::of_component(&component));
            }
            image
                .add_component(component)
                .map_err(|e| ZephyrError::Model {
                    path: origin,
                    source: ModelError::Merge(e),
                })?;
        }

        let sdk_segment = if options.include_sdk {
            match self.sdk_component()? {
                Some(sdk) => {
                    let segment = PathSegment::of_component(&sdk);
                    image.add_component(sdk).map_err(|e| ZephyrError::Model {
                        path: paths.build_info.clone(),
                        source: ModelError::Merge(e),
                    })?;
                    Some(segment)
                }
                None => None,
            }
        } else {
            None
        };

        let image_segment = PathSegment::of_image(&image);
        product.add_image(image).map_err(|e| ZephyrError::Model {
            path: paths.build_info.clone(),
            source: ModelError::Merge(e),
        })?;

        let root = product.path();
        let image_path = root.child(image_segment);
        let zephyr_path = image_path.child(zephyr_segment);
        product.add_dependency(BomRef::derive(&root), BomRef::derive(&image_path));
        product.add_dependency(BomRef::derive(&image_path), BomRef::derive(&zephyr_path));
        if let Some(segment) = sdk_segment {
            product.add_dependency(
                BomRef::derive(&image_path),
                BomRef::derive(&image_path.child(segment)),
            );
        }
        for segment in module_segments {
            product.add_dependency(
                BomRef::derive(&zephyr_path),
                BomRef::derive(&image_path.child(segment)),
            );
        }

        product.validate().map_err(|e| self.validation_error(e))?;
        Ok(product)
    }

    /// Names the input file a validation failure came from.
    fn validation_error(&self, error: ValidationError) -> ZephyrError {
        let node = match &error {
            ValidationError::EmptyName { path }
            | ValidationError::InvalidName { path }
            | ValidationError::InvalidVersion { path }
            | ValidationError::EmptyVersion { path }
            | ValidationError::DuplicateSibling { path } => {
                path.segments().last().map(|s| s.name.clone())
            }
            _ => None,
        };
        let path = node
            .and_then(|n| self.origin.get(&n).cloned())
            .unwrap_or_else(|| self.paths().zephyr_spdx.clone());
        ZephyrError::Model {
            path,
            source: ModelError::Validation(error),
        }
    }

    /// The application licence from `app.spdx`.
    fn app_licence(&mut self, image: &mut Image) -> Result<(), ZephyrError> {
        let Some(doc) = &self.build.app_spdx else {
            return Ok(());
        };
        let err = Self::model_error(&self.paths().app_spdx);
        let package = doc
            .package_by_id("SPDXRef-app-sources")
            .or_else(|| doc.package_by_name("app-sources"))
            .or_else(|| doc.packages.first());
        let Some(package) = package else {
            return Ok(());
        };
        let Some(value) = assertion(package.license_concluded.as_deref()) else {
            return Ok(());
        };
        let line = package.line_of("PackageLicenseConcluded");
        let bp = licence_confidence(package);
        image.evidence.insert(
            evidence(
                EvidenceField::Licence,
                WEST_SPDX,
                value,
                bp,
                Some(APP_SPDX),
                line,
            )
            .map_err(&err)?,
        );
        match License::new(value) {
            Ok(licence) => image.licence = Some(licence),
            Err(e) => self.warn(
                at(APP_SPDX, line),
                format!("application licence not used: {e}"),
            ),
        }
        Ok(())
    }

    fn zephyr_component(
        &mut self,
        west_row: Option<&'a WestProject>,
    ) -> Result<Component, ZephyrError> {
        let build = self.build;
        let paths = self.paths();
        let err = Self::model_error(&paths.zephyr_spdx);
        let package = zephyr_package(&build.zephyr_spdx).ok_or_else(|| {
            ZephyrError::MissingZephyrPackage {
                path: paths.zephyr_spdx.clone(),
            }
        })?;
        self.origin
            .insert("zephyr".to_owned(), paths.zephyr_spdx.clone());

        let spdx_version = assertion(package.version.as_deref());
        let info_version = build.build_info.zephyr_version().filter(|v| !v.is_empty());
        let mut component =
            Component::new(ComponentKind::OperatingSystem, "zephyr").map_err(&err)?;
        match (spdx_version, info_version) {
            (Some(v), _) => component.version = Some(v.to_owned()),
            (None, Some(v)) => {
                self.origin
                    .insert("zephyr".to_owned(), paths.build_info.clone());
                component.version = Some(v.to_owned());
            }
            (None, None) => self.warn(
                ZEPHYR_SPDX.to_owned(),
                "no Zephyr version in PackageVersion or build_info.yml; zephyr is unversioned"
                    .to_owned(),
            ),
        }
        if let (Some(s), Some(i)) = (spdx_version, info_version)
            && s != i
        {
            self.warn(
                BUILD_INFO_YML.to_owned(),
                format!(
                    "cmake.zephyr.version {i} differs from {ZEPHYR_SPDX} PackageVersion {s}; using {s}"
                ),
            );
        }

        component.evidence.insert(
            evidence(
                EvidenceField::Name,
                WEST_SPDX,
                &package.name,
                SPDX_REVISION,
                Some(ZEPHYR_SPDX),
                Some(package.line),
            )
            .map_err(&err)?,
        );
        if let Some(v) = spdx_version {
            component.evidence.insert(
                evidence(
                    EvidenceField::Version,
                    WEST_SPDX,
                    v,
                    SPDX_REVISION,
                    Some(ZEPHYR_SPDX),
                    package.line_of("PackageVersion"),
                )
                .map_err(&err)?,
            );
        }
        if let Some(v) = info_version {
            component.evidence.insert(
                evidence(
                    EvidenceField::Version,
                    BUILD_INFO,
                    v,
                    BUILD_INFO_FACT,
                    Some(BUILD_INFO_YML),
                    None,
                )
                .map_err(&err)?,
            );
        }

        self.upstream_ids(&mut component, package, ZEPHYR_SPDX, &paths.zephyr_spdx)?;

        // The commit the build used, as a purl pinned to it.
        if let Some(location) = package
            .download_location
            .as_deref()
            .and_then(parse_download_location)
            && let Some(revision) = &location.revision
            && let Some(purl) = fork_purl("zephyr", &location.url, revision)
        {
            component.evidence.insert(
                evidence(
                    EvidenceField::Purl,
                    WEST_SPDX,
                    purl.as_str(),
                    DERIVED_PURL,
                    Some(ZEPHYR_SPDX),
                    package.line_of("PackageDownloadLocation"),
                )
                .map_err(&err)?,
            );
            if component.purl.is_none() {
                component.purl = Some(purl);
            }
        }

        // A T2 workspace lists Zephyr as a west project: its revision and URL are evidence
        // on the operating-system component, not a module.
        if let Some(row) = west_row {
            let west_err = Self::model_error(paths.west_list.as_deref().unwrap_or(Path::new("")));
            let location = self.west_location();
            component.evidence.insert(
                evidence(
                    EvidenceField::Version,
                    WEST_LIST,
                    &row.revision,
                    // Not above the release version's confidence: this value (a commit) is
                    // not the concluded version.
                    SPDX_REVISION,
                    location,
                    Some(row.line),
                )
                .map_err(&west_err)?,
            );
            if let Some(purl) = fork_purl("zephyr", &row.url, &row.revision) {
                component.evidence.insert(
                    evidence(
                        EvidenceField::Purl,
                        WEST_LIST,
                        purl.as_str(),
                        DERIVED_PURL,
                        location,
                        Some(row.line),
                    )
                    .map_err(&west_err)?,
                );
            }
        }

        self.licence(&mut component, package, ZEPHYR_SPDX, &paths.zephyr_spdx)?;
        Ok(component)
    }

    /// Purl, cpe and supplier from an SPDX package's `ExternalRef`s and `PackageSupplier`.
    fn upstream_ids(
        &mut self,
        component: &mut Component,
        package: &SpdxPackage,
        location: &str,
        path: &Path,
    ) -> Result<(), ZephyrError> {
        let err = Self::model_error(path);
        if let Some(r) = package.external_ref("PACKAGE-MANAGER", "purl") {
            component.evidence.insert(
                evidence(
                    EvidenceField::Purl,
                    WEST_SPDX,
                    &r.locator,
                    UPSTREAM,
                    Some(location),
                    Some(r.line),
                )
                .map_err(&err)?,
            );
            match Purl::new(&r.locator) {
                Ok(purl) => component.purl = Some(purl),
                Err(e) => self.warn(
                    at(location, Some(r.line)),
                    format!("{}: purl not used: {e}", component.name),
                ),
            }
        }
        if let Some(r) = package.external_ref("SECURITY", "cpe23Type") {
            component.evidence.insert(
                evidence(
                    EvidenceField::Cpe,
                    WEST_SPDX,
                    &r.locator,
                    UPSTREAM,
                    Some(location),
                    Some(r.line),
                )
                .map_err(&err)?,
            );
            match Cpe::new(&r.locator) {
                Ok(cpe) => component.cpe = Some(cpe),
                Err(e) => self.warn(
                    at(location, Some(r.line)),
                    format!("{}: cpe not used: {e}", component.name),
                ),
            }
        }
        if let Some(name) = supplier_name(package.supplier.as_ref()) {
            component.evidence.insert(
                evidence(
                    EvidenceField::Supplier,
                    WEST_SPDX,
                    name,
                    UPSTREAM,
                    Some(location),
                    package.line_of("PackageSupplier"),
                )
                .map_err(&err)?,
            );
            component.supplier = Some(Supplier::new(name).map_err(&err)?);
        }
        Ok(())
    }

    /// The concluded licence of an SPDX package, when asserted and valid.
    fn licence(
        &mut self,
        component: &mut Component,
        package: &SpdxPackage,
        location: &str,
        path: &Path,
    ) -> Result<(), ZephyrError> {
        let Some(value) = assertion(package.license_concluded.as_deref()) else {
            return Ok(());
        };
        let line = package.line_of("PackageLicenseConcluded");
        component.evidence.insert(
            evidence(
                EvidenceField::Licence,
                WEST_SPDX,
                value,
                licence_confidence(package),
                Some(location),
                line,
            )
            .map_err(Self::model_error(path))?,
        );
        match License::new(value) {
            Ok(licence) => component.licence = Some(licence),
            Err(e) => self.warn(
                at(location, line),
                format!("{}: licence not used: {e}", component.name),
            ),
        }
        Ok(())
    }

    fn module_component(
        &mut self,
        name: &str,
        facts: &ModuleFacts<'a>,
        resolver: Option<&mut Resolver<'_>>,
    ) -> Result<Component, ZephyrError> {
        let paths = self.paths();
        let west_location = self.west_location();

        let spdx_revision: Option<Seen> = facts.spdx.and_then(|p| {
            let (value, line) = match assertion(p.version.as_deref()) {
                Some(v) => (v.to_owned(), p.line_of("PackageVersion")),
                None => (
                    parse_download_location(p.download_location.as_deref()?)?.revision?,
                    p.line_of("PackageDownloadLocation"),
                ),
            };
            Some(Seen {
                value,
                source: WEST_SPDX,
                location: Some(ZEPHYR_SPDX.to_owned()),
                line,
                confidence: SPDX_REVISION,
            })
        });
        let west_revision: Option<Seen> = facts.west.map(|w| Seen {
            value: w.revision.clone(),
            source: WEST_LIST,
            location: west_location.map(str::to_owned),
            line: Some(w.line),
            confidence: WEST_LIST_REVISION,
        });

        let origin = if west_revision.is_some() {
            self.west_list_path()
        } else {
            paths.zephyr_spdx.clone()
        };
        self.origin.insert(name.to_owned(), origin.clone());
        let err = Self::model_error(&origin);
        let spdx_err = Self::model_error(&paths.zephyr_spdx);
        let deps_err = Self::model_error(&paths.modules_deps_spdx);

        let mut component = Component::new(ComponentKind::Library, name).map_err(&err)?;
        let chosen = west_revision.as_ref().or(spdx_revision.as_ref());
        match chosen {
            Some(seen) => component.version = Some(seen.value.clone()),
            None => self.warn(
                ZEPHYR_SPDX.to_owned(),
                format!("module {name}: no revision recorded; left unversioned"),
            ),
        }
        if let (Some(w), Some(s)) = (&west_revision, &spdx_revision)
            && w.value != s.value
        {
            self.warn(
                at(w.location.as_deref().unwrap_or(WEST_LIST), w.line),
                format!(
                    "module {name}: west list revision {} differs from {ZEPHYR_SPDX} revision {}; using the west list",
                    w.value, s.value
                ),
            );
        }
        for seen in [&west_revision, &spdx_revision].into_iter().flatten() {
            component.evidence.insert(
                evidence(
                    EvidenceField::Version,
                    seen.source,
                    &seen.value,
                    seen.confidence,
                    seen.location.as_deref(),
                    seen.line,
                )
                .map_err(&err)?,
            );
        }

        // Name evidence from every source that saw the module.
        if let Some(w) = facts.west {
            component.evidence.insert(
                evidence(
                    EvidenceField::Name,
                    WEST_LIST,
                    &w.name,
                    WEST_LIST_REVISION,
                    west_location,
                    Some(w.line),
                )
                .map_err(&err)?,
            );
        }
        if let Some(p) = facts.spdx {
            component.evidence.insert(
                evidence(
                    EvidenceField::Name,
                    WEST_SPDX,
                    &p.name,
                    SPDX_REVISION,
                    Some(ZEPHYR_SPDX),
                    Some(p.line),
                )
                .map_err(&spdx_err)?,
            );
        }
        if let Some(config) = &self.build.config {
            let symbol = module_symbol(name);
            if config.is_set(&symbol) {
                let line = config.get(&symbol).map(|e| e.line);
                component.evidence.insert(
                    evidence(
                        EvidenceField::Name,
                        KCONFIG,
                        &symbol,
                        KCONFIG_NAME,
                        Some(CONFIG),
                        line,
                    )
                    .map_err(Self::model_error(&paths.config))?,
                );
            }
        }

        // The purl pinned to the revision the build used.
        let url = facts
            .west
            .map(|w| {
                (
                    w.url.clone(),
                    WEST_LIST,
                    west_location.map(str::to_owned),
                    Some(w.line),
                )
            })
            .filter(|(url, ..)| url != "N/A")
            .or_else(|| {
                let p = facts.spdx?;
                let location = parse_download_location(p.download_location.as_deref()?)?;
                Some((
                    location.url,
                    WEST_SPDX,
                    Some(ZEPHYR_SPDX.to_owned()),
                    p.line_of("PackageDownloadLocation"),
                ))
            });
        let derived = match (&url, chosen) {
            (Some((url, source, location, line)), Some(revision)) => {
                match fork_purl(name, url, &revision.value) {
                    Some(purl) => {
                        component.evidence.insert(
                            evidence(
                                EvidenceField::Purl,
                                source,
                                purl.as_str(),
                                DERIVED_PURL,
                                location.as_deref(),
                                *line,
                            )
                            .map_err(&err)?,
                        );
                        Some(purl)
                    }
                    None => {
                        self.warn(
                            at(location.as_deref().unwrap_or(ZEPHYR_SPDX), *line),
                            format!("module {name}: cannot derive a purl from {url}"),
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        // Upstream identity from modules-deps.spdx.
        if let Some(deps) = facts.deps {
            if let Some(version) = assertion(deps.version.as_deref()) {
                component.evidence.insert(
                    evidence(
                        EvidenceField::Version,
                        WEST_SPDX,
                        version,
                        UPSTREAM,
                        Some(MODULES_DEPS_SPDX),
                        deps.line_of("PackageVersion"),
                    )
                    .map_err(&deps_err)?,
                );
            }
            self.upstream_ids(
                &mut component,
                deps,
                MODULES_DEPS_SPDX,
                &paths.modules_deps_spdx,
            )?;
        }
        // Upstream identity from the identifier database, below modules-deps.spdx.
        if let Some(resolver) = resolver {
            let revision = chosen.map(|seen| seen.value.as_str());
            let url = url.as_ref().map(|(url, ..)| url.as_str());
            self.identify(&mut component, facts.west, revision, url, resolver)?;
        }
        if component.purl.is_none() {
            component.purl = derived;
        }

        if let Some(p) = facts.spdx {
            self.licence(&mut component, p, ZEPHYR_SPDX, &paths.zephyr_spdx)?;
        }
        Ok(component)
    }

    /// Resolves a module against the identifier database: evidence, and the purl, cpe and
    /// supplier where nothing better is known; or, the first time a module is unknown, a
    /// warning and a stub.
    fn identify(
        &mut self,
        component: &mut Component,
        west: Option<&WestProject>,
        revision: Option<&str>,
        url: Option<&str>,
        resolver: &mut Resolver<'_>,
    ) -> Result<(), ZephyrError> {
        let db_name = resolver.db().name().to_owned();
        let name = component.name.clone();
        let source_dir = match (self.workspace, west) {
            (Some(workspace), Some(row)) => Some(workspace.join(&row.path)),
            _ => None,
        };
        let query = Query {
            module: &name,
            revision,
            path: source_dir.as_deref(),
        };
        let identity = match resolver.resolve(&query, url) {
            Outcome::Identified(identity) => identity,
            Outcome::Unknown { stub } => {
                if let Some(stub) = stub {
                    self.warn(
                        db_name.clone(),
                        format!("module {name} is not in {db_name}; stub entry printed"),
                    );
                    self.unknown.push(UnknownModule {
                        name,
                        stub: stub.to_string(),
                    });
                }
                return Ok(());
            }
        };
        let err = Self::model_error(self.identifier_db.unwrap_or(Path::new(&db_name)));
        let technique = if identity.from_source() {
            Technique::SourceCodeAnalysis
        } else {
            Technique::ManifestAnalysis
        };
        let bp = identity.level.basis_points();
        let fact = |field, value: &str| {
            evidence_by(
                technique,
                field,
                IDENTIFIER_DB,
                value,
                bp,
                Some(&db_name),
                None,
            )
        };
        if let Some(version) = &identity.version {
            component
                .evidence
                .insert(fact(EvidenceField::Version, version).map_err(&err)?);
        }
        if let Some(purl) = &identity.purl {
            component
                .evidence
                .insert(fact(EvidenceField::Purl, purl.as_str()).map_err(&err)?);
            match &component.purl {
                None => component.purl = Some(purl.clone()),
                // Two spellings of the same upstream repository (e.g. Zephyr's
                // `pkg:github/mbed-tls/mbedtls@v4.1.0` and the database's
                // `pkg:generic/mbedtls@4.1.0?vcs_url=git+https://github.com/Mbed-TLS/mbedtls`):
                // the difference is in the evidence above, not worth a warning.
                Some(spdx) if spdx != purl && !same_repository(spdx, purl) => self.warn(
                    db_name.clone(),
                    format!(
                        "module {name}: {db_name} purl {purl} differs from {MODULES_DEPS_SPDX} purl {spdx}; using {spdx}"
                    ),
                ),
                Some(_) => {}
            }
        }
        if let Some(cpe) = &identity.cpe {
            component
                .evidence
                .insert(fact(EvidenceField::Cpe, cpe.as_str()).map_err(&err)?);
            match &component.cpe {
                None => component.cpe = Some(cpe.clone()),
                Some(spdx) if spdx != cpe => {
                    // An SPDX CPE that is one of the database's aliases is a known other
                    // vendor:product for the same project: no warning.
                    if !identity.cpe_aliases.contains(spdx) {
                        self.warn(
                            db_name.clone(),
                            format!(
                                "module {name}: {db_name} cpe {cpe} differs from {MODULES_DEPS_SPDX} cpe {spdx}; using {spdx}, with {cpe} as an additional CPE"
                            ),
                        );
                    }
                    component.additional_cpes.insert(cpe.clone());
                }
                Some(_) => {}
            }
        }
        // Other vendor:products the upstream's vulnerabilities are filed under. Only beside a
        // primary CPE: the model keeps no additional CPEs without one.
        for alias in &identity.cpe_aliases {
            component
                .evidence
                .insert(fact(EvidenceField::Cpe, alias.as_str()).map_err(&err)?);
            if component
                .cpe
                .as_ref()
                .is_some_and(|primary| primary != alias)
            {
                component.additional_cpes.insert(alias.clone());
            }
        }
        if let Some(supplier) = &identity.supplier {
            // The database asserts the supplier outright: it does not depend on the version
            // rule, so it takes neither the rule's technique nor its level.
            let asserted = evidence(
                EvidenceField::Supplier,
                IDENTIFIER_DB,
                supplier.name(),
                Level::High.basis_points(),
                Some(&db_name),
                None,
            )
            .map_err(&err)?;
            component.evidence.insert(asserted);
            if component.supplier.is_none() {
                component.supplier = Some(supplier.clone());
            }
        }
        if let Some(note) = &identity.note {
            self.warn(db_name.clone(), format!("module {name}: {note}"));
        }
        Ok(())
    }

    /// The SDK / toolchain component, or `None` (with a warning) if the toolchain is unknown.
    fn sdk_component(&mut self) -> Result<Option<Component>, ZephyrError> {
        let paths = self.paths();
        let err = Self::model_error(&paths.build_info);
        let Some(toolchain) = self
            .build
            .build_info
            .toolchain_name()
            .filter(|t| !t.is_empty())
        else {
            self.warn(
                BUILD_INFO_YML.to_owned(),
                "no cmake.toolchain.name; SDK component not added".to_owned(),
            );
            return Ok(None);
        };
        let name = if toolchain == "zephyr" {
            "zephyr-sdk".to_owned()
        } else {
            format!("{toolchain}-toolchain")
        };
        self.origin.insert(name.clone(), paths.build_info.clone());
        let mut component = Component::new(ComponentKind::Application, &name).map_err(&err)?;
        component.evidence.insert(
            evidence(
                EvidenceField::Name,
                BUILD_INFO,
                toolchain,
                BUILD_INFO_FACT,
                Some(BUILD_INFO_YML),
                None,
            )
            .map_err(&err)?,
        );
        if toolchain == "zephyr" {
            match &self.build.config {
                Some(config) => match config.zephyr_sdk_version() {
                    Some((version, line)) => {
                        component.evidence.insert(
                            evidence(
                                EvidenceField::Version,
                                KCONFIG,
                                &version,
                                KCONFIG_NAME,
                                Some(CONFIG),
                                Some(line),
                            )
                            .map_err(Self::model_error(&paths.config))?,
                        );
                        component.version = Some(version);
                    }
                    None => self.warn(
                        CONFIG.to_owned(),
                        "no CONFIG_TOOLCHAIN_ZEPHYR_<M>_<N>=y; zephyr-sdk is unversioned"
                            .to_owned(),
                    ),
                },
                None => self.warn(
                    CONFIG.to_owned(),
                    "not found; zephyr-sdk is unversioned".to_owned(),
                ),
            }
        }
        Ok(Some(component))
    }
}

/// `spdx/zephyr.spdx:1210` → `("spdx/zephyr.spdx", Some(1210))`.
fn split_location(location: &str) -> (&str, Option<u32>) {
    match location.rsplit_once(':') {
        Some((file, line)) => match line.parse::<u32>() {
            Ok(line) => (file, Some(line)),
            Err(_) => (location, None),
        },
        None => (location, None),
    }
}

/// Sorts warnings by file, then line number (numerically), then message.
fn sort_warnings(warnings: &mut [Warning]) {
    warnings.sort_by(|a, b| {
        let (a_file, a_line) = split_location(&a.location);
        let (b_file, b_line) = split_location(&b.location);
        (a_file, a_line, &a.message).cmp(&(b_file, b_line, &b.message))
    });
}

fn licence_confidence(package: &SpdxPackage) -> u16 {
    if package.files_analyzed == Some(true) {
        LICENCE_ANALYZED
    } else {
        LICENCE_NOT_ANALYZED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zephyr::{InputPaths, build_info, kconfig, spdx, west_list};

    const BUILD_INFO_TEXT: &str = "cmake:
  application:
    source-dir: '/ws/apps/blinky'
  toolchain:
    name: 'zephyr'
    path: '/sdk'
  zephyr:
    version: '4.4.2'
version: '0.1.0'
";

    const HEADER: &str = "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: d\nDocumentNamespace: http://spdx.org/spdxdocs/d\n";

    const REV_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REV_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn zephyr_spdx(module_rev: &str, module_licence: &str) -> String {
        format!(
            "{HEADER}\
PackageName: zephyr
SPDXID: SPDXRef-zephyr-sources
PackageLicenseConcluded: Apache-2.0
PackageDownloadLocation: git+https://github.com/zephyrproject-rtos/zephyr@dccb09599635bdff17633fa7e9dab014b91dce90
PackageVersion: 4.4.2
PackageSupplier: Organization: zephyrproject
ExternalRef: PACKAGE-MANAGER purl pkg:github/zephyrproject-rtos/zephyr@v4.4.2
ExternalRef: SECURITY cpe23Type cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*
FilesAnalyzed: true

PackageName: mbedtls-sources
SPDXID: SPDXRef-mbedtls-sources
PackageLicenseConcluded: {module_licence}
PackageDownloadLocation: git+https://github.com/zephyrproject-rtos/mbedtls@{module_rev}
PackageVersion: {module_rev}
FilesAnalyzed: false

PackageName: hal_nordic-sources
SPDXID: SPDXRef-hal-nordic-sources
PackageLicenseConcluded: NOASSERTION
PackageDownloadLocation: git+https://git.example.com/hal_nordic@{REV_B}
PackageVersion: {REV_B}
FilesAnalyzed: false
"
        )
    }

    const MODULES_DEPS: &str = "Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-zephyr-deps
Relationship: SPDXRef-mbedtls-deps DEPENDENCY_OF SPDXRef-zephyr-deps

PackageName: zephyr
SPDXID: SPDXRef-zephyr-deps

PackageName: mbed_tls
SPDXID: SPDXRef-mbedtls-deps
PackageVersion: 4.1.0
PackageSupplier: Organization: arm
ExternalRef: SECURITY cpe23Type cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*
ExternalRef: PACKAGE-MANAGER purl pkg:github/Mbed-TLS/mbedtls@v4.1.0

PackageName: hal_nordic-deps
SPDXID: SPDXRef-hal-nordic-deps
";

    fn west_list_text(mbedtls_rev: &str) -> String {
        format!(
            "manifest zephyr HEAD N/A\n\
             mbedtls modules/crypto/mbedtls {mbedtls_rev} https://github.com/zephyrproject-rtos/mbedtls\n\
             hal_nordic modules/hal/nordic {REV_B} https://git.example.com/hal_nordic\n"
        )
    }

    struct Sample {
        zephyr_spdx: String,
        modules_deps: Option<String>,
        west_list: Option<String>,
        config: Option<String>,
        app_spdx: Option<String>,
    }

    impl Default for Sample {
        fn default() -> Self {
            Self {
                zephyr_spdx: zephyr_spdx(REV_A, "Apache-2.0 OR GPL-2.0-or-later"),
                modules_deps: Some(format!("{HEADER}{MODULES_DEPS}")),
                west_list: Some(west_list_text(REV_A)),
                config: Some(
                    "CONFIG_ZEPHYR_MBEDTLS_MODULE=y\nCONFIG_ZEPHYR_HAL_NORDIC_MODULE=y\nCONFIG_TOOLCHAIN_ZEPHYR_1_0=y\n"
                        .to_owned(),
                ),
                app_spdx: Some(format!(
                    "{HEADER}PackageName: app-sources\nSPDXID: SPDXRef-app-sources\nPackageLicenseConcluded: Apache-2.0\nFilesAnalyzed: true\n"
                )),
            }
        }
    }

    fn build(sample: &Sample) -> ZephyrBuild {
        ZephyrBuild {
            build_info: build_info::parse(BUILD_INFO_TEXT).unwrap(),
            zephyr_spdx: spdx::parse(&sample.zephyr_spdx).unwrap(),
            app_spdx: sample.app_spdx.as_deref().map(|t| spdx::parse(t).unwrap()),
            build_spdx: None,
            modules_deps_spdx: sample
                .modules_deps
                .as_deref()
                .map(|t| spdx::parse(t).unwrap()),
            config: sample.config.as_deref().map(|t| kconfig::parse(t).unwrap()),
            west_list: sample
                .west_list
                .as_deref()
                .map(|t| west_list::parse(t).unwrap()),
            west_list_location: sample
                .west_list
                .as_ref()
                .map(|_| "west-list.txt".to_owned()),
            paths: InputPaths {
                build_info: "b/build_info.yml".into(),
                zephyr_spdx: "b/spdx/zephyr.spdx".into(),
                app_spdx: "b/spdx/app.spdx".into(),
                modules_deps_spdx: "b/spdx/modules-deps.spdx".into(),
                config: "b/zephyr/.config".into(),
                west_list: sample.west_list.as_ref().map(|_| "w/west-list.txt".into()),
            },
            warnings: Vec::new(),
        }
    }

    fn ingest(sample: &Sample, include_sdk: bool) -> Ingest {
        let options = IngestOptions::new("b").with_include_sdk(include_sdk);
        to_product(&build(sample), &options, None).unwrap()
    }

    fn image(product: &Product) -> &Image {
        assert_eq!(product.images.len(), 1);
        product.images.iter().next().unwrap()
    }

    fn component<'p>(product: &'p Product, name: &str) -> &'p Component {
        image(product)
            .components
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no component {name}"))
    }

    fn values(c: &Component, field: EvidenceField) -> Vec<(String, String)> {
        c.evidence
            .iter()
            .filter(|e| e.field == field)
            .map(|e| (e.source().to_owned(), e.value.clone()))
            .collect()
    }

    fn located(c: &Component, field: EvidenceField, source: &str) -> Vec<String> {
        c.evidence
            .iter()
            .filter(|e| e.field == field && e.source() == source)
            .filter_map(|e| e.occurrence.as_ref().map(ToString::to_string))
            .collect()
    }

    #[test]
    fn app_is_product_root_and_application_image() {
        let out = ingest(&Sample::default(), false);
        let product = &out.product;
        assert_eq!(product.name, "blinky");
        assert_eq!(product.version, None);
        let image = image(product);
        assert_eq!(image.kind, ImageKind::Application);
        assert_eq!(image.name, "blinky");
        assert_eq!(image.licence.as_ref().unwrap().as_str(), "Apache-2.0");
        let names: Vec<(&str, ComponentKind)> = image
            .components
            .iter()
            .map(|c| (c.name.as_str(), c.kind))
            .collect();
        assert_eq!(
            names,
            [
                ("hal_nordic", ComponentKind::Library),
                ("mbedtls", ComponentKind::Library),
                ("zephyr", ComponentKind::OperatingSystem),
            ]
        );
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    #[test]
    fn zephyr_component_carries_version_purl_cpe_licence_supplier() {
        let out = ingest(&Sample::default(), false);
        let zephyr = component(&out.product, "zephyr");
        assert_eq!(zephyr.version.as_deref(), Some("4.4.2"));
        assert_eq!(
            zephyr.purl.as_ref().unwrap().as_str(),
            "pkg:github/zephyrproject-rtos/zephyr@v4.4.2"
        );
        assert_eq!(
            zephyr.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*"
        );
        assert_eq!(zephyr.licence.as_ref().unwrap().as_str(), "Apache-2.0");
        assert_eq!(zephyr.supplier.as_ref().unwrap().name(), "zephyrproject");
        let purls = values(zephyr, EvidenceField::Purl);
        assert!(purls.contains(&(
            "west-spdx".into(),
            "pkg:github/zephyrproject-rtos/zephyr@dccb09599635bdff17633fa7e9dab014b91dce90".into()
        )));
        assert!(purls.contains(&(
            "west-spdx".into(),
            "pkg:github/zephyrproject-rtos/zephyr@v4.4.2".into()
        )));
        let versions = values(zephyr, EvidenceField::Version);
        assert_eq!(
            versions,
            [
                ("build-info".into(), "4.4.2".into()),
                ("west-spdx".into(), "4.4.2".into())
            ]
        );
        assert_eq!(
            located(zephyr, EvidenceField::Version, "west-spdx"),
            ["spdx/zephyr.spdx:10"]
        );
    }

    #[test]
    fn module_version_is_revision_with_west_list_and_spdx_evidence() {
        let out = ingest(&Sample::default(), false);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(mbedtls.version.as_deref(), Some(REV_A));
        let versions = values(mbedtls, EvidenceField::Version);
        assert!(versions.contains(&("west-list".into(), REV_A.into())));
        assert!(versions.contains(&("west-spdx".into(), REV_A.into())));
        assert!(versions.contains(&("west-spdx".into(), "4.1.0".into())));
        assert_eq!(
            located(mbedtls, EvidenceField::Version, "west-list"),
            ["west-list.txt:2"]
        );
        let names = values(mbedtls, EvidenceField::Name);
        assert!(names.contains(&("kconfig".into(), "CONFIG_ZEPHYR_MBEDTLS_MODULE".into())));
        assert!(names.contains(&("west-list".into(), "mbedtls".into())));
        assert!(names.contains(&("west-spdx".into(), "mbedtls-sources".into())));
    }

    #[test]
    fn module_with_upstream_reference_uses_upstream_purl_and_cpe() {
        let out = ingest(&Sample::default(), false);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(
            mbedtls.purl.as_ref().unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        assert_eq!(
            mbedtls.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*"
        );
        assert_eq!(mbedtls.supplier.as_ref().unwrap().name(), "arm");
        // The fork purl is still recorded as evidence.
        let purls = values(mbedtls, EvidenceField::Purl);
        assert!(
            purls
                .iter()
                .any(|(_, v)| v == &format!("pkg:github/zephyrproject-rtos/mbedtls@{REV_A}")),
            "{purls:?}"
        );
        assert_eq!(
            mbedtls.licence.as_ref().unwrap().as_str(),
            "Apache-2.0 OR GPL-2.0-or-later"
        );
        // FilesAnalyzed: false → lower licence confidence.
        assert_eq!(
            mbedtls.confidence_for(EvidenceField::Licence),
            Confidence::new(LICENCE_NOT_ANALYZED).unwrap()
        );
    }

    #[test]
    fn module_without_upstream_reference_gets_fork_purl() {
        let out = ingest(&Sample::default(), false);
        let nordic = component(&out.product, "hal_nordic");
        assert_eq!(nordic.cpe, None);
        assert_eq!(nordic.licence, None);
        let purl = nordic.purl.as_ref().unwrap().as_str();
        assert!(purl.starts_with("pkg:generic/hal_nordic@"), "{purl}");
        assert!(purl.contains("vcs_url="), "{purl}");
        assert!(purl.contains(REV_B), "{purl}");
        // A GitHub URL gives a github purl.
        assert_eq!(
            fork_purl("x", "https://github.com/org/repo.git", "abc")
                .unwrap()
                .as_str(),
            "pkg:github/org/repo@abc"
        );
    }

    #[test]
    fn module_seen_by_three_sources_appears_once() {
        let out = ingest(&Sample::default(), false);
        let count = image(&out.product)
            .components
            .iter()
            .filter(|c| c.name == "mbedtls")
            .count();
        assert_eq!(count, 1);
        let mbedtls = component(&out.product, "mbedtls");
        let sources: BTreeSet<&str> = mbedtls.evidence.iter().map(|e| e.source()).collect();
        assert_eq!(
            sources,
            BTreeSet::from(["kconfig", "west-list", "west-spdx"])
        );
    }

    #[test]
    fn manifest_row_does_not_become_a_module() {
        let out = ingest(&Sample::default(), false);
        assert!(
            image(&out.product)
                .components
                .iter()
                .all(|c| c.name != "manifest")
        );
        let libraries = image(&out.product)
            .components
            .iter()
            .filter(|c| c.kind == ComponentKind::Library)
            .count();
        assert_eq!(libraries, 2);
    }

    #[test]
    fn revision_disagreement_prefers_west_list_and_warns() {
        let sample = Sample {
            west_list: Some(west_list_text(REV_B)),
            ..Sample::default()
        };
        let out = ingest(&sample, false);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(mbedtls.version.as_deref(), Some(REV_B));
        let versions = values(mbedtls, EvidenceField::Version);
        assert!(versions.contains(&("west-list".into(), REV_B.into())));
        assert!(versions.contains(&("west-spdx".into(), REV_A.into())));
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert_eq!(out.warnings[0].location, "west-list.txt:2");
        assert!(out.warnings[0].message.contains("differs"));
    }

    #[test]
    fn include_sdk_adds_toolchain_component_with_kconfig_version() {
        let out = ingest(&Sample::default(), true);
        let sdk = component(&out.product, "zephyr-sdk");
        assert_eq!(sdk.kind, ComponentKind::Application);
        assert_eq!(sdk.version.as_deref(), Some("1.0"));
        assert_eq!(
            located(sdk, EvidenceField::Version, "kconfig"),
            ["zephyr/.config:3"]
        );
        // Without .config: unversioned, with a warning.
        let sample = Sample {
            config: None,
            ..Sample::default()
        };
        let out = ingest(&sample, true);
        assert_eq!(component(&out.product, "zephyr-sdk").version, None);
        assert!(out.warnings.iter().any(|w| w.location == "zephyr/.config"));
        // Without --include-sdk there is no SDK component.
        let out = ingest(&Sample::default(), false);
        assert!(
            image(&out.product)
                .components
                .iter()
                .all(|c| c.name != "zephyr-sdk")
        );
    }

    #[test]
    fn dependencies_follow_modules_deps_relationships() {
        let deps_of = |out: &Ingest, name: &str| -> Vec<String> {
            let product = &out.product;
            let (_, from, _) = product
                .walk()
                .find(|(p, _, _)| p.segments().last().unwrap().name == name)
                .unwrap();
            product
                .dependencies
                .get(&from)
                .map(|targets| {
                    targets
                        .iter()
                        .map(|t| {
                            product
                                .walk()
                                .find(|(_, r, _)| r == t)
                                .unwrap()
                                .0
                                .segments()
                                .last()
                                .unwrap()
                                .name
                                .clone()
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let out = ingest(&Sample::default(), true);
        // Only mbedtls is a DEPENDENCY_OF zephyr in the sample.
        assert_eq!(deps_of(&out, "zephyr"), ["mbedtls"]);
        // The product and its image share a name, so check their edges by ref.
        let root = out.product.path();
        let image_path = root.child(PathSegment::of_image(image(&out.product)));
        let edges = &out.product.dependencies;
        assert!(edges[&BomRef::derive(&root)].contains(&BomRef::derive(&image_path)));
        let zephyr = image_path.child(PathSegment::of_component(component(&out.product, "zephyr")));
        let sdk = image_path.child(PathSegment::of_component(component(
            &out.product,
            "zephyr-sdk",
        )));
        assert_eq!(
            edges[&BomRef::derive(&image_path)],
            BTreeSet::from([BomRef::derive(&zephyr), BomRef::derive(&sdk)])
        );
        // Without modules-deps.spdx, Zephyr depends on every module.
        let sample = Sample {
            modules_deps: None,
            ..Sample::default()
        };
        let out = ingest(&sample, false);
        assert_eq!(deps_of(&out, "zephyr"), ["hal_nordic", "mbedtls"]);
    }

    #[test]
    fn unparsable_licence_becomes_evidence_and_warning() {
        let sample = Sample {
            zephyr_spdx: zephyr_spdx(REV_A, "Apache-2.0 AND AND MIT"),
            ..Sample::default()
        };
        let out = ingest(&sample, false);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(mbedtls.licence, None);
        assert_eq!(
            values(mbedtls, EvidenceField::Licence),
            [("west-spdx".into(), "Apache-2.0 AND AND MIT".into())]
        );
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(out.warnings[0].location.starts_with("spdx/zephyr.spdx:"));
        assert!(out.warnings[0].message.contains("licence not used"));
    }

    #[test]
    fn module_names_are_sanitised_like_zephyr_and_west_spdx() {
        assert_eq!(
            module_symbol("tf-psa-crypto"),
            "CONFIG_ZEPHYR_TF_PSA_CRYPTO_MODULE"
        );
        assert_eq!(module_symbol("cmsis_6"), "CONFIG_ZEPHYR_CMSIS_6_MODULE");
        assert_eq!(module_symbol("lib.x+y"), "CONFIG_ZEPHYR_LIB_X_Y_MODULE");
        assert_eq!(spdx_stem("hal_nordic"), "hal-nordic");
        assert_eq!(spdx_stem("lib.x+y"), "lib.x-y");
        assert_eq!(spdx_stem("tf-psa-crypto"), "tf-psa-crypto");
    }

    /// A T2 workspace: the application is the manifest repository, and Zephyr is a project.
    fn t2_west_list(zephyr_name: &str, extra: &str) -> String {
        format!(
            "manifest blinky HEAD N/A\n\
             {zephyr_name} zephyr dccb09599635bdff17633fa7e9dab014b91dce90 https://github.com/zephyrproject-rtos/zephyr.git\n\
             mbedtls modules/crypto/mbedtls {REV_A} https://github.com/zephyrproject-rtos/mbedtls\n\
             hal_nordic modules/hal/nordic {REV_B} https://git.example.com/hal_nordic\n{extra}"
        )
    }

    #[test]
    fn t2_west_list_zephyr_row_is_evidence_on_the_operating_system_component() {
        // Matched by name, and (for a renamed project) by the Zephyr package's URL.
        for zephyr_name in ["zephyr", "zephyr-rtos"] {
            let sample = Sample {
                west_list: Some(t2_west_list(zephyr_name, "")),
                ..Sample::default()
            };
            let out = ingest(&sample, false);
            let zephyrs: Vec<&Component> = image(&out.product)
                .components
                .iter()
                .filter(|c| c.name == "zephyr" || c.name == zephyr_name)
                .collect();
            assert_eq!(zephyrs.len(), 1, "{zephyr_name}: {zephyrs:?}");
            let zephyr = zephyrs[0];
            assert_eq!(zephyr.name, "zephyr");
            assert_eq!(zephyr.kind, ComponentKind::OperatingSystem);
            assert_eq!(zephyr.version.as_deref(), Some("4.4.2"));
            // The commit does not outrank the release version it disagrees with.
            assert_eq!(
                zephyr.confidence_for(EvidenceField::Version),
                Confidence::new(SPDX_REVISION).unwrap()
            );
            let sha = "dccb09599635bdff17633fa7e9dab014b91dce90";
            assert!(
                values(zephyr, EvidenceField::Version).contains(&("west-list".into(), sha.into()))
            );
            assert_eq!(
                located(zephyr, EvidenceField::Version, "west-list"),
                ["west-list.txt:2"]
            );
            assert!(values(zephyr, EvidenceField::Purl).contains(&(
                "west-list".into(),
                format!("pkg:github/zephyrproject-rtos/zephyr@{sha}")
            )));
            let libraries: Vec<&str> = image(&out.product)
                .components
                .iter()
                .filter(|c| c.kind == ComponentKind::Library)
                .map(|c| c.name.as_str())
                .collect();
            assert_eq!(libraries, ["hal_nordic", "mbedtls"]);
            assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        }
    }

    #[test]
    fn second_zephyr_row_in_west_list_is_unmatched_and_warns() {
        let other = "1111111111111111111111111111111111111111";
        let sample = Sample {
            west_list: Some(t2_west_list(
                "zephyr",
                &format!(
                    "zephyr-copy zephyr-copy {other} https://github.com/zephyrproject-rtos/zephyr\n"
                ),
            )),
            ..Sample::default()
        };
        let out = ingest(&sample, false);
        let zephyr = component(&out.product, "zephyr");
        let west_versions: Vec<String> = values(zephyr, EvidenceField::Version)
            .into_iter()
            .filter(|(source, _)| source == "west-list")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(west_versions, ["dccb09599635bdff17633fa7e9dab014b91dce90"]);
        assert!(
            image(&out.product)
                .components
                .iter()
                .all(|c| c.name != "zephyr-copy")
        );
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(
            out.warnings[0]
                .to_string()
                .starts_with("west-list.txt:5: west list project zephyr-copy is not a module"),
            "{}",
            out.warnings[0]
        );
    }

    #[test]
    fn west_list_row_that_is_not_a_module_warns_and_adds_no_component() {
        let sample = Sample {
            west_list: Some(t2_west_list(
                "zephyr",
                "bsim tools/bsim 0123456789012345678901234567890123456789 https://github.com/zephyrproject-rtos/babblesim-manifest\n",
            )),
            ..Sample::default()
        };
        let out = ingest(&sample, false);
        assert!(
            image(&out.product)
                .components
                .iter()
                .all(|c| c.name != "bsim")
        );
        assert_eq!(image(&out.product).components.len(), 3);
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert_eq!(
            out.warnings[0].to_string(),
            "west-list.txt:5: west list project bsim is not a module of this build \
             (no bsim-sources package in spdx/zephyr.spdx); ignored"
        );
    }

    /// Ingests `sample` resolving modules with the identifier database `db`.
    fn ingest_with_db(sample: &Sample, db: &str) -> Ingest {
        let db = crate::identify::load_str("identifiers.yaml", db).unwrap();
        let mut resolver = Resolver::new(&db);
        let options = IngestOptions::new("b").with_identifier_db("d/identifiers.yaml");
        to_product(&build(sample), &options, Some(&mut resolver)).unwrap()
    }

    fn db_entry(
        module: &str,
        purl: &str,
        cpe: &str,
        supplier: &str,
        revision: &str,
        version: &str,
    ) -> String {
        format!(
            "  {module}:\n    upstream:\n      name: {module}\n      supplier: {supplier}\n    purl: {purl}\n    cpe: '{cpe}'\n    version_rule:\n      kind: manual\n      table:\n        {revision}: {version}\n"
        )
    }

    #[test]
    fn identifier_db_fills_purl_cpe_supplier_when_spdx_has_none() {
        let db = format!(
            "schema: 1\nmodules:\n{}{}",
            db_entry(
                "hal_nordic",
                "pkg:github/NordicSemiconductor/nrfx@v{version}",
                "cpe:2.3:a:nordicsemi:nrfx:{version}:*:*:*:*:*:*:*",
                "Nordic Semiconductor ASA",
                REV_B,
                "3.2.1"
            ),
            db_entry(
                "mbedtls",
                "pkg:github/Mbed-TLS/mbedtls@v{version}",
                "cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*",
                "arm",
                REV_A,
                "4.1.0"
            ),
        );
        let out = ingest_with_db(&Sample::default(), &db);
        let nordic = component(&out.product, "hal_nordic");
        // The version stays the revision; the upstream version is evidence.
        assert_eq!(nordic.version.as_deref(), Some(REV_B));
        assert_eq!(
            nordic.purl.as_ref().unwrap().as_str(),
            "pkg:github/nordicsemiconductor/nrfx@v3.2.1"
        );
        assert_eq!(
            nordic.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:nordicsemi:nrfx:3.2.1:*:*:*:*:*:*:*"
        );
        assert_eq!(
            nordic.supplier.as_ref().unwrap().name(),
            "Nordic Semiconductor ASA"
        );
        for field in [
            EvidenceField::Version,
            EvidenceField::Purl,
            EvidenceField::Cpe,
            EvidenceField::Supplier,
        ] {
            assert_eq!(
                located(nordic, field, IDENTIFIER_DB),
                ["identifiers.yaml"],
                "{field:?}"
            );
        }
        assert!(
            values(nordic, EvidenceField::Version)
                .contains(&(IDENTIFIER_DB.into(), "3.2.1".into()))
        );
        let db_version = nordic
            .evidence
            .iter()
            .find(|e| e.source() == IDENTIFIER_DB && e.field == EvidenceField::Version)
            .unwrap();
        assert_eq!(db_version.confidence, Confidence::new(9000).unwrap());
        assert_eq!(db_version.technique, Technique::ManifestAnalysis);
        // The fork purl is still evidence.
        assert!(
            values(nordic, EvidenceField::Purl)
                .iter()
                .any(|(_, v)| v.starts_with("pkg:generic/hal_nordic@"))
        );
        // mbedtls agrees with modules-deps.spdx: no warning at all.
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert!(out.unknown_modules.is_empty());

        // Without modules-deps.spdx, the database supplies mbedtls's identity too.
        let sample = Sample {
            modules_deps: None,
            ..Sample::default()
        };
        let out = ingest_with_db(&sample, &db);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(
            mbedtls.purl.as_ref().unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        assert_eq!(
            located(mbedtls, EvidenceField::Purl, IDENTIFIER_DB),
            ["identifiers.yaml"]
        );
        assert_eq!(mbedtls.supplier.as_ref().unwrap().name(), "arm");
    }

    /// No CPE from SPDX: the database's `cpe` is the primary CPE and each of its
    /// `cpe_aliases` an additional one, all with `identifier-db` evidence and no warning.
    #[test]
    fn identifier_db_cpe_is_primary_and_aliases_additional_when_spdx_has_none() {
        let db = format!(
            "schema: 1\nmodules:\n{}",
            db_entry(
                "hal_nordic",
                "pkg:generic/nrfx@{version}",
                "cpe:2.3:a:nordicsemi:nrfx:{version}:*:*:*:*:*:*:*",
                "Nordic Semiconductor ASA",
                REV_B,
                "3.2.1"
            )
            .replace(
                "    version_rule:",
                "    cpe_aliases: ['cpe:2.3:a:nordic:nrfx:{version}:*:*:*:*:*:*:*', 'cpe:2.3:a:nordicsemi:nrfx:{version}:*:*:*:*:*:*:*']\n    version_rule:"
            ),
        );
        // The second alias repeats the cpe: rejected at load.
        assert!(crate::identify::load_str("identifiers.yaml", &db).is_err());
        let db = db.replace(", 'cpe:2.3:a:nordicsemi:nrfx:{version}:*:*:*:*:*:*:*'", "");
        let out = ingest_with_db(&Sample::default(), &db);
        let nordic = component(&out.product, "hal_nordic");
        assert_eq!(
            nordic.cpe.as_ref().map(|c| c.as_str()),
            Some("cpe:2.3:a:nordicsemi:nrfx:3.2.1:*:*:*:*:*:*:*")
        );
        assert_eq!(
            nordic
                .additional_cpes
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            ["cpe:2.3:a:nordic:nrfx:3.2.1:*:*:*:*:*:*:*"]
        );
        let db_cpes: Vec<String> = values(nordic, EvidenceField::Cpe)
            .into_iter()
            .filter(|(source, _)| source == IDENTIFIER_DB)
            .map(|(_, v)| v)
            .collect();
        assert_eq!(db_cpes.len(), 2, "{db_cpes:?}");
        assert!(
            !out.warnings.iter().any(|w| w.message.contains("cpe")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn same_repository_matches_github_purls_and_vcs_urls_case_insensitively() {
        let p = |s: &str| Purl::new(s).unwrap();
        let generic =
            p("pkg:generic/mbedtls@3.6.4?vcs_url=git%2Bhttps://github.com/Mbed-TLS/mbedtls");
        assert!(same_repository(
            &p("pkg:github/Mbed-TLS/mbedtls@v3.6.4"),
            &generic
        ));
        assert!(same_repository(
            &generic,
            &p("pkg:github/mbed-tls/MBEDTLS@v4.1.0")
        ));
        // A vcs_url with a ref, or a .git suffix, names the same repository.
        assert!(same_repository(
            &p("pkg:generic/x@1?vcs_url=git%2Bhttps://github.com/Mbed-TLS/mbedtls.git%40v3.6.4"),
            &generic
        ));
        // Different repositories, or nothing to compare.
        for other in [
            "pkg:github/ARMmbed/mbedtls@v3.2.1",
            "pkg:github/Mbed-TLS/TF-PSA-Crypto@v1.1.0",
            "pkg:generic/mbedtls@3.6.4",
            "pkg:generic/mbedtls@3.6.4?vcs_url=git%2Bhttps://example.org/Mbed-TLS/mbedtls",
            "pkg:cargo/mbedtls@3.6.4",
        ] {
            assert!(!same_repository(&p(other), &generic), "{other}");
        }
    }

    /// The SPDX cpe is one of the database's aliases and the SPDX purl names the same
    /// repository as the database's: both differences are evidence only, with no warning; the
    /// database's cpe is still an additional CPE.
    #[test]
    fn spdx_cpe_alias_and_same_repository_purl_do_not_warn() {
        let db = format!(
            "schema: 1\nmodules:\n{}",
            db_entry(
                "mbedtls",
                "'pkg:generic/mbedtls@{version}?vcs_url=git+https://github.com/Mbed-TLS/mbedtls'",
                "cpe:2.3:a:trustedfirmware:mbed_tls:{version}:*:*:*:*:*:*:*",
                "arm",
                REV_A,
                "4.1.0"
            )
            .replace(
                "    version_rule:",
                "    cpe_aliases: ['cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*']\n    version_rule:"
            ),
        );
        let out = ingest_with_db(&Sample::default(), &db);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(
            mbedtls.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*"
        );
        assert_eq!(
            mbedtls
                .additional_cpes
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            ["cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*"]
        );
        assert_eq!(
            mbedtls.purl.as_ref().unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        // Both database values are kept as evidence.
        assert!(
            values(mbedtls, EvidenceField::Purl)
                .iter()
                .any(|(src, v)| src == IDENTIFIER_DB && v.starts_with("pkg:generic/mbedtls@4.1.0"))
        );
        let differs: Vec<String> = out
            .warnings
            .iter()
            .map(ToString::to_string)
            .filter(|w| w.contains("differs"))
            .collect();
        assert!(differs.is_empty(), "{differs:?}");
    }

    #[test]
    fn identifier_db_supplier_is_asserted_regardless_of_version_rule() {
        // A file_regex rule with no sources: Low, so no version, purl or cpe, and the version
        // rule's technique would be source-code-analysis. The supplier is still asserted.
        let db = "schema: 1\nmodules:\n  hal_nordic:\n    upstream:\n      name: nrfx\n      supplier: Nordic Semiconductor ASA\n    purl: pkg:github/NordicSemiconductor/nrfx@v{version}\n    version_rule:\n      kind: file_regex\n      file: nrfx.h\n      pattern: 'NRFX_VERSION (?P<version>\\S+)'\n";
        let out = ingest_with_db(&Sample::default(), db);
        let nordic = component(&out.product, "hal_nordic");
        let from_db: Vec<_> = nordic
            .evidence
            .iter()
            .filter(|e| e.source() == IDENTIFIER_DB)
            .collect();
        assert_eq!(from_db.len(), 1, "{from_db:?}");
        let supplier = from_db[0];
        assert_eq!(supplier.field, EvidenceField::Supplier);
        assert_eq!(supplier.value, "Nordic Semiconductor ASA");
        assert_eq!(supplier.technique, Technique::ManifestAnalysis);
        assert_eq!(supplier.confidence, Confidence::new(9000).unwrap());
        assert_eq!(
            nordic.supplier.as_ref().unwrap().name(),
            "Nordic Semiconductor ASA"
        );
        // No upstream version: the fork purl stays, and the reason is a warning.
        assert!(
            nordic
                .purl
                .as_ref()
                .unwrap()
                .as_str()
                .starts_with("pkg:generic/hal_nordic@")
        );
        assert!(
            out.warnings.iter().any(|w| w
                .message
                .starts_with("module hal_nordic: no module source tree")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn spdx_upstream_reference_outranks_identifier_db() {
        let db = format!(
            "schema: 1\nmodules:\n{}",
            db_entry(
                "mbedtls",
                "pkg:github/ARMmbed/mbedtls@v{version}",
                "cpe:2.3:a:armmbed:mbedtls:{version}:*:*:*:*:*:*:*",
                "Arm Limited",
                REV_A,
                "3.2.1"
            ),
        );
        let out = ingest_with_db(&Sample::default(), &db);
        let mbedtls = component(&out.product, "mbedtls");
        assert_eq!(
            mbedtls.purl.as_ref().unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        assert_eq!(
            mbedtls.cpe.as_ref().unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*"
        );
        assert_eq!(mbedtls.supplier.as_ref().unwrap().name(), "arm");
        // The database's differing cpe is an additional CPE, so scanners still see it.
        assert_eq!(
            mbedtls
                .additional_cpes
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            ["cpe:2.3:a:armmbed:mbedtls:3.2.1:*:*:*:*:*:*:*"]
        );
        // The database's facts are kept as evidence.
        assert!(values(mbedtls, EvidenceField::Purl).contains(&(
            IDENTIFIER_DB.into(),
            "pkg:github/armmbed/mbedtls@v3.2.1".into()
        )));
        assert!(
            values(mbedtls, EvidenceField::Supplier)
                .contains(&(IDENTIFIER_DB.into(), "Arm Limited".into()))
        );
        let warnings: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            warnings,
            [
                "identifiers.yaml: module hal_nordic is not in identifiers.yaml; stub entry printed",
                "identifiers.yaml: module mbedtls: identifiers.yaml cpe cpe:2.3:a:armmbed:mbedtls:3.2.1:*:*:*:*:*:*:* differs from spdx/modules-deps.spdx cpe cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*; using cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*, with cpe:2.3:a:armmbed:mbedtls:3.2.1:*:*:*:*:*:*:* as an additional CPE",
                "identifiers.yaml: module mbedtls: identifiers.yaml purl pkg:github/armmbed/mbedtls@v3.2.1 differs from spdx/modules-deps.spdx purl pkg:github/mbed-tls/mbedtls@v4.1.0; using pkg:github/mbed-tls/mbedtls@v4.1.0",
            ]
        );
        assert_eq!(out.unknown_modules.len(), 1);
        assert_eq!(out.unknown_modules[0].name, "hal_nordic");
        assert!(
            out.unknown_modules[0].stub.starts_with("  hal_nordic:\n"),
            "{}",
            out.unknown_modules[0].stub
        );
    }

    #[test]
    fn warnings_sort_by_file_then_numeric_line() {
        let w = |location: &str, message: &str| Warning {
            location: location.into(),
            message: message.into(),
        };
        let mut warnings = vec![
            w("spdx/zephyr.spdx:1210", "a"),
            w("west-list.txt:3", "a"),
            w("spdx/zephyr.spdx", "z"),
            w("spdx/zephyr.spdx:19", "b"),
            w("spdx/zephyr.spdx:19", "a"),
            w("build_info.yml", "a"),
        ];
        sort_warnings(&mut warnings);
        let order: Vec<String> = warnings.iter().map(ToString::to_string).collect();
        assert_eq!(
            order,
            [
                "build_info.yml: a",
                "spdx/zephyr.spdx: z",
                "spdx/zephyr.spdx:19: a",
                "spdx/zephyr.spdx:19: b",
                "spdx/zephyr.spdx:1210: a",
                "west-list.txt:3: a",
            ]
        );
    }
}
