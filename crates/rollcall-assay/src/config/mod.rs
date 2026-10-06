//! The configuration detectors: crypto assets from a build's Kconfig output.
//!
//! [`detect_build`] takes a `--build` directory and reads what the build configured:
//!
//! - a **Zephyr** build ([`layout::resolve`] recognises it as `rollcall generate` does, by
//!   `build_info.yml`, a sysbuild by `domains.yaml` too): every image's `zephyr/.config`, and for
//!   a sysbuild the top-level `zephyr/.config` with the `SB_CONFIG_*` settings, whose MCUboot
//!   symbols add evidence to the MCUboot image's assets;
//! - an **ESP-IDF** project (`sdkconfig` and `build/project_description.json`) or its build
//!   directory (`project_description.json`, with `../sdkconfig`): the `sdkconfig`.
//!
//! Anything else is a note, not an error. Each file is parsed by rollcall-core's panic-free
//! Kconfig parser and evaluated against a [rule set](rules) (`db/config-zephyr.yaml` or
//! `db/config-esp-idf.yaml`, checked against the [algorithm catalogue](crate::catalogue)) by
//! [`detect::evaluate`]. Every asset carries `kconfig-symbol` evidence (`file:line SYMBOL`, the
//! file relative to `--build`) at confidence `high` from detector `kconfig` (Zephyr) or
//! `sdkconfig` (ESP-IDF).
//!
//! # Placement
//!
//! Assets go under `image / library:<lib> / cryptographic-asset:<name>`, named by
//! [`asset_name`](crate::assets::asset_name):
//!
//! | Configuration | Image |
//! |---------------|-------|
//! | the Zephyr `MAIN` image, a single-image Zephyr build, an ESP-IDF `sdkconfig` | `application:<--product name>` |
//! | an image with `CONFIG_MCUBOOT=y` (and the sysbuild `SB_CONFIG_*` MCUboot settings) | `bootloader:mcuboot` |
//! | any other sysbuild image | `application:<image name>` |
//! | ESP-IDF secure boot verification in the bootloader | `bootloader:bootloader` |
//!
//! A sysbuild image other than `MAIN` whose name is the `--product` name would land in the
//! same `application:<name>` image as `MAIN`; that is a [`ConfigError::BuildInfo`] asking for
//! another `--product`.
//!
//! # Compiled out
//!
//! [`ConfigInventory::compiled_out`] records every image the detectors evaluated and lists,
//! per image and library, the algorithms that explicitly-off symbols compile out
//! (`CONFIG_MBEDTLS_CIPHER_MODE_CBC=n` out of `mbedtls`, or both `CONFIG_PSA_WANT_ALG_CBC_*`
//! not set out of `psa-crypto`). A symbol missing from the file never counts; an algorithm the
//! image's configuration emits is never compiled out there; a configuration header Kconfig
//! does not generate (`CONFIG_MBEDTLS_USER_CONFIG_FILE`) drops the image's `mbedtls` and
//! `psa-crypto` entries. [`apply_compiled_out`] uses the list to drop or down-weight source
//! findings.

pub mod compiled_out;
pub mod detect;
pub mod layout;
pub mod rules;
pub mod value;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use rollcall_core::merge::ProductSpec;
use rollcall_core::model::{Component, ComponentKind, Image, ImageKind};
use rollcall_core::zephyr::kconfig::KconfigError;

use crate::catalogue::Catalogue;

pub use compiled_out::{
    CompiledOut, CompiledOutAction, CompiledOutEntry, Suppressed, apply_compiled_out,
};
pub use detect::{AssetKey, FoundAsset, ImageFindings, evaluate};
pub use layout::{ConfigFile, Layout};
pub use rules::RuleSet;

/// An image's identity, as the inventory and the compiled-out list key it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageKey {
    /// The image's kind.
    pub kind: ImageKind,
    /// The image's name.
    pub name: String,
    /// The image's version.
    pub version: Option<String>,
}

impl ImageKey {
    /// A key.
    pub fn new(kind: ImageKind, name: &str, version: Option<&str>) -> Self {
        Self {
            kind,
            name: name.to_owned(),
            version: version.map(str::to_owned),
        }
    }

    /// The key of `image`.
    pub fn of(image: &Image) -> Self {
        Self::new(image.kind, &image.name, image.version.as_deref())
    }
}

impl fmt::Display for ImageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.name)?;
        if let Some(version) = &self.version {
            write!(f, "@{version}")?;
        }
        Ok(())
    }
}

/// Which crypto API an image's mbedTLS configuration uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CryptoApi {
    /// The PSA Crypto API.
    Psa,
    /// The legacy mbedTLS crypto API.
    Legacy,
    /// Both.
    Both,
}

/// What [`detect_build`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigInventory {
    /// The images with at least one asset, each with its library components and their assets.
    pub images: Vec<Image>,
    /// Every evaluated image and the algorithms compiled out of its libraries.
    pub compiled_out: CompiledOut,
    /// The crypto API each image with mbedTLS uses.
    pub apis: BTreeMap<ImageKey, CryptoApi>,
    /// The detectors that ran (`kconfig`, `sdkconfig`).
    pub detectors: BTreeSet<&'static str>,
    /// Things the user should know, sorted and without duplicates.
    pub notes: Vec<String>,
}

/// Why [`detect_build`] could not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A file could not be read (a directory, no permission, …).
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// A file the build layout requires does not exist.
    #[error("{}: not found", path.display())]
    Missing {
        /// The file.
        path: PathBuf,
    },
    /// A file is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// A `.config` or `sdkconfig` is malformed.
    #[error("{}", kconfig_message(path, source))]
    Kconfig {
        /// The file.
        path: PathBuf,
        /// What is wrong, with the line.
        source: KconfigError,
    },
    /// A `build_info.yml` is malformed, or its sysbuild image list is unusable.
    #[error("{}: {message}", path.display())]
    BuildInfo {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        message: String,
    },
    /// A `project_description.json` is malformed.
    #[error("{}: {message}", path.display())]
    ProjectDescription {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        message: String,
    },
    /// A built-in rule set does not load or does not agree with the catalogue.
    #[error("{message}")]
    Rules {
        /// What is wrong, one finding per line.
        message: String,
    },
    /// An asset or image could not be built (an internal inconsistency).
    #[error("{message}")]
    Model {
        /// What is wrong.
        message: String,
    },
}

impl ConfigError {
    /// Whether the error is about an input file that is missing or unreadable (exit 66), not
    /// one that is malformed (exit 65).
    pub fn is_input_error(&self) -> bool {
        matches!(self, Self::Read { .. } | Self::Missing { .. })
    }
}

/// `path:line: what`, for a Kconfig error with a line.
fn kconfig_message(path: &Path, source: &KconfigError) -> String {
    match source {
        KconfigError::UnknownSyntax { line } => format!(
            "{}:{line}: unknown syntax (expected `SYMBOL=value`, `# SYMBOL is not set` or a comment)",
            path.display()
        ),
        KconfigError::UnterminatedString { line } => {
            format!("{}:{line}: unterminated string value", path.display())
        }
        other => format!("{}: {other}", path.display()),
    }
}

/// Reads `path` as UTF-8: [`ConfigError::Missing`] when it does not exist,
/// [`ConfigError::Read`] when it cannot be read, [`ConfigError::NotUtf8`] when it is not text.
pub(crate) fn read_text(path: &Path) -> Result<String, ConfigError> {
    let bytes = std::fs::read(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ConfigError::Missing {
                path: path.to_owned(),
            }
        } else {
            ConfigError::Read {
                path: path.to_owned(),
                source,
            }
        }
    })?;
    String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8 {
        path: path.to_owned(),
    })
}

fn model_err(e: impl fmt::Display) -> ConfigError {
    ConfigError::Model {
        message: e.to_string(),
    }
}

/// Every image's findings, keyed by image.
type Findings = BTreeMap<ImageKey, ImageFindings>;

/// Adds `found` (the findings of one file) to `all`.
fn absorb(
    all: &mut Findings,
    notes: &mut BTreeSet<String>,
    image: &ImageKey,
    found: ImageFindings,
) {
    notes.extend(found.notes.iter().cloned());
    for (key, asset) in found.assets {
        all.entry(key.image.clone()).or_default().insert(key, asset);
    }
    let target = all.entry(image.clone()).or_default();
    for entry in found.compiled_out.into_values() {
        target.add_compiled_out(entry);
    }
}

/// Takes the configuration inventory of the build directory `build` for `product`, with the
/// assets' properties from `catalogue`. See the [module docs](self).
pub fn detect_build(
    build: &Path,
    product: &ProductSpec,
    catalogue: &Catalogue,
) -> Result<ConfigInventory, ConfigError> {
    let layout = layout::resolve(build)?;
    let app = ImageKey::new(ImageKind::Application, product.name(), None);
    let mut all: Findings = BTreeMap::new();
    let mut notes = BTreeSet::new();
    let mut apis = BTreeMap::new();
    let mut detectors = BTreeSet::new();
    let load = |rules: Result<RuleSet, rules::RulesError>| -> Result<RuleSet, ConfigError> {
        let rules = rules.map_err(|e| ConfigError::Rules {
            message: e.to_string(),
        })?;
        let findings = rules.lint(catalogue);
        if findings.is_empty() {
            Ok(rules)
        } else {
            Err(ConfigError::Rules {
                message: findings
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            })
        }
    };
    match layout {
        Layout::Unrecognised { note } => {
            notes.insert(note);
        }
        Layout::Zephyr { images, sysbuild } => {
            let rules = load(RuleSet::builtin_zephyr())?;
            detectors.insert("kconfig");
            let bootloaders = images.iter().filter(|i| i.is_mcuboot()).count();
            let mut mcuboot_key = None;
            for image in &images {
                let key = match &image.role {
                    layout::Role::Main => app.clone(),
                    layout::Role::Image(name) if image.is_mcuboot() => {
                        let name = if bootloaders == 1 { "mcuboot" } else { name };
                        ImageKey::new(ImageKind::Bootloader, name, None)
                    }
                    layout::Role::Image(name) if *name == app.name => {
                        return Err(ConfigError::BuildInfo {
                            path: build.join("build_info.yml"),
                            message: format!(
                                "sysbuild image {name:?} is not the MAIN image but has the --product name, so its assets would merge into the MAIN image's; pass another --product"
                            ),
                        });
                    }
                    layout::Role::Image(name) => ImageKey::new(ImageKind::Application, name, None),
                };
                if image.is_mcuboot() && mcuboot_key.is_none() {
                    mcuboot_key = Some(key.clone());
                }
                let found = evaluate(&rules, &image.config, &image.file, &key, catalogue);
                if let Some(api) = found.api {
                    apis.insert(key.clone(), api);
                }
                absorb(&mut all, &mut notes, &key, found);
            }
            if let Some((file, config)) = sysbuild {
                let target = mcuboot_key
                    .unwrap_or_else(|| ImageKey::new(ImageKind::Bootloader, "mcuboot", None));
                let found = evaluate(&rules, &config, &file, &target, catalogue);
                notes.extend(found.notes.iter().cloned());
                for (key, asset) in found.assets {
                    all.entry(key.image.clone())
                        .or_default()
                        .insert_or_attach(key, asset);
                }
            }
        }
        Layout::EspIdf { file, config } => {
            let rules = load(RuleSet::builtin_esp_idf())?;
            detectors.insert("sdkconfig");
            let found = evaluate(&rules, &config, &file, &app, catalogue);
            if let Some(api) = found.api {
                apis.insert(app.clone(), api);
            }
            absorb(&mut all, &mut notes, &app, found);
        }
    }
    let mut compiled_out = CompiledOut::new();
    let mut images = Vec::new();
    for (key, mut findings) in all {
        // Every image evaluated or given assets, so one with no entries empties `everywhere`.
        compiled_out.add_image(key.clone());
        findings.drop_emitted_from_compiled_out();
        for entry in findings.compiled_out_entries() {
            compiled_out.add(key.clone(), entry.clone());
        }
        if let Some(image) = build_image(&key, findings)? {
            images.push(image);
        }
    }
    Ok(ConfigInventory {
        images,
        compiled_out,
        apis,
        detectors,
        notes: notes.into_iter().collect(),
    })
}

/// The image `key` with its findings' assets under their libraries, or `None` when it has none.
fn build_image(key: &ImageKey, findings: ImageFindings) -> Result<Option<Image>, ConfigError> {
    if findings.assets.is_empty() {
        return Ok(None);
    }
    let mut libraries: BTreeMap<String, Component> = BTreeMap::new();
    for (asset_key, found) in findings.assets {
        let library = match libraries.entry(asset_key.library.clone()) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(
                Component::new(ComponentKind::Library, &asset_key.library).map_err(model_err)?,
            ),
        };
        let component = Component::new(ComponentKind::CryptographicAsset, &asset_key.name)
            .map_err(model_err)?
            .with_crypto(found.asset);
        library.add_component(component).map_err(model_err)?;
    }
    let mut image = Image::new(key.kind, &key.name).map_err(model_err)?;
    if let Some(version) = &key.version {
        image = image.with_version(version);
    }
    for library in libraries.into_values() {
        image.add_component(library).map_err(model_err)?;
    }
    Ok(Some(image))
}
