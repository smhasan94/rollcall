//! Which configuration files a `--build` directory has.
//!
//! [`resolve`] recognises:
//!
//! | Directory | Recognised by | Files read |
//! |-----------|---------------|------------|
//! | a Zephyr sysbuild top-level build | `build_info.yml` and `domains.yaml` | each image's `<image>/zephyr/.config` (images from `build_info.yml`'s `cmake.images`), and the top-level `zephyr/.config` (`SB_CONFIG_*`) if there |
//! | a Zephyr image build | `build_info.yml` | `zephyr/.config` |
//! | an ESP-IDF project | `sdkconfig` and `build/project_description.json` | `sdkconfig` |
//! | an ESP-IDF build directory | `project_description.json` | `../sdkconfig` |
//!
//! Recognition is rollcall-core's [`detect`](rollcall_core::detect::detect), as `rollcall
//! generate DIR` does it. Anything else is [`Layout::Unrecognised`], a note rather than an
//! error. In a recognised Zephyr build a missing `.config` is [`ConfigError::Missing`]; a
//! malformed one, `build_info.yml` or `project_description.json` is a data error with the file
//! (and line).

use std::path::{Path, PathBuf};

use rollcall_core::detect::{self, DetectOptions, Inferred};
use rollcall_core::esp_idf::project_description;
use rollcall_core::zephyr::kconfig::Kconfig;
use rollcall_core::zephyr::{self, ZephyrError, build_info, kconfig};

use super::value::option;
use super::{ConfigError, read_text};

/// A configuration file: where it is, and how evidence cites it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigFile {
    /// The file.
    pub path: PathBuf,
    /// The path relative to `--build`, with `/` separators: the evidence location.
    pub label: String,
}

impl ConfigFile {
    /// A file whose path and label are both `label` (for tests and snippets).
    pub fn new(label: &str) -> Self {
        Self {
            path: PathBuf::from(label),
            label: label.to_owned(),
        }
    }

    fn at(build: &Path, label: &str) -> Self {
        let mut path = build.to_owned();
        for part in label.split('/') {
            path.push(part);
        }
        Self {
            path,
            label: label.to_owned(),
        }
    }
}

/// What an image of a Zephyr build is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// The application: a sysbuild `MAIN` image, or a single-image build.
    Main,
    /// Another sysbuild image, by name.
    Image(String),
}

/// One Zephyr image's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageConfig {
    /// What the image is.
    pub role: Role,
    /// Its `.config`.
    pub file: ConfigFile,
    /// The parsed `.config`.
    pub config: Kconfig,
}

impl ImageConfig {
    /// Whether the image is MCUboot (`CONFIG_MCUBOOT=y`).
    pub fn is_mcuboot(&self) -> bool {
        option(&self.config, "CONFIG_MCUBOOT").is_on()
    }
}

/// The configuration files of a `--build` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    /// A Zephyr build.
    Zephyr {
        /// Every image's configuration, in image-name order (one, for a single-image build).
        images: Vec<ImageConfig>,
        /// The sysbuild top-level `zephyr/.config`, when there is one.
        sysbuild: Option<(ConfigFile, Kconfig)>,
    },
    /// An ESP-IDF project or build directory.
    EspIdf {
        /// The `sdkconfig`.
        file: ConfigFile,
        /// The parsed `sdkconfig`.
        config: Kconfig,
    },
    /// Not a build rollcall reads configuration from.
    Unrecognised {
        /// Why, for the user.
        note: String,
    },
}

/// Reads and parses a Kconfig file.
fn parse(file: &ConfigFile) -> Result<Kconfig, ConfigError> {
    let text = read_text(&file.path)?;
    kconfig::parse(&text).map_err(|source| ConfigError::Kconfig {
        path: file.path.clone(),
        source,
    })
}

/// A sysbuild discovery error as a [`ConfigError`].
fn discover_err(info_path: &Path, e: ZephyrError) -> ConfigError {
    match e {
        ZephyrError::Read { path, source } if source.kind() == std::io::ErrorKind::NotFound => {
            ConfigError::Missing { path }
        }
        ZephyrError::Read { path, source } => ConfigError::Read { path, source },
        ZephyrError::NotUtf8 { path } => ConfigError::NotUtf8 { path },
        ZephyrError::BuildInfo { path, source } => ConfigError::BuildInfo {
            path,
            message: source.to_string(),
        },
        other => {
            let text = other.to_string();
            let prefix = format!("{}: ", info_path.display());
            let message = text.strip_prefix(&prefix).unwrap_or(&text).to_owned();
            ConfigError::BuildInfo {
                path: info_path.to_owned(),
                message,
            }
        }
    }
}

fn zephyr(build: &Path, sysbuild: bool) -> Result<Layout, ConfigError> {
    let info_path = build.join("build_info.yml");
    let info = build_info::parse(&read_text(&info_path)?).map_err(|e| ConfigError::BuildInfo {
        path: info_path.clone(),
        message: e.to_string(),
    })?;
    if !(sysbuild || info.is_sysbuild()) {
        let file = ConfigFile::at(build, "zephyr/.config");
        let config = parse(&file)?;
        return Ok(Layout::Zephyr {
            images: vec![ImageConfig {
                role: Role::Main,
                file,
                config,
            }],
            sysbuild: None,
        });
    }
    let mut images = Vec::new();
    for image in zephyr::discover(build).map_err(|e| discover_err(&info_path, e))? {
        let file = ConfigFile::at(build, &format!("{}/zephyr/.config", image.name));
        let config = parse(&file)?;
        let role = if image.is_main() {
            Role::Main
        } else {
            Role::Image(image.name.clone())
        };
        images.push(ImageConfig { role, file, config });
    }
    let top = ConfigFile::at(build, "zephyr/.config");
    let sysbuild = match parse(&top) {
        Ok(config) => Some((top, config)),
        Err(ConfigError::Missing { .. }) => None,
        Err(e) => return Err(e),
    };
    Ok(Layout::Zephyr { images, sysbuild })
}

fn esp_idf_project(build: &Path) -> Result<Layout, ConfigError> {
    let file = ConfigFile::at(build, "sdkconfig");
    let config = parse(&file)?;
    Ok(Layout::EspIdf { file, config })
}

fn esp_idf_build(build: &Path) -> Result<Layout, ConfigError> {
    let description = build.join("project_description.json");
    project_description::parse(&read_text(&description)?).map_err(|e| {
        ConfigError::ProjectDescription {
            path: description.clone(),
            message: e.to_string(),
        }
    })?;
    let file = ConfigFile {
        path: build.join("..").join("sdkconfig"),
        label: "../sdkconfig".to_owned(),
    };
    let config = parse(&file)?;
    Ok(Layout::EspIdf { file, config })
}

/// The configuration files of the directory `build` (see the [module docs](self)).
pub fn resolve(build: &Path) -> Result<Layout, ConfigError> {
    match detect::detect(build, &DetectOptions::default()) {
        Ok(detection) => match detection.inferred {
            Inferred::Zephyr { sysbuild, .. } => zephyr(build, sysbuild),
            Inferred::EspIdf => esp_idf_project(build),
            _ => Ok(unrecognised(
                build,
                &format!("a {} directory", detection.ecosystem),
            )),
        },
        Err(_) if build.join("project_description.json").is_file() => esp_idf_build(build),
        Err(_) => Ok(unrecognised(build, "not a Zephyr or ESP-IDF build")),
    }
}

fn unrecognised(build: &Path, what: &str) -> Layout {
    Layout::Unrecognised {
        note: format!(
            "--build {}: {what}; the configuration detectors read a Zephyr build directory or an \
             ESP-IDF project or build directory, so none ran",
            build.display()
        ),
    }
}
