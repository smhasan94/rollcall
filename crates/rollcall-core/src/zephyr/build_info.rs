//! Parser for the `build_info.yml` Zephyr's CMake writes into every build directory.
//!
//! Only the keys rollcall uses are read; unknown keys are ignored. An image build has
//! `cmake.application`, `cmake.zephyr` and `cmake.toolchain`; a sysbuild top-level build has
//! `cmake.images[]` (and `cmake.sysbuild: 'true'`) instead.

use serde::Deserialize;

/// The parts of `build_info.yml` rollcall reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BuildInfo {
    /// The file format version, e.g. `0.1.0`.
    #[serde(default)]
    pub version: Option<String>,
    /// The `cmake` section; [`parse`] checks it is present.
    #[serde(default)]
    pub cmake: Option<Cmake>,
    /// The `west` section, if the build was run through west.
    #[serde(default)]
    pub west: Option<West>,
}

/// `cmake:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Cmake {
    /// `cmake.application`; [`parse`] checks it is present.
    #[serde(default)]
    pub application: Option<Application>,
    /// `cmake.board`.
    #[serde(default)]
    pub board: Option<Board>,
    /// `cmake.zephyr` (image builds only).
    #[serde(default)]
    pub zephyr: Option<ZephyrInfo>,
    /// `cmake.toolchain` (image builds only).
    #[serde(default)]
    pub toolchain: Option<Toolchain>,
    /// `cmake.images` (sysbuild top-level builds only).
    #[serde(default)]
    pub images: Option<Vec<SysbuildImage>>,
    /// `cmake.sysbuild`, `'true'` in a sysbuild top-level build.
    #[serde(default)]
    pub sysbuild: Option<String>,
}

/// `cmake.application`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Application {
    /// The application source directory; [`parse`] checks it is present.
    #[serde(default)]
    pub source_dir: Option<String>,
    /// The application configuration directory.
    #[serde(default)]
    pub configuration_dir: Option<String>,
}

/// `cmake.board`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Board {
    /// E.g. `nrf52840dk`.
    #[serde(default)]
    pub name: Option<String>,
    /// E.g. `nrf52840`.
    #[serde(default)]
    pub qualifiers: Option<String>,
    /// The board revision, often empty.
    #[serde(default)]
    pub revision: Option<String>,
}

/// `cmake.zephyr`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ZephyrInfo {
    /// The Zephyr version, e.g. `4.4.2`.
    #[serde(default)]
    pub version: Option<String>,
    /// `ZEPHYR_BASE`.
    #[serde(default)]
    pub zephyr_base: Option<String>,
}

/// `cmake.toolchain`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Toolchain {
    /// The toolchain variant, e.g. `zephyr` for the Zephyr SDK.
    #[serde(default)]
    pub name: Option<String>,
    /// Where it is installed.
    #[serde(default)]
    pub path: Option<String>,
}

/// One entry of `cmake.images`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SysbuildImage {
    /// The image name, which is also its build subdirectory.
    pub name: String,
    /// The image's source directory.
    #[serde(default)]
    pub source_dir: Option<String>,
    /// `MAIN`, `BOOTLOADER`, …
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// `west:`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct West {
    /// The west version.
    #[serde(default)]
    pub version: Option<String>,
}

/// Why `build_info.yml` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuildInfoError {
    /// Not YAML, or a key has the wrong type. The message includes the line and column.
    #[error("not valid build_info YAML: {0}")]
    Yaml(String),
    /// The file is empty.
    #[error("empty build_info.yml")]
    Empty,
    /// A required key is missing.
    #[error("missing key {key}")]
    Missing {
        /// The dotted key, e.g. `cmake.application.source-dir`.
        key: &'static str,
    },
}

/// Parses `build_info.yml` and checks `cmake.application.source-dir` is present.
pub fn parse(text: &str) -> Result<BuildInfo, BuildInfoError> {
    if text.trim().is_empty() {
        return Err(BuildInfoError::Empty);
    }
    let info: Option<BuildInfo> =
        yaml_serde::from_str(text).map_err(|e| BuildInfoError::Yaml(e.to_string()))?;
    let info = info.ok_or(BuildInfoError::Empty)?;
    let cmake = info
        .cmake
        .as_ref()
        .ok_or(BuildInfoError::Missing { key: "cmake" })?;
    let application = cmake.application.as_ref().ok_or(BuildInfoError::Missing {
        key: "cmake.application",
    })?;
    if application.source_dir.is_none() {
        return Err(BuildInfoError::Missing {
            key: "cmake.application.source-dir",
        });
    }
    Ok(info)
}

impl BuildInfo {
    fn cmake(&self) -> Option<&Cmake> {
        self.cmake.as_ref()
    }

    /// True for a sysbuild top-level build directory (it lists `cmake.images`, or says
    /// `cmake.sysbuild: 'true'`), which holds no image of its own.
    pub fn is_sysbuild(&self) -> bool {
        self.cmake().is_some_and(|c| {
            c.images.is_some() || c.sysbuild.as_deref().is_some_and(|s| s == "true")
        })
    }

    /// The name of the sysbuild image of type `MAIN`, if listed.
    pub fn main_image(&self) -> Option<&str> {
        self.cmake()?
            .images
            .as_ref()?
            .iter()
            .find(|i| i.kind.as_deref() == Some("MAIN"))
            .map(|i| i.name.as_str())
    }

    /// The application name: the last path component of `cmake.application.source-dir`.
    pub fn app_name(&self) -> Option<&str> {
        let dir = self.cmake()?.application.as_ref()?.source_dir.as_deref()?;
        dir.split(['/', '\\']).rfind(|part| !part.is_empty())
    }

    /// `cmake.zephyr.version`.
    pub fn zephyr_version(&self) -> Option<&str> {
        self.cmake()?.zephyr.as_ref()?.version.as_deref()
    }

    /// `cmake.toolchain.name`.
    pub fn toolchain_name(&self) -> Option<&str> {
        self.cmake()?.toolchain.as_ref()?.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const IMAGE: &str = "cmake:
  application:
    configuration-dir: '/zephyrproject/zephyr/samples/sysbuild/with_mcuboot'
    source-dir: '/zephyrproject/zephyr/samples/sysbuild/with_mcuboot'
  board:
    name: 'nrf52840dk'
    path:
     - '/zephyrproject/zephyr/boards/nordic/nrf52840dk'
    qualifiers: 'nrf52840'
    revision: ''
  toolchain:
    name: 'zephyr'
    path: '/zephyr-sdk'
  zephyr:
    version: '4.4.2'
    zephyr-base: '/zephyrproject/zephyr'
version: '0.1.0'
";

    const SYSBUILD: &str = "cmake:
  application:
    source-dir: '/zephyrproject/zephyr/share/sysbuild'
  images:
   - name: 'with_mcuboot'
     source-dir: '/zephyrproject/zephyr/samples/sysbuild/with_mcuboot'
     type: 'MAIN'
   - name: 'mcuboot'
     source-dir: '/zephyrproject/bootloader/mcuboot/boot/zephyr'
     type: 'BOOTLOADER'
  sysbuild: 'true'
version: '0.1.0'
west:
  version: '1.5.0'
";

    #[test]
    fn parses_image_build_info() {
        let info = parse(IMAGE).unwrap();
        assert!(!info.is_sysbuild());
        assert_eq!(info.version.as_deref(), Some("0.1.0"));
        assert_eq!(info.zephyr_version(), Some("4.4.2"));
        assert_eq!(info.toolchain_name(), Some("zephyr"));
        let cmake = info.cmake.as_ref().unwrap();
        let board = cmake.board.as_ref().unwrap();
        assert_eq!(board.name.as_deref(), Some("nrf52840dk"));
        assert_eq!(board.revision.as_deref(), Some(""));
        assert_eq!(info.main_image(), None);
    }

    #[test]
    fn parses_sysbuild_build_info_with_images() {
        let info = parse(SYSBUILD).unwrap();
        assert!(info.is_sysbuild());
        assert_eq!(info.main_image(), Some("with_mcuboot"));
        let images = info.cmake.as_ref().unwrap().images.as_ref().unwrap();
        assert_eq!(images.len(), 2);
        assert_eq!(images[1].kind.as_deref(), Some("BOOTLOADER"));
        assert_eq!(info.zephyr_version(), None);
    }

    #[test]
    fn app_name_is_last_path_component() {
        assert_eq!(parse(IMAGE).unwrap().app_name(), Some("with_mcuboot"));
        let trailing = IMAGE.replace(
            "source-dir: '/zephyrproject/zephyr/samples/sysbuild/with_mcuboot'",
            "source-dir: 'C:\\work\\app\\'",
        );
        assert_eq!(parse(&trailing).unwrap().app_name(), Some("app"));
        let root = IMAGE.replace(
            "source-dir: '/zephyrproject/zephyr/samples/sysbuild/with_mcuboot'",
            "source-dir: '/'",
        );
        assert_eq!(parse(&root).unwrap().app_name(), None);
    }

    #[test]
    fn missing_cmake_key_is_error() {
        assert_eq!(
            parse("version: '0.1.0'\n"),
            Err(BuildInfoError::Missing { key: "cmake" })
        );
        assert_eq!(
            parse("cmake:\n  board:\n    name: 'x'\n"),
            Err(BuildInfoError::Missing {
                key: "cmake.application"
            })
        );
        assert_eq!(
            parse("cmake:\n  application:\n    configuration-dir: '/x'\n"),
            Err(BuildInfoError::Missing {
                key: "cmake.application.source-dir"
            })
        );
    }

    #[test]
    fn not_yaml_is_error() {
        for text in [
            "cmake: [unclosed\n",
            "cmake:\n  application: 'a string, not a map'\n",
            "- a\n- list\n",
            "\t\tcmake:: :\n  - ]\n",
            "cmake:\n  images: 3\n",
        ] {
            assert!(
                matches!(parse(text), Err(BuildInfoError::Yaml(_))),
                "{text:?}: {:?}",
                parse(text)
            );
        }
    }

    #[test]
    fn empty_is_error() {
        assert_eq!(parse(""), Err(BuildInfoError::Empty));
        assert_eq!(parse("  \n\n"), Err(BuildInfoError::Empty));
        assert_eq!(parse("# only a comment\n"), Err(BuildInfoError::Empty));
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let text = format!("{IMAGE}future:\n  key: 1\n");
        assert_eq!(parse(&text).unwrap(), parse(IMAGE).unwrap());
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "(?s)(cmake:|  |- |'|:|\n|[a-z-]{1,8}|\\[|\\]|\\{|\\}|&a|\\*a|!|.){0,80}") {
            let _ = parse(&text);
        }
    }
}
