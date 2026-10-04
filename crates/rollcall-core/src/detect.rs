//! Ecosystem auto-detection: which ingester a directory is for, from the files at its top.
//!
//! [`detect`] looks only at the top of the directory, by file name ([`SIGNALS`]), and never
//! reads a file's contents:
//!
//! | Ecosystem | Matches when the directory holds | Inferred |
//! |-----------|----------------------------------|----------|
//! | `zephyr` | `build_info.yml` | a sysbuild when `domains.yaml` is there too; `west-list.txt` as the west list |
//! | `cargo` | `Cargo.toml`, else `cargo-metadata.json` | a package directory (run `cargo metadata`), or captured metadata |
//! | `esp-idf` | `sdkconfig` and `<build>/project_description.json` (`<build>`: `build`, or [`DetectOptions::build_dir`]) | — |
//! | `platformio` | `platformio.ini` | — |
//!
//! There is no precedence: a directory two ecosystems match is [`DetectError::Ambiguous`],
//! listing them, and one none matches is [`DetectError::NoMatch`], with a hint for each
//! ecosystem that half matches (an `sdkconfig` without a build). A PlatformIO project built
//! with `framework = espidf` keeps its ESP-IDF build under `.pio/build/<env>/` and its
//! configuration in `sdkconfig.<env>`, so it is PlatformIO only.
//! [`detect_as`] checks one ecosystem (the CLI's `--ecosystem`), so the override is the only
//! tie-breaker.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// An ecosystem rollcall ingests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    /// A Zephyr build directory (`--zephyr`).
    Zephyr,
    /// A Rust package or captured `cargo metadata` (`--cargo`, `--cargo-metadata`).
    Cargo,
    /// An ESP-IDF project after `idf.py build` (`--esp-idf`).
    EspIdf,
    /// A PlatformIO project (`--platformio`).
    PlatformIo,
}

impl Ecosystem {
    /// Every ecosystem, in the order they are listed.
    pub const ALL: [Ecosystem; 4] = [Self::Zephyr, Self::Cargo, Self::EspIdf, Self::PlatformIo];

    /// The name used on the command line and in the Action (`esp-idf`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zephyr => "zephyr",
            Self::Cargo => "cargo",
            Self::EspIdf => "esp-idf",
            Self::PlatformIo => "platformio",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|e| e.as_str() == s)
            .ok_or_else(|| {
                format!("unknown ecosystem {s:?}: expected zephyr, cargo, esp-idf or platformio")
            })
    }
}

/// What each ecosystem is recognised by, as printed in errors.
pub const SIGNALS: [(Ecosystem, &str); 4] = [
    (Ecosystem::Zephyr, "build_info.yml"),
    (Ecosystem::Cargo, "Cargo.toml or cargo-metadata.json"),
    (
        Ecosystem::EspIdf,
        "sdkconfig and build/project_description.json",
    ),
    (Ecosystem::PlatformIo, "platformio.ini"),
];

/// How to detect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectOptions {
    /// The ESP-IDF build directory, when not `<dir>/build`.
    pub build_dir: Option<PathBuf>,
}

/// How a detected directory is to be ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inferred {
    /// A Zephyr build.
    Zephyr {
        /// `domains.yaml` is there: a sysbuild top-level directory.
        sysbuild: bool,
        /// `west-list.txt`, if there.
        west_list: Option<PathBuf>,
    },
    /// A Rust package directory (`Cargo.toml`).
    CargoPackage,
    /// Captured `cargo metadata` output.
    CargoMetadata(PathBuf),
    /// An ESP-IDF project.
    EspIdf,
    /// A PlatformIO project.
    PlatformIo,
}

/// A directory's ecosystem, with the files that showed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The ecosystem.
    pub ecosystem: Ecosystem,
    /// The files that matched, relative to the directory.
    pub matched: Vec<String>,
    /// How to ingest it.
    pub inferred: Inferred,
}

/// Why a directory's ecosystem could not be told.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DetectError {
    /// The path is missing or not a directory.
    #[error("{}: not a directory", path.display())]
    NotADirectory {
        /// The path.
        path: PathBuf,
    },
    /// No ecosystem matches (or, with [`detect_as`], not that one).
    #[error("{}: {}", path.display(), no_match_message(looked_for, hints))]
    NoMatch {
        /// The directory.
        path: PathBuf,
        /// What was looked for, per ecosystem.
        looked_for: Vec<(Ecosystem, &'static str)>,
        /// Half matches.
        hints: Vec<String>,
    },
    /// Several ecosystems match.
    #[error("{}: {}", path.display(), ambiguous_message(candidates))]
    Ambiguous {
        /// The directory.
        path: PathBuf,
        /// Each ecosystem that matched, with the files that did.
        candidates: Vec<Detection>,
    },
}

fn no_match_message(looked_for: &[(Ecosystem, &str)], hints: &[String]) -> String {
    let list: Vec<String> = looked_for
        .iter()
        .map(|(e, signal)| format!("{signal} ({e})"))
        .collect();
    let mut message = if looked_for.len() == 1 {
        format!(
            "not a {} directory: no {}",
            looked_for.first().map_or("", |(e, _)| e.as_str()),
            list.join(", ")
        )
    } else {
        format!("no ecosystem recognised; looked for {}", list.join(", "))
    };
    for hint in hints {
        message.push_str("; ");
        message.push_str(hint);
    }
    message
}

fn ambiguous_message(candidates: &[Detection]) -> String {
    let list: Vec<String> = candidates
        .iter()
        .map(|c| format!("{} ({})", c.ecosystem, c.matched.join(", ")))
        .collect();
    let names: Vec<&str> = candidates.iter().map(|c| c.ecosystem.as_str()).collect();
    format!(
        "matches more than one ecosystem: {}; pass --ecosystem {}",
        list.join(", "),
        names.join("|")
    )
}

/// Whether `dir/name` is a file (a symlink to one counts).
fn has(dir: &Path, name: &str) -> bool {
    dir.join(name).is_file()
}

/// `ecosystem`'s detection in `dir`, or the hint when it half matches.
fn check(
    dir: &Path,
    ecosystem: Ecosystem,
    options: &DetectOptions,
) -> Result<Detection, Option<String>> {
    let found = |matched: Vec<&str>, inferred| Detection {
        ecosystem,
        matched: matched.into_iter().map(str::to_owned).collect(),
        inferred,
    };
    match ecosystem {
        Ecosystem::Zephyr => {
            if !has(dir, "build_info.yml") {
                // A Zephyr application's source directory, not its build.
                if has(dir, "prj.conf") || dir.join("build/build_info.yml").is_file() {
                    return Err(Some(
                        "looks like a Zephyr application source directory (prj.conf or build/build_info.yml); pass its build directory (e.g. DIR/build) for Zephyr".to_owned(),
                    ));
                }
                return Err(None);
            }
            let sysbuild = has(dir, "domains.yaml");
            let west = has(dir, "west-list.txt");
            let mut matched = vec!["build_info.yml"];
            if sysbuild {
                matched.push("domains.yaml");
            }
            Ok(found(
                matched,
                Inferred::Zephyr {
                    sysbuild,
                    west_list: west.then(|| dir.join("west-list.txt")),
                },
            ))
        }
        Ecosystem::Cargo => {
            if has(dir, "Cargo.toml") {
                Ok(found(vec!["Cargo.toml"], Inferred::CargoPackage))
            } else if has(dir, "cargo-metadata.json") {
                Ok(found(
                    vec!["cargo-metadata.json"],
                    Inferred::CargoMetadata(dir.join("cargo-metadata.json")),
                ))
            } else {
                Err(None)
            }
        }
        Ecosystem::EspIdf => {
            let build = options
                .build_dir
                .clone()
                .unwrap_or_else(|| dir.join("build"));
            let description = build.join("project_description.json");
            // Named relative to DIR when the build directory is inside it.
            let label = description
                .strip_prefix(dir)
                .unwrap_or(&description)
                .to_string_lossy()
                .replace('\\', "/");
            match (has(dir, "sdkconfig"), description.is_file()) {
                (true, true) => Ok(found(vec!["sdkconfig", label.as_str()], Inferred::EspIdf)),
                (true, false) => Err(Some(
                    "sdkconfig without build/project_description.json: run idf.py build (or give the build directory) for ESP-IDF".to_owned(),
                )),
                _ => Err(None),
            }
        }
        Ecosystem::PlatformIo => {
            if has(dir, "platformio.ini") {
                Ok(found(vec!["platformio.ini"], Inferred::PlatformIo))
            } else {
                Err(None)
            }
        }
    }
}

fn require_dir(dir: &Path) -> Result<(), DetectError> {
    if dir.is_dir() {
        Ok(())
    } else {
        Err(DetectError::NotADirectory {
            path: dir.to_owned(),
        })
    }
}

/// The one ecosystem `dir` is for (see the module docs).
pub fn detect(dir: &Path, options: &DetectOptions) -> Result<Detection, DetectError> {
    require_dir(dir)?;
    let mut candidates = Vec::new();
    let mut hints = Vec::new();
    for ecosystem in Ecosystem::ALL {
        match check(dir, ecosystem, options) {
            Ok(d) => candidates.push(d),
            Err(Some(hint)) => hints.push(hint),
            Err(None) => {}
        }
    }
    match candidates.len() {
        0 => Err(DetectError::NoMatch {
            path: dir.to_owned(),
            looked_for: SIGNALS.to_vec(),
            hints,
        }),
        1 => Ok(candidates.remove(0)),
        _ => Err(DetectError::Ambiguous {
            path: dir.to_owned(),
            candidates,
        }),
    }
}

/// `dir` as `ecosystem` (the `--ecosystem` override): its inferred input, or
/// [`DetectError::NoMatch`] naming what that ecosystem needs.
pub fn detect_as(
    dir: &Path,
    ecosystem: Ecosystem,
    options: &DetectOptions,
) -> Result<Detection, DetectError> {
    require_dir(dir)?;
    check(dir, ecosystem, options).map_err(|hint| DetectError::NoMatch {
        path: dir.to_owned(),
        looked_for: SIGNALS
            .iter()
            .copied()
            .filter(|(e, _)| *e == ecosystem)
            .collect(),
        hints: hint.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for e in Ecosystem::ALL {
            assert_eq!(e.as_str().parse::<Ecosystem>(), Ok(e));
        }
        assert!("espidf".parse::<Ecosystem>().is_err());
        assert_eq!(SIGNALS.map(|(e, _)| e), Ecosystem::ALL);
    }
}
