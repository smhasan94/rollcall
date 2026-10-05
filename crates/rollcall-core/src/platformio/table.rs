//! The PlatformIO table, `db/platformio.yaml` (`format: rollcall-platformio/1`): the framework
//! packages PlatformIO installs, mapped to the upstream projects they package.
//!
//! # Schema
//!
//! ```yaml
//! format: rollcall-platformio/1
//! registry: https://registry.platformio.org   # the repository_url of registry purls
//! frameworks:                       # in package order
//!   - package: framework-arduinoespressif32   # the PlatformIO package, unique
//!     framework: arduino            # the `framework =` value that selects it
//!     platforms: [espressif32]      # optional: the platforms it serves (default: any)
//!     name: arduino-esp32           # the component's name
//!     description: Arduino core for the ESP32 family
//!     purl: 'pkg:generic/arduino-esp32@{version}?vcs_url=git+https://github.com/espressif/arduino-esp32'
//!     cpe: 'cpe:2.3:a:espressif:arduino-esp32:{version}:*:*:*:*:*:*:*'   # optional
//!     supplier: Espressif Systems
//!     supplier_url: https://www.espressif.com
//!     licence: LGPL-2.1-or-later
//!     versions: {3.20017.241212: 2.0.17}   # optional: package version -> upstream release
//! ```
//!
//! `{version}` is the upstream release. [`FrameworkEntry::upstream_version`] takes it from
//! `versions` (the package version without its `+build` metadata), else decodes PlatformIO's
//! convention: the package version's middle number is the release, `MAJOR` then two digits
//! each of minor and patch (`3.20017.241212` → `2.0.17`, `3.50201.0` → `5.2.1`).
//!
//! # Rules
//!
//! Loading checks, and fails with [`TableError::Invalid`] listing every problem: the
//! format; the registry an `https` URL; packages unique and in order, names
//! `[a-z0-9][a-z0-9-]*`; non-empty framework, description and supplier; every template,
//! filled in with `1.0.0`, a valid purl or CPE (a CPE template must hold `{version}`); the
//! supplier URL and licence valid; every `versions` entry non-empty and, where the package
//! version follows the convention, equal to its decoding. Unknown keys are rejected.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::model::{Cpe, License, Purl, Supplier};

/// The `format` this rollcall reads.
pub const FORMAT: &str = "rollcall-platformio/1";
/// How errors and evidence cite the built-in table.
pub const BUILTIN_NAME: &str = "platformio.yaml";

const BUILTIN: &str = include_str!("../../db/platformio.yaml");

/// A loaded, checked PlatformIO table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIoTable {
    /// The PlatformIO registry's URL.
    pub registry: String,
    /// The framework packages, in package order.
    pub frameworks: Vec<FrameworkEntry>,
}

/// One framework package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameworkEntry {
    /// The PlatformIO package.
    pub package: String,
    /// The `framework =` value that selects it.
    pub framework: String,
    /// The platforms it serves; empty for any.
    pub platforms: Vec<String>,
    /// The component's name.
    pub name: String,
    /// What it is.
    pub description: String,
    /// The purl template.
    pub purl: String,
    /// The CPE template, if any.
    pub cpe: Option<String>,
    /// The supplier.
    pub supplier: Supplier,
    /// The licence.
    pub licence: License,
    /// Package version (without build metadata) → upstream release, checked by hand.
    pub versions: BTreeMap<String, String>,
}

/// Where an upstream version came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    /// The table's `versions`.
    Table,
    /// Decoded from the package version.
    Decoded,
}

impl FrameworkEntry {
    /// The upstream release of package version `package_version`, and where it came from.
    pub fn upstream_version(&self, package_version: &str) -> Option<(String, VersionSource)> {
        let plain = package_version.split('+').next().unwrap_or(package_version);
        if let Some(v) = self.versions.get(plain) {
            return Some((v.clone(), VersionSource::Table));
        }
        decode(plain).map(|v| (v, VersionSource::Decoded))
    }

    /// Whether this entry serves `framework` on `platform`.
    pub fn serves(&self, framework: &str, platform: &str) -> bool {
        self.framework == framework
            && (self.platforms.is_empty() || self.platforms.iter().any(|p| p == platform))
    }
}

/// Decodes PlatformIO's framework version convention (see the module docs).
pub fn decode(package_version: &str) -> Option<String> {
    let plain = package_version.split('+').next().unwrap_or(package_version);
    let middle = plain.split('.').nth(1)?;
    if middle.len() != 5 || !middle.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let major = middle.get(..1)?.parse::<u32>().ok()?;
    let minor = middle.get(1..3)?.parse::<u32>().ok()?;
    let patch = middle.get(3..5)?.parse::<u32>().ok()?;
    Some(format!("{major}.{minor}.{patch}"))
}

/// Fills `{version}` in a template.
pub fn fill(template: &str, version: &str) -> String {
    template.replace("{version}", version)
}

/// Why the table could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TableError {
    /// Empty, not YAML, an unknown key or a value of the wrong type.
    #[error("{name}: {message}")]
    Yaml {
        /// The table's name.
        name: String,
        /// What is wrong.
        message: String,
    },
    /// The table parsed but breaks the rules; one message per problem.
    #[error("{name}: {}", problems.join("; "))]
    Invalid {
        /// The table's name.
        name: String,
        /// Every problem.
        problems: Vec<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    format: String,
    registry: String,
    frameworks: Vec<RawFramework>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFramework {
    package: String,
    framework: String,
    #[serde(default)]
    platforms: Vec<String>,
    name: String,
    description: String,
    purl: String,
    #[serde(default)]
    cpe: Option<String>,
    supplier: String,
    supplier_url: String,
    licence: String,
    #[serde(default)]
    versions: BTreeMap<String, String>,
}

fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Loads the table shipped with rollcall.
pub fn builtin() -> Result<PlatformIoTable, TableError> {
    load_str(BUILTIN_NAME, BUILTIN)
}

/// Loads a table from text; `name` is how errors cite it.
pub fn load_str(name: &str, text: &str) -> Result<PlatformIoTable, TableError> {
    let yaml_err = |message: String| TableError::Yaml {
        name: name.to_owned(),
        message,
    };
    if text.trim().is_empty() {
        return Err(yaml_err("empty table".to_owned()));
    }
    let raw: RawTable = yaml_serde::from_str(text).map_err(|e| yaml_err(e.to_string()))?;
    let mut problems = Vec::new();
    if raw.format != FORMAT {
        problems.push(format!("format is {:?}, expected {FORMAT:?}", raw.format));
    }
    if !raw.registry.starts_with("https://") || raw.registry.ends_with('/') {
        problems.push(format!(
            "registry {:?} must be an https URL without a trailing /",
            raw.registry
        ));
    }
    let mut seen = BTreeSet::new();
    let mut previous: Option<String> = None;
    let mut frameworks = Vec::with_capacity(raw.frameworks.len());
    for f in raw.frameworks {
        let what = format!("framework {}", f.package);
        if !is_name(&f.package) || !is_name(&f.name) {
            problems.push(format!(
                "{what}: package and name must match [a-z0-9][a-z0-9-]*"
            ));
        }
        if !seen.insert(f.package.clone()) {
            problems.push(format!("{what}: duplicate package"));
        }
        if previous.as_ref().is_some_and(|p| *p > f.package) {
            problems.push(format!("{what}: not in package order"));
        }
        previous = Some(f.package.clone());
        if f.framework.trim().is_empty() || f.description.trim().is_empty() {
            problems.push(format!(
                "{what}: framework and description must not be empty"
            ));
        }
        if let Err(e) = Purl::new(&fill(&f.purl, "1.0.0")) {
            problems.push(format!("{what}: purl template {:?}: {e}", f.purl));
        }
        if let Some(cpe) = &f.cpe {
            if !cpe.contains("{version}") {
                problems.push(format!("{what}: cpe template {cpe:?} has no {{version}}"));
            }
            if let Err(e) = Cpe::new(&fill(cpe, "1.0.0")) {
                problems.push(format!("{what}: cpe template {cpe:?}: {e}"));
            }
        }
        let supplier = match Supplier::new(&f.supplier).and_then(|s| s.with_url(&f.supplier_url)) {
            Ok(s) => Some(s),
            Err(e) => {
                problems.push(format!("{what}: supplier: {e}"));
                None
            }
        };
        let licence = match License::new(&f.licence) {
            Ok(l) => Some(l),
            Err(e) => {
                problems.push(format!("{what}: licence {:?}: {e}", f.licence));
                None
            }
        };
        for (package_version, upstream) in &f.versions {
            if package_version.trim().is_empty() || upstream.trim().is_empty() {
                problems.push(format!("{what}: empty versions entry"));
            }
            if let Some(decoded) = decode(package_version)
                && decoded != *upstream
            {
                problems.push(format!(
                    "{what}: versions {package_version}: {upstream} is not its decoding {decoded}"
                ));
            }
        }
        if let (Some(supplier), Some(licence)) = (supplier, licence) {
            frameworks.push(FrameworkEntry {
                package: f.package,
                framework: f.framework,
                platforms: f.platforms,
                name: f.name,
                description: f.description,
                purl: f.purl,
                cpe: f.cpe,
                supplier,
                licence,
                versions: f.versions,
            });
        }
    }
    if !problems.is_empty() {
        return Err(TableError::Invalid {
            name: name.to_owned(),
            problems,
        });
    }
    Ok(PlatformIoTable {
        registry: raw.registry,
        frameworks,
    })
}

impl PlatformIoTable {
    /// The entry for `package`.
    pub fn by_package(&self, package: &str) -> Option<&FrameworkEntry> {
        self.frameworks.iter().find(|f| f.package == package)
    }

    /// The entry serving `framework` on `platform`, when exactly one does.
    pub fn by_framework(&self, framework: &str, platform: &str) -> Option<&FrameworkEntry> {
        let mut matches = self
            .frameworks
            .iter()
            .filter(|f| f.serves(framework, platform));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_table_loads_and_maps_arduino_esp32() {
        let t = builtin().unwrap();
        assert_eq!(t.registry, "https://registry.platformio.org");
        let a = t.by_package("framework-arduinoespressif32").unwrap();
        assert_eq!(a.name, "arduino-esp32");
        assert_eq!(
            a.upstream_version("3.20017.241212+sha.dcc1105b"),
            Some(("2.0.17".to_owned(), VersionSource::Table))
        );
        assert_eq!(
            t.by_framework("arduino", "espressif32")
                .map(|f| f.package.as_str()),
            Some("framework-arduinoespressif32")
        );
        assert_eq!(t.by_framework("arduino", "atmelavr"), None);
        assert_eq!(
            t.by_framework("zephyr", "nordicnrf52")
                .map(|f| f.name.as_str()),
            Some("zephyr")
        );
        // The ESP-IDF entry spells ESP-IDF's identifiers as the ESP-IDF table does.
        let esp = crate::esp_idf::table::builtin().unwrap();
        let e = t.by_package("framework-espidf").unwrap();
        assert_eq!(e.purl, esp.idf.purl);
        assert_eq!(e.cpe.as_deref(), Some(esp.idf.cpe.as_str()));
        assert_eq!(e.licence, esp.idf.licence);
    }

    #[test]
    fn versions_decode_by_the_convention() {
        assert_eq!(decode("3.20017.241212").as_deref(), Some("2.0.17"));
        assert_eq!(decode("3.50201.0").as_deref(), Some("5.2.1"));
        assert_eq!(decode("2.20701.220816+sha.1").as_deref(), Some("2.7.1"));
        for v in ["6.10.0", "1", "", "3.2001.1", "3.2a017.1", "x.y.z"] {
            assert_eq!(decode(v), None, "{v}");
        }
    }

    #[test]
    fn bad_tables_list_every_problem() {
        let text = "format: rollcall-platformio/2\nregistry: http://x/\nframeworks:\n  - package: zz\n    framework: ''\n    name: Bad Name\n    description: d\n    purl: 'nope'\n    cpe: 'cpe:2.3:a:x:y:1:*:*:*:*:*:*:*'\n    supplier: ''\n    supplier_url: not-a-url\n    licence: 'NOT A LICENCE('\n    versions: {3.20017.0: 9.9.9}\n  - package: aa\n    framework: f\n    name: aa\n    description: d\n    purl: 'pkg:generic/aa@{version}'\n    supplier: S\n    supplier_url: https://s.example\n    licence: MIT\n";
        let TableError::Invalid { problems, .. } = load_str("t.yaml", text).unwrap_err() else {
            panic!("not Invalid");
        };
        let all = problems.join("\n");
        for needle in [
            "format is",
            "registry",
            "must match",
            "must not be empty",
            "purl template",
            "has no {version}",
            "supplier",
            "licence",
            "is not its decoding 2.0.17",
            "not in package order",
        ] {
            assert!(all.contains(needle), "{all}\nlacks {needle:?}");
        }
        for text in [
            "",
            "format: [",
            "format: rollcall-platformio/1\nregistry: https://r\nframeworks: []\nextra: 1\n",
        ] {
            assert!(
                matches!(load_str("t.yaml", text), Err(TableError::Yaml { .. })),
                "{text:?}"
            );
        }
    }
}
