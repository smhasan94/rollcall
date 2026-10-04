//! The ESP-IDF table, `db/esp-idf.yaml` (`format: rollcall-esp-idf/1`): the `esp-idf`
//! component's identifiers, the subsystems split out of it, and the directories of
//! Espressif's prebuilt libraries.
//!
//! # Schema
//!
//! ```yaml
//! format: rollcall-esp-idf/1
//! idf:
//!   tag: v5.5.1                    # the ESP-IDF release the table was checked against
//!   purl: 'pkg:generic/esp-idf@{version}?vcs_url=git+https://github.com/espressif/esp-idf'
//!   cpe: 'cpe:2.3:a:espressif:esp-idf:{version}:*:*:*:*:*:*:*'
//!   supplier: Espressif Systems
//!   supplier_url: https://www.espressif.com
//!   licence: Apache-2.0
//! subsystems:                      # in name order
//!   - name: mbedtls                # [a-z0-9][a-z0-9-]*, unique
//!     description: Mbed TLS
//!     symbols: [CONFIG_MBEDTLS_TLS_ENABLED]   # any set (y or m) enables it; sorted
//!     archives:                    # build-directory-relative archives; one linked object
//!       - esp-idf/mbedtls/mbedtls/library/libmbedtls.a   #   (not glue) makes it present
//!     glue: [esp_sha256.c]         # optional: source files in those archives that are
//!                                  #   ESP-IDF's own and do not count
//!     subpath: components/mbedtls/mbedtls   # the purl subpath under esp-idf
//!     licence: Apache-2.0 OR GPL-2.0-or-later   # optional (default: idf.licence)
//!     cpe: 'cpe:2.3:a:trustedfirmware:mbed_tls:{version}:*:*:*:*:*:*:*'   # optional
//!     cpe_aliases: ['cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*']   # optional: other
//!                                  #   vendor:products NVD files its CVEs under; needs cpe
//!     purl: 'pkg:generic/mbedtls@{version}?vcs_url=git+https://github.com/espressif/mbedtls'
//!                                  # optional: its own purl (as the identifier database spells
//!                                  #   a module's); default the esp-idf purl with subpath
//!     upstream_versions: {v5.5.1: 3.6.4}   # optional: its own version per ESP-IDF tag
//!     rationale: Why it is its own component.
//! blobs:                           # in dir order
//!   - dir: components/esp_wifi/lib # under the ESP-IDF tree; every linked archive below it
//!     description: Wi-Fi libraries #   is a blob
//!     licence: Apache-2.0
//! ```
//!
//! `{version}` in a template is the ESP-IDF version (`idf`) or the subsystem's upstream
//! version. A subsystem's `cpe`, `cpe_aliases` and `purl` need `upstream_versions`: their
//! version is the upstream project's, not ESP-IDF's. Without an upstream version for the
//! build's tag, a subsystem gets the `esp-idf` purl with its `subpath` and no CPE.
//!
//! # Rules
//!
//! Loading checks, and fails with [`TableError::Invalid`] listing every problem: the
//! format; names well-formed, unique and in order; non-empty description and rationale;
//! symbols `CONFIG_[A-Z0-9_]+`, sorted, without duplicates; archives, `subpath` and blob
//! directories relative `/`-separated paths with no empty, `.` or `..` segment; every
//! template, filled in with `1.0.0`, a valid purl or CPE; every licence a valid SPDX
//! expression; blob directories in order. Unknown keys are rejected.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::model::{Cpe, License, Purl};

/// The `format` this rollcall reads.
pub const FORMAT: &str = "rollcall-esp-idf/1";
/// How errors cite the built-in table.
pub const BUILTIN_NAME: &str = "esp-idf.yaml";

const BUILTIN: &str = include_str!("../../db/esp-idf.yaml");

/// A loaded, checked ESP-IDF table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EspIdfTable {
    /// The `esp-idf` component's identifiers.
    pub idf: IdfEntry,
    /// The subsystems, in name order.
    pub subsystems: Vec<TableSubsystem>,
    /// The blob directories, in order.
    pub blobs: Vec<BlobDir>,
}

/// The `idf:` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdfEntry {
    /// The release the table was checked against.
    pub tag: String,
    /// The purl template.
    pub purl: String,
    /// The CPE template.
    pub cpe: String,
    /// The supplier's name.
    pub supplier: String,
    /// The supplier's URL.
    pub supplier_url: String,
    /// ESP-IDF's licence.
    pub licence: License,
}

/// One subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSubsystem {
    /// The name.
    pub name: String,
    /// A one-line description.
    pub description: String,
    /// The enabling sdkconfig symbols.
    pub symbols: Vec<String>,
    /// Its archives, relative to the build directory.
    pub archives: Vec<String>,
    /// Source files in those archives that are ESP-IDF glue and do not count.
    pub glue: BTreeSet<String>,
    /// Its directory in the ESP-IDF tree, the subpath of its purl.
    pub subpath: String,
    /// Its licence, when not ESP-IDF's.
    pub licence: Option<License>,
    /// Its CPE template, if it has one.
    pub cpe: Option<String>,
    /// Further CPE templates (other vendor:products), rendered as additional CPEs.
    pub cpe_aliases: Vec<String>,
    /// Its own purl template, if it has one.
    pub purl: Option<String>,
    /// Its own version per ESP-IDF tag.
    pub upstream_versions: BTreeMap<String, String>,
    /// Why it is its own component.
    pub rationale: String,
}

/// One blob directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDir {
    /// The directory, relative to the ESP-IDF tree.
    pub dir: String,
    /// What the libraries are.
    pub description: String,
    /// Their licence.
    pub licence: License,
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
        /// What is wrong, with the line when known.
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
    idf: RawIdf,
    subsystems: Vec<RawSubsystem>,
    #[serde(default)]
    blobs: Vec<RawBlob>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdf {
    tag: String,
    purl: String,
    cpe: String,
    supplier: String,
    supplier_url: String,
    licence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubsystem {
    name: String,
    description: String,
    symbols: Vec<String>,
    archives: Vec<String>,
    #[serde(default)]
    glue: Vec<String>,
    subpath: String,
    #[serde(default)]
    licence: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    cpe_aliases: Vec<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    upstream_versions: BTreeMap<String, String>,
    rationale: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlob {
    dir: String,
    description: String,
    licence: String,
}

/// Fills `{version}` in a template.
pub fn fill(template: &str, version: &str) -> String {
    template.replace("{version}", version)
}

/// Whether `path` is relative, `/`-separated, with no empty, `.` or `..` segment.
fn is_clean_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}

fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn is_symbol(symbol: &str) -> bool {
    symbol.strip_prefix("CONFIG_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    })
}

fn is_sorted_unique(items: &[String]) -> bool {
    items.windows(2).all(|w| matches!(w, [a, b] if a < b))
}

/// Loads the table shipped with rollcall.
pub fn builtin() -> Result<EspIdfTable, TableError> {
    load_str(BUILTIN_NAME, BUILTIN)
}

/// Loads a table from text; `name` is how errors cite it.
pub fn load_str(name: &str, text: &str) -> Result<EspIdfTable, TableError> {
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
    let check_purl = |what: &str, template: &str, problems: &mut Vec<String>| {
        if let Err(e) = Purl::new(&fill(template, "1.0.0")) {
            problems.push(format!("{what}: purl template {template:?}: {e}"));
        }
    };
    let check_cpe = |what: &str, template: &str, problems: &mut Vec<String>| {
        if !template.contains("{version}") {
            problems.push(format!(
                "{what}: cpe template {template:?} has no {{version}}"
            ));
        }
        if let Err(e) = Cpe::new(&fill(template, "1.0.0")) {
            problems.push(format!("{what}: cpe template {template:?}: {e}"));
        }
    };
    let licence = |what: &str, text: &str, problems: &mut Vec<String>| match License::new(text) {
        Ok(l) => Some(l),
        Err(e) => {
            problems.push(format!("{what}: licence {text:?}: {e}"));
            None
        }
    };

    check_purl("idf", &raw.idf.purl, &mut problems);
    check_cpe("idf", &raw.idf.cpe, &mut problems);
    if raw.idf.tag.trim().is_empty() || raw.idf.supplier.trim().is_empty() {
        problems.push("idf: tag and supplier must not be empty".to_owned());
    }
    if crate::model::Supplier::new(&raw.idf.supplier)
        .and_then(|s| s.with_url(&raw.idf.supplier_url))
        .is_err()
    {
        problems.push(format!(
            "idf: invalid supplier_url {:?}",
            raw.idf.supplier_url
        ));
    }
    let idf_licence = licence("idf", &raw.idf.licence, &mut problems);

    let mut seen = BTreeSet::new();
    let mut previous: Option<String> = None;
    let mut subsystems = Vec::with_capacity(raw.subsystems.len());
    for s in raw.subsystems {
        let what = format!("subsystem {}", s.name);
        if !is_name(&s.name) {
            problems.push(format!("{what}: name must match [a-z0-9][a-z0-9-]*"));
        }
        if !seen.insert(s.name.clone()) {
            problems.push(format!("{what}: duplicate name"));
        }
        if previous.as_ref().is_some_and(|p| *p > s.name) {
            problems.push(format!("{what}: not in name order"));
        }
        previous = Some(s.name.clone());
        if s.description.trim().is_empty() || s.rationale.trim().is_empty() {
            problems.push(format!(
                "{what}: description and rationale must not be empty"
            ));
        }
        if s.symbols.is_empty()
            || !s.symbols.iter().all(|x| is_symbol(x))
            || !is_sorted_unique(&s.symbols)
        {
            problems.push(format!(
                "{what}: symbols must be CONFIG_[A-Z0-9_]+, non-empty, sorted and unique"
            ));
        }
        if s.archives.is_empty()
            || !s
                .archives
                .iter()
                .all(|a| is_clean_relative(a) && a.ends_with(".a"))
        {
            problems.push(format!(
                "{what}: archives must be relative .a paths, at least one"
            ));
        }
        if !is_clean_relative(&s.subpath) {
            problems.push(format!("{what}: subpath must be a relative path"));
        }
        let own_licence = match &s.licence {
            Some(text) => licence(&what, text, &mut problems),
            None => None,
        };
        if let Some(cpe) = &s.cpe {
            check_cpe(&what, cpe, &mut problems);
            if s.upstream_versions.is_empty() {
                problems.push(format!("{what}: a cpe needs upstream_versions"));
            }
        }
        for alias in &s.cpe_aliases {
            check_cpe(&format!("{what} alias"), alias, &mut problems);
        }
        if !s.cpe_aliases.is_empty() && s.cpe.is_none() {
            problems.push(format!("{what}: cpe_aliases needs a cpe"));
        }
        if let Some(purl) = &s.purl {
            check_purl(&what, purl, &mut problems);
            if !purl.contains("{version}") {
                problems.push(format!("{what}: purl template {purl:?} has no {{version}}"));
            }
            if s.upstream_versions.is_empty() {
                problems.push(format!("{what}: a purl needs upstream_versions"));
            }
        }
        if s.upstream_versions.values().any(|v| v.trim().is_empty()) {
            problems.push(format!("{what}: empty upstream version"));
        }
        subsystems.push(TableSubsystem {
            name: s.name,
            description: s.description,
            symbols: s.symbols,
            archives: s.archives,
            glue: s.glue.into_iter().collect(),
            subpath: s.subpath,
            licence: own_licence,
            cpe: s.cpe,
            cpe_aliases: s.cpe_aliases,
            purl: s.purl,
            upstream_versions: s.upstream_versions,
            rationale: s.rationale,
        });
    }

    let mut blobs = Vec::with_capacity(raw.blobs.len());
    let mut previous: Option<String> = None;
    for b in raw.blobs {
        let what = format!("blob dir {}", b.dir);
        if !is_clean_relative(&b.dir) {
            problems.push(format!("{what}: must be a relative path"));
        }
        if previous.as_ref().is_some_and(|p| *p >= b.dir) {
            problems.push(format!("{what}: not in order"));
        }
        previous = Some(b.dir.clone());
        let blob_licence = licence(&what, &b.licence, &mut problems);
        if let Some(licence) = blob_licence {
            blobs.push(BlobDir {
                dir: b.dir,
                description: b.description,
                licence,
            });
        }
    }

    match idf_licence {
        Some(licence) if problems.is_empty() => Ok(EspIdfTable {
            idf: IdfEntry {
                tag: raw.idf.tag,
                purl: raw.idf.purl,
                cpe: raw.idf.cpe,
                supplier: raw.idf.supplier,
                supplier_url: raw.idf.supplier_url,
                licence,
            },
            subsystems,
            blobs,
        }),
        _ => Err(TableError::Invalid {
            name: name.to_owned(),
            problems,
        }),
    }
}

impl EspIdfTable {
    /// The subsystem called `name`.
    pub fn subsystem(&self, name: &str) -> Option<&TableSubsystem> {
        self.subsystems.iter().find(|s| s.name == name)
    }

    /// The blob directory `idf_relative` (a path relative to the ESP-IDF tree) lies under.
    pub fn blob_dir(&self, idf_relative: &str) -> Option<&BlobDir> {
        self.blobs.iter().find(|b| {
            idf_relative
                .strip_prefix(b.dir.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_table_loads_and_names_the_documented_subsystems() {
        let t = builtin().unwrap();
        assert_eq!(t.idf.tag, "v5.5.1");
        let names: Vec<&str> = t.subsystems.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["bluedroid", "esp-tls", "lwip", "mbedtls", "nimble", "wifi"]
        );
        let mbedtls = t.subsystem("mbedtls").unwrap();
        assert_eq!(mbedtls.upstream_versions["v5.5.1"], "3.6.4");
        assert!(mbedtls.glue.contains("esp_sha256.c"));
        assert_eq!(
            t.blob_dir("components/esp_wifi/lib/esp32/libpp.a")
                .map(|b| b.dir.as_str()),
            Some("components/esp_wifi/lib")
        );
        assert!(t.blob_dir("components/esp_wifi/libx.a").is_none());
        assert!(t.blob_dir("components/esp_wifi/lib").is_none());
    }

    #[test]
    fn malformed_table_is_an_error_not_a_panic() {
        assert!(matches!(load_str("t", ""), Err(TableError::Yaml { .. })));
        assert!(matches!(
            load_str("t", "format: [x]\n"),
            Err(TableError::Yaml { .. })
        ));
        let with_unknown = BUILTIN.replacen("format:", "colour: red\nformat:", 1);
        assert!(matches!(
            load_str("t", &with_unknown),
            Err(TableError::Yaml { .. })
        ));
        for (from, to, needle) in [
            ("format: rollcall-esp-idf/1", "format: other/1", "format"),
            ("- name: wifi", "- name: Wi-Fi", "name must match"),
            ("- name: nimble", "- name: aaa", "not in name order"),
            ("[CONFIG_LWIP_ENABLE]", "[LWIP_ENABLE]", "symbols"),
            ("[esp-idf/lwip/liblwip.a]", "[/abs/liblwip.a]", "archives"),
            ("licence: BSD-3-Clause", "licence: 'not ( spdx'", "licence"),
            (
                "lwip_project:lwip:{version}",
                "lwip_project:lwip",
                "cpe template",
            ),
            (
                "dir: components/esp_phy/lib",
                "dir: components/../x",
                "relative",
            ),
            (
                "cpe_aliases: ['cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*']",
                "cpe_aliases: ['cpe:2.3:a:arm']",
                "alias",
            ),
            (
                "purl: 'pkg:generic/lwip@{version}",
                "purl: 'pkg:generic/lwip@2.2.0",
                "no {version}",
            ),
            (
                "    cpe: 'cpe:2.3:a:trustedfirmware:mbed_tls:{version}:*:*:*:*:*:*:*'\n",
                "",
                "cpe_aliases needs a cpe",
            ),
        ] {
            assert!(BUILTIN.contains(from), "{from}");
            let err = load_str("t", &BUILTIN.replacen(from, to, 1)).unwrap_err();
            assert!(err.to_string().contains(needle), "{to}: {err}");
        }
    }
}
