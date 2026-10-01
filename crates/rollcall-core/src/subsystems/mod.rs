//! The subsystem table: Zephyr subsystem → enabling Kconfig symbols → source paths.
//!
//! The Zephyr kernel package covers far more than the kernel: the Bluetooth stacks, the IP
//! stack, USB, file systems, MCUmgr and so on, each compiled in only when its Kconfig symbols
//! are set. The subsystem table lists those subsystems so the kernel package can be split into
//! the ones a build actually compiled in, each with its own source paths and, where one
//! exists, its own CPE. rollcall ships the table in `db/subsystems.yaml`, next to the
//! identifier database ([`crate::identify`]); [`builtin`] loads it.
//!
//! # Schema
//!
//! ```yaml
//! format: rollcall-subsystems/1
//! zephyr:                          # the Zephyr release the table was verified against
//!   tag: v4.4.2
//!   commit: dccb09599635bdff17633fa7e9dab014b91dce90
//! subsystems:                      # a sequence, in name order
//!   - name: bluetooth-host         # [a-z0-9][a-z0-9-]*, unique
//!     description: Bluetooth LE host
//!     symbols: [CONFIG_BT_HCI_HOST] # any of them set to y or m means compiled in
//!     sources:                     # paths relative to the Zephyr repository root
//!       - subsys/bluetooth/host    # a directory, or a file such as lib/utils/json.c
//!     subpath: subsys/bluetooth/host # optional: the primary source, one of `sources`
//!                                  # (default: the first)
//!     module: null                 # optional: the west project whose library this wraps
//!     cpe: null                    # optional: a CPE 2.3 or 2.2 name
//!     reasons: [cve-history, size] # why it is its own component; at least one
//!     rationale: >-                # the evidence for the reasons, in words
//!       ...
//! ```
//!
//! `reasons` are `cve-history` (the code itself, not a library it wraps, has had CVEs; the
//! rationale cites their IDs, each listed in the pinned tree's
//! `doc/security/vulnerabilities.rst`), `size` (the sources hold more
//! than 2,000 lines of C at the pinned revision) and `upstream-library` (the entry wraps a
//! separately versioned upstream project, named by `module`, that scanners and VEX track on
//! their own; the entry must still own Zephyr-side `.c` files, the glue). `symbols` and `sources` are each in ascending order without duplicates. A
//! source path may lie inside another entry's (the more specific path is the better match),
//! but two entries may not list the same path. Unknown keys are rejected.
//!
//! # Enabling symbols and compiled files
//!
//! An entry's symbols say when the subsystem *as a whole* is compiled in; they are not a full
//! model of Zephyr's CMake gating. Files under a subsystem's paths can be compiled while none
//! of its symbols is set. Such files belong to the Zephyr kernel package, not to the (disabled)
//! subsystem. Known cases at the pinned revision:
//!
//! - `subsys/net/ip`: `net_core.c`, `net_if.c`, `net_timeout.c` and `utils.c` (and more with
//!   `CONFIG_NET_NATIVE`) are compiled with `CONFIG_NETWORKING` even without `CONFIG_NET_IP`.
//! - `subsys/bluetooth/common` and `subsys/bluetooth/lib` are compiled with any `CONFIG_BT`,
//!   including a controller-only build without `CONFIG_BT_HCI_HOST`.
//! - `subsys/fs/fcb` is compiled with `CONFIG_FCB` even without `CONFIG_FILE_SYSTEM`.
//! - `subsys/pm/policy/policy_latency.c` is compiled with
//!   `CONFIG_PM_POLICY_LATENCY_STANDALONE` even without `CONFIG_PM` or `CONFIG_PM_DEVICE`.
//!
//! # Lint rules
//!
//! Loading ([`load_str`], [`load_path`], [`builtin`]) parses the YAML, then runs the
//! structural rules of [`validate`]; any finding makes the load fail with
//! [`SubsystemsError::Lint`], which lists every finding as `file:line: subsystem: message
//! [rule]`, sorted by line. The structural rules ([`Rule`]): the `format` is
//! `rollcall-subsystems/1`; the pin has a tag and a 40-hex-digit commit; names are well-formed,
//! unique (a duplicate name is reported with both lines) and in order; descriptions and
//! rationales are not empty; symbols are `CONFIG_[A-Z0-9_]+`; source paths are relative,
//! `/`-separated, with no empty, `.` or `..` segment and no trailing `/`; `subpath`, if given,
//! is one of the entry's sources; symbol, source and
//! reason lists are non-empty, sorted and without duplicates; no path is listed by two
//! entries; `module` is a west project name; `cpe` is a valid CPE.
//!
//! [`lint_against`] checks a loaded table against a [`Reference`], normally the pinned Zephyr
//! checkout ([`ZephyrTree`]): every symbol must be defined by a `config` or `menuconfig`
//! stanza in some `Kconfig*` file other than a `Kconfig.defconfig*` (`unknown-symbol`), every source path must exist
//! (`unknown-source`), and the tree's version must be the table's tag (`pin-mismatch`).
//! `scripts/verify-subsystems.sh` (the `subsystems` CI job) fetches the pinned tree and runs
//! these checks.
//!
//! # Determinism
//!
//! The table is a sequence kept in name order (the lint enforces it), so iterating it,
//! [`SubsystemTable::enabled_in`] and anything built from them are in name order. Findings
//! are sorted by line, subsystem, rule and message. Nothing depends on hashing or on the
//! order a directory is read in.

pub mod lint;
pub mod tree;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::Cpe;
use crate::zephyr::Kconfig;

pub use lint::{Finding, Reference, Rule, lint_against, validate};
pub use tree::ZephyrTree;

/// The `format` this rollcall reads.
pub const FORMAT: &str = "rollcall-subsystems/1";
/// Where the built-in table lives, relative to the `rollcall-core` crate.
pub const BUILTIN_PATH: &str = "db/subsystems.yaml";
/// The name the built-in table is cited by in errors.
pub const BUILTIN_NAME: &str = "subsystems.yaml";

const BUILTIN: &str = include_str!("../../db/subsystems.yaml");

/// A loaded, validated subsystem table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemTable {
    /// The `format` (always [`FORMAT`] once loaded).
    pub format: String,
    /// The Zephyr release the table was verified against.
    pub zephyr: ZephyrPin,
    /// The subsystems, in name order.
    pub subsystems: Vec<Subsystem>,
}

/// The Zephyr release a table was verified against.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZephyrPin {
    /// The release tag, e.g. `v4.4.2`.
    pub tag: String,
    /// The full commit id of the tag.
    pub commit: String,
}

/// One subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subsystem {
    /// The name, e.g. `bluetooth-host`.
    pub name: String,
    /// A one-line description.
    pub description: String,
    /// The enabling symbols, with their `CONFIG_` prefix; any one set means compiled in.
    pub symbols: Vec<String>,
    /// Source paths relative to the Zephyr repository root (directories or files).
    pub sources: Vec<String>,
    /// The primary source path, given as `subpath` (one of `sources`), when the first source
    /// is not it (e.g. a directory the subsystem shares). See [`Subsystem::primary_source`].
    pub subpath: Option<String>,
    /// The west project whose library this subsystem's glue wraps, if any.
    pub module: Option<String>,
    /// The subsystem's own CPE, if it has one.
    pub cpe: Option<Cpe>,
    /// Why it is its own component.
    pub reasons: Vec<Reason>,
    /// The evidence for the reasons.
    pub rationale: String,
    /// The 1-based line of its `- name:` item, when it could be found.
    pub line: Option<u32>,
}

/// Why a subsystem is its own component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// The code has had CVEs of its own.
    CveHistory,
    /// The sources hold more than 2,000 lines of C.
    Size,
    /// It wraps a separately versioned upstream library.
    UpstreamLibrary,
}

impl Reason {
    /// The name used in the table.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CveHistory => "cve-history",
            Self::Size => "size",
            Self::UpstreamLibrary => "upstream-library",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Subsystem {
    /// The source path that best names the subsystem's code: `subpath` if given, else the
    /// first source. It is the subpath of the subsystem component's purl.
    pub fn primary_source(&self) -> Option<&str> {
        self.subpath
            .as_deref()
            .or_else(|| self.sources.first().map(String::as_str))
    }
}

impl SubsystemTable {
    /// The subsystem called `name`.
    pub fn get(&self, name: &str) -> Option<&Subsystem> {
        self.subsystems.iter().find(|s| s.name == name)
    }

    /// The subsystems with at least one symbol set (`y` or `m`) in `config`, in name order.
    pub fn enabled_in<'a>(&'a self, config: &Kconfig) -> Vec<&'a Subsystem> {
        let mut enabled: Vec<&Subsystem> = self
            .subsystems
            .iter()
            .filter(|s| s.symbols.iter().any(|symbol| config.is_set(symbol)))
            .collect();
        enabled.sort_by(|a, b| a.name.cmp(&b.name));
        enabled
    }
}

/// Why a subsystem table could not be loaded. Every variant names the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubsystemsError {
    /// A file could not be read.
    #[error("{}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: io::Error,
    },
    /// The file is not UTF-8.
    #[error("{}: not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file.
        path: PathBuf,
    },
    /// The file is empty (or only whitespace and comments).
    #[error("{}: empty subsystem table", path.display())]
    Empty {
        /// The file.
        path: PathBuf,
    },
    /// The YAML is malformed or does not match the schema.
    #[error("{}: {message}", Located(path, *line, *column))]
    Yaml {
        /// The file.
        path: PathBuf,
        /// The 1-based line, if known.
        line: Option<u32>,
        /// The 1-based column, if known.
        column: Option<u32>,
        /// What is wrong.
        message: String,
    },
    /// The table parsed but breaks structural rules.
    #[error("{}", Report(path, findings))]
    Lint {
        /// The file.
        path: PathBuf,
        /// Every finding, sorted.
        findings: Vec<Finding>,
    },
}

/// `path`, `path:line` or `path:line:column`.
struct Located<'a>(&'a Path, Option<u32>, Option<u32>);

impl fmt::Display for Located<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())?;
        if let Some(line) = self.1 {
            write!(f, ":{line}")?;
            if let Some(column) = self.2 {
                write!(f, ":{column}")?;
            }
        }
        Ok(())
    }
}

/// One finding per line, each prefixed by the file.
struct Report<'a>(&'a Path, &'a [Finding]);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, finding) in self.1.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{}: {finding}", Located(self.0, finding.line, None))?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTable {
    format: String,
    zephyr: ZephyrPin,
    subsystems: Vec<RawSubsystem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubsystem {
    name: String,
    description: String,
    symbols: Vec<String>,
    sources: Vec<String>,
    #[serde(default)]
    subpath: Option<String>,
    #[serde(default)]
    module: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    reasons: Vec<Reason>,
    rationale: String,
}

/// Loads the table shipped with rollcall ([`BUILTIN_PATH`]).
pub fn builtin() -> Result<SubsystemTable, SubsystemsError> {
    load_str(BUILTIN)
}

/// Loads a table from text, citing it as [`BUILTIN_NAME`] in errors.
pub fn load_str(text: &str) -> Result<SubsystemTable, SubsystemsError> {
    parse(Path::new(BUILTIN_NAME), text)
}

/// Reads and loads the table at `path`; errors cite `path`.
pub fn load_path(path: &Path) -> Result<SubsystemTable, SubsystemsError> {
    let bytes = std::fs::read(path).map_err(|source| SubsystemsError::Read {
        path: path.to_owned(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| SubsystemsError::NotUtf8 {
        path: path.to_owned(),
    })?;
    parse(path, &text)
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// `message` without a trailing ` at line N column M` that repeats the error's own location.
fn without_location(message: &str, line: Option<u32>, column: Option<u32>) -> &str {
    match (line, column) {
        (Some(line), Some(column)) => message
            .strip_suffix(&format!(" at line {line} column {column}"))
            .unwrap_or(message),
        _ => message,
    }
}

/// The 1-based line of every `- name:` sequence item, in file order. Best effort: the result
/// is only used when it has exactly one line per subsystem.
fn entry_lines(text: &str) -> Vec<u32> {
    text.split('\n')
        .enumerate()
        .filter(|(_, line)| {
            let rest = line.trim_start_matches(' ');
            rest.strip_prefix('-')
                .map(|r| r.trim_start_matches(' '))
                .is_some_and(|r| r.starts_with("name:"))
        })
        .map(|(i, _)| to_u32(i.saturating_add(1)))
        .collect()
}

fn parse(path: &Path, text: &str) -> Result<SubsystemTable, SubsystemsError> {
    if text.trim().is_empty() {
        return Err(SubsystemsError::Empty {
            path: path.to_owned(),
        });
    }
    let raw: Option<RawTable> = yaml_serde::from_str(text).map_err(|e| {
        let location = e.location();
        let line = location.as_ref().map(|l| to_u32(l.line()));
        let column = location.as_ref().map(|l| to_u32(l.column()));
        SubsystemsError::Yaml {
            path: path.to_owned(),
            line,
            column,
            message: without_location(&e.to_string(), line, column).to_owned(),
        }
    })?;
    let Some(raw) = raw else {
        return Err(SubsystemsError::Empty {
            path: path.to_owned(),
        });
    };
    let lines = entry_lines(text);
    let lines_known = lines.len() == raw.subsystems.len();
    let mut findings = Vec::new();
    let mut subsystems = Vec::with_capacity(raw.subsystems.len());
    for (i, entry) in raw.subsystems.into_iter().enumerate() {
        let line = if lines_known {
            lines.get(i).copied()
        } else {
            None
        };
        let cpe = match entry.cpe.as_deref() {
            None => None,
            Some(text) => match Cpe::new(text) {
                Ok(cpe) => Some(cpe),
                Err(e) => {
                    findings.push(Finding {
                        line,
                        subsystem: Some(entry.name.clone()),
                        rule: Rule::BadCpe,
                        message: e.to_string(),
                    });
                    None
                }
            },
        };
        subsystems.push(Subsystem {
            name: entry.name,
            description: entry.description,
            symbols: entry.symbols,
            sources: entry.sources,
            subpath: entry.subpath,
            module: entry.module,
            cpe,
            reasons: entry.reasons,
            rationale: entry.rationale,
            line,
        });
    }
    let table = SubsystemTable {
        format: raw.format,
        zephyr: raw.zephyr,
        subsystems,
    };
    findings.extend(validate(&table));
    if findings.is_empty() {
        Ok(table)
    } else {
        findings.sort();
        Err(SubsystemsError::Lint {
            path: path.to_owned(),
            findings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A valid one-entry table; `entry` replaces the entry's body lines.
    fn table_with(entries: &str) -> String {
        format!(
            "format: rollcall-subsystems/1\nzephyr:\n  tag: v4.4.2\n  commit: dccb09599635bdff17633fa7e9dab014b91dce90\nsubsystems:\n{entries}"
        )
    }

    const SHELL: &str = "  - name: shell\n    description: Shell\n    symbols: [CONFIG_SHELL]\n    sources: [subsys/shell]\n    reasons: [size]\n    rationale: Large.\n";

    fn lint_findings(text: &str) -> Vec<Finding> {
        match load_str(text) {
            Err(SubsystemsError::Lint { findings, .. }) => findings,
            Err(other) => panic!("not a lint error: {other}"),
            Ok(_) => panic!("accepted:\n{text}"),
        }
    }

    #[test]
    fn builtin_loads() {
        let table = builtin().unwrap();
        assert_eq!(table.format, FORMAT);
        assert!(!table.subsystems.is_empty());
        // Every entry's line was found.
        assert!(table.subsystems.iter().all(|s| s.line.is_some()));
        assert_eq!(
            BUILTIN_PATH, "db/subsystems.yaml",
            "the include_str! path and BUILTIN_PATH must agree"
        );
    }

    #[test]
    fn minimal_table_loads() {
        let table = load_str(&table_with(SHELL)).unwrap();
        let shell = table.get("shell").unwrap();
        assert_eq!(shell.symbols, ["CONFIG_SHELL"]);
        assert_eq!(shell.line, Some(6));
        assert_eq!(shell.reasons, [Reason::Size]);
        assert!(table.get("nope").is_none());
    }

    /// Each structural [`Rule`] with a minimal table that breaks it, and the entry line the
    /// finding must carry (`None` for table-level rules).
    fn structural_cases() -> Vec<(Rule, String, Option<u32>)> {
        let e = |body: &str| table_with(&format!("  - name: shell\n{body}"));
        let full = |symbols: &str, sources: &str, extra: &str| {
            e(&format!(
                "    description: Shell\n    symbols: {symbols}\n    sources: {sources}\n{extra}    reasons: [size]\n    rationale: Large.\n"
            ))
        };
        vec![
            (
                Rule::WrongFormat,
                table_with(SHELL).replace("rollcall-subsystems/1", "rollcall-subsystems/2"),
                None,
            ),
            (
                Rule::BadPin,
                table_with(SHELL).replace("dccb09599635bdff17633fa7e9dab014b91dce90", "HEAD"),
                None,
            ),
            (
                Rule::DuplicateName,
                table_with(&format!("{SHELL}{SHELL}")),
                Some(12),
            ),
            (
                Rule::BadName,
                table_with(&SHELL.replace("name: shell", "name: Shell_Sub")),
                Some(6),
            ),
            (
                Rule::NotSorted,
                table_with(&format!(
                    "{SHELL}{}",
                    SHELL
                        .replace("name: shell", "name: logging")
                        .replace("CONFIG_SHELL", "CONFIG_LOG")
                        .replace("subsys/shell", "subsys/logging")
                )),
                Some(12),
            ),
            (
                Rule::EmptyDescription,
                table_with(&SHELL.replace("description: Shell", "description: ' '")),
                Some(6),
            ),
            (
                Rule::EmptySymbols,
                full("[]", "[subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::BadSymbol,
                full("[SHELL]", "[subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::DuplicateSymbol,
                full("[CONFIG_SHELL, CONFIG_SHELL]", "[subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::NotSorted,
                full("[CONFIG_SHELL, CONFIG_LOG]", "[subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::EmptySources,
                full("[CONFIG_SHELL]", "[]", ""),
                Some(6),
            ),
            (
                Rule::BadSourcePath,
                full("[CONFIG_SHELL]", "[/subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::BadSourcePath,
                full("[CONFIG_SHELL]", "[subsys/../shell]", ""),
                Some(6),
            ),
            (
                Rule::BadSourcePath,
                full("[CONFIG_SHELL]", "[subsys/shell/]", ""),
                Some(6),
            ),
            (
                Rule::BadSourcePath,
                full("[CONFIG_SHELL]", "['subsys\\shell']", ""),
                Some(6),
            ),
            (
                Rule::BadSourcePath,
                full("[CONFIG_SHELL]", "[subsys//shell]", ""),
                Some(6),
            ),
            (
                Rule::DuplicateSource,
                full("[CONFIG_SHELL]", "[subsys/shell, subsys/shell]", ""),
                Some(6),
            ),
            (
                Rule::DuplicateSource,
                table_with(&format!(
                    "{SHELL}{}",
                    SHELL
                        .replace("name: shell", "name: tshell")
                        .replace("CONFIG_SHELL", "CONFIG_TSHELL")
                )),
                Some(12),
            ),
            (
                Rule::BadModule,
                full("[CONFIG_SHELL]", "[subsys/shell]", "    module: 'a b'\n"),
                Some(6),
            ),
            (
                Rule::BadSubpath,
                full(
                    "[CONFIG_SHELL]",
                    "[subsys/shell]",
                    "    subpath: subsys/shell/x\n",
                ),
                Some(6),
            ),
            (
                Rule::BadCpe,
                full(
                    "[CONFIG_SHELL]",
                    "[subsys/shell]",
                    "    cpe: 'cpe:2.3:a:zephyrproject'\n",
                ),
                Some(6),
            ),
            (
                Rule::EmptyReasons,
                table_with(&SHELL.replace("reasons: [size]", "reasons: []")),
                Some(6),
            ),
            (
                Rule::DuplicateReason,
                table_with(&SHELL.replace("reasons: [size]", "reasons: [size, size]")),
                Some(6),
            ),
            (
                Rule::EmptyRationale,
                table_with(&SHELL.replace("rationale: Large.", "rationale: ''")),
                Some(6),
            ),
        ]
    }

    #[test]
    fn load_str_rejects_structural_findings() {
        let mut covered = std::collections::BTreeSet::new();
        for (rule, text, line) in structural_cases() {
            let findings = lint_findings(&text);
            assert!(
                findings.iter().any(|f| f.rule == rule && f.line == line),
                "{rule:?} at {line:?} not found in {findings:?} for\n{text}"
            );
            covered.insert(rule);
        }
        // Every structural rule has a case; only the reference rules have none here.
        for rule in Rule::ALL {
            let reference_only = matches!(
                rule,
                Rule::UnknownSymbol | Rule::UnknownSource | Rule::PinMismatch
            );
            assert_eq!(covered.contains(&rule), !reference_only, "{rule:?}");
        }
    }

    #[test]
    fn lint_error_display_carries_file_line_subsystem_and_rule() {
        let text = table_with(&SHELL.replace("reasons: [size]", "reasons: []"));
        let shown = load_str(&text).unwrap_err().to_string();
        assert_eq!(
            shown,
            "subsystems.yaml:6: shell: reasons must list at least one reason [empty-reasons]"
        );
    }

    #[test]
    fn primary_source_is_subpath_else_first_source() {
        let table = load_str(&table_with(SHELL)).unwrap();
        assert_eq!(
            table.get("shell").unwrap().primary_source(),
            Some("subsys/shell")
        );
        let text = table_with(&SHELL.replace(
            "    sources: [subsys/shell]\n",
            "    sources: [subsys/shell, subsys/shell/backends]\n    subpath: subsys/shell/backends\n",
        ));
        let table = load_str(&text).unwrap();
        assert_eq!(
            table.get("shell").unwrap().primary_source(),
            Some("subsys/shell/backends")
        );
        // The built-in table names the stack, not a directory it shares.
        let builtin = builtin().unwrap();
        for (name, primary) in [
            ("bluetooth-host", "subsys/bluetooth/host"),
            ("usb-device", "subsys/usb/device"),
            ("bluetooth-controller", "subsys/bluetooth/controller"),
        ] {
            assert_eq!(builtin.get(name).unwrap().primary_source(), Some(primary));
        }
    }

    #[test]
    fn nested_sources_across_entries_are_allowed() {
        let text = table_with(
            "  - name: filesystem\n    description: FS\n    symbols: [CONFIG_FILE_SYSTEM]\n    sources: [subsys/fs]\n    reasons: [size]\n    rationale: Large.\n  - name: littlefs\n    description: littlefs\n    symbols: [CONFIG_FILE_SYSTEM_LITTLEFS]\n    sources: [subsys/fs/littlefs_fs.c]\n    module: littlefs\n    cpe: 'cpe:2.3:a:littlefs_project:littlefs:*:*:*:*:*:*:*:*'\n    reasons: [cve-history, upstream-library]\n    rationale: CVE.\n",
        );
        let table = load_str(&text).unwrap();
        assert_eq!(
            table
                .get("littlefs")
                .unwrap()
                .cpe
                .as_ref()
                .map(|c| c.to_string()),
            Some("cpe:2.3:a:littlefs_project:littlefs:*:*:*:*:*:*:*:*".to_owned())
        );
    }

    fn yaml_location(e: &SubsystemsError) -> (Option<u32>, Option<u32>) {
        match e {
            SubsystemsError::Yaml { line, column, .. } => (*line, *column),
            other => panic!("not a YAML error: {other}"),
        }
    }

    #[test]
    fn yaml_errors_carry_line_and_column() {
        let good = table_with(SHELL);
        // Unknown field.
        let e = load_str(&good.replace("    rationale:", "    colour: red\n    rationale:"))
            .unwrap_err();
        assert_eq!(yaml_location(&e).0, Some(11), "{e}");
        assert!(e.to_string().starts_with("subsystems.yaml:11:"), "{e}");
        assert!(e.to_string().contains("colour"), "{e}");
        // Wrong type: symbols is a string.
        let e = load_str(&good.replace("symbols: [CONFIG_SHELL]", "symbols: CONFIG_SHELL"))
            .unwrap_err();
        assert_eq!(yaml_location(&e).0, Some(8), "{e}");
        // Unknown reason.
        let e = load_str(&good.replace("reasons: [size]", "reasons: [popularity]")).unwrap_err();
        assert_eq!(yaml_location(&e).0, Some(10), "{e}");
        assert!(e.to_string().contains("popularity"), "{e}");
        // Missing required field.
        let e = load_str(&good.replace("    rationale: Large.\n", "")).unwrap_err();
        assert!(e.to_string().contains("rationale"), "{e}");
        // Truncated mid-flow-sequence.
        let cut = good.find("[CONFIG_SHELL]").unwrap() + 5;
        let e = load_str(good.get(..cut).unwrap()).unwrap_err();
        let (line, column) = yaml_location(&e);
        assert!(line.is_some() && column.is_some(), "{e}");
        // Top level of the wrong type.
        assert!(matches!(
            load_str("- a\n- b\n"),
            Err(SubsystemsError::Yaml { .. })
        ));
        // A repeated key.
        let e = load_str(&good.replace("format:", "format: x\nformat:")).unwrap_err();
        assert!(matches!(e, SubsystemsError::Yaml { .. }), "{e}");
    }

    #[test]
    fn empty_and_comment_only_tables_are_errors() {
        for text in ["", "  \n\t\n", "# nothing\n", "~\n"] {
            assert!(
                matches!(load_str(text), Err(SubsystemsError::Empty { .. })),
                "{text:?}"
            );
        }
    }

    #[test]
    fn non_utf8_and_unreadable_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subsystems.yaml");
        let mut bytes = table_with(SHELL).into_bytes();
        bytes.extend_from_slice(b"\xff\xfe");
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            load_path(&path),
            Err(SubsystemsError::NotUtf8 { .. })
        ));
        let missing = dir.path().join("missing.yaml");
        let e = load_path(&missing).unwrap_err();
        assert!(matches!(e, SubsystemsError::Read { .. }));
        assert!(e.to_string().starts_with(&missing.display().to_string()));
        assert!(matches!(
            load_path(dir.path()),
            Err(SubsystemsError::Read { .. })
        ));
        // A file's errors cite its path.
        std::fs::write(&path, table_with(SHELL).replace("[size]", "[]")).unwrap();
        let e = load_path(&path).unwrap_err();
        assert!(
            e.to_string()
                .starts_with(&format!("{}:6: shell:", path.display())),
            "{e}"
        );
        std::fs::write(&path, table_with(SHELL)).unwrap();
        assert!(load_path(&path).is_ok());
    }

    #[test]
    fn entry_lines_fall_back_to_none_when_ambiguous() {
        // Flow-style entries have no `- name:` lines; findings then carry no line.
        let text = table_with(
            "  - {name: shell, description: Shell, symbols: [CONFIG_SHELL], sources: [subsys/shell], reasons: [], rationale: Large.}\n",
        );
        let findings = lint_findings(&text);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings.first().map(|f| f.line), Some(None));
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
            let _ = load_str(&text);
        }

        #[test]
        fn mutated_builtin_never_panics(cut in 0usize..BUILTIN.len(), insert in "[ :{}\\[\\]'\"#&*!|>\\-\\n\\t]{0,4}") {
            let mut text = BUILTIN.get(..cut).unwrap_or(BUILTIN).to_owned();
            text.push_str(&insert);
            text.push_str(BUILTIN.get(cut..).unwrap_or(""));
            let _ = load_str(&text);
        }
    }
}
