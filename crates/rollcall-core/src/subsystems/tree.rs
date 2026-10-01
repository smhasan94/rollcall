//! A Zephyr checkout as a lint [`Reference`].

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use super::SubsystemsError;
use super::lint::Reference;

/// Top-level directories whose Kconfig files define nothing a build of a real application
/// uses (samples, tests and documentation define their own throw-away symbols).
const SKIPPED_TOP_LEVEL: [&str; 3] = ["doc", "samples", "tests"];

/// A Zephyr repository checkout: the Kconfig symbols it defines, its paths and its version.
#[derive(Debug, Clone)]
pub struct ZephyrTree {
    root: PathBuf,
    symbols: BTreeSet<String>,
    version: Option<String>,
}

impl ZephyrTree {
    /// Scans the checkout at `root` (the `zephyr` repository itself, which holds `VERSION`):
    /// every `config NAME` / `menuconfig NAME` line of every `Kconfig*` file, outside `.git`
    /// and the top-level `doc`, `samples` and `tests`. `Kconfig.defconfig*` files are skipped:
    /// they only give board and SoC defaults to symbols defined elsewhere, so a symbol found
    /// only there is not really defined. Symbolic links are not followed.
    pub fn open(root: &Path) -> Result<ZephyrTree, SubsystemsError> {
        let version_path = root.join("VERSION");
        let version_bytes =
            std::fs::read(&version_path).map_err(|source| SubsystemsError::Read {
                path: version_path.clone(),
                source,
            })?;
        let version = parse_version(&String::from_utf8_lossy(&version_bytes));

        let mut symbols = BTreeSet::new();
        let mut pending = vec![(root.to_owned(), true)];
        while let Some((dir, top)) = pending.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|source| SubsystemsError::Read {
                path: dir.clone(),
                source,
            })?;
            for entry in entries {
                let entry = entry.map_err(|source| SubsystemsError::Read {
                    path: dir.clone(),
                    source,
                })?;
                let file_type = entry.file_type().map_err(|source| SubsystemsError::Read {
                    path: entry.path(),
                    source,
                })?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if file_type.is_dir() {
                    if name == ".git" || (top && SKIPPED_TOP_LEVEL.contains(&name.as_ref())) {
                        continue;
                    }
                    pending.push((entry.path(), false));
                } else if file_type.is_file() && is_kconfig_file(&name) {
                    let path = entry.path();
                    let bytes = std::fs::read(&path)
                        .map_err(|source| SubsystemsError::Read { path, source })?;
                    symbols.extend(
                        kconfig_definitions(&String::from_utf8_lossy(&bytes)).map(str::to_owned),
                    );
                }
            }
        }
        Ok(ZephyrTree {
            root: root.to_owned(),
            symbols,
            version,
        })
    }

    /// The checkout's root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every defined symbol (without `CONFIG_`), in name order.
    pub fn symbols(&self) -> impl Iterator<Item = &str> {
        self.symbols.iter().map(String::as_str)
    }

    /// The version from `VERSION` as a tag, e.g. `v4.4.2` (`v4.4.0-rc1` with an
    /// `EXTRAVERSION`), if `VERSION` could be read.
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl Reference for ZephyrTree {
    fn defines_symbol(&self, name: &str) -> bool {
        self.symbols.contains(name)
    }

    fn has_source(&self, rel_path: &str) -> bool {
        let rel = Path::new(rel_path);
        // Never look outside the tree.
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return false;
        }
        std::fs::symlink_metadata(self.root.join(rel)).is_ok()
    }

    fn pin(&self) -> Option<&str> {
        self.version()
    }
}

/// Whether a file named `name` defines symbols: `Kconfig*`, but not `Kconfig.defconfig*`.
fn is_kconfig_file(name: &str) -> bool {
    name.starts_with("Kconfig") && !name.starts_with("Kconfig.defconfig")
}

/// The symbol names defined by `config NAME` and `menuconfig NAME` lines (a trailing `#`
/// comment is allowed). `configdefault` and everything else define nothing.
pub fn kconfig_definitions(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let line = line.trim();
        let rest = line
            .strip_prefix("menuconfig")
            .or_else(|| line.strip_prefix("config"))?;
        if !rest.starts_with([' ', '\t']) {
            return None;
        }
        let rest = rest.trim_start();
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(end);
        let tail = tail.trim();
        (!name.is_empty() && (tail.is_empty() || tail.starts_with('#'))).then_some(name)
    })
}

/// `v<MAJOR>.<MINOR>.<PATCHLEVEL>[-<EXTRAVERSION>]` from a Zephyr `VERSION` file.
fn parse_version(text: &str) -> Option<String> {
    let field = |key: &str| -> Option<String> {
        text.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key).then(|| v.trim().to_owned())
        })
    };
    let number = |key: &str| -> Option<u32> { field(key)?.parse().ok() };
    let (major, minor, patch) = (
        number("VERSION_MAJOR")?,
        number("VERSION_MINOR")?,
        number("PATCHLEVEL")?,
    );
    let extra = field("EXTRAVERSION").unwrap_or_default();
    Some(if extra.is_empty() {
        format!("v{major}.{minor}.{patch}")
    } else {
        format!("v{major}.{minor}.{patch}-{extra}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subsystems::{Rule, lint_against, load_str};

    #[test]
    fn kconfig_definitions_find_config_and_menuconfig_only() {
        let text = "config FOO\n\tbool \"Foo\"\nmenuconfig BAR # comment\n  config\tBAZ\nconfigdefault QUX\n\tdefault y\nconfig\nconfig BAD NAME\n# config COMMENTED\nif FOO\nendif\n";
        assert_eq!(
            kconfig_definitions(text).collect::<Vec<_>>(),
            ["FOO", "BAR", "BAZ"]
        );
    }

    #[test]
    fn version_file_is_read_as_a_tag() {
        let v = "VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 2\nVERSION_TWEAK = 0\nEXTRAVERSION =\n";
        assert_eq!(parse_version(v).as_deref(), Some("v4.4.2"));
        assert_eq!(
            parse_version(&v.replace("EXTRAVERSION =", "EXTRAVERSION = rc1")).as_deref(),
            Some("v4.4.2-rc1")
        );
        assert_eq!(parse_version("VERSION_MAJOR = x\n"), None);
        assert_eq!(parse_version(""), None);
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn zephyr_tree_reference_flags_unknowns() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "VERSION",
            "VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 1\nEXTRAVERSION =\n",
        );
        write(
            root,
            "subsys/shell/Kconfig",
            "menuconfig SHELL\n\tbool \"Shell\"\n",
        );
        write(root, "subsys/shell/shell.c", "");
        write(root, "subsys/logging/Kconfig.misc", "config LOG\n");
        // Defaults only: not definitions.
        write(
            root,
            "soc/x/Kconfig.defconfig",
            "config DEFCONFIG_ONLY\n\tdefault y\n",
        );
        write(
            root,
            "soc/x/Kconfig.defconfig.x1",
            "config DEFCONFIG_SERIES\n",
        );
        write(root, "samples/hello/Kconfig", "config SAMPLE_ONLY\n");
        write(root, "subsys/tests/Kconfig", "config NESTED_TESTS_DIR\n");
        write(root, ".git/Kconfig", "config GIT_ONLY\n");
        write(root, "subsys/shell/README", "config NOT_A_KCONFIG_FILE\n");
        // Not UTF-8: still scanned.
        std::fs::write(
            root.join("subsys/Kconfig.latin1"),
            b"config LATIN\n# \xe9\n",
        )
        .unwrap();

        let tree = ZephyrTree::open(root).unwrap();
        assert_eq!(tree.root(), root);
        assert_eq!(tree.version(), Some("v4.4.1"));
        assert_eq!(
            tree.symbols().collect::<Vec<_>>(),
            ["LATIN", "LOG", "NESTED_TESTS_DIR", "SHELL"]
        );
        assert!(tree.has_source("subsys/shell"));
        assert!(tree.has_source("subsys/shell/shell.c"));
        assert!(!tree.has_source("subsys/missing"));
        assert!(!tree.has_source("../escape"));
        assert!(!tree.has_source("/etc"));

        let table = load_str(
            "format: rollcall-subsystems/1\nzephyr:\n  tag: v4.4.2\n  commit: dccb09599635bdff17633fa7e9dab014b91dce90\nsubsystems:\n  - name: logging\n    description: Logging\n    symbols: [CONFIG_LOG]\n    sources: [subsys/logging]\n    reasons: [size]\n    rationale: Large.\n  - name: shell\n    description: Shell\n    symbols: [CONFIG_SAMPLE_ONLY, CONFIG_SHELL]\n    sources: [subsys/missing, subsys/shell]\n    reasons: [size]\n    rationale: Large.\n",
        )
        .unwrap();
        let findings = lint_against(&table, &tree);
        let shown: Vec<(Option<u32>, Rule)> = findings.iter().map(|f| (f.line, f.rule)).collect();
        assert_eq!(
            shown,
            [
                (None, Rule::PinMismatch),
                (Some(12), Rule::UnknownSymbol),
                (Some(12), Rule::UnknownSource),
            ],
            "{findings:?}"
        );
    }

    #[test]
    fn missing_tree_is_a_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let e = ZephyrTree::open(&dir.path().join("nope")).unwrap_err();
        assert!(matches!(e, SubsystemsError::Read { .. }), "{e}");
        assert!(e.to_string().contains("VERSION"), "{e}");
    }
}
