//! Deriving a module's upstream version from its [`VersionRule`].
//!
//! Source trees are read through [`SourceTree`], so the rules can be tested without a
//! checkout. [`FsTree`] reads a module directory on disk: files are size-capped, git tags are
//! read from `.git/packed-refs` and `.git/refs/tags/` directly (no `git` subprocess), and every
//! failure is simply "not found".

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{Level, VersionRule};

/// The most bytes read from any one file.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// How deep `refs/tags/` is walked, and how many loose tags are read at most.
const MAX_TAG_DEPTH: usize = 8;
const MAX_LOOSE_TAGS: usize = 10_000;

/// Read access to a module's source tree.
pub trait SourceTree {
    /// The text of the file at `rel` (forward-slash, relative to the module), or `None` if it
    /// is missing, unreadable or too large.
    fn read_file(&self, rel: &str) -> Option<String>;
    /// The names of the tags pointing at `revision`, sorted.
    fn tags_at(&self, revision: &str) -> Vec<String>;
}

/// A module source directory on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsTree(PathBuf);

impl FsTree {
    /// The module directory `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self(root.into())
    }

    /// The module directory.
    pub fn root(&self) -> &Path {
        &self.0
    }

    /// The git directory: `.git`, or where a `.git` file's `gitdir:` line points.
    fn git_dir(&self) -> Option<PathBuf> {
        let dot_git = self.0.join(".git");
        if dot_git.is_dir() {
            return Some(dot_git);
        }
        let text = read_capped(&dot_git)?;
        let target = text.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
        if target.is_empty() {
            return None;
        }
        let target = Path::new(target);
        Some(if target.is_absolute() {
            target.to_owned()
        } else {
            self.0.join(target)
        })
    }

    /// Where refs live: the `commondir` of a linked worktree's git directory, else itself.
    fn refs_dir(git_dir: &Path) -> PathBuf {
        match read_capped(&git_dir.join("commondir")) {
            Some(common) if !common.trim().is_empty() => {
                let common = Path::new(common.trim());
                if common.is_absolute() {
                    common.to_owned()
                } else {
                    git_dir.join(common)
                }
            }
            _ => git_dir.to_owned(),
        }
    }
}

/// Reads a file as text (lossily), or `None` if missing, unreadable or over the cap.
fn read_capped(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether `rel` is a safe forward-slash relative path.
fn is_safe_relative(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel.contains('\\')
        && !rel.contains(':')
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Whether `revision` looks like a git object id (7 to 64 hex digits), i.e. a commit rather
/// than a tag or branch name. A version pattern is never matched against one: a loose pattern
/// such as `v?(?P<version>\d+)` would otherwise read `512` out of `512cc7e8…`.
fn is_object_id(revision: &str) -> bool {
    (7..=64).contains(&revision.len()) && revision.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a ref value names `revision` (full hashes, compared case-insensitively).
fn same_commit(value: &str, revision: &str) -> bool {
    !value.is_empty() && value.eq_ignore_ascii_case(revision)
}

/// Collects loose tags under `dir` (named relative to `refs/tags/`) that point at `revision`.
fn loose_tags(
    dir: &Path,
    prefix: &str,
    revision: &str,
    depth: usize,
    out: &mut Vec<String>,
    budget: &mut usize,
) {
    if depth > MAX_TAG_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let name = entry.file_name().to_string_lossy().into_owned();
        let full = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => loose_tags(&path, &full, revision, depth + 1, out, budget),
            Ok(t) if t.is_file() => {
                if read_capped(&path).is_some_and(|v| same_commit(v.trim(), revision)) {
                    out.push(full);
                }
            }
            _ => {}
        }
    }
}

impl SourceTree for FsTree {
    fn read_file(&self, rel: &str) -> Option<String> {
        if !is_safe_relative(rel) {
            return None;
        }
        read_capped(&self.0.join(rel))
    }

    fn tags_at(&self, revision: &str) -> Vec<String> {
        let Some(git_dir) = self.git_dir() else {
            return Vec::new();
        };
        let refs = Self::refs_dir(&git_dir);
        let mut tags = Vec::new();
        if let Some(packed) = read_capped(&refs.join("packed-refs")) {
            let mut current: Option<&str> = None;
            for line in packed.lines() {
                if line.starts_with('#') {
                    continue;
                }
                if let Some(peeled) = line.strip_prefix('^') {
                    // The commit the previous (annotated) tag points at.
                    if let Some(tag) = current
                        && same_commit(peeled.trim(), revision)
                    {
                        tags.push(tag.to_owned());
                    }
                    continue;
                }
                current = None;
                let Some((sha, name)) = line.split_once(' ') else {
                    continue;
                };
                if let Some(tag) = name.trim().strip_prefix("refs/tags/") {
                    current = Some(tag);
                    if same_commit(sha, revision) {
                        tags.push(tag.to_owned());
                    }
                }
            }
        }
        let mut budget = MAX_LOOSE_TAGS;
        loose_tags(
            &refs.join("refs").join("tags"),
            "",
            revision,
            0,
            &mut tags,
            &mut budget,
        );
        tags.sort();
        tags.dedup();
        tags
    }
}

/// The result of applying a version rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    /// The upstream version, if one was found.
    pub version: Option<String>,
    /// How sure it is ([`Level::Low`] exactly when there is no version).
    pub level: Level,
    /// Why there is no version (or which tag gave it).
    pub note: Option<String>,
}

fn found(version: String, level: Level, note: Option<String>) -> Derived {
    Derived {
        version: Some(version),
        level,
        note,
    }
}

fn low(note: String) -> Derived {
    Derived {
        version: None,
        level: Level::Low,
        note: Some(note),
    }
}

/// Applies `rule` to a module at `revision`, reading its sources through `tree` if given.
pub fn derive_version(
    rule: &VersionRule,
    revision: Option<&str>,
    tree: Option<&dyn SourceTree>,
) -> Derived {
    let Some(revision) = revision.map(str::trim).filter(|r| !r.is_empty()) else {
        return low("no revision recorded".to_owned());
    };
    match rule {
        VersionRule::GitTag { pattern } => {
            let commit = is_object_id(revision);
            if !commit && let Some(version) = pattern.version_in(revision) {
                return found(version, Level::High, None);
            }
            let what = if commit {
                format!("revision {revision} is a commit")
            } else {
                format!("revision {revision} does not match the tag pattern")
            };
            let Some(tree) = tree else {
                return low(format!(
                    "{what} and there is no module source tree to look for tags in"
                ));
            };
            for tag in tree.tags_at(revision) {
                if let Some(version) = pattern.version_in(&tag) {
                    return found(version, Level::High, Some(format!("tag {tag}")));
                }
            }
            low(format!(
                "{what} and no tag matching the pattern points at it"
            ))
        }
        VersionRule::FileRegex { file, pattern } => {
            let Some(tree) = tree else {
                return low(format!(
                    "no module source tree to read {} from",
                    file.as_str()
                ));
            };
            let Some(text) = tree.read_file(file.as_str()) else {
                return low(format!("{} not found in the module sources", file.as_str()));
            };
            match pattern.version_in(&text) {
                Some(version) => found(version, Level::Medium, None),
                None => low(format!(
                    "{} has no match for the version pattern",
                    file.as_str()
                )),
            }
        }
        // An exact, case-sensitive match of the full revision: an abbreviated or
        // differently-cased commit hash is not looked up.
        VersionRule::Manual { table } => match table.get(revision) {
            Some(version) => found(version.clone(), Level::High, None),
            None => low(format!("revision {revision} is not in the manual table")),
        },
    }
}

/// An in-memory source tree for tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct MemTree {
    pub files: std::collections::BTreeMap<String, String>,
    pub tags: std::collections::BTreeMap<String, Vec<String>>,
}

#[cfg(test)]
impl SourceTree for MemTree {
    fn read_file(&self, rel: &str) -> Option<String> {
        self.files.get(rel).cloned()
    }

    fn tags_at(&self, revision: &str) -> Vec<String> {
        let mut tags = self.tags.get(revision).cloned().unwrap_or_default();
        tags.sort();
        tags
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::identify::{ManualTable, Pattern, RelPath};

    const SHA: &str = "a3e190fe44c78d1ba67f55979e1257328cc7d0d8";
    const OTHER: &str = "1111111111111111111111111111111111111111";

    fn git_tag() -> VersionRule {
        VersionRule::GitTag {
            pattern: Pattern::parse(r"^v?(?P<version>\d+\.\d+\.\d+)$").unwrap(),
        }
    }

    fn file_regex() -> VersionRule {
        VersionRule::FileRegex {
            file: RelPath::parse("include/version.h").unwrap(),
            pattern: Pattern::parse(r#"#define\s+LIB_VERSION\s+"(?P<version>[^"]+)""#).unwrap(),
        }
    }

    fn manual() -> VersionRule {
        VersionRule::Manual {
            table: ManualTable::from(BTreeMap::from([(SHA.to_owned(), "4.1.0".to_owned())])),
        }
    }

    #[test]
    fn git_tag_rule_never_matches_a_commit_sha_directly() {
        let loose = VersionRule::GitTag {
            pattern: Pattern::parse(r"v?(?P<version>\d+)").unwrap(),
        };
        let cmsis = "512cc7e895e8491696b61f7ba8066b4a182569b8";
        for tree in [None, Some(&MemTree::default() as &dyn SourceTree)] {
            let d = derive_version(&loose, Some(cmsis), tree);
            assert_eq!((d.version.clone(), d.level), (None, Level::Low), "{d:?}");
            assert!(d.note.unwrap().contains("is a commit"));
        }
        // Abbreviated and upper-case ids are commits too; a tag at the commit still resolves.
        for sha in ["512cc7e", "512CC7E895E8"] {
            assert_eq!(
                derive_version(&loose, Some(sha), None).version,
                None,
                "{sha}"
            );
        }
        let tagged = MemTree {
            tags: BTreeMap::from([(cmsis.to_owned(), vec!["v5".into()])]),
            ..MemTree::default()
        };
        let d = derive_version(&loose, Some(cmsis), Some(&tagged));
        assert_eq!((d.version.as_deref(), d.level), (Some("5"), Level::High));
        // A tag-like revision is still matched directly.
        assert_eq!(
            derive_version(&loose, Some("v12"), None).version.as_deref(),
            Some("12")
        );
        assert!(!is_object_id("v1.2.3") && !is_object_id("abc123") && is_object_id("abc1234"));
    }

    #[test]
    fn git_tag_rule_resolves_tag_like_revision() {
        let d = derive_version(&git_tag(), Some("v2.9.0"), None);
        assert_eq!(d.version.as_deref(), Some("2.9.0"));
        assert_eq!(d.level, Level::High);
        // Through a (mem) tree's tags, too.
        let tree = MemTree {
            tags: BTreeMap::from([(SHA.to_owned(), vec!["zephyr-fork".into(), "v3.1.4".into()])]),
            ..MemTree::default()
        };
        let d = derive_version(&git_tag(), Some(SHA), Some(&tree));
        assert_eq!(d.version.as_deref(), Some("3.1.4"));
        assert_eq!(d.level, Level::High);
        assert_eq!(d.note.as_deref(), Some("tag v3.1.4"));
        // A sha with no tree and no tag: low, no version.
        let d = derive_version(&git_tag(), Some(SHA), None);
        assert_eq!((d.version, d.level), (None, Level::Low));
    }

    #[test]
    fn git_tag_rule_resolves_sha_via_packed_refs_and_loose_tags() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(git.join("refs/tags/release")).unwrap();
        fs::write(
            git.join("packed-refs"),
            format!(
                "# pack-refs with: peeled fully-peeled sorted\n\
                 {OTHER} refs/heads/main\n\
                 2222222222222222222222222222222222222222 refs/tags/v1.0.0\n\
                 ^{SHA}\n\
                 {OTHER} refs/tags/v0.9.0\n\
                 malformed line without a space\n\
                 ^dangling-peel\n"
            ),
        )
        .unwrap();
        fs::write(git.join("refs/tags/release/v1.0.1"), format!("{SHA}\n")).unwrap();
        fs::write(git.join("refs/tags/v0.1.0"), format!("{OTHER}\n")).unwrap();
        let tree = FsTree::new(dir.path());
        assert_eq!(tree.tags_at(SHA), ["release/v1.0.1", "v1.0.0"]);
        assert_eq!(
            tree.tags_at(&SHA.to_uppercase()),
            ["release/v1.0.1", "v1.0.0"]
        );
        let d = derive_version(&git_tag(), Some(SHA), Some(&tree));
        // `release/v1.0.1` does not match the anchored pattern; the peeled `v1.0.0` does.
        assert_eq!(d.version.as_deref(), Some("1.0.0"));
        assert_eq!(d.level, Level::High);
        assert_eq!(tree.tags_at(OTHER), ["v0.1.0", "v0.9.0"]);

        // A `.git` file pointing elsewhere (a submodule or worktree) is followed.
        let module = tempfile::tempdir().unwrap();
        fs::write(
            module.path().join(".git"),
            format!("gitdir: {}\n", git.display()),
        )
        .unwrap();
        assert_eq!(
            FsTree::new(module.path()).tags_at(SHA),
            ["release/v1.0.1", "v1.0.0"]
        );
        // No .git at all: no tags, no panic.
        let empty = tempfile::tempdir().unwrap();
        assert!(FsTree::new(empty.path()).tags_at(SHA).is_empty());
        assert!(
            FsTree::new("/nonexistent/rollcall/module")
                .tags_at(SHA)
                .is_empty()
        );
    }

    #[test]
    fn file_regex_rule_resolves_version_from_source_file() {
        let tree = MemTree {
            files: BTreeMap::from([(
                "include/version.h".to_owned(),
                "/* lib */\n#define LIB_VERSION \"2.9.0\"\n".to_owned(),
            )]),
            ..MemTree::default()
        };
        let d = derive_version(&file_regex(), Some(SHA), Some(&tree));
        assert_eq!(d.version.as_deref(), Some("2.9.0"));
        assert_eq!(d.level, Level::Medium);
        // And from disk.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("include")).unwrap();
        fs::write(
            dir.path().join("include/version.h"),
            "#define LIB_VERSION \"1.2.3\"\n",
        )
        .unwrap();
        let tree = FsTree::new(dir.path());
        let d = derive_version(&file_regex(), Some(SHA), Some(&tree));
        assert_eq!(d.version.as_deref(), Some("1.2.3"));
        assert_eq!(d.level, Level::Medium);
        // FsTree refuses to leave the module.
        assert_eq!(tree.read_file("../x"), None);
        assert_eq!(tree.read_file("/etc/hosts"), None);
        assert_eq!(tree.read_file("include"), None);
    }

    #[test]
    fn file_regex_without_sources_or_match_is_low_confidence() {
        let d = derive_version(&file_regex(), Some(SHA), None);
        assert_eq!((d.version.clone(), d.level), (None, Level::Low));
        assert!(d.note.unwrap().contains("no module source tree"));
        let empty = MemTree::default();
        let d = derive_version(&file_regex(), Some(SHA), Some(&empty));
        assert_eq!((d.version.clone(), d.level), (None, Level::Low));
        assert!(d.note.unwrap().contains("not found"));
        let no_match = MemTree {
            files: BTreeMap::from([("include/version.h".to_owned(), "nothing".to_owned())]),
            ..MemTree::default()
        };
        let d = derive_version(&file_regex(), Some(SHA), Some(&no_match));
        assert_eq!((d.version.clone(), d.level), (None, Level::Low));
        assert!(d.note.unwrap().contains("no match"));
        // Over the size cap: treated as missing.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("include")).unwrap();
        let mut big = "#define LIB_VERSION \"9.9.9\"\n".to_owned();
        big.push_str(&"x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap()));
        fs::write(dir.path().join("include/version.h"), big).unwrap();
        let d = derive_version(&file_regex(), Some(SHA), Some(&FsTree::new(dir.path())));
        assert_eq!((d.version, d.level), (None, Level::Low));
    }

    #[test]
    fn manual_rule_resolves_listed_revision() {
        let d = derive_version(&manual(), Some(SHA), None);
        assert_eq!(d.version.as_deref(), Some("4.1.0"));
        assert_eq!(d.level, Level::High);
        assert_eq!(d.note, None);
    }

    #[test]
    fn manual_rule_unlisted_fork_revision_is_low_confidence_without_version() {
        let d = derive_version(&manual(), Some(OTHER), None);
        assert_eq!(d.version, None);
        assert_eq!(d.level, Level::Low);
        assert_eq!(
            d.note.as_deref(),
            Some(format!("revision {OTHER} is not in the manual table").as_str())
        );
    }

    #[test]
    fn missing_revision_is_low_confidence_without_version() {
        let tree = MemTree {
            files: BTreeMap::from([(
                "include/version.h".to_owned(),
                "#define LIB_VERSION \"2.9.0\"\n".to_owned(),
            )]),
            ..MemTree::default()
        };
        for rule in [git_tag(), file_regex(), manual()] {
            for revision in [None, Some(""), Some("  ")] {
                let d = derive_version(&rule, revision, Some(&tree));
                assert_eq!(d.version, None, "{}", rule.kind());
                assert_eq!(d.level, Level::Low, "{}", rule.kind());
                assert_eq!(d.note.as_deref(), Some("no revision recorded"));
            }
        }
    }
}
