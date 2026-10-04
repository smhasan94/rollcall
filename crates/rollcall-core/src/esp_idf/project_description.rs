//! Parser for `build/project_description.json`, which `idf.py build` writes.
//!
//! Read: `project_name` (required), `project_version`, `idf_path`, `git_revision` (ESP-IDF's
//! `IDF_VER`, e.g. `v5.5.1`), `target`, `build_dir` and `build_components`. Every other key
//! is ignored, and every read key except `project_name` may be missing. A value of the wrong
//! type is an error, never a panic.

use serde::Deserialize;

/// The fields rollcall reads from `project_description.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectDescription {
    /// The CMake project name (the application image's name).
    pub project_name: String,
    /// `PROJECT_VER`, if set.
    pub project_version: Option<String>,
    /// The ESP-IDF tree the build used, as the build saw it.
    pub idf_path: Option<String>,
    /// `IDF_VER`, e.g. `v5.5.1` or `v5.5.1-dirty`.
    pub git_revision: Option<String>,
    /// The chip, e.g. `esp32`.
    pub target: Option<String>,
    /// The build directory, as the build saw it.
    pub build_dir: Option<String>,
    /// The components in the build, in file order.
    pub build_components: Vec<String>,
}

/// Why `project_description.json` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectDescriptionError {
    /// The file is empty.
    #[error("empty file")]
    Empty,
    /// Not JSON, or a key with a value of the wrong type.
    #[error("line {line}, column {column}: {message}")]
    Json {
        /// The 1-based line.
        line: usize,
        /// The 1-based column.
        column: usize,
        /// What is wrong.
        message: String,
    },
    /// `project_name` is missing or empty.
    #[error("no project_name")]
    NoProjectName,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    project_version: Option<String>,
    #[serde(default)]
    idf_path: Option<String>,
    #[serde(default)]
    git_revision: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    build_dir: Option<String>,
    #[serde(default)]
    build_components: Option<Vec<String>>,
}

/// `Some` of a non-blank string.
fn present(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// Parses `project_description.json`.
pub fn parse(text: &str) -> Result<ProjectDescription, ProjectDescriptionError> {
    if text.trim().is_empty() {
        return Err(ProjectDescriptionError::Empty);
    }
    let raw: Raw = serde_json::from_str(text).map_err(|e| ProjectDescriptionError::Json {
        line: e.line(),
        column: e.column(),
        message: e.to_string(),
    })?;
    let project_name = present(raw.project_name).ok_or(ProjectDescriptionError::NoProjectName)?;
    Ok(ProjectDescription {
        project_name,
        project_version: present(raw.project_version),
        idf_path: present(raw.idf_path),
        git_revision: present(raw.git_revision),
        target: present(raw.target),
        build_dir: present(raw.build_dir),
        build_components: raw.build_components.unwrap_or_default(),
    })
}

/// ESP-IDF's release version from an `IDF_VER` such as `v5.5.1`: the leading `v` dropped,
/// and the `MAJOR.MINOR[.PATCH][-pre]` part kept. `None` when it does not start with a
/// number. The second value is what follows the release (`-dirty`, `-12-gabc1234`), if
/// anything, so the caller can warn that the tree is not the release.
pub fn release_version(git_revision: &str) -> Option<(String, Option<String>)> {
    let rest = git_revision.strip_prefix('v').unwrap_or(git_revision);
    let core_end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let core = rest.get(..core_end)?;
    let numbers: Vec<&str> = core.split('.').collect();
    if !(2..=3).contains(&numbers.len()) || numbers.iter().any(|n| n.is_empty()) {
        return None;
    }
    let tail = rest.get(core_end..).unwrap_or_default();
    // A pre-release (`-beta1`, `-rc2`, `-dev`) is part of the version; anything after it is
    // not.
    let (pre, extra) = match tail.strip_prefix('-') {
        Some(t) => {
            let word_end = t.find('-').unwrap_or(t.len());
            let word = t.get(..word_end).unwrap_or_default();
            let is_pre = ["alpha", "beta", "rc", "dev"]
                .iter()
                .any(|p| word.starts_with(p));
            if is_pre {
                (format!("-{word}"), t.get(word_end..).unwrap_or_default())
            } else {
                (String::new(), tail)
            }
        }
        None => (String::new(), tail),
    };
    let extra = (!extra.is_empty()).then(|| extra.to_owned());
    Some((format!("{core}{pre}"), extra))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn reads_the_documented_keys_and_ignores_the_rest() {
        let d = parse(
            r#"{"version": "1.2", "project_name": "https_request", "project_version": "1",
               "idf_path": "/opt/esp/idf", "git_revision": "v5.5.1", "target": "esp32",
               "build_dir": "/project/x/build", "build_components": ["a", "b"],
               "all_component_info": {"x": {"dir": "/y"}}}"#,
        )
        .unwrap();
        assert_eq!(d.project_name, "https_request");
        assert_eq!(d.project_version.as_deref(), Some("1"));
        assert_eq!(d.idf_path.as_deref(), Some("/opt/esp/idf"));
        assert_eq!(d.git_revision.as_deref(), Some("v5.5.1"));
        assert_eq!(d.target.as_deref(), Some("esp32"));
        assert_eq!(d.build_components, ["a", "b"]);
    }

    #[test]
    fn malformed_project_description_is_an_error_not_a_panic() {
        assert_eq!(parse(""), Err(ProjectDescriptionError::Empty));
        assert_eq!(parse("  \n"), Err(ProjectDescriptionError::Empty));
        assert_eq!(parse("{}"), Err(ProjectDescriptionError::NoProjectName));
        // serde reads a JSON array as a struct's fields in order: an empty one has none.
        for text in [r#"{"project_name": " "}"#, "[]"] {
            assert_eq!(
                parse(text),
                Err(ProjectDescriptionError::NoProjectName),
                "{text}"
            );
        }
        for text in [
            "{",
            "null",
            "[1]",
            r#"{"project_name": 3}"#,
            r#"{"project_name": "a", "build_components": "x"}"#,
            r#"{"project_name": "a", "git_revision": ["v5"]}"#,
            "{\"project_name\": \"a\"",
            "\u{feff}{}",
        ] {
            assert!(
                matches!(parse(text), Err(ProjectDescriptionError::Json { .. })),
                "{text:?}"
            );
        }
    }

    #[test]
    fn release_version_strips_v_and_reports_extras() {
        let v = |s: &str| release_version(s);
        assert_eq!(v("v5.5.1"), Some(("5.5.1".into(), None)));
        assert_eq!(v("5.5"), Some(("5.5".into(), None)));
        assert_eq!(
            v("v5.5.1-dirty"),
            Some(("5.5.1".into(), Some("-dirty".into())))
        );
        assert_eq!(
            v("v5.5.1-12-gabc1234"),
            Some(("5.5.1".into(), Some("-12-gabc1234".into())))
        );
        assert_eq!(v("v6.0-beta1"), Some(("6.0-beta1".into(), None)));
        assert_eq!(
            v("v6.0-dev-123-gabc"),
            Some(("6.0-dev".into(), Some("-123-gabc".into())))
        );
        for bad in ["", "v", "master", "v5", "v.5.1", "v5..1", "v1.2.3.4"] {
            assert_eq!(v(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
            let _ = parse(&text);
            let _ = release_version(&text);
        }
    }
}
