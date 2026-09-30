//! Parser for `west list -f "{name} {path} {revision} {url}"` output.
//!
//! Each non-blank line has exactly four whitespace-separated fields. The manifest repository
//! (`manifest zephyr HEAD N/A` in a Zephyr workspace) is kept but is not a module; see
//! [`WestProject::is_manifest_repository`].

use std::collections::BTreeSet;

/// The parsed `west list` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestList {
    /// Every row, in file order.
    pub projects: Vec<WestProject>,
}

/// One `west list` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WestProject {
    /// The project name, e.g. `hal_nordic`.
    pub name: String,
    /// The path relative to the west workspace, e.g. `modules/hal/nordic`.
    pub path: String,
    /// The checked-out revision, normally a 40-hex commit.
    pub revision: String,
    /// The upstream URL, or `N/A` for the manifest repository.
    pub url: String,
    /// The 1-based line.
    pub line: u32,
}

impl WestProject {
    /// True for the manifest repository row (`name` is `manifest`, or the revision is `HEAD`
    /// with URL `N/A`), which is Zephyr itself rather than a module.
    pub fn is_manifest_repository(&self) -> bool {
        self.name == "manifest" || (self.revision == "HEAD" && self.url == "N/A")
    }
}

impl WestList {
    /// The rows that are modules (every row except the manifest repository), in file order.
    pub fn modules(&self) -> impl Iterator<Item = &WestProject> {
        self.projects.iter().filter(|p| !p.is_manifest_repository())
    }
}

/// Why `west list` output could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WestListError {
    /// No rows at all.
    #[error("empty west list output")]
    Empty,
    /// A line does not have exactly four fields.
    #[error(
        "line {line}: expected 4 fields `{{name}} {{path}} {{revision}} {{url}}`, found {found}"
    )]
    FieldCount {
        /// The line.
        line: u32,
        /// How many fields it has.
        found: usize,
    },
    /// Two rows have the same name.
    #[error("line {line}: project {name:?} is listed twice")]
    DuplicateName {
        /// The line of the second row.
        line: u32,
        /// The repeated name.
        name: String,
    },
}

/// Parses `west list -f "{name} {path} {revision} {url}"` output.
pub fn parse(text: &str) -> Result<WestList, WestListError> {
    let mut projects = Vec::new();
    let mut names = BTreeSet::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        let fields: Vec<&str> = raw.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let [name, path, revision, url] = fields.as_slice() else {
            return Err(WestListError::FieldCount {
                line,
                found: fields.len(),
            });
        };
        if !names.insert((*name).to_owned()) {
            return Err(WestListError::DuplicateName {
                line,
                name: (*name).to_owned(),
            });
        }
        projects.push(WestProject {
            name: (*name).to_owned(),
            path: (*path).to_owned(),
            revision: (*revision).to_owned(),
            url: (*url).to_owned(),
            line,
        });
    }
    if projects.is_empty() {
        return Err(WestListError::Empty);
    }
    Ok(WestList { projects })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE: &str = "manifest zephyr HEAD N/A\n\
        cmsis modules/hal/cmsis 512cc7e895e8491696b61f7ba8066b4a182569b8 https://github.com/zephyrproject-rtos/cmsis\n\
        hal_nordic modules/hal/nordic 44fd3d44b15cb75f80a25b4679f91d2787e28664 https://github.com/zephyrproject-rtos/hal_nordic\n";

    #[test]
    fn parses_four_field_lines_in_order() {
        let list = parse(SAMPLE).unwrap();
        let names: Vec<&str> = list.projects.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["manifest", "cmsis", "hal_nordic"]);
        let nordic = &list.projects[2];
        assert_eq!(nordic.path, "modules/hal/nordic");
        assert_eq!(nordic.revision, "44fd3d44b15cb75f80a25b4679f91d2787e28664");
        assert_eq!(
            nordic.url,
            "https://github.com/zephyrproject-rtos/hal_nordic"
        );
        assert_eq!(nordic.line, 3);
        // CRLF and tabs are whitespace too.
        let crlf = parse(&SAMPLE.replace('\n', "\r\n").replace(' ', "\t")).unwrap();
        assert_eq!(crlf, list);
    }

    #[test]
    fn manifest_row_is_recognised_and_not_a_module() {
        let list = parse(SAMPLE).unwrap();
        assert!(list.projects[0].is_manifest_repository());
        assert!(!list.projects[1].is_manifest_repository());
        let modules: Vec<&str> = list.modules().map(|p| p.name.as_str()).collect();
        assert_eq!(modules, ["cmsis", "hal_nordic"]);
        // A renamed manifest row is still recognised by HEAD + N/A.
        let renamed = parse("zephyr zephyr HEAD N/A\n").unwrap();
        assert_eq!(renamed.modules().count(), 0);
    }

    #[test]
    fn blank_lines_are_skipped() {
        let list = parse(&format!("\n\n{SAMPLE}\n   \n")).unwrap();
        assert_eq!(list.projects.len(), 3);
        assert_eq!(list.projects[0].line, 3);
    }

    #[test]
    fn wrong_field_count_is_error_with_line() {
        assert_eq!(
            parse("manifest zephyr HEAD N/A\ncmsis modules/hal/cmsis 512cc7e\n"),
            Err(WestListError::FieldCount { line: 2, found: 3 })
        );
        assert_eq!(
            parse("a b c d e\n"),
            Err(WestListError::FieldCount { line: 1, found: 5 })
        );
    }

    #[test]
    fn duplicate_module_name_is_error() {
        assert_eq!(
            parse("a p1 r1 u1\nb p2 r2 u2\na p3 r3 u3\n"),
            Err(WestListError::DuplicateName {
                line: 3,
                name: "a".into()
            })
        );
    }

    #[test]
    fn empty_input_is_error() {
        assert_eq!(parse(""), Err(WestListError::Empty));
        assert_eq!(parse(" \n\t\n"), Err(WestListError::Empty));
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "(?s).{0,400}") {
            let _ = parse(&text);
        }
    }
}
