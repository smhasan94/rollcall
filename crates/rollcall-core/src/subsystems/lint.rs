//! Lint rules for a subsystem table. See the [module docs](super#lint-rules).

use std::collections::BTreeMap;
use std::fmt;

use super::{FORMAT, SubsystemTable};

/// One problem with a subsystem table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The 1-based line of the entry (or `None` for the table itself, or when unknown).
    pub line: Option<u32>,
    /// The subsystem it is about (`None` for the table itself).
    pub subsystem: Option<String>,
    /// The rule broken.
    pub rule: Rule,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(subsystem) = &self.subsystem {
            write!(f, "{subsystem}: ")?;
        }
        write!(f, "{} [{}]", self.message, self.rule)
    }
}

/// A lint rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `format` is not [`FORMAT`].
    WrongFormat,
    /// The `zephyr` pin has an empty tag or a commit that is not 40 lowercase hex digits.
    BadPin,
    /// Two entries have the same name.
    DuplicateName,
    /// A name is not `[a-z0-9][a-z0-9-]*`.
    BadName,
    /// Entries, symbols or sources are out of order.
    NotSorted,
    /// A description is empty.
    EmptyDescription,
    /// An entry lists no symbols.
    EmptySymbols,
    /// A symbol is not `CONFIG_[A-Z0-9_]+`.
    BadSymbol,
    /// An entry lists a symbol twice.
    DuplicateSymbol,
    /// An entry lists no sources.
    EmptySources,
    /// A source path is absolute, uses `\`, or has an empty, `.` or `..` segment or a
    /// trailing `/`.
    BadSourcePath,
    /// A source path is listed twice, in one entry or in two.
    DuplicateSource,
    /// `subpath` is not one of the entry's `sources`.
    BadSubpath,
    /// `module` is not a west project name (`[A-Za-z0-9_.+-]+`).
    BadModule,
    /// `cpe` is not a valid CPE.
    BadCpe,
    /// An entry lists no reasons.
    EmptyReasons,
    /// An entry lists a reason twice.
    DuplicateReason,
    /// A rationale is empty.
    EmptyRationale,
    /// A symbol is not defined by any `Kconfig*` file of the reference tree.
    UnknownSymbol,
    /// A source path does not exist in the reference tree.
    UnknownSource,
    /// The reference tree is not the release the table is pinned to.
    PinMismatch,
}

impl Rule {
    /// Every rule.
    pub const ALL: [Rule; 21] = [
        Rule::WrongFormat,
        Rule::BadPin,
        Rule::DuplicateName,
        Rule::BadName,
        Rule::NotSorted,
        Rule::EmptyDescription,
        Rule::EmptySymbols,
        Rule::BadSymbol,
        Rule::DuplicateSymbol,
        Rule::EmptySources,
        Rule::BadSourcePath,
        Rule::DuplicateSource,
        Rule::BadSubpath,
        Rule::BadModule,
        Rule::BadCpe,
        Rule::EmptyReasons,
        Rule::DuplicateReason,
        Rule::EmptyRationale,
        Rule::UnknownSymbol,
        Rule::UnknownSource,
        Rule::PinMismatch,
    ];

    /// The rule's name, as shown in findings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongFormat => "wrong-format",
            Self::BadPin => "bad-pin",
            Self::DuplicateName => "duplicate-name",
            Self::BadName => "bad-name",
            Self::NotSorted => "not-sorted",
            Self::EmptyDescription => "empty-description",
            Self::EmptySymbols => "empty-symbols",
            Self::BadSymbol => "bad-symbol",
            Self::DuplicateSymbol => "duplicate-symbol",
            Self::EmptySources => "empty-sources",
            Self::BadSourcePath => "bad-source-path",
            Self::DuplicateSource => "duplicate-source",
            Self::BadSubpath => "bad-subpath",
            Self::BadModule => "bad-module",
            Self::BadCpe => "bad-cpe",
            Self::EmptyReasons => "empty-reasons",
            Self::DuplicateReason => "duplicate-reason",
            Self::EmptyRationale => "empty-rationale",
            Self::UnknownSymbol => "unknown-symbol",
            Self::UnknownSource => "unknown-source",
            Self::PinMismatch => "pin-mismatch",
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a table is checked against: normally the pinned Zephyr checkout ([`super::ZephyrTree`]).
pub trait Reference {
    /// Whether a `config`/`menuconfig` stanza defines `name` (without the `CONFIG_` prefix).
    fn defines_symbol(&self, name: &str) -> bool;
    /// Whether `rel_path` (relative to the Zephyr repository root) exists.
    fn has_source(&self, rel_path: &str) -> bool;
    /// The reference's release tag (e.g. `v4.4.2`), if known.
    fn pin(&self) -> Option<&str>;
}

fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_symbol(symbol: &str) -> bool {
    symbol.strip_prefix("CONFIG_").is_some_and(|rest| {
        !rest.is_empty()
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

fn is_module(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

fn is_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why `path` is not a usable source path, if it is not.
fn bad_source_path(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        Some("is empty")
    } else if path.starts_with('/') {
        Some("is absolute")
    } else if path.contains('\\') {
        Some("uses `\\`; separate segments with `/`")
    } else if path.ends_with('/') {
        Some("ends with `/`")
    } else if path
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        Some("has an empty, `.` or `..` segment")
    } else if path.chars().any(|c| c.is_control()) {
        Some("contains a control character")
    } else {
        None
    }
}

/// The structural rules: everything checkable without a Zephyr tree, except `cpe` (checked
/// while loading). Findings are sorted.
pub fn validate(table: &SubsystemTable) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut push = |line: Option<u32>, subsystem: Option<&str>, rule: Rule, message: String| {
        findings.push(Finding {
            line,
            subsystem: subsystem.map(str::to_owned),
            rule,
            message,
        });
    };

    if table.format != FORMAT {
        push(
            None,
            None,
            Rule::WrongFormat,
            format!(
                "format is {:?}; this rollcall reads {FORMAT:?}",
                table.format
            ),
        );
    }
    if table.zephyr.tag.trim().is_empty() {
        push(
            None,
            None,
            Rule::BadPin,
            "zephyr.tag must not be empty".to_owned(),
        );
    }
    if !is_commit(&table.zephyr.commit) {
        push(
            None,
            None,
            Rule::BadPin,
            format!(
                "zephyr.commit {:?} must be a full commit id (40 lowercase hex digits)",
                table.zephyr.commit
            ),
        );
    }

    let mut names: BTreeMap<&str, Option<u32>> = BTreeMap::new();
    let mut paths: BTreeMap<&str, &str> = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for s in &table.subsystems {
        let name = s.name.as_str();
        let at = |line: Option<u32>| line.map_or_else(|| "?".to_owned(), |l| l.to_string());
        let sub = Some(name);
        if !is_name(name) {
            push(
                s.line,
                sub,
                Rule::BadName,
                format!("name {name:?} must match [a-z0-9][a-z0-9-]*"),
            );
        }
        if let Some(first) = names.get(name) {
            push(
                s.line,
                sub,
                Rule::DuplicateName,
                format!(
                    "subsystem {name} is listed twice (lines {} and {})",
                    at(*first),
                    at(s.line)
                ),
            );
        } else {
            names.insert(name, s.line);
        }
        if let Some(prev) = previous
            && name < prev
        {
            push(
                s.line,
                sub,
                Rule::NotSorted,
                format!("subsystems must be in name order: {name} comes after {prev}"),
            );
        }
        previous = Some(name);

        if s.description.trim().is_empty() {
            push(
                s.line,
                sub,
                Rule::EmptyDescription,
                "description must not be empty".to_owned(),
            );
        }

        if s.symbols.is_empty() {
            push(
                s.line,
                sub,
                Rule::EmptySymbols,
                "symbols must list at least one Kconfig symbol".to_owned(),
            );
        }
        for symbol in &s.symbols {
            if !is_symbol(symbol) {
                push(
                    s.line,
                    sub,
                    Rule::BadSymbol,
                    format!("symbol {symbol:?} must match CONFIG_[A-Z0-9_]+"),
                );
            }
        }
        for (a, b) in s.symbols.iter().zip(s.symbols.iter().skip(1)) {
            if a == b {
                push(
                    s.line,
                    sub,
                    Rule::DuplicateSymbol,
                    format!("symbol {a} is listed twice"),
                );
            } else if a > b {
                push(
                    s.line,
                    sub,
                    Rule::NotSorted,
                    format!("symbols must be in ascending order: {b} comes after {a}"),
                );
            }
        }

        if s.sources.is_empty() {
            push(
                s.line,
                sub,
                Rule::EmptySources,
                "sources must list at least one path".to_owned(),
            );
        }
        for path in &s.sources {
            if let Some(reason) = bad_source_path(path) {
                push(
                    s.line,
                    sub,
                    Rule::BadSourcePath,
                    format!("source {path:?} {reason}"),
                );
            }
        }
        for (a, b) in s.sources.iter().zip(s.sources.iter().skip(1)) {
            if a == b {
                push(
                    s.line,
                    sub,
                    Rule::DuplicateSource,
                    format!("source {a} is listed twice"),
                );
            } else if a > b {
                push(
                    s.line,
                    sub,
                    Rule::NotSorted,
                    format!("sources must be in ascending order: {b} comes after {a}"),
                );
            }
        }
        let mut own = std::collections::BTreeSet::new();
        for path in &s.sources {
            if !own.insert(path.as_str()) {
                continue;
            }
            match paths.get(path.as_str()) {
                Some(other) if *other != name => push(
                    s.line,
                    sub,
                    Rule::DuplicateSource,
                    format!("source {path} is also listed by {other}"),
                ),
                Some(_) => {}
                None => {
                    paths.insert(path, name);
                }
            }
        }

        if let Some(subpath) = &s.subpath
            && !s.sources.contains(subpath)
        {
            push(
                s.line,
                sub,
                Rule::BadSubpath,
                format!("subpath {subpath} must be one of the entry's sources"),
            );
        }

        if let Some(module) = &s.module
            && !is_module(module)
        {
            push(
                s.line,
                sub,
                Rule::BadModule,
                format!("module {module:?} must be a west project name, [A-Za-z0-9_.+-]+"),
            );
        }

        if s.reasons.is_empty() {
            push(
                s.line,
                sub,
                Rule::EmptyReasons,
                "reasons must list at least one reason".to_owned(),
            );
        }
        let mut reasons = std::collections::BTreeSet::new();
        for reason in &s.reasons {
            if !reasons.insert(*reason) {
                push(
                    s.line,
                    sub,
                    Rule::DuplicateReason,
                    format!("reason {reason} is listed twice"),
                );
            }
        }

        if s.rationale.trim().is_empty() {
            push(
                s.line,
                sub,
                Rule::EmptyRationale,
                "rationale must explain the reasons".to_owned(),
            );
        }
    }
    findings.sort();
    findings
}

/// The reference rules: every symbol defined, every source present, the pin matching.
/// Findings are sorted.
pub fn lint_against(table: &SubsystemTable, reference: &dyn Reference) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(pin) = reference.pin()
        && pin != table.zephyr.tag
    {
        findings.push(Finding {
            line: None,
            subsystem: None,
            rule: Rule::PinMismatch,
            message: format!(
                "the reference tree is {pin}, but the table is pinned to {}",
                table.zephyr.tag
            ),
        });
    }
    for s in &table.subsystems {
        for symbol in &s.symbols {
            // A malformed symbol is a structural finding, not an unknown one.
            let Some(bare) = symbol.strip_prefix("CONFIG_") else {
                continue;
            };
            if !reference.defines_symbol(bare) {
                findings.push(Finding {
                    line: s.line,
                    subsystem: Some(s.name.clone()),
                    rule: Rule::UnknownSymbol,
                    message: format!(
                        "symbol {symbol} is not defined by any Kconfig file of the reference tree"
                    ),
                });
            }
        }
        for path in &s.sources {
            if bad_source_path(path).is_some() {
                continue;
            }
            if !reference.has_source(path) {
                findings.push(Finding {
                    line: s.line,
                    subsystem: Some(s.name.clone()),
                    rule: Rule::UnknownSource,
                    message: format!("source {path} does not exist in the reference tree"),
                });
            }
        }
    }
    findings.sort();
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subsystems::{Reason, Subsystem, ZephyrPin};
    use std::collections::BTreeSet;

    /// A reference that knows a fixed set of symbols and paths.
    struct Fake {
        symbols: BTreeSet<&'static str>,
        paths: BTreeSet<&'static str>,
        pin: Option<&'static str>,
    }

    impl Reference for Fake {
        fn defines_symbol(&self, name: &str) -> bool {
            self.symbols.contains(name)
        }
        fn has_source(&self, rel_path: &str) -> bool {
            self.paths.contains(rel_path)
        }
        fn pin(&self) -> Option<&str> {
            self.pin
        }
    }

    fn fake() -> Fake {
        Fake {
            symbols: ["BT_HCI_HOST", "BT_LL_SW_SPLIT", "SHELL"].into(),
            paths: [
                "subsys/bluetooth/controller",
                "subsys/bluetooth/host",
                "subsys/shell",
            ]
            .into(),
            pin: Some("v4.4.2"),
        }
    }

    fn entry(name: &str, symbols: &[&str], sources: &[&str], line: u32) -> Subsystem {
        Subsystem {
            name: name.to_owned(),
            description: name.to_owned(),
            symbols: symbols.iter().map(|s| (*s).to_owned()).collect(),
            sources: sources.iter().map(|s| (*s).to_owned()).collect(),
            subpath: None,
            module: None,
            cpe: None,
            reasons: vec![Reason::Size],
            rationale: "Large.".to_owned(),
            line: Some(line),
        }
    }

    fn table(subsystems: Vec<Subsystem>) -> SubsystemTable {
        SubsystemTable {
            format: FORMAT.to_owned(),
            zephyr: ZephyrPin {
                tag: "v4.4.2".to_owned(),
                commit: "dccb09599635bdff17633fa7e9dab014b91dce90".to_owned(),
            },
            subsystems,
        }
    }

    #[test]
    fn known_symbols_and_sources_pass() {
        let t = table(vec![
            entry(
                "bluetooth-host",
                &["CONFIG_BT_HCI_HOST"],
                &["subsys/bluetooth/host"],
                6,
            ),
            entry("shell", &["CONFIG_SHELL"], &["subsys/shell"], 12),
        ]);
        assert_eq!(validate(&t), []);
        assert_eq!(lint_against(&t, &fake()), []);
    }

    #[test]
    fn lint_flags_unknown_symbol() {
        // CONFIG_BT_CTLR does not exist in Zephyr 4.4.2; the controller is BT_LL_SW_SPLIT.
        let t = table(vec![entry(
            "bluetooth-controller",
            &["CONFIG_BT_CTLR"],
            &["subsys/bluetooth/controller"],
            6,
        )]);
        assert_eq!(validate(&t), [], "structurally fine");
        let findings = lint_against(&t, &fake());
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = findings.first().unwrap();
        assert_eq!(f.rule, Rule::UnknownSymbol);
        assert_eq!(f.line, Some(6));
        assert_eq!(f.subsystem.as_deref(), Some("bluetooth-controller"));
        assert!(f.message.contains("CONFIG_BT_CTLR"), "{f}");
    }

    #[test]
    fn lint_flags_unknown_source() {
        let t = table(vec![entry(
            "bluetooth-controller",
            &["CONFIG_BT_LL_SW_SPLIT"],
            &["subsys/bluetooth/ctlr"],
            6,
        )]);
        let findings = lint_against(&t, &fake());
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = findings.first().unwrap();
        assert_eq!(f.rule, Rule::UnknownSource);
        assert!(f.message.contains("subsys/bluetooth/ctlr"), "{f}");
        assert_eq!(
            f.to_string(),
            "bluetooth-controller: source subsys/bluetooth/ctlr does not exist in the reference tree [unknown-source]"
        );
    }

    #[test]
    fn lint_flags_pin_mismatch() {
        let t = table(vec![entry(
            "shell",
            &["CONFIG_SHELL"],
            &["subsys/shell"],
            6,
        )]);
        let reference = Fake {
            pin: Some("v4.4.1"),
            ..fake()
        };
        let findings = lint_against(&t, &reference);
        assert_eq!(
            findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            [Rule::PinMismatch]
        );
        // An unknown version is not a mismatch.
        let reference = Fake {
            pin: None,
            ..fake()
        };
        assert_eq!(lint_against(&t, &reference), []);
    }

    #[test]
    fn lint_rejects_duplicate_subsystem_name() {
        let t = table(vec![
            entry("shell", &["CONFIG_SHELL"], &["subsys/shell"], 6),
            entry(
                "shell",
                &["CONFIG_SHELL_BACKENDS"],
                &["subsys/shell/backends"],
                12,
            ),
        ]);
        let findings = validate(&t);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let f = findings.first().unwrap();
        assert_eq!(f.rule, Rule::DuplicateName);
        assert_eq!(f.line, Some(12));
        assert_eq!(
            f.message,
            "subsystem shell is listed twice (lines 6 and 12)"
        );
    }

    #[test]
    fn findings_are_sorted_and_deterministic() {
        let t = table(vec![
            entry("zz", &["BAD"], &["/abs"], 20),
            entry("aa", &["CONFIG_B", "CONFIG_A"], &["x"], 6),
        ]);
        let first = validate(&t);
        assert_eq!(first, validate(&t));
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted);
        assert_eq!(first.first().map(|f| f.line), Some(Some(6)));
    }
}
