//! The rule lint: every Kconfig symbol a rule names must exist, and rule ids must be unique
//! across files.
//!
//! A `kconfig_off` or `kconfig_equals` condition on a symbol the build's `.config` does not
//! mention is unknown, never true (see the [module docs](super)), so a misspelt symbol
//! (`CONFIG_BTT`) never yields a statement, and nothing else tells the rule's author.
//! [`lint_rules`] does: it checks every such symbol against a [`SymbolReference`] and reports
//! each one it does not know as a [`LintFinding`]. [`lint_duplicate_ids`] reports an id that
//! several files define (which `rollcall vex` refuses).
//!
//! Two references are provided:
//!
//! - [`KconfigSymbols`], offline: the symbols written in one or more `.config` files (set or
//!   `is not set`). A `.config` lists only the symbols visible in that build, so a valid symbol
//!   hidden by an unmet `depends on` is reported too; give more builds, or a tree.
//! - [`ZephyrTree`], authoritative for one Zephyr version: the symbols its `Kconfig*` files
//!   define. A symbol renamed or added in another release is reported.
//!
//! The lint never panics and is deterministic: findings are sorted and deduplicated.

use std::collections::BTreeSet;
use std::fmt;

use super::rules::{Condition, RuleSet};
use crate::subsystems::{Reference, ZephyrTree};
use crate::zephyr::kconfig::Kconfig;

/// What the lint checks symbols against.
pub trait SymbolReference {
    /// Whether `symbol` (written as in a `.config`, e.g. `CONFIG_BT`) exists.
    fn knows(&self, symbol: &str) -> bool;

    /// What the reference is, for messages (e.g. `2 .config file(s)`).
    fn describe(&self) -> String;

    /// Why a symbol it does not know is reported, for messages.
    fn absence(&self) -> String;
}

/// The symbols written in some `.config` files: an offline [`SymbolReference`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KconfigSymbols {
    symbols: BTreeSet<String>,
    files: usize,
}

impl KconfigSymbols {
    /// The union of the symbols of `configs`.
    pub fn from_configs<'a, I: IntoIterator<Item = &'a Kconfig>>(configs: I) -> Self {
        let mut reference = Self::default();
        for config in configs {
            reference.symbols.extend(config.symbols.keys().cloned());
            reference.files = reference.files.saturating_add(1);
        }
        reference
    }

    /// The symbols, in name order.
    pub fn symbols(&self) -> impl Iterator<Item = &str> {
        self.symbols.iter().map(String::as_str)
    }
}

impl SymbolReference for KconfigSymbols {
    fn knows(&self, symbol: &str) -> bool {
        self.symbols.contains(symbol)
    }

    fn describe(&self) -> String {
        format!("{} .config file(s)", self.files)
    }

    fn absence(&self) -> String {
        "not in the given .config files (misspelt, renamed, or hidden by an unmet dependency)"
            .to_owned()
    }
}

impl SymbolReference for ZephyrTree {
    fn knows(&self, symbol: &str) -> bool {
        symbol
            .strip_prefix("CONFIG_")
            .is_some_and(|bare| self.defines_symbol(bare))
    }

    fn describe(&self) -> String {
        match self.version() {
            Some(version) => format!("the Zephyr {version} tree at {}", self.root().display()),
            None => format!("the Zephyr tree at {}", self.root().display()),
        }
    }

    fn absence(&self) -> String {
        format!(
            "not defined by {} (misspelt, or renamed in this release)",
            self.describe()
        )
    }
}

/// Several references: a symbol is known when any of them knows it.
impl<T: SymbolReference> SymbolReference for [T] {
    fn knows(&self, symbol: &str) -> bool {
        self.iter().any(|r| r.knows(symbol))
    }

    fn describe(&self) -> String {
        self.iter()
            .map(SymbolReference::describe)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn absence(&self) -> String {
        match self {
            [one] => one.absence(),
            _ => format!(
                "not defined by any of {} (misspelt, or renamed)",
                self.describe()
            ),
        }
    }
}

/// What a lint finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LintKind {
    /// A `kconfig_off` or `kconfig_equals` symbol the reference does not know.
    UnknownKconfigSymbol,
    /// A rule id an earlier file already defines.
    DuplicateRuleId,
    /// A `kconfig_equals` value written the way YAML writes a boolean or null (`true`, `no`,
    /// `~`, `null`, …), which a `.config` never contains: a bool there is `y`, `n` or `m`.
    BoolLikeValue,
    /// An empty `kconfig_equals` value (`{CONFIG_X: }` or `""`): it matches `CONFIG_X=""`,
    /// an empty string, not a symbol that is off or absent.
    EmptyValue,
}

impl LintKind {
    /// The kind as a short name, e.g. `unknown-kconfig-symbol`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownKconfigSymbol => "unknown-kconfig-symbol",
            Self::DuplicateRuleId => "duplicate-rule-id",
            Self::BoolLikeValue => "bool-like-value",
            Self::EmptyValue => "empty-value",
        }
    }
}

impl fmt::Display for LintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One problem with one rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LintFinding {
    /// The rules file, as given to [`lint_rules`].
    pub file: String,
    /// The rule's id.
    pub rule: String,
    /// What is wrong.
    pub kind: LintKind,
    /// The symbol, for every kind but [`LintKind::DuplicateRuleId`].
    pub symbol: Option<String>,
    /// A sentence for the rule's author.
    pub message: String,
}

impl fmt::Display for LintFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: rule {}: {}: {}",
            self.file, self.rule, self.kind, self.message
        )
    }
}

/// Values a YAML author may mean as a boolean or null, but which a `.config` never holds.
const BOOL_LIKE: [&str; 8] = ["true", "false", "yes", "no", "on", "off", "~", "null"];

/// Checks every `kconfig_off` and `kconfig_equals` symbol of `rules` (read from `file`)
/// against `reference`, and every `kconfig_equals` value against [`LintKind::BoolLikeValue`].
/// Findings are sorted and each appears once.
pub fn lint_rules<R: SymbolReference + ?Sized>(
    rules: &RuleSet,
    file: &str,
    reference: &R,
) -> Vec<LintFinding> {
    let mut findings = BTreeSet::new();
    for rule in &rules.rules {
        for condition in &rule.when {
            if let Condition::KconfigEquals(symbol, value) = condition
                && value.is_empty()
            {
                findings.insert(LintFinding {
                    file: file.to_owned(),
                    rule: rule.id.clone(),
                    kind: LintKind::EmptyValue,
                    symbol: Some(symbol.clone()),
                    message: format!(
                        "kconfig_equals value for {symbol} is empty: it matches {symbol}=\"\", \
                         an empty string, not a symbol that is off or absent (use kconfig_off \
                         for that)"
                    ),
                });
            }
            if let Condition::KconfigEquals(symbol, value) = condition
                && BOOL_LIKE.contains(&value.to_ascii_lowercase().as_str())
            {
                findings.insert(LintFinding {
                    file: file.to_owned(),
                    rule: rule.id.clone(),
                    kind: LintKind::BoolLikeValue,
                    symbol: Some(symbol.clone()),
                    message: format!(
                        "kconfig_equals value {value:?} for {symbol}: values are compared \
                         exactly as the .config writes them, and a .config writes a bool as \
                         y, n or m, so this condition is never true"
                    ),
                });
            }
            let (Condition::KconfigOff(symbol) | Condition::KconfigEquals(symbol, _)) = condition
            else {
                continue;
            };
            if reference.knows(symbol) {
                continue;
            }
            let hint = if symbol.starts_with("CONFIG_") {
                String::new()
            } else {
                " (Kconfig symbols in a .config start with CONFIG_)".to_owned()
            };
            findings.insert(LintFinding {
                file: file.to_owned(),
                rule: rule.id.clone(),
                kind: LintKind::UnknownKconfigSymbol,
                symbol: Some(symbol.clone()),
                message: format!(
                    "unknown Kconfig symbol {symbol}{hint}: {}, so this condition is never \
                     true and the rule never applies",
                    reference.absence()
                ),
            });
        }
    }
    findings.into_iter().collect()
}

/// Reports every rule id of `sets` (file name, rules, in load order) that an earlier file
/// already defines. A file cannot repeat an id itself: the parser refuses that. Sorted.
pub fn lint_duplicate_ids(sets: &[(&str, &RuleSet)]) -> Vec<LintFinding> {
    let mut first: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    let mut findings = BTreeSet::new();
    for (file, rules) in sets {
        for rule in &rules.rules {
            match first.get(rule.id.as_str()) {
                Some(earlier) => {
                    findings.insert(LintFinding {
                        file: (*file).to_owned(),
                        rule: rule.id.clone(),
                        kind: LintKind::DuplicateRuleId,
                        symbol: None,
                        message: format!(
                            "rule id {} is already defined in {earlier}; rollcall vex refuses \
                             rules files that reuse an id",
                            rule.id
                        ),
                    });
                }
                None => {
                    first.insert(rule.id.as_str(), file);
                }
            }
        }
    }
    findings.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vex::parse_rules;
    use crate::zephyr::kconfig;

    fn rules(text: &str) -> RuleSet {
        parse_rules(text, "r.yml").unwrap()
    }

    const TYPO: &str = "\
version: 1
rules:
  - id: bt-off
    match: {name: zephyr}
    when:
      - kconfig_off: CONFIG_BTT
      - kconfig_off: CONFIG_BT
      - symbol_not_linked: bt_enable
    status: not_affected
    justification: code_not_present
  - id: also-bt
    match: {name: zephyr}
    when: [{kconfig_off: BT}, {kconfig_off: CONFIG_BTT}]
    status: affected
";

    fn reference() -> KconfigSymbols {
        let a = kconfig::parse("CONFIG_BT=y\n# CONFIG_SHELL is not set\n").unwrap();
        let b = kconfig::parse("# CONFIG_BT is not set\nCONFIG_FILE_SYSTEM=y\n").unwrap();
        KconfigSymbols::from_configs([&a, &b])
    }

    #[test]
    fn unknown_symbol_is_reported_with_rule_id() {
        let findings = lint_rules(&rules(TYPO), "typo.yml", &reference());
        let shown: Vec<(&str, &str)> = findings
            .iter()
            .map(|f| (f.rule.as_str(), f.symbol.as_deref().unwrap_or_default()))
            .collect();
        assert_eq!(
            shown,
            [
                ("also-bt", "BT"),
                ("also-bt", "CONFIG_BTT"),
                ("bt-off", "CONFIG_BTT")
            ]
        );
        assert!(
            findings
                .iter()
                .all(|f| f.kind == LintKind::UnknownKconfigSymbol)
        );
        assert_eq!(
            findings[2].to_string(),
            "typo.yml: rule bt-off: unknown-kconfig-symbol: unknown Kconfig symbol CONFIG_BTT: \
             not in the given .config files (misspelt, renamed, or hidden by an unmet \
             dependency), so this condition is never true and the rule never applies"
        );
        assert!(
            findings[0].message.contains("start with CONFIG_"),
            "{}",
            findings[0]
        );
    }

    #[test]
    fn known_symbols_are_clean_and_other_conditions_ignored() {
        let text = "version: 1\nrules:\n  - id: a\n    match: {name: x}\n    when: [{kconfig_off: CONFIG_SHELL}, {symbol_not_linked: CONFIG_NOPE}, {cargo_feature_off: f}, {version_in: '<2'}]\n    status: affected\n";
        assert!(lint_rules(&rules(text), "r.yml", &reference()).is_empty());
        assert!(lint_rules(&RuleSet::default(), "r.yml", &reference()).is_empty());
    }

    #[test]
    fn empty_reference_reports_every_symbol_once() {
        let empty = KconfigSymbols::from_configs([]);
        assert_eq!(empty.describe(), "0 .config file(s)");
        let findings = lint_rules(&rules(TYPO), "t.yml", &empty);
        assert_eq!(findings.len(), 4, "{findings:?}");
        let mut sorted = findings.clone();
        sorted.sort();
        assert_eq!(sorted, findings);
    }

    #[test]
    fn kconfig_equals_symbols_are_checked_too() {
        let text = "version: 1\nrules:\n  - id: a\n    match: {name: x}\n    when: [{kconfig_equals: {CONFIG_MBEDTLS_CFG_FIL: config-mbedtls.h}}]\n    status: affected\n";
        let findings = lint_rules(&rules(text), "r.yml", &reference());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].symbol.as_deref(),
            Some("CONFIG_MBEDTLS_CFG_FIL")
        );
    }

    #[test]
    fn bool_like_kconfig_equals_values_warn() {
        let mut text = String::from("version: 1\nrules:\n");
        for (i, value) in [
            "true", "False", "yes", "no", "on", "OFF", "~", "y", "n", "0x10", "null",
        ]
        .iter()
        .enumerate()
        {
            text.push_str(&format!(
                "  - id: r{i}\n    match: {{name: x}}\n    when: [{{kconfig_equals: {{CONFIG_BT: \"{value}\"}}}}]\n    status: affected\n"
            ));
        }
        let findings = lint_rules(&rules(&text), "r.yml", &reference());
        let warned: Vec<&str> = findings
            .iter()
            .filter(|f| f.kind == LintKind::BoolLikeValue)
            .map(|f| f.rule.as_str())
            .collect();
        assert_eq!(warned, ["r0", "r1", "r10", "r2", "r3", "r4", "r5", "r6"]);
        assert_eq!(findings.len(), 8, "{findings:?}");
        assert!(
            findings[0].to_string().contains("bool-like-value"),
            "{}",
            findings[0]
        );
    }

    #[test]
    fn empty_kconfig_equals_value_warns() {
        for written in ["", "\"\""] {
            let text = format!(
                "version: 1\nrules:\n  - id: e\n    match: {{name: x}}\n    when: [{{kconfig_equals: {{CONFIG_BT: {written}}}}}]\n    status: affected\n"
            );
            let set = rules(&text);
            assert_eq!(
                set.rules[0].when,
                [Condition::KconfigEquals(
                    "CONFIG_BT".to_owned(),
                    String::new()
                )],
                "{written:?}"
            );
            let findings = lint_rules(&set, "r.yml", &reference());
            let [finding] = findings.as_slice() else {
                panic!("{written:?}: {findings:?}")
            };
            assert_eq!(finding.kind, LintKind::EmptyValue);
            assert!(finding.message.contains("CONFIG_BT=\"\""), "{finding}");
        }
    }

    #[test]
    fn duplicate_ids_across_files_are_reported_at_the_later_file() {
        let a = rules(
            "version: 1\nrules:\n  - {id: x, match: {name: a}, status: fixed}\n  - {id: y, match: {name: a}, status: fixed}\n",
        );
        let b = rules("version: 1\nrules:\n  - {id: y, match: {name: b}, status: fixed}\n");
        let c = rules(
            "version: 1\nrules:\n  - {id: x, match: {name: c}, status: fixed}\n  - {id: z, match: {name: c}, status: fixed}\n",
        );
        let findings = lint_duplicate_ids(&[("a.yml", &a), ("b.yml", &b), ("c.yml", &c)]);
        let shown: Vec<String> = findings.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "b.yml: rule y: duplicate-rule-id: rule id y is already defined in a.yml; \
                 rollcall vex refuses rules files that reuse an id",
                "c.yml: rule x: duplicate-rule-id: rule id x is already defined in a.yml; \
                 rollcall vex refuses rules files that reuse an id",
            ]
        );
        assert!(lint_duplicate_ids(&[("a.yml", &a)]).is_empty());
    }

    #[test]
    fn several_references_union() {
        let one = KconfigSymbols::from_configs([&kconfig::parse("CONFIG_BTT=y\n").unwrap()]);
        let both = [reference(), one];
        assert!(both.knows("CONFIG_BTT") && both.knows("CONFIG_SHELL"));
        assert_eq!(both.describe(), "2 .config file(s), 1 .config file(s)");
        let findings = lint_rules(&rules(TYPO), "t.yml", &both[..]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].symbol.as_deref(), Some("BT"));
    }

    #[test]
    fn zephyr_tree_reference_strips_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("VERSION"),
            "VERSION_MAJOR = 4\nVERSION_MINOR = 4\nPATCHLEVEL = 2\nEXTRAVERSION =\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("subsys/bluetooth")).unwrap();
        std::fs::write(
            root.join("subsys/bluetooth/Kconfig"),
            "menuconfig BT\n\tbool \"Bluetooth\"\n",
        )
        .unwrap();
        let tree = ZephyrTree::open(root).unwrap();
        assert!(tree.knows("CONFIG_BT"));
        assert!(!tree.knows("BT"), "a bare name is not a .config symbol");
        assert!(!tree.knows("CONFIG_BTT"));
        let findings = lint_rules(&rules(TYPO), "t.yml", &tree);
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert!(
            findings[0]
                .message
                .contains("not defined by the Zephyr v4.4.2 tree at")
        );
    }
}
