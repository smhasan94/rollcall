//! The VEX rule format and its loader. See the [module docs](super) for the format.
//!
//! The loader never panics. Every problem is a [`RuleError`] naming the file and, wherever
//! the YAML parser can place it, the line and column:
//!
//! - syntax errors, wrong types, unknown keys and unknown `status`/`justification` values are
//!   located at the offending node;
//! - per-rule checks (a missing target, a bad purl pattern or version range, a justification
//!   that is missing or not allowed, a duplicate `id`) are located at the start of that rule;
//! - per-condition checks (an unknown condition, more than one key) at that condition.
//!
//! Those per-rule and per-condition checks run inside the deserialiser's visitors, so that the
//! YAML parser stamps them with the position of the mapping being read.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

use super::pattern::PurlPattern;
use super::version::VersionRange;

/// The rule-file `version` this rollcall reads.
pub const RULES_VERSION: u32 = 1;

/// A set of rules, in file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// The rules. Their `id`s are unique.
    pub rules: Vec<Rule>,
}

/// One rule: when a finding matches `target` and every `when` condition holds, the finding
/// gets `status` (with `justification` and `detail`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The rule's unique id, `[A-Za-z0-9._-]+`.
    pub id: String,
    /// Tie-break between rules of equal specificity; higher wins. Default 0.
    pub priority: i32,
    /// What the rule applies to (`match:` in YAML).
    pub target: Match,
    /// Conditions that must all hold, evaluated against build evidence.
    pub when: Vec<Condition>,
    /// The resulting status.
    pub status: Status,
    /// Why the component is not affected; present exactly when `status` is `not_affected`.
    pub justification: Option<Justification>,
    /// Free-text detail for the statement.
    pub detail: Option<String>,
}

/// A rule's `match:`. Every field given must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    /// The component's purl matches this pattern.
    pub purl: Option<PurlPattern>,
    /// The component's name is exactly this.
    pub name: Option<String>,
    /// The component is a nested subcomponent (e.g. a kernel subsystem) with exactly this name.
    pub subsystem: Option<String>,
    /// The finding's id or one of its aliases is one of these (upper-cased). Empty: any.
    pub cves: BTreeSet<String>,
    /// The component's version is in this range.
    pub versions: Option<VersionRange>,
}

/// A `when:` condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// `kconfig_off: CONFIG_X` — the Kconfig symbol is `n` or not set.
    KconfigOff(String),
    /// `kconfig_equals: {CONFIG_X: value}` — the Kconfig symbol's value, exactly as written in
    /// the `.config` (`y`, `n` for `is not set`, `m`, a number or hex number as text, or a
    /// string's contents), is `value`.
    KconfigEquals(String, String),
    /// `cargo_feature_off: name` — the Cargo feature is not enabled.
    CargoFeatureOff(String),
    /// `symbol_not_linked: name` — the symbol is not in the linked image.
    SymbolNotLinked(String),
    /// `version_in: ">=1, <2"` — the component's version is in the range.
    VersionIn(VersionRange),
}

/// The condition keys, as written in YAML.
pub const CONDITIONS: &[&str] = &[
    "kconfig_off",
    "kconfig_equals",
    "cargo_feature_off",
    "symbol_not_linked",
    "version_in",
];

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KconfigOff(s) => write!(f, "kconfig_off: {s}"),
            Self::KconfigEquals(s, v) => write!(f, "kconfig_equals: {s}={v:?}"),
            Self::CargoFeatureOff(s) => write!(f, "cargo_feature_off: {s}"),
            Self::SymbolNotLinked(s) => write!(f, "symbol_not_linked: {s}"),
            Self::VersionIn(r) => write!(f, "version_in: {r}"),
        }
    }
}

/// A VEX status, written with the OpenVEX words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Not affected (needs a justification).
    NotAffected,
    /// Affected.
    Affected,
    /// Fixed.
    Fixed,
    /// Under investigation.
    UnderInvestigation,
}

impl Status {
    /// The word used in rules and in OpenVEX.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "affected",
            Self::Fixed => "fixed",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    /// The OpenVEX `status`.
    pub fn openvex(self) -> &'static str {
        self.as_str()
    }

    /// The CycloneDX 1.6 `analysis.state`.
    pub fn cyclonedx_state(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Affected => "exploitable",
            Self::Fixed => "resolved",
            Self::UnderInvestigation => "in_triage",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `not_affected` justification, kept as the word the rule's author wrote: one of the
/// CycloneDX 1.6 `impactAnalysisJustification` values or one of the OpenVEX justifications.
/// It is mapped to the other vocabulary only when rendered ([`Justification::cyclonedx`],
/// [`Justification::openvex`]), so a word is never rewritten on its way to the format it
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Justification {
    /// CycloneDX `code_not_present`.
    CodeNotPresent,
    /// CycloneDX `code_not_reachable`.
    CodeNotReachable,
    /// CycloneDX `requires_configuration`.
    RequiresConfiguration,
    /// CycloneDX `requires_dependency`.
    RequiresDependency,
    /// CycloneDX `requires_environment`.
    RequiresEnvironment,
    /// CycloneDX `protected_by_compiler`.
    ProtectedByCompiler,
    /// CycloneDX `protected_at_runtime`.
    ProtectedAtRuntime,
    /// CycloneDX `protected_at_perimeter`.
    ProtectedAtPerimeter,
    /// CycloneDX `protected_by_mitigating_control`.
    ProtectedByMitigatingControl,
    /// OpenVEX `component_not_present`.
    ComponentNotPresent,
    /// OpenVEX `vulnerable_code_not_present`.
    VulnerableCodeNotPresent,
    /// OpenVEX `vulnerable_code_not_in_execute_path`.
    VulnerableCodeNotInExecutePath,
    /// OpenVEX `vulnerable_code_cannot_be_controlled_by_adversary`.
    VulnerableCodeCannotBeControlledByAdversary,
    /// OpenVEX `inline_mitigations_already_exist`.
    InlineMitigationsAlreadyExist,
}

impl Justification {
    /// The word as written in the rule.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CodeNotPresent => "code_not_present",
            Self::CodeNotReachable => "code_not_reachable",
            Self::RequiresConfiguration => "requires_configuration",
            Self::RequiresDependency => "requires_dependency",
            Self::RequiresEnvironment => "requires_environment",
            Self::ProtectedByCompiler => "protected_by_compiler",
            Self::ProtectedAtRuntime => "protected_at_runtime",
            Self::ProtectedAtPerimeter => "protected_at_perimeter",
            Self::ProtectedByMitigatingControl => "protected_by_mitigating_control",
            Self::ComponentNotPresent => "component_not_present",
            Self::VulnerableCodeNotPresent => "vulnerable_code_not_present",
            Self::VulnerableCodeNotInExecutePath => "vulnerable_code_not_in_execute_path",
            Self::VulnerableCodeCannotBeControlledByAdversary => {
                "vulnerable_code_cannot_be_controlled_by_adversary"
            }
            Self::InlineMitigationsAlreadyExist => "inline_mitigations_already_exist",
        }
    }

    /// The CycloneDX 1.6 value: a CycloneDX word unchanged; `component_not_present` and
    /// `vulnerable_code_not_present` → `code_not_present`;
    /// `vulnerable_code_not_in_execute_path` → `code_not_reachable`;
    /// `vulnerable_code_cannot_be_controlled_by_adversary` → `requires_environment`;
    /// `inline_mitigations_already_exist` → `protected_by_mitigating_control`.
    pub fn cyclonedx(self) -> &'static str {
        match self {
            Self::ComponentNotPresent | Self::VulnerableCodeNotPresent => "code_not_present",
            Self::VulnerableCodeNotInExecutePath => "code_not_reachable",
            Self::VulnerableCodeCannotBeControlledByAdversary => "requires_environment",
            Self::InlineMitigationsAlreadyExist => "protected_by_mitigating_control",
            other => other.as_str(),
        }
    }

    /// The OpenVEX justification: an OpenVEX word unchanged; `code_not_present` →
    /// `vulnerable_code_not_present`; `code_not_reachable` →
    /// `vulnerable_code_not_in_execute_path`; `requires_*` →
    /// `vulnerable_code_cannot_be_controlled_by_adversary`; `protected_*` →
    /// `inline_mitigations_already_exist`. (Many-to-one; to be confirmed with SHA-113.)
    pub fn openvex(self) -> &'static str {
        match self {
            Self::CodeNotPresent => "vulnerable_code_not_present",
            Self::CodeNotReachable => "vulnerable_code_not_in_execute_path",
            Self::RequiresConfiguration | Self::RequiresDependency | Self::RequiresEnvironment => {
                "vulnerable_code_cannot_be_controlled_by_adversary"
            }
            Self::ProtectedByCompiler
            | Self::ProtectedAtRuntime
            | Self::ProtectedAtPerimeter
            | Self::ProtectedByMitigatingControl => "inline_mitigations_already_exist",
            other => other.as_str(),
        }
    }

    /// Whether two justifications say the same thing in both vocabularies (e.g.
    /// `code_not_present` and `vulnerable_code_not_present`).
    pub fn agrees_with(self, other: Self) -> bool {
        self.cyclonedx() == other.cyclonedx() && self.openvex() == other.openvex()
    }
}

impl fmt::Display for Justification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a rule file could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {message}", Located(file, *line, *column))]
pub struct RuleError {
    /// The file, as given to [`parse_rules`].
    pub file: String,
    /// The 1-based line, if known.
    pub line: Option<u32>,
    /// The 1-based column, if known.
    pub column: Option<u32>,
    /// What is wrong.
    pub message: String,
}

impl RuleError {
    fn unlocated(file: &str, message: impl Into<String>) -> Self {
        Self {
            file: file.to_owned(),
            line: None,
            column: None,
            message: message.into(),
        }
    }
}

/// `file`, `file:line` or `file:line:column`.
struct Located<'a>(&'a str, Option<u32>, Option<u32>);

impl fmt::Display for Located<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)?;
        if let Some(line) = self.1 {
            write!(f, ":{line}")?;
            if let Some(column) = self.2 {
                write!(f, ":{column}")?;
            }
        }
        Ok(())
    }
}

impl RuleSet {
    /// Appends `other`'s rules (from `file`), rejecting an `id` already in this set.
    pub fn extend_checked(&mut self, other: RuleSet, file: &str) -> Result<(), RuleError> {
        let seen: BTreeSet<&str> = self.rules.iter().map(|r| r.id.as_str()).collect();
        if let Some(dup) = other.rules.iter().find(|r| seen.contains(r.id.as_str())) {
            return Err(RuleError::unlocated(
                file,
                format!(
                    "duplicate rule id `{}`: already defined in an earlier rules file",
                    dup.id
                ),
            ));
        }
        self.rules.extend(other.rules);
        Ok(())
    }
}

/// Parses a rule file, citing it as `file` in errors.
pub fn parse_rules(text: &str, file: &str) -> Result<RuleSet, RuleError> {
    if text.trim().is_empty() {
        return Err(RuleError::unlocated(file, "empty rules file"));
    }
    let parsed: Option<RuleFile> = yaml_serde::from_str(text).map_err(|e| {
        let location = e.location();
        let line = location.as_ref().map(|l| to_u32(l.line()));
        let column = location.as_ref().map(|l| to_u32(l.column()));
        let message = e.to_string();
        RuleError {
            file: file.to_owned(),
            line,
            column,
            message: without_location(&message, line, column).to_owned(),
        }
    })?;
    match parsed {
        Some(RuleFile(rules)) => Ok(RuleSet { rules }),
        None => Err(RuleError::unlocated(file, "empty rules file")),
    }
}

/// Checks `bytes` are UTF-8, then parses them with [`parse_rules`].
pub fn parse_rules_bytes(bytes: &[u8], file: &str) -> Result<RuleSet, RuleError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| RuleError::unlocated(file, format!("not valid UTF-8: {e}")))?;
    parse_rules(text, file)
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

/// The whole file: `version` and `rules`. The version is checked inside the visitor so that
/// the error is located.
struct RuleFile(Vec<Rule>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    version: u32,
    #[serde(default)]
    rules: Rules,
}

impl<'de> Deserialize<'de> for RuleFile {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct FileVisitor;
        impl<'de> Visitor<'de> for FileVisitor {
            type Value = RuleFile;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a rules file: a mapping with `version` and `rules`")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<RuleFile, A::Error> {
                let raw = RawFile::deserialize(MapAccessDeserializer::new(map))?;
                if raw.version != RULES_VERSION {
                    return Err(de::Error::custom(format!(
                        "unsupported rules version {}; this rollcall reads version {RULES_VERSION}",
                        raw.version
                    )));
                }
                Ok(RuleFile(raw.rules.0))
            }
        }
        d.deserialize_map(FileVisitor)
    }
}

/// The `rules:` sequence, rejecting a duplicate `id` at the rule that repeats it.
#[derive(Default)]
struct Rules(Vec<Rule>);

impl<'de> Deserialize<'de> for Rules {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct RulesVisitor;
        impl<'de> Visitor<'de> for RulesVisitor {
            type Value = Rules;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of rules")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Rules, A::Error> {
                let mut seen = BTreeSet::new();
                let mut rules = Vec::new();
                while let Some(rule) = seq.next_element_seed(RuleSeed { seen: &mut seen })? {
                    rules.push(rule);
                }
                Ok(Rules(rules))
            }
        }
        d.deserialize_seq(RulesVisitor)
    }
}

/// Reads one rule, given the ids seen so far.
struct RuleSeed<'a> {
    seen: &'a mut BTreeSet<String>,
}

impl<'de> DeserializeSeed<'de> for RuleSeed<'_> {
    type Value = Rule;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Rule, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RuleSeed<'_> {
    type Value = Rule;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a rule: a mapping with `id`, `match` and `status`")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Rule, A::Error> {
        let raw = RawRule::deserialize(MapAccessDeserializer::new(map))?;
        let rule = raw.check().map_err(de::Error::custom)?;
        if !self.seen.insert(rule.id.clone()) {
            return Err(de::Error::custom(format!(
                "duplicate rule id `{}`",
                rule.id
            )));
        }
        Ok(rule)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    #[serde(default)]
    priority: i32,
    #[serde(rename = "match")]
    target: RawMatch,
    #[serde(default)]
    when: Vec<Condition>,
    status: Status,
    #[serde(default)]
    justification: Option<Justification>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatch {
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    subsystem: Option<String>,
    #[serde(default)]
    cves: Option<Vec<String>>,
    #[serde(default)]
    versions: Option<String>,
}

fn is_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn non_empty(value: Option<String>, what: &str) -> Result<Option<String>, String> {
    match value {
        Some(v) if v.trim().is_empty() => Err(format!("{what} is empty")),
        other => Ok(other),
    }
}

/// A name compared exactly: non-empty and without leading or trailing whitespace (which
/// would silently never match).
fn exact_name(value: Option<String>, what: &str) -> Result<Option<String>, String> {
    match value {
        Some(v) if v.trim().is_empty() => Err(format!("{what} is empty")),
        Some(v) if v.trim() != v => Err(format!("{what} {v:?} has leading or trailing whitespace")),
        other => Ok(other),
    }
}

/// A `match.subsystem` must name an entry of the built-in subsystem table
/// ([`crate::subsystems::builtin`]): a misspelt name would otherwise match nothing, silently.
fn check_subsystem(id: &str, name: &str) -> Result<(), String> {
    let table = crate::subsystems::builtin()
        .map_err(|e| format!("rule `{id}`: match.subsystem cannot be checked: {e}"))?;
    if table.get(name).is_some() {
        return Ok(());
    }
    let known: Vec<&str> = table.subsystems.iter().map(|s| s.name.as_str()).collect();
    Err(format!(
        "rule `{id}`: match.subsystem {name:?} is not a subsystem in {} (known: {})",
        crate::subsystems::BUILTIN_NAME,
        known.join(", ")
    ))
}

impl RawRule {
    /// The per-rule checks the types do not express.
    fn check(self) -> Result<Rule, String> {
        if !is_rule_id(&self.id) {
            return Err(format!("rule id {:?} must match [A-Za-z0-9._-]+", self.id));
        }
        let id = self.id;
        let m = self.target;
        let name = exact_name(m.name, "match.name")?;
        let subsystem = exact_name(m.subsystem, "match.subsystem")?;
        if let Some(name) = &subsystem {
            check_subsystem(&id, name)?;
        }
        let purl = match m.purl {
            Some(p) => Some(PurlPattern::new(&p).map_err(|e| format!("match.purl: {e}"))?),
            None => None,
        };
        if purl.is_none() && name.is_none() && subsystem.is_none() {
            return Err(format!(
                "rule `{id}`: match needs at least one of `purl`, `name` or `subsystem`"
            ));
        }
        let mut cves = BTreeSet::new();
        if let Some(list) = m.cves {
            if list.is_empty() {
                return Err(format!(
                    "rule `{id}`: match.cves is empty; omit it to match every vulnerability"
                ));
            }
            for cve in list {
                let cve = cve.trim();
                if cve.is_empty() || cve.chars().any(char::is_whitespace) {
                    return Err(format!(
                        "rule `{id}`: match.cves entry {cve:?} is not an identifier"
                    ));
                }
                cves.insert(cve.to_ascii_uppercase());
            }
        }
        let versions = match m.versions {
            Some(v) => Some(VersionRange::parse(&v).map_err(|e| {
                format!("rule `{id}`: match.versions {v:?} is not a semver range: {e}")
            })?),
            None => None,
        };
        let justification = self.justification;
        match (self.status, justification) {
            (Status::NotAffected, None) => {
                return Err(format!(
                    "rule `{id}`: status not_affected needs a justification"
                ));
            }
            (status, Some(_)) if status != Status::NotAffected => {
                return Err(format!(
                    "rule `{id}`: a justification is only allowed with status not_affected, \
                     not {status}"
                ));
            }
            _ => {}
        }
        let detail = non_empty(self.detail, "detail")?;
        Ok(Rule {
            id,
            priority: self.priority,
            target: Match {
                purl,
                name,
                subsystem,
                cves,
                versions,
            },
            when: self.when,
            status: self.status,
            justification,
            detail,
        })
    }
}

/// A Kconfig symbol name: a letter or `_`, then letters, digits and `_`.
fn is_kconfig_symbol(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn is_word(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl<'de> Deserialize<'de> for Condition {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ConditionVisitor;
        impl<'de> Visitor<'de> for ConditionVisitor {
            type Value = Condition;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "a condition: a mapping with one of {}",
                    CONDITIONS.join(", ")
                )
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Condition, A::Error> {
                let Some(key) = map.next_key::<String>()? else {
                    return Err(de::Error::custom(format!(
                        "empty condition; expected one of {}",
                        CONDITIONS.join(", ")
                    )));
                };
                let condition = match key.as_str() {
                    "kconfig_off" => {
                        let symbol: String = map.next_value()?;
                        if !is_kconfig_symbol(&symbol) {
                            return Err(de::Error::custom(format!(
                                "kconfig_off: {symbol:?} is not a Kconfig symbol ([A-Za-z_][A-Za-z0-9_]*)"
                            )));
                        }
                        Condition::KconfigOff(symbol)
                    }
                    "kconfig_equals" => {
                        let OnePair(symbol, value) = map.next_value()?;
                        if !is_kconfig_symbol(&symbol) {
                            return Err(de::Error::custom(format!(
                                "kconfig_equals: {symbol:?} is not a Kconfig symbol ([A-Za-z_][A-Za-z0-9_]*)"
                            )));
                        }
                        if value.chars().any(|c| c == '\n' || c == '\r') {
                            return Err(de::Error::custom(format!(
                                "kconfig_equals: the value of {symbol} spans lines"
                            )));
                        }
                        Condition::KconfigEquals(symbol, value)
                    }
                    "cargo_feature_off" => {
                        let feature: String = map.next_value()?;
                        if !is_word(&feature) {
                            return Err(de::Error::custom(format!(
                                "cargo_feature_off: {feature:?} is not a feature name"
                            )));
                        }
                        Condition::CargoFeatureOff(feature)
                    }
                    "symbol_not_linked" => {
                        let symbol: String = map.next_value()?;
                        if !is_word(&symbol) {
                            return Err(de::Error::custom(format!(
                                "symbol_not_linked: {symbol:?} is not a symbol name"
                            )));
                        }
                        Condition::SymbolNotLinked(symbol)
                    }
                    "version_in" => {
                        let range: String = map.next_value()?;
                        Condition::VersionIn(VersionRange::parse(&range).map_err(|e| {
                            de::Error::custom(format!(
                                "version_in: {range:?} is not a semver range: {e}"
                            ))
                        })?)
                    }
                    other => return Err(de::Error::unknown_field(other, CONDITIONS)),
                };
                if let Some(extra) = map.next_key::<String>()? {
                    return Err(de::Error::custom(format!(
                        "a condition has exactly one key, found `{key}` and `{extra}`; \
                         write each condition as its own list item"
                    )));
                }
                Ok(condition)
            }
        }
        d.deserialize_map(ConditionVisitor)
    }
}

/// A `kconfig_equals` mapping: exactly one `CONFIG_X: value` entry, the value a string.
/// A second entry, including a repeated key (which a map type would silently collapse), is
/// an error.
struct OnePair(String, String);

impl<'de> Deserialize<'de> for OnePair {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PairVisitor;
        impl<'de> Visitor<'de> for PairVisitor {
            type Value = OnePair;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map with one `CONFIG_X: value` entry")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OnePair, A::Error> {
                let Some(symbol) = map.next_key::<String>()? else {
                    return Err(de::Error::custom(
                        "kconfig_equals: write one `CONFIG_X: value` mapping",
                    ));
                };
                let value: String = map.next_value()?;
                if let Some(next) = map.next_key::<String>()? {
                    return Err(de::Error::custom(if next == symbol {
                        format!("kconfig_equals: duplicate key {symbol}")
                    } else {
                        format!(
                            "kconfig_equals: write one `CONFIG_X: value` mapping, found \
                             {symbol} and {next}; use one condition per symbol"
                        )
                    }));
                }
                Ok(OnePair(symbol, value))
            }
        }
        d.deserialize_map(PairVisitor)
    }
}

/// A fill-in rule for one unresolved finding, as a YAML list item to paste under `rules:`.
/// It matches the component by exact purl (or by name, without one) and the vulnerability by
/// id, with status `under_investigation`, so it loads as is.
///
/// The id is `todo-<vulnerability>-<name>-<8 hex>`, the hex being a hash of `target` (the
/// component's `bom-ref`, or the package's purl or name), so same-named components in
/// different images get different ids. With `in_sbom` false (the package is not a component
/// of the SBOM) the template starts with a comment saying that it cannot resolve the finding.
pub fn template(
    vulnerability: &str,
    name: &str,
    purl: Option<&str>,
    target: &str,
    in_sbom: bool,
) -> String {
    #[derive(Serialize)]
    struct TemplateRule<'a> {
        id: String,
        #[serde(rename = "match")]
        target: TemplateMatch<'a>,
        status: &'static str,
        detail: String,
    }
    #[derive(Serialize)]
    struct TemplateMatch<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        purl: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
        cves: [&'a str; 1],
    }
    let sanitise = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect()
    };
    let digest = Sha256::digest(target.as_bytes());
    let short: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let rule = TemplateRule {
        id: format!(
            "todo-{}-{}-{short}",
            sanitise(vulnerability),
            sanitise(name)
        ),
        target: TemplateMatch {
            purl,
            name: if purl.is_none() { Some(name) } else { None },
            cves: [vulnerability],
        },
        status: Status::UnderInvestigation.as_str(),
        detail: format!(
            "TODO: assess {vulnerability} for {name}; set status (with a justification for \
             not_affected) and add `when` conditions backed by build evidence"
        ),
    };
    let yaml = yaml_serde::to_string(&[rule]).unwrap_or_default();
    if in_sbom {
        yaml
    } else {
        let name: String = name
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        format!(
            "# {name} is not a component of the SBOM, so this rule cannot resolve the finding:\n\
             # fix the SBOM (or the scanner's package match) first.\n{yaml}"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const VALID: &str = "\
version: 1
rules:
  - id: mbedtls-dtls-compiled-out
    priority: 10
    match:
      purl: \"pkg:github/mbed-tls/mbedtls@*\"
      cves: [cve-2022-35409]
      versions: \">=2.28.0, <2.28.5\"
    when:
      - kconfig_off: CONFIG_MBEDTLS_SSL_PROTO_DTLS
      - cargo_feature_off: dtls
      - symbol_not_linked: mbedtls_ssl_parse_client_hello
      - version_in: \"<2.28.1\"
    status: not_affected
    justification: vulnerable_code_not_present
    detail: DTLS is compiled out.
  - id: mbedtls-any
    match:
      name: mbedtls
    status: under_investigation
";

    fn err(text: &str) -> RuleError {
        parse_rules(text, "rules.yml").unwrap_err()
    }

    /// A one-rule file with `body` as the rule's lines (indented four spaces); the rule
    /// mapping starts on line 3.
    fn one_rule(body: &str) -> String {
        let mut text = String::from("version: 1\nrules:\n  - id: r1\n");
        for line in body.lines() {
            text.push_str("    ");
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    #[test]
    fn valid_rules_parse() {
        let set = parse_rules(VALID, "rules.yml").unwrap();
        assert_eq!(set.rules.len(), 2);
        let r = &set.rules[0];
        assert_eq!(r.id, "mbedtls-dtls-compiled-out");
        assert_eq!(r.priority, 10);
        assert_eq!(
            r.target.purl.as_ref().map(PurlPattern::as_str),
            Some("pkg:github/mbed-tls/mbedtls@*")
        );
        assert_eq!(r.target.cves, BTreeSet::from(["CVE-2022-35409".to_owned()]));
        assert_eq!(
            r.target.versions.as_ref().map(VersionRange::as_str),
            Some(">=2.28.0, <2.28.5")
        );
        assert_eq!(
            r.when,
            vec![
                Condition::KconfigOff("CONFIG_MBEDTLS_SSL_PROTO_DTLS".to_owned()),
                Condition::CargoFeatureOff("dtls".to_owned()),
                Condition::SymbolNotLinked("mbedtls_ssl_parse_client_hello".to_owned()),
                Condition::VersionIn(VersionRange::parse("<2.28.1").unwrap()),
            ]
        );
        assert_eq!(r.status, Status::NotAffected);
        assert_eq!(
            r.justification,
            Some(Justification::VulnerableCodeNotPresent)
        );
        assert_eq!(r.detail.as_deref(), Some("DTLS is compiled out."));
        let fallback = &set.rules[1];
        assert_eq!(fallback.priority, 0);
        assert_eq!(fallback.target.name.as_deref(), Some("mbedtls"));
        assert!(fallback.when.is_empty());
        assert_eq!(fallback.justification, None);
    }

    #[test]
    fn unknown_status_rejected_with_line() {
        let e = err(&one_rule("match: {name: x}\nstatus: maybe\n"));
        assert_eq!(e.line, Some(5), "{e}");
        assert!(e.message.contains("unknown variant `maybe`"), "{e}");
        assert!(e.message.contains("not_affected"), "{e}");
        assert!(e.to_string().starts_with("rules.yml:5:"), "{e}");
    }

    #[test]
    fn unknown_justification_rejected_with_line() {
        let e = err(&one_rule(
            "match: {name: x}\nstatus: not_affected\njustification: because\n",
        ));
        assert_eq!(e.line, Some(6), "{e}");
        assert!(e.message.contains("unknown variant `because`"), "{e}");
        assert!(e.message.contains("vulnerable_code_not_present"), "{e}");
    }

    #[test]
    fn unknown_condition_rejected_with_line() {
        let e = err(&one_rule(
            "match: {name: x}\nwhen:\n  - kconfig_off: CONFIG_A\n  - moon_phase: full\nstatus: affected\n",
        ));
        assert_eq!(e.line, Some(7), "{e}");
        assert!(e.message.contains("unknown field `moon_phase`"), "{e}");
        assert!(e.message.contains("kconfig_off"), "{e}");
    }

    #[test]
    fn unknown_field_rejected_with_line() {
        let e = err(&one_rule(
            "match: {name: x}\nstatus: affected\nsevrity: high\n",
        ));
        assert_eq!(e.line, Some(6), "{e}");
        assert!(e.message.contains("unknown field `sevrity`"), "{e}");
    }

    #[test]
    fn not_affected_requires_justification() {
        let e = err(&one_rule("match: {name: x}\nstatus: not_affected\n"));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("needs a justification"), "{e}");
    }

    #[test]
    fn other_status_rejects_justification() {
        let e = err(&one_rule(
            "match: {name: x}\nstatus: affected\njustification: code_not_present\n",
        ));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(
            e.message.contains("only allowed with status not_affected"),
            "{e}"
        );
    }

    #[test]
    fn match_needs_target() {
        let e = err(&one_rule("match: {cves: [CVE-1]}\nstatus: affected\n"));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("at least one of"), "{e}");
    }

    #[test]
    fn bad_purl_pattern_rejected() {
        let e = err(&one_rule("match: {purl: \"mbedtls*\"}\nstatus: affected\n"));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("must start with `pkg:`"), "{e}");
    }

    #[test]
    fn bad_version_range_rejected() {
        let e = err(&one_rule(
            "match: {name: x, versions: \"around 2\"}\nstatus: affected\n",
        ));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("not a semver range"), "{e}");
        let e = err(&one_rule(
            "match: {name: x}\nwhen:\n  - version_in: \"=>1\"\nstatus: affected\n",
        ));
        assert_eq!(e.line, Some(6), "{e}");
        assert!(e.message.contains("version_in"), "{e}");
    }

    #[test]
    fn duplicate_id_rejected() {
        let text = "\
version: 1
rules:
  - id: a
    match: {name: x}
    status: affected
  - id: a
    match: {name: y}
    status: fixed
";
        let e = err(text);
        assert_eq!(e.line, Some(6), "{e}");
        assert!(e.message.contains("duplicate rule id `a`"), "{e}");

        let mut first = parse_rules(
            "version: 1\nrules:\n  - {id: a, match: {name: x}, status: fixed}\n",
            "a.yml",
        )
        .unwrap();
        let second = parse_rules(
            "version: 1\nrules:\n  - {id: a, match: {name: y}, status: fixed}\n",
            "b.yml",
        )
        .unwrap();
        let e = first.extend_checked(second, "b.yml").unwrap_err();
        assert_eq!(e.file, "b.yml");
        assert!(e.message.contains("duplicate rule id `a`"), "{e}");
    }

    #[test]
    fn other_checks_located() {
        let e = err(&one_rule(
            "match: {name: x}\nwhen:\n  - kconfig_off: \"CONFIG A\"\nstatus: fixed\n",
        ));
        assert_eq!(e.line, Some(6), "{e}");
        let e = err(&one_rule(
            "match: {name: x}\nwhen:\n  - {kconfig_off: A, cargo_feature_off: b}\nstatus: fixed\n",
        ));
        assert_eq!(e.line, Some(6), "{e}");
        assert!(e.message.contains("exactly one key"), "{e}");
        let e = err(&one_rule("match: {name: x, cves: []}\nstatus: fixed\n"));
        assert!(e.message.contains("match.cves is empty"), "{e}");
        let e = err("version: 2\nrules: []\n");
        assert_eq!(e.line, Some(1), "{e}");
        assert!(e.message.contains("unsupported rules version 2"), "{e}");
        let e = err(
            "version: 1\nrules:\n  - id: \"bad id\"\n    match: {name: x}\n    status: fixed\n",
        );
        assert_eq!(e.line, Some(3), "{e}");
        assert!(
            parse_rules("version: 1\n", "r.yml")
                .unwrap()
                .rules
                .is_empty()
        );
    }

    #[test]
    fn kconfig_equals_values_are_kept_as_written() {
        for (written, kept) in [
            ("0x10", "0x10"),
            ("\"0x10\"", "0x10"),
            ("4", "4"),
            ("y", "y"),
            ("true", "true"),
            ("~", "~"),
            ("config-mbedtls.h", "config-mbedtls.h"),
        ] {
            let set = parse_rules(
                &one_rule(&format!(
                    "match: {{name: x}}\nwhen:\n  - kconfig_equals: {{CONFIG_A: {written}}}\nstatus: fixed\n"
                )),
                "r.yml",
            )
            .unwrap_or_else(|e| panic!("{written}: {e}"));
            assert_eq!(
                set.rules[0].when,
                [Condition::KconfigEquals(
                    "CONFIG_A".to_owned(),
                    kept.to_owned()
                )],
                "{written}"
            );
        }
    }

    #[test]
    fn kconfig_equals_parses_and_rejects_bad_forms() {
        let set = parse_rules(
            &one_rule(
                "match: {name: x}\nwhen:\n  - kconfig_equals: {CONFIG_MBEDTLS_CFG_FILE: config-mbedtls.h}\n  - kconfig_equals: {CONFIG_N: \"4\"}\nstatus: fixed\n",
            ),
            "r.yml",
        )
        .unwrap();
        assert_eq!(
            set.rules[0].when,
            [
                Condition::KconfigEquals(
                    "CONFIG_MBEDTLS_CFG_FILE".to_owned(),
                    "config-mbedtls.h".to_owned()
                ),
                Condition::KconfigEquals("CONFIG_N".to_owned(), "4".to_owned()),
            ]
        );
        assert_eq!(
            set.rules[0].when[0].to_string(),
            "kconfig_equals: CONFIG_MBEDTLS_CFG_FILE=\"config-mbedtls.h\""
        );
        for (body, message) in [
            ("kconfig_equals: CONFIG_A", "expected a map"),
            ("kconfig_equals: {}", "one `CONFIG_X: value` mapping"),
            (
                "kconfig_equals: {CONFIG_A: y, CONFIG_B: n}",
                "one `CONFIG_X: value` mapping",
            ),
            (
                "kconfig_equals: {CONFIG_A: y, CONFIG_A: n}",
                "duplicate key CONFIG_A",
            ),
            ("kconfig_equals: {1: y}", "is not a Kconfig symbol"),
            ("kconfig_off: 1CONFIG_A", "is not a Kconfig symbol"),
            (
                "kconfig_equals: {\"CONFIG A\": y}",
                "is not a Kconfig symbol",
            ),
            ("kconfig_equals: {CONFIG_A: [y]}", "expected a string"),
            ("kconfig_equals: {CONFIG_A: \"a\\nb\"}", "spans lines"),
        ] {
            let e = err(&one_rule(&format!(
                "match: {{name: x}}\nwhen:\n  - {body}\nstatus: fixed\n"
            )));
            assert_eq!(e.line, Some(6), "{body}: {e}");
            assert!(e.message.contains(message), "{body}: {e}");
        }
    }

    #[test]
    fn empty_truncated_wrong_type_never_panic() {
        for text in [
            "",
            "   \n# only a comment\n",
            "version: 1\nrules:\n  - id: a\n    match: {name: x",
            "version: 1\nrules: 5\n",
            "version: one\n",
            "- 1\n- 2\n",
            "rules: []\n",
            "version: 1\nrules:\n  - 7\n",
            "version: 1\nrules:\n  - id: [1]\n",
            "version: 1\nrules:\n  - id: a\n    match: {name: x}\n    status: [affected]\n",
            "version: 1\nrules:\n  - id: a\n    match: {name: x}\n    when: kconfig_off\n    status: affected\n",
            "version: 1\nrules:\n  - id: a\n    match: {name: x}\n    when: [{}]\n    status: affected\n",
            "\t\u{0}",
        ] {
            assert!(parse_rules(text, "r.yml").is_err(), "accepted {text:?}");
        }
        let e = parse_rules_bytes(b"version: 1\nrules: [\xff]\n", "r.yml").unwrap_err();
        assert!(e.message.contains("UTF-8"), "{e}");
    }

    #[test]
    fn status_maps_to_cyclonedx_state() {
        assert_eq!(Status::NotAffected.cyclonedx_state(), "not_affected");
        assert_eq!(Status::Affected.cyclonedx_state(), "exploitable");
        assert_eq!(Status::Fixed.cyclonedx_state(), "resolved");
        assert_eq!(Status::UnderInvestigation.cyclonedx_state(), "in_triage");
        for s in [
            Status::NotAffected,
            Status::Affected,
            Status::Fixed,
            Status::UnderInvestigation,
        ] {
            assert_eq!(s.openvex(), s.as_str());
        }
    }

    #[test]
    fn justification_both_vocabularies_map() {
        let cases = [
            (
                "code_not_present",
                "code_not_present",
                "vulnerable_code_not_present",
            ),
            (
                "component_not_present",
                "code_not_present",
                "component_not_present",
            ),
            (
                "vulnerable_code_not_present",
                "code_not_present",
                "vulnerable_code_not_present",
            ),
            (
                "code_not_reachable",
                "code_not_reachable",
                "vulnerable_code_not_in_execute_path",
            ),
            (
                "vulnerable_code_not_in_execute_path",
                "code_not_reachable",
                "vulnerable_code_not_in_execute_path",
            ),
            (
                "requires_configuration",
                "requires_configuration",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "requires_dependency",
                "requires_dependency",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "requires_environment",
                "requires_environment",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "vulnerable_code_cannot_be_controlled_by_adversary",
                "requires_environment",
                "vulnerable_code_cannot_be_controlled_by_adversary",
            ),
            (
                "protected_by_compiler",
                "protected_by_compiler",
                "inline_mitigations_already_exist",
            ),
            (
                "protected_at_runtime",
                "protected_at_runtime",
                "inline_mitigations_already_exist",
            ),
            (
                "protected_at_perimeter",
                "protected_at_perimeter",
                "inline_mitigations_already_exist",
            ),
            (
                "protected_by_mitigating_control",
                "protected_by_mitigating_control",
                "inline_mitigations_already_exist",
            ),
            (
                "inline_mitigations_already_exist",
                "protected_by_mitigating_control",
                "inline_mitigations_already_exist",
            ),
        ];
        for (word, cdx, openvex) in cases {
            let set = parse_rules(
                &one_rule(&format!(
                    "match: {{name: x}}\nstatus: not_affected\njustification: {word}\n"
                )),
                "r.yml",
            )
            .unwrap();
            let j = set.rules[0].justification.unwrap();
            assert_eq!(j.as_str(), word);
            assert_eq!(j.to_string(), word);
            assert_eq!((j.cyclonedx(), j.openvex()), (cdx, openvex), "{word}");
        }
    }

    #[test]
    fn component_not_present_round_trips_to_openvex() {
        let set = parse_rules(
            &one_rule(
                "match: {name: x}\nstatus: not_affected\njustification: component_not_present\n",
            ),
            "r.yml",
        )
        .unwrap();
        let j = set.rules[0].justification.unwrap();
        assert_eq!(j, Justification::ComponentNotPresent);
        assert_eq!(j.openvex(), "component_not_present");
        assert_eq!(j.cyclonedx(), "code_not_present");
        assert_eq!(
            serde_json::to_string(&j).unwrap(),
            "\"component_not_present\""
        );
        assert!(Justification::CodeNotPresent.agrees_with(Justification::VulnerableCodeNotPresent));
        assert!(!j.agrees_with(Justification::VulnerableCodeNotPresent));
    }

    #[test]
    fn unknown_subsystem_rejected_at_its_rule() {
        // A misspelt name (underscore for hyphen) would never match: rejected, at the rule.
        let e = err(&one_rule(
            "match: {subsystem: bluetooth_host}\nstatus: affected\n",
        ));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(
            e.message.contains(
                "match.subsystem \"bluetooth_host\" is not a subsystem in subsystems.yaml"
            ),
            "{e}"
        );
        assert!(e.message.contains("bluetooth-host"), "{e}");
        // Every table name is accepted.
        for s in crate::subsystems::builtin().unwrap().subsystems {
            let text = one_rule(&format!(
                "match: {{subsystem: {}}}\nstatus: affected\n",
                s.name
            ));
            assert!(parse_rules(&text, "rules.yml").is_ok(), "{}", s.name);
        }
    }

    #[test]
    fn padded_names_rejected() {
        let e = err(&one_rule("match: {name: \" mbedtls\"}\nstatus: affected\n"));
        assert_eq!(e.line, Some(3), "{e}");
        assert!(e.message.contains("leading or trailing whitespace"), "{e}");
        let e = err(&one_rule(
            "match: {subsystem: \"net \"}\nstatus: affected\n",
        ));
        assert!(e.message.contains("match.subsystem"), "{e}");
    }

    #[test]
    fn template_round_trips() {
        for (purl, name) in [
            (Some("pkg:github/mbed-tls/mbedtls@v2.28.0"), "mbedtls"),
            (None, "weird name: with colon"),
        ] {
            for in_sbom in [true, false] {
                let t = template("CVE-2022-35409", name, purl, "component:abc", in_sbom);
                assert_eq!(t.starts_with("# "), !in_sbom, "{t}");
                let set = parse_rules(&format!("version: 1\nrules:\n{t}"), "t.yml")
                    .unwrap_or_else(|e| panic!("{e}\n{t}"));
                let r = &set.rules[0];
                assert_eq!(r.status, Status::UnderInvestigation);
                assert!(r.id.starts_with("todo-cve-2022-35409-"), "{}", r.id);
                assert!(r.target.cves.contains("CVE-2022-35409"));
            }
        }
        let note = template("CVE-1", "evil\nname", None, "evil", false);
        assert!(note.lines().take(2).all(|l| l.starts_with('#')), "{note}");
    }

    #[test]
    fn template_ids_differ_by_target() {
        let id = |target: &str| {
            let t = template("CVE-1", "mbedtls", None, target, true);
            parse_rules(&format!("version: 1\nrules:\n{t}"), "t.yml")
                .unwrap()
                .rules[0]
                .id
                .clone()
        };
        let boot = id("component:00000000000000000000000000000001");
        let app = id("component:00000000000000000000000000000002");
        assert_ne!(boot, app);
        assert!(
            boot.starts_with("todo-cve-1-mbedtls-")
                && boot.len() == "todo-cve-1-mbedtls-".len() + 8,
            "{boot}"
        );
        assert_eq!(boot, id("component:00000000000000000000000000000001"));
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
            let _ = parse_rules(&text, "r.yml");
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = parse_rules_bytes(&bytes, "r.yml");
        }
    }
}
