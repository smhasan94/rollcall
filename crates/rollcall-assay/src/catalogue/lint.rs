//! Lint rules for an algorithm catalogue. See the [module docs](super#lint-rules).

use std::collections::BTreeMap;
use std::fmt;

use super::raw::{self, RawAlgorithm, RawCatalogue};
use super::{CatalogueError, FORMAT, Located, QuantumRisk};
use rollcall_core::model::Primitive;

/// One problem with a catalogue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file, as the caller named it.
    pub file: String,
    /// The 1-based line (of the entry, or of a parse error), when known.
    pub line: Option<u32>,
    /// The entry it is about (`None` for the file itself).
    pub algorithm: Option<String>,
    /// The rule broken.
    pub rule: Rule,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Finding {
    /// `file:line: algorithm: message [rule]`, leaving out what is unknown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", Located(&self.file, self.line, None))?;
        if let Some(algorithm) = &self.algorithm {
            write!(f, "{algorithm}: ")?;
        }
        write!(f, "{} [{}]", self.message, self.rule)
    }
}

/// A lint rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// The file does not parse into the schema (malformed YAML, a missing required field, an
    /// unknown key, a value of the wrong type or not one of the allowed words, or empty), or an
    /// `oid` is not dotted decimal.
    Schema,
    /// `format` is not [`FORMAT`].
    Format,
    /// A name is not `[A-Za-z0-9][A-Za-z0-9+/.-]*`, or a `family`, parameter-set `id` or `curve`
    /// is empty.
    Name,
    /// Entries are not in name order (ASCII, ignoring case), or `crypto_functions` are not in
    /// ASCII order.
    Unsorted,
    /// Two entries have the same name (ignoring case), or an entry lists a crypto function twice.
    Duplicate,
    /// An entry has two parameter sets with the same id.
    DuplicateParameterSet,
    /// An entry has no parameter sets.
    EmptyParameterSets,
    /// A `shor-broken` entry has a parameter set above NIST level 0, or a `pq-safe` entry one at
    /// level 0.
    QuantumConsistency,
    /// `padding` on a primitive other than `signature` or `pke`.
    Padding,
    /// `standards` is empty or holds an empty string, or a parameter set's `source` is empty.
    Source,
}

impl Rule {
    /// Every rule.
    pub const ALL: [Rule; 10] = [
        Rule::Schema,
        Rule::Format,
        Rule::Name,
        Rule::Unsorted,
        Rule::Duplicate,
        Rule::DuplicateParameterSet,
        Rule::EmptyParameterSets,
        Rule::QuantumConsistency,
        Rule::Padding,
        Rule::Source,
    ];

    /// The rule's name, as shown in findings.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::Format => "format",
            Self::Name => "name",
            Self::Unsorted => "unsorted",
            Self::Duplicate => "duplicate",
            Self::DuplicateParameterSet => "duplicate-parameter-set",
            Self::EmptyParameterSets => "empty-parameter-sets",
            Self::QuantumConsistency => "quantum-consistency",
            Self::Padding => "padding",
            Self::Source => "source",
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lints catalogue text, cited as `name`, and returns every finding, sorted (empty when the
/// catalogue is clean). A file that does not parse into the schema is one [`Rule::Schema`]
/// finding carrying the parser's message and line, e.g. ``missing field `quantum_risk` ``.
pub fn lint_text(name: &str, text: &str) -> Vec<Finding> {
    match raw::parse(name, text) {
        Ok((raw, lines)) => lint_raw(name, &raw, &lines),
        Err(error) => {
            let (line, message) = match error {
                CatalogueError::Yaml { line, message, .. } => (line, message),
                CatalogueError::Empty { .. } => (None, "empty algorithm catalogue".to_owned()),
                other => (None, other.to_string()),
            };
            vec![Finding {
                file: name.to_owned(),
                line,
                algorithm: None,
                rule: Rule::Schema,
                message,
            }]
        }
    }
}

/// `[A-Za-z0-9][A-Za-z0-9+/.-]*`.
fn well_formed_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '.' | '-'))
}

/// `[0-2](\.(0|[1-9][0-9]*))+`.
fn dotted_decimal(oid: &str) -> bool {
    let mut arcs = oid.split('.');
    let first_ok = arcs.next().is_some_and(|a| matches!(a, "0" | "1" | "2"));
    let mut rest = 0usize;
    let rest_ok = arcs.all(|arc| {
        rest += 1;
        !arc.is_empty()
            && arc.bytes().all(|b| b.is_ascii_digit())
            && !(arc.len() > 1 && arc.starts_with('0'))
    });
    first_ok && rest > 0 && rest_ok
}

/// The structural rules, on a parsed catalogue whose entries start at `lines`.
pub(crate) fn lint_raw(file: &str, raw: &RawCatalogue, lines: &[Option<u32>]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut push = |line: Option<u32>, algorithm: Option<&str>, rule: Rule, message: String| {
        findings.push(Finding {
            file: file.to_owned(),
            line,
            algorithm: algorithm.map(str::to_owned),
            rule,
            message,
        });
    };
    if raw.format != FORMAT {
        push(
            None,
            None,
            Rule::Format,
            format!("format {:?} is not {FORMAT:?}", raw.format),
        );
    }
    let mut seen: BTreeMap<String, (usize, Option<u32>)> = BTreeMap::new();
    let mut previous: Option<&RawAlgorithm> = None;
    for (i, entry) in raw.algorithms.iter().enumerate() {
        let line = lines.get(i).copied().flatten();
        let name = Some(entry.name.as_str());
        let key = entry.name.to_ascii_lowercase();
        if !well_formed_name(&entry.name) {
            push(
                line,
                name,
                Rule::Name,
                format!("name {:?} is not [A-Za-z0-9][A-Za-z0-9+/.-]*", entry.name),
            );
        }
        match seen.get(&key) {
            Some(&(_, first_line)) => {
                let at = first_line.map_or_else(String::new, |l| format!(" (line {l})"));
                push(
                    line,
                    name,
                    Rule::Duplicate,
                    format!("name {:?} is already used{at}, ignoring case", entry.name),
                );
            }
            None => {
                seen.insert(key.clone(), (i, line));
            }
        }
        if let Some(prev) = previous
            && prev.name.to_ascii_lowercase() > key
        {
            push(
                line,
                name,
                Rule::Unsorted,
                format!(
                    "{:?} is out of order: it sorts before {:?} (ASCII, ignoring case)",
                    entry.name, prev.name
                ),
            );
        }
        previous = Some(entry);
        if entry.family.trim().is_empty() {
            push(line, name, Rule::Name, "family is empty".to_owned());
        }
        let words: Vec<&str> = entry.crypto_functions.iter().map(|f| f.as_str()).collect();
        for pair in words.windows(2) {
            if let [a, b] = pair {
                if a == b {
                    push(
                        line,
                        name,
                        Rule::Duplicate,
                        format!("crypto function {a} is listed twice"),
                    );
                } else if a > b {
                    push(
                        line,
                        name,
                        Rule::Unsorted,
                        format!("crypto_functions are not in ASCII order: {a} before {b}"),
                    );
                }
            }
        }
        if let Some(padding) = entry.padding
            && !matches!(entry.primitive, Primitive::Signature | Primitive::Pke)
        {
            push(
                line,
                name,
                Rule::Padding,
                format!(
                    "padding {padding} on primitive {}; only signature and pke take a padding",
                    entry.primitive
                ),
            );
        }
        if entry.standards.is_empty() {
            push(line, name, Rule::Source, "standards is empty".to_owned());
        }
        if entry.standards.iter().any(|s| s.trim().is_empty()) {
            push(
                line,
                name,
                Rule::Source,
                "standards holds an empty string".to_owned(),
            );
        }
        if entry.parameter_sets.is_empty() {
            push(
                line,
                name,
                Rule::EmptyParameterSets,
                "no parameter sets".to_owned(),
            );
        }
        let mut ids: BTreeMap<&str, ()> = BTreeMap::new();
        for set in &entry.parameter_sets {
            let id = set.id.as_str();
            if id.trim().is_empty() {
                push(
                    line,
                    name,
                    Rule::Name,
                    "a parameter-set id is empty".to_owned(),
                );
            }
            if ids.insert(id, ()).is_some() {
                push(
                    line,
                    name,
                    Rule::DuplicateParameterSet,
                    format!("parameter set {id:?} is listed twice"),
                );
            }
            let level = set.nist_quantum_security_level.get();
            match entry.quantum_risk {
                QuantumRisk::ShorBroken if level != 0 => push(
                    line,
                    name,
                    Rule::QuantumConsistency,
                    format!(
                        "parameter set {id:?}: shor-broken but nist_quantum_security_level {level}; \
                         Shor's algorithm leaves no quantum security (0)"
                    ),
                ),
                QuantumRisk::PqSafe if level == 0 => push(
                    line,
                    name,
                    Rule::QuantumConsistency,
                    format!(
                        "parameter set {id:?}: pq-safe but nist_quantum_security_level 0; \
                         a pq-safe set is in category 1 or above"
                    ),
                ),
                _ => {}
            }
            if set.curve.as_deref().is_some_and(|c| c.trim().is_empty()) {
                push(
                    line,
                    name,
                    Rule::Name,
                    format!("parameter set {id:?}: curve is empty"),
                );
            }
            if let Some(oid) = set.oid.as_deref()
                && !dotted_decimal(oid)
            {
                push(
                    line,
                    name,
                    Rule::Schema,
                    format!("parameter set {id:?}: oid {oid:?} is not dotted decimal"),
                );
            }
            if set.source.trim().is_empty() {
                push(
                    line,
                    name,
                    Rule::Source,
                    format!("parameter set {id:?}: source is empty"),
                );
            }
        }
    }
    findings.sort();
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean two-entry catalogue.
    const CLEAN: &str = "\
format: rollcall-algorithms/1
algorithms:
  - name: AES-GCM
    family: AES
    primitive: ae
    mode: gcm
    crypto_functions: [decrypt, encrypt, tag]
    quantum_risk: grover-weakened
    standards: [FIPS 197]
    parameter_sets:
      - id: \"128\"
        classical_security_level: 128
        nist_quantum_security_level: 1
        oid: 2.16.840.1.101.3.4.1.6
        source: \"SP 800-57\"
  - name: RSA-PSS
    family: RSA
    primitive: signature
    padding: pss
    quantum_risk: shor-broken
    standards: [FIPS 186-5]
    parameter_sets:
      - id: \"2048\"
        classical_security_level: 112
        nist_quantum_security_level: 0
        source: \"SP 800-57\"
";

    fn rules(text: &str) -> Vec<Rule> {
        let mut rules: Vec<Rule> = lint_text("t.yaml", text).iter().map(|f| f.rule).collect();
        rules.dedup();
        rules
    }

    #[test]
    fn clean_catalogue_has_no_findings() {
        assert_eq!(lint_text("t.yaml", CLEAN), Vec::new());
    }

    #[test]
    fn each_rule_fires_on_its_bad_input() {
        let cases: &[(Rule, &str, &str)] = &[
            (Rule::Schema, "quantum_risk: grover-weakened\n", ""),
            (Rule::Schema, "oid: 2.16.840.1.101.3.4.1.6", "oid: 2.16..1"),
            (Rule::Schema, "oid: 2.16.840.1.101.3.4.1.6", "oid: 3.1"),
            (Rule::Schema, "oid: 2.16.840.1.101.3.4.1.6", "oid: 2.016"),
            (
                Rule::Format,
                "format: rollcall-algorithms/1",
                "format: rollcall-algorithms/2",
            ),
            (Rule::Name, "name: AES-GCM", "name: AES GCM"),
            (Rule::Name, "name: AES-GCM", "name: -AES"),
            (Rule::Name, "family: AES", "family: \"\""),
            (Rule::Name, "id: \"128\"", "id: \" \""),
            (
                Rule::Name,
                "oid: 2.16.840.1.101.3.4.1.6",
                "oid: 2.16.840.1.101.3.4.1.6\n        curve: \"\"",
            ),
            (Rule::Unsorted, "name: RSA-PSS", "name: AAA"),
            (
                Rule::Unsorted,
                "[decrypt, encrypt, tag]",
                "[encrypt, decrypt, tag]",
            ),
            (Rule::Duplicate, "name: RSA-PSS", "name: aes-gcm"),
            (
                Rule::Duplicate,
                "[decrypt, encrypt, tag]",
                "[decrypt, decrypt]",
            ),
            (
                Rule::QuantumConsistency,
                "nist_quantum_security_level: 0",
                "nist_quantum_security_level: 1",
            ),
            (
                Rule::QuantumConsistency,
                "quantum_risk: grover-weakened",
                "quantum_risk: shor-broken",
            ),
            (Rule::Padding, "mode: gcm", "mode: gcm\n    padding: oaep"),
            (Rule::Source, "standards: [FIPS 197]", "standards: []"),
            (Rule::Source, "standards: [FIPS 197]", "standards: [\"\"]"),
            (
                Rule::Source,
                "source: \"SP 800-57\"\n  - name",
                "source: \"\"\n  - name",
            ),
        ];
        for (rule, from, to) in cases {
            assert!(CLEAN.contains(from), "{from:?} not in the clean catalogue");
            let text = CLEAN.replacen(from, to, 1);
            assert_eq!(rules(&text), vec![*rule], "{rule}: {text}");
        }
        // pq-safe with a level-0 set.
        let text = CLEAN.replacen("quantum_risk: shor-broken", "quantum_risk: pq-safe", 1);
        assert_eq!(rules(&text), vec![Rule::QuantumConsistency]);
        // Two parameter sets with the same id.
        let text = CLEAN.replacen(
            "        source: \"SP 800-57\"\n  - name",
            "        source: \"SP 800-57\"\n      - id: \"128\"\n        \
             classical_security_level: 128\n        nist_quantum_security_level: 1\n        \
             source: \"x\"\n  - name",
            1,
        );
        assert_eq!(rules(&text), vec![Rule::DuplicateParameterSet]);
        // No parameter sets.
        let end = CLEAN.find("  - name: RSA-PSS").unwrap();
        let start = CLEAN.find("      - id: \"128\"").unwrap();
        let text = format!(
            "{}{}",
            CLEAN[..start].replace("parameter_sets:\n", "parameter_sets: []\n"),
            &CLEAN[end..]
        );
        assert_eq!(rules(&text), vec![Rule::EmptyParameterSets]);
        // Every rule has a case.
        let mut covered: Vec<Rule> = cases.iter().map(|(r, _, _)| *r).collect();
        covered.extend([Rule::DuplicateParameterSet, Rule::EmptyParameterSets]);
        for rule in Rule::ALL {
            assert!(covered.contains(&rule), "no case for {rule}");
        }
    }

    #[test]
    fn findings_are_sorted_and_name_file_line_and_entry() {
        let text = CLEAN.replacen("name: RSA-PSS", "name: AAA", 1).replacen(
            "family: AES",
            "family: \"\"",
            1,
        );
        let findings = lint_text("t.yaml", &text);
        assert_eq!(
            findings.iter().map(ToString::to_string).collect::<Vec<_>>(),
            vec![
                "t.yaml:3: AES-GCM: family is empty [name]".to_owned(),
                "t.yaml:16: AAA: \"AAA\" is out of order: it sorts before \"AES-GCM\" (ASCII, \
                 ignoring case) [unsorted]"
                    .to_owned(),
            ]
        );
        let mut sorted = findings.clone();
        sorted.sort();
        assert_eq!(sorted, findings);
    }

    #[test]
    fn dotted_decimal_accepts_only_oids() {
        for ok in ["1.3.101.112", "2.16.840.1.101.3.4.1.6", "0.0"] {
            assert!(dotted_decimal(ok), "{ok}");
        }
        for bad in [
            "", "1", "3.1", "1.", ".1", "1..2", "1.02", "1.a", "1.3 ", "１.2",
        ] {
            assert!(!dotted_decimal(bad), "{bad}");
        }
    }
}
