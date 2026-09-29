//! Evidence: where each fact about a node came from, and how sure we are of it.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::confidence::Confidence;
use super::ids::IdError;

/// Which fact about a node a piece of evidence supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceField {
    /// The node's name.
    Name,
    /// The node's version.
    Version,
    /// The node's package URL.
    Purl,
    /// The node's CPE.
    Cpe,
    /// One of the node's hashes.
    Hash,
    /// The node's licence expression.
    Licence,
    /// The node's supplier.
    Supplier,
}

/// How a fact was established, as the CycloneDX 1.6 identity-evidence `technique`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Technique {
    /// Reading source code.
    SourceCodeAnalysis,
    /// Inspecting a compiled binary.
    BinaryAnalysis,
    /// Reading a manifest or build metadata file (e.g. `west.yml`, an SPDX document).
    ManifestAnalysis,
    /// Matching an abstract-syntax-tree fingerprint.
    AstFingerprint,
    /// Comparing a file hash against a known value.
    HashComparison,
    /// Instrumenting a running system.
    Instrumentation,
    /// Observing a running system.
    DynamicAnalysis,
    /// Inferring from a file name.
    Filename,
    /// A signed or otherwise trusted statement.
    Attestation,
    /// Any other technique.
    Other,
}

/// Where in a source a fact was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawOccurrence")]
pub struct Occurrence {
    /// A non-empty, forward-slash, relative path (never absolute, never containing `\`), so
    /// output does not depend on the build machine.
    location: String,
    /// The 1-based line number within `location`, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOccurrence {
    location: String,
    #[serde(default)]
    line: Option<u32>,
}

impl Occurrence {
    /// Builds an occurrence. `location` must be a non-empty, forward-slash, relative path.
    pub fn new(location: &str, line: Option<u32>) -> Result<Self, IdError> {
        let err = |reason| IdError::Location {
            input: location.to_owned(),
            reason,
        };
        if location.is_empty() {
            return Err(err("empty"));
        }
        if location.starts_with('/') {
            return Err(err("absolute path"));
        }
        if location.contains('\\') {
            return Err(err("backslash; use forward slashes"));
        }
        if location.chars().any(char::is_control) {
            return Err(err("control character"));
        }
        let bytes = location.as_bytes();
        if bytes.len() >= 2
            && bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.get(1) == Some(&b':')
        {
            return Err(err("drive-letter path"));
        }
        Ok(Self {
            location: location.to_owned(),
            line,
        })
    }

    /// The relative path.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The 1-based line number, if known.
    pub fn line(&self) -> Option<u32> {
        self.line
    }
}

impl TryFrom<RawOccurrence> for Occurrence {
    type Error = IdError;
    fn try_from(raw: RawOccurrence) -> Result<Self, Self::Error> {
        Self::new(&raw.location, raw.line)
    }
}

impl fmt::Display for Occurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}", self.location),
            None => f.write_str(&self.location),
        }
    }
}

/// One observation of one fact about a node.
///
/// The field order drives the derived ordering: by fact, then technique, source, occurrence,
/// value and finally confidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawEvidence")]
pub struct Evidence {
    /// Which fact this supports.
    pub field: EvidenceField,
    /// How the fact was established.
    pub technique: Technique,
    /// The input that produced it, e.g. `west-spdx` or `mcuboot-sysbuild`. Never empty.
    source: String,
    /// Where in that input it was found, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<Occurrence>,
    /// The value observed, as text (e.g. the version string or licence expression seen).
    pub value: String,
    /// How sure the source is of this value.
    pub confidence: Confidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    field: EvidenceField,
    technique: Technique,
    source: String,
    #[serde(default)]
    occurrence: Option<Occurrence>,
    value: String,
    confidence: Confidence,
}

/// The identity of an evidence entry: every field except confidence.
pub type EvidenceKey<'a> = (
    EvidenceField,
    Technique,
    &'a str,
    Option<&'a Occurrence>,
    &'a str,
);

impl Evidence {
    /// Builds an evidence entry with no occurrence. `source` must be non-empty.
    pub fn new(
        field: EvidenceField,
        technique: Technique,
        source: &str,
        value: &str,
        confidence: Confidence,
    ) -> Result<Self, IdError> {
        if source.is_empty() {
            return Err(IdError::Empty {
                what: "evidence source",
            });
        }
        Ok(Self {
            field,
            technique,
            source: source.to_owned(),
            occurrence: None,
            value: value.to_owned(),
            confidence,
        })
    }

    /// Sets the occurrence and returns the entry.
    pub fn at(mut self, occurrence: Occurrence) -> Self {
        self.occurrence = Some(occurrence);
        self
    }

    /// The input that produced this evidence.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Every field except confidence. Two entries with the same key are the same observation;
    /// an [`EvidenceSet`] keeps only the more confident of them.
    pub fn key(&self) -> EvidenceKey<'_> {
        (
            self.field,
            self.technique,
            &self.source,
            self.occurrence.as_ref(),
            &self.value,
        )
    }
}

impl TryFrom<RawEvidence> for Evidence {
    type Error = IdError;
    fn try_from(raw: RawEvidence) -> Result<Self, Self::Error> {
        let mut evidence = Self::new(
            raw.field,
            raw.technique,
            &raw.source,
            &raw.value,
            raw.confidence,
        )?;
        evidence.occurrence = raw.occurrence;
        Ok(evidence)
    }
}

/// A sorted set of evidence with at most one entry per [`Evidence::key`].
///
/// Serialises as a sorted JSON array. Deserialising rejects two entries with the same key, so
/// the stored form is always the normalised one.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EvidenceSet(BTreeSet<Evidence>);

impl EvidenceSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry. If an entry with the same key exists, the one with the higher
    /// confidence is kept (the combination rule is maximum).
    pub fn insert(&mut self, evidence: Evidence) {
        let existing = self.0.iter().find(|e| e.key() == evidence.key()).cloned();
        match existing {
            Some(old) if old.confidence >= evidence.confidence => {}
            Some(old) => {
                self.0.remove(&old);
                self.0.insert(evidence);
            }
            None => {
                self.0.insert(evidence);
            }
        }
    }

    /// Adds every entry of `other` with [`EvidenceSet::insert`].
    pub fn extend(&mut self, other: EvidenceSet) {
        for evidence in other.0 {
            self.insert(evidence);
        }
    }

    /// The entries, in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &Evidence> {
        self.0.iter()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The highest confidence of any entry, or [`Confidence::NONE`] if empty.
    pub fn max_confidence(&self) -> Confidence {
        self.0
            .iter()
            .map(|e| e.confidence)
            .max()
            .unwrap_or(Confidence::NONE)
    }

    /// The highest confidence of any entry for `field`, or [`Confidence::NONE`] if none.
    pub fn confidence_for(&self, field: EvidenceField) -> Confidence {
        self.0
            .iter()
            .filter(|e| e.field == field)
            .map(|e| e.confidence)
            .max()
            .unwrap_or(Confidence::NONE)
    }
}

impl FromIterator<Evidence> for EvidenceSet {
    fn from_iter<I: IntoIterator<Item = Evidence>>(iter: I) -> Self {
        let mut set = Self::new();
        for evidence in iter {
            set.insert(evidence);
        }
        set
    }
}

impl<'de> Deserialize<'de> for EvidenceSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = Vec::<Evidence>::deserialize(deserializer)?;
        let mut set = BTreeSet::new();
        for evidence in entries {
            if set.iter().any(|e: &Evidence| e.key() == evidence.key()) {
                return Err(serde::de::Error::custom(
                    "duplicate evidence entry (same field, technique, source, occurrence and value)",
                ));
            }
            set.insert(evidence);
        }
        Ok(Self(set))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(source: &str, value: &str, bp: u16) -> Evidence {
        Evidence::new(
            EvidenceField::Version,
            Technique::ManifestAnalysis,
            source,
            value,
            Confidence::new(bp).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn evidence_is_sorted_and_deduplicated() {
        let mut set = EvidenceSet::new();
        set.insert(ev("west-spdx", "3.7.0", 5000));
        set.insert(ev("cmake-cache", "3.7.0", 9000));
        set.insert(ev("west-spdx", "3.7.0", 8000)); // same key, higher: replaces
        set.insert(ev("west-spdx", "3.7.0", 1000)); // same key, lower: ignored
        set.insert(ev("cmake-cache", "3.7.0", 9000)); // exact duplicate
        let got: Vec<(&str, u16)> = set
            .iter()
            .map(|e| (e.source(), e.confidence.basis_points()))
            .collect();
        assert_eq!(got, vec![("cmake-cache", 9000), ("west-spdx", 8000)]);

        let json = serde_json::to_string(&set).unwrap();
        assert!(json.starts_with('['));
        let back: EvidenceSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn duplicate_key_in_json_is_rejected() {
        let one = serde_json::to_value(ev("s", "v", 1)).unwrap();
        let two = serde_json::to_value(ev("s", "v", 2)).unwrap();
        let json = serde_json::Value::Array(vec![one, two]).to_string();
        assert!(serde_json::from_str::<EvidenceSet>(&json).is_err());
    }

    #[test]
    fn occurrence_rules() {
        assert!(Occurrence::new("zephyr/CMakeLists.txt", Some(3)).is_ok());
        assert!(Occurrence::new("", None).is_err());
        assert!(Occurrence::new("/abs/path", None).is_err());
        assert!(Occurrence::new("a\\b", None).is_err());
        assert!(Occurrence::new("C:/x", None).is_err());
        assert!(
            Evidence::new(
                EvidenceField::Name,
                Technique::Other,
                "",
                "x",
                Confidence::FULL
            )
            .is_err()
        );
    }

    #[test]
    fn confidence_queries() {
        let mut set = EvidenceSet::new();
        assert_eq!(set.max_confidence(), Confidence::NONE);
        set.insert(ev("a", "1", 4000));
        set.insert(
            Evidence::new(
                EvidenceField::Licence,
                Technique::SourceCodeAnalysis,
                "a",
                "MIT",
                Confidence::new(9000).unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(set.max_confidence().basis_points(), 9000);
        assert_eq!(
            set.confidence_for(EvidenceField::Version).basis_points(),
            4000
        );
        assert_eq!(set.confidence_for(EvidenceField::Cpe), Confidence::NONE);
    }
}
