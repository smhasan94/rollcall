//! The algorithm catalogue: what rollcall knows about each cryptographic algorithm it reports,
//! and the CycloneDX `algorithmProperties` a detector puts on a crypto asset.
//!
//! The catalogue is data, not code: `db/algorithms.yaml` in this crate, embedded at build time
//! ([`ALGORITHMS_YAML`]) and loaded by [`Catalogue::builtin`]. It is rollcall's single source of
//! truth; cbom-infra keeps a copy and checks it with `scripts/check-catalogue-sync.sh` (see
//! [Export contract](#export-contract)). `docs/catalogue.md` explains the risk classes and
//! where every number comes from.
//!
//! # Schema
//!
//! ```yaml
//! format: rollcall-algorithms/1
//! algorithms:                    # a sequence, in name order (ASCII, ignoring case)
//!   - name: AES-GCM              # the lookup key; one entry per family, primitive and mode
//!                                # or padding; [A-Za-z0-9][A-Za-z0-9+/.-]*, unique ignoring case
//!     family: AES
//!     primitive: ae              # a CycloneDX 1.6 primitive word
//!     mode: gcm                  # optional: a CycloneDX 1.6 mode word
//!     padding: null              # optional: oaep | pss | pkcs1v15
//!     crypto_functions: [decrypt, encrypt, tag]  # optional: CycloneDX words, ASCII order
//!     quantum_risk: grover-weakened  # shor-broken | grover-weakened | pq-safe
//!     standards: [FIPS 197, SP 800-38D]  # at least one
//!     parameter_sets:            # at least one; ids unique within the entry
//!       - id: "128"              # the CycloneDX parameterSetIdentifier, always a string
//!         classical_security_level: 128   # bits
//!         nist_quantum_security_level: 1  # the NIST category, 0..=6 (0: none)
//!         curve: null            # optional: the curve, as https://neuromancer.sk/std/ names it
//!         oid: 2.16.840.1.101.3.4.1.6     # optional: dotted decimal
//!         source: "SP 800-57 Pt 1 Rev 5 Table 2; ..."  # where the two levels come from
//! ```
//!
//! Unknown keys are rejected, at the top level, in an entry and in a parameter set. The same
//! shape, as a JSON Schema (draft 2020-12), is `db/algorithms.schema.json`
//! ([`ALGORITHMS_SCHEMA_JSON`]); its `required` lists are exactly the fields this loader
//! requires.
//!
//! # Risk classes
//!
//! Every entry has a [`QuantumRisk`]:
//!
//! - `shor-broken`: a quantum computer running Shor's algorithm recovers the key (RSA, DSA, DH,
//!   ECDSA, ECDH, Ed25519, X25519). No parameter set helps, so every set's NIST level is `0`.
//! - `grover-weakened`: Grover's search (or a quantum collision search) speeds up a brute-force
//!   attack but a larger key or digest restores the margin (AES, ChaCha20-Poly1305, the SHA-2
//!   and SHA-3 families, HMAC, HKDF, PBKDF2). The NIST level depends on the parameter set.
//! - `pq-safe`: designed to resist a quantum computer (ML-KEM, ML-DSA, SLH-DSA, LMS, HSS, XMSS,
//!   XMSS-MT). Every set's NIST level is at least `1`.
//!
//! # Lint rules
//!
//! Loading ([`Catalogue::builtin`], [`Catalogue::load_str`], [`Catalogue::load_path`]) parses
//! the YAML into typed values (so a missing required field, an unknown key, a number where a
//! string belongs or a word that is not a CycloneDX 1.6 word fails), checks the `format`, then
//! runs the structural rules of [`lint`] ([`Rule`]): names well-formed, unique ignoring case and
//! in order; `family` and every parameter-set `id` and `curve` non-empty; at least one parameter
//! set, with unique ids; `shor-broken` entries at NIST level `0` and `pq-safe` entries at `1` or
//! more; `padding` only on a `signature` or `pke` primitive; `standards` and every `source`
//! non-empty; `crypto_functions` in ASCII order without duplicates; every `oid` dotted decimal.
//! Any finding fails the load with [`CatalogueError::Lint`]. [`lint_text`] runs the same checks
//! and returns the findings, a file that does not parse being one `schema` finding.
//!
//! # Determinism
//!
//! The catalogue is a sequence kept in name order (the lint enforces it), and the lookup index is
//! a `BTreeMap`, so [`Catalogue::algorithms`], lint findings and [`compare`] results are always
//! in the same order. Nothing depends on hashing.
//!
//! # Export contract
//!
//! cbom-infra copies `algorithms.yaml` as it is, in the same `rollcall-algorithms/1` format,
//! validated by `algorithms.schema.json`. An entry is *shared* when its name (ignoring case) and
//! parameter-set id are in both files; every field of a shared entry must agree, except the
//! prose `source`. Entries in only one file are reported but are not a disagreement.
//! [`compare`] implements the check; `scripts/check-catalogue-sync.sh THEIRS [OURS]` runs it.

pub mod lint;
mod raw;
pub mod sync;

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use rollcall_core::model::{
    AlgorithmProperties, CryptoFunction, Mode, Primitive, QuantumSecurityLevel,
};
use serde::Deserialize;

pub use lint::{Finding, Rule, lint_text};
pub use sync::{Comparison, Disagreement, compare};

/// The `format` this rollcall reads.
pub const FORMAT: &str = "rollcall-algorithms/1";
/// The name the built-in catalogue is cited by in errors and findings.
pub const FILE_NAME: &str = "algorithms.yaml";
/// Where the built-in catalogue lives, relative to the `rollcall-assay` crate.
pub const PATH: &str = "db/algorithms.yaml";
/// Where its JSON Schema lives, relative to the `rollcall-assay` crate.
pub const SCHEMA_PATH: &str = "db/algorithms.schema.json";
/// The built-in catalogue's text.
pub const ALGORITHMS_YAML: &str = include_str!("../../db/algorithms.yaml");
/// The catalogue's JSON Schema (draft 2020-12): the export contract.
pub const ALGORITHMS_SCHEMA_JSON: &str = include_str!("../../db/algorithms.schema.json");

/// How a quantum computer affects an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum QuantumRisk {
    /// Shor's algorithm breaks it, whatever the parameter set.
    #[serde(rename = "shor-broken")]
    ShorBroken,
    /// Grover's (or a collision) search weakens it; a larger key or digest restores it.
    #[serde(rename = "grover-weakened")]
    GroverWeakened,
    /// Designed to resist a quantum computer.
    #[serde(rename = "pq-safe")]
    PqSafe,
}

impl QuantumRisk {
    /// Every class.
    pub const ALL: &'static [Self] = &[Self::ShorBroken, Self::GroverWeakened, Self::PqSafe];

    /// The word used in the catalogue.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShorBroken => "shor-broken",
            Self::GroverWeakened => "grover-weakened",
            Self::PqSafe => "pq-safe",
        }
    }
}

impl fmt::Display for QuantumRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A padding scheme. Only RSA entries have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum Padding {
    /// RSAES-OAEP.
    #[serde(rename = "oaep")]
    Oaep,
    /// RSASSA-PSS.
    #[serde(rename = "pss")]
    Pss,
    /// PKCS #1 v1.5.
    #[serde(rename = "pkcs1v15")]
    Pkcs1v15,
}

impl Padding {
    /// Every scheme.
    pub const ALL: &'static [Self] = &[Self::Oaep, Self::Pss, Self::Pkcs1v15];

    /// The word used in the catalogue.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oaep => "oaep",
            Self::Pss => "pss",
            Self::Pkcs1v15 => "pkcs1v15",
        }
    }

    /// The CycloneDX 1.6 `algorithmProperties.padding` word. CycloneDX 1.6 has no word for PSS,
    /// so `pss` is `other`.
    pub fn as_cyclonedx(self) -> &'static str {
        match self {
            Self::Oaep => "oaep",
            Self::Pss => "other",
            Self::Pkcs1v15 => "pkcs1v15",
        }
    }
}

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One parameter set of an algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterSet {
    /// The CycloneDX `parameterSetIdentifier`, e.g. `128` or `SHA2-128s`.
    pub id: String,
    /// The classical security level, in bits.
    pub classical_security_level: u32,
    /// The NIST post-quantum security category (`0`: none).
    pub nist_quantum_security_level: QuantumSecurityLevel,
    /// The elliptic curve, as <https://neuromancer.sk/std/> names it.
    pub curve: Option<String>,
    /// The object identifier.
    pub oid: Option<String>,
    /// Where the two levels come from, in words.
    pub source: String,
}

/// One catalogue entry: an algorithm in one mode or with one padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Algorithm {
    /// The lookup key, e.g. `AES-GCM`.
    pub name: String,
    /// The family, e.g. `AES`.
    pub family: String,
    /// The CycloneDX primitive.
    pub primitive: Primitive,
    /// The CycloneDX mode, for a block cipher or AEAD mode.
    pub mode: Option<Mode>,
    /// The padding scheme, for RSA.
    pub padding: Option<Padding>,
    /// The CycloneDX crypto functions, in ASCII order of their words.
    pub crypto_functions: Vec<CryptoFunction>,
    /// How a quantum computer affects it.
    pub quantum_risk: QuantumRisk,
    /// The documents that specify it.
    pub standards: Vec<String>,
    /// Its parameter sets, in file order.
    pub parameter_sets: Vec<ParameterSet>,
    /// The 1-based line of its `- name:` item, when it could be found.
    pub line: Option<u32>,
}

impl Algorithm {
    /// The parameter set with this id (exact match).
    pub fn parameter_set(&self, id: &str) -> Option<&ParameterSet> {
        self.parameter_sets.iter().find(|p| p.id == id)
    }
}

/// A loaded, linted catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalogue {
    algorithms: Vec<Algorithm>,
    /// ASCII-lowercased name → index into `algorithms`.
    names: BTreeMap<String, usize>,
    /// (ASCII-lowercased name, exact id) → (algorithm index, parameter-set index).
    index: BTreeMap<(String, String), (usize, usize)>,
}

/// One (algorithm, parameter set) of a [`Catalogue`], as [`Catalogue::lookup`] returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The algorithm.
    pub algorithm: &'a Algorithm,
    /// The parameter set.
    pub parameter_set: &'a ParameterSet,
}

impl Entry<'_> {
    /// The CycloneDX 1.6 `algorithmProperties` for an asset of this algorithm and parameter set:
    /// `primitive`, `parameterSetIdentifier`, `mode`, `cryptoFunctions`,
    /// `classicalSecurityLevel` and `nistQuantumSecurityLevel`. `executionEnvironment` and
    /// `implementationPlatform` describe a build, not an algorithm, so they are left `None` for
    /// the detector to fill in.
    pub fn algorithm_properties(&self) -> AlgorithmProperties {
        AlgorithmProperties {
            primitive: Some(self.algorithm.primitive),
            parameter_set_identifier: Some(self.parameter_set.id.clone()),
            execution_environment: None,
            implementation_platform: None,
            mode: self.algorithm.mode,
            crypto_functions: self.algorithm.crypto_functions.iter().copied().collect(),
            classical_security_level: Some(self.parameter_set.classical_security_level),
            nist_quantum_security_level: Some(self.parameter_set.nist_quantum_security_level),
        }
    }

    /// The object identifier, for `cryptoProperties.oid`.
    pub fn oid(&self) -> Option<&str> {
        self.parameter_set.oid.as_deref()
    }

    /// The elliptic curve (not modelled in rollcall-core's `AlgorithmProperties`).
    pub fn curve(&self) -> Option<&str> {
        self.parameter_set.curve.as_deref()
    }

    /// The padding scheme (not modelled in rollcall-core's `AlgorithmProperties`).
    pub fn padding(&self) -> Option<Padding> {
        self.algorithm.padding
    }

    /// The algorithm's risk class.
    pub fn quantum_risk(&self) -> QuantumRisk {
        self.algorithm.quantum_risk
    }
}

/// Why a lookup found nothing. There is never a default.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// No entry has this name.
    #[error("unknown algorithm {name:?}: not in the catalogue")]
    UnknownAlgorithm {
        /// The name asked for.
        name: String,
    },
    /// The entry exists but has no parameter set with this id.
    #[error(
        "unknown parameter set {parameter_set:?} for {algorithm}; known: {}",
        known.join(", ")
    )]
    UnknownParameterSet {
        /// The entry's name, as the catalogue spells it.
        algorithm: String,
        /// The id asked for.
        parameter_set: String,
        /// The entry's ids, in file order.
        known: Vec<String>,
    },
}

/// Why a catalogue could not be loaded. Every variant names the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogueError {
    /// The file could not be read.
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
    #[error("{file}: empty algorithm catalogue")]
    Empty {
        /// The file.
        file: String,
    },
    /// The YAML is malformed or does not match the schema.
    #[error("{}: {message}", Located(file, *line, *column))]
    Yaml {
        /// The file.
        file: String,
        /// The 1-based line, if known.
        line: Option<u32>,
        /// The 1-based column, if known.
        column: Option<u32>,
        /// What is wrong.
        message: String,
    },
    /// The `format` is not [`FORMAT`].
    #[error("{file}: unsupported format {found:?}; expected {FORMAT:?}")]
    UnsupportedFormat {
        /// The file.
        file: String,
        /// The format found.
        found: String,
    },
    /// The catalogue parsed but breaks lint rules; every finding, sorted.
    #[error("{}", Report(.0))]
    Lint(Vec<Finding>),
}

/// `file`, `file:line` or `file:line:column`.
pub(crate) struct Located<'a>(pub &'a str, pub Option<u32>, pub Option<u32>);

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

/// One finding per line.
struct Report<'a>(&'a [Finding]);

impl fmt::Display for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, finding) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{finding}")?;
        }
        Ok(())
    }
}

impl Catalogue {
    /// Loads the catalogue shipped with rollcall ([`ALGORITHMS_YAML`]).
    pub fn builtin() -> Result<Self, CatalogueError> {
        Self::load_str(FILE_NAME, ALGORITHMS_YAML)
    }

    /// Loads a catalogue from text; errors and findings cite it as `name`.
    pub fn load_str(name: &str, text: &str) -> Result<Self, CatalogueError> {
        let (raw, lines) = raw::parse(name, text)?;
        if raw.format != FORMAT {
            return Err(CatalogueError::UnsupportedFormat {
                file: name.to_owned(),
                found: raw.format,
            });
        }
        let findings = lint::lint_raw(name, &raw, &lines);
        if !findings.is_empty() {
            return Err(CatalogueError::Lint(findings));
        }
        Ok(Self::build(raw, &lines))
    }

    /// Reads and loads the catalogue at `path`; errors cite `path`.
    pub fn load_path(path: &Path) -> Result<Self, CatalogueError> {
        let bytes = std::fs::read(path).map_err(|source| CatalogueError::Read {
            path: path.to_owned(),
            source,
        })?;
        let text = String::from_utf8(bytes).map_err(|_| CatalogueError::NotUtf8 {
            path: path.to_owned(),
        })?;
        Self::load_str(&path.display().to_string(), &text)
    }

    fn build(raw: raw::RawCatalogue, lines: &[Option<u32>]) -> Self {
        let mut algorithms = Vec::with_capacity(raw.algorithms.len());
        let mut names = BTreeMap::new();
        let mut index = BTreeMap::new();
        for (a, entry) in raw.algorithms.into_iter().enumerate() {
            let key = entry.name.to_ascii_lowercase();
            names.insert(key.clone(), a);
            let parameter_sets: Vec<ParameterSet> = entry
                .parameter_sets
                .into_iter()
                .map(|p| ParameterSet {
                    id: p.id,
                    classical_security_level: p.classical_security_level,
                    nist_quantum_security_level: p.nist_quantum_security_level,
                    curve: p.curve,
                    oid: p.oid,
                    source: p.source,
                })
                .collect();
            for (s, set) in parameter_sets.iter().enumerate() {
                index.insert((key.clone(), set.id.clone()), (a, s));
            }
            algorithms.push(Algorithm {
                name: entry.name,
                family: entry.family,
                primitive: entry.primitive,
                mode: entry.mode,
                padding: entry.padding,
                crypto_functions: entry.crypto_functions,
                quantum_risk: entry.quantum_risk,
                standards: entry.standards,
                parameter_sets,
                line: lines.get(a).copied().flatten(),
            });
        }
        Self {
            algorithms,
            names,
            index,
        }
    }

    /// Every entry, in name order.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.algorithms
    }

    /// The entry called `name` (ASCII case ignored).
    pub fn algorithm(&self, name: &str) -> Option<&Algorithm> {
        self.names
            .get(&name.to_ascii_lowercase())
            .and_then(|&a| self.algorithms.get(a))
    }

    /// The entry called `algorithm` (ASCII case ignored) and its parameter set `parameter_set`
    /// (exact match). An unknown name or id is an error, never a default.
    pub fn lookup(&self, algorithm: &str, parameter_set: &str) -> Result<Entry<'_>, LookupError> {
        let key = (algorithm.to_ascii_lowercase(), parameter_set.to_owned());
        if let Some(&(a, s)) = self.index.get(&key)
            && let Some(found) = self.algorithms.get(a)
            && let Some(set) = found.parameter_sets.get(s)
        {
            return Ok(Entry {
                algorithm: found,
                parameter_set: set,
            });
        }
        match self.algorithm(algorithm) {
            None => Err(LookupError::UnknownAlgorithm {
                name: algorithm.to_owned(),
            }),
            Some(found) => Err(LookupError::UnknownParameterSet {
                algorithm: found.name.clone(),
                parameter_set: parameter_set.to_owned(),
                known: found.parameter_sets.iter().map(|p| p.id.clone()).collect(),
            }),
        }
    }

    /// Every (algorithm, parameter set), in name order and then file order.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'_>> {
        self.algorithms.iter().flat_map(|algorithm| {
            algorithm
                .parameter_sets
                .iter()
                .map(move |parameter_set| Entry {
                    algorithm,
                    parameter_set,
                })
        })
    }
}
