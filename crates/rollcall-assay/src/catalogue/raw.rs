//! The catalogue as serde reads it: the typed schema. Unknown keys are rejected everywhere, and
//! a string field must hold a YAML string: a plain scalar YAML resolves to a number, boolean or
//! null (`id: 128`) is rejected, as the JSON Schema rejects it, rather than turned into text.

use std::fmt;

use rollcall_core::model::{CryptoFunction, Mode, Primitive, QuantumSecurityLevel};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};

use super::{CatalogueError, Padding, QuantumRisk};

/// A YAML string scalar (see the module docs).
struct Text(String);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl Visitor<'_> for TextVisitor {
            type Value = Text;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string (quote a number: \"128\")")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Text, E> {
                Ok(Text(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Text, E> {
                Ok(Text(v))
            }
        }
        deserializer.deserialize_any(TextVisitor)
    }
}

fn text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    Text::deserialize(deserializer).map(|t| t.0)
}

fn optional_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<Text>::deserialize(deserializer).map(|t| t.map(|t| t.0))
}

fn texts<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    Vec::<Text>::deserialize(deserializer).map(|v| v.into_iter().map(|t| t.0).collect())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCatalogue {
    #[serde(deserialize_with = "text")]
    pub format: String,
    pub algorithms: Vec<RawAlgorithm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAlgorithm {
    #[serde(deserialize_with = "text")]
    pub name: String,
    #[serde(deserialize_with = "text")]
    pub family: String,
    pub primitive: Primitive,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default)]
    pub padding: Option<Padding>,
    #[serde(default)]
    pub crypto_functions: Vec<CryptoFunction>,
    pub quantum_risk: QuantumRisk,
    #[serde(deserialize_with = "texts")]
    pub standards: Vec<String>,
    pub parameter_sets: Vec<RawParameterSet>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawParameterSet {
    #[serde(deserialize_with = "text")]
    pub id: String,
    pub classical_security_level: u32,
    pub nist_quantum_security_level: QuantumSecurityLevel,
    #[serde(default, deserialize_with = "optional_text")]
    pub curve: Option<String>,
    #[serde(default, deserialize_with = "optional_text")]
    pub oid: Option<String>,
    #[serde(deserialize_with = "text")]
    pub source: String,
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

/// The 1-based line of every `- name:` sequence item, in file order (parameter sets start with
/// `- id:`, so only entries match). Best effort: used only when there is one per entry.
fn entry_lines(text: &str) -> Vec<u32> {
    text.split('\n')
        .enumerate()
        .filter(|(_, line)| {
            let rest = line.trim_start_matches(' ');
            rest.strip_prefix('-')
                .map(|r| r.trim_start_matches(' '))
                .is_some_and(|r| r.starts_with("name:"))
        })
        .map(|(i, _)| to_u32(i.saturating_add(1)))
        .collect()
}

/// Parses `text` (cited as `file`) into the raw catalogue and each entry's line (`None` when the
/// lines could not be matched to entries).
pub(crate) fn parse(
    file: &str,
    text: &str,
) -> Result<(RawCatalogue, Vec<Option<u32>>), CatalogueError> {
    if text.trim().is_empty() {
        return Err(CatalogueError::Empty {
            file: file.to_owned(),
        });
    }
    let raw: Option<RawCatalogue> = yaml_serde::from_str(text).map_err(|e| {
        let location = e.location();
        let line = location.as_ref().map(|l| to_u32(l.line()));
        let column = location.as_ref().map(|l| to_u32(l.column()));
        CatalogueError::Yaml {
            file: file.to_owned(),
            line,
            column,
            message: without_location(&e.to_string(), line, column).to_owned(),
        }
    })?;
    let Some(raw) = raw else {
        return Err(CatalogueError::Empty {
            file: file.to_owned(),
        });
    };
    let found = entry_lines(text);
    let lines = if found.len() == raw.algorithms.len() {
        found.into_iter().map(Some).collect()
    } else {
        vec![None; raw.algorithms.len()]
    };
    Ok((raw, lines))
}
