//! The internal JSON form: canonical serialisation and validated parsing.

use serde::Serialize;

use super::graph::{MergeError, Product, ValidationError};
use super::ids::IdError;

/// Any error from building, parsing or checking a model.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// The input is not valid JSON for the model (syntax, types, unknown fields, or a value
    /// that fails validation while being read).
    #[error("invalid model JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The input bytes are not UTF-8.
    #[error("model JSON is not UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// An identifier or value is invalid.
    #[error(transparent)]
    Id(#[from] IdError),
    /// Two nodes disagree about a fact.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// The model breaks an invariant checked by [`Product::validate`].
    #[error("invalid model: {0}")]
    Validation(#[from] ValidationError),
}

/// Serialises `value` in the canonical form: two-space-indented JSON, keys in declaration
/// order, sets and maps sorted, followed by a single `\n`. The same value always yields the
/// same bytes.
pub fn to_canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<String, ModelError> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

impl Product {
    /// The canonical internal JSON form of the product. See [`to_canonical_json`].
    pub fn to_json(&self) -> Result<String, ModelError> {
        to_canonical_json(self)
    }

    /// Parses the internal JSON form and runs [`Product::validate`].
    pub fn from_json(text: &str) -> Result<Self, ModelError> {
        let product: Product = serde_json::from_str(text)?;
        product.validate()?;
        Ok(product)
    }

    /// Checks `bytes` are UTF-8, then parses them with [`Product::from_json`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ModelError> {
        Self::from_json(std::str::from_utf8(bytes)?)
    }
}
