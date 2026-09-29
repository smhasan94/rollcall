//! The document serial number (`serialNumber`).

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};

use super::ParseError;
use crate::model::Product;

/// Domain-separation prefix hashed before the model; bump the suffix if the input changes.
const DOMAIN: &[u8] = b"rollcall-serial/1\n";

const PREFIX: &str = "urn:uuid:";

/// A CycloneDX `serialNumber`: `urn:uuid:` followed by a lowercase RFC 4122 UUID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SerialNumber(String);

impl SerialNumber {
    /// Derives the serial number from the product's content alone: SHA-256 over
    /// `"rollcall-serial/1\n"` followed by the product's canonical internal JSON
    /// ([`Product::to_json`]), truncated to 128 bits and marked as a version-8 (custom),
    /// RFC 4122-variant UUID.
    ///
    /// It depends on nothing else — not the timestamp, not the rollcall version — so the same
    /// model always gets the same serial number, and a changed model gets a new one.
    pub fn derive(product: &Product) -> Result<Self, serde_json::Error> {
        // The same bytes as `Product::to_json`: pretty-printed JSON and a trailing newline.
        let mut json = serde_json::to_vec_pretty(product)?;
        json.push(b'\n');
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(&json);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        for (out, byte) in bytes.iter_mut().zip(digest.iter()) {
            *out = *byte;
        }
        if let Some(b) = bytes.get_mut(6) {
            *b = (*b & 0x0f) | 0x80; // version 8
        }
        if let Some(b) = bytes.get_mut(8) {
            *b = (*b & 0x3f) | 0x80; // variant 10 (RFC 4122)
        }

        let mut text = String::with_capacity(PREFIX.len() + 36);
        text.push_str(PREFIX);
        for (i, byte) in bytes.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                text.push('-');
            }
            text.push(hex_digit(byte >> 4));
            text.push(hex_digit(byte & 0x0f));
        }
        Ok(Self(text))
    }

    /// Parses `urn:uuid:` followed by a UUID in lowercase 8-4-4-4-12 hex form (the pattern
    /// the CycloneDX 1.6 schema requires). Upper-case hex is rejected.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let err = |reason: &'static str| ParseError::SerialNumber {
            input: input.to_owned(),
            reason,
        };
        let uuid = input
            .strip_prefix(PREFIX)
            .ok_or_else(|| err("must start with \"urn:uuid:\""))?;
        let groups: Vec<&str> = uuid.split('-').collect();
        let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        if lengths != [8, 4, 4, 4, 12] {
            return Err(err("UUID must be 8-4-4-4-12 hex digits"));
        }
        if !groups
            .iter()
            .all(|g| g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(err("UUID must be lowercase hex"));
        }
        Ok(Self(input.to_owned()))
    }

    /// The `urn:uuid:…` text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn hex_digit(nibble: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(nibble & 0x0f))
            .copied()
            .unwrap_or(b'0'),
    )
}

impl FromStr for SerialNumber {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_v8_urn_and_stable() {
        let product = Product::new("widget").unwrap().with_version("1.0.0");
        let serial = SerialNumber::derive(&product).unwrap();
        let text = serial.as_str();
        assert_eq!(SerialNumber::parse(text).unwrap(), serial, "{text}");
        let uuid = text.strip_prefix("urn:uuid:").unwrap();
        // Version nibble is 8; variant bits are 10 (8, 9, a or b).
        assert_eq!(&uuid[14..15], "8", "{text}");
        assert!(matches!(&uuid[19..20], "8" | "9" | "a" | "b"), "{text}");
        assert_eq!(SerialNumber::derive(&product.clone()).unwrap(), serial);

        // Any content change gives a different serial number.
        let other = Product::new("widget").unwrap().with_version("1.0.1");
        assert_ne!(SerialNumber::derive(&other).unwrap(), serial);

        // The documented construction: SHA-256 over the domain and the canonical JSON.
        let mut hasher = Sha256::new();
        hasher.update(b"rollcall-serial/1\n");
        hasher.update(product.to_json().unwrap().as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
        let compact: String = uuid.chars().filter(|c| *c != '-').collect();
        assert_eq!(&compact[..12], &hex[..12]);
        assert_eq!(&compact[13..16], &hex[13..16]);
        assert_eq!(&compact[17..], &hex[17..]);
    }

    #[test]
    fn parse_rejects_uppercase_and_wrong_shape() {
        assert!(SerialNumber::parse("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79").is_ok());
        for bad in [
            "",
            "urn:uuid:",
            "3e671687-395b-41f5-a30f-a58921a69b79",
            "URN:UUID:3e671687-395b-41f5-a30f-a58921a69b79",
            "urn:uuid:3E671687-395B-41F5-A30F-A58921A69B79",
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b7",
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b790",
            "urn:uuid:3e671687395b41f5a30fa58921a69b79",
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b7g",
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79-",
            "urn:uuid:3e67168-7395b-41f5-a30f-a58921a69b79",
            "urn:uuid:NOPE",
            "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b7\u{e9}",
        ] {
            let err = SerialNumber::parse(bad).unwrap_err();
            assert!(err.to_string().contains("serial number"), "{bad:?}: {err}");
            assert!(bad.parse::<SerialNumber>().is_err());
        }
    }
}
