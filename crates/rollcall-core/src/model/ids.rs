//! Validated identifier and value types used by the model.
//!
//! Every constructor here returns `Result<_, IdError>` and never panics. Deserialisation goes
//! through the same constructors, so a value that exists is always valid.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error returned when an identifier or value fails validation.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// A required string was empty.
    #[error("{what} must not be empty")]
    Empty {
        /// Which value was empty.
        what: &'static str,
    },
    /// The input is not a valid package URL.
    #[error("invalid purl {input:?}: {source}")]
    Purl {
        /// The rejected input.
        input: String,
        /// The parser's reason.
        #[source]
        source: packageurl::Error,
    },
    /// The package URL's canonical form does not re-parse to itself, so it cannot be stored
    /// stably.
    #[error("purl {input:?} has no stable canonical form")]
    PurlNotCanonicalisable {
        /// The rejected input.
        input: String,
    },
    /// The input is not a valid CPE 2.3 formatted string or CPE 2.2 URI.
    #[error("invalid cpe {input:?}: {reason}")]
    Cpe {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A hash digest has the wrong length for its algorithm.
    #[error("{algorithm} digest must be {expected} hex characters, got {actual}")]
    DigestLength {
        /// The hash algorithm.
        algorithm: HashAlgorithm,
        /// The required number of hex characters.
        expected: usize,
        /// The number of characters supplied.
        actual: usize,
    },
    /// A hash digest contains something other than lowercase hex.
    #[error("digest must be lowercase hex: {input:?}")]
    DigestNotLowerHex {
        /// The rejected digest.
        input: String,
    },
    /// The input is not a syntactically valid SPDX licence expression.
    #[error("invalid licence expression {input:?}: {reason}")]
    License {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A confidence value is outside 0..=1 (or 0..=10000 basis points) or not finite.
    #[error("confidence out of range: {input}")]
    Confidence {
        /// The rejected value, formatted.
        input: String,
    },
    /// An evidence location is not a forward-slash relative path.
    #[error("invalid evidence location {input:?}: {reason}")]
    Location {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A supplier URL cannot be written as an IRI reference.
    #[error("invalid supplier URL {input:?}: {reason}")]
    SupplierUrl {
        /// The rejected input.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A string is not a valid `bom-ref` (`<level>:<32 lowercase hex>`).
    #[error("invalid bom-ref {input:?}")]
    BomRef {
        /// The rejected input.
        input: String,
    },
}

/// A package URL, stored in its canonical form.
///
/// Parsed with the `packageurl` crate; the stored string is the canonical `Display` form
/// (for example qualifiers sorted, type lower-cased), so two spellings of the same purl compare
/// equal and serialise identically.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Purl(String);

impl Purl {
    /// Parses and canonicalises a package URL.
    pub fn new(input: &str) -> Result<Self, IdError> {
        let canonical = canonical_purl(input)?;
        // Only store a fixed point of canonicalisation, so a stored value always round-trips.
        if canonical_purl(&canonical)? != canonical {
            return Err(IdError::PurlNotCanonicalisable {
                input: input.to_owned(),
            });
        }
        Ok(Self(canonical))
    }

    /// The canonical purl string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn canonical_purl(input: &str) -> Result<String, IdError> {
    packageurl::PackageUrl::from_str(input)
        .map(|p| p.to_string())
        .map_err(|source| IdError::Purl {
            input: input.to_owned(),
            source,
        })
}

impl TryFrom<String> for Purl {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<Purl> for String {
    fn from(value: Purl) -> Self {
        value.0
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A CPE name, either a CPE 2.3 formatted string or a CPE 2.2 URI, stored verbatim.
///
/// - 2.3: `cpe:2.3:` followed by the remaining fields, 13 `:`-separated fields in total
///   (counting `cpe` and `2.3`); a `\:` escape does not separate fields. Every field is
///   non-empty.
/// - 2.2: `cpe:/` followed by 2 to 7 `:`-separated fields, the first (part) non-empty.
///
/// Both forms must be printable ASCII with no whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cpe(String);

impl Cpe {
    /// Validates a CPE string and stores it verbatim.
    pub fn new(input: &str) -> Result<Self, IdError> {
        let err = |reason| IdError::Cpe {
            input: input.to_owned(),
            reason,
        };
        if !input.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(err("must be printable ASCII without whitespace"));
        }
        if let Some(rest) = input.strip_prefix("cpe:2.3:") {
            let fields = split_unescaped(rest).ok_or_else(|| err("dangling escape"))?;
            if fields.len() + 2 != 13 {
                return Err(err("CPE 2.3 needs exactly 13 fields"));
            }
            if fields.iter().any(|f| f.is_empty()) {
                return Err(err("CPE 2.3 fields must not be empty"));
            }
        } else if let Some(rest) = input.strip_prefix("cpe:/") {
            let fields: Vec<&str> = rest.split(':').collect();
            if !(2..=7).contains(&fields.len()) {
                return Err(err("CPE 2.2 URI needs 2 to 7 fields"));
            }
            if fields.first().is_none_or(|part| part.is_empty()) {
                return Err(err("CPE 2.2 part must not be empty"));
            }
        } else {
            return Err(err("must start with \"cpe:2.3:\" or \"cpe:/\""));
        }
        Ok(Self(input.to_owned()))
    }

    /// The CPE string as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Splits on `:` that is not preceded by a `\` escape. Returns `None` for a trailing lone `\`.
fn split_unescaped(input: &str) -> Option<Vec<&str>> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in input.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            fields.push(input.get(start..i)?);
            start = i + 1;
        }
    }
    if escaped {
        return None;
    }
    fields.push(input.get(start..)?);
    Some(fields)
}

impl TryFrom<String> for Cpe {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<Cpe> for String {
    fn from(value: Cpe) -> Self {
        value.0
    }
}

impl fmt::Display for Cpe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A hash algorithm, named as in CycloneDX 1.6.
///
/// The derived `Ord` follows declaration order and decides how a node's hashes sort, so new
/// variants must be appended at the end; inserting one elsewhere reorders golden output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize,
)]
pub enum HashAlgorithm {
    /// MD5.
    #[serde(rename = "MD5")]
    Md5,
    /// SHA-1.
    #[serde(rename = "SHA-1")]
    Sha1,
    /// SHA-256.
    #[serde(rename = "SHA-256")]
    Sha256,
    /// SHA-384.
    #[serde(rename = "SHA-384")]
    Sha384,
    /// SHA-512.
    #[serde(rename = "SHA-512")]
    Sha512,
    /// SHA3-256.
    #[serde(rename = "SHA3-256")]
    Sha3_256,
    /// SHA3-384.
    #[serde(rename = "SHA3-384")]
    Sha3_384,
    /// SHA3-512.
    #[serde(rename = "SHA3-512")]
    Sha3_512,
    /// BLAKE2b-256.
    #[serde(rename = "BLAKE2b-256")]
    Blake2b256,
    /// BLAKE2b-384.
    #[serde(rename = "BLAKE2b-384")]
    Blake2b384,
    /// BLAKE2b-512.
    #[serde(rename = "BLAKE2b-512")]
    Blake2b512,
    /// BLAKE3 (256-bit output).
    #[serde(rename = "BLAKE3")]
    Blake3,
}

impl HashAlgorithm {
    /// The CycloneDX 1.6 name of the algorithm.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b256 => "BLAKE2b-256",
            Self::Blake2b384 => "BLAKE2b-384",
            Self::Blake2b512 => "BLAKE2b-512",
            Self::Blake3 => "BLAKE3",
        }
    }

    /// The length of a digest for this algorithm, in hex characters.
    pub fn digest_len_hex(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 | Self::Sha3_256 | Self::Blake2b256 | Self::Blake3 => 64,
            Self::Sha384 | Self::Sha3_384 | Self::Blake2b384 => 96,
            Self::Sha512 | Self::Sha3_512 | Self::Blake2b512 => 128,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A content hash: an algorithm and a lowercase-hex digest of the right length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize)]
#[serde(try_from = "RawHash")]
pub struct Hash {
    /// The hash algorithm.
    algorithm: HashAlgorithm,
    /// The digest, lowercase hex, `algorithm.digest_len_hex()` characters long.
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHash {
    algorithm: HashAlgorithm,
    digest: String,
}

impl Hash {
    /// Validates and builds a hash. The digest must be lowercase hex of the algorithm's length.
    pub fn new(algorithm: HashAlgorithm, digest: &str) -> Result<Self, IdError> {
        if !digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(IdError::DigestNotLowerHex {
                input: digest.to_owned(),
            });
        }
        let expected = algorithm.digest_len_hex();
        if digest.len() != expected {
            return Err(IdError::DigestLength {
                algorithm,
                expected,
                actual: digest.len(),
            });
        }
        Ok(Self {
            algorithm,
            digest: digest.to_owned(),
        })
    }

    /// The hash algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// The lowercase-hex digest.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl TryFrom<RawHash> for Hash {
    type Error = IdError;
    fn try_from(raw: RawHash) -> Result<Self, Self::Error> {
        Self::new(raw.algorithm, &raw.digest)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.digest)
    }
}

/// An SPDX licence expression, checked for syntax only and stored verbatim.
///
/// The expression must be non-empty ASCII with no leading or trailing whitespace and balanced
/// parentheses. Operands match `[A-Za-z0-9.+\-:]+` (licence IDs, `LicenseRef-…`,
/// `DocumentRef-…:LicenseRef-…`, `GPL-2.0+`) and are joined by the operators `AND`, `OR` or
/// `WITH`, separated by spaces. Licence IDs are not checked against the SPDX list.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct License(String);

impl License {
    /// Checks the syntax of an SPDX licence expression and stores it verbatim.
    pub fn new(input: &str) -> Result<Self, IdError> {
        check_license(input).map_err(|reason| IdError::License {
            input: input.to_owned(),
            reason,
        })?;
        Ok(Self(input.to_owned()))
    }

    /// The expression as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn check_license(input: &str) -> Result<(), &'static str> {
    if input.is_empty() {
        return Err("empty");
    }
    if !input.is_ascii() {
        return Err("not ASCII");
    }
    if input.trim() != input {
        return Err("leading or trailing whitespace");
    }
    // Tokenise into "(", ")", and words; words are operators or operands.
    let mut tokens: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in input.char_indices() {
        let is_word = c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | ':');
        if is_word {
            if start.is_none() {
                start = Some(i);
            }
            continue;
        }
        if let Some(s) = start.take() {
            tokens.push(input.get(s..i).ok_or("bad token boundary")?);
        }
        match c {
            '(' => tokens.push("("),
            ')' => tokens.push(")"),
            ' ' => {}
            _ => return Err("invalid character"),
        }
    }
    if let Some(s) = start {
        tokens.push(input.get(s..).ok_or("bad token boundary")?);
    }

    // State machine: expecting an operand (or "(") versus expecting an operator (or ")").
    let mut depth: usize = 0;
    let mut expect_operand = true;
    for token in tokens {
        match (expect_operand, token) {
            (true, "(") => depth += 1,
            (true, "AND" | "OR" | "WITH" | ")") => return Err("expected a licence identifier"),
            (true, _) => expect_operand = false,
            (false, ")") => {
                depth = depth.checked_sub(1).ok_or("unbalanced parentheses")?;
            }
            (false, "AND" | "OR" | "WITH") => expect_operand = true,
            (false, _) => return Err("expected AND, OR or WITH"),
        }
    }
    if expect_operand {
        return Err("expression ends without an operand");
    }
    if depth != 0 {
        return Err("unbalanced parentheses");
    }
    Ok(())
}

impl TryFrom<String> for License {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<License> for String {
    fn from(value: License) -> Self {
        value.0
    }
}

impl fmt::Display for License {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The organisation or person that supplied a node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize)]
#[serde(try_from = "RawSupplier")]
pub struct Supplier {
    /// The supplier's name; never empty.
    name: String,
    /// The supplier's URLs, sorted and deduplicated; never empty strings.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    urls: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSupplier {
    name: String,
    #[serde(default)]
    urls: BTreeSet<String>,
}

impl Supplier {
    /// Builds a supplier with no URLs. The name must be non-empty.
    pub fn new(name: &str) -> Result<Self, IdError> {
        if name.is_empty() {
            return Err(IdError::Empty {
                what: "supplier name",
            });
        }
        Ok(Self {
            name: name.to_owned(),
            urls: BTreeSet::new(),
        })
    }

    /// Adds a URL (kept sorted and deduplicated) and returns the supplier. The URL must be
    /// non-empty and usable as an IRI reference (the CycloneDX `supplier.url` format): no
    /// whitespace, no control characters, none of `<`, `>`, `"`, `{`, `}`, `|`, `\`, `^` or
    /// `` ` ``, and every `%` followed by two hex digits.
    pub fn with_url(mut self, url: &str) -> Result<Self, IdError> {
        if url.is_empty() {
            return Err(IdError::Empty {
                what: "supplier URL",
            });
        }
        check_iri_reference_chars(url).map_err(|reason| IdError::SupplierUrl {
            input: url.to_owned(),
            reason,
        })?;
        self.urls.insert(url.to_owned());
        Ok(self)
    }

    /// The supplier's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The supplier's URLs, sorted.
    pub fn urls(&self) -> &BTreeSet<String> {
        &self.urls
    }
}

/// Rejects the characters an IRI reference can never contain, and malformed `%` escapes.
pub(crate) fn check_iri_reference_chars(url: &str) -> Result<(), &'static str> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("contains whitespace or a control character");
    }
    if url
        .chars()
        .any(|c| matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '\\' | '^' | '`'))
    {
        return Err("contains one of < > \" { } | \\ ^ `");
    }
    let bytes = url.as_bytes();
    for (i, _) in url.match_indices('%') {
        let hex = |at: usize| bytes.get(at).is_some_and(u8::is_ascii_hexdigit);
        if !(hex(i + 1) && hex(i + 2)) {
            return Err("'%' must be followed by two hex digits");
        }
    }
    Ok(())
}

impl TryFrom<RawSupplier> for Supplier {
    type Error = IdError;
    fn try_from(raw: RawSupplier) -> Result<Self, Self::Error> {
        raw.urls
            .iter()
            .try_fold(Self::new(&raw.name)?, |supplier, url| {
                supplier.with_url(url)
            })
    }
}

impl fmt::Display for Supplier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if !self.urls.is_empty() {
            let urls: Vec<&str> = self.urls.iter().map(String::as_str).collect();
            write!(f, " ({})", urls.join(", "))?;
        }
        Ok(())
    }
}

/// The role of a firmware image within a product.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ImageKind {
    /// A bootloader image, e.g. MCUboot.
    Bootloader,
    /// The application image, e.g. a Zephyr application.
    Application,
    /// An opaque binary blob shipped in the product, e.g. radio firmware.
    Blob,
}

impl ImageKind {
    /// The serialised name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootloader => "bootloader",
            Self::Application => "application",
            Self::Blob => "blob",
        }
    }
}

impl fmt::Display for ImageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The type of a component, as the CycloneDX 1.6 component `type`.
///
/// The derived `Ord` follows declaration order and decides how sibling components sort, so
/// new variants must be appended at the end; inserting one elsewhere reorders golden output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKind {
    /// A software application.
    Application,
    /// A software framework.
    Framework,
    /// A software library.
    Library,
    /// A container image.
    Container,
    /// A runtime platform.
    Platform,
    /// An operating system, e.g. the Zephyr kernel.
    OperatingSystem,
    /// A hardware device.
    Device,
    /// A device driver.
    DeviceDriver,
    /// Firmware.
    Firmware,
    /// A file.
    File,
    /// Data.
    Data,
    /// A machine-learning model.
    MachineLearningModel,
    /// A cryptographic asset (CycloneDX 1.6 CBOM).
    CryptographicAsset,
}

impl ComponentKind {
    /// The serialised (CycloneDX) name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Framework => "framework",
            Self::Library => "library",
            Self::Container => "container",
            Self::Platform => "platform",
            Self::OperatingSystem => "operating-system",
            Self::Device => "device",
            Self::DeviceDriver => "device-driver",
            Self::Firmware => "firmware",
            Self::File => "file",
            Self::Data => "data",
            Self::MachineLearningModel => "machine-learning-model",
            Self::CryptographicAsset => "cryptographic-asset",
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_is_canonicalised() {
        let a = Purl::new("pkg:github/zephyrproject-rtos/zephyr@v3.7.0").unwrap();
        assert_eq!(a.as_str(), "pkg:github/zephyrproject-rtos/zephyr@v3.7.0");
        assert!(Purl::new("not a purl").is_err());
        assert!(Purl::new("").is_err());
    }

    #[test]
    fn cpe_forms() {
        assert!(Cpe::new("cpe:2.3:o:zephyrproject:zephyr:3.7.0:*:*:*:*:*:*:*").is_ok());
        assert!(Cpe::new("cpe:2.3:a:ven\\:dor:product:1:*:*:*:*:*:*:*").is_ok());
        assert!(Cpe::new("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*").is_err());
        assert!(Cpe::new("cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*:*").is_err());
        assert!(Cpe::new("cpe:2.3:a:v:p:1:*:*:*:*:*:*:\\").is_err());
        assert!(Cpe::new("cpe:/a:vendor").is_ok());
        assert!(Cpe::new("cpe:/a:vendor:product:1.0:u:e:en").is_ok());
        assert!(Cpe::new("cpe:/a").is_err());
        assert!(Cpe::new("cpe:/a:1:2:3:4:5:6:7").is_err());
        assert!(Cpe::new("cpe:2.3:a:v p:p:1:*:*:*:*:*:*:*").is_err());
        assert!(Cpe::new("").is_err());
    }

    #[test]
    fn hash_digest_rules() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        assert!(Hash::new(HashAlgorithm::Md5, md5).is_ok());
        assert!(Hash::new(HashAlgorithm::Md5, &md5.to_uppercase()).is_err());
        assert!(Hash::new(HashAlgorithm::Sha256, md5).is_err());
        assert!(Hash::new(HashAlgorithm::Md5, "").is_err());
    }

    #[test]
    fn license_syntax() {
        for ok in [
            "MIT",
            "Apache-2.0 OR MIT",
            "(Apache-2.0 OR MIT) AND BSD-3-Clause",
            "GPL-2.0-or-later WITH Classpath-exception-2.0",
            "LicenseRef-proprietary",
            "DocumentRef-x:LicenseRef-y",
            "GPL-2.0+",
        ] {
            assert!(License::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            " MIT",
            "MIT ",
            "(MIT",
            "MIT)",
            "MIT OR",
            "AND MIT",
            "MIT Apache-2.0",
            "MIT/Apache",
            "MIT\tOR Apache-2.0",
            "()",
            "Ümlaut",
        ] {
            assert!(License::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn supplier_name_required() {
        assert!(Supplier::new("").is_err());
        let s = Supplier::new("ACME")
            .unwrap()
            .with_url("https://b")
            .unwrap()
            .with_url("https://a")
            .unwrap();
        assert_eq!(s.to_string(), "ACME (https://a, https://b)");
    }

    #[test]
    fn supplier_rejects_empty_url() {
        assert!(Supplier::new("ACME").unwrap().with_url("").is_err());
        let ok: Supplier =
            serde_json::from_str(r#"{"name":"ACME","urls":["https://acme.example"]}"#).unwrap();
        assert_eq!(ok.urls().len(), 1);
        assert!(serde_json::from_str::<Supplier>(r#"{"name":"ACME","urls":[""]}"#).is_err());
        assert!(
            serde_json::from_str::<Supplier>(r#"{"name":"ACME","urls":["https://a",""]}"#).is_err()
        );
    }

    #[test]
    fn supplier_rejects_url_with_whitespace_or_control_characters() {
        for bad in [
            "https://acme.example/a b",
            " https://acme.example",
            "https://acme.example\t",
            "https://acme.example\n",
            "https://acme\u{0}.example",
            "https://acme\u{7f}.example",
            "https://acme\u{a0}.example",
            "https://acme\u{2028}.example",
        ] {
            let err = Supplier::new("ACME").unwrap().with_url(bad).unwrap_err();
            assert!(
                matches!(err, IdError::SupplierUrl { .. }),
                "{bad:?}: {err:?}"
            );
            let json = serde_json::json!({"name": "ACME", "urls": [bad]}).to_string();
            assert!(serde_json::from_str::<Supplier>(&json).is_err(), "{bad:?}");
        }
        // Non-ASCII letters are fine in an IRI.
        for good in [
            "https://acme.example/path?q=1#f",
            "https://bücher.example/ä",
        ] {
            assert!(
                Supplier::new("ACME").unwrap().with_url(good).is_ok(),
                "{good:?}"
            );
        }
    }

    #[test]
    fn supplier_rejects_url_invalid_for_iri_reference() {
        for bad in [
            "https://a.example/<x",
            "https://a.example/x>",
            "https://a.example/\"q\"",
            "https://a.example/{x",
            "https://a.example/x}",
            "https://a.example/a|b",
            "https://a.example/a\\b",
            "https://a.example/a^b",
            "https://a.example/`x`",
            "https://a.example/%zz",
            "https://a.example/%2",
            "https://a.example/%",
            "https://a.example/%%20",
        ] {
            let err = Supplier::new("ACME").unwrap().with_url(bad).unwrap_err();
            assert!(
                matches!(err, IdError::SupplierUrl { .. }),
                "{bad:?}: {err:?}"
            );
            let json = serde_json::json!({"name": "ACME", "urls": [bad]}).to_string();
            assert!(serde_json::from_str::<Supplier>(&json).is_err(), "{bad:?}");
        }
        for good in [
            "https://acme.example/path?q=1#f",
            "https://bücher.example/ä",
            "relative/path",
            "https://acme.example/a%20b",
            "https://acme.example/%C3%A4%2f",
        ] {
            let s = Supplier::new("ACME").unwrap().with_url(good).unwrap();
            assert!(s.urls().contains(good), "{good:?}");
        }
    }

    #[test]
    fn component_kind_cryptographic_asset_sorts_last() {
        let json = serde_json::to_string(&ComponentKind::CryptographicAsset).unwrap();
        assert_eq!(json, "\"cryptographic-asset\"");
        assert_eq!(
            ComponentKind::CryptographicAsset.as_str(),
            "cryptographic-asset"
        );
        assert!(ComponentKind::MachineLearningModel < ComponentKind::CryptographicAsset);
    }
}
