//! Cryptographic assets: the CycloneDX 1.6 `cryptoProperties` of a `cryptographic-asset`
//! component, with the evidence that it is there and how sure rollcall is of it.
//!
//! The JSON form of a [`CryptoAsset`] is exactly CycloneDX's `cryptoProperties` object
//! (`assetType`, one property block, `oid`) plus a rollcall-only `evidence` array, so one
//! serde implementation serves the internal model JSON and the CycloneDX document (which
//! leaves `evidence` out; see [`crate::cyclonedx`]).

use std::collections::BTreeSet;
use std::fmt;

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::confidence::Confidence;
use super::evidence::{Occurrence, Technique};
use super::ids::IdError;

/// The longest evidence reason, in characters.
pub const MAX_REASON_CHARS: usize = 200;

/// Defines an enum of CycloneDX 1.6 words: each variant serialises as its word, sorts in
/// schema order, and has [`as_str`](AssetType::as_str), `ALL` and `Display`.
macro_rules! word_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $word:literal,)+ }) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub enum $name {
            $(
                #[doc = concat!("`", $word, "`.")]
                #[serde(rename = $word)]
                $variant,
            )+
        }

        impl $name {
            /// Every value, in the schema's order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The CycloneDX 1.6 word.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $word,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

word_enum! {
    /// `cryptoProperties.assetType`: which kind of asset this is, and so which property block
    /// it carries.
    AssetType {
        Algorithm => "algorithm",
        Certificate => "certificate",
        Protocol => "protocol",
        RelatedCryptoMaterial => "related-crypto-material",
    }
}

word_enum! {
    /// `algorithmProperties.primitive`: the cryptographic building block.
    Primitive {
        Drbg => "drbg",
        Mac => "mac",
        BlockCipher => "block-cipher",
        StreamCipher => "stream-cipher",
        Signature => "signature",
        Hash => "hash",
        Pke => "pke",
        Xof => "xof",
        Kdf => "kdf",
        KeyAgree => "key-agree",
        Kem => "kem",
        Ae => "ae",
        Combiner => "combiner",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `algorithmProperties.mode`: the block-cipher mode of operation.
    Mode {
        Cbc => "cbc",
        Ecb => "ecb",
        Ccm => "ccm",
        Gcm => "gcm",
        Cfb => "cfb",
        Ofb => "ofb",
        Ctr => "ctr",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `algorithmProperties.padding`: the padding scheme. A scheme the schema has no word for,
    /// such as RSA-PSS, is `other`.
    Padding {
        Pkcs5 => "pkcs5",
        Pkcs7 => "pkcs7",
        Pkcs1v15 => "pkcs1v15",
        Oaep => "oaep",
        Raw => "raw",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `algorithmProperties.executionEnvironment`: where the algorithm runs.
    ExecutionEnvironment {
        SoftwarePlainRam => "software-plain-ram",
        SoftwareEncryptedRam => "software-encrypted-ram",
        SoftwareTee => "software-tee",
        Hardware => "hardware",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `algorithmProperties.implementationPlatform`: the target platform.
    ImplementationPlatform {
        Generic => "generic",
        X86_32 => "x86_32",
        X86_64 => "x86_64",
        Armv7A => "armv7-a",
        Armv7M => "armv7-m",
        Armv8A => "armv8-a",
        Armv8M => "armv8-m",
        Armv9A => "armv9-a",
        Armv9M => "armv9-m",
        S390x => "s390x",
        Ppc64 => "ppc64",
        Ppc64le => "ppc64le",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// One of `algorithmProperties.cryptoFunctions`: what the algorithm is used for.
    CryptoFunction {
        Generate => "generate",
        Keygen => "keygen",
        Encrypt => "encrypt",
        Decrypt => "decrypt",
        Digest => "digest",
        Tag => "tag",
        Keyderive => "keyderive",
        Sign => "sign",
        Verify => "verify",
        Encapsulate => "encapsulate",
        Decapsulate => "decapsulate",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `protocolProperties.type`: the protocol.
    ProtocolType {
        Tls => "tls",
        Ssh => "ssh",
        Ipsec => "ipsec",
        Ike => "ike",
        Sstp => "sstp",
        Wpa => "wpa",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `relatedCryptoMaterialProperties.type`: the kind of material.
    MaterialType {
        PrivateKey => "private-key",
        PublicKey => "public-key",
        SecretKey => "secret-key",
        Key => "key",
        Ciphertext => "ciphertext",
        Signature => "signature",
        Digest => "digest",
        InitializationVector => "initialization-vector",
        Nonce => "nonce",
        Seed => "seed",
        Salt => "salt",
        SharedSecret => "shared-secret",
        Tag => "tag",
        AdditionalData => "additional-data",
        Password => "password",
        Credential => "credential",
        Token => "token",
        Other => "other",
        Unknown => "unknown",
    }
}

word_enum! {
    /// `relatedCryptoMaterialProperties.state`: the material's key-management state.
    MaterialState {
        PreActivation => "pre-activation",
        Active => "active",
        Suspended => "suspended",
        Deactivated => "deactivated",
        Compromised => "compromised",
        Destroyed => "destroyed",
    }
}

word_enum! {
    /// How sure a detector is that an asset is there. Ordered `low < medium < high`; an
    /// asset's confidence is the highest of its evidence ([`CryptoAsset::confidence`]).
    ///
    /// The word is the source of truth; in CycloneDX it is written as the number
    /// [`ConfidenceLevel::as_confidence`] gives: 0.3, 0.6 or 0.9.
    ConfidenceLevel {
        Low => "low",
        Medium => "medium",
        High => "high",
    }
}

impl ConfidenceLevel {
    /// The level as a [`Confidence`]: low 3000, medium 6000, high 9000 basis points (0.3,
    /// 0.6 and 0.9 in CycloneDX).
    pub fn as_confidence(self) -> Confidence {
        let basis_points = match self {
            Self::Low => 3000,
            Self::Medium => 6000,
            Self::High => 9000,
        };
        // All three are within 0..=10000, so `new` never fails here.
        Confidence::new(basis_points).unwrap_or(Confidence::NONE)
    }
}

/// `algorithmProperties.nistQuantumSecurityLevel`: the NIST post-quantum security category,
/// `0..=6`. `0` (no quantum security) is a value, not an absence, and is always written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct QuantumSecurityLevel(u8);

impl QuantumSecurityLevel {
    /// The highest level the schema allows.
    pub const MAX: u8 = 6;

    /// A level; errors above 6.
    pub fn new(level: u8) -> Result<Self, IdError> {
        if level > Self::MAX {
            return Err(crypto_err(format!(
                "nistQuantumSecurityLevel {level} is above {}",
                Self::MAX
            )));
        }
        Ok(Self(level))
    }

    /// The level.
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for QuantumSecurityLevel {
    type Error = IdError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<QuantumSecurityLevel> for u8 {
    fn from(value: QuantumSecurityLevel) -> Self {
        value.0
    }
}

fn crypto_err(reason: impl Into<String>) -> IdError {
    IdError::CryptoAsset {
        reason: reason.into(),
    }
}

fn evidence_err(reason: impl Into<String>) -> IdError {
    IdError::CryptoEvidence {
        reason: reason.into(),
    }
}

/// `algorithmProperties`: the ten fields rollcall models, in schema order. Only
/// `certificationLevel` is not modelled. Every field is optional and omitted when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AlgorithmProperties {
    /// The cryptographic primitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primitive: Option<Primitive>,
    /// The parameter set, e.g. the key or digest size (`128`, `256`) or a named set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    /// The elliptic curve, by its <https://neuromancer.sk/std/> name, e.g. `secp256r1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    /// Where the algorithm runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_environment: Option<ExecutionEnvironment>,
    /// The target platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_platform: Option<ImplementationPlatform>,
    /// The mode of operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// The padding scheme.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub padding: Option<Padding>,
    /// What the algorithm is used for, sorted in schema order; omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub crypto_functions: BTreeSet<CryptoFunction>,
    /// The classical security level, in bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classical_security_level: Option<u32>,
    /// The NIST post-quantum security category (`0` is written as `0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nist_quantum_security_level: Option<QuantumSecurityLevel>,
}

/// `protocolProperties`: the protocol and its version. `cipherSuites`, `ikev2TransformTypes`
/// and `cryptoRefArray` are not modelled.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolProperties {
    /// The protocol.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub protocol_type: Option<ProtocolType>,
    /// The protocol version, e.g. `1.2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// `certificateProperties`. `signatureAlgorithmRef` and `subjectPublicKeyRef` are not
/// modelled. The two dates, when present, are RFC 3339 date-times.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RawCertificateProperties")]
pub struct CertificateProperties {
    /// The subject's distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_name: Option<String>,
    /// The issuer's distinguished name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Start of validity, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_before: Option<String>,
    /// End of validity, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_valid_after: Option<String>,
    /// The format, e.g. `X.509`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_format: Option<String>,
    /// The file extension, e.g. `crt`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_extension: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCertificateProperties {
    #[serde(default)]
    subject_name: Option<String>,
    #[serde(default)]
    issuer_name: Option<String>,
    #[serde(default)]
    not_valid_before: Option<String>,
    #[serde(default)]
    not_valid_after: Option<String>,
    #[serde(default)]
    certificate_format: Option<String>,
    #[serde(default)]
    certificate_extension: Option<String>,
}

impl TryFrom<RawCertificateProperties> for CertificateProperties {
    type Error = IdError;
    fn try_from(raw: RawCertificateProperties) -> Result<Self, Self::Error> {
        let properties = Self {
            subject_name: raw.subject_name,
            issuer_name: raw.issuer_name,
            not_valid_before: raw.not_valid_before,
            not_valid_after: raw.not_valid_after,
            certificate_format: raw.certificate_format,
            certificate_extension: raw.certificate_extension,
        };
        properties.check()?;
        Ok(properties)
    }
}

impl CertificateProperties {
    /// Checks the two dates are RFC 3339 date-times.
    fn check(&self) -> Result<(), IdError> {
        for (field, value) in [
            ("notValidBefore", &self.not_valid_before),
            ("notValidAfter", &self.not_valid_after),
        ] {
            if let Some(value) = value {
                OffsetDateTime::parse(value, &Rfc3339).map_err(|e| {
                    crypto_err(format!(
                        "{field} {value:?} is not an RFC 3339 date-time: {e}"
                    ))
                })?;
            }
        }
        Ok(())
    }
}

/// `relatedCryptoMaterialProperties`. The material's `value` is deliberately never modelled
/// (rollcall does not carry key material); `algorithmRef`, the dates and `securedBy` are not
/// modelled either.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedCryptoMaterialProperties {
    /// The kind of material.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub material_type: Option<MaterialType>,
    /// An identifier for the material (never its value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The key-management state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<MaterialState>,
    /// The size, in bits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// The encoding format, e.g. `PEM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// An asset's property block. The variant is the asset type, so an asset always carries the
/// block that matches its `assetType` and no other.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CryptoAssetProperties {
    /// `assetType: algorithm` with `algorithmProperties`.
    Algorithm(AlgorithmProperties),
    /// `assetType: protocol` with `protocolProperties`.
    Protocol(ProtocolProperties),
    /// `assetType: certificate` with `certificateProperties`.
    Certificate(CertificateProperties),
    /// `assetType: related-crypto-material` with `relatedCryptoMaterialProperties`.
    RelatedCryptoMaterial(RelatedCryptoMaterialProperties),
}

impl CryptoAssetProperties {
    /// The `assetType` this block belongs to.
    pub fn asset_type(&self) -> AssetType {
        match self {
            Self::Algorithm(_) => AssetType::Algorithm,
            Self::Protocol(_) => AssetType::Protocol,
            Self::Certificate(_) => AssetType::Certificate,
            Self::RelatedCryptoMaterial(_) => AssetType::RelatedCryptoMaterial,
        }
    }

    /// The JSON key of the block, e.g. `algorithmProperties`.
    pub fn block_name(&self) -> &'static str {
        block_name(self.asset_type())
    }
}

/// The JSON key of the property block for `asset_type`.
fn block_name(asset_type: AssetType) -> &'static str {
    match asset_type {
        AssetType::Algorithm => "algorithmProperties",
        AssetType::Protocol => "protocolProperties",
        AssetType::Certificate => "certificateProperties",
        AssetType::RelatedCryptoMaterial => "relatedCryptoMaterialProperties",
    }
}

/// Where an asset was seen: a source line, an ELF symbol, a Kconfig symbol or a Cargo
/// feature. Paths are forward-slash and relative, with the same rules as an
/// [`Occurrence`]; symbols, packages and features are non-empty, without whitespace or
/// control characters.
///
/// Serialised with a `kind` tag: `{"kind":"source-line","location":…,"line":…}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", try_from = "RawLocator")]
pub enum Locator {
    /// A line of a source file (`src/x.c:42`).
    SourceLine {
        /// The file.
        location: String,
        /// The 1-based line.
        line: u32,
    },
    /// A symbol in an ELF file (`zephyr.elf mbedtls_gcm_setkey`).
    ElfSymbol {
        /// The ELF file.
        location: String,
        /// The symbol.
        symbol: String,
    },
    /// A Kconfig symbol in a `.config` (`zephyr/.config:812 CONFIG_MBEDTLS_CIPHER_MODE_GCM`).
    KconfigSymbol {
        /// The `.config` file.
        location: String,
        /// The 1-based line, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
        /// The symbol, e.g. `CONFIG_MBEDTLS_CIPHER_MODE_GCM`.
        symbol: String,
    },
    /// A Cargo feature of a package (`Cargo.toml chacha20poly1305[default]`).
    CargoFeature {
        /// The manifest or lock file that enables it.
        location: String,
        /// The package.
        package: String,
        /// The feature.
        feature: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RawLocator {
    SourceLine {
        location: String,
        line: u32,
    },
    ElfSymbol {
        location: String,
        symbol: String,
    },
    KconfigSymbol {
        location: String,
        #[serde(default)]
        line: Option<u32>,
        symbol: String,
    },
    CargoFeature {
        location: String,
        package: String,
        feature: String,
    },
}

impl TryFrom<RawLocator> for Locator {
    type Error = IdError;
    fn try_from(raw: RawLocator) -> Result<Self, Self::Error> {
        let locator = match raw {
            RawLocator::SourceLine { location, line } => Self::SourceLine { location, line },
            RawLocator::ElfSymbol { location, symbol } => Self::ElfSymbol { location, symbol },
            RawLocator::KconfigSymbol {
                location,
                line,
                symbol,
            } => Self::KconfigSymbol {
                location,
                line,
                symbol,
            },
            RawLocator::CargoFeature {
                location,
                package,
                feature,
            } => Self::CargoFeature {
                location,
                package,
                feature,
            },
        };
        locator.check()?;
        Ok(locator)
    }
}

/// Checks a symbol, package or feature name: non-empty, no whitespace or control character.
fn check_word(what: &str, text: &str) -> Result<(), IdError> {
    if text.is_empty() {
        return Err(evidence_err(format!("empty {what}")));
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(evidence_err(format!(
            "{what} {text:?} contains whitespace or a control character"
        )));
    }
    Ok(())
}

impl Locator {
    /// The file the locator points into.
    pub fn location(&self) -> &str {
        match self {
            Self::SourceLine { location, .. }
            | Self::ElfSymbol { location, .. }
            | Self::KconfigSymbol { location, .. }
            | Self::CargoFeature { location, .. } => location,
        }
    }

    /// The 1-based line, if the locator has one.
    pub fn line(&self) -> Option<u32> {
        match self {
            Self::SourceLine { line, .. } => Some(*line),
            Self::KconfigSymbol { line, .. } => *line,
            Self::ElfSymbol { .. } | Self::CargoFeature { .. } => None,
        }
    }

    /// The named thing within the file, if any: the ELF or Kconfig symbol, or
    /// `package[feature]` for a Cargo feature.
    pub fn symbol(&self) -> Option<String> {
        match self {
            Self::SourceLine { .. } => None,
            Self::ElfSymbol { symbol, .. } | Self::KconfigSymbol { symbol, .. } => {
                Some(symbol.clone())
            }
            Self::CargoFeature {
                package, feature, ..
            } => Some(format!("{package}[{feature}]")),
        }
    }

    /// How a locator of this kind establishes an asset: reading source code
    /// ([`Technique::SourceCodeAnalysis`]), a binary ([`Technique::BinaryAnalysis`]) or build
    /// configuration ([`Technique::ManifestAnalysis`], for Kconfig and Cargo features).
    pub fn technique(&self) -> Technique {
        match self {
            Self::SourceLine { .. } => Technique::SourceCodeAnalysis,
            Self::ElfSymbol { .. } => Technique::BinaryAnalysis,
            Self::KconfigSymbol { .. } | Self::CargoFeature { .. } => Technique::ManifestAnalysis,
        }
    }

    /// Checks the path (as [`Occurrence::new`] does, line 0 rejected) and the names.
    pub fn check(&self) -> Result<(), IdError> {
        Occurrence::new(self.location(), self.line())?;
        match self {
            Self::SourceLine { .. } => Ok(()),
            Self::ElfSymbol { symbol, .. } => check_word("ELF symbol", symbol),
            Self::KconfigSymbol { symbol, .. } => check_word("Kconfig symbol", symbol),
            Self::CargoFeature {
                package, feature, ..
            } => {
                check_word("Cargo package", package)?;
                check_word("Cargo feature", feature)
            }
        }
    }
}

impl fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceLine { location, line } => write!(f, "{location}:{line}"),
            Self::ElfSymbol { location, symbol } => write!(f, "{location} {symbol}"),
            Self::KconfigSymbol {
                location,
                line: Some(line),
                symbol,
            } => write!(f, "{location}:{line} {symbol}"),
            Self::KconfigSymbol {
                location,
                line: None,
                symbol,
            } => write!(f, "{location} {symbol}"),
            Self::CargoFeature {
                location,
                package,
                feature,
            } => write!(f, "{location} {package}[{feature}]"),
        }
    }
}

/// One observation of a cryptographic asset: where ([`Locator`]), which detector saw it, how
/// sure it is ([`ConfidenceLevel`]) and why, in one line.
///
/// The field order drives the derived ordering: by locator, then detector, confidence and
/// reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawCryptoEvidence")]
pub struct CryptoEvidence {
    /// Where the asset was seen.
    pub locator: Locator,
    /// The detector that saw it, e.g. `kconfig` or `elf-symbols`. Never empty.
    detector: String,
    /// How sure the detector is.
    pub confidence: ConfidenceLevel,
    /// Why, in one line of at most [`MAX_REASON_CHARS`] characters.
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCryptoEvidence {
    locator: Locator,
    detector: String,
    confidence: ConfidenceLevel,
    reason: String,
}

impl TryFrom<RawCryptoEvidence> for CryptoEvidence {
    type Error = IdError;
    fn try_from(raw: RawCryptoEvidence) -> Result<Self, Self::Error> {
        Self::new(raw.locator, &raw.detector, raw.confidence, &raw.reason)
    }
}

/// The identity of a crypto evidence entry: every field except confidence.
pub type CryptoEvidenceKey<'a> = (&'a Locator, &'a str, &'a str);

impl CryptoEvidence {
    /// Builds an evidence entry. The locator must pass [`Locator::check`]; `detector` must be
    /// non-empty, not whitespace-only and free of control characters; `reason` must be one
    /// non-empty line (no control characters) of at most [`MAX_REASON_CHARS`] characters.
    pub fn new(
        locator: Locator,
        detector: &str,
        confidence: ConfidenceLevel,
        reason: &str,
    ) -> Result<Self, IdError> {
        locator.check()?;
        if detector.trim().is_empty() {
            return Err(evidence_err("empty detector"));
        }
        if detector.chars().any(char::is_control) {
            return Err(evidence_err(format!(
                "detector {detector:?} contains a control character"
            )));
        }
        if reason.trim().is_empty() {
            return Err(evidence_err("empty reason"));
        }
        if reason.chars().any(char::is_control) {
            return Err(evidence_err(
                "the reason must be one line, without control characters",
            ));
        }
        let chars = reason.chars().count();
        if chars > MAX_REASON_CHARS {
            return Err(evidence_err(format!(
                "the reason is {chars} characters, more than {MAX_REASON_CHARS}"
            )));
        }
        Ok(Self {
            locator,
            detector: detector.to_owned(),
            confidence,
            reason: reason.to_owned(),
        })
    }

    /// The detector that saw the asset.
    pub fn detector(&self) -> &str {
        &self.detector
    }

    /// Why the detector reports the asset, in one line.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// How the observation was made, from the locator's kind ([`Locator::technique`]).
    pub fn technique(&self) -> Technique {
        self.locator.technique()
    }

    /// Every field except confidence. Two entries with the same key are the same
    /// observation; an asset keeps only the more confident of them.
    pub fn key(&self) -> CryptoEvidenceKey<'_> {
        (&self.locator, &self.detector, &self.reason)
    }

    /// Re-runs the checks of [`CryptoEvidence::new`] (the locator is a public field).
    fn check(&self) -> Result<(), IdError> {
        Self::new(
            self.locator.clone(),
            &self.detector,
            self.confidence,
            &self.reason,
        )
        .map(|_| ())
    }
}

/// A cryptographic asset: the CycloneDX 1.6 `cryptoProperties` of a
/// [`ComponentKind::CryptographicAsset`](super::ComponentKind::CryptographicAsset) component,
/// and the evidence that it is there.
///
/// Serialised as `cryptoProperties` plus an `evidence` array:
/// `{"assetType":"algorithm","algorithmProperties":{…},"oid":…,"evidence":[…]}`. Reading
/// rejects unknown fields, a missing block, a block that does not match `assetType`, more
/// than one block, an empty `oid`, no evidence, and two evidence entries with the same
/// [`CryptoEvidence::key`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "RawCryptoAsset")]
pub struct CryptoAsset {
    /// The asset type and its property block.
    pub properties: CryptoAssetProperties,
    /// The object identifier, e.g. `2.16.840.1.101.3.4.1.6` for AES-128-GCM.
    pub oid: Option<String>,
    /// Where the asset was seen; never empty ([`Product::validate`](super::Product::validate)
    /// checks it).
    pub evidence: BTreeSet<CryptoEvidence>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawCryptoAsset {
    asset_type: AssetType,
    #[serde(default)]
    algorithm_properties: Option<AlgorithmProperties>,
    #[serde(default)]
    certificate_properties: Option<CertificateProperties>,
    #[serde(default)]
    related_crypto_material_properties: Option<RelatedCryptoMaterialProperties>,
    #[serde(default)]
    protocol_properties: Option<ProtocolProperties>,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    evidence: Vec<CryptoEvidence>,
}

impl TryFrom<RawCryptoAsset> for CryptoAsset {
    type Error = IdError;
    fn try_from(raw: RawCryptoAsset) -> Result<Self, Self::Error> {
        let mut blocks = Vec::new();
        if let Some(p) = raw.algorithm_properties {
            blocks.push(CryptoAssetProperties::Algorithm(p));
        }
        if let Some(p) = raw.certificate_properties {
            blocks.push(CryptoAssetProperties::Certificate(p));
        }
        if let Some(p) = raw.related_crypto_material_properties {
            blocks.push(CryptoAssetProperties::RelatedCryptoMaterial(p));
        }
        if let Some(p) = raw.protocol_properties {
            blocks.push(CryptoAssetProperties::Protocol(p));
        }
        let expected = block_name(raw.asset_type);
        let mut blocks = blocks.into_iter();
        let properties = match (blocks.next(), blocks.next()) {
            (None, _) => {
                return Err(crypto_err(format!(
                    "assetType {} without {expected}",
                    raw.asset_type
                )));
            }
            (Some(first), Some(second)) => {
                return Err(crypto_err(format!(
                    "more than one property block ({} and {})",
                    first.block_name(),
                    second.block_name()
                )));
            }
            (Some(only), None) if only.asset_type() != raw.asset_type => {
                return Err(crypto_err(format!(
                    "assetType {} with {}; expected {expected}",
                    raw.asset_type,
                    only.block_name()
                )));
            }
            (Some(only), None) => only,
        };
        let mut evidence = BTreeSet::new();
        for entry in raw.evidence {
            if evidence
                .iter()
                .any(|e: &CryptoEvidence| e.key() == entry.key())
            {
                return Err(crypto_err(
                    "duplicate evidence entry (same locator, detector and reason)",
                ));
            }
            evidence.insert(entry);
        }
        let asset = Self {
            properties,
            oid: raw.oid,
            evidence,
        };
        asset.check()?;
        Ok(asset)
    }
}

impl CryptoAsset {
    /// An asset with these properties and evidence (at least one entry; the same
    /// observation twice keeps the more confident).
    pub fn new(
        properties: CryptoAssetProperties,
        evidence: impl IntoIterator<Item = CryptoEvidence>,
    ) -> Result<Self, IdError> {
        let mut asset = Self {
            properties,
            oid: None,
            evidence: BTreeSet::new(),
        };
        for entry in evidence {
            asset.add_evidence(entry);
        }
        asset.check()?;
        Ok(asset)
    }

    /// Sets the object identifier (non-empty, without control characters) and returns the
    /// asset.
    pub fn with_oid(mut self, oid: &str) -> Result<Self, IdError> {
        self.oid = Some(oid.to_owned());
        self.check()?;
        Ok(self)
    }

    /// Adds an evidence entry. If one with the same [`CryptoEvidence::key`] is present, the
    /// more confident is kept.
    pub fn add_evidence(&mut self, entry: CryptoEvidence) {
        let existing = self
            .evidence
            .iter()
            .find(|e| e.key() == entry.key())
            .cloned();
        match existing {
            Some(old) if old.confidence >= entry.confidence => {}
            Some(old) => {
                self.evidence.remove(&old);
                self.evidence.insert(entry);
            }
            None => {
                self.evidence.insert(entry);
            }
        }
    }

    /// The asset type.
    pub fn asset_type(&self) -> AssetType {
        self.properties.asset_type()
    }

    /// The highest confidence of any evidence entry ([`ConfidenceLevel::Low`] if there is
    /// none, which [`Product::validate`](super::Product::validate) rejects).
    pub fn confidence(&self) -> ConfidenceLevel {
        self.evidence
            .iter()
            .map(|e| e.confidence)
            .max()
            .unwrap_or(ConfidenceLevel::Low)
    }

    /// Checks the invariants the public fields do not enforce: at least one evidence entry,
    /// each valid, no two with the same key; a non-empty `oid` without control characters;
    /// and RFC 3339 certificate dates.
    pub fn check(&self) -> Result<(), IdError> {
        if self.evidence.is_empty() {
            return Err(crypto_err(
                "no evidence: every asset needs at least one evidence entry",
            ));
        }
        for entry in &self.evidence {
            entry.check()?;
            // Entries sort by confidence before reason, so two with the same key are not
            // necessarily adjacent; compare against every earlier one.
            if self
                .evidence
                .iter()
                .take_while(|e| *e != entry)
                .any(|e| e.key() == entry.key())
            {
                return Err(crypto_err(
                    "duplicate evidence entry (same locator, detector and reason)",
                ));
            }
        }
        if let Some(oid) = &self.oid
            && (oid.trim().is_empty() || oid.chars().any(char::is_control))
        {
            return Err(crypto_err(format!(
                "oid {oid:?} is empty or contains a control character"
            )));
        }
        if let CryptoAssetProperties::Certificate(certificate) = &self.properties {
            certificate.check()?;
        }
        Ok(())
    }

    /// Serialises the asset as CycloneDX `cryptoProperties`, with or without the rollcall
    /// `evidence` array.
    fn serialize_with<S: Serializer>(
        &self,
        serializer: S,
        with_evidence: bool,
    ) -> Result<S::Ok, S::Error> {
        let fields = 2 + usize::from(self.oid.is_some()) + usize::from(with_evidence);
        let mut state = serializer.serialize_struct("CryptoAsset", fields)?;
        state.serialize_field("assetType", &self.asset_type())?;
        match &self.properties {
            CryptoAssetProperties::Algorithm(p) => {
                state.serialize_field("algorithmProperties", p)?;
            }
            CryptoAssetProperties::Certificate(p) => {
                state.serialize_field("certificateProperties", p)?;
            }
            CryptoAssetProperties::RelatedCryptoMaterial(p) => {
                state.serialize_field("relatedCryptoMaterialProperties", p)?;
            }
            CryptoAssetProperties::Protocol(p) => {
                state.serialize_field("protocolProperties", p)?;
            }
        }
        match &self.oid {
            Some(oid) => state.serialize_field("oid", oid)?,
            None => state.skip_field("oid")?,
        }
        if with_evidence {
            state.serialize_field("evidence", &self.evidence)?;
        }
        state.end()
    }

    /// Serialises the asset as the CycloneDX `cryptoProperties` object alone: no `evidence`.
    pub(crate) fn serialize_cyclonedx<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        self.serialize_with(serializer, false)
    }
}

impl Serialize for CryptoAsset {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.serialize_with(serializer, true)
    }
}

impl fmt::Display for CryptoAsset {
    /// The asset as compact JSON (its model form), e.g. in a merge conflict.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => f.write_str(&json),
            Err(_) => f.write_str(self.asset_type().as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn kconfig(symbol: &str, line: u32, level: ConfidenceLevel) -> CryptoEvidence {
        CryptoEvidence::new(
            Locator::KconfigSymbol {
                location: "build/zephyr/.config".to_owned(),
                line: Some(line),
                symbol: symbol.to_owned(),
            },
            "kconfig",
            level,
            &format!("{symbol}=y"),
        )
        .unwrap()
    }

    fn asset(properties: CryptoAssetProperties) -> CryptoAsset {
        CryptoAsset::new(
            properties,
            [kconfig("CONFIG_X", 1, ConfidenceLevel::Medium)],
        )
        .unwrap()
    }

    fn every_type() -> Vec<CryptoAsset> {
        vec![
            asset(CryptoAssetProperties::Algorithm(AlgorithmProperties {
                primitive: Some(Primitive::Ae),
                ..AlgorithmProperties::default()
            })),
            asset(CryptoAssetProperties::Protocol(ProtocolProperties {
                protocol_type: Some(ProtocolType::Tls),
                version: Some("1.3".to_owned()),
            })),
            asset(CryptoAssetProperties::Certificate(CertificateProperties {
                subject_name: Some("CN=x".to_owned()),
                ..CertificateProperties::default()
            })),
            asset(CryptoAssetProperties::RelatedCryptoMaterial(
                RelatedCryptoMaterialProperties {
                    material_type: Some(MaterialType::SecretKey),
                    size: Some(256),
                    ..RelatedCryptoMaterialProperties::default()
                },
            )),
        ]
    }

    const BLOCKS: [&str; 4] = [
        "algorithmProperties",
        "protocolProperties",
        "certificateProperties",
        "relatedCryptoMaterialProperties",
    ];

    #[test]
    fn each_asset_type_serialises_only_its_own_property_block() {
        let expected = [
            ("algorithm", "algorithmProperties"),
            ("protocol", "protocolProperties"),
            ("certificate", "certificateProperties"),
            ("related-crypto-material", "relatedCryptoMaterialProperties"),
        ];
        for (asset, (asset_type, block)) in every_type().into_iter().zip(expected) {
            let value = serde_json::to_value(&asset).unwrap();
            assert_eq!(value["assetType"], asset_type, "{value}");
            assert!(value[block].is_object(), "{value}");
            for other in BLOCKS.iter().filter(|b| **b != block) {
                assert!(
                    value.get(*other).is_none(),
                    "{asset_type}: {other} in {value}"
                );
            }
            assert_eq!(asset.asset_type().as_str(), asset_type);
            assert_eq!(asset.properties.block_name(), block);
            // The CycloneDX form is the same object without `evidence`.
            let mut document = Vec::new();
            asset
                .serialize_cyclonedx(&mut serde_json::Serializer::new(&mut document))
                .unwrap();
            let document: Value = serde_json::from_slice(&document).unwrap();
            let mut without = value.clone();
            without.as_object_mut().unwrap().remove("evidence");
            assert_eq!(document, without);
            // And it reads back.
            let back: CryptoAsset = serde_json::from_value(value).unwrap();
            assert_eq!(back, asset);
        }
    }

    #[test]
    fn missing_optional_fields_are_omitted_not_null() {
        let empty = [
            CryptoAssetProperties::Algorithm(AlgorithmProperties::default()),
            CryptoAssetProperties::Protocol(ProtocolProperties::default()),
            CryptoAssetProperties::Certificate(CertificateProperties::default()),
            CryptoAssetProperties::RelatedCryptoMaterial(RelatedCryptoMaterialProperties::default()),
        ];
        for properties in empty {
            let block = properties.block_name();
            let value = serde_json::to_value(asset(properties)).unwrap();
            assert_eq!(value[block], json!({}), "{value}");
            assert!(value.get("oid").is_none(), "{value}");
            let text = value.to_string();
            assert!(!text.contains("null"), "{text}");
        }
        // Absent `curve` and `padding` are left out, not written as null, beside present
        // fields.
        let partial = asset(CryptoAssetProperties::Algorithm(AlgorithmProperties {
            primitive: Some(Primitive::Signature),
            parameter_set_identifier: Some("2048".to_owned()),
            ..AlgorithmProperties::default()
        }));
        let value = serde_json::to_value(&partial).unwrap();
        let block = &value["algorithmProperties"];
        assert!(block.get("curve").is_none(), "{value}");
        assert!(block.get("padding").is_none(), "{value}");
        assert!(!value.to_string().contains("null"), "{value}");
        // A KconfigSymbol without a line omits `line`.
        let evidence = CryptoEvidence::new(
            Locator::KconfigSymbol {
                location: ".config".to_owned(),
                line: None,
                symbol: "CONFIG_X".to_owned(),
            },
            "kconfig",
            ConfidenceLevel::Low,
            "set",
        )
        .unwrap();
        let value = serde_json::to_value(&evidence).unwrap();
        assert!(value["locator"].get("line").is_none(), "{value}");
        // Present zero levels are values, not absences: `0` is written.
        let zero = asset(CryptoAssetProperties::Algorithm(AlgorithmProperties {
            classical_security_level: Some(0),
            nist_quantum_security_level: Some(QuantumSecurityLevel::new(0).unwrap()),
            ..AlgorithmProperties::default()
        }));
        let value = serde_json::to_value(&zero).unwrap();
        assert_eq!(value["algorithmProperties"]["nistQuantumSecurityLevel"], 0);
        assert_eq!(value["algorithmProperties"]["classicalSecurityLevel"], 0);
        assert_eq!(serde_json::from_value::<CryptoAsset>(value).unwrap(), zero);
    }

    #[test]
    fn curve_and_padding_round_trip_present_and_absent() {
        let cases = [
            (None, None),
            (Some("secp256r1"), None),
            (None, Some(Padding::Pkcs1v15)),
            (Some("brainpoolP256r1"), Some(Padding::Other)),
        ];
        for (curve, padding) in cases {
            let original = asset(CryptoAssetProperties::Algorithm(AlgorithmProperties {
                primitive: Some(Primitive::Signature),
                parameter_set_identifier: Some("256".to_owned()),
                curve: curve.map(str::to_owned),
                padding,
                ..AlgorithmProperties::default()
            }));
            // Model JSON.
            let text = serde_json::to_string(&original).unwrap();
            let value: Value = serde_json::from_str(&text).unwrap();
            let block = &value["algorithmProperties"];
            match curve {
                Some(curve) => assert_eq!(block["curve"], curve, "{text}"),
                None => assert!(block.get("curve").is_none(), "{text}"),
            }
            match padding {
                Some(padding) => assert_eq!(block["padding"], padding.as_str(), "{text}"),
                None => assert!(block.get("padding").is_none(), "{text}"),
            }
            assert!(!text.contains("null"), "{text}");
            let back: CryptoAsset = serde_json::from_str(&text).unwrap();
            assert_eq!(back, original, "{text}");
            // The CycloneDX form carries the same block and reads back too.
            let mut document = Vec::new();
            original
                .serialize_cyclonedx(&mut serde_json::Serializer::new(&mut document))
                .unwrap();
            let document: Value = serde_json::from_slice(&document).unwrap();
            assert_eq!(&document["algorithmProperties"], block);
        }
        // The fields sit in schema order: curve after parameterSetIdentifier, padding after
        // mode.
        let full = asset(CryptoAssetProperties::Algorithm(AlgorithmProperties {
            parameter_set_identifier: Some("256".to_owned()),
            curve: Some("secp256r1".to_owned()),
            execution_environment: Some(ExecutionEnvironment::SoftwarePlainRam),
            mode: Some(Mode::Cbc),
            padding: Some(Padding::Pkcs7),
            crypto_functions: BTreeSet::from([CryptoFunction::Encrypt]),
            ..AlgorithmProperties::default()
        }));
        let text = serde_json::to_string(&full).unwrap();
        let at = |key: &str| text.find(&format!("\"{key}\"")).unwrap();
        assert!(at("parameterSetIdentifier") < at("curve"), "{text}");
        assert!(at("curve") < at("executionEnvironment"), "{text}");
        assert!(at("mode") < at("padding"), "{text}");
        assert!(at("padding") < at("cryptoFunctions"), "{text}");
        assert_eq!(serde_json::from_str::<CryptoAsset>(&text).unwrap(), full);
    }

    fn valid() -> Value {
        serde_json::to_value(every_type().remove(0)).unwrap()
    }

    /// A named edit of an evidence entry's JSON.
    type Mutation<'a> = (&'a str, &'a dyn Fn(&mut Value));

    #[test]
    fn malformed_crypto_asset_json_errors_never_panic() {
        let evidence = valid()["evidence"].clone();
        let entry = evidence[0].clone();
        let with_entry = |mutate: &dyn Fn(&mut Value)| {
            let mut e = entry.clone();
            mutate(&mut e);
            json!({"assetType": "algorithm", "algorithmProperties": {}, "evidence": [e]})
        };
        let mut cases: Vec<(&str, Value)> = vec![
            (
                "tag without block",
                json!({"assetType": "algorithm", "evidence": evidence}),
            ),
            (
                "tag/block mismatch",
                json!({"assetType": "protocol", "algorithmProperties": {}, "evidence": evidence}),
            ),
            (
                "two blocks",
                json!({"assetType": "algorithm", "algorithmProperties": {},
                       "protocolProperties": {}, "evidence": evidence}),
            ),
            (
                "unknown top-level field",
                json!({"assetType": "algorithm", "algorithmProperties": {},
                       "evidence": evidence, "extra": 1}),
            ),
            (
                "unknown block field (certificationLevel is not modelled)",
                json!({"assetType": "algorithm",
                       "algorithmProperties": {"certificationLevel": ["none"]},
                       "evidence": evidence}),
            ),
            (
                "padding pss is not a CycloneDX word",
                json!({"assetType": "algorithm", "algorithmProperties": {"padding": "pss"},
                       "evidence": evidence}),
            ),
            (
                "numeric padding",
                json!({"assetType": "algorithm", "algorithmProperties": {"padding": 1},
                       "evidence": evidence}),
            ),
            (
                "numeric curve",
                json!({"assetType": "algorithm", "algorithmProperties": {"curve": 256},
                       "evidence": evidence}),
            ),
            (
                "material value is never modelled",
                json!({"assetType": "related-crypto-material",
                       "relatedCryptoMaterialProperties": {"value": "c2VjcmV0"},
                       "evidence": evidence}),
            ),
            (
                "nistQuantumSecurityLevel 7",
                json!({"assetType": "algorithm",
                       "algorithmProperties": {"nistQuantumSecurityLevel": 7},
                       "evidence": evidence}),
            ),
            (
                "negative level",
                json!({"assetType": "algorithm",
                       "algorithmProperties": {"classicalSecurityLevel": -1},
                       "evidence": evidence}),
            ),
            (
                "unknown enum word",
                json!({"assetType": "algorithm", "algorithmProperties": {"mode": "xts"},
                       "evidence": evidence}),
            ),
            (
                "unknown asset type",
                json!({"assetType": "key", "algorithmProperties": {}, "evidence": evidence}),
            ),
            (
                "bad certificate date",
                json!({"assetType": "certificate",
                       "certificateProperties": {"notValidAfter": "next year"},
                       "evidence": evidence}),
            ),
            (
                "empty oid",
                json!({"assetType": "algorithm", "algorithmProperties": {}, "oid": "",
                       "evidence": evidence}),
            ),
            (
                "empty evidence",
                json!({"assetType": "algorithm", "algorithmProperties": {}, "evidence": []}),
            ),
            (
                "no evidence",
                json!({"assetType": "algorithm", "algorithmProperties": {}}),
            ),
            (
                "duplicate evidence",
                json!({"assetType": "algorithm", "algorithmProperties": {},
                       "evidence": [entry.clone(), entry.clone()]}),
            ),
            (
                "wrong types",
                json!({"assetType": 1, "algorithmProperties": [], "evidence": {}}),
            ),
            (
                "wrong field type in block",
                json!({"assetType": "algorithm",
                       "algorithmProperties": {"cryptoFunctions": "encrypt"},
                       "evidence": evidence}),
            ),
            ("not an object", json!("algorithm")),
            ("null", Value::Null),
        ];
        let entry_cases: [Mutation<'_>; 11] = [
            ("reason with newline", &|e| e["reason"] = json!("one\ntwo")),
            ("empty reason", &|e| e["reason"] = json!("")),
            ("reason too long", &|e| e["reason"] = json!("x".repeat(201))),
            ("empty detector", &|e| e["detector"] = json!("")),
            ("unknown confidence", &|e| {
                e["confidence"] = json!("certain")
            }),
            ("numeric confidence", &|e| e["confidence"] = json!(0.9)),
            ("absolute path", &|e| {
                e["locator"]["location"] = json!("/home/me/build/.config");
            }),
            ("backslash path", &|e| {
                e["locator"]["location"] = json!("build\\zephyr\\.config");
            }),
            ("line 0", &|e| e["locator"]["line"] = json!(0)),
            ("empty symbol", &|e| e["locator"]["symbol"] = json!("")),
            ("unknown locator kind", &|e| {
                e["locator"]["kind"] = json!("pcap")
            }),
        ];
        for (name, mutate) in entry_cases {
            cases.push((name, with_entry(mutate)));
        }
        cases.push((
            "unknown locator field",
            with_entry(&|e| e["locator"]["offset"] = json!(3)),
        ));
        cases.push((
            "unknown evidence field",
            with_entry(&|e| e["extra"] = json!(1)),
        ));
        for (name, value) in cases {
            let text = value.to_string();
            assert!(
                serde_json::from_str::<CryptoAsset>(&text).is_err(),
                "{name}: accepted {text}"
            );
        }
        // Truncated, empty and non-UTF-8 input.
        let text = valid().to_string();
        for cut in [0, 1, text.len() / 2, text.len() - 1] {
            assert!(serde_json::from_str::<CryptoAsset>(&text[..cut]).is_err());
        }
        assert!(serde_json::from_slice::<CryptoAsset>(b"{\"assetType\":\"\xff\"}").is_err());
        // The valid one reads.
        assert!(serde_json::from_value::<CryptoAsset>(valid()).is_ok());
    }

    #[test]
    fn constructors_validate_and_evidence_keeps_the_higher_confidence() {
        let properties = CryptoAssetProperties::Algorithm(AlgorithmProperties::default());
        assert!(CryptoAsset::new(properties.clone(), []).is_err());
        let mut a = CryptoAsset::new(
            properties,
            [
                kconfig("CONFIG_X", 1, ConfidenceLevel::Low),
                kconfig("CONFIG_X", 1, ConfidenceLevel::High),
                kconfig("CONFIG_X", 1, ConfidenceLevel::Medium),
            ],
        )
        .unwrap();
        assert_eq!(a.evidence.len(), 1);
        assert_eq!(a.confidence(), ConfidenceLevel::High);
        a.add_evidence(kconfig("CONFIG_Y", 2, ConfidenceLevel::Low));
        assert_eq!(a.evidence.len(), 2);
        assert_eq!(a.confidence(), ConfidenceLevel::High);
        assert!(a.clone().with_oid("").is_err());
        assert!(a.clone().with_oid("1.2\n3").is_err());
        assert_eq!(
            a.clone().with_oid("1.2.3").unwrap().oid.as_deref(),
            Some("1.2.3")
        );
        assert!(QuantumSecurityLevel::new(6).is_ok());
        assert!(QuantumSecurityLevel::new(7).is_err());

        let loc = || Locator::SourceLine {
            location: "src/a.c".to_owned(),
            line: 3,
        };
        assert!(CryptoEvidence::new(loc(), " ", ConfidenceLevel::Low, "r").is_err());
        assert!(CryptoEvidence::new(loc(), "d\n", ConfidenceLevel::Low, "r").is_err());
        assert!(CryptoEvidence::new(loc(), "d", ConfidenceLevel::Low, "a\tb").is_err());
        assert!(CryptoEvidence::new(loc(), "d", ConfidenceLevel::Low, &"é".repeat(200)).is_ok());
        assert!(CryptoEvidence::new(loc(), "d", ConfidenceLevel::Low, &"é".repeat(201)).is_err());
        let bad_symbol = Locator::ElfSymbol {
            location: "zephyr.elf".to_owned(),
            symbol: "two words".to_owned(),
        };
        assert!(CryptoEvidence::new(bad_symbol, "d", ConfidenceLevel::Low, "r").is_err());
        let bad_feature = Locator::CargoFeature {
            location: "Cargo.toml".to_owned(),
            package: "p".to_owned(),
            feature: String::new(),
        };
        assert!(CryptoEvidence::new(bad_feature, "d", ConfidenceLevel::Low, "r").is_err());
        let drive = Locator::SourceLine {
            location: "C:/src/a.c".to_owned(),
            line: 1,
        };
        assert!(CryptoEvidence::new(drive, "d", ConfidenceLevel::Low, "r").is_err());
    }

    #[test]
    fn locators_display_technique_and_confidence_numbers() {
        let cases = [
            (
                Locator::SourceLine {
                    location: "src/x.c".to_owned(),
                    line: 42,
                },
                "src/x.c:42",
                Technique::SourceCodeAnalysis,
            ),
            (
                Locator::ElfSymbol {
                    location: "zephyr.elf".to_owned(),
                    symbol: "mbedtls_gcm_setkey".to_owned(),
                },
                "zephyr.elf mbedtls_gcm_setkey",
                Technique::BinaryAnalysis,
            ),
            (
                Locator::KconfigSymbol {
                    location: "zephyr/.config".to_owned(),
                    line: Some(812),
                    symbol: "CONFIG_MBEDTLS_CIPHER_MODE_GCM".to_owned(),
                },
                "zephyr/.config:812 CONFIG_MBEDTLS_CIPHER_MODE_GCM",
                Technique::ManifestAnalysis,
            ),
            (
                Locator::CargoFeature {
                    location: "Cargo.toml".to_owned(),
                    package: "chacha20poly1305".to_owned(),
                    feature: "default".to_owned(),
                },
                "Cargo.toml chacha20poly1305[default]",
                Technique::ManifestAnalysis,
            ),
        ];
        for (locator, display, technique) in cases {
            assert_eq!(locator.to_string(), display);
            assert_eq!(locator.technique(), technique);
            let value = serde_json::to_value(&locator).unwrap();
            assert_eq!(serde_json::from_value::<Locator>(value).unwrap(), locator);
        }
        let numbers: Vec<u16> = ConfidenceLevel::ALL
            .iter()
            .map(|l| l.as_confidence().basis_points())
            .collect();
        assert_eq!(numbers, vec![3000, 6000, 9000]);
        assert!(ConfidenceLevel::Low < ConfidenceLevel::Medium);
        assert!(ConfidenceLevel::Medium < ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::High.to_string(), "high");
    }

    #[test]
    fn enum_words_match_the_cyclonedx_1_6_schema() {
        let schema: Value = serde_json::from_str(crate::cyclonedx::BOM_1_6_SCHEMA).unwrap();
        let crypto = &schema["definitions"]["cryptoProperties"]["properties"];
        let words = |pointer: &str| -> Vec<String> {
            crypto
                .pointer(pointer)
                .unwrap_or_else(|| panic!("no {pointer}"))
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        fn ours<T: Copy>(all: &[T], word: fn(T) -> &'static str) -> Vec<String> {
            all.iter().map(|v| word(*v).to_owned()).collect()
        }
        assert_eq!(
            ours(AssetType::ALL, AssetType::as_str),
            words("/assetType/enum")
        );
        let alg = "/algorithmProperties/properties";
        assert_eq!(
            ours(Primitive::ALL, Primitive::as_str),
            words(&format!("{alg}/primitive/enum"))
        );
        assert_eq!(
            ours(Mode::ALL, Mode::as_str),
            words(&format!("{alg}/mode/enum"))
        );
        assert_eq!(
            ours(Padding::ALL, Padding::as_str),
            words(&format!("{alg}/padding/enum"))
        );
        assert_eq!(
            ours(ExecutionEnvironment::ALL, ExecutionEnvironment::as_str),
            words(&format!("{alg}/executionEnvironment/enum"))
        );
        assert_eq!(
            ours(ImplementationPlatform::ALL, ImplementationPlatform::as_str),
            words(&format!("{alg}/implementationPlatform/enum"))
        );
        assert_eq!(
            ours(CryptoFunction::ALL, CryptoFunction::as_str),
            words(&format!("{alg}/cryptoFunctions/items/enum"))
        );
        assert_eq!(
            ours(ProtocolType::ALL, ProtocolType::as_str),
            words("/protocolProperties/properties/type/enum")
        );
        let material = "/relatedCryptoMaterialProperties/properties";
        assert_eq!(
            ours(MaterialType::ALL, MaterialType::as_str),
            words(&format!("{material}/type/enum"))
        );
        assert_eq!(
            ours(MaterialState::ALL, MaterialState::as_str),
            words(&format!("{material}/state/enum"))
        );
        // Every word round-trips through serde.
        for word in ImplementationPlatform::ALL {
            let json = serde_json::to_value(word).unwrap();
            assert_eq!(json, word.as_str());
            assert_eq!(
                serde_json::from_value::<ImplementationPlatform>(json).unwrap(),
                *word
            );
        }
    }
}
