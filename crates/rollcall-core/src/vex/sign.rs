//! Detached Ed25519 signatures over VEX documents (`rollcall-signature/1`).
//!
//! The signature covers the document's exact bytes (pure Ed25519, RFC 8032), not a
//! canonicalised form, so any change to the file — even whitespace — fails verification.
//! Ed25519 is deterministic: the same key and document always give the same signature.
//!
//! The signature file is JSON:
//!
//! ```json
//! {
//!   "format": "rollcall-signature/1",
//!   "algorithm": "Ed25519",
//!   "key_id": "sha256:<hex SHA-256 of the 32-byte public key>",
//!   "document": { "sha256": "<hex>", "bytes": 1234 },
//!   "signature": "<128 hex digits>"
//! }
//! ```
//!
//! `document` lets [`verify`] say *how* a tampered document differs before it checks the
//! signature itself. Keys are PEM: a PKCS#8 `PRIVATE KEY` to sign (as written by
//! `openssl genpkey -algorithm ed25519`), and an SPKI `PUBLIC KEY` (or the private key) to
//! verify.

use std::fmt;

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
/// A `String` (or other buffer) that is zeroed when dropped, for key material.
pub use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::to_canonical_json;

/// The `format` of a signature file.
pub const SIGNATURE_FORMAT: &str = "rollcall-signature/1";

/// The only `algorithm` rollcall signs with.
pub const ALGORITHM: &str = "Ed25519";

/// A key could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(String);

/// A signature file could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SignatureError(String);

/// Why a document failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The document is not the one that was signed.
    #[error(
        "verification failed: the document has been modified since it was signed (signed \
         sha256 {signed_sha256}, {signed_len} bytes; now sha256 {actual_sha256}, {actual_len} \
         bytes)"
    )]
    DocumentModified {
        /// The digest recorded in the signature.
        signed_sha256: String,
        /// The document's digest now.
        actual_sha256: String,
        /// The length recorded in the signature.
        signed_len: u64,
        /// The document's length now.
        actual_len: u64,
    },
    /// The signature was made with a different key.
    #[error(
        "verification failed: the signature was made with key {signed}, not the given key \
         {given}"
    )]
    KeyMismatch {
        /// The signature's key id.
        signed: String,
        /// The given key's id.
        given: String,
    },
    /// The digest matches but the Ed25519 signature does not verify.
    #[error("verification failed: the Ed25519 signature is not valid for this document and key")]
    InvalidSignature,
}

/// An Ed25519 private key.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningKey")
            .field(&self.verifying_key().key_id())
            .finish()
    }
}

impl SigningKey {
    /// Parses a PKCS#8 `-----BEGIN PRIVATE KEY-----` PEM holding an Ed25519 key.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(Self)
            .map_err(|e| {
                KeyError(format!(
                    "not an Ed25519 PKCS#8 private key PEM ({e}); create one with `openssl \
                     genpkey -algorithm ed25519 -out key.pem`"
                ))
            })
    }

    /// The key from a 32-byte Ed25519 seed. For tests, which derive keys from fixed seeds
    /// rather than commit key material; not part of the supported API.
    #[doc(hidden)]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The key as a PKCS#8 `PRIVATE KEY` PEM (the form [`SigningKey::from_pem`] reads),
    /// zeroed when dropped. For tests; not part of the supported API.
    #[doc(hidden)]
    pub fn to_pem(&self) -> Result<Zeroizing<String>, KeyError> {
        self.0
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| KeyError(format!("cannot encode the private key: {e}")))
    }

    /// The public half.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

/// Which kind of PEM a [`VerifyingKey`] was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PemForm {
    /// An SPKI `PUBLIC KEY`.
    Public,
    /// A PKCS#8 `PRIVATE KEY` (only its public half is used).
    Private,
}

/// An Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    /// Parses an SPKI `-----BEGIN PUBLIC KEY-----` PEM, or takes the public half of a
    /// PKCS#8 private key PEM.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        Self::from_pem_with_form(pem).map(|(key, _)| key)
    }

    /// [`VerifyingKey::from_pem`], also saying which form the PEM was: a verifier handed a
    /// private key should be told it only needs the public one.
    pub fn from_pem_with_form(pem: &str) -> Result<(Self, PemForm), KeyError> {
        if let Ok(key) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem) {
            return Ok((Self(key), PemForm::Public));
        }
        if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
            return Ok((Self(key.verifying_key()), PemForm::Private));
        }
        Err(KeyError(
            "not an Ed25519 public key PEM (SPKI) or private key PEM (PKCS#8); export the \
             public key with `openssl pkey -in key.pem -pubout -out key.pub.pem`"
                .to_owned(),
        ))
    }

    /// The key as an SPKI `PUBLIC KEY` PEM.
    pub fn to_pem(&self) -> Result<String, KeyError> {
        self.0
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| KeyError(format!("cannot encode the public key: {e}")))
    }

    /// `sha256:` followed by the hex SHA-256 of the 32-byte public key.
    pub fn key_id(&self) -> String {
        format!("sha256:{}", hex(&Sha256::digest(self.0.as_bytes())))
    }
}

/// The signed document's digest and length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentDigest {
    /// Hex SHA-256 of the document's bytes.
    pub sha256: String,
    /// The document's length in bytes.
    pub bytes: u64,
}

/// A detached signature file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    /// Always [`SIGNATURE_FORMAT`].
    pub format: String,
    /// Always [`ALGORITHM`].
    pub algorithm: String,
    /// The signing key's id ([`VerifyingKey::key_id`]).
    pub key_id: String,
    /// What was signed.
    pub document: DocumentDigest,
    /// The 64-byte Ed25519 signature, hex.
    pub signature: String,
}

impl DetachedSignature {
    /// The signature file's text: canonical JSON ending in a newline.
    pub fn to_json(&self) -> String {
        to_canonical_json(self).unwrap_or_default()
    }

    /// Parses a signature file, checking its format, algorithm and field syntax. Never
    /// panics.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignatureError> {
        let sig: Self = serde_json::from_slice(bytes)
            .map_err(|e| SignatureError(format!("not a rollcall signature file: {e}")))?;
        if sig.format != SIGNATURE_FORMAT {
            return Err(SignatureError(format!(
                "unsupported signature format {:?} (expected {SIGNATURE_FORMAT:?})",
                sig.format
            )));
        }
        if sig.algorithm != ALGORITHM {
            return Err(SignatureError(format!(
                "unsupported algorithm {:?} (expected {ALGORITHM:?})",
                sig.algorithm
            )));
        }
        let key_hex = sig.key_id.strip_prefix("sha256:").unwrap_or("");
        if unhex(key_hex).is_none_or(|b| b.len() != 32) {
            return Err(SignatureError(
                "key_id is not sha256: followed by 64 hex digits".to_owned(),
            ));
        }
        if unhex(&sig.document.sha256).is_none_or(|b| b.len() != 32) {
            return Err(SignatureError(
                "document.sha256 is not 64 hex digits".to_owned(),
            ));
        }
        if unhex(&sig.signature).is_none_or(|b| b.len() != 64) {
            return Err(SignatureError("signature is not 128 hex digits".to_owned()));
        }
        Ok(sig)
    }
}

/// Signs `document` (its exact bytes) with `key`.
pub fn sign(document: &[u8], key: &SigningKey) -> DetachedSignature {
    let signature = key.0.sign(document);
    DetachedSignature {
        format: SIGNATURE_FORMAT.to_owned(),
        algorithm: ALGORITHM.to_owned(),
        key_id: key.verifying_key().key_id(),
        document: digest(document),
        signature: hex(&signature.to_bytes()),
    }
}

fn digest(document: &[u8]) -> DocumentDigest {
    DocumentDigest {
        sha256: hex(&Sha256::digest(document)),
        bytes: u64::try_from(document.len()).unwrap_or(u64::MAX),
    }
}

/// Verifies `signature` over `document` with `key`, returning the key id on success. Checks,
/// in order: the key is the one that signed, the document is byte-identical to the signed
/// one, and the Ed25519 signature is valid (strict verification).
pub fn verify(
    document: &[u8],
    signature: &DetachedSignature,
    key: &VerifyingKey,
) -> Result<String, VerifyError> {
    let given = key.key_id();
    if signature.key_id != given {
        return Err(VerifyError::KeyMismatch {
            signed: signature.key_id.clone(),
            given,
        });
    }
    let actual = digest(document);
    if actual != signature.document {
        return Err(VerifyError::DocumentModified {
            signed_sha256: signature.document.sha256.clone(),
            actual_sha256: actual.sha256,
            signed_len: signature.document.bytes,
            actual_len: actual.bytes,
        });
    }
    let bytes = unhex(&signature.signature).ok_or(VerifyError::InvalidSignature)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| VerifyError::InvalidSignature)?;
    key.0
        .verify_strict(document, &sig)
        .map_err(|_| VerifyError::InvalidSignature)?;
    Ok(given)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// Decodes lowercase hex; `None` for odd length or any other character.
fn unhex(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => Some(value(*hi)? << 4 | value(*lo)?),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &[u8] = b"{\n  \"statements\": []\n}\n";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let k = key(7);
        let sig = sign(DOC, &k);
        let parsed = DetachedSignature::parse(sig.to_json().as_bytes()).unwrap();
        assert_eq!(parsed, sig);
        assert_eq!(
            verify(DOC, &parsed, &k.verifying_key()),
            Ok(k.verifying_key().key_id())
        );
    }

    #[test]
    fn signature_is_deterministic() {
        assert_eq!(sign(DOC, &key(7)).to_json(), sign(DOC, &key(7)).to_json());
    }

    #[test]
    fn flipping_any_single_byte_fails_with_document_modified() {
        let k = key(7);
        let sig = sign(DOC, &k);
        for i in 0..DOC.len() {
            let mut tampered = DOC.to_vec();
            if let Some(b) = tampered.get_mut(i) {
                *b ^= 0x01;
            }
            let err = verify(&tampered, &sig, &k.verifying_key()).unwrap_err();
            assert!(
                matches!(err, VerifyError::DocumentModified { .. }),
                "{i}: {err}"
            );
            assert!(
                err.to_string()
                    .contains("the document has been modified since it was signed"),
                "{err}"
            );
        }
    }

    #[test]
    fn tampered_digest_and_signature_fail_with_invalid_signature() {
        let k = key(7);
        let mut tampered = DOC.to_vec();
        tampered.push(b' ');
        // An attacker who rewrites the recorded digest too is caught by the signature.
        let mut sig = sign(DOC, &k);
        sig.document = digest(&tampered);
        assert_eq!(
            verify(&tampered, &sig, &k.verifying_key()),
            Err(VerifyError::InvalidSignature)
        );
        // A flipped bit in the signature itself.
        let mut sig = sign(DOC, &k);
        let first = if sig.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        sig.signature.replace_range(0..1, first);
        assert_eq!(
            verify(DOC, &sig, &k.verifying_key()),
            Err(VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_key_fails_with_key_mismatch() {
        let sig = sign(DOC, &key(7));
        let err = verify(DOC, &sig, &key(8).verifying_key()).unwrap_err();
        assert!(matches!(err, VerifyError::KeyMismatch { .. }), "{err}");
    }

    #[test]
    fn pem_round_trip_and_private_pem_verifies() {
        let k = key(9);
        let public = k.verifying_key().to_pem().unwrap();
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"), "{public}");
        assert_eq!(VerifyingKey::from_pem(&public).unwrap(), k.verifying_key());
        let private = k.to_pem().unwrap();
        assert!(private.starts_with("-----BEGIN PRIVATE KEY-----"));
        let back = SigningKey::from_pem(&private).unwrap();
        assert_eq!(back.verifying_key(), k.verifying_key());
        assert_eq!(VerifyingKey::from_pem(&private).unwrap(), k.verifying_key());
        assert_eq!(
            VerifyingKey::from_pem_with_form(&private).unwrap().1,
            PemForm::Private
        );
        assert_eq!(
            VerifyingKey::from_pem_with_form(&public).unwrap().1,
            PemForm::Public
        );
    }

    #[test]
    fn openssl_generated_keys_parse() {
        // The RFC 8032 test 1 key (secret 9d61b19d…7f60) in the PEM forms that
        // `openssl genpkey -algorithm ed25519` and `openssl pkey -pubout` write.
        let private = "-----BEGIN PRIVATE KEY-----\n\
                       MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n\
                       -----END PRIVATE KEY-----\n";
        let public = "-----BEGIN PUBLIC KEY-----\n\
                      MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n\
                      -----END PUBLIC KEY-----\n";
        let k = SigningKey::from_pem(private).unwrap();
        assert_eq!(VerifyingKey::from_pem(public).unwrap(), k.verifying_key());
        assert_eq!(VerifyingKey::from_pem(private).unwrap(), k.verifying_key());
        // RFC 8032 test 1: the empty message.
        assert_eq!(
            sign(b"", &k).signature,
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn malformed_pem_and_signature_never_panic() {
        for pem in [
            "",
            "-----BEGIN PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
            "\u{fffd}\u{0}",
            // An RSA public key: well-formed PEM, wrong algorithm.
            "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n\
             9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n\
             -----END PUBLIC KEY-----\n",
        ] {
            assert!(SigningKey::from_pem(pem).is_err(), "{pem:?}");
            assert!(VerifyingKey::from_pem(pem).is_err(), "{pem:?}");
        }
        let good = sign(DOC, &key(1)).to_json();
        let mut bad: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"{".to_vec(),
            b"[]".to_vec(),
            b"\xff\xfe".to_vec(),
            b"{\"format\":1}".to_vec(),
            good.replace("rollcall-signature/1", "rollcall-signature/2")
                .into_bytes(),
            good.replace("Ed25519", "RSA").into_bytes(),
            good.replace("\"key_id\": \"sha256:", "\"key_id\": \"md5:")
                .into_bytes(),
            good.replace("\"bytes\": ", "\"bytes\": -").into_bytes(),
            good.replace("\"signature\": \"", "\"signature\": \"zz")
                .into_bytes(),
            good.replace("\"signature\": \"", "\"signature\": \"0")
                .into_bytes(),
            good.replace("\"format\"", "\"extra\": 1, \"format\"")
                .into_bytes(),
        ];
        bad.push(good.as_bytes()[..good.len() / 2].to_vec());
        for b in bad {
            assert!(
                DetachedSignature::parse(&b).is_err(),
                "{}",
                String::from_utf8_lossy(&b)
            );
        }
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(
            unhex(&hex(&[0, 1, 0xab, 0xff])),
            Some(vec![0, 1, 0xab, 0xff])
        );
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("AB"), None);
        assert_eq!(unhex("é1"), None);
    }
}
