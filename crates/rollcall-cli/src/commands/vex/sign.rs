//! `rollcall vex --sign`: a detached Ed25519 signature next to the output, or a Sigstore
//! bundle made by `cosign`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use rollcall_core::vex::{SigningKey, Zeroizing, sign as sign_bytes};

use super::super::output::write_atomically;
use super::{Failure, cosign, read};
use crate::cli::{EXIT_DATAERR, EXIT_IOERR, SignSpec};

/// `path` with `suffix` appended to its file name (`vex.json` → `vex.json.sig`).
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// A signer whose inputs (the key, or the cosign binary) are already checked, so signing
/// cannot fail on them after the document is written.
pub enum Signer {
    /// A loaded Ed25519 key.
    Local(SigningKey),
    /// The cosign binary.
    Cosign(PathBuf),
}

impl Signer {
    /// Loads the key named by `--sign local:KEY.pem` (66 if missing, 65 if malformed) or
    /// finds cosign for `--sign cosign` (69 if missing).
    pub fn prepare(spec: &SignSpec) -> Result<Self, Failure> {
        match spec {
            SignSpec::Local(key_path) => {
                let pem = Zeroizing::new(read(key_path)?);
                let pem = std::str::from_utf8(&pem)
                    .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", key_path.display())))?;
                let key = SigningKey::from_pem(pem)
                    .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", key_path.display())))?;
                Ok(Self::Local(key))
            }
            SignSpec::Cosign => Ok(Self::Cosign(cosign::locate()?)),
        }
    }

    /// Signs `document` (the in-memory bytes just written to `output`).
    pub fn sign(&self, output: &Path, document: &[u8]) -> Result<(), Failure> {
        match self {
            Self::Local(key) => {
                let signature = sign_bytes(document, key);
                let sig_path = with_suffix(output, ".sig");
                write_atomically(&sig_path, signature.to_json().as_bytes())
                    .map_err(|e| (EXIT_IOERR, format!("{}: {e}", sig_path.display())))
            }
            Self::Cosign(cosign) => {
                cosign::sign_blob(cosign, output, &with_suffix(output, ".sigstore.json"))
            }
        }
    }
}
