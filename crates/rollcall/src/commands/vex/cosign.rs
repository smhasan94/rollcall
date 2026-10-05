//! Sigstore keyless signing and verification through the `cosign` binary.
//!
//! Keyless signing needs an OIDC identity: in GitHub Actions a job with
//! `permissions: id-token: write`, elsewhere an interactive browser login whose URL cosign
//! prints on stderr (which is why signing passes cosign's stderr straight through). rollcall
//! never bundles Sigstore itself; without `cosign` on `PATH` it says so and exits 69.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Failure;
use crate::cli::{EXIT_INVALID, EXIT_UNAVAILABLE};

const NOT_AVAILABLE: &str = "cosign not available: install cosign (https://docs.sigstore.dev) \
                             and run where an OIDC identity is available (e.g. GitHub Actions \
                             with id-token: write), or use --sign local:<key.pem>";

/// `cosign` on `PATH`.
pub fn locate() -> Result<PathBuf, Failure> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .flat_map(|dir| [dir.join("cosign"), dir.join("cosign.exe")])
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| (EXIT_UNAVAILABLE, NOT_AVAILABLE.to_owned()))
}

fn exit_of(status: std::process::ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "a signal".to_owned(), |c| format!("exit {c}"))
}

/// `cosign sign-blob --yes --bundle <bundle> <file>`. cosign's stderr is inherited, so an
/// interactive OIDC login URL reaches the user; its stdout (the base64 signature, which the
/// bundle also holds) is discarded so rollcall's own stdout stays clean.
pub fn sign_blob(cosign: &Path, file: &Path, bundle: &Path) -> Result<(), Failure> {
    let status = Command::new(cosign)
        .arg("sign-blob")
        .arg("--yes")
        .arg("--bundle")
        .arg(bundle)
        .arg(file)
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            (
                EXIT_UNAVAILABLE,
                format!("cannot run cosign: {e}; {NOT_AVAILABLE}"),
            )
        })?;
    if status.success() {
        return Ok(());
    }
    Err((
        EXIT_UNAVAILABLE,
        format!(
            "cosign sign-blob failed ({}); keyless signing needs an OIDC identity (e.g. \
             GitHub Actions with id-token: write); cosign's messages are above",
            exit_of(status)
        ),
    ))
}

/// The certificate constraints `cosign verify-blob` requires.
pub struct Identity<'a> {
    /// `--certificate-identity`.
    pub identity: Option<&'a str>,
    /// `--certificate-identity-regexp`.
    pub identity_regexp: Option<&'a str>,
    /// `--certificate-oidc-issuer`.
    pub oidc_issuer: Option<&'a str>,
}

/// `cosign verify-blob --bundle <bundle> [identity flags] <file>`; a failure is exit 1 with
/// cosign's stderr.
pub fn verify_blob(file: &Path, bundle: &Path, identity: &Identity<'_>) -> Result<(), Failure> {
    let mut command = Command::new(locate()?);
    command.arg("verify-blob").arg("--bundle").arg(bundle);
    for (flag, value) in [
        ("--certificate-identity", identity.identity),
        ("--certificate-identity-regexp", identity.identity_regexp),
        ("--certificate-oidc-issuer", identity.oidc_issuer),
    ] {
        if let Some(value) = value {
            command.arg(flag).arg(value);
        }
    }
    command.arg(file);
    let output = command.output().map_err(|e| {
        (
            EXIT_UNAVAILABLE,
            format!("cannot run cosign: {e}; {NOT_AVAILABLE}"),
        )
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err((
        EXIT_INVALID,
        format!(
            "{}: verification failed: cosign verify-blob ({}): {}",
            file.display(),
            exit_of(output.status),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    ))
}
