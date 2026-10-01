//! `rollcall vex verify`: check a VEX document's detached Ed25519 signature or its Sigstore
//! bundle. Exits 0 when it verifies, 1 when it does not (with the reason), 65 for a
//! malformed key or signature file, 66 for a missing one, and 69 when `--cosign` is asked
//! for without `cosign` installed.

use std::io::Write;

use rollcall_core::vex::{
    DetachedSignature, PemForm, VerifyingKey, Zeroizing, verify as verify_bytes,
};

use super::cosign::{self, Identity};
use super::sign::with_suffix;
use super::{Failure, read};
use crate::cli::{EXIT_DATAERR, EXIT_INVALID, EXIT_USAGE, VexVerifyArgs};

/// Runs `rollcall vex verify`, returning the exit code.
pub fn run(args: &VexVerifyArgs) -> u8 {
    match verify(args) {
        Ok(message) => {
            let _ = writeln!(std::io::stdout(), "{message}");
            0
        }
        Err((code, message)) => {
            let _ = writeln!(std::io::stderr(), "rollcall vex verify: {message}");
            code
        }
    }
}

fn verify(args: &VexVerifyArgs) -> Result<String, Failure> {
    let file = &args.file;
    if args.cosign {
        let bundle = args
            .bundle
            .clone()
            .unwrap_or_else(|| with_suffix(file, ".sigstore.json"));
        // Missing inputs are 66 here, so exit 1 always means cosign rejected the signature.
        read(file)?;
        read(&bundle)?;
        cosign::verify_blob(
            file,
            &bundle,
            &Identity {
                identity: args.certificate_identity.as_deref(),
                identity_regexp: args.certificate_identity_regexp.as_deref(),
                oidc_issuer: args.certificate_oidc_issuer.as_deref(),
            },
        )?;
        return Ok(format!(
            "{}: verified (Sigstore bundle {})",
            file.display(),
            bundle.display()
        ));
    }
    let Some(key_path) = &args.key else {
        return Err((EXIT_USAGE, "give --key PEM or --cosign".to_owned()));
    };
    let document = read(file)?;
    let sig_path = args
        .signature
        .clone()
        .unwrap_or_else(|| with_suffix(file, ".sig"));
    let signature = read(&sig_path)?;
    let pem = Zeroizing::new(read(key_path)?);
    let pem = std::str::from_utf8(&pem)
        .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", key_path.display())))?;
    let (key, form) = VerifyingKey::from_pem_with_form(pem)
        .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", key_path.display())))?;
    if form == PemForm::Private {
        let _ = writeln!(
            std::io::stderr(),
            "rollcall vex verify: note: {} is a private key; verification only needs the \
             public key (`openssl pkey -in KEY.pem -pubout`), so keep the private key with \
             the signer",
            key_path.display()
        );
    }
    let signature = DetachedSignature::parse(&signature)
        .map_err(|e| (EXIT_DATAERR, format!("{}: {e}", sig_path.display())))?;
    let key_id = verify_bytes(&document, &signature, &key)
        .map_err(|e| (EXIT_INVALID, format!("{}: {e}", file.display())))?;
    Ok(format!(
        "{}: verified (Ed25519, key {key_id})",
        file.display()
    ))
}
