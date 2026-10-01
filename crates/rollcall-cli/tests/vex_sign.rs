//! `rollcall vex --sign` and `rollcall vex verify`: detached Ed25519 signatures over the
//! rendered VEX document, and the cosign (Sigstore keyless) path's behaviour when cosign is
//! not available. Keys are derived from fixed seeds at test time; no key material is
//! committed. The cosign keyless round trip needs an OIDC identity and runs only in CI
//! (`.github/workflows/ci.yml`, job `vex-cosign`).

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use rollcall_core::vex::SigningKey;

const GOLDEN_TIMESTAMP: &str = "2026-01-02T03:04:05Z";

fn rollcall() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rollcall"))
}

fn data(path: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rollcall-core/tests/data")
        .join(path)
        .display()
        .to_string()
}

fn tls_config() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zephyr/tls/http_server/zephyr/.config")
        .display()
        .to_string()
}

/// Writes `<name>.pem` (PKCS#8 private) and `<name>.pub.pem` (SPKI public) for the key with
/// `seed`, returning their paths.
fn write_test_keys(dir: &Path, name: &str, seed: u8) -> (PathBuf, PathBuf) {
    let key = SigningKey::from_seed(&[seed; 32]);
    let private = dir.join(format!("{name}.pem"));
    let public = dir.join(format!("{name}.pub.pem"));
    std::fs::write(&private, key.to_pem().unwrap().as_bytes()).unwrap();
    std::fs::write(&public, key.verifying_key().to_pem().unwrap()).unwrap();
    (private, public)
}

/// `rollcall vex --format openvex` on the old-mbedTLS model, signed with `sign`, written to
/// `out`.
fn vex_signed(out: &Path, sign: &str) -> Command {
    let mut cmd = rollcall();
    cmd.arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .args(["--kconfig", &tls_config()])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .args(["--rules", &data("vex/old-mbedtls.rules.yml")])
        .args(["--format", "openvex", "--timestamp", GOLDEN_TIMESTAMP])
        .args(["--sign", sign, "-o"])
        .arg(out);
    cmd
}

fn sig_of(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// Signs the OpenVEX document into `dir`, returning (document, public key).
fn signed_document(dir: &Path) -> (PathBuf, PathBuf) {
    let (private, public) = write_test_keys(dir, "signer", 7);
    let out = dir.join("vex.openvex.json");
    vex_signed(&out, &format!("local:{}", private.display()))
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
    (out, public)
}

fn verify(file: &Path, key: &Path) -> Command {
    let mut cmd = rollcall();
    cmd.args(["vex", "verify"]).arg(file).arg("--key").arg(key);
    cmd
}

#[test]
fn vex_sign_local_then_verify_exit_0() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    let sig = std::fs::read_to_string(sig_of(&out)).unwrap();
    assert!(
        sig.contains("\"format\": \"rollcall-signature/1\""),
        "{sig}"
    );
    assert!(sig.contains("\"algorithm\": \"Ed25519\""), "{sig}");
    verify(&out, &public)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("verified (Ed25519, key sha256:"))
        .stderr(predicate::str::is_empty());
    // The private key PEM verifies too (its public half).
    verify(&out, &dir.path().join("signer.pem"))
        .assert()
        .code(0);
    // Ed25519 is deterministic: signing the same document again gives the same file.
    let again = tempfile::tempdir().unwrap();
    let (out2, _) = signed_document(again.path());
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&out2).unwrap());
    assert_eq!(
        std::fs::read(sig_of(&out)).unwrap(),
        std::fs::read(sig_of(&out2)).unwrap()
    );
}

#[test]
fn vex_sign_local_cyclonedx_and_explicit_signature_path() {
    let dir = tempfile::tempdir().unwrap();
    let (private, public) = write_test_keys(dir.path(), "signer", 3);
    let sbom = dir.path().join("sbom.cdx.json");
    rollcall()
        .args(["generate", "--model", &data("old-mbedtls.model.json")])
        .args(["--timestamp", GOLDEN_TIMESTAMP, "-o"])
        .arg(&sbom)
        .assert()
        .code(0);
    let out = dir.path().join("vex.cdx.json");
    rollcall()
        .arg("vex")
        .arg("--sbom")
        .arg(&sbom)
        .args(["--kconfig", &tls_config()])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .args(["--rules", &data("vex/old-mbedtls.rules.yml")])
        .args(["--format", "cyclonedx", "--sign"])
        .arg(format!("local:{}", private.display()))
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    let moved = dir.path().join("elsewhere.sig");
    std::fs::rename(sig_of(&out), &moved).unwrap();
    verify(&out, &public)
        .assert()
        .code(66)
        .stderr(predicate::str::contains("vex.cdx.json.sig"));
    verify(&out, &public)
        .arg("--signature")
        .arg(&moved)
        .assert()
        .code(0);
}

#[test]
fn vex_verify_tampered_document_exit_1_with_clear_message() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    let mut bytes = std::fs::read(&out).unwrap();
    // Flip one bit of one byte in the middle of the document.
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&out, &bytes).unwrap();
    verify(&out, &public)
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with("rollcall vex verify: "))
        .stderr(predicate::str::contains(
            "verification failed: the document has been modified since it was signed",
        ));
}

#[test]
fn vex_verify_tampered_signature_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    let sig_path = sig_of(&out);
    let sig = std::fs::read_to_string(&sig_path).unwrap();
    // Flip one hex digit of the signature value.
    let at = sig.find("\"signature\": \"").unwrap() + "\"signature\": \"".len();
    let digit = &sig[at..at + 1];
    let flipped = if digit == "0" { "1" } else { "0" };
    let tampered = format!("{}{flipped}{}", &sig[..at], &sig[at + 1..]);
    std::fs::write(&sig_path, tampered).unwrap();
    verify(&out, &public)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "the Ed25519 signature is not valid for this document and key",
        ));
}

#[test]
fn vex_verify_wrong_key_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let (out, _) = signed_document(dir.path());
    let (_, other) = write_test_keys(dir.path(), "other", 8);
    verify(&out, &other)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("was made with key sha256:"));
}

#[test]
fn vex_sign_requires_output_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let (private, _) = write_test_keys(dir.path(), "signer", 7);
    rollcall()
        .arg("vex")
        .args(["--model", &data("old-mbedtls.model.json")])
        .args(["--findings", &data("findings/old-mbedtls.grype.json")])
        .arg("--sign")
        .arg(format!("local:{}", private.display()))
        .assert()
        .code(64)
        .stdout(predicate::str::is_empty());
    let out = dir.path().join("vex.json");
    for bad in ["local:", "pgp", "LOCAL:x.pem"] {
        vex_signed(&out, bad).assert().code(64);
    }
    assert!(!out.exists());
}

#[test]
fn vex_sign_cosign_not_available_exit_69_clear_message() {
    let dir = tempfile::tempdir().unwrap();
    let empty_path = dir.path().join("empty-bin");
    std::fs::create_dir(&empty_path).unwrap();
    let out = dir.path().join("vex.json");
    vex_signed(&out, "cosign")
        .env("PATH", &empty_path)
        .assert()
        .code(69)
        .stderr(predicate::str::contains(
            "rollcall vex: cosign not available",
        ))
        .stderr(predicate::str::contains("--sign local:<key.pem>"));
    assert!(!out.exists(), "nothing is written when cosign is missing");
    // verify --cosign with every input present but no cosign.
    let (doc, _) = signed_document(dir.path());
    let bundle = dir.path().join("bundle.json");
    std::fs::write(&bundle, "{}").unwrap();
    verify_cosign(&doc, &bundle)
        .env("PATH", &empty_path)
        .assert()
        .code(69)
        .stderr(predicate::str::contains("cosign not available"));
}

/// `rollcall vex verify FILE --cosign --bundle BUNDLE` with identity constraints.
fn verify_cosign(file: &Path, bundle: &Path) -> Command {
    let mut cmd = rollcall();
    cmd.args(["vex", "verify"])
        .arg(file)
        .arg("--cosign")
        .arg("--bundle")
        .arg(bundle)
        .args(["--certificate-identity", "someone@example.com"])
        .args([
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ]);
    cmd
}

#[test]
fn vex_verify_cosign_requires_identity_and_issuer_exit_64() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, _) = signed_document(dir.path());
    let issuer = [
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
    ];
    let cases: [&[&str]; 4] = [
        &[],
        &issuer,
        &["--certificate-identity", "someone@example.com"],
        &[
            "--certificate-identity",
            "a@example.com",
            "--certificate-identity-regexp",
            ".*",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ],
    ];
    for extra in cases {
        rollcall()
            .args(["vex", "verify"])
            .arg(&doc)
            .arg("--cosign")
            .args(extra)
            .assert()
            .code(64)
            .stdout(predicate::str::is_empty());
    }
    // The identity flags only make sense with --cosign.
    rollcall()
        .args(["vex", "verify"])
        .arg(&doc)
        .args(["--key", "k.pem", "--certificate-identity", "a@example.com"])
        .assert()
        .code(64);
}

#[test]
fn vex_verify_cosign_missing_bundle_or_document_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let (doc, _) = signed_document(dir.path());
    // Exit 66 comes before looking for cosign, so this holds with or without it installed.
    verify_cosign(&doc, &dir.path().join("missing.sigstore.json"))
        .assert()
        .code(66)
        .stderr(predicate::str::contains("missing.sigstore.json"));
    let bundle = dir.path().join("bundle.json");
    std::fs::write(&bundle, "{}").unwrap();
    verify_cosign(&dir.path().join("missing.json"), &bundle)
        .assert()
        .code(66);
    // The default bundle path is FILE.sigstore.json.
    rollcall()
        .args(["vex", "verify"])
        .arg(&doc)
        .arg("--cosign")
        .args(["--certificate-identity-regexp", ".*"])
        .args([
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ])
        .assert()
        .code(66)
        .stderr(predicate::str::contains("vex.openvex.json.sigstore.json"));
}

/// A stand-in `cosign` on PATH: `sign-blob` prints a login prompt on stderr and a signature
/// on stdout, then writes the bundle; `verify-blob` succeeds unless the file's first line
/// contains `TAMPERED`. Unix only (a shell script using only builtins, as PATH holds only
/// it).
#[cfg(unix)]
fn fake_cosign(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("fake-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = bin.join("cosign");
    std::fs::write(
        &script,
        r#"#!/bin/sh
case "$1" in
  sign-blob)
    echo "Go to https://oauth2.sigstore.dev/auth/device to sign in (fake cosign)" >&2
    echo "FAKE-SIGNATURE-ON-STDOUT"
    shift
    while [ $# -gt 1 ]; do
      if [ "$1" = "--bundle" ]; then bundle="$2"; fi
      shift
    done
    echo '{"fake": true}' > "$bundle"
    ;;
  verify-blob)
    for last; do :; done
    IFS= read -r first < "$last" || true
    case "$first" in
      *TAMPERED*) echo "invalid signature (fake cosign)" >&2; exit 1 ;;
    esac
    ;;
esac
"#,
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[cfg(unix)]
#[test]
fn vex_sign_cosign_shows_cosign_stderr_and_keeps_stdout_clean() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_cosign(dir.path());
    let out = dir.path().join("vex.json");
    let output = vex_signed(&out, "cosign")
        .env("PATH", &bin)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("https://oauth2.sigstore.dev/auth/device"),
        "{stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "cosign's stdout leaked into rollcall's"
    );
    let bundle = dir.path().join("vex.json.sigstore.json");
    assert!(bundle.exists());
    verify_cosign(&out, &bundle)
        .env("PATH", &bin)
        .assert()
        .code(0);
    // cosign rejecting the signature is exit 1, with its message.
    let tampered = dir.path().join("tampered.json");
    std::fs::write(&tampered, "TAMPERED").unwrap();
    verify_cosign(&tampered, &bundle)
        .env("PATH", &bin)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("verification failed"))
        .stderr(predicate::str::contains("invalid signature (fake cosign)"));
}

#[test]
fn vex_sign_bad_or_missing_key_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("vex.json");
    let sig = sig_of(&out);
    std::fs::write(&sig, "stale signature from an earlier run").unwrap();
    let bad = dir.path().join("bad.pem");
    std::fs::write(
        &bad,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    let not_utf8 = dir.path().join("binary.pem");
    std::fs::write(&not_utf8, b"\xff\xfe").unwrap();
    for (key, code) in [
        (dir.path().join("missing.pem"), 66),
        (bad, 65),
        (not_utf8, 65),
        (dir.path().to_path_buf(), 66),
    ] {
        vex_signed(&out, &format!("local:{}", key.display()))
            .assert()
            .code(code)
            .stdout(predicate::str::is_empty());
        assert!(
            !out.exists(),
            "{}: an unsigned document was written",
            key.display()
        );
        assert_eq!(
            std::fs::read_to_string(&sig).unwrap(),
            "stale signature from an earlier run",
            "{}: the old .sig was touched",
            key.display()
        );
    }
}

#[test]
fn vex_verify_with_private_key_notes_it_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    verify(&out, &dir.path().join("signer.pem"))
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "is a private key; verification only needs the public key",
        ));
    verify(&out, &public)
        .assert()
        .code(0)
        .stderr(predicate::str::is_empty());
}

#[test]
fn vex_verify_missing_key_exit_66() {
    let dir = tempfile::tempdir().unwrap();
    let (out, _) = signed_document(dir.path());
    verify(&out, &dir.path().join("missing.pub.pem"))
        .assert()
        .code(66);
    verify(
        &dir.path().join("missing.json"),
        &dir.path().join("signer.pub.pem"),
    )
    .assert()
    .code(66);
    rollcall()
        .args(["vex", "verify"])
        .arg(&out)
        .assert()
        .code(64);
}

#[test]
fn vex_verify_malformed_key_exit_65() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    let pem = std::fs::read_to_string(&public).unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("truncated", pem.as_bytes()[..pem.len() / 2].to_vec()),
        ("not-utf8", b"\xff\xfe\xfd".to_vec()),
        (
            "garbage",
            b"-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n".to_vec(),
        ),
    ];
    for (name, bytes) in cases {
        let key = dir.path().join(format!("{name}.pem"));
        std::fs::write(&key, bytes).unwrap();
        let output = verify(&out, &key).output().unwrap();
        assert_eq!(output.status.code(), Some(65), "{name}: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("panicked"), "{name}: {stderr}");
    }
    // A malformed key given to --sign is also 65, and nothing is signed.
    let bad = dir.path().join("garbage.pem");
    let out2 = dir.path().join("vex2.json");
    vex_signed(&out2, &format!("local:{}", bad.display()))
        .assert()
        .code(65);
    assert!(!sig_of(&out2).exists());
}

#[test]
fn vex_verify_malformed_signature_exit_65() {
    let dir = tempfile::tempdir().unwrap();
    let (out, public) = signed_document(dir.path());
    let sig_path = sig_of(&out);
    let sig = std::fs::read_to_string(&sig_path).unwrap();
    for (name, bytes) in [
        ("empty", String::new()),
        ("truncated", sig[..sig.len() / 2].to_owned()),
        (
            "wrong-format",
            sig.replace("rollcall-signature/1", "rollcall-signature/9"),
        ),
        ("wrong-algorithm", sig.replace("Ed25519", "ECDSA")),
        ("array", "[]".to_owned()),
    ] {
        std::fs::write(&sig_path, bytes).unwrap();
        let output = verify(&out, &public).output().unwrap();
        assert_eq!(output.status.code(), Some(65), "{name}: {output:?}");
        assert!(
            !String::from_utf8(output.stderr)
                .unwrap()
                .contains("panicked"),
            "{name}"
        );
    }
}
