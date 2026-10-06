//! Naming crypto assets and filling in their properties from the [algorithm
//! catalogue](crate::catalogue), shared by every detector.
//!
//! - [`asset_name`] is the component name of an asset: the catalogue algorithm and its
//!   parameter set, `AES-CBC-128`, `ECDSA-secp256r1`, `HMAC-SHA-256`, or the algorithm alone
//!   (`AES-CBC`) when the parameter set is unknown. A parameter set spelled like the algorithm
//!   (`Ed25519`, `X25519`) is not repeated.
//! - [`parse_asset_name`] reverses it, by the longest catalogue name that prefixes the name.
//! - [`algorithm_properties`] is the CycloneDX `algorithmProperties` (and OID) for an asset:
//!   with a parameter set, exactly [`Entry::algorithm_properties`](crate::catalogue::Entry); without
//!   one, the algorithm's primitive, mode and functions and no security levels, because the
//!   levels belong to a parameter set.

use rollcall_core::model::AlgorithmProperties;

use crate::catalogue::{Catalogue, LookupError};

/// The component name of an asset of `algorithm` (as the catalogue spells it) with
/// `parameter_set`: `AES-CBC-128`, `ECDSA-secp256r1`, `Ed25519` (a set spelled like the algorithm
/// is not repeated), or `AES-CBC` when there is no parameter set.
pub fn asset_name(algorithm: &str, parameter_set: Option<&str>) -> String {
    match parameter_set {
        None => algorithm.to_owned(),
        Some(set) if set.eq_ignore_ascii_case(algorithm) => algorithm.to_owned(),
        Some(set) => format!("{algorithm}-{set}"),
    }
}

/// The (algorithm, parameter set) an [`asset_name`] names, with the algorithm as the catalogue
/// spells it: the longest catalogue name that is a prefix of `name` (ASCII case ignored) and is
/// followed by the end of the name or by `-` and the parameter set. `None` when no catalogue name
/// fits. A name that is exactly an algorithm whose parameter set is spelled like it (`Ed25519`)
/// gives that set.
pub fn parse_asset_name(catalogue: &Catalogue, name: &str) -> Option<(String, Option<String>)> {
    let mut best: Option<(&crate::catalogue::Algorithm, &str)> = None;
    for algorithm in catalogue.algorithms() {
        let Some(head) = name.get(..algorithm.name.len()) else {
            continue;
        };
        if !head.eq_ignore_ascii_case(&algorithm.name) {
            continue;
        }
        let Some(rest) = name.get(algorithm.name.len()..) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with('-')) {
            continue;
        }
        if best.is_none_or(|(b, _)| algorithm.name.len() > b.name.len()) {
            best = Some((algorithm, rest));
        }
    }
    let (algorithm, rest) = best?;
    let parameter_set = match rest.strip_prefix('-') {
        Some("") => return None,
        Some(set) => Some(set.to_owned()),
        None => algorithm
            .parameter_sets
            .iter()
            .find(|p| p.id.eq_ignore_ascii_case(&algorithm.name))
            .map(|p| p.id.clone()),
    };
    Some((algorithm.name.clone(), parameter_set))
}

/// The CycloneDX `algorithmProperties` and OID of an asset of `algorithm` with
/// `parameter_set`, from the catalogue. With a parameter set this is
/// [`Entry::algorithm_properties`](crate::catalogue::Entry::algorithm_properties) and the set's OID;
/// without one, the algorithm's primitive, mode, padding and crypto functions only (no
/// parameter set, no curve, no security levels, no OID). An unknown algorithm or parameter set is an error, never a default.
pub fn algorithm_properties(
    catalogue: &Catalogue,
    algorithm: &str,
    parameter_set: Option<&str>,
) -> Result<(AlgorithmProperties, Option<String>), LookupError> {
    match parameter_set {
        Some(set) => {
            let entry = catalogue.lookup(algorithm, set)?;
            Ok((entry.algorithm_properties(), entry.oid().map(str::to_owned)))
        }
        None => {
            let found =
                catalogue
                    .algorithm(algorithm)
                    .ok_or_else(|| LookupError::UnknownAlgorithm {
                        name: algorithm.to_owned(),
                    })?;
            let properties = AlgorithmProperties {
                primitive: Some(found.primitive),
                mode: found.mode,
                padding: found.padding.map(Into::into),
                crypto_functions: found.crypto_functions.iter().copied().collect(),
                ..Default::default()
            };
            Ok((properties, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_names_and_their_parse_round_trip() {
        let catalogue = Catalogue::builtin().unwrap();
        for (algorithm, set, name) in [
            ("AES-CBC", Some("128"), "AES-CBC-128"),
            ("AES-CBC", None, "AES-CBC"),
            ("ECDSA", Some("secp256r1"), "ECDSA-secp256r1"),
            ("HMAC", Some("SHA-256"), "HMAC-SHA-256"),
            ("SHA2", Some("512/256"), "SHA2-512/256"),
            ("Ed25519", Some("Ed25519"), "Ed25519"),
            ("X25519", Some("X25519"), "X25519"),
            ("HSS", Some("LMS_SHA256_M32_H10"), "HSS-LMS_SHA256_M32_H10"),
            (
                "XMSS-MT",
                Some("XMSSMT-SHA2_20/2_256"),
                "XMSS-MT-XMSSMT-SHA2_20/2_256",
            ),
            ("ML-DSA", Some("44"), "ML-DSA-44"),
        ] {
            assert_eq!(asset_name(algorithm, set), name);
            assert_eq!(
                parse_asset_name(&catalogue, name),
                Some((algorithm.to_owned(), set.map(str::to_owned))),
                "{name}"
            );
        }
        // Case is ignored and the catalogue spelling returned.
        assert_eq!(
            parse_asset_name(&catalogue, "aes-gcm-256"),
            Some(("AES-GCM".to_owned(), Some("256".to_owned())))
        );
        for name in [
            "",
            "-",
            "AES",
            "AES-CBC-",
            "SHA-1",
            "MD5",
            "AESCBC-128",
            "ECDHE",
        ] {
            assert_eq!(parse_asset_name(&catalogue, name), None, "{name}");
        }
    }

    #[test]
    fn algorithm_properties_with_and_without_a_parameter_set() {
        let catalogue = Catalogue::builtin().unwrap();
        let (sized, oid) = algorithm_properties(&catalogue, "AES-GCM", Some("128")).unwrap();
        let entry = catalogue.lookup("AES-GCM", "128").unwrap();
        assert_eq!(sized, entry.algorithm_properties());
        assert_eq!(oid.as_deref(), entry.oid());
        let (bare, oid) = algorithm_properties(&catalogue, "AES-GCM", None).unwrap();
        assert_eq!(bare.primitive, sized.primitive);
        assert_eq!(bare.mode, sized.mode);
        assert_eq!(bare.crypto_functions, sized.crypto_functions);
        assert_eq!(bare.parameter_set_identifier, None);
        assert_eq!(bare.classical_security_level, None);
        assert_eq!(bare.nist_quantum_security_level, None);
        assert_eq!(bare.padding, None);
        assert_eq!(oid, None);
        // RSA without a size keeps the algorithm's padding: PKCS #1 v1.5 as `pkcs1v15`, PSS as
        // CycloneDX `other`, OAEP as `oaep`, the same as with a size.
        for (algorithm, padding) in [
            ("RSA-PKCS1v15", rollcall_core::model::Padding::Pkcs1v15),
            ("RSA-PSS", rollcall_core::model::Padding::Other),
            ("RSA-OAEP", rollcall_core::model::Padding::Oaep),
        ] {
            let (bare, oid) = algorithm_properties(&catalogue, algorithm, None).unwrap();
            assert_eq!(bare.padding, Some(padding), "{algorithm}");
            assert_eq!(bare.parameter_set_identifier, None, "{algorithm}");
            assert_eq!(oid, None);
            let (sized, _) = algorithm_properties(&catalogue, algorithm, Some("2048")).unwrap();
            assert_eq!(sized.padding, bare.padding, "{algorithm}");
        }
        assert!(matches!(
            algorithm_properties(&catalogue, "MD5", None),
            Err(LookupError::UnknownAlgorithm { .. })
        ));
        assert!(matches!(
            algorithm_properties(&catalogue, "AES-GCM", Some("64")),
            Err(LookupError::UnknownParameterSet { .. })
        ));
    }
}
