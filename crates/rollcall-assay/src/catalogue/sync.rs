//! Comparing rollcall's catalogue with a copy (cbom-infra's). See the
//! [export contract](super#export-contract).

use std::collections::BTreeMap;
use std::fmt;

use super::{Algorithm, Catalogue, ParameterSet};

/// One (algorithm, parameter set), as `(name, id)`; the name as the file spells it.
pub type Key = (String, String);

/// What [`compare`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comparison {
    /// The (algorithm, parameter set)s in both catalogues, with our spelling of the name, sorted.
    pub shared: Vec<Key>,
    /// Those only in ours, sorted.
    pub only_ours: Vec<Key>,
    /// Those only in theirs, with their spelling, sorted.
    pub only_theirs: Vec<Key>,
    /// Every field that differs on a shared entry, sorted.
    pub disagreements: Vec<Disagreement>,
}

impl Comparison {
    /// Whether every shared entry agrees.
    pub fn agrees(&self) -> bool {
        self.disagreements.is_empty()
    }
}

/// A field that differs between the two catalogues on a shared entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Disagreement {
    /// The entry's name, as ours spells it.
    pub algorithm: String,
    /// The parameter set, for a parameter-set field (`None` for an entry field).
    pub parameter_set: Option<String>,
    /// The field, as the catalogue names it, e.g. `nist_quantum_security_level`.
    pub field: &'static str,
    /// Our value, as text.
    pub ours: String,
    /// Their value, as text.
    pub theirs: String,
}

impl fmt::Display for Disagreement {
    /// `AES-GCM/128 nist_quantum_security_level: ours 1, theirs 3`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.algorithm)?;
        if let Some(set) = &self.parameter_set {
            write!(f, "/{set}")?;
        }
        write!(
            f,
            " {}: ours {}, theirs {}",
            self.field, self.ours, self.theirs
        )
    }
}

fn opt<T: fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "(none)".to_owned(), |v| v.to_string())
}

fn list<T: fmt::Display>(values: &[T]) -> String {
    let items: Vec<String> = values.iter().map(ToString::to_string).collect();
    format!("[{}]", items.join(", "))
}

/// The entry-level fields, as text: every field but `name`, `parameter_sets` and `line`.
fn algorithm_fields(a: &Algorithm) -> [(&'static str, String); 7] {
    [
        ("family", a.family.clone()),
        ("primitive", a.primitive.to_string()),
        ("mode", opt(a.mode)),
        ("padding", opt(a.padding)),
        ("crypto_functions", list(&a.crypto_functions)),
        ("quantum_risk", a.quantum_risk.to_string()),
        ("standards", list(&a.standards)),
    ]
}

/// The parameter-set fields, as text: every field but `id` and the prose `source`.
fn parameter_set_fields(p: &ParameterSet) -> [(&'static str, String); 4] {
    [
        (
            "classical_security_level",
            p.classical_security_level.to_string(),
        ),
        (
            "nist_quantum_security_level",
            p.nist_quantum_security_level.get().to_string(),
        ),
        ("curve", opt(p.curve.as_deref())),
        ("oid", opt(p.oid.as_deref())),
    ]
}

fn differences<const N: usize>(
    ours: [(&'static str, String); N],
    theirs: [(&'static str, String); N],
    algorithm: &str,
    parameter_set: Option<&str>,
    out: &mut Vec<Disagreement>,
) {
    for ((field, ours), (_, theirs)) in ours.into_iter().zip(theirs) {
        if ours != theirs {
            out.push(Disagreement {
                algorithm: algorithm.to_owned(),
                parameter_set: parameter_set.map(str::to_owned),
                field,
                ours,
                theirs,
            });
        }
    }
}

/// Compares `ours` with `theirs` on their shared entries: an (algorithm, parameter set) is
/// shared when both have the name (ASCII case ignored) and the id. On a shared entry every field
/// must agree except `source`; entry-level fields are compared once per entry with at least one
/// shared parameter set. Entries in only one catalogue are listed, not counted as disagreements.
pub fn compare(ours: &Catalogue, theirs: &Catalogue) -> Comparison {
    let mut comparison = Comparison::default();
    let by_name: BTreeMap<String, &Algorithm> = theirs
        .algorithms()
        .iter()
        .map(|a| (a.name.to_ascii_lowercase(), a))
        .collect();
    for ours_algorithm in ours.algorithms() {
        let theirs_algorithm = by_name.get(&ours_algorithm.name.to_ascii_lowercase());
        let mut any_shared = false;
        for set in &ours_algorithm.parameter_sets {
            let key = (ours_algorithm.name.clone(), set.id.clone());
            match theirs_algorithm.and_then(|t| t.parameter_set(&set.id)) {
                Some(their_set) => {
                    any_shared = true;
                    differences(
                        parameter_set_fields(set),
                        parameter_set_fields(their_set),
                        &ours_algorithm.name,
                        Some(&set.id),
                        &mut comparison.disagreements,
                    );
                    comparison.shared.push(key);
                }
                None => comparison.only_ours.push(key),
            }
        }
        if any_shared && let Some(theirs_algorithm) = theirs_algorithm {
            differences(
                algorithm_fields(ours_algorithm),
                algorithm_fields(theirs_algorithm),
                &ours_algorithm.name,
                None,
                &mut comparison.disagreements,
            );
        }
    }
    for theirs_algorithm in theirs.algorithms() {
        let ours_algorithm = ours.algorithm(&theirs_algorithm.name);
        for set in &theirs_algorithm.parameter_sets {
            if ours_algorithm
                .and_then(|o| o.parameter_set(&set.id))
                .is_none()
            {
                comparison
                    .only_theirs
                    .push((theirs_algorithm.name.clone(), set.id.clone()));
            }
        }
    }
    comparison.shared.sort();
    comparison.only_ours.sort();
    comparison.only_theirs.sort();
    comparison.disagreements.sort();
    comparison
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "\
format: rollcall-algorithms/1
algorithms:
  - name: AES-GCM
    family: AES
    primitive: ae
    mode: gcm
    crypto_functions: [decrypt, encrypt, tag]
    quantum_risk: grover-weakened
    standards: [FIPS 197]
    parameter_sets:
      - id: \"128\"
        classical_security_level: 128
        nist_quantum_security_level: 1
        oid: 2.16.840.1.101.3.4.1.6
        source: \"ours\"
      - id: \"256\"
        classical_security_level: 256
        nist_quantum_security_level: 5
        source: \"ours\"
  - name: ECDSA
    family: ECDSA
    primitive: signature
    quantum_risk: shor-broken
    standards: [FIPS 186-5]
    parameter_sets:
      - id: \"secp256r1\"
        classical_security_level: 128
        nist_quantum_security_level: 0
        curve: secp256r1
        source: \"ours\"
  - name: RSA-PSS
    family: RSA
    primitive: signature
    padding: pss
    quantum_risk: shor-broken
    standards: [FIPS 186-5]
    parameter_sets:
      - id: \"2048\"
        classical_security_level: 112
        nist_quantum_security_level: 0
        source: \"ours\"
";

    fn load(text: &str) -> Catalogue {
        Catalogue::load_str("t.yaml", text).unwrap()
    }

    #[test]
    fn compare_reports_only_shared_entries_and_ignores_source() {
        // Theirs: AES-GCM/128 only (different source, name in another case), ECDSA without the
        // shared set, and an entry of their own.
        let theirs = OURS
            .replace("source: \"ours\"", "source: \"cbom-infra's own words\"")
            .replace("name: AES-GCM", "name: aes-gcm")
            .replace(
                "      - id: \"256\"\n        classical_security_level: 256\n        \
                 nist_quantum_security_level: 5\n        source: \"cbom-infra's own words\"\n",
                "",
            )
            .replace("id: \"secp256r1\"", "id: \"secp384r1\"")
            .replace("name: RSA-PSS", "name: SM4")
            .replace("    padding: pss\n", "");
        let comparison = compare(&load(OURS), &load(&theirs));
        assert_eq!(
            comparison.shared,
            vec![("AES-GCM".to_owned(), "128".to_owned())]
        );
        assert_eq!(
            comparison.only_ours,
            vec![
                ("AES-GCM".to_owned(), "256".to_owned()),
                ("ECDSA".to_owned(), "secp256r1".to_owned()),
                ("RSA-PSS".to_owned(), "2048".to_owned()),
            ]
        );
        assert_eq!(
            comparison.only_theirs,
            vec![
                ("ECDSA".to_owned(), "secp384r1".to_owned()),
                ("SM4".to_owned(), "2048".to_owned()),
            ]
        );
        // ECDSA shares no set, so its entry fields are not compared; sources never are.
        assert!(comparison.agrees(), "{:?}", comparison.disagreements);
    }

    #[test]
    fn compare_reports_each_kind_of_disagreement() {
        let theirs = OURS
            .replace("family: AES", "family: Rijndael")
            .replace("primitive: ae", "primitive: block-cipher")
            .replace("mode: gcm", "mode: ccm")
            .replace("padding: pss", "padding: oaep")
            .replace("[decrypt, encrypt, tag]", "[decrypt, encrypt]")
            .replace("quantum_risk: grover-weakened", "quantum_risk: pq-safe")
            .replace(
                "nist_quantum_security_level: 1",
                "nist_quantum_security_level: 3",
            )
            .replace("standards: [FIPS 197]", "standards: [FIPS 197, SP 800-38D]")
            .replace(
                "classical_security_level: 112",
                "classical_security_level: 128",
            )
            .replace("curve: secp256r1", "curve: P-256")
            .replace(
                "oid: 2.16.840.1.101.3.4.1.6",
                "oid: 2.16.840.1.101.3.4.1.46",
            );
        let comparison = compare(&load(OURS), &load(&theirs));
        assert_eq!(comparison.only_ours, Vec::<Key>::new());
        assert_eq!(comparison.only_theirs, Vec::<Key>::new());
        let lines: Vec<String> = comparison
            .disagreements
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            lines,
            vec![
                "AES-GCM crypto_functions: ours [decrypt, encrypt, tag], theirs [decrypt, encrypt]",
                "AES-GCM family: ours AES, theirs Rijndael",
                "AES-GCM mode: ours gcm, theirs ccm",
                "AES-GCM primitive: ours ae, theirs block-cipher",
                "AES-GCM quantum_risk: ours grover-weakened, theirs pq-safe",
                "AES-GCM standards: ours [FIPS 197], theirs [FIPS 197, SP 800-38D]",
                "AES-GCM/128 nist_quantum_security_level: ours 1, theirs 3",
                "AES-GCM/128 oid: ours 2.16.840.1.101.3.4.1.6, theirs 2.16.840.1.101.3.4.1.46",
                "ECDSA/secp256r1 curve: ours secp256r1, theirs P-256",
                "RSA-PSS padding: ours pss, theirs oaep",
                "RSA-PSS/2048 classical_security_level: ours 112, theirs 128",
            ]
        );
        assert!(!comparison.agrees());
        // A field present on one side only.
        let theirs = OURS.replace("        oid: 2.16.840.1.101.3.4.1.6\n", "");
        let comparison = compare(&load(OURS), &load(&theirs));
        assert_eq!(
            comparison
                .disagreements
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["AES-GCM/128 oid: ours 2.16.840.1.101.3.4.1.6, theirs (none)"]
        );
    }

    #[test]
    fn compare_with_itself_shares_everything() {
        let ours = Catalogue::builtin().unwrap();
        let comparison = compare(&ours, &ours);
        assert!(comparison.agrees());
        assert!(comparison.only_ours.is_empty() && comparison.only_theirs.is_empty());
        assert_eq!(comparison.shared.len(), ours.entries().count());
    }
}
