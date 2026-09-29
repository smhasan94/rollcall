//! The model's documentation explains evidence and confidence.

const MODEL_DOCS: &str = include_str!("../src/model/mod.rs");

#[test]
fn model_docs_explain_evidence_and_confidence() {
    for heading in [
        "//! # Hierarchy",
        "//! # Evidence",
        "//! # Confidence",
        "//! # Determinism and bom-refs",
        "//! # Internal JSON form",
    ] {
        assert!(
            MODEL_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?}"
        );
    }
    let section = |name: &str| -> String {
        MODEL_DOCS
            .lines()
            .skip_while(|l| l.trim_end() != format!("//! # {name}"))
            .skip(1)
            .take_while(|l| !l.starts_with("//! # "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let evidence = section("Evidence");
    for term in ["source", "technique", "occurrence", "confidence"] {
        assert!(evidence.contains(term), "Evidence section lacks {term:?}");
    }
    let confidence = section("Confidence");
    for term in ["basis points", "maximum"] {
        assert!(
            confidence.contains(term),
            "Confidence section lacks {term:?}"
        );
    }
}
