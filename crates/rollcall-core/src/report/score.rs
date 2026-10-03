//! The readiness score: integer basis points, rounded down, so only a perfect result scores
//! 100. See the [module docs](super#score) for the formula.

use super::model::{Category, Score};

/// What the score is computed from.
pub(super) struct Counts {
    /// Every node.
    pub nodes: u64,
    /// Nodes with a purl or a CPE.
    pub identified: u64,
    /// Nodes with a hash.
    pub hashed: u64,
    /// Nodes with a licence.
    pub licensed: u64,
    /// Nodes with no regulator-profile finding (a document-level finding counts against
    /// the product).
    pub validated: u64,
    /// Whether the SBOM is valid CycloneDX 1.6.
    pub schema_valid: bool,
    /// Zephyr modules.
    pub modules: u64,
    /// Modules the identifier database resolved.
    pub modules_resolved: u64,
    /// With a scan: (joined findings that are not open, joined findings).
    pub vulnerabilities: Option<(u64, u64)>,
}

/// `weight × 10000 × numerator / denominator`, rounded down; the full weight for a zero
/// denominator.
fn earned(weight: u32, numerator: u64, denominator: u64) -> u64 {
    let full = u64::from(weight) * 10_000;
    if denominator == 0 {
        return full;
    }
    let value = u128::from(full) * u128::from(numerator.min(denominator)) / u128::from(denominator);
    u64::try_from(value).unwrap_or(full)
}

fn category(id: &'static str, weight: u32, numerator: u64, denominator: u64) -> Category {
    Category {
        id,
        weight,
        assessed: true,
        numerator,
        denominator,
        earned: earned(weight, numerator, denominator),
    }
}

/// The score from `counts`.
pub(super) fn score(counts: &Counts) -> Score {
    let mut validation = category("validation", 25, counts.validated, counts.nodes);
    if !counts.schema_valid {
        validation.earned = 0;
    }
    let vulnerabilities = match counts.vulnerabilities {
        Some((closed, joined)) => category("vulnerabilities", 10, closed, joined),
        None => Category {
            id: "vulnerabilities",
            weight: 10,
            assessed: false,
            numerator: 0,
            denominator: 0,
            earned: 0,
        },
    };
    let categories = vec![
        category("identified", 25, counts.identified, counts.nodes),
        category("hashed", 15, counts.hashed, counts.nodes),
        category("licensed", 15, counts.licensed, counts.nodes),
        validation,
        category("modules", 10, counts.modules_resolved, counts.modules),
        vulnerabilities,
    ];
    let weight: u32 = categories
        .iter()
        .filter(|c| c.assessed)
        .map(|c| c.weight)
        .sum();
    let earned: u64 = categories.iter().map(|c| c.earned).sum();
    // earned is in units of 1/10000 point; the score in basis points is earned / weight.
    let basis_points = if weight == 0 {
        0
    } else {
        u32::try_from(earned / u64::from(weight)).unwrap_or(10_000)
    };
    Score {
        value: basis_points / 100,
        basis_points,
        weight_assessed: weight,
        scan_supplied: counts.vulnerabilities.is_some(),
        categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perfect() -> Counts {
        Counts {
            nodes: 10,
            identified: 10,
            hashed: 10,
            licensed: 10,
            validated: 10,
            schema_valid: true,
            modules: 0,
            modules_resolved: 0,
            vulnerabilities: None,
        }
    }

    #[test]
    fn only_a_perfect_result_scores_100() {
        let s = score(&perfect());
        assert_eq!(
            (s.value, s.basis_points, s.weight_assessed),
            (100, 10_000, 90)
        );
        let mut almost = perfect();
        almost.nodes = 10_000;
        almost.identified = 10_000;
        almost.hashed = 10_000;
        almost.licensed = 9_999;
        almost.validated = 10_000;
        let s = score(&almost);
        assert_eq!(s.value, 99);
        assert!(s.basis_points < 10_000);
    }

    #[test]
    fn schema_violation_zeroes_validation_and_scan_renormalises() {
        let mut c = perfect();
        c.schema_valid = false;
        let s = score(&c);
        // 65 of 90 points: 7222 bp.
        assert_eq!(s.basis_points, 7222);
        let mut c = perfect();
        c.vulnerabilities = Some((1, 4));
        let s = score(&c);
        // 90 + 2.5 of 100 points.
        assert_eq!((s.basis_points, s.weight_assessed), (9250, 100));
        c.vulnerabilities = Some((0, 0));
        assert_eq!(score(&c).basis_points, 10_000);
    }
}
