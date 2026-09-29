//! Confidence in a fact, in basis points.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::ids::IdError;

/// How sure rollcall is of a fact, in basis points: `0` is no confidence, `10000` is certain.
///
/// Stored as an integer so ordering, equality and serialisation are exact and deterministic;
/// the JSON form is the integer (e.g. `9000` for 0.9).
///
/// **Combination rule: maximum.** When the same fact is reported more than once, or when a
/// node's overall confidence is asked for, the highest confidence wins. Independent sources
/// agreeing do not add up to more than the strongest single source; a weak source never
/// lowers a strong one.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(try_from = "u16", into = "u16")]
pub struct Confidence(u16);

impl Confidence {
    /// No confidence (0 basis points).
    pub const NONE: Self = Self(0);
    /// Full confidence (10000 basis points).
    pub const FULL: Self = Self(10_000);

    /// Builds a confidence from basis points; errors above 10000.
    pub fn new(basis_points: u16) -> Result<Self, IdError> {
        if basis_points > Self::FULL.0 {
            return Err(IdError::Confidence {
                input: basis_points.to_string(),
            });
        }
        Ok(Self(basis_points))
    }

    /// Builds a confidence from a fraction in `0.0..=1.0`, rounded to the nearest basis point.
    /// Errors on NaN, infinities and values outside the range.
    pub fn from_f64(fraction: f64) -> Result<Self, IdError> {
        if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
            return Err(IdError::Confidence {
                input: fraction.to_string(),
            });
        }
        let bp = (fraction * 10_000.0).round();
        // `bp` is within 0.0..=10000.0 here, so the conversion is exact.
        let bp = u16::try_from(bp as i64).map_err(|_| IdError::Confidence {
            input: fraction.to_string(),
        })?;
        Self::new(bp)
    }

    /// The confidence in basis points.
    pub fn basis_points(self) -> u16 {
        self.0
    }

    /// The confidence as a fraction (`basis_points / 10000`).
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / 10_000.0
    }

    /// Combines two confidences for the same fact: the maximum.
    pub fn combine(self, other: Self) -> Self {
        self.max(other)
    }
}

impl TryFrom<u16> for Confidence {
    type Error = IdError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Confidence> for u16 {
    fn from(value: Confidence) -> Self {
        value.0
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:04}", self.0 / 10_000, self.0 % 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_and_rounding() {
        assert_eq!(Confidence::new(10_000).unwrap(), Confidence::FULL);
        assert!(Confidence::new(10_001).is_err());
        assert_eq!(Confidence::from_f64(0.9).unwrap().basis_points(), 9000);
        assert_eq!(Confidence::from_f64(0.123_45).unwrap().basis_points(), 1235);
        assert_eq!(Confidence::from_f64(0.0).unwrap(), Confidence::NONE);
        assert!(Confidence::from_f64(1.000_1).is_err());
        assert!(Confidence::from_f64(-0.1).is_err());
        assert!(Confidence::from_f64(f64::NAN).is_err());
        assert!(Confidence::from_f64(f64::INFINITY).is_err());
        assert_eq!(Confidence::FULL.as_f64(), 1.0);
        assert_eq!(Confidence::new(9000).unwrap().to_string(), "0.9000");
    }

    #[test]
    fn combine_is_max() {
        let a = Confidence::new(3000).unwrap();
        let b = Confidence::new(7000).unwrap();
        assert_eq!(a.combine(b), b);
        assert_eq!(b.combine(a), b);
    }
}
