//! Vulnerability severity levels, normalised across scanners.
//!
//! grype writes `Critical`, `High`, `Medium`, `Low`, `Negligible` or `Unknown`; osv-scanner
//! passes on the advisory database's word (GitHub's `CRITICAL`, `HIGH`, `MODERATE`, `LOW`).
//! [`normalise_severity`] maps either onto the five levels of [`Severity`], ignoring ASCII
//! case:
//!
//! | Severity   | Scanner words           |
//! |------------|-------------------------|
//! | `critical` | `critical`              |
//! | `high`     | `high`                  |
//! | `medium`   | `medium`, `moderate`    |
//! | `low`      | `low`, `negligible`     |
//! | `unknown`  | anything else, or none  |
//!
//! `unknown` is the lowest level: a gate such as `rollcall scan --fail-on high` does not fail
//! on it, only `--fail-on unknown` does. Callers that gate on severity should say how many
//! findings had an unknown severity, so they are not overlooked.

use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// A normalised severity. Ordered from the lowest ([`Severity::Unknown`]) to the highest
/// ([`Severity::Critical`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// No severity, or a word rollcall does not recognise.
    Unknown,
    /// Low (grype's `Negligible` too).
    Low,
    /// Medium (GitHub's `MODERATE` too).
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

impl Severity {
    /// Every level, lowest first.
    pub const ALL: [Severity; 5] = [
        Severity::Unknown,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    /// The level's lowercase name, e.g. `high`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Severity {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A severity name that is not one of the five levels.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown severity {0:?} (expected critical, high, medium, low or unknown)")]
pub struct ParseSeverityError(pub String);

impl FromStr for Severity {
    type Err = ParseSeverityError;

    /// Parses a level's own name ([`Severity::as_str`], ignoring ASCII case). Unlike
    /// [`normalise_severity`], an unrecognised word is an error: this is for names a user
    /// types, such as a `--fail-on` threshold.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|level| level.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| ParseSeverityError(s.to_owned()))
    }
}

/// Maps a scanner's severity word onto a [`Severity`] (see the [module docs](self)).
pub fn normalise_severity(text: Option<&str>) -> Severity {
    let Some(text) = text else {
        return Severity::Unknown;
    };
    let word = text.trim();
    let is = |name: &str| word.eq_ignore_ascii_case(name);
    if is("critical") {
        Severity::Critical
    } else if is("high") {
        Severity::High
    } else if is("medium") || is("moderate") {
        Severity::Medium
    } else if is("low") || is("negligible") {
        Severity::Low
    } else {
        Severity::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping_matches_spec() {
        let cases = [
            (Some("Critical"), Severity::Critical),
            (Some("CRITICAL"), Severity::Critical),
            (Some("High"), Severity::High),
            (Some("high"), Severity::High),
            (Some("Medium"), Severity::Medium),
            (Some("MODERATE"), Severity::Medium),
            (Some("moderate"), Severity::Medium),
            (Some("Low"), Severity::Low),
            (Some("Negligible"), Severity::Low),
            (Some(" low "), Severity::Low),
            (Some("Unknown"), Severity::Unknown),
            (Some(""), Severity::Unknown),
            (Some("7.5"), Severity::Unknown),
            (Some("severe"), Severity::Unknown),
            (None, Severity::Unknown),
        ];
        for (text, want) in cases {
            assert_eq!(normalise_severity(text), want, "{text:?}");
        }
    }

    #[test]
    fn levels_are_ordered_lowest_first_with_unknown_lowest() {
        let mut sorted = Severity::ALL;
        sorted.sort();
        assert_eq!(sorted, Severity::ALL);
        assert!(Severity::Unknown < Severity::Low);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn names_round_trip_and_others_are_errors() {
        for level in Severity::ALL {
            assert_eq!(level.as_str().parse::<Severity>(), Ok(level));
            assert_eq!(level.as_str().to_uppercase().parse::<Severity>(), Ok(level));
            assert_eq!(
                serde_json::to_string(&level).unwrap(),
                format!("\"{level}\"")
            );
        }
        for bad in ["", "moderate", "negligible", "none", "7"] {
            assert!(bad.parse::<Severity>().is_err(), "{bad:?}");
        }
    }
}
