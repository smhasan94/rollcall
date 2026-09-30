//! The document timestamp (`metadata.timestamp`).

use std::fmt;
use std::str::FromStr;

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use super::ParseError;

/// An RFC 3339 date-time in UTC, as written to `metadata.timestamp`.
///
/// Always normalised: converted to UTC and written with a `Z` suffix, so two spellings of the
/// same instant produce the same bytes. Fractional seconds are kept when given (without
/// trailing zeros); [`Timestamp::now`] has none.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(String);

impl Timestamp {
    /// Parses an RFC 3339 date-time (e.g. `2026-01-02T03:04:05Z` or
    /// `2026-01-02T05:04:05+02:00`) and normalises it to UTC. A date-time without an offset,
    /// an impossible date, or an instant whose UTC year is outside `0000..=9999` is an error.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let err = |reason: String| ParseError::Timestamp {
            input: input.to_owned(),
            reason,
        };
        let parsed = OffsetDateTime::parse(input, &Rfc3339).map_err(|e| err(e.to_string()))?;
        let text = parsed
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|e| err(e.to_string()))?;
        Ok(Self(text))
    }

    /// The current time in UTC, to the whole second.
    pub fn now() -> Self {
        let now = OffsetDateTime::now_utc();
        let now = now.replace_nanosecond(0).unwrap_or(now);
        // Formatting a present-day UTC instant (four-digit year, UTC offset) cannot fail; the
        // fallback only keeps this function total.
        Self(
            now.format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        )
    }

    /// The normalised RFC 3339 text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_rfc3339_and_normalises() {
        for (input, expected) in [
            ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z"),
            ("2026-01-02T03:04:05z", "2026-01-02T03:04:05Z"),
            ("2026-01-02t03:04:05Z", "2026-01-02T03:04:05Z"),
            ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05Z"),
            ("2026-01-02T05:04:05+02:00", "2026-01-02T03:04:05Z"),
            ("2026-01-01T23:04:05-04:00", "2026-01-02T03:04:05Z"),
            ("2026-01-02T03:04:05.500Z", "2026-01-02T03:04:05.5Z"),
        ] {
            let ts = Timestamp::parse(input).unwrap();
            assert_eq!(ts.as_str(), expected, "{input}");
            assert_eq!(ts.to_string(), expected);
            assert_eq!(input.parse::<Timestamp>().unwrap(), ts);
            // Normalised text is a fixed point.
            assert_eq!(Timestamp::parse(expected).unwrap(), ts);
        }
    }

    #[test]
    fn parse_rejects_invalid_dates_and_missing_offset() {
        for input in [
            "",
            "yesterday",
            "2026-01-02",
            "2026-01-02T03:04:05",
            "2026-01-02 03:04:05",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-02T24:00:00Z",
            "2026-01-02T03:04:05+25:00",
            "0000-01-01T00:00:00+01:00",
            "2026-01-02T03:04:05Z ",
            "\u{0}",
        ] {
            let err = Timestamp::parse(input).unwrap_err();
            assert!(err.to_string().contains("timestamp"), "{input:?}: {err}");
        }
    }

    #[test]
    fn now_is_utc_whole_seconds() {
        let now = Timestamp::now();
        let text = now.as_str();
        assert_eq!(text.len(), "2026-01-02T03:04:05Z".len(), "{text}");
        assert!(text.ends_with('Z'), "{text}");
        assert!(!text.contains('.'), "{text}");
        assert_eq!(Timestamp::parse(text).unwrap(), now);
    }
}
