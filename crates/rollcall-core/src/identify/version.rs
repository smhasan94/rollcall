//! The identifier database's version (`db_version`) and the minimum this rollcall accepts.
//!
//! `db_version` is semver. A database release bumps MINOR when it adds modules, PATCH when it
//! fixes entries, and MAJOR only with a schema change, which needs a rollcall release. So a
//! database is compatible iff its version is at least [`MIN_DB_VERSION`] and its MAJOR is
//! [`SUPPORTED_DB_MAJOR`]: any newer 1.x database works with this rollcall unchanged.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer};

/// The oldest database this rollcall accepts.
pub const MIN_DB_VERSION: &str = "1.0.0";

/// The database MAJOR version this rollcall reads (the schema generation).
pub const SUPPORTED_DB_MAJOR: u64 = 1;

/// A database version: `db_version`, semver (`1.2.0`; a pre-release such as `1.2.0-rc.1` is
/// allowed and orders before `1.2.0`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DbVersion(semver::Version);

impl DbVersion {
    /// The MAJOR component.
    pub fn major(&self) -> u64 {
        self.0.major
    }

    /// [`MIN_DB_VERSION`] as a version.
    pub fn minimum() -> Self {
        // A literal that is known to parse; a test pins it.
        Self(semver::Version::new(1, 0, 0))
    }
}

impl fmt::Display for DbVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why a string is not a database version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not a semver version such as 1.2.0: {reason}")]
pub struct DbVersionError {
    /// The rejected text.
    pub value: String,
    /// What semver said.
    pub reason: String,
}

impl FromStr for DbVersion {
    type Err = DbVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        semver::Version::parse(s)
            .map(Self)
            .map_err(|e| DbVersionError {
                value: s.to_owned(),
                reason: e.to_string(),
            })
    }
}

impl<'de> Deserialize<'de> for DbVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(de::Error::custom)
    }
}

/// Why a database version is not accepted by this rollcall.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Incompatible {
    /// Older than [`MIN_DB_VERSION`].
    #[error("db_version {found} is older than {MIN_DB_VERSION}, the minimum this rollcall accepts")]
    TooOld {
        /// The database's version.
        found: DbVersion,
    },
    /// Another MAJOR version (another schema generation).
    #[error(
        "db_version {found} is major version {}; this rollcall reads major version {SUPPORTED_DB_MAJOR} (a newer rollcall is needed)",
        found.major()
    )]
    OtherMajor {
        /// The database's version.
        found: DbVersion,
    },
}

/// Whether this rollcall accepts a database of `version`.
pub fn check_compatible(version: &DbVersion) -> Result<(), Incompatible> {
    if *version < DbVersion::minimum() {
        return Err(Incompatible::TooOld {
            found: version.clone(),
        });
    }
    if version.major() != SUPPORTED_DB_MAJOR {
        return Err(Incompatible::OtherMajor {
            found: version.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_is_the_documented_constant() {
        assert_eq!(DbVersion::minimum().to_string(), MIN_DB_VERSION);
        assert_eq!(DbVersion::minimum().major(), SUPPORTED_DB_MAJOR);
    }

    #[test]
    fn malformed_versions_are_errors_not_panics() {
        for bad in [
            "", "1", "1.0", "v1.0.0", "1.0.0.0", "01.0.0", "1.0.0-", "x.y.z", " 1.0.0", "1.0.0 ",
            "\u{0}", "١.٠.٠",
        ] {
            let e = bad.parse::<DbVersion>().unwrap_err();
            assert!(
                e.to_string().contains("is not a semver version"),
                "{bad:?}: {e}"
            );
        }
    }
}
