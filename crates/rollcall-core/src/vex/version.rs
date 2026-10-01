//! Lenient version parsing and semver ranges for `match.versions` and `version_in`.

use std::fmt;

use semver::{Version, VersionReq};

use crate::model::Component;

/// How a version string reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionKind {
    /// A plain release version, e.g. `2.28.0`, `v2.28` (→ `2.28.0`), `3` (→ `3.0.0`).
    Release(Version),
    /// A release core with a pre-release or build part, e.g. `v3.7.0-123-gabc` (git
    /// describe), `4.1.0-rc1` or `1.0.0+meta`. Not compared: it is not known which release
    /// it is.
    Qualified,
    /// Not a version at all, e.g. a git SHA (including an all-digit abbreviated one of 7 or
    /// more digits), a branch name, or empty.
    NotAVersion,
}

/// Classifies a version string. A leading `v`/`V` is dropped and a `major` or
/// `major.minor` core is padded with zeros. A single all-digit token of 7 or more digits
/// (an abbreviated SHA) is not a version.
pub fn classify_version(text: &str) -> VersionKind {
    let text = text.trim();
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    let split = text.find(['-', '+']).unwrap_or(text.len());
    let (core, rest) = text.split_at(split);
    let parts: Vec<&str> = core.split('.').collect();
    let numeric = |p: &&str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    if parts.is_empty() || parts.len() > 3 || !parts.iter().all(numeric) {
        return VersionKind::NotAVersion;
    }
    if parts.len() == 1 && core.len() >= 7 {
        return VersionKind::NotAVersion;
    }
    let mut padded = parts.join(".");
    for _ in parts.len()..3 {
        padded.push_str(".0");
    }
    padded.push_str(rest);
    match Version::parse(&padded) {
        Ok(v) if v.pre.is_empty() && v.build.is_empty() => VersionKind::Release(v),
        Ok(_) => VersionKind::Qualified,
        Err(_) => VersionKind::NotAVersion,
    }
}

/// The release version `text` names, if it names exactly one (see [`classify_version`]).
pub fn parse_version(text: &str) -> Option<Version> {
    match classify_version(text) {
        VersionKind::Release(v) => Some(v),
        VersionKind::Qualified | VersionKind::NotAVersion => None,
    }
}

/// The version a component is compared with: its `version` if that is a release version;
/// unknown (`None`) if it is a qualified one (pre-release, build or git-describe suffix);
/// otherwise (a SHA, or no version) the release version in its purl (`pkg:…@v4.1.0`), if any.
pub fn effective_version(component: &Component) -> Option<Version> {
    match component.version.as_deref().map(classify_version) {
        Some(VersionKind::Release(v)) => return Some(v),
        Some(VersionKind::Qualified) => return None,
        Some(VersionKind::NotAVersion) | None => {}
    }
    let purl = component.purl.as_ref()?;
    let (_, after) = purl.as_str().rsplit_once('@')?;
    let end = after.find(['?', '#']).unwrap_or(after.len());
    after.get(..end).and_then(parse_version)
}

/// A semver range as Cargo writes it, e.g. `>=2.28.0, <2.28.5`. A bare version (`2.28.0`)
/// means `^2.28.0`, as in Cargo.
#[derive(Debug, Clone)]
pub struct VersionRange {
    text: String,
    req: VersionReq,
}

impl VersionRange {
    /// Parses a range.
    pub fn parse(text: &str) -> Result<Self, semver::Error> {
        let req = VersionReq::parse(text)?;
        Ok(Self {
            text: text.trim().to_owned(),
            req,
        })
    }

    /// Whether `version` is in the range.
    pub fn contains(&self, version: &Version) -> bool {
        self.req.matches(version)
    }

    /// The range as written.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl PartialEq for VersionRange {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for VersionRange {}

impl fmt::Display for VersionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ComponentKind, Purl};

    #[test]
    fn lenient_versions() {
        assert_eq!(parse_version("2.28.0"), Some(Version::new(2, 28, 0)));
        assert_eq!(parse_version("v2.28"), Some(Version::new(2, 28, 0)));
        assert_eq!(parse_version("V3"), Some(Version::new(3, 0, 0)));
        assert_eq!(parse_version("4e0d9a1c0f3b2a1d"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("1..2"), None);
    }

    #[test]
    fn git_describe_and_prerelease_are_qualified() {
        for text in [
            "v3.7.0-123-gabc1234",
            "4.1.0-rc1",
            "1.0.0+build.5",
            "v2.28-rc2",
        ] {
            assert_eq!(classify_version(text), VersionKind::Qualified, "{text}");
            assert_eq!(parse_version(text), None, "{text}");
        }
        let mut c = Component::new(ComponentKind::Library, "zephyr")
            .unwrap()
            .with_version("v3.7.0-123-gabc1234");
        c.purl = Some(Purl::new("pkg:github/zephyrproject-rtos/zephyr@v3.7.0").unwrap());
        // The purl's tag is not used: the build is somewhere after v3.7.0.
        assert_eq!(effective_version(&c), None);
    }

    #[test]
    fn short_sha_digits_are_not_a_version() {
        for text in ["1234567", "20240917", "0123456789"] {
            assert_eq!(classify_version(text), VersionKind::NotAVersion, "{text}");
        }
        assert_eq!(parse_version("123456"), Some(Version::new(123456, 0, 0)));
        assert_eq!(parse_version("2024.9.17"), Some(Version::new(2024, 9, 17)));
    }

    #[test]
    fn effective_version_falls_back_to_purl() {
        let mut c = Component::new(ComponentKind::Library, "mbedtls")
            .unwrap()
            .with_version("85440ef5fffa95d0e9971e9163719189cf34d979");
        assert_eq!(effective_version(&c), None);
        c.purl = Some(Purl::new("pkg:github/mbed-tls/mbedtls@v4.1.0").unwrap());
        assert_eq!(effective_version(&c), Some(Version::new(4, 1, 0)));
    }

    #[test]
    fn ranges() {
        let r = VersionRange::parse(">=2.28.0, <2.28.5").unwrap();
        assert!(r.contains(&Version::new(2, 28, 0)));
        assert!(!r.contains(&Version::new(2, 28, 5)));
        assert_eq!(r.to_string(), ">=2.28.0, <2.28.5");
        assert!(VersionRange::parse("not a range").is_err());
    }
}
