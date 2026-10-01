//! Purl patterns (`match.purl`) and rule specificity.

use std::fmt;

use super::rules::Match;
use crate::model::Purl;

/// A purl, or a purl glob in which `*` matches any run of characters (including none).
///
/// A pattern without `*` is parsed and canonicalised like any [`Purl`], so it matches exactly
/// the purls that are equal to it. A pattern with `*` is **not** canonicalised: it is compared,
/// as written and case-sensitively, with the canonical form of the component's purl (in which,
/// for example, the type is lower-cased, as are the namespace and name of some types such as
/// `github`). Write glob patterns in canonical form, e.g. `pkg:github/mbed-tls/mbedtls@*`
/// rather than `pkg:GitHub/Mbed-TLS/mbedtls@*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurlPattern(String);

impl PurlPattern {
    /// Checks and stores a pattern: non-empty, starting with `pkg:`, without whitespace or
    /// control characters; and, without `*`, a valid purl.
    pub fn new(pattern: &str) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("purl pattern is empty".to_owned());
        }
        if !pattern.starts_with("pkg:") {
            return Err(format!("purl pattern {pattern:?} must start with `pkg:`"));
        }
        if pattern.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!(
                "purl pattern {pattern:?} contains whitespace or a control character"
            ));
        }
        if pattern.contains('*') {
            return Ok(Self(pattern.to_owned()));
        }
        Purl::new(pattern)
            .map(|purl| Self(purl.as_str().to_owned()))
            .map_err(|e| format!("purl pattern {pattern:?} is not a valid purl: {e}"))
    }

    /// True when the pattern has no `*`.
    pub fn is_exact(&self) -> bool {
        !self.0.contains('*')
    }

    /// Whether `purl` matches.
    pub fn matches(&self, purl: &Purl) -> bool {
        glob(self.0.as_bytes(), purl.as_str().as_bytes())
    }

    /// The pattern as stored.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PurlPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `*`-only glob match, iterative with a single backtrack point, so it runs in
/// O(pattern × text) time and constant space for any input.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match (pattern.get(p), text.get(t)) {
            (Some(b'*'), _) => {
                star = Some((p, t));
                p += 1;
            }
            (Some(a), Some(b)) if a == b => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|&b| b == b'*'))
}

/// How specific a rule's `match` is. Compared lexicographically: a rule naming CVEs beats one
/// that does not; then one with a version range beats one without; then the target: an exact
/// purl (3) beats a purl glob (2) beats a name or subsystem (1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Specificity {
    /// `match.cves` is given.
    pub cves: bool,
    /// `match.versions` is given.
    pub versions: bool,
    /// The target's rank: 3 exact purl, 2 purl glob, 1 name or subsystem.
    pub target: u8,
}

impl Specificity {
    /// The specificity of `m`.
    pub fn of(m: &Match) -> Self {
        let target = match &m.purl {
            Some(p) if p.is_exact() => 3,
            Some(_) => 2,
            None => 1,
        };
        Self {
            cves: !m.cves.is_empty(),
            versions: m.versions.is_some(),
            target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn purl(s: &str) -> Purl {
        Purl::new(s).unwrap()
    }

    #[test]
    fn exact_and_glob() {
        let exact = PurlPattern::new("pkg:github/mbed-tls/mbedtls@v2.28.0").unwrap();
        assert!(exact.is_exact());
        assert!(exact.matches(&purl("pkg:github/mbed-tls/mbedtls@v2.28.0")));
        assert!(!exact.matches(&purl("pkg:github/mbed-tls/mbedtls@v2.28.1")));

        let any = PurlPattern::new("pkg:github/mbed-tls/mbedtls@*").unwrap();
        assert!(!any.is_exact());
        assert!(any.matches(&purl("pkg:github/mbed-tls/mbedtls@v2.28.0")));
        assert!(!any.matches(&purl("pkg:github/zephyrproject-rtos/zephyr@v3.7.0")));

        let middle = PurlPattern::new("pkg:*/mbedtls@v2.*").unwrap();
        assert!(middle.matches(&purl("pkg:github/mbed-tls/mbedtls@v2.28.0")));
        assert!(!middle.matches(&purl("pkg:github/mbed-tls/mbedtls@v3.6.0")));
    }

    #[test]
    fn bad_patterns() {
        assert!(PurlPattern::new("").is_err());
        assert!(PurlPattern::new("mbedtls").is_err());
        assert!(PurlPattern::new("pkg:github/a b").is_err());
        assert!(PurlPattern::new("pkg:").is_err());
    }

    #[test]
    fn glob_basics() {
        assert!(glob(b"*", b""));
        assert!(glob(b"a*b*c", b"axxbyyc"));
        assert!(!glob(b"a*b*c", b"axxbyy"));
        assert!(glob(b"**", b"abc"));
        assert!(!glob(b"", b"a"));
    }

    proptest! {
        #[test]
        fn glob_never_panics_and_star_matches_all(p in "[a*]{0,12}", t in "[ab]{0,24}") {
            let _ = glob(p.as_bytes(), t.as_bytes());
            prop_assert!(glob(b"*", t.as_bytes()));
            prop_assert!(glob(t.as_bytes(), t.as_bytes()));
        }
    }
}
