//! Validated scalar types of the identifier database: purl and cpe templates, version
//! patterns and relative file paths.
//!
//! Each has a hand-written [`Deserialize`] whose visitor validates the scalar, so a rejection
//! carries the scalar's own line and column in the YAML error.
//!
//! # Templates
//!
//! A template is a purl or a CPE 2.3 formatted string in which `{version}` stands for the
//! derived upstream version. `{version}` must appear at least once; any other `{` or `}` is an
//! error (an unknown placeholder or an unbalanced brace). At load time the template is
//! rendered with the probe version `0.0.0` and the result must be a valid purl (parsed by the
//! `packageurl` crate) or CPE 2.3 formatted string ([`super::cpe::parse`]).
//!
//! When rendering, the version is made safe for its context first: in a purl every character
//! outside `[A-Za-z0-9._~-]` is percent-encoded (the result is then canonicalised by
//! [`Purl::new`]); in a CPE every character outside `[A-Za-z0-9._-]` is `\`-escaped.

use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::de::{self, Deserialize, Deserializer, Visitor};

use super::cpe;
use crate::model::{Cpe, IdError, Purl};

/// The placeholder for the upstream version.
pub const PLACEHOLDER: &str = "{version}";
/// The version a template is rendered with at load time.
const PROBE: &str = "0.0.0";
/// The compiled-size limit for a version pattern.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// Checks the placeholder grammar: at least one `{version}`, no other braces.
fn check_placeholders(template: &str) -> Result<(), String> {
    let mut rest = template;
    let mut found = 0usize;
    while let Some(open) = rest.find(['{', '}']) {
        let tail = rest.get(open..).unwrap_or_default();
        if let Some(after) = tail.strip_prefix(PLACEHOLDER) {
            found += 1;
            rest = after;
            continue;
        }
        return Err(if tail.starts_with('}') {
            "unbalanced '}'; the only placeholder is {version}".to_owned()
        } else {
            match tail.find('}') {
                Some(close) => format!(
                    "unknown placeholder {}; the only placeholder is {{version}}",
                    tail.get(..=close).unwrap_or(tail)
                ),
                None => "unbalanced '{'; the only placeholder is {version}".to_owned(),
            }
        });
    }
    if found == 0 {
        return Err("template has no {version} placeholder".to_owned());
    }
    Ok(())
}

/// Percent-encodes every byte outside `[A-Za-z0-9._~-]`.
fn purl_escape(version: &str) -> String {
    let mut out = String::with_capacity(version.len());
    for b in version.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `\`-escapes every character outside `[A-Za-z0-9._-]`.
fn cpe_escape(version: &str) -> String {
    let mut out = String::with_capacity(version.len());
    for c in version.chars() {
        if !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A purl with `{version}` placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurlTemplate(String);

impl PurlTemplate {
    /// Validates a purl template.
    pub fn parse(template: &str) -> Result<Self, String> {
        check_placeholders(template)?;
        let probe = template.replace(PLACEHOLDER, PROBE);
        Purl::new(&probe).map_err(|e| format!("not a valid purl template: {e}"))?;
        Ok(Self(template.to_owned()))
    }

    /// The template as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The purl for `version`.
    pub fn render(&self, version: &str) -> Result<Purl, IdError> {
        Purl::new(&self.0.replace(PLACEHOLDER, &purl_escape(version)))
    }
}

/// A CPE 2.3 formatted string with `{version}` placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeTemplate(String);

impl CpeTemplate {
    /// Validates a CPE template.
    pub fn parse(template: &str) -> Result<Self, String> {
        check_placeholders(template)?;
        let probe = template.replace(PLACEHOLDER, PROBE);
        cpe::parse(&probe).map_err(|e| format!("not a valid CPE 2.3 template: {e}"))?;
        Ok(Self(template.to_owned()))
    }

    /// The template as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The CPE for `version`.
    pub fn render(&self, version: &str) -> Result<Cpe, IdError> {
        let text = self.0.replace(PLACEHOLDER, &cpe_escape(version));
        cpe::parse(&text).map_err(|e| IdError::Cpe {
            input: text.clone(),
            reason: e.reason,
        })?;
        Cpe::new(&text)
    }
}

/// A regular expression with a named group `version`.
#[derive(Debug, Clone)]
pub struct Pattern {
    regex: Regex,
    source: String,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for Pattern {}

impl Pattern {
    /// Compiles a version pattern (size-limited) and checks it has a `version` group.
    pub fn parse(source: &str) -> Result<Self, String> {
        let regex = RegexBuilder::new(source)
            .size_limit(PATTERN_SIZE_LIMIT)
            .build()
            .map_err(|e| format!("invalid regular expression: {e}"))?;
        if !regex.capture_names().any(|n| n == Some("version")) {
            return Err("pattern has no named group (?P<version>…)".to_owned());
        }
        Ok(Self {
            regex,
            source: source.to_owned(),
        })
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The `version` group of the first match in `text`, if non-empty after trimming.
    pub fn version_in(&self, text: &str) -> Option<String> {
        self.regex
            .captures_iter(text)
            .filter_map(|c| c.name("version").map(|m| m.as_str().trim().to_owned()))
            .find(|v| !v.is_empty())
    }
}

/// A forward-slash path relative to a module's root, without `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPath(String);

impl RelPath {
    /// Validates a relative path.
    pub fn parse(path: &str) -> Result<Self, String> {
        if path.is_empty() {
            return Err("file must not be empty".to_owned());
        }
        if path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
            return Err(
                "file must be a forward-slash path relative to the module, without control characters"
                    .to_owned(),
            );
        }
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes.get(1) == Some(&b':') {
            return Err("file must be relative, not a drive path".to_owned());
        }
        if path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        {
            return Err("file must not contain empty, . or .. components".to_owned());
        }
        Ok(Self(path.to_owned()))
    }

    /// The path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A visitor for a string scalar validated by `parse`.
struct Checked<T> {
    expecting: &'static str,
    parse: fn(&str) -> Result<T, String>,
}

impl<T> Visitor<'_> for Checked<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<T, E> {
        (self.parse)(v).map_err(E::custom)
    }
}

macro_rules! checked_deserialize {
    ($ty:ty, $expecting:literal) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                d.deserialize_str(Checked {
                    expecting: $expecting,
                    parse: <$ty>::parse,
                })
            }
        }
    };
}

checked_deserialize!(PurlTemplate, "a purl template containing {version}");
checked_deserialize!(CpeTemplate, "a CPE 2.3 template containing {version}");
checked_deserialize!(Pattern, "a regular expression with a (?P<version>…) group");
checked_deserialize!(RelPath, "a relative file path");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_and_escaping() {
        // Grammar.
        assert!(check_placeholders("a{version}b{version}").is_ok());
        for (bad, needle) in [
            ("pkg:generic/x@1", "no {version}"),
            ("pkg:generic/x@{ver}", "unknown placeholder {ver}"),
            ("pkg:generic/x@{version", "unbalanced '{'"),
            ("pkg:generic/x@version}", "unbalanced '}'"),
            ("pkg:generic/x@{version}}", "unbalanced '}'"),
            ("pkg:generic/x@{{version}", "unknown placeholder {{version}"),
        ] {
            let e = check_placeholders(bad).unwrap_err();
            assert!(e.contains(needle), "{bad}: {e}");
        }

        // Purl: rendered, percent-encoded, canonicalised.
        let purl = PurlTemplate::parse("pkg:github/Mbed-TLS/mbedtls@v{version}").unwrap();
        assert_eq!(
            purl.render("4.1.0").unwrap().as_str(),
            "pkg:github/mbed-tls/mbedtls@v4.1.0"
        );
        let odd = purl.render("1.0#frag?x=y@z").unwrap();
        assert_eq!(
            odd.as_str(),
            "pkg:github/mbed-tls/mbedtls@v1.0%23frag%3Fx%3Dy%40z"
        );
        assert!(PurlTemplate::parse("pkg:x{version}").is_err());
        assert!(PurlTemplate::parse("not a purl {version}").is_err());

        // CPE: escaped, then checked against the 2.3 grammar.
        let cpe = CpeTemplate::parse("cpe:2.3:a:arm:mbed_tls:{version}:*:*:*:*:*:*:*").unwrap();
        assert_eq!(
            cpe.render("4.1.0").unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*"
        );
        assert_eq!(
            cpe.render("1.0:rc1+b*").unwrap().as_str(),
            "cpe:2.3:a:arm:mbed_tls:1.0\\:rc1\\+b\\*:*:*:*:*:*:*:*"
        );
        assert!(cpe.render("").is_err());
        assert!(cpe.render("é").is_err());
        assert!(CpeTemplate::parse("cpe:2.3:a:arm:{version}:*:*:*:*:*:*:*").is_err());
        assert!(CpeTemplate::parse("cpe:/a:arm:mbed_tls:{version}").is_err());

        // Patterns need a version group; paths must stay inside the module.
        assert!(Pattern::parse(r"^v(?P<version>\d+)$").is_ok());
        assert!(Pattern::parse(r"^v(\d+)$").is_err());
        assert!(Pattern::parse(r"(?P<version>").is_err());
        let p = Pattern::parse(r"VERSION (?P<version>[0-9.]*)").unwrap();
        assert_eq!(p.version_in("VERSION \nVERSION 1.2"), Some("1.2".into()));
        assert_eq!(p.version_in("nothing"), None);
        for good in ["include/version.h", "a.b/c"] {
            assert!(RelPath::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../b",
            "a//b",
            "a\\b",
            "C:x",
            "./a",
            "a\0",
        ] {
            assert!(RelPath::parse(bad).is_err(), "{bad:?}");
        }
    }
}
