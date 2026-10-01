//! A strict parser for CPE 2.3 formatted strings (NISTIR 7695 §6.2).
//!
//! ```text
//! cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//! ```
//!
//! - 13 `:`-separated fields; a `\:` escape does not separate fields.
//! - `part` is `a`, `h`, `o`, `*` or `-`.
//! - `language` is `*`, `-`, or a language tag `xx`/`xxx` with an optional `-XX` region or
//!   `-NNN` area code.
//! - Every other attribute is `*` (ANY), `-` (NA) or a value: one or more of `[A-Za-z0-9._-]`
//!   or a `\` followed by one punctuation character, optionally preceded and followed by
//!   either a run of `?` or a single `*` (the only places those wildcards may appear
//!   unescaped).
//! - The whole string is printable ASCII without whitespace.
//!
//! This is the grammar of the official CPE 2.3 dictionary schema's `cpe23Type` pattern.
//! [`Cpe`](crate::model::Cpe) keeps its looser structural check (it also takes CPE 2.2 URIs,
//! which `west spdx` documents may carry); this parser is for identifier-database templates,
//! where only well-formed 2.3 names belong.

use std::fmt;

/// Why a string is not a CPE 2.3 formatted string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct CpeError {
    /// What is wrong.
    pub reason: &'static str,
}

fn err(reason: &'static str) -> CpeError {
    CpeError { reason }
}

/// The `part` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Part {
    /// `a`: an application.
    Application,
    /// `h`: hardware.
    Hardware,
    /// `o`: an operating system.
    OperatingSystem,
    /// `*`: any.
    Any,
    /// `-`: not applicable.
    Na,
}

/// One attribute value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attribute {
    /// `*`: any value.
    Any,
    /// `-`: not applicable.
    Na,
    /// A value, as written (escapes kept).
    Value(String),
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Na => f.write_str("-"),
            Self::Value(v) => f.write_str(v),
        }
    }
}

/// A parsed CPE 2.3 formatted string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cpe23 {
    /// `part`.
    pub part: Part,
    /// `vendor`.
    pub vendor: Attribute,
    /// `product`.
    pub product: Attribute,
    /// `version`.
    pub version: Attribute,
    /// `update`.
    pub update: Attribute,
    /// `edition`.
    pub edition: Attribute,
    /// `language`.
    pub language: Attribute,
    /// `sw_edition`.
    pub sw_edition: Attribute,
    /// `target_sw`.
    pub target_sw: Attribute,
    /// `target_hw`.
    pub target_hw: Attribute,
    /// `other`.
    pub other: Attribute,
}

/// Characters that may follow a `\` in a value.
const QUOTABLE: &str = "\\*?!\"#$%&'()+,/:;<=>@[]^`{|}~";

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

/// Splits on `:` not preceded by a `\` escape.
fn split_fields(input: &str) -> Result<Vec<&str>, CpeError> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (i, b) in input.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b':' {
            fields.push(
                input
                    .get(start..i)
                    .ok_or_else(|| err("bad field boundary"))?,
            );
            start = i + 1;
        }
    }
    if escaped {
        return Err(err("dangling escape at the end"));
    }
    fields.push(
        input
            .get(start..)
            .ok_or_else(|| err("bad field boundary"))?,
    );
    Ok(fields)
}

/// A value attribute: `(?*|*?) body+ (?*|*?)`.
fn avstring(field: &str) -> Result<Attribute, CpeError> {
    match field {
        "" => return Err(err("empty attribute; use * or -")),
        "*" => return Ok(Attribute::Any),
        "-" => return Ok(Attribute::Na),
        _ => {}
    }
    let bytes = field.as_bytes();
    let mut i = 0;
    // Leading wildcards: a run of `?`, or one `*`.
    if bytes.first() == Some(&b'*') {
        i = 1;
    } else {
        while bytes.get(i) == Some(&b'?') {
            i += 1;
        }
    }
    let mut body = 0;
    while let Some(&b) = bytes.get(i) {
        if is_unreserved(b) {
            i += 1;
            body += 1;
        } else if b == b'\\' {
            match bytes.get(i + 1) {
                Some(&q) if QUOTABLE.as_bytes().contains(&q) => {
                    i += 2;
                    body += 1;
                }
                _ => return Err(err("\\ must be followed by a punctuation character")),
            }
        } else {
            break;
        }
    }
    if body == 0 {
        return Err(err(
            "a value needs at least one character besides wildcards",
        ));
    }
    // Trailing wildcards: a run of `?`, or one `*`.
    match bytes.get(i) {
        None => {}
        Some(b'*') => i += 1,
        Some(b'?') => {
            while bytes.get(i) == Some(&b'?') {
                i += 1;
            }
        }
        Some(_) => {
            return Err(err(
                "a value may only contain A-Z a-z 0-9 . _ - and \\-escaped punctuation",
            ));
        }
    }
    if i != bytes.len() {
        return Err(err(
            "? and * may only appear at the start or end of a value",
        ));
    }
    Ok(Attribute::Value(field.to_owned()))
}

/// `*`, `-`, or `xx`/`xxx` with an optional `-XX` or `-NNN`.
fn language(field: &str) -> Result<Attribute, CpeError> {
    match field {
        "*" => return Ok(Attribute::Any),
        "-" => return Ok(Attribute::Na),
        _ => {}
    }
    let bad = || err("language must be *, - or a tag like en or en-us");
    let (lang, region) = match field.split_once('-') {
        Some((lang, region)) => (lang, Some(region)),
        None => (field, None),
    };
    if !(2..=3).contains(&lang.len()) || !lang.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(bad());
    }
    if let Some(region) = region {
        let alpha = region.len() == 2 && region.bytes().all(|b| b.is_ascii_alphabetic());
        let digits = region.len() == 3 && region.bytes().all(|b| b.is_ascii_digit());
        if !(alpha || digits) {
            return Err(bad());
        }
    }
    Ok(Attribute::Value(field.to_owned()))
}

/// Parses a CPE 2.3 formatted string. Never panics.
pub fn parse(input: &str) -> Result<Cpe23, CpeError> {
    if !input.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(err("must be printable ASCII without whitespace"));
    }
    let rest = input
        .strip_prefix("cpe:2.3:")
        .ok_or_else(|| err("must start with \"cpe:2.3:\""))?;
    let fields = split_fields(rest)?;
    let [
        part,
        vendor,
        product,
        version,
        update,
        edition,
        lang,
        sw_edition,
        target_sw,
        target_hw,
        other,
    ] = fields.as_slice()
    else {
        return Err(err("needs exactly 13 :-separated fields"));
    };
    let part = match *part {
        "a" => Part::Application,
        "h" => Part::Hardware,
        "o" => Part::OperatingSystem,
        "*" => Part::Any,
        "-" => Part::Na,
        _ => return Err(err("part must be a, h, o, * or -")),
    };
    Ok(Cpe23 {
        part,
        vendor: avstring(vendor)?,
        product: avstring(product)?,
        version: avstring(version)?,
        update: avstring(update)?,
        edition: avstring(edition)?,
        language: language(lang)?,
        sw_edition: avstring(sw_edition)?,
        target_sw: avstring(target_sw)?,
        target_hw: avstring(target_hw)?,
        other: avstring(other)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The `cpe23Type` pattern of the official CPE 2.3 dictionary schema, anchored.
    const OFFICIAL: &str = r##"^cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}$"##;

    #[test]
    fn cpe23_grammar_accepts_and_rejects() {
        let accepted = [
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:o:zephyrproject:zephyr:4.4.2:-:*:*:*:*:*:*",
            "cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:h:nordicsemi:nrf52840:-:*:*:*:*:*:*:*",
            "cpe:2.3:a:vendor:product:1.0\\:rc1:*:*:*:*:*:*:*",
            "cpe:2.3:a:vendor:product:1.0\\+build:*:*:*:*:*:*:*",
            "cpe:2.3:a:vendor:prod*:1.?:*:*:*:*:*:*:*",
            "cpe:2.3:a:vendor:*prod:??1:*:*:*:*:*:*:*",
            "cpe:2.3:*:-:-:-:-:-:-:-:-:-:-",
            "cpe:2.3:a:vendor:product:1.0:*:*:en-us:*:*:*:*",
            "cpe:2.3:a:vendor:product:1.0:*:*:es-419:*:*:*:*",
        ];
        let rejected = [
            "",
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*:*",
            "cpe:/a:arm:mbed_tls:4.1.0",
            "cpe:2.3:x:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed tls:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm::4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed+tls:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mb*ed:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:**:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:??:4.1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed:4.1.0\\:*:*:*:*:*:*:*\\",
            "cpe:2.3:a:arm:mbed:4.1.0\\a:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed:4.1.0:*:*:english:*:*:*:*",
            "cpe:2.3:a:arm:mbed:{version}:*:*:*:*:*:*:*",
            "cpe:2.3:a:arm:mbed:é:*:*:*:*:*:*:*",
        ];
        let official = regex::Regex::new(OFFICIAL).unwrap();
        for input in accepted {
            assert!(parse(input).is_ok(), "{input}: {:?}", parse(input));
            assert!(official.is_match(input), "official pattern rejects {input}");
        }
        for input in rejected {
            assert!(parse(input).is_err(), "{input} accepted");
        }
        let cpe = parse("cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(cpe.part, Part::Application);
        assert_eq!(cpe.vendor, Attribute::Value("arm".into()));
        assert_eq!(cpe.version.to_string(), "4.1.0");
        assert_eq!(cpe.update, Attribute::Any);
    }

    proptest! {
        /// The parser agrees with the official pattern on CPE-shaped strings, and never
        /// panics on arbitrary text.
        #[test]
        fn parser_agrees_with_official_pattern(
            fields in proptest::collection::vec("[a-z0-9_.*?\\\\:+-]{0,6}", 11),
            noise in ".{0,40}",
        ) {
            let official = regex::Regex::new(OFFICIAL).unwrap();
            let input = format!("cpe:2.3:{}", fields.join(":"));
            prop_assert_eq!(parse(&input).is_ok(), official.is_match(&input), "{}", input);
            let _ = parse(&noise);
        }
    }
}
