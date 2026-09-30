//! Parser for a Kconfig `.config` file.
//!
//! Accepted lines, as Kconfiglib writes them:
//!
//! - `SYMBOL=y`, `SYMBOL=n`, `SYMBOL=m`, `SYMBOL=<decimal>`, `SYMBOL=0x<hex>`,
//!   `SYMBOL="<string>"` (with `\"` and `\\` escapes), where `SYMBOL` is `[A-Za-z0-9_]+`
//!   (so both `CONFIG_…` and sysbuild's `SB_CONFIG_…` are accepted);
//! - `# SYMBOL is not set`, recorded as `n`;
//! - other `#` comments and blank lines, which are ignored.
//!
//! Anything else is [`KconfigError::UnknownSyntax`]. A symbol assigned twice keeps the later
//! value, as in Kconfiglib. CRLF line endings are accepted.

use std::collections::BTreeMap;

/// A parsed `.config`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Kconfig {
    /// Every symbol, by name.
    pub symbols: BTreeMap<String, KconfigEntry>,
}

/// One symbol's value and the line it was (last) assigned on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KconfigEntry {
    /// The value.
    pub value: KconfigValue,
    /// The 1-based line.
    pub line: u32,
}

/// A symbol value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KconfigValue {
    /// `y` (true), or `n` / `# … is not set` (false).
    Bool(bool),
    /// Tristate `m`.
    Module,
    /// A decimal integer, as written.
    Int(String),
    /// A `0x` hex integer, as written.
    Hex(String),
    /// A string, unescaped.
    Str(String),
}

/// Why a `.config` could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KconfigError {
    /// A line is neither an assignment, a `# … is not set` line, a comment nor blank.
    #[error(
        "line {line}: unknown syntax (expected `SYMBOL=value`, `# SYMBOL is not set` or a comment)"
    )]
    UnknownSyntax {
        /// The line.
        line: u32,
    },
    /// A string value has no closing quote.
    #[error("line {line}: unterminated string value")]
    UnterminatedString {
        /// The line.
        line: u32,
    },
}

fn is_symbol(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses a `.config`.
pub fn parse(text: &str) -> Result<Kconfig, KconfigError> {
    let mut symbols = BTreeMap::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        let content = raw.strip_suffix('\r').unwrap_or(raw);
        if content.trim().is_empty() {
            continue;
        }
        if let Some(comment) = content.strip_prefix('#') {
            let unset = comment
                .strip_prefix(' ')
                .and_then(|c| c.strip_suffix(" is not set"))
                .filter(|name| is_symbol(name));
            if let Some(name) = unset {
                symbols.insert(
                    name.to_owned(),
                    KconfigEntry {
                        value: KconfigValue::Bool(false),
                        line,
                    },
                );
            }
            continue;
        }
        let Some((name, value)) = content.split_once('=') else {
            return Err(KconfigError::UnknownSyntax { line });
        };
        if !is_symbol(name) {
            return Err(KconfigError::UnknownSyntax { line });
        }
        let value = parse_value(value, line)?;
        symbols.insert(name.to_owned(), KconfigEntry { value, line });
    }
    Ok(Kconfig { symbols })
}

fn parse_value(value: &str, line: u32) -> Result<KconfigValue, KconfigError> {
    match value {
        "y" => return Ok(KconfigValue::Bool(true)),
        "n" => return Ok(KconfigValue::Bool(false)),
        "m" => return Ok(KconfigValue::Module),
        _ => {}
    }
    if let Some(body) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = body.chars();
        loop {
            match chars.next() {
                None => return Err(KconfigError::UnterminatedString { line }),
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some(c) => out.push(c),
                    None => return Err(KconfigError::UnterminatedString { line }),
                },
                Some(c) => out.push(c),
            }
        }
        if chars.next().is_some() {
            return Err(KconfigError::UnknownSyntax { line });
        }
        return Ok(KconfigValue::Str(out));
    }
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(KconfigValue::Hex(value.to_owned()));
        }
        return Err(KconfigError::UnknownSyntax { line });
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        return Ok(KconfigValue::Int(value.to_owned()));
    }
    Err(KconfigError::UnknownSyntax { line })
}

impl Kconfig {
    /// The entry for `name`.
    pub fn get(&self, name: &str) -> Option<&KconfigEntry> {
        self.symbols.get(name)
    }

    /// True if `name` is `y` or `m`.
    pub fn is_set(&self, name: &str) -> bool {
        matches!(
            self.get(name).map(|e| &e.value),
            Some(KconfigValue::Bool(true) | KconfigValue::Module)
        )
    }

    /// The string value of `name`, if it is a string.
    pub fn string(&self, name: &str) -> Option<&str> {
        match self.get(name).map(|e| &e.value) {
            Some(KconfigValue::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// Every entry whose name starts with `prefix`, in name order.
    pub fn entries_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a KconfigEntry)> + 'a {
        self.symbols
            .range(prefix.to_owned()..)
            .take_while(move |(name, _)| name.starts_with(prefix))
            .map(|(name, entry)| (name.as_str(), entry))
    }

    /// The Zephyr SDK `major.minor` from `CONFIG_TOOLCHAIN_ZEPHYR_<M>_<N>=y`, with its line.
    /// `CONFIG_TOOLCHAIN_ZEPHYR_SUPPORTS_*` and anything not two numbers are ignored.
    pub fn zephyr_sdk_version(&self) -> Option<(String, u32)> {
        const PREFIX: &str = "CONFIG_TOOLCHAIN_ZEPHYR_";
        self.entries_with_prefix(PREFIX).find_map(|(name, entry)| {
            let rest = name.strip_prefix(PREFIX)?;
            let (major, minor) = rest.split_once('_')?;
            let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
            (numeric(major) && numeric(minor) && entry.value == KconfigValue::Bool(true))
                .then(|| (format!("{major}.{minor}"), entry.line))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_bool_int_hex_and_string_values() {
        let config = parse(
            "CONFIG_A=y\nCONFIG_B=n\nCONFIG_C=m\nCONFIG_D=42\nCONFIG_E=-7\nCONFIG_F=0x1F\nCONFIG_G=\"nrf52840\"\n",
        )
        .unwrap();
        let value = |n: &str| config.get(n).unwrap().value.clone();
        assert_eq!(value("CONFIG_A"), KconfigValue::Bool(true));
        assert_eq!(value("CONFIG_B"), KconfigValue::Bool(false));
        assert_eq!(value("CONFIG_C"), KconfigValue::Module);
        assert_eq!(value("CONFIG_D"), KconfigValue::Int("42".into()));
        assert_eq!(value("CONFIG_E"), KconfigValue::Int("-7".into()));
        assert_eq!(value("CONFIG_F"), KconfigValue::Hex("0x1F".into()));
        assert_eq!(config.string("CONFIG_G"), Some("nrf52840"));
        assert!(config.is_set("CONFIG_A") && config.is_set("CONFIG_C"));
        assert!(!config.is_set("CONFIG_B") && !config.is_set("CONFIG_MISSING"));
        assert_eq!(config.get("CONFIG_G").unwrap().line, 7);
        assert_eq!(
            parse("CONFIG_EMPTY=\"\"\n").unwrap().string("CONFIG_EMPTY"),
            Some("")
        );
    }

    #[test]
    fn not_set_comment_is_recorded() {
        let config = parse("# CONFIG_X is not set\n").unwrap();
        assert_eq!(
            config.get("CONFIG_X"),
            Some(&KconfigEntry {
                value: KconfigValue::Bool(false),
                line: 1
            })
        );
    }

    #[test]
    fn string_escapes_are_unescaped() {
        let config = parse(r#"CONFIG_S="a \"quoted\" \\ path""#).unwrap();
        assert_eq!(config.string("CONFIG_S"), Some(r#"a "quoted" \ path"#));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let config = parse("#\n# Modules\n#\n\n   \n# end of Modules\nCONFIG_A=y\n").unwrap();
        assert_eq!(config.symbols.len(), 1);
        let crlf = parse("# c\r\nCONFIG_A=y\r\nCONFIG_S=\"x\"\r\n").unwrap();
        assert_eq!(crlf.string("CONFIG_S"), Some("x"));
    }

    #[test]
    fn sb_config_prefix_is_accepted() {
        let config =
            parse("SB_CONFIG_BOARD=\"nrf52840dk\"\n# SB_CONFIG_BOOT_ENCRYPTION is not set\n")
                .unwrap();
        assert_eq!(config.string("SB_CONFIG_BOARD"), Some("nrf52840dk"));
        let prefixed: Vec<&str> = config
            .entries_with_prefix("SB_CONFIG_B")
            .map(|(n, _)| n)
            .collect();
        assert_eq!(prefixed, ["SB_CONFIG_BOARD", "SB_CONFIG_BOOT_ENCRYPTION"]);
    }

    #[test]
    fn later_assignment_wins() {
        let config = parse("CONFIG_A=1\n# CONFIG_A is not set\nCONFIG_A=2\n").unwrap();
        assert_eq!(
            config.get("CONFIG_A"),
            Some(&KconfigEntry {
                value: KconfigValue::Int("2".into()),
                line: 3
            })
        );
    }

    #[test]
    fn unknown_syntax_is_error_with_line() {
        for (text, line) in [
            ("CONFIG_A=y\nCONFIG_FOO\n", 2),
            ("CONFIG_X=\n", 1),
            ("foo bar\n", 1),
            ("CONFIG A=y\n", 1),
            ("CONFIG_A=yes\n", 1),
            ("CONFIG_A=0xZZ\n", 1),
            ("CONFIG_A=\"x\" trailing\n", 1),
            ("=y\n", 1),
            (" CONFIG_A=y\n", 1),
        ] {
            assert_eq!(
                parse(text),
                Err(KconfigError::UnknownSyntax { line }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn unterminated_string_is_error() {
        assert_eq!(
            parse("CONFIG_A=y\nCONFIG_S=\"open\n"),
            Err(KconfigError::UnterminatedString { line: 2 })
        );
        assert_eq!(
            parse("CONFIG_S=\"ends in escape\\"),
            Err(KconfigError::UnterminatedString { line: 1 })
        );
    }

    #[test]
    fn zephyr_sdk_version_is_extracted_and_supports_symbols_ignored() {
        let config = parse(
            "CONFIG_TOOLCHAIN_ZEPHYR_SUPPORTS_THREAD_LOCAL_STORAGE=y\n\
             CONFIG_TOOLCHAIN_ZEPHYR_1_0=y\n\
             CONFIG_TOOLCHAIN_ZEPHYR_SUPPORTS_GNU_EXTENSIONS=y\n",
        )
        .unwrap();
        assert_eq!(config.zephyr_sdk_version(), Some(("1.0".into(), 2)));
        let unset = parse("# CONFIG_TOOLCHAIN_ZEPHYR_0_17 is not set\n").unwrap();
        assert_eq!(unset.zephyr_sdk_version(), None);
        assert_eq!(Kconfig::default().zephyr_sdk_version(), None);
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "(?s)(CONFIG_[A-Z_0-9]{0,6}|# |=|\"|\\\\|y|0x|-|[ -~]|\n|\r|.){0,120}") {
            let _ = parse(&text);
        }
    }
}
