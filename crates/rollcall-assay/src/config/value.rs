//! What a Kconfig option is set to, as the configuration detectors read it.
//!
//! [`option`] reads one symbol of a parsed `.config` or `sdkconfig` (rollcall-core's panic-free
//! [`kconfig::parse`](rollcall_core::zephyr::kconfig::parse)):
//!
//! | Line | [`OptionValue`] |
//! |------|-----------------|
//! | `CONFIG_X=y`, `CONFIG_X=m` | [`On`](OptionValue::On) |
//! | `CONFIG_X=n`, `# CONFIG_X is not set` | [`Off`](OptionValue::Off), with its line |
//! | no line for `CONFIG_X` | [`Absent`](OptionValue::Absent): unknown, never off |
//! | `CONFIG_X=2048`, `CONFIG_X=0x800` | [`Int`](OptionValue::Int) |
//! | `CONFIG_X="RSA"` | [`Str`](OptionValue::Str), unescaped |
//!
//! Only an explicit [`Off`](OptionValue::Off) feeds the compiled-out list: a symbol that is not in
//! the file at all says nothing about whether the code is built. A number too large for an
//! `i64` reads as [`Str`](OptionValue::Str) (its text), so a rule that wants an integer reports it
//! rather than misreading it.

use rollcall_core::zephyr::kconfig::{Kconfig, KconfigValue};

/// One option's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionValue {
    /// `=y` or `=m`.
    On,
    /// `=n` or `# SYMBOL is not set`.
    Off {
        /// The 1-based line that says so.
        explicit_line: u32,
    },
    /// The symbol is not in the file.
    Absent,
    /// A decimal or `0x` hex integer.
    Int(i64),
    /// A string (or an integer too large for an `i64`, as written).
    Str(String),
}

impl OptionValue {
    /// Whether the option is `y` or `m`.
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On)
    }

    /// The line of an explicit off, if it is one.
    pub fn explicit_off(&self) -> Option<u32> {
        match self {
            Self::Off { explicit_line } => Some(*explicit_line),
            _ => None,
        }
    }

    /// What kind of value it is, in words, for notes: `y`, `n`, `absent`, `an integer`, `a
    /// string`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::On => "y",
            Self::Off { .. } => "n",
            Self::Absent => "absent",
            Self::Int(_) => "an integer",
            Self::Str(_) => "a string",
        }
    }
}

/// The value of `symbol` in `config`.
pub fn option(config: &Kconfig, symbol: &str) -> OptionValue {
    let Some(entry) = config.get(symbol) else {
        return OptionValue::Absent;
    };
    match &entry.value {
        KconfigValue::Bool(true) | KconfigValue::Module => OptionValue::On,
        KconfigValue::Bool(false) => OptionValue::Off {
            explicit_line: entry.line,
        },
        KconfigValue::Int(text) => text
            .parse::<i64>()
            .map_or_else(|_| OptionValue::Str(text.clone()), OptionValue::Int),
        KconfigValue::Hex(text) => {
            let digits = text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .unwrap_or(text);
            i64::from_str_radix(digits, 16)
                .map_or_else(|_| OptionValue::Str(text.clone()), OptionValue::Int)
        }
        KconfigValue::Str(text) => OptionValue::Str(text.clone()),
    }
}

/// The 1-based line `symbol` is set on, if it is in `config`.
pub fn line(config: &Kconfig, symbol: &str) -> Option<u32> {
    config.get(symbol).map(|e| e.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rollcall_core::zephyr::kconfig;

    use crate::catalogue::Catalogue;
    use crate::config::detect::evaluate;
    use crate::config::rules::RuleSet;
    use crate::config::{ConfigFile, ImageKey};
    use rollcall_core::model::ImageKind;

    /// TP2: `=y`, `=n`, `=m`, decimal and hex integers, strings and `# X is not set` lines,
    /// with absent distinct from off; a string where an integer belongs gives a note and an
    /// unsized asset; an integer where a bool belongs gives a note and no asset.
    #[test]
    fn option_values_y_n_m_int_string_and_not_set() {
        let text = "\
CONFIG_A=y
CONFIG_B=n
CONFIG_C=m
# CONFIG_D is not set
CONFIG_E=2048
CONFIG_F=0x800
CONFIG_G=\"RSA\"
CONFIG_H=\"say \\\"hi\\\"\"
CONFIG_I=-3
CONFIG_J=99999999999999999999
CONFIG_K=0xFFFFFFFFFFFFFFFFFF
CONFIG_L=\"\"
";
        let config = kconfig::parse(text).unwrap();
        assert_eq!(option(&config, "CONFIG_A"), OptionValue::On);
        assert_eq!(
            option(&config, "CONFIG_B"),
            OptionValue::Off { explicit_line: 2 }
        );
        assert_eq!(option(&config, "CONFIG_C"), OptionValue::On);
        assert_eq!(
            option(&config, "CONFIG_D"),
            OptionValue::Off { explicit_line: 4 }
        );
        assert_eq!(option(&config, "CONFIG_E"), OptionValue::Int(2048));
        assert_eq!(option(&config, "CONFIG_F"), OptionValue::Int(2048));
        assert_eq!(option(&config, "CONFIG_G"), OptionValue::Str("RSA".into()));
        assert_eq!(
            option(&config, "CONFIG_H"),
            OptionValue::Str("say \"hi\"".into())
        );
        assert_eq!(option(&config, "CONFIG_I"), OptionValue::Int(-3));
        // Too large for an i64: kept as text, never a panic or a wrapped number.
        assert_eq!(
            option(&config, "CONFIG_J"),
            OptionValue::Str("99999999999999999999".into())
        );
        assert_eq!(
            option(&config, "CONFIG_K"),
            OptionValue::Str("0xFFFFFFFFFFFFFFFFFF".into())
        );
        assert_eq!(option(&config, "CONFIG_L"), OptionValue::Str(String::new()));
        // Absent is not off.
        assert_eq!(option(&config, "CONFIG_NOPE"), OptionValue::Absent);
        assert_eq!(option(&config, "CONFIG_NOPE").explicit_off(), None);
        assert_eq!(option(&config, "CONFIG_B").explicit_off(), Some(2));
        assert!(option(&config, "CONFIG_A").is_on());
        assert!(!option(&config, "CONFIG_E").is_on());
        assert_eq!(line(&config, "CONFIG_G"), Some(7));
        assert_eq!(line(&config, "CONFIG_NOPE"), None);
        // The later assignment wins, as in Kconfiglib.
        let again = kconfig::parse("CONFIG_A=y\n# CONFIG_A is not set\n").unwrap();
        assert_eq!(
            option(&again, "CONFIG_A"),
            OptionValue::Off { explicit_line: 2 }
        );

        // Through the detector: MCUboot's RSA key length as a string is a note and an unsized
        // RSA-PSS; as an integer it sizes the asset; a bool symbol set to an integer is a note.
        let catalogue = Catalogue::builtin().unwrap();
        let rules = RuleSet::builtin_zephyr().unwrap();
        let file = ConfigFile::new("mcuboot/zephyr/.config");
        let image = ImageKey::new(ImageKind::Bootloader, "mcuboot", None);
        let names = |text: &str| {
            let config = kconfig::parse(text).unwrap();
            let found = evaluate(&rules, &config, &file, &image, &catalogue);
            let names: Vec<String> = found.assets.keys().map(|k| k.name.clone()).collect();
            (names, found.notes)
        };
        let (assets, notes) =
            names("CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\nCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=2048\n");
        assert_eq!(assets, ["RSA-PSS-2048"]);
        assert!(notes.is_empty(), "{notes:?}");
        let (assets, notes) = names(
            "CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\nCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=\"2048\"\n",
        );
        assert_eq!(assets, ["RSA-PSS"]);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with(
                "mcuboot/zephyr/.config:2: CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN is a string"
            ),
            "{notes:?}"
        );
        let (assets, notes) = names("CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\n");
        assert_eq!(assets, ["RSA-PSS"], "absent length: unsized, no note");
        assert!(notes.is_empty(), "{notes:?}");
        let (assets, notes) = names("CONFIG_BOOT_SIGNATURE_TYPE_RSA=1\n");
        assert!(assets.is_empty(), "{assets:?}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("CONFIG_BOOT_SIGNATURE_TYPE_RSA is an integer; expected y or n"),
            "{notes:?}"
        );
        // A length the catalogue has no parameter set for: a note and an unsized asset.
        let (assets, notes) =
            names("CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\nCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=1024\n");
        assert_eq!(assets, ["RSA-PSS"]);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("1024"), "{notes:?}");
    }
}
