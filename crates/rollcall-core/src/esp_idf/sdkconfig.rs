//! Parser for a project's `sdkconfig`, ESP-IDF's Kconfig output.
//!
//! An `sdkconfig` has the syntax of a Kconfiglib `.config` (ESP-IDF generates it with
//! `kconfgen`, built on Kconfiglib), so it is parsed by the same panic-free parser as
//! Zephyr's ([`crate::zephyr::kconfig::parse`]); see there for the accepted lines. On top of
//! it this reads:
//!
//! - the chip, `CONFIG_IDF_TARGET="esp32"` ([`SdkConfig::target`]);
//! - the ESP-IDF version in the generated header comment, `# Espressif IoT Development
//!   Framework (ESP-IDF) 5.5.1 Project Configuration` ([`SdkConfig::header_version`]);
//! - which Bluetooth host is enabled ([`SdkConfig::bt_hosts`]).

use crate::zephyr::kconfig::{self, Kconfig, KconfigError};

/// The prefix of the header comment that names the ESP-IDF version.
const HEADER_PREFIX: &str = "# Espressif IoT Development Framework (ESP-IDF) ";
/// Its suffix.
const HEADER_SUFFIX: &str = " Project Configuration";

/// A parsed `sdkconfig`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SdkConfig {
    /// Every symbol.
    pub config: Kconfig,
    /// The ESP-IDF version in the header comment, and its line.
    header_version: Option<(String, u32)>,
}

/// Parses an `sdkconfig`.
pub fn parse(text: &str) -> Result<SdkConfig, KconfigError> {
    let config = kconfig::parse(text)?;
    let header_version = text.split('\n').enumerate().find_map(|(index, raw)| {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let version = line
            .strip_prefix(HEADER_PREFIX)?
            .strip_suffix(HEADER_SUFFIX)?
            .trim();
        let number = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        (!version.is_empty() && !version.contains(char::is_whitespace))
            .then(|| (version.to_owned(), number))
    });
    Ok(SdkConfig {
        config,
        header_version,
    })
}

impl SdkConfig {
    /// `CONFIG_IDF_TARGET` and its line.
    pub fn target(&self) -> Option<(&str, u32)> {
        let entry = self.config.get("CONFIG_IDF_TARGET")?;
        self.config
            .string("CONFIG_IDF_TARGET")
            .filter(|t| !t.is_empty())
            .map(|t| (t, entry.line))
    }

    /// The ESP-IDF version the header comment names, and its line.
    pub fn header_version(&self) -> Option<(&str, u32)> {
        self.header_version.as_ref().map(|(v, l)| (v.as_str(), *l))
    }

    /// Whether `symbol` is `y` or `m`.
    pub fn is_set(&self, symbol: &str) -> bool {
        self.config.is_set(symbol)
    }

    /// The line `symbol` is assigned on, if it is.
    pub fn line(&self, symbol: &str) -> Option<u32> {
        self.config.get(symbol).map(|e| e.line)
    }

    /// The enabled Bluetooth hosts, in name order: `bluedroid` for
    /// `CONFIG_BT_BLUEDROID_ENABLED`, `nimble` for `CONFIG_BT_NIMBLE_ENABLED`, each only with
    /// `CONFIG_BT_ENABLED`.
    pub fn bt_hosts(&self) -> Vec<&'static str> {
        if !self.is_set("CONFIG_BT_ENABLED") {
            return Vec::new();
        }
        [
            ("CONFIG_BT_BLUEDROID_ENABLED", "bluedroid"),
            ("CONFIG_BT_NIMBLE_ENABLED", "nimble"),
        ]
        .into_iter()
        .filter(|(symbol, _)| self.is_set(symbol))
        .map(|(_, host)| host)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zephyr::kconfig::KconfigValue;
    use proptest::prelude::*;

    /// The shapes of a real ESP-IDF 5.5 `sdkconfig`: the generated header, menu comments,
    /// bools, `is not set`, strings, hex, decimal and negative ints, and the deprecated-options
    /// tail.
    const SDKCONFIG: &str = "\
#
# Automatically generated file. DO NOT EDIT.
# Espressif IoT Development Framework (ESP-IDF) 5.5.1 Project Configuration
#
CONFIG_SOC_CAPS_ECO_VER_MAX=301
CONFIG_IDF_TARGET_ARCH_XTENSA=y
CONFIG_IDF_TARGET=\"esp32\"
CONFIG_IDF_FIRMWARE_CHIP_ID=0x0000

#
# Bluetooth
#
CONFIG_BT_ENABLED=y
CONFIG_BT_NIMBLE_ENABLED=y
# CONFIG_BT_BLUEDROID_ENABLED is not set
CONFIG_ESP_WIFI_ENABLED=y
CONFIG_LWIP_ENABLE=y
CONFIG_MBEDTLS_TLS_ENABLED=y
CONFIG_ESP_TLS_USING_MBEDTLS=y
CONFIG_LWIP_TCP_MSL=60000
CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE=-1
CONFIG_PARTITION_TABLE_FILENAME=\"partitions_singleapp.csv\"
# end of Bluetooth

# Deprecated options for backward compatibility
# CONFIG_APP_BUILD_TYPE_ELF_RAM is not set
CONFIG_FLASHMODE_DIO=y
# End of deprecated options
";

    #[test]
    fn parses_esp_idf_sdkconfig_shapes() {
        let c = parse(SDKCONFIG).unwrap();
        assert_eq!(c.header_version(), Some(("5.5.1", 3)));
        let value = |n: &str| c.config.get(n).unwrap().value.clone();
        assert_eq!(
            value("CONFIG_IDF_FIRMWARE_CHIP_ID"),
            KconfigValue::Hex("0x0000".into())
        );
        assert_eq!(
            value("CONFIG_LWIP_TCP_MSL"),
            KconfigValue::Int("60000".into())
        );
        assert_eq!(
            value("CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE"),
            KconfigValue::Int("-1".into())
        );
        assert_eq!(
            value("CONFIG_APP_BUILD_TYPE_ELF_RAM"),
            KconfigValue::Bool(false)
        );
        // CRLF is accepted too.
        assert_eq!(parse(&SDKCONFIG.replace('\n', "\r\n")).unwrap(), c);
        // No header: no version, still a config.
        let bare = parse("CONFIG_IDF_TARGET=\"esp32c3\"\n").unwrap();
        assert_eq!(bare.header_version(), None);
        assert_eq!(bare.target(), Some(("esp32c3", 1)));
    }

    #[test]
    fn subsystem_symbols_and_target_are_read() {
        let c = parse(SDKCONFIG).unwrap();
        assert_eq!(c.target(), Some(("esp32", 7)));
        assert!(c.is_set("CONFIG_ESP_WIFI_ENABLED"));
        assert!(c.is_set("CONFIG_MBEDTLS_TLS_ENABLED"));
        assert!(!c.is_set("CONFIG_BT_BLUEDROID_ENABLED"));
        assert_eq!(c.line("CONFIG_LWIP_ENABLE"), Some(17));
        assert_eq!(c.bt_hosts(), ["nimble"]);
        let both = parse(
            "CONFIG_BT_ENABLED=y\nCONFIG_BT_BLUEDROID_ENABLED=y\nCONFIG_BT_NIMBLE_ENABLED=y\n",
        )
        .unwrap();
        assert_eq!(both.bt_hosts(), ["bluedroid", "nimble"]);
        let off = parse("# CONFIG_BT_ENABLED is not set\nCONFIG_BT_NIMBLE_ENABLED=y\n").unwrap();
        assert!(off.bt_hosts().is_empty());
        assert_eq!(parse("CONFIG_IDF_TARGET=\"\"\n").unwrap().target(), None);
        assert_eq!(parse("CONFIG_IDF_TARGET=1\n").unwrap().target(), None);
    }

    #[test]
    fn malformed_sdkconfig_is_an_error_with_line() {
        for (text, line) in [
            ("CONFIG_A=y\nnot a line\n", 2),
            ("CONFIG_A=y\nCONFIG_B=\"open\n", 2),
            ("CONFIG_A=maybe\n", 1),
            ("CONFIG-A=y\n", 1),
            ("\u{feff}CONFIG_A=y\n", 1),
        ] {
            let err = parse(text).unwrap_err();
            let (KconfigError::UnknownSyntax { line: got }
            | KconfigError::UnterminatedString { line: got }) = err;
            assert_eq!(got, line, "{text:?}: {err}");
        }
        // Truncated anywhere: parsed or an error, never a panic.
        for n in 0..SDKCONFIG.len() {
            if let Some(prefix) = SDKCONFIG.get(..n) {
                let _ = parse(prefix);
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(text in "\\PC{0,200}") {
            let _ = parse(&text);
        }
    }
}
