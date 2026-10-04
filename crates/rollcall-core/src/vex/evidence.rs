//! Build evidence and the evaluation of `when` conditions against it.

use std::collections::{BTreeMap, BTreeSet};

use super::rules::Condition;
use super::version::effective_version;
use crate::model::Component;
use crate::zephyr::kconfig::{Kconfig, KconfigValue};

/// What is known about the build, beyond the SBOM. Every part is optional: a condition that
/// needs a missing part evaluates to [`Verdict::Unknown`], never to true.
///
/// Kconfig and linked symbols are per image: a product's images (e.g. MCUboot and the
/// application in a sysbuild build) are configured and linked separately, so a `kconfig_off`
/// or `symbol_not_linked` condition for a component is judged only by the evidence of the
/// image that component is in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildEvidence {
    /// Each image's Kconfig `.config`, by image name.
    pub kconfig: BTreeMap<String, Kconfig>,
    /// The enabled Cargo features.
    pub cargo_features: Option<BTreeSet<String>>,
    /// Each image's linked symbols (e.g. from
    /// [`linked_functions`](crate::linker_map::linked_functions)), by image name.
    pub linked_symbols: BTreeMap<String, BTreeSet<String>>,
}

/// How a `.config` is cited in evidence text: `<image>/zephyr/.config`, a stable label
/// independent of where the file was read from.
pub fn kconfig_label(image: &str) -> String {
    format!("{image}/zephyr/.config")
}

impl BuildEvidence {
    /// No evidence at all.
    pub fn new() -> Self {
        Self::default()
    }

    /// With the `.config` of the image named `image` (replacing any given before).
    pub fn with_kconfig(mut self, image: &str, kconfig: Kconfig) -> Self {
        self.kconfig.insert(image.to_owned(), kconfig);
        self
    }

    /// With the set of enabled Cargo features.
    pub fn with_cargo_features<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        features: I,
    ) -> Self {
        self.cargo_features = Some(features.into_iter().map(Into::into).collect());
        self
    }

    /// With the symbols linked into the image named `image` (replacing any given before).
    pub fn with_linked_symbols<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        image: &str,
        symbols: I,
    ) -> Self {
        self.linked_symbols.insert(
            image.to_owned(),
            symbols.into_iter().map(Into::into).collect(),
        );
        self
    }
}

/// The outcome of one condition, with the evidence (or the gap) as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The condition holds.
    True(String),
    /// The condition does not hold.
    False(String),
    /// The evidence needed is missing.
    Unknown(String),
}

impl Condition {
    /// Evaluates the condition for `component`, which is in the image named `image`.
    ///
    /// - `kconfig_off`: judged by that image's `.config` only: true when the symbol is `n` or
    ///   not set; false for `y`, `m` or any value; unknown when the image has no `.config` or
    ///   the symbol is not in it (a misspelt symbol must not yield `not_affected`).
    /// - `kconfig_equals`: judged like `kconfig_off`; true when the symbol's value, as written
    ///   (`y`, `n` for `is not set`, `m`, a number, or a string's contents), is the one given.
    /// - `cargo_feature_off`: true when the name is not in the set, false when it is, unknown
    ///   without the set.
    /// - `symbol_not_linked`: judged by that image's linked-symbol set only: true when the
    ///   name is not in it, false when it is, unknown when the image has none.
    /// - `version_in`: compares the component's effective version (see
    ///   [`effective_version`](super::effective_version)); unknown when there is none.
    pub fn evaluate(
        &self,
        image: &str,
        component: &Component,
        evidence: &BuildEvidence,
    ) -> Verdict {
        match self {
            Self::KconfigOff(symbol) => kconfig_off(symbol, image, evidence),
            Self::CargoFeatureOff(feature) => match &evidence.cargo_features {
                None => Verdict::Unknown(format!(
                    "no Cargo feature list given, so cannot tell whether `{feature}` is off"
                )),
                Some(set) if set.contains(feature) => {
                    Verdict::False(format!("Cargo feature `{feature}` is enabled"))
                }
                Some(_) => Verdict::True(format!("Cargo feature `{feature}` is not enabled")),
            },
            Self::KconfigEquals(symbol, value) => kconfig_equals(symbol, value, image, evidence),
            Self::SymbolNotLinked(symbol) => match evidence.linked_symbols.get(image) {
                None => Verdict::Unknown(format!(
                    "no linked-symbol list given for image {image}, so cannot tell whether \
                     `{symbol}` is linked"
                )),
                Some(set) if set.contains(symbol) => {
                    Verdict::False(format!("{image}: symbol `{symbol}` is linked"))
                }
                Some(_) => Verdict::True(format!("{image}: symbol `{symbol}` is not linked")),
            },
            Self::VersionIn(range) => {
                let shown = component.version.as_deref().unwrap_or("(none)");
                match effective_version(component) {
                    None => Verdict::Unknown(format!(
                        "{} version {shown:?} is not a release version, so cannot compare \
                         with {range}",
                        component.name
                    )),
                    Some(v) if range.contains(&v) => {
                        Verdict::True(format!("{} {v} is in {range}", component.name))
                    }
                    Some(v) => Verdict::False(format!("{} {v} is not in {range}", component.name)),
                }
            }
        }
    }
}

/// The value of a `.config` entry as written: `y`, `n`, `m`, the number, or the string's
/// contents.
fn written_value(value: &KconfigValue) -> &str {
    match value {
        KconfigValue::Bool(true) => "y",
        KconfigValue::Bool(false) => "n",
        KconfigValue::Module => "m",
        KconfigValue::Int(v) | KconfigValue::Hex(v) | KconfigValue::Str(v) => v,
    }
}

fn kconfig_equals(symbol: &str, want: &str, image: &str, evidence: &BuildEvidence) -> Verdict {
    let location = kconfig_label(image);
    let Some(kconfig) = evidence.kconfig.get(image) else {
        return Verdict::Unknown(format!(
            "no .config given for image {image}, so cannot tell whether {symbol} is {want:?}"
        ));
    };
    let Some(entry) = kconfig.get(symbol) else {
        return Verdict::Unknown(format!("{symbol} is not in {location}"));
    };
    let at = format!("{location}:{}", entry.line);
    let got = written_value(&entry.value);
    if got == want {
        Verdict::True(format!("{at}: {symbol} is {want:?}"))
    } else {
        Verdict::False(format!("{at}: {symbol} is {got:?}, not {want:?}"))
    }
}

fn kconfig_off(symbol: &str, image: &str, evidence: &BuildEvidence) -> Verdict {
    let location = kconfig_label(image);
    let Some(kconfig) = evidence.kconfig.get(image) else {
        return Verdict::Unknown(format!(
            "no .config given for image {image}, so cannot tell whether {symbol} is off"
        ));
    };
    let Some(entry) = kconfig.get(symbol) else {
        return Verdict::Unknown(format!("{symbol} is not in {location}"));
    };
    let at = format!("{location}:{}", entry.line);
    match &entry.value {
        KconfigValue::Bool(false) => Verdict::True(format!("{at}: {symbol} is not set")),
        KconfigValue::Bool(true) => Verdict::False(format!("{at}: {symbol}=y")),
        KconfigValue::Module => Verdict::False(format!("{at}: {symbol}=m")),
        KconfigValue::Int(v) | KconfigValue::Hex(v) => {
            Verdict::False(format!("{at}: {symbol}={v}"))
        }
        KconfigValue::Str(v) => Verdict::False(format!("{at}: {symbol}={v:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ComponentKind, Purl};
    use crate::vex::version::VersionRange;
    use crate::zephyr::kconfig;

    const CONFIG: &str = "CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=n\nCONFIG_D=m\nCONFIG_E=4\n";

    fn evidence() -> BuildEvidence {
        BuildEvidence::new().with_kconfig("app", kconfig::parse(CONFIG).unwrap())
    }

    fn lib(version: &str) -> Component {
        Component::new(ComponentKind::Library, "mbedtls")
            .unwrap()
            .with_version(version)
    }

    fn off(symbol: &str) -> Condition {
        Condition::KconfigOff(symbol.to_owned())
    }

    #[test]
    fn kconfig_off_true() {
        let c = lib("2.28.0");
        assert_eq!(
            off("CONFIG_B").evaluate("app", &c, &evidence()),
            Verdict::True("app/zephyr/.config:2: CONFIG_B is not set".to_owned())
        );
        assert!(matches!(
            off("CONFIG_C").evaluate("app", &c, &evidence()),
            Verdict::True(_)
        ));
    }

    #[test]
    fn kconfig_off_false() {
        let c = lib("2.28.0");
        assert_eq!(
            off("CONFIG_A").evaluate("app", &c, &evidence()),
            Verdict::False("app/zephyr/.config:1: CONFIG_A=y".to_owned())
        );
        assert!(matches!(
            off("CONFIG_D").evaluate("app", &c, &evidence()),
            Verdict::False(_)
        ));
        assert!(matches!(
            off("CONFIG_E").evaluate("app", &c, &evidence()),
            Verdict::False(_)
        ));
    }

    #[test]
    fn kconfig_off_unknown_absent() {
        assert_eq!(
            off("CONFIG_TYPO").evaluate("app", &lib("1.0.0"), &evidence()),
            Verdict::Unknown("CONFIG_TYPO is not in app/zephyr/.config".to_owned())
        );
    }

    #[test]
    fn kconfig_off_unknown_for_image_without_config() {
        // The `.config` given is the application's; a bootloader component is not judged by it.
        assert_eq!(
            off("CONFIG_B").evaluate("mcuboot", &lib("1.0.0"), &evidence()),
            Verdict::Unknown(
                "no .config given for image mcuboot, so cannot tell whether CONFIG_B is off"
                    .to_owned()
            )
        );
    }

    #[test]
    fn kconfig_off_unknown_no_config() {
        assert!(matches!(
            off("CONFIG_A").evaluate("app", &lib("1.0.0"), &BuildEvidence::new()),
            Verdict::Unknown(_)
        ));
    }

    fn feature(name: &str) -> Condition {
        Condition::CargoFeatureOff(name.to_owned())
    }

    #[test]
    fn cargo_feature_off_true() {
        let e = BuildEvidence::new().with_cargo_features(["std"]);
        assert!(matches!(
            feature("dtls").evaluate("app", &lib("1.0.0"), &e),
            Verdict::True(_)
        ));
    }

    #[test]
    fn cargo_feature_off_false() {
        let e = BuildEvidence::new().with_cargo_features(["std", "dtls"]);
        assert!(matches!(
            feature("dtls").evaluate("app", &lib("1.0.0"), &e),
            Verdict::False(_)
        ));
    }

    #[test]
    fn cargo_feature_off_unknown() {
        assert!(matches!(
            feature("dtls").evaluate("app", &lib("1.0.0"), &BuildEvidence::new()),
            Verdict::Unknown(_)
        ));
    }

    fn linked(name: &str) -> Condition {
        Condition::SymbolNotLinked(name.to_owned())
    }

    #[test]
    fn symbol_not_linked_true() {
        let e = BuildEvidence::new().with_linked_symbols("app", ["main"]);
        assert!(matches!(
            linked("parse_hello").evaluate("app", &lib("1.0.0"), &e),
            Verdict::True(_)
        ));
    }

    #[test]
    fn symbol_not_linked_false() {
        let e = BuildEvidence::new().with_linked_symbols("app", ["main", "parse_hello"]);
        assert!(matches!(
            linked("parse_hello").evaluate("app", &lib("1.0.0"), &e),
            Verdict::False(_)
        ));
    }

    #[test]
    fn symbol_not_linked_unknown() {
        assert!(matches!(
            linked("parse_hello").evaluate("app", &lib("1.0.0"), &BuildEvidence::new()),
            Verdict::Unknown(_)
        ));
    }

    #[test]
    fn symbol_not_linked_is_per_image() {
        // Only the application's map was given: MCUboot's component stays unknown.
        let e = BuildEvidence::new().with_linked_symbols("app", ["main"]);
        assert_eq!(
            linked("parse_hello").evaluate("mcuboot", &lib("1.0.0"), &e),
            Verdict::Unknown(
                "no linked-symbol list given for image mcuboot, so cannot tell whether \
                 `parse_hello` is linked"
                    .to_owned()
            )
        );
        let e = e.with_linked_symbols("mcuboot", ["parse_hello"]);
        assert!(matches!(
            linked("parse_hello").evaluate("mcuboot", &lib("1.0.0"), &e),
            Verdict::False(_)
        ));
        assert!(matches!(
            linked("parse_hello").evaluate("app", &lib("1.0.0"), &e),
            Verdict::True(_)
        ));
    }

    fn equals(symbol: &str, value: &str) -> Condition {
        Condition::KconfigEquals(symbol.to_owned(), value.to_owned())
    }

    #[test]
    fn kconfig_equals_compares_the_written_value() {
        let config =
            "CONFIG_FILE=\"config-mbedtls.h\"\nCONFIG_A=y\n# CONFIG_B is not set\nCONFIG_E=4\n";
        let e = BuildEvidence::new().with_kconfig("app", kconfig::parse(config).unwrap());
        let c = lib("1.0.0");
        assert_eq!(
            equals("CONFIG_FILE", "config-mbedtls.h").evaluate("app", &c, &e),
            Verdict::True("app/zephyr/.config:1: CONFIG_FILE is \"config-mbedtls.h\"".to_owned())
        );
        assert_eq!(
            equals("CONFIG_FILE", "mcuboot-mbedtls-cfg.h").evaluate("app", &c, &e),
            Verdict::False(
                "app/zephyr/.config:1: CONFIG_FILE is \"config-mbedtls.h\", not \"mcuboot-mbedtls-cfg.h\""
                    .to_owned()
            )
        );
        for (symbol, value) in [("CONFIG_A", "y"), ("CONFIG_B", "n"), ("CONFIG_E", "4")] {
            assert!(matches!(
                equals(symbol, value).evaluate("app", &c, &e),
                Verdict::True(_)
            ));
        }
        assert!(matches!(
            equals("CONFIG_TYPO", "y").evaluate("app", &c, &e),
            Verdict::Unknown(_)
        ));
        assert!(matches!(
            equals("CONFIG_A", "y").evaluate("mcuboot", &c, &e),
            Verdict::Unknown(_)
        ));
    }

    fn within(range: &str) -> Condition {
        Condition::VersionIn(VersionRange::parse(range).unwrap())
    }

    #[test]
    fn version_in_true() {
        assert_eq!(
            within("<2.28.1").evaluate("app", &lib("2.28.0"), &BuildEvidence::new()),
            Verdict::True("mbedtls 2.28.0 is in <2.28.1".to_owned())
        );
    }

    #[test]
    fn version_in_false() {
        assert!(matches!(
            within("<2.28.1").evaluate("app", &lib("v3.6.0"), &BuildEvidence::new()),
            Verdict::False(_)
        ));
    }

    #[test]
    fn version_in_prerelease_is_unknown() {
        for v in ["v3.7.0-123-gabc1234", "2.28.0-rc1", "1234567"] {
            assert!(
                matches!(
                    within("<5").evaluate("app", &lib(v), &BuildEvidence::new()),
                    Verdict::Unknown(_)
                ),
                "{v}"
            );
        }
    }

    #[test]
    fn version_in_unknown() {
        let mut c = lib("85440ef5fffa95d0e9971e9163719189cf34d979");
        assert!(matches!(
            within("<5").evaluate("app", &c, &BuildEvidence::new()),
            Verdict::Unknown(_)
        ));
        c.purl = Some(Purl::new("pkg:github/mbed-tls/mbedtls@v4.1.0").unwrap());
        assert!(matches!(
            within("<5").evaluate("app", &c, &BuildEvidence::new()),
            Verdict::True(_)
        ));
    }
}
