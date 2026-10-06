//! The symbol → algorithm mapping of the configuration detectors, as data.
//!
//! Two rule files ship with rollcall and are embedded at build time:
//! `db/config-zephyr.yaml` ([`RuleSet::builtin_zephyr`]: Zephyr `.config` and sysbuild
//! `SB_CONFIG_*`) and `db/config-esp-idf.yaml` ([`RuleSet::builtin_esp_idf`]: ESP-IDF
//! `sdkconfig`). `docs/assay-config.md` explains the format; in short:
//!
//! ```yaml
//! format: rollcall-config-rules/1
//! detector: kconfig                 # the evidence detector name
//! api:                              # which crypto API an image uses (a note)
//!   psa: [CONFIG_MBEDTLS_PSA_CRYPTO_C]
//!   legacy: [CONFIG_MBEDTLS_RSA_C]
//! dimensions:                       # a curve or hash, chosen by its own symbols
//!   ecdh-curve:
//!     - {symbol: CONFIG_PSA_WANT_ECC_SECP_R1_256, parameter_set: secp256r1}
//!     - {symbol: CONFIG_PSA_WANT_ECC_MONTGOMERY_255, algorithm: X25519, parameter_set: X25519}
//!     - {symbol: CONFIG_PSA_WANT_ECC_SECP_K1_256, uncatalogued: secp256k1}
//! rules:
//!   - id: psa-ecdh                  # unique
//!     when: [CONFIG_PSA_WANT_ALG_ECDH]          # every one y/m
//!     when_any: [CONFIG_MBEDTLS_SSL_PROTO_TLS1_2, CONFIG_MBEDTLS_TLS_VERSION_1_2]  # at least one y/m
//!     when_value: {SB_CONFIG_SIGNATURE_TYPE: RSA}  # string options equal to these
//!     when_off: [CONFIG_SECURE_BOOT]            # every one explicitly n / not set
//!     unless: [CONFIG_BT_SMP_SC_ONLY]           # none y/m
//!     library: psa-crypto           # the component the assets go under
//!     image: {kind: bootloader, name: bootloader}  # optional: another image than the file's
//!     emit:                         # catalogue assets
//!       - AES-GCM-128               # an asset name (algorithm and parameter set)
//!       - {algorithm: ECDH, parameter_set_from: {dimension: ecdh-curve}}
//!       - {algorithm: RSA-PSS, parameter_set_from: {int: CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN}}
//!       - {algorithm: AES-CCM, parameter_set: "128", hardware: true}
//!     protocol: {type: tls, version: "1.2"}
//!     uncatalogued: [SHA-1]         # not in the catalogue: a note, never an asset
//!     note: secure boot not enabled  # a note
//!     reason: one line, at most 200 characters, the evidence reason
//! hardware:                         # mark assets as running in hardware
//!   - when: [CONFIG_MBEDTLS_HARDWARE_AES]
//!     library: mbedtls
//!     algorithms: [AES-GCM, AES-CCM, SHA2-256]  # an algorithm (every set) or one set
//!     reason: ...
//! compiled_out:                     # explicitly-off symbols that compile algorithms out
//!   - when_all_off: [CONFIG_PSA_WANT_ALG_CBC_NO_PADDING, CONFIG_PSA_WANT_ALG_CBC_PKCS7]
//!     library: psa-crypto           # the library they are compiled out of
//!     algorithms: [AES-CBC]
//! custom_config:                    # a configuration header Kconfig does not generate
//!   - symbol: CONFIG_MBEDTLS_USER_CONFIG_FILE
//!     defaults: [""]                # the values that mean Kconfig's own configuration
//!     libraries: [mbedtls, psa-crypto]  # whose compiled-out entries it makes untrustworthy
//! ```
//!
//! [`RuleSet::load_str`] rejects unknown keys, a wrong `format`, and structural mistakes (a
//! symbol that is not `CONFIG_…`/`SB_CONFIG_…`, a duplicate id, a rule with no condition or no
//! effect, an emitting rule without a library or reason, a reason over 200 characters, an
//! unknown dimension, a dimension entry with both or neither of `parameter_set` and
//! `uncatalogued`, a compiled-out rule without a library, a custom-config entry without
//! libraries or defaults, a hardware, compiled-out or custom-config library no rule emits
//! under), each finding with the line of its rule or entry where it can be found. [`RuleSet::lint`] checks the set against the algorithm catalogue: every emitted,
//! dimension, hardware and compiled-out algorithm and parameter set resolves, and every
//! `uncatalogued` name is really missing from the catalogue.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use rollcall_core::model::{ImageKind, MAX_REASON_CHARS, ProtocolType};
use serde::Deserialize;

use crate::assets::{algorithm_properties, parse_asset_name};
use crate::catalogue::Catalogue;

/// The `format` this rollcall reads.
pub const FORMAT: &str = "rollcall-config-rules/1";
/// The built-in Zephyr rules' file name, as errors cite it.
pub const ZEPHYR_FILE: &str = "config-zephyr.yaml";
/// The built-in ESP-IDF rules' file name, as errors cite it.
pub const ESP_IDF_FILE: &str = "config-esp-idf.yaml";
/// The built-in Zephyr rules.
pub const ZEPHYR_YAML: &str = include_str!("../../db/config-zephyr.yaml");
/// The built-in ESP-IDF rules.
pub const ESP_IDF_YAML: &str = include_str!("../../db/config-esp-idf.yaml");

/// A loaded rule set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// The file the rules came from, as errors cite it.
    #[serde(skip)]
    pub file: String,
    /// Always [`FORMAT`].
    pub format: String,
    /// The evidence detector name, e.g. `kconfig`.
    pub detector: String,
    /// The symbols that show which crypto API an image uses.
    #[serde(default)]
    pub api: Api,
    /// Named choices of parameter set (curves, hashes), by name.
    #[serde(default)]
    pub dimensions: BTreeMap<String, Vec<DimensionEntry>>,
    /// The rules, in file order.
    pub rules: Vec<Rule>,
    /// Symbols that put named algorithms in hardware.
    #[serde(default)]
    pub hardware: Vec<HardwareRule>,
    /// Explicitly-off symbols that compile algorithms out.
    #[serde(default)]
    pub compiled_out: Vec<CompiledOutRule>,
    /// String options naming a configuration header that, when not Kconfig's own, make the
    /// compiled-out entries of some libraries untrustworthy.
    #[serde(default)]
    pub custom_config: Vec<CustomConfigRule>,
    /// The 1-based line of each rule (by id) and section entry (`hardware[0]`,
    /// `dimensions.ecdh-curve`, `rules`, …), as far as they could be found, for findings.
    #[serde(skip)]
    pub lines: BTreeMap<String, u32>,
}

/// Which symbols show the PSA Crypto API and which the legacy mbedTLS API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// Any of these `y`: the PSA Crypto API.
    #[serde(default)]
    pub psa: Vec<String>,
    /// Any of these `y`: the legacy mbedTLS crypto API.
    #[serde(default)]
    pub legacy: Vec<String>,
}

/// One choice of a dimension: a symbol and the parameter set it selects (or the name of one the
/// catalogue does not have).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionEntry {
    /// The symbol that selects it.
    pub symbol: String,
    /// Another catalogue algorithm to emit instead (ECDH on Curve25519 is `X25519`).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// The catalogue parameter set.
    #[serde(default)]
    pub parameter_set: Option<String>,
    /// A choice the catalogue does not list: a note, never an asset.
    #[serde(default)]
    pub uncatalogued: Option<String>,
}

/// Where a rule's assets go, when not in the image whose file the rule matched.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageTarget {
    /// The image's kind.
    pub kind: ImageKind,
    /// The image's name.
    pub name: String,
}

/// A protocol a rule emits.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSpec {
    /// The protocol.
    #[serde(rename = "type")]
    pub protocol_type: ProtocolType,
    /// Its version.
    pub version: String,
}

/// Where an emitted asset's parameter set comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SetSource {
    /// An integer option's value, e.g. `CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=2048`.
    #[serde(rename = "int")]
    Int(String),
    /// A string option's value, e.g. an LMS parameter-set name.
    #[serde(rename = "string")]
    Str(String),
    /// Every enabled choice of a dimension.
    #[serde(rename = "dimension")]
    Dimension(String),
}

/// One asset a rule emits, written out.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmitSpec {
    /// The catalogue algorithm.
    pub algorithm: String,
    /// A fixed parameter set.
    #[serde(default)]
    pub parameter_set: Option<String>,
    /// Where the parameter set comes from.
    #[serde(default)]
    pub parameter_set_from: Option<SetSource>,
    /// The asset runs in hardware (`executionEnvironment: hardware`).
    #[serde(default)]
    pub hardware: bool,
}

/// One asset a rule emits: an asset name (`AES-GCM-128`) or a written-out [`EmitSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Emit {
    /// An [`asset_name`](crate::assets::asset_name).
    Name(String),
    /// A written-out emission.
    Spec(EmitSpec),
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// A unique id, for messages.
    pub id: String,
    /// Every one `y` or `m`.
    #[serde(default)]
    pub when: Vec<String>,
    /// At least one `y` or `m`; each one that is on is evidence.
    #[serde(default)]
    pub when_any: Vec<String>,
    /// String options equal to these values.
    #[serde(default)]
    pub when_value: BTreeMap<String, String>,
    /// Every one explicitly `n` or `# … is not set`.
    #[serde(default)]
    pub when_off: Vec<String>,
    /// None of these `y` or `m`.
    #[serde(default)]
    pub unless: Vec<String>,
    /// The library component the assets go under.
    #[serde(default)]
    pub library: Option<String>,
    /// Another image than the file's.
    #[serde(default)]
    pub image: Option<ImageTarget>,
    /// The catalogue assets.
    #[serde(default)]
    pub emit: Vec<Emit>,
    /// A protocol asset.
    #[serde(default)]
    pub protocol: Option<ProtocolSpec>,
    /// Algorithms the catalogue does not list: one note each.
    #[serde(default)]
    pub uncatalogued: Vec<String>,
    /// A note.
    #[serde(default)]
    pub note: Option<String>,
    /// The evidence reason.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Rule {
    /// Whether the rule emits an asset (and so needs a library and a reason).
    pub fn emits(&self) -> bool {
        !self.emit.is_empty() || self.protocol.is_some()
    }

    /// Every symbol the rule tests, in order: `when`, `when_any`, `when_value`, `when_off`,
    /// `unless`.
    pub fn symbols(&self) -> impl Iterator<Item = &str> {
        self.when
            .iter()
            .chain(self.when_any.iter())
            .chain(self.when_value.keys())
            .chain(self.when_off.iter())
            .chain(self.unless.iter())
            .map(String::as_str)
    }
}

/// Symbols that put named algorithms of a library in hardware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareRule {
    /// Every one `y` or `m`.
    pub when: Vec<String>,
    /// The library whose assets it marks.
    pub library: String,
    /// Asset names: an algorithm (every parameter set) or an algorithm and parameter set
    /// (that set only).
    pub algorithms: Vec<String>,
    /// The evidence reason.
    pub reason: String,
}

/// Symbols that, all explicitly off, compile algorithms out.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledOutRule {
    /// Every one explicitly `n` or `# … is not set`.
    pub when_all_off: Vec<String>,
    /// The library the algorithms are compiled out of (`mbedtls`, `psa-crypto`): the library
    /// component a finding must sit under to be removed rather than down-weighted.
    pub library: String,
    /// Asset names: an algorithm (every parameter set) or an algorithm and parameter set.
    pub algorithms: Vec<String>,
}

/// A string option naming a library's configuration header. A value outside `defaults` means
/// a header Kconfig does not generate can turn algorithms back on (or off) behind Kconfig's
/// back, so the image gets no compiled-out entries for `libraries`, and a note.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomConfigRule {
    /// The string option, e.g. `CONFIG_MBEDTLS_USER_CONFIG_FILE`.
    pub symbol: String,
    /// The values that mean the Kconfig-generated configuration (`""` for none). A symbol
    /// missing from the file is always fine.
    pub defaults: Vec<String>,
    /// The libraries whose compiled-out entries a value outside `defaults` drops.
    pub libraries: Vec<String>,
}

/// One problem with a rule set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file.
    pub file: String,
    /// The 1-based line of the rule or entry, when it could be found.
    pub line: Option<u32>,
    /// The rule id, or the section (`dimensions.ecdh-curve`, `hardware[0]`, …).
    pub at: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{line}: {}: {}", self.file, self.at, self.message),
            None => write!(f, "{}: {}: {}", self.file, self.at, self.message),
        }
    }
}

/// Why a rule set could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RulesError {
    /// The file is empty.
    #[error("{file}: empty rule set")]
    Empty {
        /// The file.
        file: String,
    },
    /// The YAML is malformed or does not match the schema.
    #[error("{file}{}: {message}", line.map(|l| format!(":{l}")).unwrap_or_default())]
    Yaml {
        /// The file.
        file: String,
        /// The 1-based line, if known.
        line: Option<u32>,
        /// What is wrong.
        message: String,
    },
    /// The `format` is not [`FORMAT`].
    #[error("{file}: unsupported format {found:?}; expected {FORMAT:?}")]
    UnsupportedFormat {
        /// The file.
        file: String,
        /// The format found.
        found: String,
    },
    /// The rules parsed but are inconsistent; every finding, sorted.
    #[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<Finding>),
}

/// Whether `symbol` is a `CONFIG_…` or `SB_CONFIG_…` name of `[A-Z0-9_]`.
fn is_symbol(symbol: &str) -> bool {
    (symbol.starts_with("CONFIG_") || symbol.starts_with("SB_CONFIG_"))
        && symbol.len() > "CONFIG_".len()
        && symbol
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The id in a YAML rule line (`- id: x` or `- {id: x, …}`), if it has one.
fn rule_id(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('-')?.trim_start();
    let rest = rest.strip_prefix('{').unwrap_or(rest).trim_start();
    let rest = rest.strip_prefix("id:")?;
    let end = rest.find([',', '}', '#']).unwrap_or(rest.len());
    let id = rest[..end].trim().trim_matches(['"', '\'']);
    (!id.is_empty()).then_some(id)
}

/// The 1-based lines of a rule file's top-level keys, dimensions (`dimensions.NAME`), rules
/// (by id) and list entries (`hardware[0]`, `compiled_out[3]`, `custom_config[1]`), found by
/// reading the text line by line. Anything it cannot place is simply missing.
fn index_lines(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    let mut section = String::new();
    let mut item_indent: Option<usize> = None;
    let mut items = 0usize;
    for (n, line) in text.lines().enumerate() {
        let n = u32::try_from(n + 1).unwrap_or(u32::MAX);
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            if let Some((key, _)) = line.split_once(':') {
                section = key.trim().to_owned();
                out.entry(section.clone()).or_insert(n);
            }
            item_indent = None;
            items = 0;
            continue;
        }
        match section.as_str() {
            "dimensions" => {
                if !trimmed.starts_with('-')
                    && let Some((key, _)) = trimmed.split_once(':')
                {
                    out.entry(format!("dimensions.{}", key.trim())).or_insert(n);
                }
            }
            "rules" => {
                if let Some(id) = rule_id(line) {
                    out.entry(id.to_owned()).or_insert(n);
                }
            }
            "hardware" | "compiled_out" | "custom_config" if trimmed.starts_with('-') => {
                let first = *item_indent.get_or_insert(indent);
                if indent == first {
                    out.entry(format!("{section}[{items}]")).or_insert(n);
                    items += 1;
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether `text` is one non-empty line without control characters.
fn is_line(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(char::is_control)
}

impl RuleSet {
    /// The built-in Zephyr rules ([`ZEPHYR_YAML`]).
    pub fn builtin_zephyr() -> Result<Self, RulesError> {
        Self::load_str(ZEPHYR_FILE, ZEPHYR_YAML)
    }

    /// The built-in ESP-IDF rules ([`ESP_IDF_YAML`]).
    pub fn builtin_esp_idf() -> Result<Self, RulesError> {
        Self::load_str(ESP_IDF_FILE, ESP_IDF_YAML)
    }

    /// Loads a rule set from text; errors cite it as `file`.
    pub fn load_str(file: &str, text: &str) -> Result<Self, RulesError> {
        if text.trim().is_empty() {
            return Err(RulesError::Empty {
                file: file.to_owned(),
            });
        }
        let parsed: Option<Self> = yaml_serde::from_str(text).map_err(|e| RulesError::Yaml {
            file: file.to_owned(),
            line: e
                .location()
                .map(|l| u32::try_from(l.line()).unwrap_or(u32::MAX)),
            message: e.to_string(),
        })?;
        let Some(mut set) = parsed else {
            return Err(RulesError::Empty {
                file: file.to_owned(),
            });
        };
        set.file = file.to_owned();
        set.lines = index_lines(text);
        if set.format != FORMAT {
            return Err(RulesError::UnsupportedFormat {
                file: file.to_owned(),
                found: set.format,
            });
        }
        let findings = set.check_structure();
        if findings.is_empty() {
            Ok(set)
        } else {
            Err(RulesError::Invalid(findings))
        }
    }

    fn finding(&self, at: impl Into<String>, message: impl Into<String>) -> Finding {
        let at = at.into();
        Finding {
            file: self.file.clone(),
            line: self.lines.get(&at).copied(),
            at,
            message: message.into(),
        }
    }

    /// The structural checks of [`RuleSet::load_str`], sorted.
    fn check_structure(&self) -> Vec<Finding> {
        let mut out = BTreeSet::new();
        let symbol = |at: &str, s: &str, out: &mut BTreeSet<Finding>| {
            if !is_symbol(s) {
                out.insert(
                    self.finding(at, format!("{s:?} is not a CONFIG_ or SB_CONFIG_ symbol")),
                );
            }
        };
        if !is_line(&self.detector) {
            out.insert(self.finding("detector", "empty or not one line"));
        }
        for s in self.api.psa.iter().chain(&self.api.legacy) {
            symbol("api", s, &mut out);
        }
        for (name, entries) in &self.dimensions {
            let at = format!("dimensions.{name}");
            if entries.is_empty() {
                out.insert(self.finding(&at, "no entries"));
            }
            for entry in entries {
                symbol(&at, &entry.symbol, &mut out);
                if entry.parameter_set.is_some() == entry.uncatalogued.is_some() {
                    out.insert(self.finding(
                        &at,
                        format!(
                            "{}: exactly one of parameter_set and uncatalogued",
                            entry.symbol
                        ),
                    ));
                }
            }
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            let at = rule.id.as_str();
            if !is_line(at) {
                out.insert(self.finding("rules", "a rule with an empty id"));
            }
            if !ids.insert(at) {
                out.insert(self.finding(at, "duplicate rule id"));
            }
            for s in rule.symbols() {
                symbol(at, s, &mut out);
            }
            if rule.when.is_empty()
                && rule.when_any.is_empty()
                && rule.when_value.is_empty()
                && rule.when_off.is_empty()
            {
                out.insert(
                    self.finding(at, "no condition (when, when_any, when_value or when_off)"),
                );
            }
            if !rule.emits() && rule.uncatalogued.is_empty() && rule.note.is_none() {
                out.insert(self.finding(at, "no effect (emit, protocol, uncatalogued or note)"));
            }
            if rule.emits() {
                match &rule.library {
                    Some(l) if is_line(l) => {}
                    _ => {
                        out.insert(self.finding(at, "an emitting rule needs a library"));
                    }
                }
                if rule.reason.is_none() {
                    out.insert(self.finding(at, "an emitting rule needs a reason"));
                }
            }
            if let Some(reason) = &rule.reason {
                self.check_reason(at, reason, &mut out);
            }
            for text in rule.uncatalogued.iter().chain(rule.note.iter()) {
                if !is_line(text) {
                    out.insert(self.finding(at, "an empty or multi-line note"));
                }
            }
            if let Some(image) = &rule.image
                && !is_line(&image.name)
            {
                out.insert(self.finding(at, "an empty image name"));
            }
            for emit in &rule.emit {
                if let Emit::Spec(spec) = emit {
                    if spec.parameter_set.is_some() && spec.parameter_set_from.is_some() {
                        out.insert(self.finding(
                            at,
                            format!(
                                "{}: parameter_set and parameter_set_from both given",
                                spec.algorithm
                            ),
                        ));
                    }
                    match &spec.parameter_set_from {
                        Some(SetSource::Int(s) | SetSource::Str(s)) => symbol(at, s, &mut out),
                        Some(SetSource::Dimension(d)) if !self.dimensions.contains_key(d) => {
                            out.insert(self.finding(at, format!("unknown dimension {d:?}")));
                        }
                        _ => {}
                    }
                }
            }
        }
        // Every library a hardware, compiled-out or custom-config entry names must be one some
        // rule emits under: a misspelt one would silently match nothing.
        let emitted: BTreeSet<&str> = self
            .rules
            .iter()
            .filter(|r| r.emits())
            .filter_map(|r| r.library.as_deref())
            .collect();
        let known = |at: &str, library: &str, out: &mut BTreeSet<Finding>| {
            if is_line(library) && !emitted.contains(library) {
                out.insert(self.finding(
                    at,
                    format!("library {library:?} is not one any rule emits under"),
                ));
            }
        };
        for (i, hw) in self.hardware.iter().enumerate() {
            let at = format!("hardware[{i}]");
            known(&at, &hw.library, &mut out);
            if hw.when.is_empty() || hw.algorithms.is_empty() {
                out.insert(self.finding(&at, "needs when and algorithms"));
            }
            for s in &hw.when {
                symbol(&at, s, &mut out);
            }
            if !is_line(&hw.library) {
                out.insert(self.finding(&at, "an empty library"));
            }
            self.check_reason(&at, &hw.reason, &mut out);
        }
        for (i, co) in self.compiled_out.iter().enumerate() {
            let at = format!("compiled_out[{i}]");
            if co.when_all_off.is_empty() || co.algorithms.is_empty() {
                out.insert(self.finding(&at, "needs when_all_off and algorithms"));
            }
            for s in &co.when_all_off {
                symbol(&at, s, &mut out);
            }
            if !is_line(&co.library) {
                out.insert(self.finding(&at, "an empty library"));
            }
            known(&at, &co.library, &mut out);
        }
        for (i, cc) in self.custom_config.iter().enumerate() {
            let at = format!("custom_config[{i}]");
            symbol(&at, &cc.symbol, &mut out);
            if cc.libraries.is_empty() || cc.libraries.iter().any(|l| !is_line(l)) {
                out.insert(self.finding(&at, "needs libraries, each one non-empty line"));
            }
            for library in &cc.libraries {
                known(&at, library, &mut out);
            }
            if cc.defaults.is_empty() {
                out.insert(self.finding(
                    &at,
                    "no defaults (the values that mean the Kconfig-generated header)",
                ));
            }
            if cc.defaults.iter().any(|d| d.chars().any(char::is_control)) {
                out.insert(self.finding(&at, "a default with a control character"));
            }
        }
        out.into_iter().collect()
    }

    fn check_reason(&self, at: &str, reason: &str, out: &mut BTreeSet<Finding>) {
        if !is_line(reason) {
            out.insert(self.finding(at, "the reason must be one non-empty line"));
        }
        let chars = reason.chars().count();
        if chars > MAX_REASON_CHARS {
            out.insert(self.finding(
                at,
                format!("the reason is {chars} characters, more than {MAX_REASON_CHARS}"),
            ));
        }
    }

    /// Checks every algorithm and parameter set the rules name against `catalogue`; the
    /// findings, sorted (none for a good rule set).
    pub fn lint(&self, catalogue: &Catalogue) -> Vec<Finding> {
        let mut out = BTreeSet::new();
        let resolves = |algorithm: &str, set: Option<&str>| {
            algorithm_properties(catalogue, algorithm, set).map_err(|e| e.to_string())
        };
        for (name, entries) in &self.dimensions {
            for entry in entries {
                if let Some(alg) = &entry.algorithm
                    && let Err(e) = resolves(alg, entry.parameter_set.as_deref())
                {
                    out.insert(self.finding(format!("dimensions.{name}"), e));
                }
            }
        }
        for rule in &self.rules {
            let at = rule.id.as_str();
            for emit in &rule.emit {
                match emit {
                    Emit::Name(text) => match parse_asset_name(catalogue, text) {
                        None => {
                            out.insert(
                                self.finding(at, format!("{text:?} names no catalogue algorithm")),
                            );
                        }
                        Some((alg, set)) => {
                            if let Err(e) = resolves(&alg, set.as_deref()) {
                                out.insert(self.finding(at, e));
                            }
                        }
                    },
                    Emit::Spec(spec) => {
                        if let Err(e) = resolves(&spec.algorithm, spec.parameter_set.as_deref()) {
                            out.insert(self.finding(at, e));
                        }
                        if let Some(SetSource::Dimension(d)) = &spec.parameter_set_from {
                            for entry in self.dimensions.get(d).into_iter().flatten() {
                                if entry.algorithm.is_some() {
                                    continue;
                                }
                                if let Some(set) = &entry.parameter_set
                                    && let Err(e) = resolves(&spec.algorithm, Some(set))
                                {
                                    out.insert(self.finding(at, format!("dimension {d}: {e}")));
                                }
                            }
                        }
                    }
                }
            }
            for name in &rule.uncatalogued {
                let resolved = parse_asset_name(catalogue, name)
                    .is_some_and(|(alg, set)| resolves(&alg, set.as_deref()).is_ok());
                if catalogue.algorithm(name).is_some() || resolved {
                    out.insert(
                        self.finding(at, format!("{name:?} is in the catalogue; emit it instead")),
                    );
                }
            }
        }
        for (i, hw) in self.hardware.iter().enumerate() {
            for text in &hw.algorithms {
                let ok = parse_asset_name(catalogue, text)
                    .is_some_and(|(alg, set)| resolves(&alg, set.as_deref()).is_ok());
                if !ok {
                    out.insert(self.finding(
                        format!("hardware[{i}]"),
                        format!("{text:?} names no catalogue algorithm or parameter set"),
                    ));
                }
            }
        }
        for (i, co) in self.compiled_out.iter().enumerate() {
            for text in &co.algorithms {
                let ok = parse_asset_name(catalogue, text)
                    .is_some_and(|(alg, set)| resolves(&alg, set.as_deref()).is_ok());
                if !ok {
                    out.insert(self.finding(
                        format!("compiled_out[{i}]"),
                        format!("{text:?} names no catalogue algorithm or parameter set"),
                    ));
                }
            }
        }
        out.into_iter().collect()
    }

    /// Every symbol the rule set mentions, sorted.
    pub fn symbols(&self) -> BTreeSet<&str> {
        let mut out: BTreeSet<&str> = BTreeSet::new();
        out.extend(self.api.psa.iter().map(String::as_str));
        out.extend(self.api.legacy.iter().map(String::as_str));
        for entries in self.dimensions.values() {
            out.extend(entries.iter().map(|e| e.symbol.as_str()));
        }
        for rule in &self.rules {
            out.extend(rule.symbols());
            for emit in &rule.emit {
                if let Emit::Spec(EmitSpec {
                    parameter_set_from: Some(SetSource::Int(s) | SetSource::Str(s)),
                    ..
                }) = emit
                {
                    out.insert(s);
                }
            }
        }
        for hw in &self.hardware {
            out.extend(hw.when.iter().map(String::as_str));
        }
        for co in &self.compiled_out {
            out.extend(co.when_all_off.iter().map(String::as_str));
        }
        for cc in &self.custom_config {
            out.insert(cc.symbol.as_str());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_lint_clean_and_resolve_against_catalogue() {
        let catalogue = Catalogue::builtin().unwrap();
        for set in [
            RuleSet::builtin_zephyr().unwrap(),
            RuleSet::builtin_esp_idf().unwrap(),
        ] {
            let findings = set.lint(&catalogue);
            assert!(
                findings.is_empty(),
                "{}",
                findings
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            assert!(!set.rules.is_empty());
        }
        let zephyr = RuleSet::builtin_zephyr().unwrap();
        assert_eq!(zephyr.detector, "kconfig");
        assert_eq!(RuleSet::builtin_esp_idf().unwrap().detector, "sdkconfig");
        // The ticket's symbols are all mapped.
        let symbols = zephyr.symbols();
        for s in [
            "CONFIG_MBEDTLS_CIPHER_MODE_CBC",
            "CONFIG_BOOT_SIGNATURE_TYPE_RSA",
            "CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256",
            "CONFIG_BOOT_SIGNATURE_TYPE_ED25519",
            "CONFIG_BOOT_ENCRYPT_IMAGE",
            "CONFIG_BT_SMP",
            "CONFIG_NRF_SECURITY",
            "CONFIG_CRYPTO_NRF_ECB",
            "CONFIG_BOOT_KEELSIGN_MLDSA44",
            "CONFIG_BOOT_KEELSIGN_MLDSA65",
            "CONFIG_BOOT_KEELSIGN_LMS_HSS",
            "CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET",
            "SB_CONFIG_SIGNATURE_TYPE",
        ] {
            assert!(symbols.contains(s), "{s}");
        }
        // The controller crypto switch is deliberately not reported.
        assert!(!symbols.contains("CONFIG_BT_CTLR_CRYPTO"));
        let esp = RuleSet::builtin_esp_idf().unwrap();
        for s in [
            "CONFIG_SECURE_BOOT",
            "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME",
            "CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME",
            "CONFIG_SECURE_FLASH_ENC_ENABLED",
            "CONFIG_MBEDTLS_HARDWARE_AES",
        ] {
            assert!(esp.symbols().contains(s), "{s}");
        }
    }

    #[test]
    fn lint_reports_names_the_catalogue_cannot_resolve() {
        let catalogue = Catalogue::builtin().unwrap();
        let text = r#"
format: rollcall-config-rules/1
detector: kconfig
dimensions:
  curve:
    - {symbol: CONFIG_C1, parameter_set: secp999r1}
rules:
  - id: a
    when: [CONFIG_A]
    library: lib
    emit: [MD5, AES-GCM-64, {algorithm: ECDSA, parameter_set_from: {dimension: curve}}, {algorithm: Nope}]
    uncatalogued: [SHA2-256]
    reason: r
hardware:
  - {when: [CONFIG_H], library: lib, algorithms: [AES, SHA2-99], reason: r}
compiled_out:
  - {when_all_off: [CONFIG_X], library: lib, algorithms: [AES-CBC-99]}
"#;
        let set = RuleSet::load_str("t.yaml", text).unwrap();
        let findings = set.lint(&catalogue);
        let text: Vec<String> = findings.iter().map(ToString::to_string).collect();
        let joined = text.join("\n");
        for needle in [
            "t.yaml:8: a: \"MD5\" names no catalogue algorithm",
            "t.yaml:8: a: unknown parameter set \"64\" for AES-GCM",
            "t.yaml:8: a: dimension curve: unknown parameter set \"secp999r1\" for ECDSA",
            "t.yaml:8: a: unknown algorithm \"Nope\"",
            "t.yaml:8: a: \"SHA2-256\" is in the catalogue",
            "t.yaml:15: hardware[0]: \"AES\" names no catalogue algorithm",
            "t.yaml:15: hardware[0]: \"SHA2-99\" names no catalogue algorithm or parameter set",
            "t.yaml:17: compiled_out[0]: \"AES-CBC-99\" names no catalogue",
        ] {
            assert!(joined.contains(needle), "{needle}\n{joined}");
        }
        assert_eq!(findings.len(), 8, "{joined}");
    }

    #[test]
    fn malformed_rules_error_never_panic() {
        let good = "format: rollcall-config-rules/1\ndetector: kconfig\nrules:\n  - {id: a, when: [CONFIG_A], note: n}\n";
        assert!(RuleSet::load_str("t", good).is_ok());
        let cases: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("whitespace", "  \n# just a comment\n".into()),
            ("null document", "~\n".into()),
            ("not a mapping", "- 1\n- 2\n".into()),
            ("truncated", good[..good.len() / 2].into()),
            ("wrong format", good.replace("/1", "/2")),
            ("unknown key", good.replace("detector:", "colour: red\ndetector:")),
            ("unknown rule key", good.replace("note: n", "note: n, colour: red")),
            ("number for a string", good.replace("note: n", "note: [1]")),
            ("bad symbol", good.replace("CONFIG_A", "config_a")),
            ("no condition", good.replace("when: [CONFIG_A], ", "")),
            ("no effect", good.replace(", note: n", "")),
            (
                "duplicate id",
                format!("{good}  - {{id: a, when: [CONFIG_B], note: n}}\n"),
            ),
            (
                "emit without library or reason",
                good.replace("note: n", "emit: [AES-GCM-128]"),
            ),
            (
                "reason too long",
                good.replace(
                    "note: n",
                    &format!("emit: [AES-GCM-128], library: l, reason: {}", "x".repeat(201)),
                ),
            ),
            (
                "unknown dimension",
                good.replace(
                    "note: n",
                    "emit: [{algorithm: ECDH, parameter_set_from: {dimension: nope}}], library: l, reason: r",
                ),
            ),
            (
                "unknown set source",
                good.replace(
                    "note: n",
                    "emit: [{algorithm: ECDH, parameter_set_from: {float: CONFIG_X}}], library: l, reason: r",
                ),
            ),
            (
                "dimension with neither",
                good.replace("rules:", "dimensions:\n  d:\n    - {symbol: CONFIG_D}\nrules:"),
            ),
            ("tab indentation", good.replace("  - ", "\t- ")),
            ("bad image kind", good.replace("note: n", "note: n, image: {kind: rom, name: x}")),
            ("bad protocol", good.replace("note: n", "protocol: {type: carrier-pigeon, version: '1'}, library: l, reason: r")),
            (
                "compiled out without a library",
                format!("{good}compiled_out:\n  - {{when_all_off: [CONFIG_X], algorithms: [AES-CBC]}}\n"),
            ),
            (
                "compiled out with an empty library",
                format!("{good}compiled_out:\n  - {{when_all_off: [CONFIG_X], library: '', algorithms: [AES-CBC]}}\n"),
            ),
            (
                "custom config without libraries",
                format!("{good}custom_config:\n  - {{symbol: CONFIG_F, defaults: ['']}}\n"),
            ),
            (
                "custom config with no library",
                format!("{good}custom_config:\n  - {{symbol: CONFIG_F, defaults: [''], libraries: []}}\n"),
            ),
            (
                "custom config with a bad symbol",
                format!("{good}custom_config:\n  - {{symbol: f, defaults: [''], libraries: [l]}}\n"),
            ),
            (
                "custom config with an unknown key",
                format!("{good}custom_config:\n  - {{symbol: CONFIG_F, defaults: [''], libraries: [l], colour: red}}\n"),
            ),
            (
                "when_any not a list",
                good.replace("when: [CONFIG_A]", "when_any: CONFIG_A"),
            ),
            (
                "when_any with a bad symbol",
                good.replace("when: [CONFIG_A]", "when_any: [config_a]"),
            ),
        ];
        for (name, text) in cases {
            let result = RuleSet::load_str("t.yaml", &text);
            let err = result.expect_err(name);
            assert!(err.to_string().starts_with("t.yaml"), "{name}: {err}");
        }
        // Library references must name a library some rule emits under, defaults must not be
        // empty; each finding carries the line of its entry.
        let emitting = "format: rollcall-config-rules/1\ndetector: kconfig\nrules:\n  - id: a\n    when: [CONFIG_A]\n    library: mbedtls\n    emit: [AES-GCM-128]\n    reason: r\n  - {id: b, when: [CONFIG_B], library: psa-crypto, emit: [SHA2-256], reason: r}\n";
        assert!(RuleSet::load_str("t.yaml", emitting).is_ok());
        let tail_cases = [
            (
                "compiled out of a misspelt library",
                "compiled_out:\n  - {when_all_off: [CONFIG_X], library: mbedtls, algorithms: [AES-CBC]}\n  - {when_all_off: [CONFIG_Y], library: mbedtsl, algorithms: [AES-CBC]}\n",
                "t.yaml:12: compiled_out[1]: library \"mbedtsl\" is not one any rule emits under",
            ),
            (
                "custom config with a misspelt library",
                "custom_config:\n  - {symbol: CONFIG_F, defaults: [''], libraries: [mbedtls, psa_crypto]}\n",
                "t.yaml:11: custom_config[0]: library \"psa_crypto\" is not one any rule emits under",
            ),
            (
                "hardware for a misspelt library",
                "hardware:\n  - when: [CONFIG_H]\n    library: psa-crytpo\n    algorithms: [AES-GCM]\n    reason: r\n",
                "t.yaml:11: hardware[0]: library \"psa-crytpo\" is not one any rule emits under",
            ),
            (
                "custom config with empty defaults",
                "custom_config:\n  - {symbol: CONFIG_F, defaults: [], libraries: [mbedtls]}\n",
                "t.yaml:11: custom_config[0]: no defaults",
            ),
        ];
        for (name, tail, message) in tail_cases {
            let err = RuleSet::load_str("t.yaml", &format!("{emitting}{tail}")).expect_err(name);
            assert_eq!(err.to_string().lines().count(), 1, "{name}: {err}");
            assert!(err.to_string().starts_with(message), "{name}: {err}");
        }
        // A rule-level structural error names the rule's line.
        let err = RuleSet::load_str(
            "t.yaml",
            &emitting.replace(
                "emit: [AES-GCM-128]",
                "emit: [AES-GCM-128]\n    image: {kind: bootloader, name: ' '}",
            ),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "t.yaml:4: a: an empty image name");
        // Arbitrary bytes as text never panic.
        for text in [
            "\u{feff}format: x",
            "format: [",
            "rules: {",
            "\0\0",
            "format: rollcall-config-rules/1\nrules: 5\n",
        ] {
            assert!(RuleSet::load_str("t.yaml", text).is_err());
        }
    }
}
