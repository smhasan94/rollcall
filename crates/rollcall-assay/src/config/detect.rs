//! Evaluating a [`RuleSet`] against one parsed configuration file.
//!
//! [`evaluate`] fires every rule whose conditions hold, in file order, and returns the assets,
//! compiled-out entries, notes and crypto API it found. Assets are keyed by (image, library,
//! asset name); a second rule that emits the same asset adds its evidence to it
//! ([`CryptoAsset::add_evidence`]), so each asset appears once with every symbol that put it
//! there. Each evidence entry is one symbol: a `kconfig-symbol` locator at its line, the
//! rule set's detector, confidence `high` and the rule's reason.
//!
//! A `custom_config` option set to a header Kconfig does not generate (a non-empty
//! `CONFIG_MBEDTLS_USER_CONFIG_FILE`, say) drops the file's compiled-out entries for the
//! libraries it names, with a note: such a header can turn back on what Kconfig says is off.

use std::collections::{BTreeMap, BTreeSet};

use rollcall_core::model::{
    ConfidenceLevel, CryptoAsset, CryptoAssetProperties, CryptoEvidence, ExecutionEnvironment,
    Locator, ProtocolProperties,
};
use rollcall_core::zephyr::kconfig::Kconfig;

use super::compiled_out::{CompiledOutEntry, EntryKey};
use super::layout::ConfigFile;
use super::rules::{Emit, Rule, RuleSet, SetSource};
use super::value::{OptionValue, line, option};
use super::{CryptoApi, ImageKey};
use crate::assets::{algorithm_properties, asset_name, parse_asset_name};
use crate::catalogue::Catalogue;

/// Where an asset goes: its image, its library and its name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetKey {
    /// The image.
    pub image: ImageKey,
    /// The library component.
    pub library: String,
    /// The asset's component name.
    pub name: String,
}

/// An asset a configuration emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundAsset {
    /// The catalogue algorithm and parameter set, for an algorithm asset.
    pub algorithm: Option<(String, Option<String>)>,
    /// The asset, with its evidence.
    pub asset: CryptoAsset,
}

/// What one configuration file (or, merged, one image) gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageFindings {
    /// The assets, by key.
    pub assets: BTreeMap<AssetKey, FoundAsset>,
    /// The algorithms compiled out of the file's image, by (library, algorithm, parameter
    /// set).
    pub compiled_out: BTreeMap<EntryKey, CompiledOutEntry>,
    /// Notes, sorted and without duplicates.
    pub notes: Vec<String>,
    /// The crypto API the file's image uses, if it has mbedTLS.
    pub api: Option<CryptoApi>,
}

/// Whether two assets' parameter sets overlap: equal, or either unknown.
fn sets_overlap(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

impl ImageFindings {
    /// Adds an asset, or merges its evidence (and a hardware execution environment) into the
    /// asset already under `key`.
    pub fn insert(&mut self, key: AssetKey, found: FoundAsset) {
        match self.assets.get_mut(&key) {
            None => {
                self.assets.insert(key, found);
            }
            Some(existing) => merge_into(&mut existing.asset, found.asset),
        }
    }

    /// Like [`ImageFindings::insert`], except that an asset without a parameter set whose
    /// algorithm the same image and library already has (with any set) adds its evidence to
    /// those assets instead: the sysbuild `SB_CONFIG_BOOT_SIGNATURE_TYPE_RSA` backs MCUboot's
    /// `RSA-PSS-2048` rather than standing beside it as `RSA-PSS`.
    pub fn insert_or_attach(&mut self, key: AssetKey, found: FoundAsset) {
        if let Some((algorithm, None)) = &found.algorithm {
            let targets: Vec<AssetKey> = self
                .assets
                .iter()
                .filter(|(k, f)| {
                    k.image == key.image
                        && k.library == key.library
                        && f.algorithm
                            .as_ref()
                            .is_some_and(|(a, _)| a.eq_ignore_ascii_case(algorithm))
                })
                .map(|(k, _)| k.clone())
                .collect();
            if !targets.is_empty() {
                for target in targets {
                    if let Some(existing) = self.assets.get_mut(&target) {
                        merge_into(&mut existing.asset, found.asset.clone());
                    }
                }
                return;
            }
        }
        self.insert(key, found);
    }

    /// Adds a compiled-out entry, merging its locators into an existing one.
    pub fn add_compiled_out(&mut self, entry: CompiledOutEntry) {
        let key = entry.key();
        match self.compiled_out.get_mut(&key) {
            Some(existing) => existing.merge(entry),
            None => {
                self.compiled_out.insert(key, entry);
            }
        }
    }

    /// Removes every compiled-out entry, of any library, for an algorithm one of the assets
    /// is (with an overlapping parameter set): what the image's configuration emits is never
    /// compiled out of it.
    pub fn drop_emitted_from_compiled_out(&mut self) {
        let emitted: Vec<(String, Option<String>)> = self
            .assets
            .values()
            .filter_map(|f| f.algorithm.clone())
            .collect();
        self.compiled_out.retain(|(_, algorithm, set), _| {
            !emitted.iter().any(|(a, s)| {
                a.eq_ignore_ascii_case(algorithm) && sets_overlap(s.as_deref(), set.as_deref())
            })
        });
    }

    /// The compiled-out entries, in (library, algorithm, parameter set) order.
    pub fn compiled_out_entries(&self) -> impl Iterator<Item = &CompiledOutEntry> {
        self.compiled_out.values()
    }
}

/// Adds `incoming`'s evidence to `existing`, and its hardware execution environment if it has
/// one.
fn merge_into(existing: &mut CryptoAsset, incoming: CryptoAsset) {
    if let (CryptoAssetProperties::Algorithm(have), CryptoAssetProperties::Algorithm(new)) =
        (&mut existing.properties, &incoming.properties)
        && have.execution_environment.is_none()
    {
        have.execution_environment = new.execution_environment;
    }
    for entry in incoming.evidence {
        existing.add_evidence(entry);
    }
}

/// One evaluation: the file, its config, the notes so far.
struct Context<'a> {
    rules: &'a RuleSet,
    config: &'a Kconfig,
    file: &'a ConfigFile,
    image: &'a ImageKey,
    catalogue: &'a Catalogue,
    notes: BTreeSet<String>,
    found: ImageFindings,
}

/// A symbol and its line: one evidence locator.
type Hit = (String, u32);

impl Context<'_> {
    fn note(&mut self, line: Option<u32>, text: &str) {
        let at = match line {
            Some(line) => format!("{}:{line}", self.file.label),
            None => self.file.label.clone(),
        };
        self.notes.insert(format!("{at}: {text}"));
    }

    /// The value of a symbol tested as a bool: an integer or string is a note and reads as
    /// absent.
    fn boolean(&mut self, symbol: &str) -> OptionValue {
        let value = option(self.config, symbol);
        match value {
            OptionValue::Int(_) | OptionValue::Str(_) => {
                let at = line(self.config, symbol);
                self.note(
                    at,
                    &format!(
                        "{symbol} is {}; expected y or n, so it is ignored",
                        value.kind()
                    ),
                );
                OptionValue::Absent
            }
            other => other,
        }
    }

    /// The symbols `symbols` all on, with their lines, or `None`.
    fn all_on(&mut self, symbols: &[String]) -> Option<Vec<Hit>> {
        let mut hits = Vec::new();
        let mut ok = true;
        for symbol in symbols {
            if self.boolean(symbol).is_on() {
                hits.push((symbol.clone(), line(self.config, symbol).unwrap_or(1)));
            } else {
                ok = false;
            }
        }
        ok.then_some(hits)
    }

    /// The symbols all explicitly off, with their lines, or `None`.
    fn all_off(&mut self, symbols: &[String]) -> Option<Vec<Hit>> {
        let mut hits = Vec::new();
        let mut ok = true;
        for symbol in symbols {
            match self.boolean(symbol).explicit_off() {
                Some(l) => hits.push((symbol.clone(), l)),
                None => ok = false,
            }
        }
        ok.then_some(hits)
    }

    /// The symbols that fire `rule`, in order, or `None` when it does not fire.
    fn fires(&mut self, rule: &Rule) -> Option<Vec<Hit>> {
        let mut hits = self.all_on(&rule.when)?;
        if !rule.when_any.is_empty() {
            let mut any = Vec::new();
            for symbol in &rule.when_any {
                if self.boolean(symbol).is_on() {
                    any.push((symbol.clone(), line(self.config, symbol).unwrap_or(1)));
                }
            }
            if any.is_empty() {
                return None;
            }
            hits.extend(any);
        }
        for (symbol, expected) in &rule.when_value {
            match option(self.config, symbol) {
                OptionValue::Str(s) if s == *expected => {
                    hits.push((symbol.clone(), line(self.config, symbol).unwrap_or(1)));
                }
                _ => return None,
            }
        }
        hits.extend(self.all_off(&rule.when_off)?);
        let mut blocked = false;
        for symbol in &rule.unless {
            if self.boolean(symbol).is_on() {
                blocked = true;
            }
        }
        (!blocked).then_some(hits)
    }

    fn locator(&self, (symbol, line): &Hit) -> Locator {
        Locator::KconfigSymbol {
            location: self.file.label.clone(),
            line: Some(*line),
            symbol: symbol.clone(),
        }
    }

    /// Evidence entries for `hits` with `reason`; a locator or reason the model rejects is a
    /// note.
    fn evidence(&mut self, hits: &[Hit], reason: &str) -> Vec<CryptoEvidence> {
        let mut out = Vec::new();
        for hit in hits {
            match CryptoEvidence::new(
                self.locator(hit),
                &self.rules.detector,
                ConfidenceLevel::High,
                reason,
            ) {
                Ok(e) => out.push(e),
                Err(e) => self.note(Some(hit.1), &format!("{}: {e}", hit.0)),
            }
        }
        out
    }

    /// The (algorithm, parameter set, extra hits) of one emission, after reading any value it
    /// takes its parameter set from.
    fn resolve(
        &mut self,
        emit: &Emit,
        first: Option<u32>,
    ) -> Vec<(String, Option<String>, Vec<Hit>, bool)> {
        match emit {
            Emit::Name(text) => match parse_asset_name(self.catalogue, text) {
                Some((alg, set)) => vec![(alg, set, Vec::new(), false)],
                None => {
                    self.note(first, &format!("{text} is not in the algorithm catalogue"));
                    Vec::new()
                }
            },
            Emit::Spec(spec) => {
                let alg = spec.algorithm.clone();
                let hw = spec.hardware;
                match &spec.parameter_set_from {
                    None => vec![(alg, spec.parameter_set.clone(), Vec::new(), hw)],
                    Some(SetSource::Int(symbol)) => {
                        let at = line(self.config, symbol);
                        match option(self.config, symbol) {
                            OptionValue::Int(n) => vec![(
                                alg,
                                Some(n.to_string()),
                                at.map(|l| (symbol.clone(), l)).into_iter().collect(),
                                hw,
                            )],
                            OptionValue::Absent => vec![(alg, None, Vec::new(), hw)],
                            other => {
                                self.note(
                                    at,
                                    &format!(
                                        "{symbol} is {}; expected an integer, so {alg} is reported without a parameter set",
                                        other.kind()
                                    ),
                                );
                                vec![(alg, None, Vec::new(), hw)]
                            }
                        }
                    }
                    Some(SetSource::Str(symbol)) => {
                        let at = line(self.config, symbol);
                        match option(self.config, symbol) {
                            OptionValue::Str(s) => vec![(
                                alg,
                                Some(s),
                                at.map(|l| (symbol.clone(), l)).into_iter().collect(),
                                hw,
                            )],
                            OptionValue::Absent => vec![(alg, None, Vec::new(), hw)],
                            other => {
                                self.note(
                                    at,
                                    &format!(
                                        "{symbol} is {}; expected a string, so {alg} is reported without a parameter set",
                                        other.kind()
                                    ),
                                );
                                vec![(alg, None, Vec::new(), hw)]
                            }
                        }
                    }
                    Some(SetSource::Dimension(name)) => {
                        let entries = self.rules.dimensions.get(name).cloned().unwrap_or_default();
                        let mut out = Vec::new();
                        for entry in entries {
                            if !self.boolean(&entry.symbol).is_on() {
                                continue;
                            }
                            let at = line(self.config, &entry.symbol).unwrap_or(1);
                            if let Some(value) = &entry.uncatalogued {
                                self.note(
                                    Some(at),
                                    &format!(
                                        "{} enables {alg} on {value}, which the algorithm catalogue does not list yet; not reported",
                                        entry.symbol
                                    ),
                                );
                                continue;
                            }
                            let target = entry.algorithm.clone().unwrap_or_else(|| alg.clone());
                            out.push((
                                target,
                                entry.parameter_set.clone(),
                                vec![(entry.symbol.clone(), at)],
                                hw,
                            ));
                        }
                        if out.is_empty() {
                            out.push((alg, None, Vec::new(), hw));
                        }
                        out
                    }
                }
            }
        }
    }

    fn target(&self, rule: &Rule) -> ImageKey {
        match &rule.image {
            Some(t) => ImageKey::new(t.kind, &t.name, None),
            None => self.image.clone(),
        }
    }

    fn run_rule(&mut self, rule: &Rule) {
        let Some(hits) = self.fires(rule) else {
            return;
        };
        let first = hits.first().cloned();
        let first_line = first.as_ref().map(|h| h.1);
        let first_symbol = first.as_ref().map(|h| h.0.clone()).unwrap_or_default();
        for name in &rule.uncatalogued {
            self.note(
                first_line,
                &format!(
                    "{first_symbol} enables {name}, which the algorithm catalogue does not list yet; not reported"
                ),
            );
        }
        if let Some(note) = &rule.note {
            self.note(first_line, note);
        }
        let (Some(library), Some(reason)) = (rule.library.clone(), rule.reason.clone()) else {
            return;
        };
        let image = self.target(rule);
        for emit in &rule.emit {
            for (alg, set, extra, hardware) in self.resolve(emit, first_line) {
                let (alg, set, properties) = match self.properties(&alg, set, first_line) {
                    Some(found) => found,
                    None => continue,
                };
                let (mut properties, oid) = properties;
                if hardware {
                    properties.execution_environment = Some(ExecutionEnvironment::Hardware);
                }
                let mut all_hits = hits.clone();
                all_hits.extend(extra);
                let evidence = self.evidence(&all_hits, &reason);
                let name = asset_name(&alg, set.as_deref());
                let built =
                    CryptoAsset::new(CryptoAssetProperties::Algorithm(properties), evidence)
                        .and_then(|a| match &oid {
                            Some(oid) => a.with_oid(oid),
                            None => Ok(a),
                        });
                match built {
                    Ok(asset) => self.found.insert(
                        AssetKey {
                            image: image.clone(),
                            library: library.clone(),
                            name,
                        },
                        FoundAsset {
                            algorithm: Some((alg, set)),
                            asset,
                        },
                    ),
                    Err(e) => self.note(first_line, &format!("{name}: {e}")),
                }
            }
        }
        if let Some(protocol) = &rule.protocol {
            let name = format!(
                "{}-{}",
                protocol.protocol_type.as_str().to_ascii_uppercase(),
                protocol.version
            );
            let properties = ProtocolProperties {
                protocol_type: Some(protocol.protocol_type),
                version: Some(protocol.version.clone()),
            };
            let evidence = self.evidence(&hits, &reason);
            match CryptoAsset::new(CryptoAssetProperties::Protocol(properties), evidence) {
                Ok(asset) => self.found.insert(
                    AssetKey {
                        image,
                        library,
                        name,
                    },
                    FoundAsset {
                        algorithm: None,
                        asset,
                    },
                ),
                Err(e) => self.note(first_line, &format!("{name}: {e}")),
            }
        }
    }

    /// The catalogue spelling, parameter set and properties of (`alg`, `set`); a parameter set
    /// the catalogue lacks is a note and falls back to none; an unknown algorithm is a note.
    #[allow(clippy::type_complexity)]
    fn properties(
        &mut self,
        alg: &str,
        set: Option<String>,
        at: Option<u32>,
    ) -> Option<(
        String,
        Option<String>,
        (rollcall_core::model::AlgorithmProperties, Option<String>),
    )> {
        let canonical = match self.catalogue.algorithm(alg) {
            Some(a) => a.name.clone(),
            None => {
                self.note(
                    at,
                    &format!("{alg} is not in the algorithm catalogue; not reported"),
                );
                return None;
            }
        };
        match algorithm_properties(self.catalogue, &canonical, set.as_deref()) {
            Ok(p) => Some((canonical, set, p)),
            Err(e) => {
                self.note(
                    at,
                    &format!("{e}; {canonical} is reported without a parameter set"),
                );
                algorithm_properties(self.catalogue, &canonical, None)
                    .ok()
                    .map(|p| (canonical, None, p))
            }
        }
    }

    fn run_hardware(&mut self) {
        for hw in &self.rules.hardware {
            let Some(hits) = self.all_on(&hw.when) else {
                continue;
            };
            let evidence = self.evidence(&hits, &hw.reason);
            // Each entry: an algorithm (every set) or an algorithm and one set.
            let targets: Vec<(String, Option<String>)> = hw
                .algorithms
                .iter()
                .filter_map(|text| parse_asset_name(self.catalogue, text))
                .collect();
            for (key, found) in &mut self.found.assets {
                let matches = key.library == hw.library
                    && found.algorithm.as_ref().is_some_and(|(a, s)| {
                        targets.iter().any(|(ta, ts)| {
                            ta.eq_ignore_ascii_case(a)
                                && ts.as_ref().is_none_or(|ts| s.as_ref() == Some(ts))
                        })
                    });
                if !matches {
                    continue;
                }
                if let CryptoAssetProperties::Algorithm(p) = &mut found.asset.properties {
                    p.execution_environment = Some(ExecutionEnvironment::Hardware);
                }
                for entry in &evidence {
                    found.asset.add_evidence(entry.clone());
                }
            }
        }
    }

    /// The libraries whose compiled-out entries a `custom_config` option outside its defaults
    /// makes untrustworthy, each with a note.
    fn untrusted_libraries(&mut self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for rule in &self.rules.custom_config {
            let value = match option(self.config, &rule.symbol) {
                OptionValue::Absent => continue,
                OptionValue::Str(s) => s,
                OptionValue::Off { .. } => String::new(),
                OptionValue::On => "y".to_owned(),
                OptionValue::Int(n) => n.to_string(),
            };
            if rule.defaults.contains(&value) {
                continue;
            }
            let at = line(self.config, &rule.symbol);
            self.note(
                at,
                &format!(
                    "{} is {value:?}, not the configuration Kconfig generates, so the symbols that are off are not taken to compile anything out of {}",
                    rule.symbol,
                    rule.libraries.join(" or ")
                ),
            );
            out.extend(rule.libraries.iter().cloned());
        }
        out
    }

    fn run_compiled_out(&mut self) {
        let untrusted = self.untrusted_libraries();
        for rule in &self.rules.compiled_out {
            if untrusted.contains(&rule.library) {
                continue;
            }
            let Some(hits) = self.all_off(&rule.when_all_off) else {
                continue;
            };
            let locators: Vec<Locator> = hits.iter().map(|h| self.locator(h)).collect();
            for text in &rule.algorithms {
                if let Some((algorithm, parameter_set)) = parse_asset_name(self.catalogue, text) {
                    self.found.add_compiled_out(CompiledOutEntry::new(
                        &rule.library,
                        &algorithm,
                        parameter_set.as_deref(),
                        locators.clone(),
                    ));
                }
            }
        }
        let image = self.image.clone();
        let emitted_here: Vec<(String, Option<String>)> = self
            .found
            .assets
            .iter()
            .filter(|(k, _)| k.image == image)
            .filter_map(|(_, f)| f.algorithm.clone())
            .collect();
        self.found.compiled_out.retain(|(_, algorithm, set), _| {
            !emitted_here.iter().any(|(a, s)| {
                a.eq_ignore_ascii_case(algorithm) && sets_overlap(s.as_deref(), set.as_deref())
            })
        });
    }

    fn run_api(&mut self) {
        let first_on = |ctx: &mut Self, symbols: &[String]| {
            symbols.iter().find(|s| ctx.boolean(s).is_on()).cloned()
        };
        let psa_symbols = self.rules.api.psa.clone();
        let legacy_symbols = self.rules.api.legacy.clone();
        let psa = first_on(self, &psa_symbols);
        let legacy = first_on(self, &legacy_symbols);
        let (api, text) = match (psa, legacy) {
            (Some(p), Some(l)) => (
                CryptoApi::Both,
                format!(
                    "uses both the PSA Crypto API ({p}) and the legacy mbedTLS crypto API ({l})"
                ),
            ),
            (Some(p), None) => (CryptoApi::Psa, format!("uses the PSA Crypto API ({p})")),
            (None, Some(l)) => (
                CryptoApi::Legacy,
                format!("uses the legacy mbedTLS crypto API ({l})"),
            ),
            (None, None) => return,
        };
        self.found.api = Some(api);
        self.note(None, &text);
    }
}

/// Evaluates `rules` against `config`, the parsed `file` of `image`, with properties from
/// `catalogue`. See the [module docs](self).
pub fn evaluate(
    rules: &RuleSet,
    config: &Kconfig,
    file: &ConfigFile,
    image: &ImageKey,
    catalogue: &Catalogue,
) -> ImageFindings {
    let mut ctx = Context {
        rules,
        config,
        file,
        image,
        catalogue,
        notes: BTreeSet::new(),
        found: ImageFindings::default(),
    };
    for rule in &rules.rules {
        ctx.run_rule(rule);
    }
    ctx.run_hardware();
    ctx.run_compiled_out();
    ctx.run_api();
    let mut found = ctx.found;
    found.notes = ctx.notes.into_iter().collect();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rollcall_core::model::ImageKind;
    use rollcall_core::zephyr::kconfig;

    fn catalogue() -> Catalogue {
        Catalogue::builtin().unwrap()
    }

    fn run(rules: &RuleSet, label: &str, image: &ImageKey, text: &str) -> ImageFindings {
        let config = kconfig::parse(text).unwrap();
        evaluate(rules, &config, &ConfigFile::new(label), image, &catalogue())
    }

    fn names(found: &ImageFindings) -> Vec<String> {
        found
            .assets
            .keys()
            .map(|k| format!("{} / library:{} / {}", k.image, k.library, k.name))
            .collect()
    }

    fn mcuboot() -> ImageKey {
        ImageKey::new(ImageKind::Bootloader, "mcuboot", None)
    }

    /// AC2: keelsign's post-quantum TLV options (provisional symbol names) give ML-DSA-44,
    /// ML-DSA-65 and HSS with the configured LMS parameter set, under MCUboot.
    #[test]
    fn keelsign_pq_tlv_options_recognised_when_present() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let text = "\
CONFIG_MCUBOOT=y
CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y
CONFIG_BOOT_KEELSIGN_MLDSA44=y
CONFIG_BOOT_KEELSIGN_MLDSA65=y
CONFIG_BOOT_KEELSIGN_LMS_HSS=y
CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET=\"LMS_SHA256_M32_H10\"
";
        let found = run(&rules, "mcuboot/zephyr/.config", &mcuboot(), text);
        assert_eq!(
            names(&found),
            [
                "bootloader:mcuboot / library:mcuboot / Ed25519",
                "bootloader:mcuboot / library:mcuboot / HSS-LMS_SHA256_M32_H10",
                "bootloader:mcuboot / library:mcuboot / ML-DSA-44",
                "bootloader:mcuboot / library:mcuboot / ML-DSA-65",
            ]
        );
        let hss = &found.assets.values().nth(1).unwrap().asset;
        let symbols: Vec<String> = hss.evidence.iter().map(|e| e.locator.to_string()).collect();
        assert_eq!(
            symbols,
            [
                "mcuboot/zephyr/.config:5 CONFIG_BOOT_KEELSIGN_LMS_HSS",
                "mcuboot/zephyr/.config:6 CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET",
            ]
        );
        for found in found.assets.values() {
            for e in &found.asset.evidence {
                assert_eq!(e.detector(), "kconfig");
                assert_eq!(e.confidence, ConfidenceLevel::High);
            }
        }
        let mldsa = found
            .assets
            .iter()
            .find(|(k, _)| k.name == "ML-DSA-65")
            .unwrap()
            .1;
        assert!(
            mldsa
                .asset
                .evidence
                .iter()
                .all(|e| e.reason().contains("TLV 0x4BA2")),
            "{:?}",
            mldsa.asset.evidence
        );
        // Not present: nothing.
        let found = run(
            &rules,
            "mcuboot/zephyr/.config",
            &mcuboot(),
            "# CONFIG_BOOT_KEELSIGN_MLDSA44 is not set\n",
        );
        assert!(found.assets.is_empty());
        // HSS without a parameter set: unsized; with one the catalogue lacks: a note.
        let found = run(
            &rules,
            "c",
            &mcuboot(),
            "CONFIG_BOOT_KEELSIGN_LMS_HSS=y\nCONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET=\"LMS_SHA256_M32_H99\"\n",
        );
        assert_eq!(
            names(&found),
            ["bootloader:mcuboot / library:mcuboot / HSS"]
        );
        assert_eq!(found.notes.len(), 1, "{:?}", found.notes);
    }

    /// ESP-IDF secure boot v2: the RSA scheme is RSA-PSS-3072, the ECDSA scheme ECDSA on the
    /// configured curve, under `bootloader:bootloader` (verified at boot) and under the
    /// application (verified on OTA update); without secure boot, a note. Flash encryption is
    /// XTS-AES, except on the original ESP32.
    #[test]
    fn esp_secure_boot_v2_rsa_and_ecdsa_schemes() {
        let rules = RuleSet::builtin_esp_idf().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let rsa = "\
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_SIGNED_ON_BOOT=y
CONFIG_SECURE_SIGNED_ON_UPDATE=y
CONFIG_SECURE_SIGNED_APPS=y
CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y
# CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME is not set
CONFIG_SECURE_FLASH_ENC_ENABLED=y
CONFIG_SECURE_FLASH_ENCRYPTION_AES256=y
CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y
";
        let found = run(&rules, "sdkconfig", &app, rsa);
        assert_eq!(
            names(&found),
            [
                "bootloader:bootloader / library:bootloader_support / RSA-PSS-3072",
                "bootloader:bootloader / library:bootloader_support / SHA2-256",
                "application:widget / library:bootloader_support / RSA-PSS-3072",
                "application:widget / library:bootloader_support / SHA2-256",
            ]
        );
        assert!(
            found.notes.iter().any(|n| n.contains("enables XTS-AES")),
            "{:?}",
            found.notes
        );
        let esp32 = format!("{rsa}CONFIG_IDF_TARGET_ESP32=y\n");
        let notes = run(&rules, "sdkconfig", &app, &esp32).notes;
        assert!(
            notes
                .iter()
                .any(|n| n.contains("per-block key tweak, not XTS"))
                && !notes.iter().any(|n| n.contains("enables XTS-AES")),
            "{notes:?}"
        );
        assert!(
            found.notes.iter().any(|n| n.contains("release mode")),
            "{:?}",
            found.notes
        );
        assert!(
            !found
                .notes
                .iter()
                .any(|n| n.contains("secure boot not enabled"))
        );
        let ecdsa = "\
CONFIG_SECURE_BOOT=y
CONFIG_SECURE_BOOT_V2_ENABLED=y
CONFIG_SECURE_SIGNED_ON_BOOT=y
# CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME is not set
CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME=y
# CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_192_BITS is not set
CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS=y
";
        let found = run(&rules, "sdkconfig", &app, ecdsa);
        assert_eq!(
            names(&found),
            [
                "bootloader:bootloader / library:bootloader_support / ECDSA-secp256r1",
                "bootloader:bootloader / library:bootloader_support / SHA2-256",
            ]
        );
        let ecdsa_384 = ecdsa.replace(
            "CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS=y",
            "CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_384_BITS=y",
        );
        let found = run(&rules, "sdkconfig", &app, &ecdsa_384);
        assert!(names(&found).contains(
            &"bootloader:bootloader / library:bootloader_support / ECDSA-secp384r1".to_owned()
        ));
        let ecdsa_192 = ecdsa.replace(
            "CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS=y",
            "CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_192_BITS=y",
        );
        let found = run(&rules, "sdkconfig", &app, &ecdsa_192);
        assert!(
            found.notes.iter().any(|n| n.contains("secp192r1")),
            "{:?}",
            found.notes
        );
        let off = "# CONFIG_SECURE_BOOT is not set\n# CONFIG_SECURE_FLASH_ENC_ENABLED is not set\n";
        let found = run(&rules, "sdkconfig", &app, off);
        assert!(found.assets.is_empty());
        assert_eq!(
            found.notes,
            [
                "sdkconfig:1: secure boot not enabled (CONFIG_SECURE_BOOT is not set)",
                "sdkconfig:2: flash encryption not enabled (CONFIG_SECURE_FLASH_ENC_ENABLED is not set)",
            ]
        );
    }

    /// ESP-IDF signed apps without secure boot: with the RSA or ECDSA v2 scheme only the app
    /// verifies signatures, on OTA update (`CONFIG_SECURE_SIGNED_ON_UPDATE`), so the assets go
    /// under the application and none under the bootloader; the v1 ECDSA scheme with
    /// `CONFIG_SECURE_SIGNED_ON_BOOT_NO_SECURE_BOOT` is verified by the bootloader too.
    #[test]
    fn esp_signed_apps_without_secure_boot_are_verified_on_update() {
        let rules = RuleSet::builtin_esp_idf().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        for scheme in [
            "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME",
            "CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME",
        ] {
            let text = format!(
                "# CONFIG_SECURE_BOOT is not set\nCONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y\n{scheme}=y\nCONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y\nCONFIG_SECURE_SIGNED_ON_UPDATE=y\nCONFIG_SECURE_SIGNED_APPS=y\nCONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS=y\n"
            );
            let found = run(&rules, "sdkconfig", &app, &text);
            let names = names(&found);
            assert!(!names.is_empty(), "{scheme}");
            assert!(
                names
                    .iter()
                    .all(|n| n.starts_with("application:widget / library:bootloader_support / ")),
                "{scheme}: {names:?}"
            );
            assert!(names.iter().any(|n| n.ends_with("/ SHA2-256")), "{names:?}");
            for f in found.assets.values() {
                assert!(
                    f.asset.evidence.iter().all(|e| e
                        .reason()
                        .starts_with("the app verifies OTA update signatures")),
                    "{:?}",
                    f.asset.evidence
                );
                assert!(f.asset.evidence.iter().any(|e| {
                    e.locator.symbol().as_deref() == Some("CONFIG_SECURE_SIGNED_ON_UPDATE")
                }));
            }
            assert!(
                found
                    .notes
                    .iter()
                    .any(|n| n.contains("secure boot not enabled")),
                "{:?}",
                found.notes
            );
            // Without the update check either, nothing verifies: no asset.
            let off = text.replace("CONFIG_SECURE_SIGNED_ON_UPDATE=y\n", "");
            assert!(
                run(&rules, "sdkconfig", &app, &off).assets.is_empty(),
                "{scheme}"
            );
        }
        // v1 ECDSA, bootloader check on: the bootloader and the app both verify.
        let v1 = "# CONFIG_SECURE_BOOT is not set\nCONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT=y\nCONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME=y\nCONFIG_SECURE_SIGNED_ON_BOOT_NO_SECURE_BOOT=y\nCONFIG_SECURE_SIGNED_ON_BOOT=y\nCONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT=y\nCONFIG_SECURE_SIGNED_ON_UPDATE=y\n";
        assert_eq!(
            names(&run(&rules, "sdkconfig", &app, v1)),
            [
                "bootloader:bootloader / library:bootloader_support / ECDSA-secp256r1",
                "bootloader:bootloader / library:bootloader_support / SHA2-256",
                "application:widget / library:bootloader_support / ECDSA-secp256r1",
                "application:widget / library:bootloader_support / SHA2-256",
            ]
        );
    }

    /// ESP-IDF hardware: `CONFIG_MBEDTLS_HARDWARE_MPI` is a note and marks nothing as
    /// hardware; the SHA accelerator marks SHA2-256, and SHA2-384/512 only where the SoC
    /// supports them; SHA2-256 is reported in software when `CONFIG_MBEDTLS_HARDWARE_SHA` is
    /// off.
    #[test]
    fn esp_hardware_marks_only_what_the_accelerator_runs() {
        let rules = RuleSet::builtin_esp_idf().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let hardware = |found: &ImageFindings, name: &str| -> Option<bool> {
            found
                .assets
                .iter()
                .find(|(k, _)| k.name == name)
                .map(|(_, f)| match &f.asset.properties {
                    CryptoAssetProperties::Algorithm(p) => {
                        p.execution_environment == Some(ExecutionEnvironment::Hardware)
                    }
                    _ => false,
                })
        };
        let text = "\
CONFIG_SOC_SHA_SUPPORT_SHA384=y
CONFIG_MBEDTLS_HARDWARE_MPI=y
CONFIG_MBEDTLS_HARDWARE_SHA=y
CONFIG_MBEDTLS_SHA512_C=y
CONFIG_MBEDTLS_KEY_EXCHANGE_RSA=y
CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y
";
        let found = run(&rules, "sdkconfig", &app, text);
        assert_eq!(hardware(&found, "RSA-PKCS1v15"), Some(false));
        assert_eq!(hardware(&found, "SHA2-256"), Some(true));
        assert_eq!(hardware(&found, "SHA2-384"), Some(true));
        // No CONFIG_SOC_SHA_SUPPORT_SHA512: SHA-512 is software.
        assert_eq!(hardware(&found, "SHA2-512"), Some(false));
        assert!(
            found
                .notes
                .iter()
                .any(|n| n.starts_with("sdkconfig:2: mbedTLS uses the MPI accelerator")),
            "{:?}",
            found.notes
        );
        let sha384 = found
            .assets
            .iter()
            .find(|(k, _)| k.name == "SHA2-384")
            .unwrap()
            .1;
        let symbols: BTreeSet<String> = sha384
            .asset
            .evidence
            .iter()
            .filter_map(|e| e.locator.symbol())
            .collect();
        assert!(
            symbols.contains("CONFIG_SOC_SHA_SUPPORT_SHA384"),
            "{symbols:?}"
        );
        // The SHA accelerator off: SHA2-256 in software.
        let found = run(
            &rules,
            "sdkconfig",
            &app,
            "# CONFIG_MBEDTLS_HARDWARE_SHA is not set\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:mbedtls / SHA2-256"]
        );
        assert_eq!(hardware(&found, "SHA2-256"), Some(false));
    }

    /// AC3: symbols that are set but have nothing to do with which algorithms are built (log
    /// levels, buffer sizes, module switches, key files, capability flags) give no asset, no
    /// compiled-out entry and no note. The names are real ones from the fixtures.
    /// (`CONFIG_MBEDTLS_CFG_FILE` used to be here; it now matters when it names a header Kconfig
    /// does not generate, see `custom_mbedtls_config_file_drops_compiled_out_entries`.)
    #[test]
    fn set_but_irrelevant_symbols_produce_no_assets() {
        let text = "\
CONFIG_MBEDTLS_LOG_LEVEL=3
CONFIG_MBEDTLS_LOG_LEVEL_DEFAULT=y
CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=2048
CONFIG_MBEDTLS_HEAP_SIZE=60000
CONFIG_MBEDTLS_ENABLE_HEAP=y
CONFIG_ZEPHYR_MBEDTLS_MODULE=y
CONFIG_ZEPHYR_TF_PSA_CRYPTO_MODULE=y
CONFIG_MBEDTLS_VERSION_4_x=y
CONFIG_MBEDTLS_INIT=y
CONFIG_APP_LINK_WITH_MBEDTLS=y
CONFIG_MBEDTLS_PSK_MAX_LEN=32
CONFIG_MBEDTLS_PSA_KEY_SLOT_COUNT=16
CONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"\"
CONFIG_BOOT_SIGNATURE_KEY_FILE=\"/zephyrproject/bootloader/mcuboot/root-rsa-2048.pem\"
CONFIG_BOOT_ENCRYPTION_SUPPORT=y
CONFIG_BOOT_IMG_HASH_ALG_SHA256_ALLOW=y
CONFIG_MCUBOOT_LOG_LEVEL=2
CONFIG_NRF_SOC_SECURE_SUPPORTED=y
CONFIG_CURRENT_THREAD_USE_TLS=y
CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES=4
CONFIG_TLS_CREDENTIALS=y
CONFIG_BT_CTLR_CRYPTO=y
CONFIG_BT_CTLR_CRYPTO_SUPPORT=y
CONFIG_BT_CTLR_LE_ENC_SUPPORT=y
CONFIG_BT_HCI_TX_STACK_SIZE=768
CONFIG_SOC_SECURE_BOOT_SUPPORTED=y
CONFIG_SECURE_BOOT_V1_SUPPORTED=y
CONFIG_SOC_FLASH_ENC_SUPPORTED=y
CONFIG_SOC_AES_SUPPORTED=y
CONFIG_SOC_SHA_SUPPORT_SHA256=y
CONFIG_SOC_AES_SUPPORT_AES_256=y
CONFIG_SOC_FLASH_ENCRYPTED_XTS_AES_BLOCK_MAX=32
CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN=16384
CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS=200
CONFIG_APP_RETRIEVE_LEN_ELF_SHA=9
CONFIG_ESP_TLS_USING_MBEDTLS=y
SB_CONFIG_BOOT_SIGNATURE_KEY_FILE=\"/zephyrproject/bootloader/mcuboot/root-rsa-2048.pem\"
SB_CONFIG_SUPPORT_BOOT_ENCRYPTION=y
SB_CONFIG_ZEPHYR_MBEDTLS_MODULE=y
";
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        for rules in [
            RuleSet::builtin_zephyr().unwrap(),
            RuleSet::builtin_esp_idf().unwrap(),
        ] {
            let found = run(&rules, "zephyr/.config", &app, text);
            assert!(found.assets.is_empty(), "{:?}", names(&found));
            assert!(found.compiled_out.is_empty(), "{:?}", found.compiled_out);
            assert!(found.notes.is_empty(), "{:?}", found.notes);
            assert_eq!(found.api, None);
            // And none of them is a rule's symbol.
            let symbols = rules.symbols();
            for line in text.lines() {
                let symbol = line.split('=').next().unwrap();
                assert!(!symbols.contains(symbol), "{symbol}");
            }
        }
    }

    /// Two rules that emit the same asset give one asset with both symbols' evidence; a PSA
    /// mode needs its key type; an unless symbol blocks a rule.
    #[test]
    fn same_asset_from_two_rules_merges_evidence_and_conditions_hold() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let found = run(
            &rules,
            "zephyr/.config",
            &app,
            "CONFIG_PSA_WANT_ALG_ECDSA=y\nCONFIG_PSA_WANT_ALG_DETERMINISTIC_ECDSA=y\nCONFIG_PSA_WANT_ECC_SECP_R1_256=y\nCONFIG_PSA_WANT_ALG_GCM=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:psa-crypto / ECDSA-secp256r1"]
        );
        let ecdsa = &found.assets.values().next().unwrap().asset;
        let symbols: BTreeSet<String> = ecdsa
            .evidence
            .iter()
            .filter_map(|e| e.locator.symbol())
            .collect();
        assert_eq!(
            symbols,
            BTreeSet::from([
                "CONFIG_PSA_WANT_ALG_DETERMINISTIC_ECDSA".to_owned(),
                "CONFIG_PSA_WANT_ALG_ECDSA".to_owned(),
                "CONFIG_PSA_WANT_ECC_SECP_R1_256".to_owned(),
            ])
        );
        // BT: LE Secure Connections is ECDH-P256 unless legacy pairing only; legacy pairing is
        // AES-128 unless SC only.
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_BT_SMP=y\nCONFIG_BT_SMP_SC_ONLY=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:zephyr-bluetooth / ECDH-secp256r1"]
        );
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_BT_SMP=y\nCONFIG_BT_SMP_LEGACY_PAIR_ONLY=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:zephyr-bluetooth / AES-ECB-128"]
        );
    }

    fn notes_containing<'a>(found: &'a ImageFindings, needle: &str) -> Vec<&'a String> {
        found.notes.iter().filter(|n| n.contains(needle)).collect()
    }

    /// nRF Connect SDK legacy mbedTLS names (`MBEDTLS_AES_C`, `MBEDTLS_CIPHER_MODE_CBC`,
    /// `MBEDTLS_GCM_C`, ...) give assets under `library:mbedtls`; the Zephyr 3.x
    /// `CONFIG_MBEDTLS_CIPHER_AES_ENABLED` does not combine with an NCS mode switch.
    #[test]
    fn ncs_legacy_mbedtls_names_give_assets() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let text = "\
CONFIG_NRF_SECURITY=y
CONFIG_MBEDTLS_AES_C=y
CONFIG_MBEDTLS_CIPHER_MODE_CBC=y
CONFIG_MBEDTLS_GCM_C=y
";
        let found = run(&rules, "zephyr/.config", &app, text);
        assert_eq!(
            names(&found),
            [
                "application:widget / library:mbedtls / AES-CBC",
                "application:widget / library:mbedtls / AES-GCM",
            ]
        );
        let cbc = &found.assets.values().next().unwrap().asset;
        let symbols: Vec<String> = cbc.evidence.iter().map(|e| e.locator.to_string()).collect();
        assert_eq!(
            symbols,
            [
                "zephyr/.config:2 CONFIG_MBEDTLS_AES_C",
                "zephyr/.config:3 CONFIG_MBEDTLS_CIPHER_MODE_CBC",
            ]
        );
        assert_eq!(found.api, Some(CryptoApi::Both));
        // The rest of Kconfig.legacy's algorithm switches.
        let text = "\
CONFIG_MBEDTLS_LEGACY_CRYPTO_C=y
CONFIG_MBEDTLS_AES_C=y
CONFIG_MBEDTLS_CIPHER_MODE_CTR=y
CONFIG_MBEDTLS_CIPHER_MODE_XTS=y
CONFIG_MBEDTLS_CMAC_C=y
CONFIG_MBEDTLS_CCM_C=y
CONFIG_MBEDTLS_CHACHA20_C=y
CONFIG_MBEDTLS_POLY1305_C=y
CONFIG_MBEDTLS_CHACHAPOLY_C=y
CONFIG_MBEDTLS_MD5_C=y
CONFIG_MBEDTLS_SHA1_C=y
CONFIG_MBEDTLS_SHA224_C=y
CONFIG_MBEDTLS_SHA256_C=y
CONFIG_MBEDTLS_SHA384_C=y
CONFIG_MBEDTLS_SHA512_C=y
CONFIG_MBEDTLS_ECJPAKE_C=y
CONFIG_MBEDTLS_ECP_C=y
CONFIG_MBEDTLS_ECDH_C=y
CONFIG_MBEDTLS_ECP_DP_CURVE448_ENABLED=y
";
        let found = run(&rules, "zephyr/.config", &app, text);
        assert_eq!(
            names(&found),
            [
                "application:widget / library:mbedtls / AES-CCM",
                "application:widget / library:mbedtls / AES-CTR",
                "application:widget / library:mbedtls / ChaCha20-Poly1305-256",
                "application:widget / library:mbedtls / ECDH",
                "application:widget / library:mbedtls / SHA2-224",
                "application:widget / library:mbedtls / SHA2-256",
                "application:widget / library:mbedtls / SHA2-384",
                "application:widget / library:mbedtls / SHA2-512",
            ]
        );
        for name in [
            "AES-XTS",
            "CMAC",
            "ChaCha20,",
            "MD5",
            "SHA-1",
            "EC-JPAKE",
            "curve448",
        ] {
            assert_eq!(
                notes_containing(&found, name).len(),
                1,
                "{name}: {:?}",
                found.notes
            );
        }
        // The NCS switches explicitly off compile algorithms out of mbedtls.
        let found = run(
            &rules,
            "zephyr/.config",
            &app,
            "# CONFIG_MBEDTLS_AES_C is not set\n# CONFIG_MBEDTLS_SHA512_C is not set\n",
        );
        for (alg, set) in [("AES-CBC", None), ("AES-GCM", None), ("SHA2", Some("512"))] {
            assert!(
                found
                    .compiled_out
                    .keys()
                    .any(|(l, a, s)| l == "mbedtls" && a == alg && s.as_deref() == set),
                "{alg}: {:?}",
                found.compiled_out.keys()
            );
        }
        // Zephyr 3.x's AES switch with the NCS CBC switch is no tree's spelling: nothing.
        let found = run(
            &rules,
            "zephyr/.config",
            &app,
            "CONFIG_MBEDTLS_CIPHER_AES_ENABLED=y\nCONFIG_MBEDTLS_CIPHER_MODE_CBC=y\n",
        );
        assert!(found.assets.is_empty(), "{:?}", names(&found));
    }

    /// A configuration header Kconfig does not generate (a user config file, a custom
    /// `CONFIG_MBEDTLS_CONFIG_FILE`/`CONFIG_MBEDTLS_CFG_FILE`/`CONFIG_TF_PSA_CRYPTO_CONFIG_FILE`)
    /// drops the image's mbedtls and psa-crypto compiled-out entries, with a note; the
    /// Kconfig-generated defaults (from the fixtures and the Zephyr, NCS trees) keep them.
    #[test]
    fn custom_mbedtls_config_file_drops_compiled_out_entries() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let off = "CONFIG_MBEDTLS_CIPHER_MODE_CBC=n\n# CONFIG_PSA_WANT_ALG_GCM is not set\n";
        for defaults in [
            "",
            "CONFIG_MBEDTLS_USER_CONFIG_FILE=\"\"\n",
            "CONFIG_MBEDTLS_CONFIG_FILE=\"config-mbedtls.h\"\nCONFIG_MBEDTLS_CFG_FILE=\"\"\n",
            "CONFIG_MBEDTLS_CFG_FILE=\"config-mbedtls.h\"\n",
            "CONFIG_MBEDTLS_CFG_FILE=\"config-tls-generic.h\"\n",
            "CONFIG_MBEDTLS_CFG_FILE=\"nrf-config.h\"\nCONFIG_MBEDTLS_CONFIG_FILE=\"nrf-config.h\"\n",
            "CONFIG_TF_PSA_CRYPTO_CONFIG_FILE=\"config-tf-psa-crypto.h\"\nCONFIG_TF_PSA_CRYPTO_USER_CONFIG_FILE=\"\"\n",
            // nRF Connect SDK 3.4 (Kconfig.tf-psa-crypto.defconfig) and 2.9 to 3.3.
            "CONFIG_MBEDTLS_CONFIG_FILE=\"nrf-config.h\"\nCONFIG_TF_PSA_CRYPTO_CONFIG_FILE=\"nrf-psa-crypto-config.h\"\nCONFIG_TF_PSA_CRYPTO_USER_CONFIG_FILE=\"nrf-psa-crypto-user-config.h\"\n",
            "CONFIG_MBEDTLS_CFG_FILE=\"nrf-config.h\"\nCONFIG_MBEDTLS_PSA_CRYPTO_CONFIG_FILE=\"nrf-psa-crypto-config.h\"\nCONFIG_MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE=\"nrf-psa-crypto-user-config.h\"\n",
        ] {
            let found = run(&rules, "zephyr/.config", &app, &format!("{defaults}{off}"));
            assert_eq!(
                found.compiled_out.len(),
                2,
                "{defaults:?}: {:?}",
                found.compiled_out
            );
            assert!(found.notes.is_empty(), "{defaults:?}: {:?}", found.notes);
        }
        for custom in [
            "CONFIG_MBEDTLS_USER_CONFIG_FILE=\"my-mbedtls.h\"\n",
            "CONFIG_MBEDTLS_CONFIG_FILE=\"mcuboot-mbedtls-cfg.h\"\n",
            "CONFIG_MBEDTLS_CFG_FILE=\"board-tls.h\"\n",
            "CONFIG_TF_PSA_CRYPTO_CONFIG_FILE=\"mine.h\"\n",
            "CONFIG_TF_PSA_CRYPTO_USER_CONFIG_FILE=\"extra.h\"\n",
            "CONFIG_MBEDTLS_PSA_CRYPTO_CONFIG_FILE=\"my-psa.h\"\n",
            "CONFIG_MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE=\"my-psa-user.h\"\n",
        ] {
            let found = run(&rules, "zephyr/.config", &app, &format!("{custom}{off}"));
            assert!(
                found.compiled_out.is_empty(),
                "{custom:?}: {:?}",
                found.compiled_out
            );
            assert_eq!(found.notes.len(), 1, "{custom:?}: {:?}", found.notes);
            let note = &found.notes[0];
            assert!(note.starts_with("zephyr/.config:1: CONFIG_"), "{note}");
            assert!(
                note.contains("not the configuration Kconfig generates")
                    && note.ends_with("compile anything out of mbedtls or psa-crypto"),
                "{note}"
            );
        }
        // The assets are still reported: only the compiled-out list is affected.
        let found = run(
            &rules,
            "zephyr/.config",
            &app,
            "CONFIG_MBEDTLS_USER_CONFIG_FILE=\"my.h\"\nCONFIG_PSA_WANT_ALG_SHA_256=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:psa-crypto / SHA2-256"]
        );
    }

    /// TLS key exchanges are TLS 1.2 only: `CONFIG_MBEDTLS_KEY_EXCHANGE_*` alone (as in
    /// MCUboot's mbedTLS), or with only TLS 1.3, gives nothing; with TLS 1.2 on, spelt either
    /// way, it gives its algorithms, the TLS symbol among the evidence. One `when_any` rule per
    /// key exchange: both spellings on give one evidence entry each, no duplicates.
    #[test]
    fn tls_key_exchange_needs_a_tls_version() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let kx = "CONFIG_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED=y\nCONFIG_MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED=y\nCONFIG_PSA_WANT_ECC_SECP_R1_256=y\n";
        for not_tls12 in [
            "",
            "# CONFIG_MBEDTLS_TLS_VERSION_1_2 is not set\n",
            "CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y\n# CONFIG_MBEDTLS_SSL_PROTO_TLS1_2 is not set\n",
            "CONFIG_MBEDTLS_TLS_VERSION_1_3=y\n",
        ] {
            let found = run(&rules, "c", &app, &format!("{kx}{not_tls12}"));
            let names = names(&found);
            assert!(
                !names
                    .iter()
                    .any(|n| n.ends_with("/ RSA-PKCS1v15") || n.contains("/ ECDH")),
                "{not_tls12:?}: {names:?}"
            );
        }
        let symbols_of = |found: &ImageFindings, name: &str| -> Vec<String> {
            found
                .assets
                .iter()
                .find(|(k, _)| k.name == name)
                .map(|(_, f)| {
                    f.asset
                        .evidence
                        .iter()
                        .filter_map(|e| e.locator.symbol())
                        .collect()
                })
                .unwrap_or_default()
        };
        for tls in [
            "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2",
            "CONFIG_MBEDTLS_TLS_VERSION_1_2",
        ] {
            let found = run(&rules, "c", &app, &format!("{kx}{tls}=y\n"));
            let names = names(&found);
            for want in [
                "application:widget / library:mbedtls / ECDH-secp256r1",
                "application:widget / library:mbedtls / RSA-PKCS1v15",
            ] {
                assert!(names.contains(&want.to_owned()), "{tls}: {names:?}");
            }
            let mut symbols = symbols_of(&found, "RSA-PKCS1v15");
            symbols.sort();
            assert_eq!(
                symbols,
                ["CONFIG_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED", tls],
                "{tls}"
            );
        }
        // Both spellings on: each symbol once.
        let found = run(
            &rules,
            "c",
            &app,
            &format!("{kx}CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y\nCONFIG_MBEDTLS_TLS_VERSION_1_2=y\n"),
        );
        assert_eq!(
            symbols_of(&found, "RSA-PKCS1v15"),
            [
                "CONFIG_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED",
                "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2",
                "CONFIG_MBEDTLS_TLS_VERSION_1_2",
            ]
        );
        // ESP-IDF: the key exchanges need CONFIG_MBEDTLS_SSL_PROTO_TLS1_2 too.
        let esp = RuleSet::builtin_esp_idf().unwrap();
        let esp_kx = "CONFIG_MBEDTLS_KEY_EXCHANGE_RSA=y\n";
        assert!(run(&esp, "sdkconfig", &app, esp_kx).assets.is_empty());
        assert!(
            run(
                &esp,
                "sdkconfig",
                &app,
                &format!("{esp_kx}CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y\n# CONFIG_MBEDTLS_SSL_PROTO_TLS1_2 is not set\n")
            )
            .assets
            .keys()
            .all(|k| k.name != "RSA-PKCS1v15")
        );
        let found = run(
            &esp,
            "sdkconfig",
            &app,
            &format!("{esp_kx}CONFIG_MBEDTLS_SSL_PROTO_TLS1_2=y\n"),
        );
        assert_eq!(
            symbols_of(&found, "RSA-PKCS1v15"),
            [
                "CONFIG_MBEDTLS_KEY_EXCHANGE_RSA",
                "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2"
            ]
        );
    }

    /// An RSA asset the configuration sizes with a length the catalogue lacks falls back to no
    /// parameter set, but keeps the algorithm's padding (PSS is CycloneDX `other`).
    #[test]
    fn rsa_without_a_catalogued_size_keeps_its_padding() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let found = run(
            &rules,
            "c",
            &mcuboot(),
            "CONFIG_BOOT_SIGNATURE_TYPE_RSA=y\nCONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN=1024\nCONFIG_PSA_WANT_ALG_RSA_PKCS1V15_SIGN=y\n",
        );
        let padding = |name: &str| {
            found
                .assets
                .iter()
                .find(|(k, _)| k.name == name)
                .and_then(|(_, f)| match &f.asset.properties {
                    CryptoAssetProperties::Algorithm(p) => p.padding,
                    _ => None,
                })
        };
        assert_eq!(
            padding("RSA-PSS"),
            Some(rollcall_core::model::Padding::Other)
        );
        assert_eq!(
            padding("RSA-PKCS1v15"),
            Some(rollcall_core::model::Padding::Pkcs1v15)
        );
        assert!(
            found
                .notes
                .iter()
                .any(|n| n.contains("reported without a parameter set")),
            "{:?}",
            found.notes
        );
    }

    /// MCUboot's ECDSA P-256 and Ed25519 signatures, and its image encryption key exchanges:
    /// RSA-OAEP-2048, ECIES on P-256 (ECDH, HKDF and HMAC with SHA-256), ECIES on X25519 (with
    /// SHA-256 by default, SHA-512 when chosen), each with AES-CTR; and no signature type is a
    /// note.
    #[test]
    fn mcuboot_ecdsa_ed25519_and_encryption_rules() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let mb = |text: &str| names(&run(&rules, "mcuboot/zephyr/.config", &mcuboot(), text));
        let at = |names: &[&str]| -> Vec<String> {
            names
                .iter()
                .map(|n| format!("bootloader:mcuboot / library:mcuboot / {n}"))
                .collect()
        };
        assert_eq!(
            mb("CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y\n"),
            at(&["ECDSA-secp256r1"])
        );
        assert_eq!(
            mb("CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y\n"),
            at(&["Ed25519"])
        );
        assert_eq!(
            mb("CONFIG_BOOT_ENCRYPT_IMAGE=y\nCONFIG_BOOT_ENCRYPT_RSA=y\n"),
            at(&["AES-CTR-128", "RSA-OAEP-2048"])
        );
        assert_eq!(
            mb(
                "CONFIG_BOOT_ENCRYPT_IMAGE=y\nCONFIG_BOOT_ENCRYPT_EC256=y\nCONFIG_BOOT_ENCRYPT_ALG_AES_256=y\n"
            ),
            at(&[
                "AES-CTR-256",
                "ECDH-secp256r1",
                "HKDF-SHA-256",
                "HMAC-SHA-256"
            ])
        );
        assert_eq!(
            mb("CONFIG_BOOT_ENCRYPT_IMAGE=y\nCONFIG_BOOT_ENCRYPT_X25519=y\n"),
            at(&["AES-CTR-128", "HKDF-SHA-256", "HMAC-SHA-256", "X25519"])
        );
        assert_eq!(
            mb(
                "CONFIG_BOOT_ENCRYPT_IMAGE=y\nCONFIG_BOOT_ENCRYPT_X25519=y\nCONFIG_BOOT_HMAC_SHA512=y\n"
            ),
            at(&["AES-CTR-128", "HKDF-SHA-512", "HMAC-SHA-512", "X25519"])
        );
        // The encryption key exchange symbols do nothing without CONFIG_BOOT_ENCRYPT_IMAGE.
        assert!(mb("CONFIG_BOOT_ENCRYPT_EC256=y\nCONFIG_BOOT_ENCRYPT_X25519=y\n").is_empty());
        let found = run(
            &rules,
            "mcuboot/zephyr/.config",
            &mcuboot(),
            "CONFIG_BOOT_SIGNATURE_TYPE_NONE=y\n",
        );
        assert!(found.assets.is_empty());
        assert_eq!(
            found.notes,
            [
                "mcuboot/zephyr/.config:1: MCUboot does not verify image signatures (CONFIG_BOOT_SIGNATURE_TYPE_NONE)"
            ]
        );
    }

    /// Small mapping fixes: the PQCP driver with ML-DSA-87 gives only `ML-DSA-87`, not an
    /// unsized `ML-DSA` too; LE Secure Connections notes AES-CMAC; CryptoCell marks only the
    /// hash sets it has (up to SHA-256) as hardware.
    #[test]
    fn mldsa87_le_sc_cmac_and_cryptocell_hash_sets() {
        let rules = RuleSet::builtin_zephyr().unwrap();
        let app = ImageKey::new(ImageKind::Application, "widget", None);
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED=y\nCONFIG_TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:psa-crypto / ML-DSA-87"]
        );
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_TF_PSA_CRYPTO_PQCP_MLDSA_ENABLED=y\n",
        );
        assert_eq!(
            names(&found),
            ["application:widget / library:psa-crypto / ML-DSA"]
        );
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_BT_SMP=y\nCONFIG_BT_SMP_SC_ONLY=y\n",
        );
        assert_eq!(
            found.notes,
            [
                "c:1: CONFIG_BT_SMP enables AES-CMAC, which the algorithm catalogue does not list yet; not reported"
            ]
        );
        let found = run(
            &rules,
            "c",
            &app,
            "CONFIG_NRF_SECURITY=y\nCONFIG_PSA_CRYPTO_DRIVER_CC3XX=y\nCONFIG_PSA_WANT_ALG_SHA_256=y\nCONFIG_PSA_WANT_ALG_SHA_384=y\nCONFIG_PSA_WANT_ALG_SHA_512=y\nCONFIG_PSA_WANT_ALG_HMAC=y\n",
        );
        let hardware: Vec<(String, bool)> = found
            .assets
            .iter()
            .map(|(k, f)| {
                let hw = matches!(
                    &f.asset.properties,
                    CryptoAssetProperties::Algorithm(p)
                        if p.execution_environment == Some(ExecutionEnvironment::Hardware)
                );
                (k.name.clone(), hw)
            })
            .collect();
        assert_eq!(
            hardware,
            [
                ("HMAC-SHA-256".to_owned(), true),
                ("HMAC-SHA-384".to_owned(), false),
                ("HMAC-SHA-512".to_owned(), false),
                ("SHA2-256".to_owned(), true),
                ("SHA2-384".to_owned(), false),
                ("SHA2-512".to_owned(), false),
            ]
        );
    }

    proptest! {
        /// Whatever a `.config` says, evaluation never panics and every asset has evidence.
        #[test]
        fn arbitrary_config_text_never_panics_through_evaluate(
            lines in proptest::collection::vec(
                (
                    prop::sample::select(vec![
                        "CONFIG_PSA_WANT_ALG_ECDH", "CONFIG_PSA_WANT_ECC_SECP_R1_256",
                        "CONFIG_BOOT_SIGNATURE_TYPE_RSA", "CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN",
                        "CONFIG_BOOT_KEELSIGN_LMS_HSS", "CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET",
                        "CONFIG_MBEDTLS_CIPHER_MODE_CBC", "SB_CONFIG_SIGNATURE_TYPE",
                        "CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_256_BITS", "CONFIG_BT_SMP",
                        "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2", "CONFIG_X",
                    ]),
                    prop::sample::select(vec![
                        "y", "n", "m", "0", "2048", "-1", "0x10", "\"\"", "\"RSA\"",
                        "\"LMS_SHA256_M32_H10\"", "99999999999999999999", "\"\\\"\"",
                    ]),
                    any::<bool>(),
                ),
                0..24,
            ),
            noise in ".{0,40}",
        ) {
            let mut text = String::new();
            for (symbol, value, unset) in &lines {
                if *unset {
                    text.push_str(&format!("# {symbol} is not set\n"));
                } else {
                    text.push_str(&format!("{symbol}={value}\n"));
                }
            }
            text.push_str(&noise);
            let catalogue = catalogue();
            let image = mcuboot();
            for rules in [RuleSet::builtin_zephyr().unwrap(), RuleSet::builtin_esp_idf().unwrap()] {
                if let Ok(config) = kconfig::parse(&text) {
                    let found = evaluate(&rules, &config, &ConfigFile::new("c"), &image, &catalogue);
                    for f in found.assets.values() {
                        prop_assert!(f.asset.check().is_ok());
                    }
                }
            }
        }
    }
}
