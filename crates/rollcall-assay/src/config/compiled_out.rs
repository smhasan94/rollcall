//! The compiled-out list: algorithms a build's configuration explicitly leaves out of a
//! library, per image, and [`apply_compiled_out`], which the source engine uses to drop or
//! down-weight its findings.
//!
//! An entry comes from a `compiled_out` rule whose symbols are all *explicitly* off (`=n` or
//! `# … is not set`); a symbol missing from the file never counts, and an algorithm the image's
//! configuration emits is never compiled out there. An entry without a parameter set covers
//! every parameter set of its algorithm. Every entry names the **library** it is compiled out
//! of (`mbedtls`, `psa-crypto`): `# CONFIG_PSA_WANT_ALG_RSA_PSS is not set` says PSA Crypto
//! lacks RSA-PSS, not that TinyCrypt, a vendored `aes.c` or MCUboot's bootutil does.
//!
//! [`apply_compiled_out`] goes through a product's crypto assets. An asset whose algorithm is
//! compiled out of some library of its image, and that has `source-line` evidence:
//!
//! - sitting under that library (`library:<name>`) with only `source-line` evidence, is
//!   removed;
//! - sitting under that library with other non-configuration evidence too (an ELF symbol, a
//!   Cargo feature), stays, with its `source-line` entries lowered to confidence `low`;
//! - sitting under another library, or under no library, stays, with its `source-line` entries
//!   lowered to confidence `low`: never removed, since another implementation may have it;
//! - with any `kconfig-symbol` evidence, is never touched: the configuration is the authority.
//!
//! Every removal and every down-weighting is returned as a [`Suppressed`] naming the action,
//! the libraries and the symbols (and lines) behind it.

use std::collections::{BTreeMap, BTreeSet};

use rollcall_core::model::{
    AssetType, BomRef, Component, ComponentKind, ConfidenceLevel, CryptoEvidence, Locator, Product,
};

use super::ImageKey;
use crate::assets::parse_asset_name;
use crate::catalogue::Catalogue;

/// What a compiled-out entry is keyed by: (library, algorithm, parameter set).
pub type EntryKey = (String, String, Option<String>);

/// One compiled-out algorithm: the library it is compiled out of, the catalogue algorithm, its
/// parameter set (`None`: all), and the explicitly-off symbols that say so.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompiledOutEntry {
    /// The library component it is compiled out of (`mbedtls`, `psa-crypto`).
    pub library: String,
    /// The catalogue algorithm, as the catalogue spells it.
    pub algorithm: String,
    /// The parameter set, or `None` for every one.
    pub parameter_set: Option<String>,
    /// The `kconfig-symbol` locators of the off symbols, sorted, without duplicates.
    pub locators: Vec<Locator>,
}

impl CompiledOutEntry {
    /// An entry.
    pub fn new(
        library: &str,
        algorithm: &str,
        parameter_set: Option<&str>,
        locators: Vec<Locator>,
    ) -> Self {
        let mut entry = Self {
            library: library.to_owned(),
            algorithm: algorithm.to_owned(),
            parameter_set: parameter_set.map(str::to_owned),
            locators: Vec::new(),
        };
        entry.add_locators(locators);
        entry
    }

    /// Its key: (library, algorithm, parameter set).
    pub fn key(&self) -> EntryKey {
        (
            self.library.clone(),
            self.algorithm.clone(),
            self.parameter_set.clone(),
        )
    }

    fn add_locators(&mut self, locators: Vec<Locator>) {
        let mut all: BTreeSet<Locator> = std::mem::take(&mut self.locators).into_iter().collect();
        all.extend(locators);
        self.locators = all.into_iter().collect();
    }

    /// Adds `other`'s locators (the same key, from another rule or image).
    pub fn merge(&mut self, other: CompiledOutEntry) {
        self.add_locators(other.locators);
    }

    /// Whether the entry covers an asset of `algorithm` with `parameter_set`, in any library:
    /// the same algorithm (ASCII case ignored) and, when the entry has a parameter set, the
    /// same one.
    pub fn covers(&self, algorithm: &str, parameter_set: Option<&str>) -> bool {
        self.algorithm.eq_ignore_ascii_case(algorithm)
            && match &self.parameter_set {
                None => true,
                Some(set) => parameter_set == Some(set.as_str()),
            }
    }
}

/// The compiled-out list of a build: the images the detectors evaluated, each with its entries
/// (possibly none).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledOut {
    images: BTreeMap<ImageKey, BTreeMap<EntryKey, CompiledOutEntry>>,
}

impl CompiledOut {
    /// An empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no image has an entry.
    pub fn is_empty(&self) -> bool {
        self.images.values().all(BTreeMap::is_empty)
    }

    /// Records that the detectors evaluated `image`, with or without entries. An image with no
    /// entries makes [`CompiledOut::everywhere`] empty.
    pub fn add_image(&mut self, image: ImageKey) {
        self.images.entry(image).or_default();
    }

    /// Adds an entry for `image` (recording the image), merging its locators into an existing
    /// one.
    pub fn add(&mut self, image: ImageKey, entry: CompiledOutEntry) {
        let entries = self.images.entry(image).or_default();
        match entries.get_mut(&entry.key()) {
            Some(existing) => existing.merge(entry),
            None => {
                entries.insert(entry.key(), entry);
            }
        }
    }

    /// Every image the detectors evaluated, with or without entries, sorted.
    pub fn images(&self) -> impl Iterator<Item = &ImageKey> {
        self.images.keys()
    }

    /// `image`'s entries, in (library, algorithm, parameter set) order.
    pub fn entries(&self, image: &ImageKey) -> impl Iterator<Item = &CompiledOutEntry> {
        self.images
            .get(image)
            .into_iter()
            .flat_map(BTreeMap::values)
    }

    /// The entries that compile `algorithm` with `parameter_set` out of some library of
    /// `image`, in (library, algorithm, parameter set) order.
    pub fn covering<'a>(
        &'a self,
        image: &ImageKey,
        algorithm: &'a str,
        parameter_set: Option<&'a str>,
    ) -> impl Iterator<Item = &'a CompiledOutEntry> {
        self.images
            .get(image)
            .into_iter()
            .flat_map(BTreeMap::values)
            .filter(move |e| e.covers(algorithm, parameter_set))
    }

    /// The entry that compiles `algorithm` with `parameter_set` out of `library` in `image`,
    /// if any.
    pub fn covers(
        &self,
        image: &ImageKey,
        library: &str,
        algorithm: &str,
        parameter_set: Option<&str>,
    ) -> Option<&CompiledOutEntry> {
        self.entries(image)
            .find(|e| e.library.eq_ignore_ascii_case(library) && e.covers(algorithm, parameter_set))
    }

    /// The entries every evaluated image has (the same library, algorithm and parameter set),
    /// with the locators of all of them: what is compiled out of the whole build, for a
    /// finding that cannot be placed in one image. Empty when no image was evaluated, or when
    /// any evaluated image has no such entry (an image with no entries at all makes it empty).
    pub fn everywhere(&self) -> Vec<CompiledOutEntry> {
        let mut images = self.images.values();
        let Some(first) = images.next() else {
            return Vec::new();
        };
        let mut out: BTreeMap<EntryKey, CompiledOutEntry> = first.clone();
        for entries in images {
            out.retain(|key, _| entries.contains_key(key));
            for (key, entry) in &mut out {
                if let Some(other) = entries.get(key) {
                    entry.merge(other.clone());
                }
            }
        }
        out.into_values().collect()
    }
}

/// What [`apply_compiled_out`] did to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompiledOutAction {
    /// Removed: only `source-line` evidence, under the library the algorithm is compiled out
    /// of.
    Removed,
    /// Kept, with its `source-line` evidence lowered to confidence `low`: it has other
    /// non-configuration evidence too, or it sits under another library (or none) than the
    /// one the algorithm is compiled out of.
    Downgraded,
}

/// A finding [`apply_compiled_out`] removed or down-weighted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppressed {
    /// What was done.
    pub action: CompiledOutAction,
    /// The image it is in.
    pub image: ImageKey,
    /// The components above it in the image, outermost first, as `kind:name`.
    pub parents: Vec<String>,
    /// The asset's component name.
    pub asset: String,
    /// Its evidence, as it was before.
    pub evidence: Vec<CryptoEvidence>,
    /// The libraries the algorithm is compiled out of that led to the action, sorted.
    pub libraries: Vec<String>,
    /// The explicitly-off symbols that compiled it out of those libraries, sorted.
    pub by: Vec<Locator>,
}

/// What to do with one asset.
enum Action {
    Keep,
    Act(CompiledOutAction, Vec<String>, Vec<Locator>),
}

/// The library a component under `parents` sits under: the innermost `library:` parent.
fn library_of(parents: &[String]) -> Option<&str> {
    parents
        .iter()
        .rev()
        .find_map(|p| p.strip_prefix("library:"))
}

fn decide(
    component: &Component,
    image: &ImageKey,
    parents: &[String],
    compiled_out: &CompiledOut,
    catalogue: &Catalogue,
) -> Action {
    let Some(crypto) = &component.crypto else {
        return Action::Keep;
    };
    if component.kind != ComponentKind::CryptographicAsset
        || crypto.asset_type() != AssetType::Algorithm
        || crypto.evidence.is_empty()
        || crypto
            .evidence
            .iter()
            .any(|e| matches!(e.locator, Locator::KconfigSymbol { .. }))
        || !crypto
            .evidence
            .iter()
            .any(|e| matches!(e.locator, Locator::SourceLine { .. }))
    {
        return Action::Keep;
    }
    let Some((algorithm, set)) = parse_asset_name(catalogue, &component.name) else {
        return Action::Keep;
    };
    let covering: Vec<&CompiledOutEntry> = compiled_out
        .covering(image, &algorithm, set.as_deref())
        .collect();
    if covering.is_empty() {
        return Action::Keep;
    }
    let own = library_of(parents).and_then(|library| {
        covering
            .iter()
            .find(|e| e.library.eq_ignore_ascii_case(library))
    });
    let only_source = crypto
        .evidence
        .iter()
        .all(|e| matches!(e.locator, Locator::SourceLine { .. }));
    let (action, entries): (CompiledOutAction, Vec<&CompiledOutEntry>) = match own {
        Some(entry) if only_source => (CompiledOutAction::Removed, vec![*entry]),
        Some(entry) => (CompiledOutAction::Downgraded, vec![*entry]),
        None => (CompiledOutAction::Downgraded, covering),
    };
    let libraries: BTreeSet<String> = entries.iter().map(|e| e.library.clone()).collect();
    let by: BTreeSet<Locator> = entries
        .iter()
        .flat_map(|e| e.locators.iter().cloned())
        .collect();
    Action::Act(
        action,
        libraries.into_iter().collect(),
        by.into_iter().collect(),
    )
}

fn walk(
    components: &mut std::collections::BTreeSet<Component>,
    image: &ImageKey,
    parents: &mut Vec<String>,
    compiled_out: &CompiledOut,
    catalogue: &Catalogue,
    out: &mut Vec<Suppressed>,
) {
    for mut component in std::mem::take(components) {
        parents.push(format!("{}:{}", component.kind.as_str(), component.name));
        walk(
            &mut component.components,
            image,
            parents,
            compiled_out,
            catalogue,
            out,
        );
        parents.pop();
        if let Action::Act(action, libraries, by) =
            decide(&component, image, parents, compiled_out, catalogue)
        {
            out.push(Suppressed {
                action,
                image: image.clone(),
                parents: parents.clone(),
                asset: component.name.clone(),
                evidence: component
                    .crypto
                    .as_ref()
                    .map(|c| c.evidence.iter().cloned().collect())
                    .unwrap_or_default(),
                libraries,
                by,
            });
            match action {
                CompiledOutAction::Removed => continue,
                CompiledOutAction::Downgraded => {
                    if let Some(crypto) = &mut component.crypto {
                        crypto.evidence = std::mem::take(&mut crypto.evidence)
                            .into_iter()
                            .map(|mut e| {
                                if matches!(e.locator, Locator::SourceLine { .. }) {
                                    e.confidence = ConfidenceLevel::Low;
                                }
                                e
                            })
                            .collect();
                    }
                }
            }
        }
        components.insert(component);
    }
}

/// Removes or down-weights `product`'s source findings for algorithms `compiled_out` lists for
/// their image (see the [module docs](self)), and returns every removal and down-weighting.
/// Dependency edges to removed assets are dropped.
pub fn apply_compiled_out(
    product: &mut Product,
    compiled_out: &CompiledOut,
    catalogue: &Catalogue,
) -> Vec<Suppressed> {
    let mut out = Vec::new();
    let images = std::mem::take(&mut product.images);
    for mut image in images {
        let key = ImageKey::of(&image);
        let mut parents = Vec::new();
        walk(
            &mut image.components,
            &key,
            &mut parents,
            compiled_out,
            catalogue,
            &mut out,
        );
        product.images.insert(image);
    }
    if out.iter().any(|s| s.action == CompiledOutAction::Removed) {
        let refs: BTreeSet<BomRef> = product.walk().map(|(_, r, _)| r).collect();
        let dependencies = std::mem::take(&mut product.dependencies);
        for (from, targets) in dependencies {
            if !refs.contains(&from) {
                continue;
            }
            let kept: BTreeSet<BomRef> = targets.into_iter().filter(|t| refs.contains(t)).collect();
            if !kept.is_empty() {
                product.dependencies.insert(from, kept);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rollcall_core::model::{CryptoAsset, CryptoAssetProperties, Image, ImageKind};
    use rollcall_core::zephyr::kconfig;

    use crate::assets::algorithm_properties;
    use crate::config::detect::evaluate;
    use crate::config::layout::ConfigFile;
    use crate::config::rules::RuleSet;

    fn app() -> ImageKey {
        ImageKey::new(ImageKind::Application, "widget", None)
    }

    /// The compiled-out list the built-in Zephyr rules give for `text` in the application image.
    fn compiled_out_for(text: &str) -> CompiledOut {
        let catalogue = Catalogue::builtin().unwrap();
        let rules = RuleSet::builtin_zephyr().unwrap();
        let config = kconfig::parse(text).unwrap();
        let found = evaluate(
            &rules,
            &config,
            &ConfigFile::new("zephyr/.config"),
            &app(),
            &catalogue,
        );
        let mut out = CompiledOut::new();
        out.add_image(app());
        for entry in found.compiled_out.into_values() {
            out.add(app(), entry);
        }
        out
    }

    fn evidence(locator: Locator, detector: &str) -> CryptoEvidence {
        CryptoEvidence::new(locator, detector, ConfidenceLevel::Medium, "seen").unwrap()
    }

    fn source(line: u32) -> Locator {
        Locator::SourceLine {
            location: "src/crypto.c".into(),
            line,
        }
    }

    fn asset(name: &str, evidence: Vec<CryptoEvidence>) -> Component {
        let catalogue = Catalogue::builtin().unwrap();
        let (alg, set) = parse_asset_name(&catalogue, name).unwrap();
        let (properties, _) = algorithm_properties(&catalogue, &alg, set.as_deref()).unwrap();
        Component::new(ComponentKind::CryptographicAsset, name)
            .unwrap()
            .with_crypto(
                CryptoAsset::new(CryptoAssetProperties::Algorithm(properties), evidence).unwrap(),
            )
    }

    /// `application:widget / library:mbedtls / {AES-CBC-128 (source), AES-GCM-128 (source),
    /// AES-CBC-256 (source + ELF), AES-CBC (kconfig)}`.
    fn product() -> Product {
        let mut library = Component::new(ComponentKind::Library, "mbedtls").unwrap();
        library
            .add_component(asset(
                "AES-CBC-128",
                vec![
                    evidence(source(10), "source"),
                    evidence(source(12), "source"),
                ],
            ))
            .unwrap();
        library
            .add_component(asset("AES-GCM-128", vec![evidence(source(20), "source")]))
            .unwrap();
        library
            .add_component(asset(
                "AES-CBC-256",
                vec![
                    evidence(source(30), "source"),
                    evidence(
                        Locator::ElfSymbol {
                            location: "zephyr.elf".into(),
                            symbol: "mbedtls_aes_crypt_cbc".into(),
                        },
                        "elf-symbols",
                    ),
                ],
            ))
            .unwrap();
        library
            .add_component(asset(
                "AES-CBC",
                vec![
                    evidence(source(40), "source"),
                    evidence(
                        Locator::KconfigSymbol {
                            location: "zephyr/.config".into(),
                            line: Some(3),
                            symbol: "CONFIG_X".into(),
                        },
                        "kconfig",
                    ),
                ],
            ))
            .unwrap();
        let mut image = Image::new(ImageKind::Application, "widget").unwrap();
        image.add_component(library).unwrap();
        let mut product = Product::new("widget").unwrap();
        product.add_image(image).unwrap();
        let refs: Vec<(String, BomRef)> =
            product.walk().map(|(p, r, _)| (p.to_string(), r)).collect();
        let library_ref = refs
            .iter()
            .find(|(p, _)| p.ends_with("library:mbedtls"))
            .unwrap()
            .1
            .clone();
        for (path, r) in &refs {
            if path.contains("cryptographic-asset:") {
                product.add_dependency(library_ref.clone(), r.clone());
            }
        }
        product
    }

    fn asset_names(product: &Product) -> Vec<String> {
        product
            .crypto_assets()
            .map(|(_, _, c)| c.name.clone())
            .collect()
    }

    fn evidence_of(product: &Product, name: &str) -> Vec<CryptoEvidence> {
        product
            .crypto_assets()
            .find(|(_, _, c)| c.name == name)
            .and_then(|(_, _, c)| c.crypto.clone())
            .map(|c| c.evidence.into_iter().collect())
            .unwrap_or_default()
    }

    /// TP3: `CONFIG_MBEDTLS_CIPHER_MODE_CBC=n` removes a CBC finding seen only in source under
    /// `library:mbedtls`, naming the symbol and its line; `=y` or no line at all leaves it;
    /// AES-GCM is untouched; a CBC asset with ELF evidence too stays with its source entry
    /// lowered to low (and that is reported too); an asset with configuration evidence is never
    /// touched.
    #[test]
    fn cbc_mode_n_suppresses_cbc_source_finding() {
        let catalogue = Catalogue::builtin().unwrap();
        let co = compiled_out_for("CONFIG_MBEDTLS_CIPHER_MODE_CBC=n\n");
        let entry = co
            .covers(&app(), "mbedtls", "AES-CBC", Some("128"))
            .unwrap();
        assert_eq!(entry.library, "mbedtls");
        assert_eq!(
            entry.locators,
            [Locator::KconfigSymbol {
                location: "zephyr/.config".into(),
                line: Some(1),
                symbol: "CONFIG_MBEDTLS_CIPHER_MODE_CBC".into(),
            }]
        );
        let mut p = product();
        let suppressed = apply_compiled_out(&mut p, &co, &catalogue);
        let removed: Vec<&Suppressed> = suppressed
            .iter()
            .filter(|s| s.action == CompiledOutAction::Removed)
            .collect();
        assert_eq!(removed.len(), 1, "{suppressed:?}");
        let s = removed[0];
        assert_eq!(s.asset, "AES-CBC-128");
        assert_eq!(s.image, app());
        assert_eq!(s.parents, ["library:mbedtls"]);
        assert_eq!(s.libraries, ["mbedtls"]);
        assert_eq!(s.evidence.len(), 2);
        assert_eq!(
            s.by.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["zephyr/.config:1 CONFIG_MBEDTLS_CIPHER_MODE_CBC"]
        );
        assert_eq!(asset_names(&p), ["AES-CBC", "AES-CBC-256", "AES-GCM-128"]);
        // The ELF-backed one is kept, its source entry at low and the ELF entry as it was, and
        // the down-weighting is reported.
        let downgraded: Vec<&Suppressed> = suppressed
            .iter()
            .filter(|s| s.action == CompiledOutAction::Downgraded)
            .collect();
        assert_eq!(downgraded.len(), 1, "{suppressed:?}");
        assert_eq!(downgraded[0].asset, "AES-CBC-256");
        assert_eq!(downgraded[0].libraries, ["mbedtls"]);
        for e in evidence_of(&p, "AES-CBC-256") {
            match e.locator {
                Locator::SourceLine { .. } => assert_eq!(e.confidence, ConfidenceLevel::Low),
                _ => assert_eq!(e.confidence, ConfidenceLevel::Medium),
            }
        }
        // AES-GCM and the kconfig-backed AES-CBC are exactly as they were.
        let before = product();
        for name in ["AES-GCM-128", "AES-CBC"] {
            let find = |p: &Product| {
                p.crypto_assets()
                    .find(|(_, _, c)| c.name == name)
                    .map(|(_, _, c)| c.clone())
            };
            assert_eq!(find(&p), find(&before), "{name}");
        }
        // The dependency on the removed asset is gone; the product still validates.
        p.validate().unwrap();
        let edges: usize = p.dependencies.values().map(BTreeSet::len).sum();
        assert_eq!(edges, 3);

        // =y, or no line for the symbol: nothing compiled out, nothing changes.
        for text in ["CONFIG_MBEDTLS_CIPHER_MODE_CBC=y\n", "", "CONFIG_OTHER=n\n"] {
            let co = compiled_out_for(text);
            assert_eq!(
                co.covering(&app(), "AES-CBC", Some("128")).count(),
                0,
                "{text:?}"
            );
            let mut p = product();
            assert!(apply_compiled_out(&mut p, &co, &catalogue).is_empty());
            assert_eq!(p, product(), "{text:?}");
        }
        // Another image's list does not apply.
        let mut other = CompiledOut::new();
        for entry in co.entries(&app()) {
            other.add(
                ImageKey::new(ImageKind::Bootloader, "mcuboot", None),
                entry.clone(),
            );
        }
        let mut p = product();
        assert!(apply_compiled_out(&mut p, &other, &catalogue).is_empty());
    }

    /// A compiled-out entry is about one library: an AES-CBC source finding under
    /// `library:tinycrypt`, or under no library, is kept with its source evidence lowered to
    /// low (and reported as down-weighted), never removed, when only mbedTLS (or PSA Crypto)
    /// has CBC compiled out.
    #[test]
    fn compiled_out_of_mbedtls_downgrades_other_library_findings() {
        let catalogue = Catalogue::builtin().unwrap();
        let place = |library: Option<&str>| {
            let cbc = asset("AES-CBC-128", vec![evidence(source(7), "source")]);
            let mut image = Image::new(ImageKind::Application, "widget").unwrap();
            match library {
                Some(name) => {
                    let mut lib = Component::new(ComponentKind::Library, name).unwrap();
                    lib.add_component(cbc).unwrap();
                    image.add_component(lib).unwrap();
                }
                None => image.add_component(cbc).unwrap(),
            }
            let mut product = Product::new("widget").unwrap();
            product.add_image(image).unwrap();
            product
        };
        let legacy = compiled_out_for("CONFIG_MBEDTLS_CIPHER_MODE_CBC=n\n");
        let psa = compiled_out_for(
            "# CONFIG_PSA_WANT_ALG_CBC_NO_PADDING is not set\n# CONFIG_PSA_WANT_ALG_CBC_PKCS7 is not set\n",
        );
        assert!(
            psa.covers(&app(), "psa-crypto", "AES-CBC", Some("128"))
                .is_some()
        );
        assert!(
            psa.covers(&app(), "mbedtls", "AES-CBC", Some("128"))
                .is_none()
        );
        for (co, library) in [
            (&legacy, Some("tinycrypt")),
            (&legacy, None),
            (&legacy, Some("psa-crypto")),
            (&psa, Some("mbedtls")),
            (&psa, Some("tinycrypt")),
        ] {
            let mut p = place(library);
            let suppressed = apply_compiled_out(&mut p, co, &catalogue);
            assert_eq!(asset_names(&p), ["AES-CBC-128"], "{library:?}");
            assert_eq!(suppressed.len(), 1, "{library:?}: {suppressed:?}");
            let s = &suppressed[0];
            assert_eq!(s.action, CompiledOutAction::Downgraded, "{library:?}");
            assert_eq!(s.asset, "AES-CBC-128");
            assert_eq!(s.evidence[0].confidence, ConfidenceLevel::Medium);
            assert!(!s.by.is_empty());
            for e in evidence_of(&p, "AES-CBC-128") {
                assert_eq!(e.confidence, ConfidenceLevel::Low, "{library:?}");
            }
            p.validate().unwrap();
        }
        // Under the library the entry names, it is removed.
        let mut p = place(Some("psa-crypto"));
        let suppressed = apply_compiled_out(&mut p, &psa, &catalogue);
        assert_eq!(suppressed[0].action, CompiledOutAction::Removed);
        assert_eq!(suppressed[0].libraries, ["psa-crypto"]);
        assert!(asset_names(&p).is_empty());
    }

    /// An algorithm the image's configuration emits is never in its compiled-out list, even
    /// when a compiled-out rule's symbols are all off.
    #[test]
    fn emitted_algorithm_is_never_compiled_out() {
        // The legacy CBC switch is off, but the PSA CBC algorithm is on: AES-CBC is emitted.
        let text = "\
CONFIG_MBEDTLS_CIPHER_MODE_CBC=n
CONFIG_PSA_WANT_KEY_TYPE_AES=y
CONFIG_PSA_WANT_ALG_CBC_NO_PADDING=y
# CONFIG_PSA_WANT_ALG_CBC_PKCS7 is not set
# CONFIG_PSA_WANT_ALG_GCM is not set
";
        let catalogue = Catalogue::builtin().unwrap();
        let rules = RuleSet::builtin_zephyr().unwrap();
        let config = kconfig::parse(text).unwrap();
        let found = evaluate(
            &rules,
            &config,
            &ConfigFile::new("zephyr/.config"),
            &app(),
            &catalogue,
        );
        assert!(found.assets.keys().any(|k| k.name == "AES-CBC"));
        assert!(
            !found.compiled_out.keys().any(|(_, a, _)| a == "AES-CBC"),
            "{:?}",
            found.compiled_out
        );
        // GCM is off and not emitted: compiled out of PSA Crypto.
        assert!(
            found
                .compiled_out
                .keys()
                .any(|(l, a, _)| l == "psa-crypto" && a == "AES-GCM")
        );
        // No compiled-out entry overlaps an asset.
        for (_, a, s) in found.compiled_out.keys() {
            for f in found.assets.values() {
                if let Some((fa, fs)) = &f.algorithm {
                    assert!(
                        !(fa == a && (s.is_none() || fs.is_none() || s == fs)),
                        "{a} {s:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn everywhere_is_the_intersection_over_images() {
        let loc = |s: &str| Locator::KconfigSymbol {
            location: "c".into(),
            line: Some(1),
            symbol: s.into(),
        };
        let mut co = CompiledOut::new();
        assert!(co.everywhere().is_empty());
        assert!(co.is_empty());
        let a = app();
        let b = ImageKey::new(ImageKind::Bootloader, "mcuboot", None);
        co.add(
            a.clone(),
            CompiledOutEntry::new("mbedtls", "AES-CBC", None, vec![loc("CONFIG_A")]),
        );
        co.add(
            a.clone(),
            CompiledOutEntry::new("mbedtls", "AES-GCM", None, vec![loc("CONFIG_G")]),
        );
        co.add(
            a.clone(),
            CompiledOutEntry::new("psa-crypto", "AES-CCM", None, vec![loc("CONFIG_C")]),
        );
        co.add(
            b.clone(),
            CompiledOutEntry::new("mbedtls", "AES-CBC", None, vec![loc("CONFIG_B")]),
        );
        co.add(
            b.clone(),
            CompiledOutEntry::new("mbedtls", "AES-CCM", None, vec![loc("CONFIG_D")]),
        );
        let every = co.everywhere();
        assert_eq!(every.len(), 1);
        assert_eq!(every[0].library, "mbedtls");
        assert_eq!(every[0].algorithm, "AES-CBC");
        assert_eq!(every[0].locators, [loc("CONFIG_A"), loc("CONFIG_B")]);
        assert_eq!(co.images().count(), 2);
        // An evaluated image with no entries at all: nothing is compiled out everywhere.
        co.add_image(ImageKey::new(ImageKind::Application, "other", None));
        assert!(co.everywhere().is_empty());
        assert_eq!(co.images().count(), 3);
        assert!(!co.is_empty());
        let mut only_empty = CompiledOut::new();
        only_empty.add_image(app());
        assert!(only_empty.is_empty());
        assert!(only_empty.everywhere().is_empty());
        // A set-specific entry covers only that set.
        let e = CompiledOutEntry::new("mbedtls", "SHA2", Some("384"), vec![]);
        assert!(e.covers("sha2", Some("384")));
        assert!(!e.covers("SHA2", Some("256")));
        assert!(!e.covers("SHA2", None));
    }
}
