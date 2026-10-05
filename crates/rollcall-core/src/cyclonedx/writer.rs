//! Model → CycloneDX 1.6 document. See the [module docs](super) for the mapping.

use std::collections::{BTreeMap, BTreeSet};

use super::document::{
    Bom, Component, CryptoProperties, Dependency, Evidence, Hash, Identity, LicenseChoice,
    Metadata, Method, NamedLicense, Occurrence, Property, Supplier, Tool, Tools,
};
use super::{SerialNumber, WriteError, WriteOptions};
use crate::model::{
    self, BomRef, Cpe, CryptoAsset, EvidenceField, EvidenceSet, ImageKind, License, NodePath,
    PathSegment, Product, Purl, Scope,
};

/// CycloneDX component type used for the product. Each image is written with its own
/// [`ImageType`](crate::model::ImageType).
const FIRMWARE: &str = "firmware";
/// Property carrying an image's [`ImageKind`](crate::model::ImageKind).
pub(super) const IMAGE_KIND: &str = "rollcall:image-kind";
/// Property carrying the name of an input that contributed evidence.
pub(super) const EVIDENCE_SOURCE: &str = "rollcall:evidence-source";
/// Property carrying one [`Evidence`](crate::model::Evidence) entry, losslessly, as compact
/// JSON in the model's form.
pub(super) const EVIDENCE_PROPERTY: &str = "rollcall:evidence";
/// Property carrying one [`CryptoEvidence`](crate::model::CryptoEvidence) entry of a crypto
/// asset, losslessly, as compact JSON in the model's form.
pub(super) const CRYPTO_EVIDENCE_PROPERTY: &str = "rollcall:crypto-evidence";
/// Property marking a `blob` image's contents as not analysed.
pub(super) const OPAQUE_PROPERTY: &str = "rollcall:opaque";
/// Property carrying one of a component's additional CPEs, under the name syft and grype
/// read (grype matches on these as well as on `cpe`; it ignores `evidence.identity`).
pub(super) const ADDITIONAL_CPE: &str = "syft:cpe23";
/// No additional CPEs: products and images have none.
static NO_CPES: BTreeSet<Cpe> = BTreeSet::new();
/// The value of [`OPAQUE_PROPERTY`].
pub(super) const OPAQUE_NOTE: &str = "contents not analysed; hashes computed from the file";

/// The identity fields that map to `evidence.identity[]`, in output order.
const IDENTITY_FIELDS: [EvidenceField; 5] = [
    EvidenceField::Name,
    EvidenceField::Version,
    EvidenceField::Purl,
    EvidenceField::Cpe,
    EvidenceField::Hash,
];

/// The facts every node level shares, borrowed from a product, image or component.
struct Facts<'a> {
    name: &'a str,
    version: Option<&'a str>,
    supplier: Option<&'a model::Supplier>,
    purl: Option<&'a Purl>,
    cpe: Option<&'a Cpe>,
    additional_cpes: &'a BTreeSet<Cpe>,
    hashes: &'a BTreeSet<model::Hash>,
    licence: Option<&'a License>,
    scope: Option<Scope>,
    evidence: &'a EvidenceSet,
    crypto: Option<&'a CryptoAsset>,
}

impl<'a> Facts<'a> {
    fn of_product(p: &'a Product) -> Self {
        Self {
            name: &p.name,
            version: p.version.as_deref(),
            supplier: p.supplier.as_ref(),
            purl: p.purl.as_ref(),
            cpe: p.cpe.as_ref(),
            additional_cpes: &NO_CPES,
            hashes: &p.hashes,
            licence: p.licence.as_ref(),
            scope: None,
            evidence: &p.evidence,
            crypto: None,
        }
    }

    fn of_image(i: &'a model::Image) -> Self {
        Self {
            name: &i.name,
            version: i.version.as_deref(),
            supplier: i.supplier.as_ref(),
            purl: i.purl.as_ref(),
            cpe: i.cpe.as_ref(),
            additional_cpes: &NO_CPES,
            hashes: &i.hashes,
            licence: i.licence.as_ref(),
            scope: None,
            evidence: &i.evidence,
            crypto: None,
        }
    }

    fn of_component(c: &'a model::Component) -> Self {
        Self {
            name: &c.name,
            version: c.version.as_deref(),
            supplier: c.supplier.as_ref(),
            purl: c.purl.as_ref(),
            cpe: c.cpe.as_ref(),
            additional_cpes: &c.additional_cpes,
            hashes: &c.hashes,
            licence: c.licence.as_ref(),
            scope: c.scope,
            evidence: &c.evidence,
            crypto: c.crypto.as_ref(),
        }
    }

    /// The node's stored value for an identity field, if it has one (never for `hash`).
    fn concluded(&self, field: EvidenceField) -> Option<String> {
        match field {
            EvidenceField::Name => Some(self.name.to_owned()),
            EvidenceField::Version => self.version.map(str::to_owned),
            EvidenceField::Purl => self.purl.map(|p| p.as_str().to_owned()),
            EvidenceField::Cpe => self.cpe.map(|c| c.as_str().to_owned()),
            EvidenceField::Hash | EvidenceField::Licence | EvidenceField::Supplier => None,
        }
    }

    /// The CycloneDX component for this node, without nested components. `properties` are
    /// extra node-specific properties; evidence sources (and crypto detectors), one
    /// `rollcall:evidence` property per evidence entry and one `rollcall:crypto-evidence`
    /// property per crypto evidence entry are added here, and all are sorted.
    fn to_component(
        &self,
        kind: &'static str,
        bom_ref: &BomRef,
        mut properties: Vec<Property>,
    ) -> Result<Component, serde_json::Error> {
        let crypto_evidence = self.crypto.into_iter().flat_map(|c| &c.evidence);
        let sources: BTreeSet<&str> = self
            .evidence
            .iter()
            .map(|e| e.source())
            .chain(crypto_evidence.clone().map(|e| e.detector()))
            .collect();
        properties.extend(sources.into_iter().map(|source| Property {
            name: EVIDENCE_SOURCE,
            value: source.to_owned(),
        }));
        for entry in self.evidence.iter() {
            properties.push(Property {
                name: EVIDENCE_PROPERTY,
                value: serde_json::to_string(entry)?,
            });
        }
        for entry in crypto_evidence {
            properties.push(Property {
                name: CRYPTO_EVIDENCE_PROPERTY,
                value: serde_json::to_string(entry)?,
            });
        }
        properties.extend(self.additional_cpes.iter().map(|cpe| Property {
            name: ADDITIONAL_CPE,
            value: cpe.as_str().to_owned(),
        }));
        properties.sort();
        properties.dedup();

        let evidence = self.evidence();
        Ok(Component {
            kind,
            bom_ref: bom_ref.as_str().to_owned(),
            name: self.name.to_owned(),
            version: self.version.map(str::to_owned),
            scope: self.scope.map(Scope::as_str),
            supplier: self.supplier.map(|s| Supplier {
                name: s.name().to_owned(),
                url: s.urls().iter().cloned().collect(),
            }),
            purl: self.purl.map(|p| p.as_str().to_owned()),
            cpe: self.cpe.map(|c| c.as_str().to_owned()),
            hashes: self
                .hashes
                .iter()
                .map(|h| Hash {
                    alg: h.algorithm().as_str(),
                    content: h.digest().to_owned(),
                })
                .collect(),
            licenses: self
                .licence
                .map(|l| {
                    vec![LicenseChoice::Expression {
                        expression: l.as_str().to_owned(),
                    }]
                })
                .unwrap_or_default(),
            evidence: (!evidence.is_empty()).then_some(evidence),
            crypto_properties: self.crypto.cloned().map(CryptoProperties),
            properties,
            components: Vec::new(),
        })
    }

    /// `evidence`: identity per field, de-duplicated occurrences and licence evidence.
    /// Supplier evidence has no CycloneDX evidence field and is not emitted (its source still
    /// appears as a `rollcall:evidence-source` property). A crypto asset's evidence adds one
    /// `name` method per entry (after the node's own `name` methods; the entry's confidence is
    /// the higher of the two) and one occurrence per entry, with its symbol and reason.
    fn evidence(&self) -> Evidence {
        let mut identity = Vec::new();
        for field in IDENTITY_FIELDS {
            if field == EvidenceField::Cpe && !self.additional_cpes.is_empty() {
                identity.extend(self.cpe_identities());
                continue;
            }
            let mut methods = self.methods(field, |_| true);
            let mut confidence = self.evidence.confidence_for(field);
            if field == EvidenceField::Name
                && let Some(crypto) = self.crypto
            {
                methods.extend(crypto.evidence.iter().map(|e| Method {
                    technique: e.technique(),
                    confidence: e.confidence.as_confidence().as_f64(),
                    value: e.locator.to_string(),
                }));
                confidence = confidence.combine(crypto.confidence().as_confidence());
            }
            if !methods.is_empty() {
                identity.push(Identity {
                    field,
                    confidence: Some(confidence.as_f64()),
                    concluded_value: self.concluded(field),
                    methods,
                });
            }
        }

        // (location, line, symbol, additional context), so ordinary occurrences sort exactly
        // as before and crypto ones beside them.
        type Key = (String, Option<u32>, Option<String>, Option<String>);
        let mut occurrences: BTreeSet<Key> = self
            .evidence
            .iter()
            .filter_map(|e| e.occurrence.as_ref())
            .map(|o| (o.location().to_owned(), o.line(), None, None))
            .collect();
        for entry in self.crypto.into_iter().flat_map(|c| &c.evidence) {
            occurrences.insert((
                entry.locator.location().to_owned(),
                entry.locator.line(),
                entry.locator.symbol(),
                Some(entry.reason().to_owned()),
            ));
        }
        let occurrences = occurrences
            .into_iter()
            .map(|(location, line, symbol, additional_context)| Occurrence {
                location,
                line,
                symbol,
                additional_context,
            })
            .collect();

        let licences: BTreeSet<&str> = self
            .evidence
            .iter()
            .filter(|e| e.field == EvidenceField::Licence)
            .map(|e| e.value.as_str())
            .collect();
        let licenses = licence_evidence(licences);

        Evidence {
            identity,
            occurrences,
            licenses,
        }
    }
}

impl Facts<'_> {
    /// `methods[]` for the evidence of `field` whose value passes `keep`, in set order.
    fn methods(&self, field: EvidenceField, keep: impl Fn(&str) -> bool) -> Vec<Method> {
        self.evidence
            .iter()
            .filter(|e| e.field == field && keep(&e.value))
            .map(|e| Method {
                technique: e.technique,
                confidence: e.confidence.as_f64(),
                value: e.value.clone(),
            })
            .collect()
    }

    /// The `cpe` identity entries of a node with additional CPEs: the primary CPE's (with
    /// every cpe observation that is not an additional CPE), then one per additional CPE in
    /// sorted order (with the observations of that value). Each entry's confidence is the
    /// highest of its methods, omitted when it has none.
    fn cpe_identities(&self) -> Vec<Identity> {
        let field = EvidenceField::Cpe;
        let highest = |methods: &[Method]| methods.iter().map(|m| m.confidence).reduce(f64::max);
        let is_additional = |v: &str| self.additional_cpes.iter().any(|c| c.as_str() == v);
        let mut out = Vec::new();
        let primary = self.methods(field, |v| !is_additional(v));
        if !primary.is_empty() || self.cpe.is_some() {
            out.push(Identity {
                field,
                confidence: highest(&primary),
                concluded_value: self.concluded(field),
                methods: primary,
            });
        }
        for cpe in self.additional_cpes {
            let methods = self.methods(field, |v| v == cpe.as_str());
            out.push(Identity {
                field,
                confidence: highest(&methods),
                concluded_value: Some(cpe.as_str().to_owned()),
                methods,
            });
        }
        out
    }
}

/// `evidence.licenses` for the distinct licence values observed, in sorted order.
///
/// An evidence value is free text, so it is written as `{"expression": …}` only when it is
/// the single value and is a syntactically valid SPDX expression ([`License::new`] accepts
/// it); anything else is a `{"license": {"name": …}}`. Several values are always written as
/// names: CycloneDX's licence choice allows either a list of licences or exactly one
/// expression, so there is no slot for several expressions.
fn licence_evidence(values: BTreeSet<&str>) -> Vec<LicenseChoice> {
    let named = |v: &str| LicenseChoice::License {
        license: NamedLicense { name: v.to_owned() },
    };
    let mut iter = values.iter();
    match (iter.next(), iter.next()) {
        (Some(&only), None) if License::new(only).is_ok() => vec![LicenseChoice::Expression {
            expression: only.to_owned(),
        }],
        _ => values.into_iter().map(named).collect(),
    }
}

/// A component and, recursively, its subcomponents. `path` is the component's own path,
/// derived exactly as [`Product::walk`] derives it.
fn component(c: &model::Component, path: &NodePath) -> Result<Component, serde_json::Error> {
    let mut out =
        Facts::of_component(c).to_component(c.kind.as_str(), &BomRef::derive(path), vec![])?;
    out.components = c
        .components
        .iter()
        .map(|child| component(child, &path.child(PathSegment::of_component(child))))
        .collect::<Result<_, _>>()?;
    Ok(out)
}

/// Maps a validated product to a CycloneDX 1.6 document.
pub(super) fn to_document(product: &Product, options: &WriteOptions) -> Result<Bom, WriteError> {
    product.validate().map_err(WriteError::Invalid)?;
    let serial_number = match &options.serial_number {
        Some(serial) => serial.clone(),
        None => SerialNumber::derive(product).map_err(WriteError::Json)?,
    };

    let root = product.path();
    // The root carries its own facts only: osv-scanner ignores components nested under
    // `metadata.component`, so the images go to the top-level `components`.
    let root_component = Facts::of_product(product)
        .to_component(FIRMWARE, &BomRef::derive(&root), vec![])
        .map_err(WriteError::Json)?;

    let components = product
        .images
        .iter()
        .map(|image| {
            let path = root.child(PathSegment::of_image(image));
            let mut properties = vec![Property {
                name: IMAGE_KIND,
                value: image.kind.as_str().to_owned(),
            }];
            if image.kind == ImageKind::Blob {
                properties.push(Property {
                    name: OPAQUE_PROPERTY,
                    value: OPAQUE_NOTE.to_owned(),
                });
            }
            let mut out = Facts::of_image(image).to_component(
                image.image_type.as_str(),
                &BomRef::derive(&path),
                properties,
            )?;
            out.components = image
                .components
                .iter()
                .map(|c| component(c, &path.child(PathSegment::of_component(c))))
                .collect::<Result<_, _>>()?;
            Ok(out)
        })
        .collect::<Result<_, serde_json::Error>>()
        .map_err(WriteError::Json)?;

    let edges: &BTreeMap<BomRef, BTreeSet<BomRef>> = &product.dependencies;
    let dependencies = product
        .walk()
        .map(|(_, bom_ref, _)| Dependency {
            depends_on: edges
                .get(&bom_ref)
                .map(|targets| targets.iter().map(|t| t.as_str().to_owned()).collect())
                .unwrap_or_default(),
            bom_ref: bom_ref.as_str().to_owned(),
        })
        .collect();

    Ok(Bom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: serial_number.as_str().to_owned(),
        version: 1,
        metadata: Metadata {
            timestamp: options.timestamp.as_str().to_owned(),
            tools: Tools {
                components: vec![Tool {
                    kind: "application",
                    name: "rollcall",
                    version: env!("CARGO_PKG_VERSION"),
                }],
            },
            component: root_component,
            properties: {
                let mut properties = options.properties.clone();
                properties.sort();
                properties.dedup();
                properties
            },
        },
        components,
        dependencies,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::cyclonedx::Timestamp;
    use crate::model::{
        AlgorithmProperties, CertificateProperties, ComponentKind, ConfidenceLevel,
        CryptoAssetProperties, CryptoEvidence, Image, Locator, ProtocolProperties,
        RelatedCryptoMaterialProperties,
    };

    const BLOCKS: [&str; 4] = [
        "algorithmProperties",
        "protocolProperties",
        "certificateProperties",
        "relatedCryptoMaterialProperties",
    ];

    #[test]
    fn crypto_properties_block_matches_asset_type() {
        let cases = [
            (
                CryptoAssetProperties::Algorithm(AlgorithmProperties::default()),
                "algorithm",
                "algorithmProperties",
            ),
            (
                CryptoAssetProperties::Protocol(ProtocolProperties::default()),
                "protocol",
                "protocolProperties",
            ),
            (
                CryptoAssetProperties::Certificate(CertificateProperties::default()),
                "certificate",
                "certificateProperties",
            ),
            (
                CryptoAssetProperties::RelatedCryptoMaterial(
                    RelatedCryptoMaterialProperties::default(),
                ),
                "related-crypto-material",
                "relatedCryptoMaterialProperties",
            ),
        ];
        for (properties, asset_type, block) in cases {
            let evidence = CryptoEvidence::new(
                Locator::ElfSymbol {
                    location: "zephyr.elf".to_owned(),
                    symbol: "f".to_owned(),
                },
                "elf-symbols",
                ConfidenceLevel::Medium,
                "linked",
            )
            .unwrap();
            let asset = CryptoAsset::new(properties, [evidence]).unwrap();
            let component = model::Component::new(ComponentKind::CryptographicAsset, "x")
                .unwrap()
                .with_crypto(asset);
            let mut image = Image::new(model::ImageKind::Application, "app").unwrap();
            image.add_component(component).unwrap();
            let mut product = Product::new("p").unwrap();
            product.add_image(image).unwrap();
            let options = WriteOptions::new(Timestamp::parse("2026-01-02T03:04:05Z").unwrap());
            let bom = to_document(&product, &options).unwrap();
            let doc = serde_json::to_value(&bom).unwrap();
            let asset = &doc["components"][0]["components"][0];
            assert_eq!(asset["type"], "cryptographic-asset");
            let crypto = &asset["cryptoProperties"];
            assert_eq!(crypto["assetType"], asset_type, "{crypto}");
            assert!(crypto[block].is_object(), "{crypto}");
            for other in BLOCKS.iter().filter(|b| **b != block) {
                assert!(crypto.get(*other).is_none(), "{other} in {crypto}");
            }
            // The rollcall evidence is not in `cryptoProperties`; it is in properties and
            // `evidence`.
            assert!(crypto.get("evidence").is_none(), "{crypto}");
            // Schema order: `evidence`, `cryptoProperties`, `properties`.
            let text = serde_json::to_string(&bom.components[0].components[0]).unwrap();
            let at = |key: &str| text.find(&format!("\"{key}\":")).unwrap();
            assert!(
                at("evidence") < at("cryptoProperties")
                    && at("cryptoProperties") < at("properties"),
                "{text}"
            );
            let names: Vec<&str> = asset["properties"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["name"].as_str().unwrap())
                .collect();
            assert_eq!(
                names,
                vec![CRYPTO_EVIDENCE_PROPERTY, EVIDENCE_SOURCE],
                "{names:?}"
            );
            assert_eq!(
                asset["evidence"]["occurrences"][0],
                serde_json::json!({"location": "zephyr.elf", "symbol": "f",
                                   "additionalContext": "linked"})
            );
            assert_eq!(
                asset["evidence"]["identity"][0]["confidence"],
                Value::from(0.6)
            );
        }
    }
}
