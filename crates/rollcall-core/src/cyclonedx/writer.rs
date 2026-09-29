//! Model → CycloneDX 1.6 document. See the [module docs](super) for the mapping.

use std::collections::{BTreeMap, BTreeSet};

use super::document::{
    Bom, Component, Dependency, Evidence, Hash, Identity, LicenseChoice, Metadata, Method,
    NamedLicense, Occurrence, Property, Supplier, Tool, Tools,
};
use super::{SerialNumber, WriteError, WriteOptions};
use crate::model::{
    self, BomRef, Cpe, EvidenceField, EvidenceSet, License, NodePath, PathSegment, Product, Purl,
};

/// CycloneDX component type used for the product and for every image.
const FIRMWARE: &str = "firmware";
/// Property carrying an image's [`ImageKind`](crate::model::ImageKind).
const IMAGE_KIND: &str = "rollcall:image-kind";
/// Property carrying the name of an input that contributed evidence.
const EVIDENCE_SOURCE: &str = "rollcall:evidence-source";

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
    hashes: &'a BTreeSet<model::Hash>,
    licence: Option<&'a License>,
    evidence: &'a EvidenceSet,
}

impl<'a> Facts<'a> {
    fn of_product(p: &'a Product) -> Self {
        Self {
            name: &p.name,
            version: p.version.as_deref(),
            supplier: p.supplier.as_ref(),
            purl: p.purl.as_ref(),
            cpe: p.cpe.as_ref(),
            hashes: &p.hashes,
            licence: p.licence.as_ref(),
            evidence: &p.evidence,
        }
    }

    fn of_image(i: &'a model::Image) -> Self {
        Self {
            name: &i.name,
            version: i.version.as_deref(),
            supplier: i.supplier.as_ref(),
            purl: i.purl.as_ref(),
            cpe: i.cpe.as_ref(),
            hashes: &i.hashes,
            licence: i.licence.as_ref(),
            evidence: &i.evidence,
        }
    }

    fn of_component(c: &'a model::Component) -> Self {
        Self {
            name: &c.name,
            version: c.version.as_deref(),
            supplier: c.supplier.as_ref(),
            purl: c.purl.as_ref(),
            cpe: c.cpe.as_ref(),
            hashes: &c.hashes,
            licence: c.licence.as_ref(),
            evidence: &c.evidence,
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
    /// extra node-specific properties; evidence sources are added here and all are sorted.
    fn to_component(
        &self,
        kind: &'static str,
        bom_ref: &BomRef,
        mut properties: Vec<Property>,
    ) -> Component {
        let sources: BTreeSet<&str> = self.evidence.iter().map(|e| e.source()).collect();
        properties.extend(sources.into_iter().map(|source| Property {
            name: EVIDENCE_SOURCE,
            value: source.to_owned(),
        }));
        properties.sort();
        properties.dedup();

        let evidence = self.evidence();
        Component {
            kind,
            bom_ref: bom_ref.as_str().to_owned(),
            name: self.name.to_owned(),
            version: self.version.map(str::to_owned),
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
            properties,
            components: Vec::new(),
        }
    }

    /// `evidence`: identity per field, de-duplicated occurrences and licence evidence.
    /// Supplier evidence has no CycloneDX evidence field and is not emitted (its source still
    /// appears as a `rollcall:evidence-source` property).
    fn evidence(&self) -> Evidence {
        let identity = IDENTITY_FIELDS
            .iter()
            .filter_map(|&field| {
                let methods: Vec<Method> = self
                    .evidence
                    .iter()
                    .filter(|e| e.field == field)
                    .map(|e| Method {
                        technique: e.technique,
                        confidence: e.confidence.as_f64(),
                        value: e.value.clone(),
                    })
                    .collect();
                (!methods.is_empty()).then(|| Identity {
                    field,
                    confidence: self.evidence.confidence_for(field).as_f64(),
                    concluded_value: self.concluded(field),
                    methods,
                })
            })
            .collect();

        let occurrences: BTreeSet<&model::Occurrence> = self
            .evidence
            .iter()
            .filter_map(|e| e.occurrence.as_ref())
            .collect();
        let occurrences = occurrences
            .into_iter()
            .map(|o| Occurrence {
                location: o.location().to_owned(),
                line: o.line(),
            })
            .collect();

        let licences: BTreeSet<&str> = self
            .evidence
            .iter()
            .filter(|e| e.field == EvidenceField::Licence)
            .map(|e| e.value.as_str())
            .collect();
        let licenses = if licences.len() == 1 {
            licences
                .into_iter()
                .map(|v| LicenseChoice::Expression {
                    expression: v.to_owned(),
                })
                .collect()
        } else {
            licences
                .into_iter()
                .map(|v| LicenseChoice::License {
                    license: NamedLicense { name: v.to_owned() },
                })
                .collect()
        };

        Evidence {
            identity,
            occurrences,
            licenses,
        }
    }
}

/// A component and, recursively, its subcomponents. `path` is the component's own path,
/// derived exactly as [`Product::walk`] derives it.
fn component(c: &model::Component, path: &NodePath) -> Component {
    let mut out =
        Facts::of_component(c).to_component(c.kind.as_str(), &BomRef::derive(path), vec![]);
    out.components = c
        .components
        .iter()
        .map(|child| component(child, &path.child(PathSegment::of_component(child))))
        .collect();
    out
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
    let root_component =
        Facts::of_product(product).to_component(FIRMWARE, &BomRef::derive(&root), vec![]);

    let components = product
        .images
        .iter()
        .map(|image| {
            let path = root.child(PathSegment::of_image(image));
            let kind = vec![Property {
                name: IMAGE_KIND,
                value: image.kind.as_str().to_owned(),
            }];
            let mut out =
                Facts::of_image(image).to_component(FIRMWARE, &BomRef::derive(&path), kind);
            out.components = image
                .components
                .iter()
                .map(|c| component(c, &path.child(PathSegment::of_component(c))))
                .collect();
            out
        })
        .collect();

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
        },
        components,
        dependencies,
    })
}
