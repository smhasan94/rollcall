//! The CSAF `product_tree`, built from the SBOM's hierarchy as written.
//!
//! The SBOM JSON is walked directly (not the model), so every `bom-ref`, purl and CPE reaches
//! the CSAF document byte for byte as the SBOM spells it. See the [module docs](super) for
//! the mapping.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Map, Value};

use super::vulnerabilities::product_id_of;

/// A `full_product_name_t`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FullProductName {
    /// `name`: the node's name and version.
    pub name: String,
    /// `product_id`: the node's `bom-ref`.
    pub product_id: String,
    /// `product_identification_helper`: the node's purl and CPE, verbatim. Absent when it has
    /// neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_identification_helper: Option<IdentificationHelper>,
}

/// A `product_identification_helper`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct IdentificationHelper {
    /// The CPE, verbatim from the SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
    /// The purl, verbatim from the SBOM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// A `branches_t` item: a category, a name and exactly one of `branches` or `product`.
/// Fields (here and in every CSAF struct) are declared in alphabetical order, so the JSON
/// keys are sorted (the validator's optional test 6.2.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Branch {
    /// The branches below this one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branches: Option<Vec<Branch>>,
    /// `vendor`, `product_name` or `product_version`.
    pub category: &'static str,
    /// The vendor, product name or version.
    pub name: String,
    /// The product this branch ends in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<FullProductName>,
}

/// A `relationships` item: a component is part of its parent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Relationship {
    /// `default_component_of`, or `optional_component_of` for an optional component.
    pub category: &'static str,
    /// The combination: `<component bom-ref>@<product bom-ref>`.
    pub full_product_name: FullProductName,
    /// The component's `bom-ref`.
    pub product_reference: String,
    /// The product's `bom-ref`.
    pub relates_to_product_reference: String,
}

/// The `product_tree`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductTree {
    /// The product: vendor → product name → product version.
    pub branches: Vec<Branch>,
    /// The SBOM components the vulnerabilities name, sorted by `product_id`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub full_product_names: Vec<FullProductName>,
    /// Each component as part of the product, sorted by component.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
}

impl ProductTree {
    /// Every `product_id` the tree defines, the relationships' included.
    pub fn product_ids(&self) -> BTreeSet<&str> {
        fn walk<'a>(branches: &'a [Branch], out: &mut BTreeSet<&'a str>) {
            for b in branches {
                if let Some(p) = &b.product {
                    out.insert(p.product_id.as_str());
                }
                if let Some(children) = &b.branches {
                    walk(children, out);
                }
            }
        }
        let mut out = BTreeSet::new();
        walk(&self.branches, &mut out);
        out.extend(
            self.full_product_names
                .iter()
                .map(|f| f.product_id.as_str()),
        );
        out.extend(
            self.relationships
                .iter()
                .map(|r| r.full_product_name.product_id.as_str()),
        );
        out
    }
}

/// One SBOM node, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// `bom-ref`.
    pub bom_ref: String,
    /// `name`.
    pub name: String,
    /// `version`.
    pub version: Option<String>,
    /// `supplier.name`.
    pub supplier: Option<String>,
    /// `purl`, verbatim.
    pub purl: Option<String>,
    /// `cpe`, verbatim.
    pub cpe: Option<String>,
}

impl Node {
    /// `name version`, or `name`.
    pub fn label(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {v}", self.name),
            None => self.name.clone(),
        }
    }

    fn full_product_name(&self) -> FullProductName {
        let helper = (self.purl.is_some() || self.cpe.is_some()).then(|| IdentificationHelper {
            cpe: self.cpe.clone(),
            purl: self.purl.clone(),
        });
        FullProductName {
            name: self.label(),
            product_id: self.bom_ref.clone(),
            product_identification_helper: helper,
        }
    }
}

/// A non-product SBOM node, with its nearest ancestor that has a `bom-ref` and its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// The node.
    pub node: Node,
    /// The parent's `bom-ref`.
    pub parent: String,
    /// The CycloneDX `scope`, if given.
    pub scope: Option<String>,
}

/// The SBOM's hierarchy: the product (`metadata.component`) and every component below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomTree {
    /// `metadata.component`.
    pub product: Node,
    /// Every component with a `bom-ref`, in document order.
    pub children: Vec<Child>,
}

fn opt_str<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<&'a str>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{path}/{key}: expected a string")),
    }
}

fn node(obj: &Map<String, Value>, path: &str) -> Result<(Option<Node>, Option<String>), String> {
    let name = opt_str(obj, "name", path)?
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| format!("{path}/name: expected a non-empty string"))?;
    let supplier = match obj.get("supplier") {
        None | Some(Value::Null) => None,
        Some(Value::Object(s)) => opt_str(s, "name", &format!("{path}/supplier"))?
            .filter(|n| !n.trim().is_empty())
            .map(str::to_owned),
        Some(_) => return Err(format!("{path}/supplier: expected an object")),
    };
    let nonempty = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_owned);
    let scope = opt_str(obj, "scope", path)?.map(str::to_owned);
    let built = opt_str(obj, "bom-ref", path)?
        .filter(|r| !r.is_empty())
        .map(|bom_ref| -> Result<Node, String> {
            Ok(Node {
                bom_ref: bom_ref.to_owned(),
                name: name.to_owned(),
                version: nonempty(opt_str(obj, "version", path)?),
                supplier,
                purl: nonempty(opt_str(obj, "purl", path)?),
                cpe: nonempty(opt_str(obj, "cpe", path)?),
            })
        })
        .transpose()?;
    Ok((built, scope))
}

fn walk(
    components: &Value,
    path: &str,
    parent: &str,
    depth: usize,
    out: &mut Vec<Child>,
) -> Result<(), String> {
    // CycloneDX nesting is shallow in practice; this only bounds hostile input.
    if depth > 64 {
        return Err(format!("{path}: components nested more than 64 deep"));
    }
    let items = match components {
        Value::Null => return Ok(()),
        Value::Array(items) => items,
        _ => return Err(format!("{path}: expected an array")),
    };
    for (i, item) in items.iter().enumerate() {
        let ipath = format!("{path}/{i}");
        let obj = item
            .as_object()
            .ok_or_else(|| format!("{ipath}: expected an object"))?;
        let (built, scope) = node(obj, &ipath)?;
        let next_parent = match built {
            Some(node) => {
                let r = node.bom_ref.clone();
                out.push(Child {
                    node,
                    parent: parent.to_owned(),
                    scope,
                });
                r
            }
            // A component without a bom-ref cannot be named by a finding; its children
            // hang off its nearest named ancestor.
            None => parent.to_owned(),
        };
        if let Some(nested) = obj.get("components") {
            walk(
                nested,
                &format!("{ipath}/components"),
                &next_parent,
                depth + 1,
                out,
            )?;
        }
    }
    Ok(())
}

/// Reads the product and its components from a CycloneDX JSON SBOM. Never panics; a field
/// with the wrong type, or a product without a name or `bom-ref`, is an error naming its JSON
/// pointer.
pub fn read_tree(document: &Value) -> Result<SbomTree, String> {
    let root = document
        .as_object()
        .ok_or_else(|| "the SBOM is not a JSON object".to_owned())?;
    let product = root
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(Value::as_object)
        .ok_or_else(|| "/metadata/component: expected an object (the product)".to_owned())?;
    let (product, _) = node(product, "/metadata/component")?;
    let product = product.ok_or_else(|| {
        "/metadata/component/bom-ref: the product needs a bom-ref to be a CSAF product".to_owned()
    })?;
    let mut children = Vec::new();
    if let Some(components) = root.get("components") {
        walk(
            components,
            "/components",
            &product.bom_ref,
            0,
            &mut children,
        )?;
    }
    Ok(SbomTree { product, children })
}

/// Builds the `product_tree` (see the [module docs](super)): the product, and the SBOM
/// components in `components` (by `bom-ref`; scope `excluded` ones are never included), each
/// as a full product name and as a relationship product "component as part of the product".
pub fn build(tree: &SbomTree, components: &BTreeSet<String>) -> ProductTree {
    let product = &tree.product;
    let leaf = match &product.version {
        Some(version) => Branch {
            category: "product_version",
            name: version.clone(),
            branches: None,
            product: Some(product.full_product_name()),
        },
        None => Branch {
            category: "product_name",
            name: product.name.clone(),
            branches: None,
            product: Some(product.full_product_name()),
        },
    };
    let named = if product.version.is_some() {
        Branch {
            category: "product_name",
            name: product.name.clone(),
            branches: Some(vec![leaf]),
            product: None,
        }
    } else {
        leaf
    };
    let top = match &product.supplier {
        Some(vendor) => Branch {
            category: "vendor",
            name: vendor.clone(),
            branches: Some(vec![named]),
            product: None,
        },
        None => named,
    };

    // Only the components a vulnerability names, so every product id the tree defines is
    // used (the validator's optional test 6.2.1). Excluded components are never part of it.
    let named: Vec<&Child> = tree
        .children
        .iter()
        .filter(|c| components.contains(&c.node.bom_ref))
        .filter(|c| c.scope.as_deref() != Some("excluded"))
        .collect();
    let mut full_product_names: Vec<FullProductName> =
        named.iter().map(|c| c.node.full_product_name()).collect();
    full_product_names.sort_by(|a, b| (&a.product_id, a).cmp(&(&b.product_id, b)));
    full_product_names.dedup();

    // Each named component as part of the product (CSAF 2.0 3.2.3.4): what the
    // vulnerabilities' statuses are about.
    let mut relationships: Vec<Relationship> = named
        .iter()
        .map(|c| Relationship {
            category: if c.scope.as_deref() == Some("optional") {
                "optional_component_of"
            } else {
                "default_component_of"
            },
            full_product_name: FullProductName {
                name: format!("{} as a component of {}", c.node.label(), product.label()),
                product_id: product_id_of(&c.node.bom_ref, &product.bom_ref),
                product_identification_helper: None,
            },
            product_reference: c.node.bom_ref.clone(),
            relates_to_product_reference: product.bom_ref.clone(),
        })
        .collect();
    relationships.sort_by(|a, b| {
        (&a.product_reference, &a.relates_to_product_reference, a).cmp(&(
            &b.product_reference,
            &b.relates_to_product_reference,
            b,
        ))
    });
    relationships.dedup();

    ProductTree {
        branches: vec![top],
        full_product_names,
        relationships,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sbom() -> Value {
        json!({
            "bomFormat": "CycloneDX",
            "metadata": {"component": {
                "type": "firmware", "bom-ref": "product:1", "name": "node", "version": "1.0.0",
                "supplier": {"name": "Example Devices Ltd"}
            }},
            "components": [
                {"type": "firmware", "bom-ref": "image:1", "name": "app", "components": [
                    {"type": "library", "bom-ref": "c:1", "name": "mbedtls", "version": "2.28.0",
                     "purl": "pkg:github/mbed-tls/mbedtls@v2.28.0",
                     "cpe": "cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*"},
                    {"type": "library", "name": "anonymous", "components": [
                        {"type": "library", "bom-ref": "c:2", "name": "deep", "scope": "optional"}
                    ]},
                    {"type": "library", "bom-ref": "c:3", "name": "gone", "scope": "excluded"}
                ]}
            ]
        })
    }

    fn refs(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|r| (*r).to_owned()).collect()
    }

    #[test]
    fn tree_has_vendor_product_version_and_relationships_to_the_product() {
        let all = refs(&["image:1", "c:1", "c:2", "c:3"]);
        let tree = build(&read_tree(&sbom()).unwrap(), &all);
        let value = serde_json::to_value(&tree).unwrap();
        let top = &value["branches"][0];
        assert_eq!(top["category"], "vendor");
        assert_eq!(top["name"], "Example Devices Ltd");
        assert_eq!(top["branches"][0]["category"], "product_name");
        assert_eq!(
            top["branches"][0]["branches"][0]["category"],
            "product_version"
        );
        assert_eq!(
            top["branches"][0]["branches"][0]["product"]["product_id"],
            "product:1"
        );
        // c:3 is excluded: never part of the tree, even when asked for.
        let ids: Vec<&str> = tree
            .full_product_names
            .iter()
            .map(|f| f.product_id.as_str())
            .collect();
        assert_eq!(ids, ["c:1", "c:2", "image:1"]);
        let mbedtls = &tree.full_product_names[0];
        assert_eq!(mbedtls.name, "mbedtls 2.28.0");
        let helper = mbedtls.product_identification_helper.as_ref().unwrap();
        assert_eq!(
            helper.purl.as_deref(),
            Some("pkg:github/mbed-tls/mbedtls@v2.28.0")
        );
        let rels: Vec<(&str, &str, &str, &str)> = tree
            .relationships
            .iter()
            .map(|r| {
                (
                    r.category,
                    r.full_product_name.product_id.as_str(),
                    r.product_reference.as_str(),
                    r.relates_to_product_reference.as_str(),
                )
            })
            .collect();
        // Flat: every component as part of the product, whatever its nesting.
        assert_eq!(
            rels,
            [
                ("default_component_of", "c:1@product:1", "c:1", "product:1"),
                ("optional_component_of", "c:2@product:1", "c:2", "product:1"),
                (
                    "default_component_of",
                    "image:1@product:1",
                    "image:1",
                    "product:1"
                ),
            ]
        );
        assert_eq!(
            tree.relationships[0].full_product_name.name,
            "mbedtls 2.28.0 as a component of node 1.0.0"
        );
        assert_eq!(tree.product_ids().len(), 7);
    }

    #[test]
    fn only_the_named_components_are_in_the_tree() {
        let tree = build(&read_tree(&sbom()).unwrap(), &refs(&["c:1"]));
        assert_eq!(tree.full_product_names.len(), 1);
        assert_eq!(tree.relationships.len(), 1);
        assert_eq!(
            tree.product_ids(),
            BTreeSet::from(["product:1", "c:1", "c:1@product:1"])
        );
        let none = build(&read_tree(&sbom()).unwrap(), &BTreeSet::new());
        assert!(none.full_product_names.is_empty() && none.relationships.is_empty());
    }

    #[test]
    fn product_without_version_or_supplier_is_one_branch() {
        let mut doc = sbom();
        doc["metadata"]["component"] = json!({"bom-ref": "p", "name": "bare"});
        let tree = build(&read_tree(&doc).unwrap(), &BTreeSet::new());
        assert_eq!(tree.branches.len(), 1);
        assert_eq!(tree.branches[0].category, "product_name");
        assert_eq!(tree.branches[0].product.as_ref().unwrap().product_id, "p");
    }

    #[test]
    fn malformed_sbom_trees_are_errors_not_panics() {
        let cases = [
            (json!(null), "not a JSON object"),
            (json!({}), "/metadata/component"),
            (json!({"metadata": {"component": {"name": "x"}}}), "bom-ref"),
            (
                json!({"metadata": {"component": {"bom-ref": "p"}}}),
                "/metadata/component/name",
            ),
            (
                json!({"metadata": {"component": {"bom-ref": "p", "name": 3}}}),
                "/metadata/component/name",
            ),
            (
                json!({"metadata": {"component": {"bom-ref": "p", "name": "x", "supplier": "s"}}}),
                "/metadata/component/supplier",
            ),
            (
                json!({"metadata": {"component": {"bom-ref": "p", "name": "x"}}, "components": {}}),
                "/components",
            ),
            (
                json!({"metadata": {"component": {"bom-ref": "p", "name": "x"}}, "components": [1]}),
                "/components/0",
            ),
            (
                json!({"metadata": {"component": {"bom-ref": "p", "name": "x"}},
                       "components": [{"name": "c", "bom-ref": "c", "purl": 5}]}),
                "/components/0/purl",
            ),
        ];
        for (doc, want) in cases {
            let err = read_tree(&doc).unwrap_err();
            assert!(err.contains(want), "{doc}: {err}");
        }
        // Hostile nesting is bounded.
        let mut deep = json!([{"name": "leaf", "bom-ref": "leaf"}]);
        for i in 0..100 {
            deep = json!([{"name": format!("n{i}"), "components": deep}]);
        }
        let doc =
            json!({"metadata": {"component": {"bom-ref": "p", "name": "x"}}, "components": deep});
        assert!(read_tree(&doc).unwrap_err().contains("nested"));
    }
}
