//! A lenient, generic view of a CycloneDX JSON document for the profile checks.
//!
//! The reader works on any [`Value`], not just documents rollcall wrote, and never fails: a
//! field of the wrong type is read as absent, so a malformed document produces findings
//! rather than errors. The tree is walked iteratively (no recursion), so nesting depth cannot
//! overflow the stack.

use std::collections::BTreeMap;

use serde_json::Value;

/// One component of the document: the root (`metadata.component`) or an entry of
/// `components[]` at any depth.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Node {
    /// JSON pointer to the component, e.g. `/components/1/components/0`.
    pub pointer: String,
    /// `bom-ref`, when it is a non-empty string.
    pub bom_ref: Option<String>,
    /// `type`.
    pub kind: Option<String>,
    /// `name`.
    pub name: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `supplier.name`.
    pub supplier: Option<String>,
    /// `manufacturer.name`.
    pub manufacturer: Option<String>,
    /// `authors[]` has an entry with a non-empty `name` or `email`.
    pub has_authors: bool,
    /// `publisher`.
    pub publisher: Option<String>,
    /// Identifiers present, keyed by the profile parameter name (`purl`, `cpe`, `swid`,
    /// `omniborId`, `swhid`).
    pub identifiers: BTreeMap<&'static str, String>,
    /// `hashes[]` as `(alg, content)`, entries of the wrong shape left out.
    pub hashes: Vec<(String, String)>,
    /// `properties[]` as `(name, value)`, entries of the wrong shape left out.
    pub properties: Vec<(String, String)>,
    /// Index of the enclosing component, if any (the root and top-level components have none).
    pub parent: Option<usize>,
    /// Whether this is a direct entry of the document's top-level `components[]`.
    pub top_level: bool,
}

impl Node {
    /// How findings refer to the node: its `bom-ref`, else its JSON pointer.
    pub fn label(&self) -> &str {
        self.bom_ref.as_deref().unwrap_or(&self.pointer)
    }

    /// The value of the first property called `name`.
    pub fn property(&self, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One `dependencies[]` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Declared {
    /// JSON pointer to the entry, e.g. `/dependencies/3`.
    pub pointer: String,
    /// `ref`, when it is a string.
    pub r#ref: Option<String>,
    /// `dependsOn[]`: each entry, `None` when it is not a string.
    pub depends_on: Vec<Option<String>>,
}

/// What the document-level checks look at in `metadata`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DocMetadata {
    /// `metadata.timestamp`, when it is a string.
    pub timestamp: Option<String>,
    /// `metadata.authors[]` has an entry with a non-empty `name` or `email`.
    pub has_authors: bool,
    /// `metadata.tools` lists a tool: `tools.components[]`, `tools.services[]`, or the legacy
    /// `tools[]` array, with a non-empty `name`.
    pub has_tools: bool,
    /// `metadata.manufacturer.name` is non-empty.
    pub has_manufacturer: bool,
}

/// One `services[]` entry, at any depth.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Service {
    /// JSON pointer to the service, e.g. `/services/0/services/1`.
    pub pointer: String,
    /// `bom-ref`, when it is a non-empty string.
    pub bom_ref: Option<String>,
}

/// The flattened document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Doc {
    /// Index of `metadata.component` in `nodes`, when present.
    pub root: Option<usize>,
    /// Every component in document order: the root first, then `components[]` pre-order.
    pub nodes: Vec<Node>,
    /// `dependencies[]` in document order; entries that are not objects are left out.
    pub declared: Vec<Declared>,
    /// Pointers of `dependencies[]` entries that are not objects.
    pub malformed_dependencies: Vec<String>,
    /// Every `services[]` entry (and nested `services`), pre-order. Services may be named by
    /// `dependencies`, but are not components: no component check applies to them and they
    /// need not be reachable from the root.
    pub services: Vec<Service>,
    /// Document metadata.
    pub metadata: DocMetadata,
}

/// A non-empty (after trimming) string, else `None`.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
}

fn has_named_entry(value: Option<&Value>, keys: &[&str]) -> bool {
    value.and_then(Value::as_array).is_some_and(|entries| {
        entries
            .iter()
            .any(|e| keys.iter().any(|k| text(e.get(*k)).is_some()))
    })
}

fn read_node(value: &Value, pointer: String, parent: Option<usize>, top_level: bool) -> Node {
    let mut identifiers = BTreeMap::new();
    for (key, field) in [("purl", "purl"), ("cpe", "cpe")] {
        if let Some(v) = text(value.get(field)) {
            identifiers.insert(key, v);
        }
    }
    if let Some(v) = text(value.get("swid").and_then(|s| s.get("tagId"))) {
        identifiers.insert("swid", v);
    }
    for key in ["omniborId", "swhid"] {
        let first = value
            .get(key)
            .and_then(Value::as_array)
            .and_then(|ids| ids.iter().find_map(|id| text(Some(id))));
        if let Some(v) = first {
            identifiers.insert(key, v);
        }
    }
    let pairs = |field: &str, a: &str, b: &str| -> Vec<(String, String)> {
        value
            .get(field)
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| Some((text(e.get(a))?, text(e.get(b))?)))
                    .collect()
            })
            .unwrap_or_default()
    };
    Node {
        pointer,
        bom_ref: text(value.get("bom-ref")),
        kind: text(value.get("type")),
        name: text(value.get("name")),
        version: text(value.get("version")),
        supplier: text(value.get("supplier").and_then(|s| s.get("name"))),
        manufacturer: text(value.get("manufacturer").and_then(|s| s.get("name"))),
        has_authors: has_named_entry(value.get("authors"), &["name", "email"]),
        publisher: text(value.get("publisher")),
        identifiers,
        hashes: pairs("hashes", "alg", "content"),
        properties: pairs("properties", "name", "value"),
        parent,
        top_level,
    }
}

/// A component still to be read by [`Doc::from_value`]'s walk.
struct Pending<'a> {
    value: &'a Value,
    pointer: String,
    parent: Option<usize>,
    top_level: bool,
}

/// Pushes the object entries of `list` (a `components` array) in reverse, so they pop in
/// document order.
fn push_children<'a>(
    stack: &mut Vec<Pending<'a>>,
    list: Option<&'a Value>,
    base: &str,
    parent: Option<usize>,
    top_level: bool,
) {
    if let Some(children) = list.and_then(Value::as_array) {
        for (i, child) in children.iter().enumerate().rev() {
            if child.is_object() {
                stack.push(Pending {
                    value: child,
                    pointer: format!("{base}/components/{i}"),
                    parent,
                    top_level,
                });
            }
        }
    }
}

/// Pushes the object entries of `list` (a `services` array) in reverse, so they pop in
/// document order.
fn push_services<'a>(stack: &mut Vec<(&'a Value, String)>, list: Option<&'a Value>, base: &str) {
    if let Some(entries) = list.and_then(Value::as_array) {
        for (i, service) in entries.iter().enumerate().rev() {
            if service.is_object() {
                stack.push((service, format!("{base}/services/{i}")));
            }
        }
    }
}

impl Doc {
    /// Flattens `document`. Never fails and never panics.
    pub fn from_value(document: &Value) -> Doc {
        let mut doc = Doc::default();
        let metadata = document.get("metadata");
        doc.metadata = DocMetadata {
            timestamp: metadata
                .and_then(|m| m.get("timestamp"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            has_authors: has_named_entry(
                metadata.and_then(|m| m.get("authors")),
                &["name", "email"],
            ),
            has_tools: metadata.and_then(|m| m.get("tools")).is_some_and(|tools| {
                has_named_entry(Some(tools), &["name"])
                    || has_named_entry(tools.get("components"), &["name"])
                    || has_named_entry(tools.get("services"), &["name"])
            }),
            has_manufacturer: text(
                metadata
                    .and_then(|m| m.get("manufacturer"))
                    .and_then(|m| m.get("name")),
            )
            .is_some(),
        };
        if let Some(root) = metadata
            .and_then(|m| m.get("component"))
            .filter(|c| c.is_object())
        {
            doc.root = Some(0);
            doc.nodes.push(read_node(
                root,
                "/metadata/component".to_owned(),
                None,
                false,
            ));
        }

        // Pre-order walk with an explicit stack.
        let mut stack: Vec<Pending<'_>> = Vec::new();
        push_children(&mut stack, document.get("components"), "", None, true);
        while let Some(Pending {
            value,
            pointer,
            parent,
            top_level,
        }) = stack.pop()
        {
            let index = doc.nodes.len();
            let node = read_node(value, pointer, parent, top_level);
            push_children(
                &mut stack,
                value.get("components"),
                &node.pointer,
                Some(index),
                false,
            );
            doc.nodes.push(node);
        }

        // Services, pre-order, with an explicit stack.
        let mut services: Vec<(&Value, String)> = Vec::new();
        push_services(&mut services, document.get("services"), "");
        while let Some((value, pointer)) = services.pop() {
            push_services(&mut services, value.get("services"), &pointer);
            doc.services.push(Service {
                bom_ref: text(value.get("bom-ref")),
                pointer,
            });
        }

        if let Some(entries) = document.get("dependencies").and_then(Value::as_array) {
            for (i, entry) in entries.iter().enumerate() {
                let pointer = format!("/dependencies/{i}");
                if !entry.is_object() {
                    doc.malformed_dependencies.push(pointer);
                    continue;
                }
                let depends_on = entry
                    .get("dependsOn")
                    .and_then(Value::as_array)
                    .map(|targets| {
                        targets
                            .iter()
                            .map(|t| t.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                doc.declared.push(Declared {
                    pointer,
                    r#ref: entry.get("ref").and_then(Value::as_str).map(str::to_owned),
                    depends_on,
                });
            }
        }
        doc
    }

    /// The root node, if the document has one.
    pub fn root_node(&self) -> Option<&Node> {
        self.root.and_then(|i| self.nodes.get(i))
    }

    /// Every `bom-ref` a dependency may name, mapped to its first holder: a component
    /// (index `i < nodes.len()` into [`Doc::nodes`]) or a service (index
    /// `nodes.len() + j` for [`Doc::services`]`[j]`). Components come first, so a ref used
    /// by both maps to the component.
    pub fn index_of(&self) -> BTreeMap<&str, usize> {
        let mut map = BTreeMap::new();
        let refs = self
            .nodes
            .iter()
            .map(|n| n.bom_ref.as_deref())
            .chain(self.services.iter().map(|s| s.bom_ref.as_deref()));
        for (i, r) in refs.enumerate() {
            if let Some(r) = r {
                map.entry(r).or_insert(i);
            }
        }
        map
    }

    /// The JSON pointer of the component or service at an [`Doc::index_of`] index.
    pub fn pointer_of(&self, index: usize) -> &str {
        match self.nodes.get(index) {
            Some(node) => &node.pointer,
            None => self
                .services
                .get(index - self.nodes.len().min(index))
                .map_or("", |s| s.pointer.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_root_and_nested_components_in_document_order() {
        let doc = Doc::from_value(&json!({
            "metadata": {"timestamp": "2026-01-02T03:04:05Z",
                         "tools": {"components": [{"name": "rollcall"}]},
                         "component": {"bom-ref": "root", "name": "p"}},
            "components": [
                {"bom-ref": "a", "name": "a", "components": [{"bom-ref": "a1", "name": "a1"}]},
                {"bom-ref": "b", "name": "b", "purl": "pkg:generic/b@1",
                 "omniborId": ["gitoid:blob:sha1:00"], "hashes": [{"alg": "SHA-256", "content": "00"}]}
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["a", 3]}, 7]
        }));
        let refs: Vec<_> = doc.nodes.iter().map(Node::label).collect();
        assert_eq!(refs, ["root", "a", "a1", "b"]);
        assert_eq!(doc.root, Some(0));
        assert_eq!(doc.nodes[2].parent, Some(1));
        assert_eq!(doc.nodes[2].pointer, "/components/0/components/0");
        assert!(doc.nodes[1].top_level && !doc.nodes[2].top_level && !doc.nodes[0].top_level);
        assert_eq!(doc.nodes[3].identifiers.len(), 2);
        assert_eq!(doc.nodes[3].hashes, [("SHA-256".into(), "00".into())]);
        assert!(doc.metadata.has_tools && !doc.metadata.has_authors);
        assert_eq!(doc.declared[0].depends_on, [Some("a".into()), None]);
        assert_eq!(doc.malformed_dependencies, ["/dependencies/1"]);
        assert!(doc.services.is_empty());
        let doc = Doc::from_value(&json!({
            "services": [{"bom-ref": "s1", "services": [{"bom-ref": "s2"}, 3]}, {"name": "x"}, null],
            "components": [{"bom-ref": "c"}]
        }));
        let services: Vec<_> = doc
            .services
            .iter()
            .map(|s| (s.pointer.as_str(), s.bom_ref.as_deref()))
            .collect();
        assert_eq!(
            services,
            [
                ("/services/0", Some("s1")),
                ("/services/0/services/0", Some("s2")),
                ("/services/1", None)
            ]
        );
        let index = doc.index_of();
        assert_eq!((index["c"], index["s1"], index["s2"]), (0, 1, 2));
        assert_eq!(doc.pointer_of(2), "/services/0/services/0");
    }

    #[test]
    fn reader_never_panics_on_malformed_shapes() {
        let cases = [
            json!(null),
            json!([]),
            json!("text"),
            json!(3),
            json!({}),
            json!({"metadata": 3, "components": 3, "dependencies": "x"}),
            json!({"metadata": {"component": [], "tools": 3, "authors": {}}}),
            json!({"metadata": {"timestamp": 5, "tools": [{"name": 1}]}}),
            json!({"components": [null, 1, "x", {"name": 3, "hashes": {}, "properties": 4}]}),
            json!({"components": [{"hashes": [1, {"alg": 2}], "properties": [{"name": "n"}]}]}),
            json!({"components": [{"supplier": "acme", "manufacturer": [], "swid": 1, "swhid": "x"}]}),
            json!({"dependencies": [{"ref": 1}, {"dependsOn": {}}, {"ref": "a", "dependsOn": [null]}]}),
            json!({"services": 3}),
            json!({"services": [{"bom-ref": 1, "services": {"a": 1}}, [], "s"]}),
        ];
        for case in cases {
            let doc = Doc::from_value(&case);
            for node in &doc.nodes {
                assert!(!node.label().is_empty(), "{case}");
            }
        }
        // Deep nesting (beyond serde_json's parse limit of 128) is walked without recursion.
        let mut deep = json!({"name": "leaf"});
        for _ in 0..300 {
            deep = json!({"name": "n", "components": [deep]});
        }
        let doc = Doc::from_value(&json!({"components": [deep]}));
        assert_eq!(doc.nodes.len(), 301);
    }

    #[test]
    fn truncated_goldens_are_read_without_panic() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
        for name in ["widget.cdx.json", "minimal.cdx.json"] {
            let text = std::fs::read_to_string(dir.join(name)).unwrap();
            let value: Value = serde_json::from_str(&text).unwrap();
            let full = Doc::from_value(&value);
            assert!(!full.nodes.is_empty());
            // Every prefix that still parses (none past the first byte do, but the reader
            // must cope with whatever serde_json accepts); and every sub-tree on its own.
            for cut in [1, text.len() / 3, text.len() / 2] {
                if let Ok(v) = serde_json::from_str::<Value>(text.get(..cut).unwrap_or("")) {
                    let _ = Doc::from_value(&v);
                }
            }
            for key in ["metadata", "components", "dependencies"] {
                let _ = Doc::from_value(&value[key]);
            }
        }
    }
}
