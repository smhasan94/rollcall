//! The catalogue of profile checks.
//!
//! Checks are code; which checks a profile runs, at what severity, with which parameters and
//! citing which clause is data ([`super::Profile`]). Check ids are a stable public contract:
//! profiles name them, and `--json` output reports them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::reader::{Doc, Node};

/// The kind of value a check parameter takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// `true` or `false`.
    Bool,
    /// A list of strings, each one of these.
    Choices(&'static [&'static str]),
}

/// A parameter's default, used when a profile leaves it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamDefault {
    /// A boolean default.
    Bool(bool),
    /// A list default (sorted, without duplicates; empty means "any" where the check says so).
    List(&'static [&'static str]),
}

impl ParamDefault {
    /// The default as a [`ParamValue`].
    pub fn value(self) -> ParamValue {
        match self {
            ParamDefault::Bool(b) => ParamValue::Bool(b),
            ParamDefault::List(items) => {
                let mut items: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
                items.sort();
                items.dedup();
                ParamValue::List(items)
            }
        }
    }
}

/// One parameter a check accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamDef {
    /// The parameter name, as written under `params:` in a profile.
    pub name: &'static str,
    /// Its type.
    pub kind: ParamKind,
    /// Its value when not given. The check functions read it from here, so there is one
    /// source of truth.
    pub default: ParamDefault,
    /// What it does, and its default.
    pub description: &'static str,
}

/// A parameter value, as loaded from a profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamValue {
    /// A boolean.
    Bool(bool),
    /// A list of strings, sorted and without duplicates.
    List(Vec<String>),
}

/// A check's parameters, as given by a profile. Names and types are checked when the profile
/// is loaded; a parameter that is not given takes the check's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Params(pub(crate) BTreeMap<String, ParamValue>);

impl Params {
    /// No parameters: every check's defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a parameter (no validation; profiles validate when they load).
    pub fn with(mut self, name: &str, value: ParamValue) -> Self {
        let value = match value {
            ParamValue::List(mut items) => {
                items.sort();
                items.dedup();
                ParamValue::List(items)
            }
            other => other,
        };
        self.0.insert(name.to_owned(), value);
        self
    }

    /// These parameters with every value equal to `check`'s default removed, so an explicit
    /// default and an omitted parameter compare (and group) equal.
    pub fn normalized(&self, check: &CheckDef) -> Params {
        Params(
            self.0
                .iter()
                .filter(|(name, value)| {
                    check
                        .params
                        .iter()
                        .find(|p| p.name == name.as_str())
                        .is_none_or(|p| p.default.value() != **value)
                })
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
        )
    }

    fn bool(&self, def: &ParamDef) -> bool {
        match (self.0.get(def.name), def.default) {
            (Some(ParamValue::Bool(b)), _) => *b,
            (_, ParamDefault::Bool(b)) => b,
            _ => false,
        }
    }

    fn strings(&self, def: &ParamDef) -> Vec<String> {
        match self.0.get(def.name) {
            Some(ParamValue::List(items)) => items.clone(),
            _ => match def.default.value() {
                ParamValue::List(items) => items,
                ParamValue::Bool(_) => Vec::new(),
            },
        }
    }
}

/// Where a failure is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum At {
    /// At a JSON pointer outside any component (document-level).
    Document(String),
    /// At a component (index into [`Doc::nodes`]).
    Node(usize),
}

/// One failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    pub at: At,
    /// What is wrong, without naming the component (the report adds that).
    pub problem: String,
    /// How to fix it.
    pub fix: String,
    /// Reported as a warning even if the profile gives the check error severity.
    pub warning_only: bool,
}

fn fail(at: At, problem: impl Into<String>, fix: impl Into<String>) -> Failure {
    Failure {
        at,
        problem: problem.into(),
        fix: fix.into(),
        warning_only: false,
    }
}

/// A check in the catalogue.
#[derive(Clone, Copy)]
pub struct CheckDef {
    /// The stable check id, e.g. `component.hash`.
    pub id: &'static str,
    /// What the check requires, one sentence.
    pub description: &'static str,
    /// The parameters it accepts.
    pub params: &'static [ParamDef],
    pub(crate) run: fn(&Doc, &Params) -> Vec<Failure>,
}

impl std::fmt::Debug for CheckDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckDef")
            .field("id", &self.id)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

const INCLUDE_ROOT: ParamDef = ParamDef {
    name: "include_root",
    kind: ParamKind::Bool,
    default: ParamDefault::Bool(true),
    description: "also check metadata.component (default true)",
};
const AUTHOR_ACCEPT: ParamDef = ParamDef {
    name: "accept",
    kind: ParamKind::Choices(AUTHOR_SOURCES),
    default: ParamDefault::List(AUTHOR_SOURCES),
    description: "which of authors, tools, manufacturer satisfy the check (default all three)",
};
const SUPPLIER_ACCEPT: ParamDef = ParamDef {
    name: "accept",
    kind: ParamKind::Choices(SUPPLIER_FIELDS),
    default: ParamDefault::List(&["supplier"]),
    description: "which of supplier (supplier.name), manufacturer (manufacturer.name), \
                  authors (authors[].name or email) and publisher satisfy the check \
                  (default supplier)",
};
const IDENTIFIER_FIELDS_PARAM: ParamDef = ParamDef {
    name: "fields",
    kind: ParamKind::Choices(IDENTIFIER_FIELDS),
    default: ParamDefault::List(&["cpe", "purl"]),
    description: "which identifiers count: purl, cpe, swid, omniborId, swhid (default purl, cpe)",
};
const HASH_ALGORITHMS_PARAM: ParamDef = ParamDef {
    name: "algorithms",
    kind: ParamKind::Choices(HASH_ALGORITHMS),
    default: ParamDefault::List(&[]),
    description: "the CycloneDX hash algorithms that count (default: any)",
};
const NESTING_IS_DEPENDENCY: ParamDef = ParamDef {
    name: "nesting_is_dependency",
    kind: ParamKind::Bool,
    default: ParamDefault::Bool(true),
    description: "a nested components[] entry counts as an edge from its parent (default true)",
};

/// The author sources `document.author` can accept.
pub const AUTHOR_SOURCES: &[&str] = &["authors", "manufacturer", "tools"];
/// The supplier fields `component.supplier` can accept.
pub const SUPPLIER_FIELDS: &[&str] = &["authors", "manufacturer", "publisher", "supplier"];
/// The identifier fields `component.identifier` can accept.
pub const IDENTIFIER_FIELDS: &[&str] = &["cpe", "omniborId", "purl", "swhid", "swid"];
/// CycloneDX 1.6 hash algorithm names (`hash-alg`).
pub const HASH_ALGORITHMS: &[&str] = &[
    "BLAKE2b-256",
    "BLAKE2b-384",
    "BLAKE2b-512",
    "BLAKE3",
    "MD5",
    "SHA-1",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "Streebog-256",
    "Streebog-512",
];
/// The `rollcall:image-kind` values that mark a top-level component as an image.
pub const IMAGE_KINDS: &[&str] = &["application", "blob", "bootloader"];

/// Every check, in a fixed order (document, component, graph, image).
pub const CHECKS: &[CheckDef] = &[
    CheckDef {
        id: "document.timestamp",
        description: "metadata.timestamp is present and an RFC 3339 date-time",
        params: &[],
        run: document_timestamp,
    },
    CheckDef {
        id: "document.author",
        description: "the document names who produced it: metadata.authors, metadata.tools or \
                      metadata.manufacturer (as accepted)",
        params: &[AUTHOR_ACCEPT],
        run: document_author,
    },
    CheckDef {
        id: "document.root",
        description: "metadata.component (the component the SBOM describes) is present with a bom-ref",
        params: &[],
        run: document_root,
    },
    CheckDef {
        id: "component.name",
        description: "every component has a non-empty name",
        params: &[INCLUDE_ROOT],
        run: component_name,
    },
    CheckDef {
        id: "component.version",
        description: "every component has a non-empty version",
        params: &[INCLUDE_ROOT],
        run: component_version,
    },
    CheckDef {
        id: "component.supplier",
        description: "every component names its supplier (supplier.name, or manufacturer.name \
                      when accepted)",
        params: &[SUPPLIER_ACCEPT, INCLUDE_ROOT],
        run: component_supplier,
    },
    CheckDef {
        id: "component.identifier",
        description: "every component has a unique identifier (purl or cpe by default)",
        params: &[IDENTIFIER_FIELDS_PARAM, INCLUDE_ROOT],
        run: component_identifier,
    },
    CheckDef {
        id: "component.hash",
        description: "every component has at least one hash with an accepted algorithm",
        params: &[HASH_ALGORITHMS_PARAM, INCLUDE_ROOT],
        run: component_hash,
    },
    CheckDef {
        id: "graph.refs-resolve",
        description: "every dependencies[].ref and dependsOn entry names the bom-ref of a \
                      component or service in the document, and no bom-ref is used twice",
        params: &[],
        run: graph_refs_resolve,
    },
    CheckDef {
        id: "graph.reachable",
        description: "every component is reachable from the root through the dependency graph \
                      (edges may pass through services; services need not be reachable)",
        params: &[NESTING_IS_DEPENDENCY],
        run: graph_reachable,
    },
    CheckDef {
        id: "graph.top-level-complete",
        description: "the root's dependencies entry lists every top-level component",
        params: &[],
        run: graph_top_level_complete,
    },
    CheckDef {
        id: "image.represented",
        description: "the SBOM has top-level components and each is a firmware image (type \
                      firmware or a rollcall:image-kind property); a top-level component that \
                      is neither is a warning",
        params: &[],
        run: image_represented,
    },
];

/// The check with this id.
pub fn check(id: &str) -> Option<&'static CheckDef> {
    CHECKS.iter().find(|c| c.id == id)
}

fn document_timestamp(doc: &Doc, _: &Params) -> Vec<Failure> {
    const FIX: &str = "set metadata.timestamp to the RFC 3339 date-time the SBOM was produced, \
                       e.g. 2026-01-02T03:04:05Z";
    let at = || At::Document("/metadata/timestamp".to_owned());
    match doc.metadata.timestamp.as_deref() {
        None => vec![fail(at(), "metadata.timestamp is missing", FIX)],
        Some(t) if OffsetDateTime::parse(t, &Rfc3339).is_err() => vec![fail(
            at(),
            format!("metadata.timestamp {t:?} is not an RFC 3339 date-time"),
            FIX,
        )],
        Some(_) => Vec::new(),
    }
}

fn document_author(doc: &Doc, params: &Params) -> Vec<Failure> {
    let accept = params.strings(&AUTHOR_ACCEPT);
    let m = &doc.metadata;
    let found = accept.iter().any(|a| match a.as_str() {
        "authors" => m.has_authors,
        "tools" => m.has_tools,
        "manufacturer" => m.has_manufacturer,
        _ => false,
    });
    if found {
        return Vec::new();
    }
    let fields: Vec<String> = accept.iter().map(|a| format!("metadata.{a}")).collect();
    vec![fail(
        At::Document("/metadata".to_owned()),
        format!("no SBOM author: none of {} is present", fields.join(", ")),
        format!(
            "name the entity that produced the SBOM in {}",
            fields.join(" or ")
        ),
    )]
}

fn document_root(doc: &Doc, _: &Params) -> Vec<Failure> {
    match doc.root {
        None => vec![fail(
            At::Document("/metadata/component".to_owned()),
            "the document has no metadata.component (the component the SBOM describes)",
            "add metadata.component describing the product, with a bom-ref",
        )],
        Some(i) if doc.nodes.get(i).is_some_and(|n| n.bom_ref.is_none()) => vec![fail(
            At::Node(i),
            "metadata.component has no bom-ref, so the dependency graph cannot start from it",
            "give metadata.component a bom-ref",
        )],
        Some(_) => Vec::new(),
    }
}

/// Runs `test` on every node (the root only when `include_root`), failing those it rejects.
fn each_node(
    doc: &Doc,
    params: &Params,
    mut test: impl FnMut(&Node) -> Option<(String, String)>,
) -> Vec<Failure> {
    let include_root = params.bool(&INCLUDE_ROOT);
    doc.nodes
        .iter()
        .enumerate()
        .filter(|(i, _)| include_root || Some(*i) != doc.root)
        .filter_map(|(i, node)| test(node).map(|(problem, fix)| fail(At::Node(i), problem, fix)))
        .collect()
}

fn component_name(doc: &Doc, params: &Params) -> Vec<Failure> {
    each_node(doc, params, |n| {
        n.name.is_none().then(|| {
            (
                "no name".to_owned(),
                "set name to the name its supplier gives the component".to_owned(),
            )
        })
    })
}

fn component_version(doc: &Doc, params: &Params) -> Vec<Failure> {
    each_node(doc, params, |n| {
        n.version.is_none().then(|| {
            (
                "no version".to_owned(),
                "set version to the identifier its supplier uses for this release of the \
                 component"
                    .to_owned(),
            )
        })
    })
}

fn component_supplier(doc: &Doc, params: &Params) -> Vec<Failure> {
    let accept = params.strings(&SUPPLIER_ACCEPT);
    let fields: Vec<&str> = accept
        .iter()
        .map(|a| match a.as_str() {
            "authors" => "authors[].name",
            "manufacturer" => "manufacturer.name",
            "publisher" => "publisher",
            _ => "supplier.name",
        })
        .collect();
    each_node(doc, params, |n| {
        let ok = accept.iter().any(|a| match a.as_str() {
            "authors" => n.has_authors,
            "manufacturer" => n.manufacturer.is_some(),
            "publisher" => n.publisher.is_some(),
            "supplier" => n.supplier.is_some(),
            _ => false,
        });
        (!ok).then(|| {
            (
                format!("no supplier ({} missing)", fields.join(" and ")),
                format!(
                    "set {} to the organisation that supplies this component",
                    fields.join(" or ")
                ),
            )
        })
    })
}

fn component_identifier(doc: &Doc, params: &Params) -> Vec<Failure> {
    let fields = params.strings(&IDENTIFIER_FIELDS_PARAM);
    each_node(doc, params, |n| {
        let ok = fields
            .iter()
            .any(|f| n.identifiers.contains_key(f.as_str()));
        (!ok).then(|| {
            (
                format!("no unique identifier ({} missing)", fields.join(", ")),
                format!(
                    "add one of {} identifying this component (for Zephyr modules, \
                     rollcall generate --identifier-db supplies purl and cpe)",
                    fields.join(", ")
                ),
            )
        })
    })
}

fn component_hash(doc: &Doc, params: &Params) -> Vec<Failure> {
    let algorithms = params.strings(&HASH_ALGORITHMS_PARAM);
    let accepted = |alg: &str| algorithms.is_empty() || algorithms.iter().any(|a| a == alg);
    let wanted = if algorithms.is_empty() {
        "a".to_owned()
    } else {
        format!("a {}", algorithms.join(" or "))
    };
    each_node(doc, params, |n| {
        if n.hashes.iter().any(|(alg, _)| accepted(alg)) {
            return None;
        }
        let problem = if n.hashes.is_empty() {
            "no hash".to_owned()
        } else {
            let have: BTreeSet<&str> = n.hashes.iter().map(|(a, _)| a.as_str()).collect();
            format!(
                "no hash with an accepted algorithm (has {}; accepted: {})",
                have.into_iter().collect::<Vec<_>>().join(", "),
                algorithms.join(", ")
            )
        };
        Some((
            problem,
            format!("add hashes[] with {wanted} digest of the component's deliverable file"),
        ))
    })
}

fn graph_refs_resolve(doc: &Doc, _: &Params) -> Vec<Failure> {
    const FIX: &str = "make every dependencies[].ref and dependsOn entry the bom-ref of a \
                       component or service in this document";
    let index = doc.index_of();
    let mut failures = Vec::new();
    // Components, then services: the same order as the `index_of` indices.
    let holders = doc
        .nodes
        .iter()
        .map(|n| n.bom_ref.as_deref())
        .chain(doc.services.iter().map(|s| s.bom_ref.as_deref()));
    for (i, r) in holders.enumerate() {
        if let Some(r) = r
            && let Some(&first) = index.get(r).filter(|&&first| first != i)
        {
            let at = if i < doc.nodes.len() {
                At::Node(i)
            } else {
                At::Document(doc.pointer_of(i).to_owned())
            };
            failures.push(fail(
                at,
                format!("bom-ref {r:?} is also used by {}", doc.pointer_of(first)),
                "give every component and service its own bom-ref",
            ));
        }
    }
    for pointer in &doc.malformed_dependencies {
        failures.push(fail(
            At::Document(pointer.clone()),
            "dependencies entry is not an object",
            FIX,
        ));
    }
    for entry in &doc.declared {
        match entry.r#ref.as_deref() {
            None => failures.push(fail(
                At::Document(format!("{}/ref", entry.pointer)),
                "dependencies entry has no ref",
                FIX,
            )),
            Some(r) if !index.contains_key(r) => failures.push(fail(
                At::Document(format!("{}/ref", entry.pointer)),
                format!("ref {r:?} names no component"),
                FIX,
            )),
            Some(_) => {}
        }
        for (j, target) in entry.depends_on.iter().enumerate() {
            let at = || At::Document(format!("{}/dependsOn/{j}", entry.pointer));
            match target.as_deref() {
                None => failures.push(fail(at(), "dependsOn entry is not a string", FIX)),
                Some(t) if !index.contains_key(t) => {
                    failures.push(fail(
                        at(),
                        format!("dependsOn {t:?} names no component"),
                        FIX,
                    ));
                }
                Some(_) => {}
            }
        }
    }
    failures
}

fn no_root() -> Failure {
    fail(
        At::Document("/metadata/component".to_owned()),
        "the document has no metadata.component, so the dependency graph has no root",
        "add metadata.component describing the product, with a bom-ref",
    )
}

fn graph_reachable(doc: &Doc, params: &Params) -> Vec<Failure> {
    let Some(root) = doc.root else {
        return vec![no_root()];
    };
    let nesting = params.bool(&NESTING_IS_DEPENDENCY);
    let index = doc.index_of();
    let mut edges: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for entry in &doc.declared {
        let Some(&from) = entry.r#ref.as_deref().and_then(|r| index.get(r)) else {
            continue;
        };
        for target in entry.depends_on.iter().flatten() {
            if let Some(&to) = index.get(target.as_str()) {
                edges.entry(from).or_default().insert(to);
            }
        }
    }
    if nesting {
        for (i, node) in doc.nodes.iter().enumerate() {
            if let Some(parent) = node.parent {
                edges.entry(parent).or_default().insert(i);
            }
        }
    }
    let mut seen = BTreeSet::from([root]);
    let mut queue = VecDeque::from([root]);
    while let Some(at) = queue.pop_front() {
        for &next in edges.get(&at).into_iter().flatten() {
            if seen.insert(next) {
                queue.push_back(next);
            }
        }
    }
    let root_label = doc.root_node().map_or("", Node::label);
    let via = if nesting {
        "dependencies or nesting"
    } else {
        "dependencies"
    };
    doc.nodes
        .iter()
        .enumerate()
        .filter(|(i, _)| !seen.contains(i))
        .map(|(i, node)| {
            fail(
                At::Node(i),
                format!("not reachable from the root {root_label} through {via}"),
                format!(
                    "add {} to the dependsOn of the component that includes it, or to the root's",
                    node.label()
                ),
            )
        })
        .collect()
}

fn graph_top_level_complete(doc: &Doc, _: &Params) -> Vec<Failure> {
    let Some(root) = doc.root else {
        return vec![no_root()];
    };
    let root_ref = doc.root_node().and_then(|n| n.bom_ref.as_deref());
    let mut failures = Vec::new();
    let entries: Vec<_> = doc
        .declared
        .iter()
        .filter(|e| root_ref.is_some() && e.r#ref.as_deref() == root_ref)
        .collect();
    if entries.is_empty() {
        failures.push(fail(
            At::Node(root),
            "the root has no dependencies[] entry, so its top-level dependencies are not listed",
            "add a dependencies entry for the root whose dependsOn lists every top-level component",
        ));
    }
    let listed: BTreeSet<&str> = entries
        .iter()
        .flat_map(|e| e.depends_on.iter().flatten())
        .map(String::as_str)
        .collect();
    for (i, node) in doc.nodes.iter().enumerate().filter(|(_, n)| n.top_level) {
        match node.bom_ref.as_deref() {
            None => failures.push(fail(
                At::Node(i),
                "top-level component has no bom-ref, so the root's dependsOn cannot list it",
                "give the component a bom-ref and add it to the root's dependsOn",
            )),
            Some(r) if !listed.contains(r) => failures.push(fail(
                At::Node(i),
                "top-level component is not listed in the root's dependsOn",
                format!("add {r} to the dependsOn of the root's dependencies entry"),
            )),
            Some(_) => {}
        }
    }
    failures
}

fn image_represented(doc: &Doc, _: &Params) -> Vec<Failure> {
    let top: Vec<(usize, &Node)> = doc
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.top_level)
        .collect();
    if top.is_empty() {
        return vec![fail(
            At::Document("/components".to_owned()),
            "the SBOM lists no top-level component, so it represents no deliverable image",
            "list each firmware image (bootloader, application, blob) as a top-level component",
        )];
    }
    top.into_iter()
        .filter(|(_, n)| {
            n.kind.as_deref() != Some("firmware")
                && !n
                    .property("rollcall:image-kind")
                    .is_some_and(|k| IMAGE_KINDS.contains(&k))
        })
        .map(|(i, n)| Failure {
            warning_only: true,
            ..fail(
                At::Node(i),
                format!(
                    "top-level component of type {} is not marked as a firmware image",
                    n.kind.as_deref().unwrap_or("(none)")
                ),
                "give each image type firmware, or the property rollcall:image-kind = \
                 bootloader, application or blob",
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn run(id: &str, document: &Value, params: &Params) -> Vec<Failure> {
        let def = check(id).unwrap();
        (def.run)(&Doc::from_value(document), params)
    }

    fn run_default(id: &str, document: &Value) -> Vec<Failure> {
        run(id, document, &Params::new())
    }

    /// The labels of the failing nodes (bom-ref, or pointer for document-level failures).
    fn labels(document: &Value, failures: &[Failure]) -> Vec<String> {
        let doc = Doc::from_value(document);
        for f in failures {
            assert!(!f.fix.is_empty() && !f.problem.is_empty(), "{f:?}");
        }
        failures
            .iter()
            .map(|f| match &f.at {
                At::Document(p) => p.clone(),
                At::Node(i) => doc.nodes[*i].label().to_owned(),
            })
            .collect()
    }

    fn list(items: &[&str]) -> ParamValue {
        ParamValue::List(items.iter().map(|s| (*s).to_owned()).collect())
    }

    /// A small document that passes every check with default parameters.
    fn good() -> Value {
        json!({
            "metadata": {
                "timestamp": "2026-01-02T03:04:05Z",
                "authors": [{"name": "Example Devices Ltd"}],
                "tools": {"components": [{"type": "application", "name": "rollcall"}]},
                "component": {"type": "firmware", "bom-ref": "root", "name": "p", "version": "1",
                              "supplier": {"name": "Acme"}, "purl": "pkg:generic/p@1",
                              "hashes": [{"alg": "SHA-256", "content": "aa"}]}
            },
            "components": [{
                "type": "firmware", "bom-ref": "img", "name": "app", "version": "1",
                "supplier": {"name": "Acme"}, "purl": "pkg:generic/app@1",
                "hashes": [{"alg": "SHA-256", "content": "bb"}],
                "properties": [{"name": "rollcall:image-kind", "value": "application"}],
                "components": [{
                    "type": "library", "bom-ref": "lib", "name": "lib", "version": "2",
                    "supplier": {"name": "Lib Org"}, "cpe": "cpe:2.3:a:lib:lib:2:*:*:*:*:*:*:*",
                    "hashes": [{"alg": "SHA-512", "content": "cc"}]
                }]
            }],
            "dependencies": [
                {"ref": "root", "dependsOn": ["img"]},
                {"ref": "img", "dependsOn": ["lib"]},
                {"ref": "lib", "dependsOn": []}
            ]
        })
    }

    #[test]
    fn good_document_passes_every_check() {
        for def in CHECKS {
            assert!(run_default(def.id, &good()).is_empty(), "{}", def.id);
        }
    }

    #[test]
    fn normalized_drops_explicit_defaults() {
        let def = check("component.hash").unwrap();
        let explicit = Params::new()
            .with("include_root", ParamValue::Bool(true))
            .with("algorithms", list(&["SHA-512"]));
        assert_eq!(
            explicit.normalized(def),
            Params::new().with("algorithms", list(&["SHA-512"]))
        );
        let def = check("component.supplier").unwrap();
        assert_eq!(
            Params::new()
                .with("accept", list(&["supplier"]))
                .normalized(def),
            Params::new()
        );
        // Every parameter's default is a value of its own kind.
        for c in CHECKS {
            for p in c.params {
                match (p.kind, p.default) {
                    (ParamKind::Bool, ParamDefault::Bool(_)) => {}
                    (ParamKind::Choices(allowed), ParamDefault::List(items)) => {
                        assert!(items.iter().all(|i| allowed.contains(i)), "{}", c.id);
                    }
                    _ => panic!("{}.{}: default of the wrong kind", c.id, p.name),
                }
            }
        }
    }

    #[test]
    fn every_check_in_catalogue_has_a_unit_test() {
        let source = include_str!("checks.rs");
        for def in CHECKS {
            let name = format!(
                "fn check_{}_passes_and_fails()",
                def.id.replace(['.', '-'], "_")
            );
            assert!(source.contains(&name), "no unit test {name}");
        }
        let ids: BTreeSet<_> = CHECKS.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), CHECKS.len(), "duplicate check id");
    }

    #[test]
    fn check_document_timestamp_passes_and_fails() {
        let id = "document.timestamp";
        assert!(run_default(id, &good()).is_empty());
        let mut doc = good();
        doc["metadata"]["timestamp"] = json!("2026-01-02T03:04:05+02:00");
        assert!(run_default(id, &doc).is_empty());
        for bad in [json!(null), json!("yesterday"), json!(""), json!(5)] {
            let mut doc = good();
            doc["metadata"]["timestamp"] = bad.clone();
            let failures = run_default(id, &doc);
            assert_eq!(labels(&doc, &failures), ["/metadata/timestamp"], "{bad}");
        }
        assert_eq!(run_default(id, &json!({})).len(), 1);
    }

    #[test]
    fn check_document_author_passes_and_fails() {
        let id = "document.author";
        assert!(run_default(id, &good()).is_empty());
        // Tools alone satisfy the default; not when only authors are accepted.
        let mut tools_only = good();
        tools_only["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("authors");
        assert!(run_default(id, &tools_only).is_empty());
        let authors = Params::new().with("accept", list(&["authors"]));
        let failures = run(id, &tools_only, &authors);
        assert_eq!(labels(&tools_only, &failures), ["/metadata"]);
        assert!(failures[0].problem.contains("metadata.authors"));
        // Legacy tools array and manufacturer.
        let legacy = json!({"metadata": {"tools": [{"name": "syft"}]}});
        assert!(run_default(id, &legacy).is_empty());
        let manufacturer = json!({"metadata": {"manufacturer": {"name": "Acme"}}});
        assert!(run_default(id, &manufacturer).is_empty());
        // Empty or wrongly typed entries do not count.
        for bad in [
            json!({"metadata": {"authors": [], "tools": {"components": []}}}),
            json!({"metadata": {"authors": [{"name": ""}], "tools": 3}}),
            json!({"metadata": {"authors": "me", "manufacturer": {"name": 1}}}),
            json!({}),
        ] {
            assert_eq!(run_default(id, &bad).len(), 1, "{bad}");
        }
    }

    #[test]
    fn check_document_root_passes_and_fails() {
        let id = "document.root";
        assert!(run_default(id, &good()).is_empty());
        let mut no_root = good();
        no_root["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("component");
        let failures = run_default(id, &no_root);
        assert_eq!(labels(&no_root, &failures), ["/metadata/component"]);
        let mut no_ref = good();
        no_ref["metadata"]["component"]
            .as_object_mut()
            .unwrap()
            .remove("bom-ref");
        let failures = run_default(id, &no_ref);
        assert_eq!(labels(&no_ref, &failures), ["/metadata/component"]);
        assert!(failures[0].problem.contains("no bom-ref"));
        let mut wrong_type = good();
        wrong_type["metadata"]["component"] = json!("p");
        assert_eq!(run_default(id, &wrong_type).len(), 1);
    }

    /// Removes `field` from the `lib` component of [`good`].
    fn lib_without(field: &str) -> Value {
        let mut doc = good();
        doc["components"][0]["components"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        doc
    }

    fn set_lib(field: &str, value: Value) -> Value {
        let mut doc = good();
        doc["components"][0]["components"][0][field] = value;
        doc
    }

    #[test]
    fn check_component_name_passes_and_fails() {
        let id = "component.name";
        assert!(run_default(id, &good()).is_empty());
        for doc in [
            lib_without("name"),
            set_lib("name", json!("")),
            set_lib("name", json!(3)),
        ] {
            assert_eq!(labels(&doc, &run_default(id, &doc)), ["lib"]);
        }
    }

    #[test]
    fn check_component_version_passes_and_fails() {
        let id = "component.version";
        assert!(run_default(id, &good()).is_empty());
        for doc in [
            lib_without("version"),
            set_lib("version", json!(" ")),
            set_lib("version", json!(2)),
        ] {
            assert_eq!(labels(&doc, &run_default(id, &doc)), ["lib"]);
        }
        // include_root: false skips metadata.component.
        let mut doc = good();
        doc["metadata"]["component"]
            .as_object_mut()
            .unwrap()
            .remove("version");
        assert_eq!(labels(&doc, &run_default(id, &doc)), ["root"]);
        let params = Params::new().with("include_root", ParamValue::Bool(false));
        assert!(run(id, &doc, &params).is_empty());
    }

    #[test]
    fn check_component_supplier_passes_and_fails() {
        let id = "component.supplier";
        assert!(run_default(id, &good()).is_empty());
        for doc in [
            lib_without("supplier"),
            set_lib("supplier", json!({"name": ""})),
            set_lib("supplier", json!("Lib Org")),
            set_lib("supplier", json!({"url": ["https://lib.example"]})),
        ] {
            let failures = run_default(id, &doc);
            assert_eq!(labels(&doc, &failures), ["lib"]);
            assert!(failures[0].fix.contains("supplier.name"));
        }
        // manufacturer counts only when accepted.
        let mut doc = lib_without("supplier");
        doc["components"][0]["components"][0]["manufacturer"] = json!({"name": "Lib Org"});
        assert_eq!(run_default(id, &doc).len(), 1);
        let params = Params::new().with("accept", list(&["supplier", "manufacturer"]));
        assert!(run(id, &doc, &params).is_empty());
        // authors and publisher are opt-in choices, off by default.
        for (field, value) in [
            ("authors", json!([{"name": "Lib Org"}])),
            ("publisher", json!("Lib Org")),
        ] {
            let mut doc = lib_without("supplier");
            doc["components"][0]["components"][0][field] = value;
            assert_eq!(run_default(id, &doc).len(), 1, "{field}");
            // Only lib carries the field, so only lib passes with accept: [field].
            let params = Params::new().with("accept", list(&[field]));
            assert_eq!(
                labels(&doc, &run(id, &doc, &params)),
                ["root", "img"],
                "{field}"
            );
            let bare = lib_without("supplier");
            let failures = run(id, &bare, &params);
            assert_eq!(labels(&bare, &failures), ["root", "img", "lib"], "{field}");
            let label = if field == "authors" {
                "authors[].name"
            } else {
                "publisher"
            };
            assert!(failures[2].fix.contains(label), "{:?}", failures[2]);
        }
    }

    #[test]
    fn check_component_identifier_passes_and_fails() {
        let id = "component.identifier";
        assert!(run_default(id, &good()).is_empty());
        for doc in [
            lib_without("cpe"),
            set_lib("cpe", json!("")),
            set_lib("cpe", json!(["cpe:2.3:a:lib:lib:2"])),
        ] {
            assert_eq!(labels(&doc, &run_default(id, &doc)), ["lib"]);
        }
        // An OmniBOR id counts only when accepted.
        let mut doc = lib_without("cpe");
        doc["components"][0]["components"][0]["omniborId"] = json!(["gitoid:blob:sha1:00"]);
        assert_eq!(run_default(id, &doc).len(), 1);
        let params = Params::new().with("fields", list(&["purl", "cpe", "omniborId"]));
        assert!(run(id, &doc, &params).is_empty());
    }

    #[test]
    fn check_component_hash_passes_and_fails() {
        let id = "component.hash";
        assert!(run_default(id, &good()).is_empty());
        for doc in [
            lib_without("hashes"),
            set_lib("hashes", json!([])),
            set_lib("hashes", json!({"alg": "SHA-512", "content": "cc"})),
            set_lib("hashes", json!([{"alg": "SHA-512"}])),
        ] {
            let failures = run_default(id, &doc);
            assert_eq!(labels(&doc, &failures), ["lib"]);
            assert_eq!(failures[0].problem, "no hash");
        }
        // The algorithms parameter: SHA-1 alone is not accepted.
        let doc = set_lib("hashes", json!([{"alg": "SHA-1", "content": "dd"}]));
        assert!(run_default(id, &doc).is_empty());
        let params = Params::new().with("algorithms", list(&["SHA-256", "SHA-512"]));
        let failures = run(id, &doc, &params);
        assert_eq!(labels(&doc, &failures), ["lib"]);
        assert!(failures[0].problem.contains("has SHA-1"), "{failures:?}");
        assert!(run(id, &good(), &params).is_empty());
    }

    #[test]
    fn check_graph_refs_resolve_passes_and_fails() {
        let id = "graph.refs-resolve";
        assert!(run_default(id, &good()).is_empty());
        let mut doc = good();
        doc["dependencies"] = json!([
            {"ref": "ghost", "dependsOn": ["img", "nowhere", 4]},
            {"dependsOn": []},
            "img"
        ]);
        let failures = run_default(id, &doc);
        assert_eq!(
            labels(&doc, &failures),
            [
                "/dependencies/2",
                "/dependencies/0/ref",
                "/dependencies/0/dependsOn/1",
                "/dependencies/0/dependsOn/2",
                "/dependencies/1/ref"
            ]
        );
        // A duplicated bom-ref is reported on its second use (and the edges naming the old
        // ref "lib" no longer resolve).
        let doc = set_lib("bom-ref", json!("img"));
        let failures = run_default(id, &doc);
        assert_eq!(
            labels(&doc, &failures),
            ["img", "/dependencies/1/dependsOn/0", "/dependencies/2/ref"]
        );
        assert_eq!(failures[0].at, At::Node(2));
        assert!(failures[0].problem.contains("/components/0"));
    }

    #[test]
    fn services_are_dependency_targets_but_need_not_be_reachable() {
        let mut doc = good();
        doc["services"] = json!([{"bom-ref": "svc", "name": "ota",
                                  "services": [{"bom-ref": "svc-inner", "name": "inner"}]},
                                 {"bom-ref": "lonely", "name": "unused"}]);
        doc["dependencies"]
            .as_array_mut()
            .unwrap()
            .push(json!({"ref": "svc", "dependsOn": ["svc-inner"]}));
        doc["dependencies"][0]["dependsOn"] = json!(["img", "svc"]);
        for id in [
            "graph.refs-resolve",
            "graph.reachable",
            "graph.top-level-complete",
        ] {
            assert!(run_default(id, &doc).is_empty(), "{id}");
        }
        // A component reachable only through a service is reachable.
        doc["dependencies"] = json!([
            {"ref": "root", "dependsOn": ["svc"]},
            {"ref": "svc", "dependsOn": ["img"]}
        ]);
        assert!(run_default("graph.reachable", &doc).is_empty());
        // A dangling ref still fails; a service reusing a component's bom-ref is a duplicate.
        doc["dependencies"][1]["dependsOn"] = json!(["img", "ghost"]);
        doc["services"][1]["bom-ref"] = json!("lib");
        let failures = run_default("graph.refs-resolve", &doc);
        assert_eq!(
            labels(&doc, &failures),
            ["/services/1", "/dependencies/1/dependsOn/1"]
        );
        assert!(failures[0].problem.contains("/components/0/components/0"));
    }

    #[test]
    fn check_graph_reachable_passes_and_fails() {
        let id = "graph.reachable";
        assert!(run_default(id, &good()).is_empty());
        // An orphan top-level component.
        let mut doc = good();
        doc["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "library", "bom-ref": "orphan", "name": "orphan"}));
        let failures = run_default(id, &doc);
        assert_eq!(labels(&doc, &failures), ["orphan"]);
        assert!(failures[0].fix.contains("orphan"));
        // A nested component with no edge: reachable through nesting by default only.
        let mut doc = good();
        doc["dependencies"] = json!([{"ref": "root", "dependsOn": ["img"]}]);
        assert!(run_default(id, &doc).is_empty());
        let no_nesting = Params::new().with("nesting_is_dependency", ParamValue::Bool(false));
        assert_eq!(labels(&doc, &run(id, &doc, &no_nesting)), ["lib"]);
        // Reachable only through a dangling ref: still an orphan.
        let mut doc = good();
        doc["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"bom-ref": "far", "name": "far"}));
        doc["dependencies"] = json!([
            {"ref": "root", "dependsOn": ["img", "ghost"]},
            {"ref": "ghost", "dependsOn": ["far"]}
        ]);
        assert_eq!(labels(&doc, &run_default(id, &doc)), ["far"]);
        // A component without a bom-ref is reported by its pointer.
        let mut doc = good();
        doc["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "anon"}));
        assert_eq!(labels(&doc, &run_default(id, &doc)), ["/components/1"]);
        // No root at all.
        let failures = run_default(id, &json!({"components": [{"name": "x"}]}));
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].at, At::Document("/metadata/component".into()));
    }

    #[test]
    fn check_graph_top_level_complete_passes_and_fails() {
        let id = "graph.top-level-complete";
        assert!(run_default(id, &good()).is_empty());
        // A second top-level component not listed by the root.
        let mut doc = good();
        doc["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "firmware", "bom-ref": "boot", "name": "boot"}));
        let failures = run_default(id, &doc);
        assert_eq!(labels(&doc, &failures), ["boot"]);
        assert!(failures[0].fix.contains("boot"));
        // No root entry at all: the root and every top-level component are reported.
        let mut doc = good();
        doc["dependencies"] = json!([{"ref": "img", "dependsOn": ["lib"]}]);
        assert_eq!(labels(&doc, &run_default(id, &doc)), ["root", "img"]);
        // A top-level component without a bom-ref.
        let mut doc = good();
        doc["components"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "anon"}));
        assert_eq!(labels(&doc, &run_default(id, &doc)), ["/components/1"]);
        assert_eq!(run_default(id, &json!({})).len(), 1);
    }

    #[test]
    fn check_image_represented_passes_and_fails() {
        let id = "image.represented";
        assert!(run_default(id, &good()).is_empty());
        // A blob image typed library still counts through its image-kind property.
        let mut doc = good();
        doc["components"][0]["type"] = json!("library");
        assert!(run_default(id, &doc).is_empty());
        // Neither firmware nor image-kind: a warning, not an error.
        doc["components"][0]["properties"] = json!([{"name": "rollcall:image-kind", "value": "x"}]);
        let failures = run_default(id, &doc);
        assert_eq!(labels(&doc, &failures), ["img"]);
        assert!(failures[0].warning_only);
        // No top-level component at all: an error.
        for bad in [
            json!({"components": []}),
            json!({"components": 3}),
            json!({}),
        ] {
            let failures = run_default(id, &bad);
            assert_eq!(labels(&bad, &failures), ["/components"], "{bad}");
            assert!(!failures[0].warning_only);
        }
    }
}
