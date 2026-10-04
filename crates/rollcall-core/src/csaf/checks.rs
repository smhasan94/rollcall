//! The CSAF 2.0 mandatory tests (§6.1) a rollcall export could break and the JSON schema
//! cannot catch: 6.1.1, 6.1.2, 6.1.6, 6.1.23, 6.1.33 and, for `csaf_vex` documents, the VEX
//! profile tests 6.1.27.4, .5, .7, .8, .9, .10 and .11.
//!
//! The full mandatory test suite is run in CI by the official validator library
//! (`scripts/csaf-check.sh`); these checks make `rollcall csaf` refuse to write a document
//! that would fail the ones rollcall's own mapping is responsible for. They read any JSON
//! value and never panic: a part with an unexpected shape is skipped (the schema reports it).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::cyclonedx::SchemaViolation;

fn violation(path: impl Into<String>, test: &str, message: impl Into<String>) -> SchemaViolation {
    SchemaViolation {
        path: path.into(),
        message: format!("CSAF {test}: {}", message.into()),
    }
}

fn array(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn strings(value: Option<&Value>) -> impl Iterator<Item = (usize, &str)> {
    array(value)
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.as_str().map(|s| (i, s)))
}

/// Every `product_id` definition: (id, JSON pointer).
fn definitions(tree: &Map<String, Value>) -> Vec<(String, String)> {
    fn branches(items: &[Value], path: &str, depth: usize, out: &mut Vec<(String, String)>) {
        if depth > 64 {
            return;
        }
        for (i, b) in items.iter().enumerate() {
            let bpath = format!("{path}/{i}");
            if let Some(id) = b
                .get("product")
                .and_then(|p| p.get("product_id"))
                .and_then(Value::as_str)
            {
                out.push((id.to_owned(), format!("{bpath}/product/product_id")));
            }
            branches(
                array(b.get("branches")),
                &format!("{bpath}/branches"),
                depth + 1,
                out,
            );
        }
    }
    let mut out = Vec::new();
    branches(
        array(tree.get("branches")),
        "/product_tree/branches",
        0,
        &mut out,
    );
    for (i, f) in array(tree.get("full_product_names")).iter().enumerate() {
        if let Some(id) = f.get("product_id").and_then(Value::as_str) {
            out.push((
                id.to_owned(),
                format!("/product_tree/full_product_names/{i}/product_id"),
            ));
        }
    }
    for (i, r) in array(tree.get("relationships")).iter().enumerate() {
        if let Some(id) = r
            .get("full_product_name")
            .and_then(|f| f.get("product_id"))
            .and_then(Value::as_str)
        {
            out.push((
                id.to_owned(),
                format!("/product_tree/relationships/{i}/full_product_name/product_id"),
            ));
        }
    }
    out
}

const STATUS_LISTS: [&str; 8] = [
    "first_affected",
    "first_fixed",
    "fixed",
    "known_affected",
    "known_not_affected",
    "last_affected",
    "recommended",
    "under_investigation",
];

/// Every product reference: (id, JSON pointer).
fn references(document: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut push = |items: Option<&Value>, path: String| {
        for (i, id) in strings(items) {
            out.push((id.to_owned(), format!("{path}/{i}")));
        }
    };
    let tree = document.get("product_tree");
    for (i, g) in array(tree.and_then(|t| t.get("product_groups")))
        .iter()
        .enumerate()
    {
        push(
            g.get("product_ids"),
            format!("/product_tree/product_groups/{i}/product_ids"),
        );
    }
    for (i, r) in array(tree.and_then(|t| t.get("relationships")))
        .iter()
        .enumerate()
    {
        for key in ["product_reference", "relates_to_product_reference"] {
            if let Some(id) = r.get(key).and_then(Value::as_str) {
                out.push((
                    id.to_owned(),
                    format!("/product_tree/relationships/{i}/{key}"),
                ));
            }
        }
    }
    let mut push = |items: Option<&Value>, path: String| {
        for (i, id) in strings(items) {
            out.push((id.to_owned(), format!("{path}/{i}")));
        }
    };
    for (v, vuln) in array(document.get("vulnerabilities")).iter().enumerate() {
        let vpath = format!("/vulnerabilities/{v}");
        for list in STATUS_LISTS {
            push(
                vuln.get("product_status").and_then(|s| s.get(list)),
                format!("{vpath}/product_status/{list}"),
            );
        }
        for (key, field) in [
            ("flags", "product_ids"),
            ("threats", "product_ids"),
            ("remediations", "product_ids"),
            ("scores", "products"),
        ] {
            for (i, item) in array(vuln.get(key)).iter().enumerate() {
                push(item.get(field), format!("{vpath}/{key}/{i}/{field}"));
            }
        }
    }
    out
}

/// The product ids an item (`flags[]`, `threats[]`, `remediations[]`) is about: its
/// `product_ids` and the members of its `group_ids`.
fn about(item: &Value, groups: &BTreeMap<&str, BTreeSet<&str>>) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = strings(item.get("product_ids"))
        .map(|(_, s)| s.to_owned())
        .collect();
    for (_, g) in strings(item.get("group_ids")) {
        if let Some(members) = groups.get(g) {
            out.extend(members.iter().map(|m| (*m).to_owned()));
        }
    }
    out
}

/// Runs the CSAF 2.0 mandatory tests listed in the [`csaf`](super) module docs: 6.1.1, 6.1.2,
/// 6.1.6, 6.1.23, 6.1.33 and, for `csaf_vex`, 6.1.27.4/5/7/8/9/10/11. Returns every failure, sorted by path and
/// then message; an empty list means the document passes them.
pub fn check_mandatory(document: &Value) -> Vec<SchemaViolation> {
    let mut out = Vec::new();
    let tree = document.get("product_tree").and_then(Value::as_object);
    let defined = tree.map(definitions).unwrap_or_default();

    // 6.1.2 Multiple Definition of Product ID.
    let mut first: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, path) in &defined {
        if let Some(earlier) = first.insert(id.as_str(), path.as_str()) {
            out.push(violation(
                path.clone(),
                "6.1.2",
                format!("product id {id:?} is already defined at {earlier}"),
            ));
        }
    }

    // 6.1.1 Missing Definition of Product ID.
    let ids: BTreeSet<&str> = defined.iter().map(|(id, _)| id.as_str()).collect();
    for (id, path) in references(document) {
        if !ids.contains(id.as_str()) {
            out.push(violation(
                path,
                "6.1.1",
                format!("product id {id:?} is not defined in the product tree"),
            ));
        }
    }

    let groups: BTreeMap<&str, BTreeSet<&str>> = array(tree.and_then(|t| t.get("product_groups")))
        .iter()
        .filter_map(|g| {
            let id = g.get("group_id").and_then(Value::as_str)?;
            Some((id, strings(g.get("product_ids")).map(|(_, s)| s).collect()))
        })
        .collect();
    let vex = document
        .get("document")
        .and_then(|d| d.get("category"))
        .and_then(Value::as_str)
        == Some("csaf_vex");

    // 6.1.27.4 Product Tree, 6.1.27.11 Vulnerabilities.
    if vex && tree.is_none() {
        out.push(violation(
            "/product_tree",
            "6.1.27.4",
            "a csaf_vex document needs a product_tree",
        ));
    }
    let vulnerabilities = array(document.get("vulnerabilities"));
    if vex && vulnerabilities.is_empty() {
        out.push(violation(
            "/vulnerabilities",
            "6.1.27.11",
            "a csaf_vex document needs vulnerabilities",
        ));
    }

    let mut cves: BTreeMap<&str, usize> = BTreeMap::new();
    for (v, vuln) in vulnerabilities.iter().enumerate() {
        let vpath = format!("/vulnerabilities/{v}");

        // 6.1.23 Multiple Use of Same CVE.
        if let Some(cve) = vuln.get("cve").and_then(Value::as_str)
            && let Some(earlier) = cves.insert(cve, v)
        {
            out.push(violation(
                format!("{vpath}/cve"),
                "6.1.23",
                format!("{cve} is already used by /vulnerabilities/{earlier}"),
            ));
        }

        // 6.1.6 Contradicting Product Status.
        let status = vuln.get("product_status");
        let list = |names: &[&str]| -> BTreeSet<&str> {
            names
                .iter()
                .flat_map(|n| strings(status.and_then(|s| s.get(*n))).map(|(_, id)| id))
                .collect()
        };
        let affected = list(&["first_affected", "known_affected", "last_affected"]);
        let not_affected = list(&["known_not_affected"]);
        let fixed = list(&["first_fixed", "fixed"]);
        let investigating = list(&["under_investigation"]);
        let all: BTreeSet<&str> = affected
            .iter()
            .chain(&not_affected)
            .chain(&fixed)
            .chain(&investigating)
            .copied()
            .collect();
        for id in all {
            let groups_in = [&affected, &not_affected, &fixed, &investigating]
                .iter()
                .filter(|g| g.contains(id))
                .count();
            if groups_in > 1 {
                out.push(violation(
                    format!("{vpath}/product_status"),
                    "6.1.6",
                    format!("product {id:?} is in contradicting status groups"),
                ));
            }
        }

        // 6.1.33 Multiple Flags with VEX Justification Codes per Product.
        let mut flagged: BTreeSet<String> = BTreeSet::new();
        for (i, flag) in array(vuln.get("flags")).iter().enumerate() {
            for id in about(flag, &groups) {
                if !flagged.insert(id.clone()) {
                    out.push(violation(
                        format!("{vpath}/flags/{i}"),
                        "6.1.33",
                        format!("product {id:?} has more than one flag"),
                    ));
                }
            }
        }

        if !vex {
            continue;
        }
        // 6.1.27.5 Vulnerability Notes.
        if array(vuln.get("notes")).is_empty() {
            out.push(violation(
                format!("{vpath}/notes"),
                "6.1.27.5",
                "every vulnerability of a csaf_vex document needs notes",
            ));
        }
        // 6.1.27.7 VEX Product Status.
        let any_status = [
            "fixed",
            "known_affected",
            "known_not_affected",
            "under_investigation",
        ]
        .iter()
        .any(|n| !array(status.and_then(|s| s.get(*n))).is_empty());
        if !any_status {
            out.push(violation(
                format!("{vpath}/product_status"),
                "6.1.27.7",
                "needs fixed, known_affected, known_not_affected or under_investigation",
            ));
        }
        // 6.1.27.8 Vulnerability ID.
        if vuln.get("cve").is_none() && array(vuln.get("ids")).is_empty() {
            out.push(violation(
                vpath.clone(),
                "6.1.27.8",
                "every vulnerability of a csaf_vex document needs a cve or ids",
            ));
        }
        // 6.1.27.9 Impact Statement.
        let mut impact: BTreeSet<String> = BTreeSet::new();
        for flag in array(vuln.get("flags")) {
            impact.extend(about(flag, &groups));
        }
        for threat in array(vuln.get("threats")) {
            if threat.get("category").and_then(Value::as_str) == Some("impact") {
                impact.extend(about(threat, &groups));
            }
        }
        for id in &not_affected {
            if !impact.contains(*id) {
                out.push(violation(
                    format!("{vpath}/product_status/known_not_affected"),
                    "6.1.27.9",
                    format!("product {id:?} has no flag or impact threat"),
                ));
            }
        }
        // 6.1.27.10 Action Statement.
        let mut action: BTreeSet<String> = BTreeSet::new();
        for remediation in array(vuln.get("remediations")) {
            action.extend(about(remediation, &groups));
        }
        for (_, id) in strings(status.and_then(|s| s.get("known_affected"))) {
            if !action.contains(id) {
                out.push(violation(
                    format!("{vpath}/product_status/known_affected"),
                    "6.1.27.10",
                    format!("product {id:?} has no remediation"),
                ));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn good() -> Value {
        json!({
            "document": {"category": "csaf_vex", "csaf_version": "2.0"},
            "product_tree": {
                "branches": [{"category": "vendor", "name": "v", "branches": [
                    {"category": "product_name", "name": "p",
                     "product": {"name": "p", "product_id": "P"}}
                ]}],
                "full_product_names": [
                    {"name": "a", "product_id": "A"},
                    {"name": "b", "product_id": "B"},
                    {"name": "c", "product_id": "C"}
                ],
                "relationships": [{"category": "default_component_of",
                    "full_product_name": {"name": "a in p", "product_id": "A@P"},
                    "product_reference": "A", "relates_to_product_reference": "P"}]
            },
            "vulnerabilities": [{
                "cve": "CVE-2024-0001",
                "notes": [{"category": "summary", "text": "t"}],
                "product_status": {"known_affected": ["A"], "known_not_affected": ["B", "C"],
                                   "under_investigation": ["P"]},
                "flags": [{"label": "vulnerable_code_not_present", "product_ids": ["B"]}],
                "threats": [{"category": "impact", "details": "d", "product_ids": ["C"]}],
                "remediations": [{"category": "vendor_fix", "details": "u", "product_ids": ["A"]}]
            }]
        })
    }

    fn tests_failed(doc: &Value) -> Vec<String> {
        check_mandatory(doc)
            .iter()
            .map(|v| {
                v.message
                    .trim_start_matches("CSAF ")
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_good_vex_document_passes() {
        assert_eq!(check_mandatory(&good()), Vec::new());
    }

    #[test]
    fn each_mandatory_test_catches_its_failure() {
        type Break = Box<dyn Fn(&mut Value)>;
        let cases: Vec<(&str, Break)> = vec![
            (
                "6.1.1",
                Box::new(|d| {
                    d["vulnerabilities"][0]["product_status"]["under_investigation"] = json!(["Z"])
                }),
            ),
            (
                "6.1.1",
                Box::new(|d| {
                    d["product_tree"]["relationships"][0]["relates_to_product_reference"] =
                        json!("Z")
                }),
            ),
            (
                "6.1.2",
                Box::new(|d| d["product_tree"]["full_product_names"][1]["product_id"] = json!("A")),
            ),
            (
                "6.1.2",
                Box::new(|d| {
                    d["product_tree"]["relationships"][0]["full_product_name"]["product_id"] =
                        json!("P")
                }),
            ),
            (
                "6.1.6",
                Box::new(|d| d["vulnerabilities"][0]["product_status"]["fixed"] = json!(["A"])),
            ),
            (
                "6.1.23",
                Box::new(|d| {
                    let copy = d["vulnerabilities"][0].clone();
                    d["vulnerabilities"].as_array_mut().unwrap().push(copy);
                }),
            ),
            (
                "6.1.33",
                Box::new(|d| {
                    d["vulnerabilities"][0]["flags"] = json!([
                {"label": "vulnerable_code_not_present", "product_ids": ["B"]},
                {"label": "component_not_present", "product_ids": ["B"]}])
                }),
            ),
            (
                "6.1.27.4",
                Box::new(|d| {
                    d.as_object_mut().unwrap().remove("product_tree");
                }),
            ),
            (
                "6.1.27.5",
                Box::new(|d| {
                    d["vulnerabilities"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("notes");
                }),
            ),
            (
                "6.1.27.7",
                Box::new(|d| {
                    d["vulnerabilities"][0]["product_status"] = json!({"recommended": ["A"]})
                }),
            ),
            (
                "6.1.27.8",
                Box::new(|d| {
                    d["vulnerabilities"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("cve");
                }),
            ),
            (
                "6.1.27.9",
                Box::new(|d| {
                    d["vulnerabilities"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("threats");
                }),
            ),
            (
                "6.1.27.10",
                Box::new(|d| {
                    d["vulnerabilities"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("remediations");
                }),
            ),
            ("6.1.27.11", Box::new(|d| d["vulnerabilities"] = json!([]))),
        ];
        for (test, break_it) in cases {
            let mut doc = good();
            break_it(&mut doc);
            let failed = tests_failed(&doc);
            assert!(failed.iter().any(|f| f == test), "{test}: {failed:?}");
        }
    }

    #[test]
    fn group_ids_count_for_impact_and_action_statements() {
        let mut doc = good();
        doc["product_tree"]["product_groups"] =
            json!([{"group_id": "G", "product_ids": ["A", "C"]}]);
        doc["vulnerabilities"][0]["threats"] =
            json!([{"category": "impact", "details": "d", "group_ids": ["G"]}]);
        doc["vulnerabilities"][0]["remediations"] =
            json!([{"category": "vendor_fix", "details": "u", "group_ids": ["G"]}]);
        assert_eq!(check_mandatory(&doc), Vec::new());
    }

    #[test]
    fn profile_tests_apply_only_to_csaf_vex() {
        let mut doc = good();
        doc["document"]["category"] = json!("csaf_base");
        doc["vulnerabilities"][0]
            .as_object_mut()
            .unwrap()
            .remove("remediations");
        assert_eq!(check_mandatory(&doc), Vec::new());
    }

    #[test]
    fn any_json_value_is_checked_without_panicking() {
        for doc in [
            json!(null),
            json!([]),
            json!("x"),
            json!({"product_tree": 5, "vulnerabilities": {}}),
            json!({"document": {"category": "csaf_vex"}, "product_tree": {"branches": 1},
                   "vulnerabilities": [1, {"product_status": [], "flags": "x"}]}),
        ] {
            let _ = check_mandatory(&doc);
        }
    }
}
