//! The evaluator: findings × components × rules → statements and unresolved findings. See
//! the [module docs](super) for the semantics.

use std::collections::{BTreeMap, BTreeSet};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use super::evidence::{BuildEvidence, Verdict};
use super::findings::Finding;
use super::pattern::Specificity;
use super::rules::{self, Justification, Rule, RuleSet, Status};
use super::version::effective_version;
use crate::model::{Component, ModelError, NodePath, NodeRef, Product, Purl, to_canonical_json};
use crate::warning::Warning;

/// The `schema` of a [`Report`].
pub const REPORT_SCHEMA: &str = "rollcall-vex/1";

/// The component a statement is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ComponentRef {
    /// Its `bom-ref`: the input document's own when the product was read from one
    /// ([`evaluate_document`]), else rollcall's derived one.
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Its name.
    pub name: String,
    /// Its version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Its purl.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
}

/// The package a scanner reported, as it reported it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Package {
    /// The package name.
    pub name: String,
    /// The package version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The package purl.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<Purl>,
}

/// A VEX statement: one vulnerability's status for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Statement {
    /// The vulnerability id.
    pub vulnerability: String,
    /// Its aliases, from every scanner that reported it.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub aliases: BTreeSet<String>,
    /// The component.
    pub component: ComponentRef,
    /// The status.
    pub status: Status,
    /// The justification (for `not_affected`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<Justification>,
    /// The detail of the first deciding rule (by id) that has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The ids of the deciding rules, sorted.
    pub rules: Vec<String>,
    /// The evidence for their `when` conditions, sorted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// Why a finding got no statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reason {
    /// No rule matches it.
    NoRule,
    /// The reported package is not a component of the SBOM.
    ComponentNotInSbom,
    /// The deciding rules disagree.
    Conflict {
        /// The disagreeing rules, sorted.
        rules: Vec<String>,
    },
    /// A deciding rule's condition could not be evaluated.
    NeedsEvidence {
        /// The rules lacking evidence, sorted.
        rules: Vec<String>,
        /// What is missing, per condition.
        missing: Vec<String>,
    },
}

/// A finding without a statement, with a rule template to fill in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unresolved {
    /// The vulnerability id.
    pub vulnerability: String,
    /// Its aliases.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub aliases: BTreeSet<String>,
    /// The component it was joined to, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<ComponentRef>,
    /// The package as the scanner reported it.
    pub package: Package,
    /// The scanner's severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Versions it is fixed in.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub fixed_in: BTreeSet<String>,
    /// Why there is no statement.
    pub reason: Reason,
    /// A rule to paste under `rules:` and complete (see [`rules::template`]).
    pub template: String,
}

/// The evaluator's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The statements, sorted by vulnerability then component `bom-ref`.
    pub statements: Vec<Statement>,
    /// The unresolved findings, in the same order.
    pub unresolved: Vec<Unresolved>,
    /// Conflicts between rules (one per conflicting finding) and components the input
    /// document gave no `bom-ref`.
    pub warnings: Vec<Warning>,
}

impl Serialize for Report {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct W<'a> {
            location: &'a str,
            message: &'a str,
        }
        let warnings: Vec<W<'_>> = self
            .warnings
            .iter()
            .map(|w| W {
                location: &w.location,
                message: &w.message,
            })
            .collect();
        let mut st = s.serialize_struct("Report", 4)?;
        st.serialize_field("schema", REPORT_SCHEMA)?;
        st.serialize_field("statements", &self.statements)?;
        st.serialize_field("unresolved", &self.unresolved)?;
        st.serialize_field("warnings", &warnings)?;
        st.end()
    }
}

impl Report {
    /// The report as canonical JSON (`rollcall-vex/1`), ending in a newline.
    pub fn to_json(&self) -> Result<String, ModelError> {
        to_canonical_json(self)
    }
}

/// A component of the product with where it sits.
struct Node<'a> {
    /// The `bom-ref` statements cite: the input document's own, when it has one for this
    /// node, else rollcall's derived one.
    bom_ref: String,
    component: &'a Component,
    /// The name of the image the component is in.
    image: &'a str,
    /// A subcomponent of another component (e.g. a kernel subsystem).
    nested: bool,
}

impl Node<'_> {
    fn reference(&self) -> ComponentRef {
        ComponentRef {
            bom_ref: self.bom_ref.clone(),
            name: self.component.name.clone(),
            version: self.component.version.clone(),
            purl: self.component.purl.clone(),
        }
    }

    fn label(&self) -> String {
        match &self.component.version {
            Some(v) => format!("{}@{v}", self.component.name),
            None => self.component.name.clone(),
        }
    }
}

/// What a finding is about: a component of the SBOM, or a package that is not one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Node(usize),
    Package(Package),
}

/// Every report of one vulnerability (one connected set of ids and aliases) against one
/// target, merged across scanners.
struct Merged {
    /// The primary id: the lowest `CVE-` id in the set, else the lowest id.
    id: String,
    /// Every other id in the set.
    aliases: BTreeSet<String>,
    package: Package,
    severity: Option<String>,
    fixed_in: BTreeSet<String>,
}

/// One rule that matched, with its `when` outcome.
struct Candidate<'a> {
    rule: &'a Rule,
    rank: (Specificity, i32),
    evidence: Vec<String>,
    missing: Vec<String>,
}

/// Evaluates `rules` for every finding against `product`, with `evidence` for `when`
/// conditions. Statements cite rollcall's derived `bom-ref`s; for a product read from a
/// CycloneDX document use [`evaluate_document`]. Deterministic: the report depends only on
/// the inputs' contents, not their order.
pub fn evaluate(
    product: &Product,
    evidence: &BuildEvidence,
    findings: &[Finding],
    rules: &RuleSet,
) -> Report {
    evaluate_inner(product, None, evidence, findings, rules)
}

/// [`evaluate`] for a product read from a CycloneDX document, citing the document's own
/// `bom-ref`s: `document_refs` is the reader's table of document `bom-ref` → node path
/// ([`Read::refs`](crate::cyclonedx::Read::refs)). A component the document gave no
/// `bom-ref` keeps rollcall's derived one, with a warning.
pub fn evaluate_document(
    product: &Product,
    document_refs: &BTreeMap<String, NodePath>,
    evidence: &BuildEvidence,
    findings: &[Finding],
    rules: &RuleSet,
) -> Report {
    evaluate_inner(product, Some(document_refs), evidence, findings, rules)
}

fn evaluate_inner(
    product: &Product,
    document_refs: Option<&BTreeMap<String, NodePath>>,
    evidence: &BuildEvidence,
    findings: &[Finding],
    rules: &RuleSet,
) -> Report {
    let mut report = Report {
        statements: Vec::new(),
        unresolved: Vec::new(),
        warnings: Vec::new(),
    };

    // Each path's document ref (the lowest, should the document give a node several).
    let mut by_path: BTreeMap<&NodePath, &str> = BTreeMap::new();
    for (doc_ref, path) in document_refs.into_iter().flatten() {
        by_path.entry(path).or_insert(doc_ref.as_str());
    }
    let mut nodes: Vec<Node<'_>> = Vec::new();
    let mut image = "";
    for (path, bom_ref, node) in product.walk() {
        match node {
            NodeRef::Image(i) => image = i.name.as_str(),
            NodeRef::Component(component) => {
                let cited = match (document_refs, by_path.get(&path)) {
                    (Some(_), Some(doc_ref)) => (*doc_ref).to_owned(),
                    (Some(_), None) => {
                        report.warnings.push(Warning::new(
                            path.to_string(),
                            format!(
                                "the document gives this component no bom-ref; statements \
                                 cite rollcall's derived {bom_ref}"
                            ),
                        ));
                        bom_ref.as_str().to_owned()
                    }
                    (None, _) => bom_ref.as_str().to_owned(),
                };
                nodes.push(Node {
                    bom_ref: cited,
                    component,
                    image,
                    nested: is_nested(&path),
                });
            }
            NodeRef::Product(_) => {}
        }
    }

    for m in merge(findings, &nodes) {
        let (id, target) = (&m.0.id, &m.1);
        let m_ = &m.0;
        let unresolved = |node: Option<&Node<'_>>, reason: Reason| {
            let (name, purl, key) = match node {
                Some(n) => (
                    n.component.name.as_str(),
                    n.component.purl.as_ref(),
                    n.bom_ref.clone(),
                ),
                None => {
                    let purl = m_.package.purl.as_ref();
                    let key = purl.map_or_else(|| m_.package.name.clone(), |p| p.to_string());
                    (m_.package.name.as_str(), purl, key)
                }
            };
            Unresolved {
                vulnerability: id.clone(),
                aliases: m_.aliases.clone(),
                component: node.map(Node::reference),
                package: m_.package.clone(),
                severity: m_.severity.clone(),
                fixed_in: m_.fixed_in.clone(),
                template: rules::template(id, name, purl.map(Purl::as_str), &key, node.is_some()),
                reason,
            }
        };
        let node = match target {
            Target::Node(index) => match nodes.get(*index) {
                Some(node) => node,
                None => continue,
            },
            Target::Package(_) => {
                report
                    .unresolved
                    .push(unresolved(None, Reason::ComponentNotInSbom));
                continue;
            }
        };
        let mut ids: BTreeSet<String> = m_.aliases.iter().map(|a| a.to_ascii_uppercase()).collect();
        ids.insert(id.to_ascii_uppercase());
        let candidates = candidates(rules, node, &ids, evidence);
        let Some(top) = candidates.iter().map(|c| c.rank).max() else {
            report
                .unresolved
                .push(unresolved(Some(node), Reason::NoRule));
            continue;
        };
        let mut tier: Vec<&Candidate<'_>> = candidates.iter().filter(|c| c.rank == top).collect();
        tier.sort_by(|a, b| a.rule.id.cmp(&b.rule.id));

        let lacking: Vec<&&Candidate<'_>> = tier.iter().filter(|c| !c.missing.is_empty()).collect();
        if !lacking.is_empty() {
            let reason = Reason::NeedsEvidence {
                rules: lacking.iter().map(|c| c.rule.id.clone()).collect(),
                missing: lacking
                    .iter()
                    .flat_map(|c| {
                        c.missing
                            .iter()
                            .map(|w| format!("rule `{}`: {w}", c.rule.id))
                    })
                    .collect(),
            };
            report.unresolved.push(unresolved(Some(node), reason));
            continue;
        }

        let Some(first) = tier.first() else {
            continue;
        };
        let agree = tier.iter().all(|c| {
            c.rule.status == first.rule.status
                && match (c.rule.justification, first.rule.justification) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.agrees_with(b),
                    _ => false,
                }
        });
        if !agree {
            let ids: Vec<String> = tier.iter().map(|c| c.rule.id.clone()).collect();
            report.warnings.push(Warning::new(
                format!("{id} on {} ({})", node.label(), node.bom_ref),
                format!(
                    "conflicting rules at equal precedence: {}; finding left unresolved",
                    describe(&tier)
                ),
            ));
            report
                .unresolved
                .push(unresolved(Some(node), Reason::Conflict { rules: ids }));
            continue;
        }
        let found: BTreeSet<String> = tier
            .iter()
            .flat_map(|c| c.evidence.iter().cloned())
            .collect();
        report.statements.push(Statement {
            vulnerability: id.clone(),
            aliases: m_.aliases.clone(),
            component: node.reference(),
            status: first.rule.status,
            justification: first.rule.justification,
            detail: tier.iter().find_map(|c| c.rule.detail.clone()),
            rules: tier.iter().map(|c| c.rule.id.clone()).collect(),
            evidence: found.into_iter().collect(),
        });
    }
    report
        .statements
        .sort_by(|a, b| (&a.vulnerability, &a.component).cmp(&(&b.vulnerability, &b.component)));
    report.unresolved.sort_by(|a, b| {
        (&a.vulnerability, &a.component, &a.package).cmp(&(
            &b.vulnerability,
            &b.component,
            &b.package,
        ))
    });
    report.warnings.sort();
    report
}

/// Joins every finding to its targets, then merges, per target, the findings whose ids and
/// aliases connect (e.g. a RUSTSEC and a GHSA advisory that both alias one CVE) into one
/// entry with a deterministic primary id. Sorted by (primary id, target).
fn merge(findings: &[Finding], nodes: &[Node<'_>]) -> Vec<(Merged, Target)> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort();
    sorted.dedup();
    let mut by_target: BTreeMap<Target, Vec<&Finding>> = BTreeMap::new();
    for finding in sorted {
        let joined = join(finding, nodes);
        if joined.is_empty() {
            let package = Package {
                name: finding.name.clone(),
                version: finding.version.clone(),
                purl: finding.purl.clone(),
            };
            by_target
                .entry(Target::Package(package))
                .or_default()
                .push(finding);
        } else {
            for index in joined {
                by_target
                    .entry(Target::Node(index))
                    .or_default()
                    .push(finding);
            }
        }
    }

    let mut out = Vec::new();
    for (target, list) in by_target {
        // Connected components over "shares an id or alias"; the result does not depend on
        // the order findings are visited in.
        let mut groups: Vec<(BTreeSet<String>, Vec<&Finding>)> = Vec::new();
        for finding in list {
            let mut names: BTreeSet<String> = finding.aliases.clone();
            names.insert(finding.id.clone());
            let mut members = vec![finding];
            let mut kept = Vec::with_capacity(groups.len());
            for (group_names, group_members) in groups {
                if group_names.is_disjoint(&names) {
                    kept.push((group_names, group_members));
                } else {
                    names.extend(group_names);
                    members.extend(group_members);
                }
            }
            kept.push((names, members));
            groups = kept;
        }
        for (mut names, mut members) in groups {
            members.sort();
            let primary = names
                .iter()
                .filter(|n| n.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("CVE-")))
                .min()
                .or_else(|| names.iter().min())
                .cloned()
                .unwrap_or_default();
            names.remove(&primary);
            let package = members.first().map_or_else(
                || Package {
                    name: String::new(),
                    version: None,
                    purl: None,
                },
                |f| Package {
                    name: f.name.clone(),
                    version: f.version.clone(),
                    purl: f.purl.clone(),
                },
            );
            let severity = members
                .iter()
                .find(|f| f.id == primary && f.severity.is_some())
                .or_else(|| members.iter().find(|f| f.severity.is_some()))
                .and_then(|f| f.severity.clone());
            let fixed_in = members
                .iter()
                .flat_map(|f| f.fixed_in.iter().cloned())
                .collect();
            out.push((
                Merged {
                    id: primary,
                    aliases: names,
                    package,
                    severity,
                    fixed_in,
                },
                target.clone(),
            ));
        }
    }
    out.sort_by(|a, b| (&a.0.id, &a.1).cmp(&(&b.0.id, &b.1)));
    out
}

/// `` `a` (not_affected, code_not_present) and `b` (affected) ``.
fn describe(tier: &[&Candidate<'_>]) -> String {
    let parts: Vec<String> = tier
        .iter()
        .map(|c| match c.rule.justification {
            Some(j) => format!("`{}` ({}, {j})", c.rule.id, c.rule.status),
            None => format!("`{}` ({})", c.rule.id, c.rule.status),
        })
        .collect();
    match parts.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        Some((last, _)) => last.clone(),
        None => String::new(),
    }
}

/// A path is product / image / component / subcomponent…; deeper than a top-level component
/// means nested.
fn is_nested(path: &NodePath) -> bool {
    path.segments().len() > 3
}

/// The components a finding is about: those with an equal purl; else those with one of its
/// cpes; else those with the same name (ignoring ASCII case) and version.
fn join(finding: &Finding, nodes: &[Node<'_>]) -> Vec<usize> {
    let pick = |f: &dyn Fn(&Component) -> bool| -> Vec<usize> {
        nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| f(n.component))
            .map(|(i, _)| i)
            .collect()
    };
    if let Some(purl) = &finding.purl {
        let hits = pick(&|c| c.purl.as_ref() == Some(purl));
        if !hits.is_empty() {
            return hits;
        }
    }
    if !finding.cpes.is_empty() {
        let hits = pick(&|c| c.cpe.as_ref().is_some_and(|cpe| finding.cpes.contains(cpe)));
        if !hits.is_empty() {
            return hits;
        }
    }
    pick(&|c| c.name.eq_ignore_ascii_case(&finding.name) && c.version == finding.version)
}

/// Whether `rule`'s target (purl, name, subsystem) matches `node`.
fn target_matches(rule: &Rule, node: &Node<'_>) -> bool {
    let m = &rule.target;
    let c = node.component;
    let purl_ok = m
        .purl
        .as_ref()
        .is_none_or(|pattern| c.purl.as_ref().is_some_and(|p| pattern.matches(p)));
    let name_ok = m.name.as_ref().is_none_or(|name| c.name == *name);
    let subsystem_ok = m
        .subsystem
        .as_ref()
        .is_none_or(|subsystem| node.nested && c.name == *subsystem);
    purl_ok && name_ok && subsystem_ok
}

/// Every rule whose `match` applies and whose `when` is not false, with its evidence. A
/// `match.versions` that cannot be compared (no release version) counts as missing evidence,
/// like an unknown condition.
fn candidates<'a>(
    rules: &'a RuleSet,
    node: &Node<'_>,
    ids: &BTreeSet<String>,
    evidence: &BuildEvidence,
) -> Vec<Candidate<'a>> {
    let mut out = Vec::new();
    'rules: for rule in &rules.rules {
        if !target_matches(rule, node) {
            continue;
        }
        if !rule.target.cves.is_empty() && rule.target.cves.is_disjoint(ids) {
            continue;
        }
        let mut found = Vec::new();
        let mut missing = Vec::new();
        if let Some(range) = &rule.target.versions {
            match effective_version(node.component) {
                Some(v) if range.contains(&v) => {}
                Some(_) => continue,
                None => missing.push(format!(
                    "match.versions {range}: {} version {:?} is not a release version",
                    node.component.name,
                    node.component.version.as_deref().unwrap_or("(none)")
                )),
            }
        }
        for condition in &rule.when {
            match condition.evaluate(node.image, node.component, evidence) {
                Verdict::True(text) => found.push(text),
                Verdict::False(_) => continue 'rules,
                Verdict::Unknown(why) => missing.push(format!("{condition}: {why}")),
            }
        }
        out.push(Candidate {
            rule,
            rank: (Specificity::of(&rule.target), rule.priority),
            evidence: found,
            missing,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ComponentKind, Cpe, Image, ImageKind};
    use crate::vex::findings::Scanner;
    use crate::vex::rules::parse_rules;
    use crate::zephyr::kconfig;

    const MBEDTLS_PURL: &str = "pkg:github/mbed-tls/mbedtls@v2.28.0";

    fn product() -> Product {
        let mut product = Product::new("node").unwrap().with_version("1.0.0");
        let mut app = Image::new(ImageKind::Application, "app").unwrap();
        let mut mbedtls = Component::new(ComponentKind::Library, "mbedtls")
            .unwrap()
            .with_version("2.28.0");
        mbedtls.purl = Some(Purl::new(MBEDTLS_PURL).unwrap());
        mbedtls.cpe = Some(Cpe::new("cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*").unwrap());
        let mut zephyr = Component::new(ComponentKind::OperatingSystem, "zephyr")
            .unwrap()
            .with_version("3.7.0");
        zephyr
            .add_component(Component::new(ComponentKind::Library, "shell").unwrap())
            .unwrap();
        app.add_component(mbedtls).unwrap();
        app.add_component(zephyr).unwrap();
        app.add_component(Component::new(ComponentKind::Library, "shell").unwrap())
            .unwrap();
        product.add_image(app).unwrap();
        product
    }

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_owned(),
            purl: Some(Purl::new(MBEDTLS_PURL).unwrap()),
            name: "mbedtls".to_owned(),
            version: Some("2.28.0".to_owned()),
            aliases: BTreeSet::new(),
            cpes: BTreeSet::new(),
            severity: Some("High".to_owned()),
            fixed_in: BTreeSet::from(["2.28.1".to_owned()]),
            scanner: Scanner::Grype,
        }
    }

    fn rules(body: &str) -> RuleSet {
        parse_rules(&format!("version: 1\nrules:\n{body}"), "rules.yml")
            .unwrap_or_else(|e| panic!("{e}"))
    }

    fn evidence() -> BuildEvidence {
        BuildEvidence::new().with_kconfig(
            "app",
            kconfig::parse("CONFIG_DTLS=n\nCONFIG_TLS=y\n").unwrap(),
        )
    }

    fn run(findings: &[Finding], body: &str) -> Report {
        evaluate(&product(), &evidence(), findings, &rules(body))
    }

    fn only_statement(report: &Report) -> &Statement {
        assert!(report.unresolved.is_empty(), "{:?}", report.unresolved);
        let [s] = report.statements.as_slice() else {
            panic!("{report:?}")
        };
        s
    }

    fn only_unresolved(report: &Report) -> &Unresolved {
        assert!(report.statements.is_empty(), "{:?}", report.statements);
        let [u] = report.unresolved.as_slice() else {
            panic!("{report:?}")
        };
        u
    }

    #[test]
    fn status_not_affected_statement() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: a, match: {name: mbedtls}, when: [{kconfig_off: CONFIG_DTLS}], status: not_affected, justification: code_not_present, detail: DTLS off}\n",
        );
        let s = only_statement(&r);
        assert_eq!(s.status, Status::NotAffected);
        assert_eq!(s.justification, Some(Justification::CodeNotPresent));
        assert_eq!(s.detail.as_deref(), Some("DTLS off"));
        assert_eq!(s.rules, ["a"]);
        assert_eq!(s.evidence, ["app/zephyr/.config:1: CONFIG_DTLS is not set"]);
        assert_eq!(s.component.name, "mbedtls");
    }

    #[test]
    fn status_affected_statement() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: a, match: {name: mbedtls}, status: affected}\n",
        );
        assert_eq!(only_statement(&r).status, Status::Affected);
        assert_eq!(only_statement(&r).justification, None);
    }

    #[test]
    fn status_fixed_statement() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: a, match: {name: mbedtls}, status: fixed}\n",
        );
        assert_eq!(only_statement(&r).status, Status::Fixed);
    }

    #[test]
    fn status_under_investigation_statement() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: a, match: {name: mbedtls}, status: under_investigation}\n",
        );
        assert_eq!(only_statement(&r).status, Status::UnderInvestigation);
    }

    #[test]
    fn false_condition_skips_rule() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: a, match: {name: mbedtls, cves: [CVE-1]}, when: [{kconfig_off: CONFIG_TLS}], status: not_affected, justification: code_not_present}\n  - {id: b, match: {name: mbedtls}, status: under_investigation}\n",
        );
        assert_eq!(only_statement(&r).rules, ["b"]);
    }

    #[test]
    fn cve_rule_beats_component_rule() {
        let body = "  - {id: component-wide, match: {purl: \"pkg:github/mbed-tls/mbedtls@v2.28.0\"}, status: affected}\n  - {id: specific, match: {name: mbedtls, cves: [CVE-1]}, status: not_affected, justification: code_not_present}\n";
        let r = run(&[finding("CVE-1"), finding("CVE-2")], body);
        assert!(r.unresolved.is_empty());
        assert_eq!(r.statements.len(), 2);
        assert_eq!(r.statements[0].vulnerability, "CVE-1");
        assert_eq!(r.statements[0].rules, ["specific"]);
        assert_eq!(r.statements[1].vulnerability, "CVE-2");
        assert_eq!(r.statements[1].rules, ["component-wide"]);
    }

    #[test]
    fn exact_purl_beats_glob_beats_name() {
        let exact = "  - {id: exact, match: {purl: \"pkg:github/mbed-tls/mbedtls@v2.28.0\"}, status: fixed}\n";
        let glob = "  - {id: glob, match: {purl: \"pkg:github/mbed-tls/*\"}, status: affected}\n";
        let name = "  - {id: name, match: {name: mbedtls}, status: under_investigation}\n";
        let r = run(&[finding("CVE-1")], &format!("{name}{glob}{exact}"));
        assert_eq!(only_statement(&r).rules, ["exact"]);
        let r = run(&[finding("CVE-1")], &format!("{name}{glob}"));
        assert_eq!(only_statement(&r).rules, ["glob"]);
        let versioned = "  - {id: versioned, match: {name: mbedtls, versions: \"<2.28.1\"}, status: affected}\n";
        let r = run(&[finding("CVE-1")], &format!("{exact}{versioned}"));
        assert_eq!(only_statement(&r).rules, ["versioned"]);
    }

    #[test]
    fn equal_specificity_priority_decides() {
        let body = "  - {id: low, priority: 1, match: {name: mbedtls}, status: affected}\n  - {id: high, priority: 5, match: {name: mbedtls}, status: fixed}\n";
        let s = run(&[finding("CVE-1")], body);
        let s = only_statement(&s);
        assert_eq!(s.rules, ["high"]);
        assert_eq!(s.status, Status::Fixed);
    }

    #[test]
    fn equal_priority_same_outcome_cites_both() {
        let body = "  - {id: b, match: {name: mbedtls}, status: affected, detail: from b}\n  - {id: a, match: {name: mbedtls}, status: affected}\n";
        let r = run(&[finding("CVE-1")], body);
        let s = only_statement(&r);
        assert_eq!(s.rules, ["a", "b"]);
        assert_eq!(s.detail.as_deref(), Some("from b"));
        assert!(r.warnings.is_empty());
    }

    const CONFLICT: &str = "  - {id: says-fixed, match: {name: mbedtls}, status: fixed}\n  - {id: says-affected, match: {name: mbedtls}, status: affected}\n";

    #[test]
    fn conflict_warns_naming_both_rules() {
        let r = run(&[finding("CVE-1")], CONFLICT);
        let [w] = r.warnings.as_slice() else {
            panic!("{r:?}")
        };
        let bom_ref = &r.unresolved[0].component.as_ref().unwrap().bom_ref;
        assert_eq!(w.location, format!("CVE-1 on mbedtls@2.28.0 ({bom_ref})"));
        assert!(bom_ref.starts_with("component:"), "{bom_ref}");
        assert!(w.message.contains("`says-affected` (affected)"), "{w}");
        assert!(w.message.contains("`says-fixed` (fixed)"), "{w}");
    }

    #[test]
    fn conflict_leaves_finding_unresolved() {
        let r = run(&[finding("CVE-1")], CONFLICT);
        let u = only_unresolved(&r);
        assert_eq!(
            u.reason,
            Reason::Conflict {
                rules: vec!["says-affected".to_owned(), "says-fixed".to_owned()]
            }
        );
        assert!(!u.template.is_empty());
    }

    #[test]
    fn no_rule_gives_unresolved_with_template() {
        let r = run(
            &[finding("CVE-9")],
            "  - {id: other, match: {name: zephyr}, status: affected}\n",
        );
        let u = only_unresolved(&r);
        assert_eq!(u.reason, Reason::NoRule);
        assert_eq!(u.vulnerability, "CVE-9");
        assert_eq!(u.severity.as_deref(), Some("High"));
        assert_eq!(u.fixed_in, BTreeSet::from(["2.28.1".to_owned()]));
        assert_eq!(
            u.component.as_ref().map(|c| c.name.as_str()),
            Some("mbedtls")
        );
        assert!(u.template.contains("CVE-9"), "{}", u.template);
        assert!(u.template.contains(MBEDTLS_PURL), "{}", u.template);
    }

    #[test]
    fn template_parses_as_rule() {
        let r = run(&[finding("CVE-9")], "");
        let u = only_unresolved(&r);
        let set = rules(&u.template);
        // Feeding the template back resolves the finding as under investigation.
        let again = evaluate(&product(), &evidence(), &[finding("CVE-9")], &set);
        let s = only_statement(&again);
        assert_eq!(s.status, Status::UnderInvestigation);
        assert_eq!(s.rules, [set.rules[0].id.clone()]);
    }

    #[test]
    fn needs_evidence_is_unresolved() {
        let body = "  - {id: dtls, match: {name: mbedtls, cves: [CVE-1]}, when: [{symbol_not_linked: ssl_parse}], status: not_affected, justification: code_not_present}\n  - {id: fallback, match: {name: mbedtls}, status: affected}\n";
        let r = run(&[finding("CVE-1")], body);
        let u = only_unresolved(&r);
        match &u.reason {
            Reason::NeedsEvidence { rules, missing } => {
                assert_eq!(rules, &["dtls"]);
                assert_eq!(missing.len(), 1);
                assert!(
                    missing[0].starts_with("rule `dtls`: symbol_not_linked: ssl_parse: "),
                    "{missing:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn joins_by_purl_then_cpe_then_name() {
        let body = "  - {id: a, match: {name: mbedtls}, status: affected}\n";
        let mut by_cpe = finding("CVE-1");
        by_cpe.purl = Some(Purl::new("pkg:generic/mbedtls@2.28.0").unwrap());
        by_cpe.cpes =
            BTreeSet::from([Cpe::new("cpe:2.3:a:arm:mbed_tls:2.28.0:*:*:*:*:*:*:*").unwrap()]);
        assert_eq!(
            only_statement(&run(&[by_cpe], body)).component.name,
            "mbedtls"
        );
        let mut by_name = finding("CVE-1");
        by_name.purl = None;
        by_name.name = "MbedTLS".to_owned();
        assert_eq!(
            only_statement(&run(&[by_name], body)).component.name,
            "mbedtls"
        );
    }

    #[test]
    fn finding_for_absent_component_is_unresolved() {
        let mut f = finding("CVE-1");
        f.purl = Some(Purl::new("pkg:cargo/heapless@0.5.0").unwrap());
        f.name = "heapless".to_owned();
        f.version = Some("0.5.0".to_owned());
        let r = run(
            &[f],
            "  - {id: a, match: {name: heapless}, status: affected}\n",
        );
        let u = only_unresolved(&r);
        assert_eq!(u.reason, Reason::ComponentNotInSbom);
        assert_eq!(u.component, None);
        assert!(
            u.template.contains("pkg:cargo/heapless@0.5.0"),
            "{}",
            u.template
        );
    }

    #[test]
    fn subsystem_rule_is_active_and_does_not_warn() {
        let r = run(
            &[finding("CVE-1")],
            "  - {id: sub, match: {subsystem: shell}, status: affected}\n",
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        // mbedtls is not a nested `net` subcomponent: no rule matched it.
        assert_eq!(only_unresolved(&r).reason, Reason::NoRule);
    }

    #[test]
    fn subsystem_matches_nested_only() {
        let mut f = finding("CVE-1");
        f.purl = None;
        f.name = "shell".to_owned();
        f.version = None;
        let r = run(
            &[f],
            "  - {id: sub, match: {subsystem: shell}, status: affected}\n",
        );
        // Joined to both `net` components; the rule applies only to the nested one.
        assert_eq!(r.statements.len(), 1, "{r:?}");
        assert_eq!(r.unresolved.len(), 1, "{r:?}");
        assert_eq!(r.unresolved[0].reason, Reason::NoRule);
    }

    #[test]
    fn alias_matches_cves_and_scanners_merge() {
        let mut grype = finding("CVE-1");
        grype.aliases = BTreeSet::from(["GHSA-1".to_owned()]);
        let mut osv = finding("CVE-1");
        osv.scanner = Scanner::Osv;
        osv.aliases = BTreeSet::from(["RUSTSEC-1".to_owned()]);
        osv.fixed_in = BTreeSet::from(["2.28.2".to_owned()]);
        let r = run(
            &[osv, grype],
            "  - {id: a, match: {name: mbedtls, cves: [ghsa-1]}, status: affected}\n",
        );
        let s = only_statement(&r);
        assert_eq!(
            s.aliases,
            BTreeSet::from(["GHSA-1".to_owned(), "RUSTSEC-1".to_owned()])
        );
    }

    #[test]
    fn aliases_merge_into_one_entry_with_cve_primary() {
        let mut rustsec = finding("RUSTSEC-2020-0145");
        rustsec.aliases = BTreeSet::from(["CVE-2020-36464".to_owned(), "GHSA-qgwf".to_owned()]);
        rustsec.severity = None;
        let mut ghsa = finding("GHSA-qgwf");
        ghsa.aliases =
            BTreeSet::from(["CVE-2020-36464".to_owned(), "RUSTSEC-2020-0145".to_owned()]);
        ghsa.fixed_in = BTreeSet::from(["0.6.1".to_owned()]);
        let r = run(&[rustsec, ghsa], "");
        let u = only_unresolved(&r);
        assert_eq!(u.vulnerability, "CVE-2020-36464");
        assert_eq!(
            u.aliases,
            BTreeSet::from(["GHSA-qgwf".to_owned(), "RUSTSEC-2020-0145".to_owned()])
        );
        assert_eq!(u.severity.as_deref(), Some("High"));
        assert_eq!(
            u.fixed_in,
            BTreeSet::from(["0.6.1".to_owned(), "2.28.1".to_owned()])
        );
    }

    #[test]
    fn alias_sets_merge_transitively_without_a_cve() {
        let mut a = finding("GHSA-a");
        a.aliases = BTreeSet::from(["OSV-1".to_owned()]);
        let mut c = finding("RUSTSEC-c");
        c.aliases = BTreeSet::from(["OSV-2".to_owned()]);
        let mut bridge = finding("ZZZ-1");
        bridge.aliases = BTreeSet::from(["OSV-1".to_owned(), "OSV-2".to_owned()]);
        let unrelated = finding("GHSA-z");
        for order in [
            vec![a.clone(), c.clone(), bridge.clone(), unrelated.clone()],
            vec![bridge.clone(), unrelated.clone(), c.clone(), a.clone()],
        ] {
            let r = run(&order, "");
            let ids: Vec<&str> = r
                .unresolved
                .iter()
                .map(|u| u.vulnerability.as_str())
                .collect();
            assert_eq!(ids, ["GHSA-a", "GHSA-z"], "{r:?}");
            assert_eq!(r.unresolved[0].aliases.len(), 4);
        }
    }

    #[test]
    fn unknown_version_with_match_versions_needs_evidence() {
        let body =
            "  - {id: old, match: {name: mbedtls, versions: \"<2.28.2\"}, status: affected}\n";
        let mut p = product();
        let mut app = p.images.pop_first().unwrap();
        let mut c = app.components.pop_first().unwrap();
        assert_eq!(c.name, "mbedtls");
        c.version = Some("v2.28.0-12-gabcdef0".to_owned());
        app.components.insert(c);
        p.images.insert(app);
        let mut f = finding("CVE-1");
        f.version = Some("v2.28.0-12-gabcdef0".to_owned());
        let r = evaluate(&p, &evidence(), &[f], &rules(body));
        let u = only_unresolved(&r);
        match &u.reason {
            Reason::NeedsEvidence { rules, missing } => {
                assert_eq!(rules, &["old"]);
                assert!(missing[0].contains("match.versions <2.28.2"), "{missing:?}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn kconfig_is_judged_per_image() {
        let mut p = product();
        let mut boot = Image::new(ImageKind::Bootloader, "boot").unwrap();
        let mut mbedtls = Component::new(ComponentKind::Library, "mbedtls")
            .unwrap()
            .with_version("2.28.0");
        mbedtls.purl = Some(Purl::new(MBEDTLS_PURL).unwrap());
        boot.add_component(mbedtls).unwrap();
        p.add_image(boot).unwrap();
        let body = "  - {id: dtls, match: {name: mbedtls}, when: [{kconfig_off: CONFIG_DTLS}], status: not_affected, justification: code_not_present}\n";
        // Only the application's .config is given.
        let r = evaluate(&p, &evidence(), &[finding("CVE-1")], &rules(body));
        assert_eq!(r.statements.len(), 1, "{r:?}");
        assert!(r.statements[0].evidence[0].starts_with("app/zephyr/.config:"));
        let [u] = r.unresolved.as_slice() else {
            panic!("{r:?}")
        };
        assert!(matches!(u.reason, Reason::NeedsEvidence { .. }), "{u:?}");
        assert!(u.template.contains("todo-cve-1-mbedtls-"));
        // With the bootloader's own .config, where DTLS is on, the rule does not apply.
        let both = evidence().with_kconfig("boot", kconfig::parse("CONFIG_DTLS=y\n").unwrap());
        let r = evaluate(&p, &both, &[finding("CVE-1")], &rules(body));
        assert_eq!(r.statements.len(), 1, "{r:?}");
        assert_eq!(r.unresolved[0].reason, Reason::NoRule);
        // The two templates differ although the components share a name.
        let r = evaluate(&p, &BuildEvidence::new(), &[finding("CVE-1")], &rules(""));
        assert_ne!(r.unresolved[0].template, r.unresolved[1].template);
    }

    #[test]
    fn document_refs_are_cited() {
        let p = product();
        let mut refs = BTreeMap::new();
        for (path, _, node) in p.walk() {
            if let NodeRef::Component(c) = node
                && c.name == "mbedtls"
            {
                refs.insert("doc-ref-mbedtls".to_owned(), path);
            }
        }
        let body = "  - {id: a, match: {name: mbedtls}, status: affected}\n";
        let r = evaluate_document(&p, &refs, &evidence(), &[finding("CVE-1")], &rules(body));
        assert_eq!(r.statements[0].component.bom_ref, "doc-ref-mbedtls");
        // The other components have no document ref: each is warned about.
        assert_eq!(r.warnings.len(), 3, "{:?}", r.warnings);
        assert!(r.warnings.iter().all(|w| w.message.contains("no bom-ref")));
    }

    #[test]
    fn order_of_inputs_does_not_matter() {
        let body = "  - {id: a, match: {name: mbedtls, cves: [CVE-1]}, status: affected}\n  - {id: b, match: {name: mbedtls}, status: under_investigation}\n";
        let fs = [finding("CVE-2"), finding("CVE-1"), finding("CVE-3")];
        let mut reversed = fs.clone();
        reversed.reverse();
        let a = run(&fs, body).to_json().unwrap();
        let b = run(&reversed, body).to_json().unwrap();
        assert_eq!(a, b);
    }
}
