//! Profile validation: checks beyond schema validity, as regulators' SBOM guidance asks.
//!
//! [`validate_profiles`] reads any CycloneDX JSON document generically (it does not need to
//! be one rollcall wrote) and runs the checks of one or more [`Profile`]s against it. The
//! built-in profiles are `cisa-2026` (CISA et al., *2026 Minimum Elements for a Software
//! Bill of Materials*) and `cra` (Regulation (EU) 2024/2847, the Cyber Resilience Act, with
//! BSI TR-03183-2 for the per-component fields); `docs/validate.md` cites the clause each
//! check encodes.
//!
//! # Checks
//!
//! Each check is code with a stable id ([`CHECKS`]): `document.timestamp`,
//! `document.author`, `document.root`, `component.name`, `component.version`,
//! `component.supplier`, `component.identifier`, `component.hash`, `graph.refs-resolve`,
//! `graph.reachable`, `graph.top-level-complete` and `image.represented`. Component checks
//! cover `metadata.component` (the root) and every `components[]` entry at any depth.
//!
//! # Profiles
//!
//! A profile is data, a YAML file in `profiles/` (`format: rollcall-profile/1`): which checks
//! run, each one's severity (`error` or `warning`), its parameters, and the source document
//! and clause it cites. New regulator guidance is a new YAML file, not new code, unless it
//! needs a check the catalogue does not have. Loading never panics; a malformed profile is a
//! [`ProfileError`].
//!
//! # Report
//!
//! A [`Report`] lists every [`Finding`]: the check, severity, the component's `bom-ref`
//! (or the JSON pointer of a document-level field), its name and version, what is wrong,
//! how to fix it, and the clause each requiring profile cites. A check that several
//! profiles require with identical parameters runs once and its findings name every such
//! profile, at the strictest of their severities; with different parameters it runs once
//! per parameter set. The document passes when no finding is an error.
//!
//! # Determinism
//!
//! Findings are sorted: document-level findings first, then by component in document order
//! (`metadata.component`, then `components[]` pre-order), then by check in catalogue order,
//! JSON pointer and message. Nothing depends on hash order, so the same document and
//! profiles always give the same report.

mod checks;
mod profile;
mod reader;
mod report;

use serde_json::Value;

pub use checks::{CHECKS, CheckDef, ParamDef, ParamKind, ParamValue, Params, check};
pub use profile::{
    BUILTIN_DIR, Cite, FORMAT, Profile, ProfileCheck, ProfileError, Source, builtin_ids,
    builtin_profiles,
};
pub use report::{Citation, Finding, Report, Severity};

use checks::At;
use reader::Doc;

/// One distinct (check, parameters) pair and the profiles that require it.
struct Group<'a> {
    def: &'static CheckDef,
    /// The parameters, [`Params::normalized`], so explicit defaults group with omitted ones.
    params: Params,
    requirers: Vec<(&'a str, &'a ProfileCheck)>,
}

/// Validates `document` against `profiles`. Never fails and never panics: a document of the
/// wrong shape (not an object, fields of the wrong type) simply has findings.
///
/// A [`Profile`] built by hand (not through [`Profile::from_yaml`]) may name a check that is
/// not in [`CHECKS`]. Such a check is not skipped silently: it becomes an error finding of
/// that check id at the document level, saying the check is unknown.
pub fn validate_profiles(document: &Value, profiles: &[Profile]) -> Report {
    let doc = Doc::from_value(document);
    let mut groups: Vec<Group<'_>> = Vec::new();
    let mut findings = Vec::new();
    for profile in profiles {
        for pc in &profile.checks {
            let Some(def) = check(&pc.id) else {
                findings.push(Finding {
                    profiles: vec![profile.id.clone()],
                    check: pc.id.clone(),
                    severity: Severity::Error,
                    r#ref: None,
                    path: String::new(),
                    name: None,
                    version: None,
                    message: format!("unknown check {:?}: it is not in the catalogue", pc.id),
                    fix: "use a check id from the catalogue (load profiles with \
                          Profile::from_yaml, which rejects unknown checks)"
                        .to_owned(),
                    citations: vec![Citation {
                        profile: profile.id.clone(),
                        document: pc.cite.document.clone(),
                        url: pc.cite.url.clone(),
                        clause: pc.cite.clause.clone(),
                    }],
                    order: (0, usize::MAX),
                });
                continue;
            };
            let params = pc.params.normalized(def);
            match groups
                .iter_mut()
                .find(|g| g.def.id == def.id && g.params == params)
            {
                Some(g) => g.requirers.push((&profile.id, pc)),
                None => groups.push(Group {
                    def,
                    params,
                    requirers: vec![(&profile.id, pc)],
                }),
            }
        }
    }

    for group in &groups {
        let position = CHECKS
            .iter()
            .position(|c| c.id == group.def.id)
            .unwrap_or(usize::MAX);
        let strictest = group
            .requirers
            .iter()
            .map(|(_, pc)| pc.severity)
            .max()
            .unwrap_or(Severity::Error);
        let citations: Vec<Citation> = group
            .requirers
            .iter()
            .map(|(id, pc)| Citation {
                profile: (*id).to_owned(),
                document: pc.cite.document.clone(),
                url: pc.cite.url.clone(),
                clause: pc.cite.clause.clone(),
            })
            .collect();
        let mut profile_ids: Vec<String> = group
            .requirers
            .iter()
            .map(|(id, _)| (*id).to_owned())
            .collect();
        profile_ids.dedup();
        for failure in (group.def.run)(&doc, &group.params) {
            let (node_order, node, path) = match &failure.at {
                At::Document(pointer) => (0, None, pointer.clone()),
                At::Node(i) => {
                    let node = doc.nodes.get(*i);
                    (
                        i + 1,
                        node,
                        node.map(|n| n.pointer.clone()).unwrap_or_default(),
                    )
                }
            };
            let severity = if failure.warning_only {
                Severity::Warning
            } else {
                strictest
            };
            findings.push(Finding {
                profiles: profile_ids.clone(),
                check: group.def.id.to_owned(),
                severity,
                r#ref: node.and_then(|n| n.bom_ref.clone()),
                path,
                name: node.and_then(|n| n.name.clone()),
                version: node.and_then(|n| n.version.clone()),
                message: failure.problem,
                fix: failure.fix,
                citations: citations.clone(),
                order: (node_order, position),
            });
        }
    }
    findings.sort_by(|a, b| {
        (a.order, &a.path, &a.message, &a.profiles).cmp(&(
            b.order,
            &b.path,
            &b.message,
            &b.profiles,
        ))
    });
    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    Report {
        profiles: profiles.iter().map(|p| p.id.clone()).collect(),
        checks_run: groups.len(),
        errors,
        warnings: findings.len() - errors,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(yaml_checks: &str, id: &str) -> Profile {
        Profile::from_yaml(&format!(
            "format: rollcall-profile/1\nid: {id}\ntitle: T\nsources:\n  - key: s\n    document: D\nchecks:\n{yaml_checks}"
        ))
        .unwrap()
    }

    #[test]
    fn shared_checks_run_once_and_name_every_profile() {
        let a = profile(
            "  - id: component.version\n    severity: warning\n    cite: { source: s, clause: a1 }\n",
            "a",
        );
        let b = profile(
            "  - id: component.version\n    severity: error\n    cite: { source: s, clause: b1 }\n  - id: component.hash\n    severity: error\n    cite: { source: s, clause: b2 }\n    params: { algorithms: [SHA-512] }\n",
            "b",
        );
        let doc = json!({"metadata": {"component": {"bom-ref": "r", "name": "p"}}});
        let report = validate_profiles(&doc, &[a, b]);
        assert_eq!(report.checks_run, 2);
        assert_eq!(report.findings.len(), 2);
        let version = &report.findings[0];
        assert_eq!(version.check, "component.version");
        assert_eq!(version.profiles, ["a", "b"]);
        assert_eq!(version.severity, Severity::Error);
        assert_eq!(version.citations.len(), 2);
        assert_eq!(version.r#ref.as_deref(), Some("r"));
        assert!(!report.passed());
    }

    #[test]
    fn different_params_run_separately_and_warnings_pass() {
        let a = profile(
            "  - id: component.hash\n    severity: warning\n    cite: { source: s, clause: a }\n",
            "a",
        );
        let b = profile(
            "  - id: component.hash\n    severity: warning\n    cite: { source: s, clause: b }\n    params: { include_root: false }\n",
            "b",
        );
        let doc = json!({"metadata": {"component": {"bom-ref": "r", "name": "p"}},
                         "components": [{"bom-ref": "c", "name": "c"}]});
        let report = validate_profiles(&doc, &[a, b]);
        assert_eq!(report.checks_run, 2);
        assert_eq!(report.warnings, 3);
        assert!(report.passed());
        let order: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.r#ref.clone().unwrap(), f.profiles.join(",")))
            .collect();
        assert_eq!(
            order,
            [
                ("r".into(), "a".into()),
                ("c".into(), "a".into()),
                ("c".into(), "b".into())
            ]
        );
    }

    #[test]
    fn explicit_default_params_group_with_omitted_ones() {
        let a = profile(
            "  - id: component.hash\n    severity: error\n    cite: { source: s, clause: a }\n",
            "a",
        );
        let b = profile(
            "  - id: component.hash\n    severity: error\n    cite: { source: s, clause: b }\n    params: { include_root: true }\n",
            "b",
        );
        assert_eq!(a.checks[0].params, b.checks[0].params);
        let doc = json!({"metadata": {"component": {"bom-ref": "r", "name": "p"}}});
        let report = validate_profiles(&doc, &[a.clone(), b.clone()]);
        assert_eq!(report.checks_run, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].profiles, ["a", "b"]);
        // Also for hand-built params that were never normalised at load.
        let mut c = b;
        c.id = "c".into();
        c.checks[0].params = Params::new().with("include_root", ParamValue::Bool(true));
        let report = validate_profiles(&doc, &[a, c]);
        assert_eq!((report.checks_run, report.findings.len()), (1, 1));
    }

    #[test]
    fn unknown_check_in_hand_built_profile_is_an_error_finding() {
        let mut p = profile(
            "  - id: component.name\n    severity: warning\n    cite: { source: s, clause: a }\n",
            "hand",
        );
        p.checks[0].id = "component.colour".into();
        let report = validate_profiles(&json!({}), &[p]);
        assert_eq!(report.checks_run, 0);
        assert_eq!(report.errors, 1);
        let f = &report.findings[0];
        assert_eq!(f.check, "component.colour");
        assert!(f.message.contains("unknown check"));
        assert!(!report.passed());
    }

    #[test]
    fn non_object_documents_give_findings_not_panics() {
        let profiles = builtin_profiles();
        for doc in [json!(null), json!([]), json!("x"), json!({})] {
            let report = validate_profiles(&doc, &profiles);
            assert!(!report.passed(), "{doc}");
            assert!(report.findings.iter().all(|f| f.r#ref.is_none()));
        }
    }
}
