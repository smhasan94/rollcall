//! Unresolved modules and unidentified components, each with a paste-ready identifier
//! database stub.

use super::coverage::Node;
use super::model::UnresolvedEntry;
use crate::identify::stub;
use crate::model::EvidenceField;

/// The evidence source the identifier database writes.
const IDENTIFIER_DB: &str = "identifier-db";

/// `module-not-in-identifier-db`.
pub(super) const NOT_IN_DB: &str = "module-not-in-identifier-db";
/// `no-identifier`.
pub(super) const NO_IDENTIFIER: &str = "no-identifier";

/// Whether `node` is a Zephyr (west) module: a component with `west-list` evidence, or whose
/// name Kconfig evidences with a `CONFIG_ZEPHYR_<MODULE>_MODULE` symbol.
pub(super) fn is_module(node: &Node<'_>) -> bool {
    node.level == "component"
        && node.evidence.iter().any(|e| {
            e.source() == "west-list"
                || (e.source() == "kconfig"
                    && e.field == EvidenceField::Name
                    && e.value.starts_with("CONFIG_ZEPHYR_")
                    && e.value.ends_with("_MODULE"))
        })
}

/// Whether the identifier database resolved `node` (it has `identifier-db` evidence).
pub(super) fn is_resolved(node: &Node<'_>) -> bool {
    node.evidence.iter().any(|e| e.source() == IDENTIFIER_DB)
}

/// `https://github.com/<owner>/<repo>` from a `pkg:github/<owner>/<repo>@…` purl.
fn github_url(purl: &str) -> Option<String> {
    let rest = purl.strip_prefix("pkg:github/")?;
    let end = rest.find(['@', '?', '#']).unwrap_or(rest.len());
    let (owner, repo) = rest.get(..end)?.split_once('/')?;
    (!owner.is_empty() && !repo.is_empty() && !repo.contains('/'))
        .then(|| format!("https://github.com/{owner}/{repo}"))
}

/// The module's repository URL: from its purl, else from a purl its evidence records.
fn repository(node: &Node<'_>) -> Option<String> {
    node.purl.and_then(|p| github_url(p.as_str())).or_else(|| {
        node.evidence
            .iter()
            .filter(|e| e.field == EvidenceField::Purl)
            .find_map(|e| github_url(&e.value))
    })
}

/// Every module the identifier database did not resolve, and every component with neither
/// a purl nor a CPE, sorted by path, name and version.
pub(super) fn unresolved(nodes: &[Node<'_>]) -> Vec<UnresolvedEntry> {
    let mut out: Vec<UnresolvedEntry> = nodes
        .iter()
        .filter(|n| n.level == "component")
        .filter_map(|n| {
            let reason = if is_module(n) && !is_resolved(n) {
                NOT_IN_DB
            } else if n.purl.is_none() && !n.has_cpe {
                NO_IDENTIFIER
            } else {
                return None;
            };
            let hint = stub(&n.name, repository(n).as_deref(), n.version.as_deref()).to_string();
            Some(UnresolvedEntry {
                path: n.label.clone(),
                name: n.name.clone(),
                version: n.version.clone(),
                reason,
                hint,
            })
        })
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::github_url;

    #[test]
    fn github_url_from_purl() {
        assert_eq!(
            github_url("pkg:github/zephyrproject-rtos/cmsis_6@abc").as_deref(),
            Some("https://github.com/zephyrproject-rtos/cmsis_6")
        );
        assert_eq!(
            github_url("pkg:github/a/b").as_deref(),
            Some("https://github.com/a/b")
        );
        assert_eq!(github_url("pkg:github/a@1"), None);
        assert_eq!(github_url("pkg:generic/a@1"), None);
        assert_eq!(github_url("pkg:github//b@1"), None);
    }
}
