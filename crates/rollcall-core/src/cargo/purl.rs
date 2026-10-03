//! Package URLs for crates.
//!
//! | Source | purl |
//! |--------|------|
//! | crates.io | `pkg:cargo/<name>@<version>` |
//! | another registry | `pkg:cargo/<name>@<version>?repository_url=<index URL>` |
//! | git | `pkg:generic/<name>@<version>?vcs_url=git%2B<url>%40<commit>` (the qualifier value percent-encoded, `/` as `%2F`, as the purl spec's canonical form); without a full 40-hex commit, `vcs_url` has no `@<commit>` |
//! | crate known only from `.dep-v0`, from an alternative registry | `pkg:generic/<name>@<version>` (`.dep-v0` records no registry URL, and a bare `pkg:cargo` means crates.io) |
//! | path (and the root package) | `pkg:generic/<name>@<version>`, with no host path |

use packageurl::PackageUrl;

use super::auditable::DepSource;
use super::metadata::SourceKind;
use crate::model::{IdError, Purl};

/// The purl of a crate from `cargo metadata`.
pub fn purl_for(name: &str, version: &str, source: &SourceKind) -> Result<Purl, IdError> {
    let built = match source {
        SourceKind::CratesIo => build("cargo", name, version, None),
        SourceKind::Registry(index) => build(
            "cargo",
            name,
            version,
            Some(("repository_url", index.clone())),
        ),
        SourceKind::Git { url, commit, .. } => {
            let vcs_url = match commit {
                Some(commit) => format!("git+{url}@{commit}"),
                None => format!("git+{url}"),
            };
            build("generic", name, version, Some(("vcs_url", vcs_url)))
        }
        SourceKind::Path => build("generic", name, version, None),
    };
    built.and_then(|text| Purl::new(&text))
}

/// The purl of a crate known only from `.dep-v0`, which records the kind of source but not
/// its URL or revision: `pkg:cargo` for crates.io, else `pkg:generic`. An alternative
/// registry's crate is not `pkg:cargo`: without a `repository_url` that would name crates.io.
pub fn purl_for_dep_v0(name: &str, version: &str, source: &DepSource) -> Result<Purl, IdError> {
    let ty = match source {
        DepSource::CratesIo => "cargo",
        DepSource::Registry | DepSource::Git | DepSource::Local | DepSource::Other(_) => "generic",
    };
    build(ty, name, version, None).and_then(|text| Purl::new(&text))
}

fn build(
    ty: &str,
    name: &str,
    version: &str,
    qualifier: Option<(&str, String)>,
) -> Result<String, IdError> {
    let err = |source| IdError::Purl {
        input: format!("pkg:{ty}/{name}@{version}"),
        source,
    };
    let mut purl = PackageUrl::new(ty, name).map_err(err)?;
    purl.with_version(version).map_err(err)?;
    if let Some((key, value)) = qualifier {
        purl.add_qualifier(key, value).map_err(err)?;
    }
    Ok(purl.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_pkg_cargo() {
        let p = purl_for("heapless", "0.5.6", &SourceKind::CratesIo).unwrap();
        assert_eq!(p.as_str(), "pkg:cargo/heapless@0.5.6");
    }

    #[test]
    fn git_is_pkg_generic_with_vcs_url_revision() {
        let p = purl_for(
            "panic-halt",
            "1.0.0",
            &SourceKind::Git {
                url: "https://github.com/korken89/panic-halt".to_owned(),
                commit: Some("5505dccc8162d36ae260a12c7d9de870fadcf783".to_owned()),
                reference: None,
            },
        )
        .unwrap();
        assert_eq!(
            p.as_str(),
            "pkg:generic/panic-halt@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fkorken89%2Fpanic-halt%405505dccc8162d36ae260a12c7d9de870fadcf783"
        );
    }

    #[test]
    fn git_without_a_full_commit_has_no_revision() {
        let p = purl_for(
            "g",
            "1.0.0",
            &SourceKind::Git {
                url: "https://github.com/o/g".to_owned(),
                commit: None,
                reference: Some("main".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(
            p.as_str(),
            "pkg:generic/g@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fo%2Fg"
        );
    }

    #[test]
    fn path_is_pkg_generic_without_host_path() {
        let p = purl_for("board-support", "0.1.0", &SourceKind::Path).unwrap();
        assert_eq!(p.as_str(), "pkg:generic/board-support@0.1.0");
    }

    #[test]
    fn alt_registry_has_repository_url() {
        let p = purl_for(
            "x",
            "1.0.0",
            &SourceKind::Registry("https://my.registry/index/".to_owned()),
        )
        .unwrap();
        assert_eq!(
            p.as_str(),
            "pkg:cargo/x@1.0.0?repository_url=https:%2F%2Fmy.registry%2Findex%2F"
        );
    }

    #[test]
    fn dep_v0_only_forms() {
        assert_eq!(
            purl_for_dep_v0("a", "1.0.0", &DepSource::CratesIo)
                .unwrap()
                .as_str(),
            "pkg:cargo/a@1.0.0"
        );
        assert_eq!(
            purl_for_dep_v0("g", "1.0.0", &DepSource::Git)
                .unwrap()
                .as_str(),
            "pkg:generic/g@1.0.0"
        );
    }

    #[test]
    fn dep_v0_alternative_registry_is_not_pkg_cargo() {
        let p = purl_for_dep_v0("x", "1.0.0", &DepSource::Registry).unwrap();
        assert_eq!(p.as_str(), "pkg:generic/x@1.0.0");
        assert!(!p.as_str().starts_with("pkg:cargo"));
    }

    #[test]
    fn odd_names_and_versions_are_errors_or_encoded_never_panics() {
        for (name, version) in [("", "1"), ("a", ""), ("a b", "1+x"), ("a/b", "1")] {
            let _ = purl_for(name, version, &SourceKind::CratesIo);
        }
        assert!(purl_for("", "1", &SourceKind::CratesIo).is_err());
    }
}
