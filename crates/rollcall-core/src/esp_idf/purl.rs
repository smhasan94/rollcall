//! Package URLs for ESP-IDF builds.
//!
//! There is no purl type for the ESP Component Registry, so registry components are
//! `pkg:generic` with the registry as `repository_url`:
//!
//! | Source (`dependencies.lock`) | purl |
//! |------------------------------|------|
//! | ESP-IDF itself (`idf`) | the table's template, `pkg:generic/esp-idf@<version>?vcs_url=git+https://github.com/espressif/esp-idf` |
//! | registry (`service`) | `pkg:generic/<namespace>/<name>@<version>?repository_url=<registry>` (default registry `https://components.espressif.com`; a trailing `/` is dropped) |
//! | `git` | `pkg:generic/[<namespace>/]<name>@<commit>?vcs_url=git+<url>@<commit>#<path>`; without a commit, no version and no `@<commit>` |
//! | `local`, inside the ESP-IDF tree | the `esp-idf` purl with the directory as subpath (`#examples/common_components/protocol_examples_common`) |
//! | `local` elsewhere, or an unknown type | none (a warning: a host path is not an identifier) |
//!
//! A subsystem or blob gets the `esp-idf` purl with its path in the tree as subpath.

use packageurl::PackageUrl;

use super::dependencies_lock::{LockEntry, LockSource, split_namespace};
use crate::model::{IdError, Purl};

/// The ESP Component Registry.
pub const DEFAULT_REGISTRY: &str = "https://components.espressif.com";

/// `purl` with `subpath` added; `None` when it already has one or `subpath` is not a valid
/// purl subpath.
pub fn with_subpath(purl: &Purl, subpath: &str) -> Option<Purl> {
    let mut parsed: PackageUrl<'_> = purl.as_str().parse().ok()?;
    if parsed.subpath().is_some() {
        return None;
    }
    parsed.with_subpath(subpath.to_owned()).ok()?;
    Purl::new(&parsed.to_string()).ok()
}

/// Whether `s` is a full 40-hex git commit.
pub fn is_commit(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `path` relative to `root` (both `/`-separated), when it lies strictly under it.
pub fn relative_to<'a>(path: &'a str, root: &str) -> Option<&'a str> {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return None;
    }
    path.strip_prefix(root)?
        .strip_prefix('/')
        .filter(|rest| !rest.is_empty())
}

fn build(
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifier: Option<(&str, String)>,
    subpath: Option<&str>,
) -> Result<Purl, IdError> {
    let err = |source| IdError::Purl {
        input: format!("pkg:generic/{name}"),
        source,
    };
    let mut purl = PackageUrl::new("generic", name).map_err(err)?;
    if let Some(namespace) = namespace {
        purl.with_namespace(namespace).map_err(err)?;
    }
    if let Some(version) = version {
        purl.with_version(version).map_err(err)?;
    }
    if let Some((key, value)) = qualifier {
        purl.add_qualifier(key, value).map_err(err)?;
    }
    if let Some(subpath) = subpath {
        purl.with_subpath(subpath).map_err(err)?;
    }
    Purl::new(&purl.to_string())
}

/// Why a managed component has no purl (the caller warns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoPurl {
    /// A local component outside the ESP-IDF tree.
    LocalOutsideIdf,
    /// A source type rollcall does not know.
    UnknownSource(String),
    /// The model rejected the purl built (e.g. a name it cannot hold).
    Invalid(String),
}

/// The purl of the lock entry `name`. `idf_purl` is the `esp-idf` component's purl and
/// `idf_path` the ESP-IDF tree as the build saw it (from `project_description.json`).
pub fn managed_purl(
    name: &str,
    entry: &LockEntry,
    idf_purl: Option<&Purl>,
    idf_path: Option<&str>,
) -> Result<Purl, NoPurl> {
    let invalid = |e: IdError| NoPurl::Invalid(e.to_string());
    let (namespace, short) = split_namespace(name);
    match &entry.source {
        LockSource::Service { registry_url } => {
            let registry = registry_url
                .as_deref()
                .map(|u| u.trim_end_matches('/'))
                .filter(|u| !u.is_empty())
                .unwrap_or(DEFAULT_REGISTRY);
            build(
                namespace,
                short,
                entry.version.as_deref(),
                Some(("repository_url", registry.to_owned())),
                None,
            )
            .map_err(invalid)
        }
        LockSource::Git { url, path } => {
            let commit = entry.version.as_deref().filter(|v| is_commit(v));
            let vcs_url = match commit {
                Some(commit) => format!("git+{url}@{commit}"),
                None => format!("git+{url}"),
            };
            build(
                namespace,
                short,
                commit,
                Some(("vcs_url", vcs_url)),
                path.as_deref(),
            )
            .map_err(invalid)
        }
        LockSource::Local { path } => {
            let relative = path
                .as_deref()
                .zip(idf_path)
                .and_then(|(path, root)| relative_to(path, root));
            match (relative, idf_purl) {
                (Some(relative), Some(idf)) => with_subpath(idf, relative).ok_or_else(|| {
                    NoPurl::Invalid(format!("subpath {relative:?} is not a purl subpath"))
                }),
                _ => Err(NoPurl::LocalOutsideIdf),
            }
        }
        LockSource::Idf => idf_purl.cloned().ok_or(NoPurl::LocalOutsideIdf),
        LockSource::Other(ty) => Err(NoPurl::UnknownSource(ty.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idf() -> Purl {
        Purl::new("pkg:generic/esp-idf@5.5.1?vcs_url=git+https://github.com/espressif/esp-idf")
            .unwrap()
    }

    fn entry(version: Option<&str>, source: LockSource) -> LockEntry {
        LockEntry {
            version: version.map(str::to_owned),
            component_hash: None,
            source,
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn service_sources_give_documented_purls() {
        for registry in [
            Some("https://components.espressif.com/".to_owned()),
            Some("https://components.espressif.com".to_owned()),
            None,
        ] {
            let p = managed_purl(
                "espressif/cjson",
                &entry(
                    Some("1.7.19~2"),
                    LockSource::Service {
                        registry_url: registry,
                    },
                ),
                Some(&idf()),
                Some("/opt/esp/idf"),
            )
            .unwrap();
            assert_eq!(
                p.as_str(),
                "pkg:generic/espressif/cjson@1.7.19~2?repository_url=https:%2F%2Fcomponents.espressif.com"
            );
        }
        let other = managed_purl(
            "acme/thing",
            &entry(
                Some("1.0.0"),
                LockSource::Service {
                    registry_url: Some("https://registry.example/".into()),
                },
            ),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            other.as_str(),
            "pkg:generic/acme/thing@1.0.0?repository_url=https:%2F%2Fregistry.example"
        );
    }

    #[test]
    fn git_sources_give_documented_purls() {
        let commit = "9d2c4f8c4b5f8b6a1b3e1c1f2d0a2e7b8c9d0e1f";
        let git = LockSource::Git {
            url: "https://github.com/espressif/idf-extra-components.git".into(),
            path: Some("esp_jpeg".into()),
        };
        let p = managed_purl("esp_jpeg", &entry(Some(commit), git.clone()), None, None).unwrap();
        assert_eq!(
            p.as_str(),
            format!(
                "pkg:generic/esp_jpeg@{commit}?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fidf-extra-components.git%40{commit}#esp_jpeg"
            )
        );
        // Without a full commit: no version, and the vcs_url has no revision.
        for version in [None, Some("main"), Some("9d2c4f8")] {
            let p = managed_purl("esp_jpeg", &entry(version, git.clone()), None, None).unwrap();
            assert_eq!(
                p.as_str(),
                "pkg:generic/esp_jpeg?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fidf-extra-components.git#esp_jpeg"
            );
        }
    }

    #[test]
    fn local_sources_give_documented_purls() {
        let local = |path: &str| LockSource::Local {
            path: Some(path.to_owned()),
        };
        let p = managed_purl(
            "protocol_examples_common",
            &entry(
                Some("*"),
                local("/opt/esp/idf/examples/common_components/protocol_examples_common"),
            ),
            Some(&idf()),
            Some("/opt/esp/idf/"),
        )
        .unwrap();
        assert_eq!(
            p.as_str(),
            "pkg:generic/esp-idf@5.5.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fespressif%2Fesp-idf#examples/common_components/protocol_examples_common"
        );
        for (path, idf_path) in [
            ("/home/me/components/x", Some("/opt/esp/idf")),
            ("/opt/esp/idfx/components/x", Some("/opt/esp/idf")),
            ("/opt/esp/idf", Some("/opt/esp/idf")),
            ("/opt/esp/idf/components/x", None),
        ] {
            assert_eq!(
                managed_purl("x", &entry(None, local(path)), Some(&idf()), idf_path),
                Err(NoPurl::LocalOutsideIdf),
                "{path}"
            );
        }
        assert_eq!(
            managed_purl(
                "x",
                &entry(None, LockSource::Local { path: None }),
                Some(&idf()),
                Some("/opt/esp/idf")
            ),
            Err(NoPurl::LocalOutsideIdf)
        );
    }

    #[test]
    fn idf_sources_give_documented_purls() {
        let p = managed_purl(
            "idf",
            &entry(Some("5.5.1"), LockSource::Idf),
            Some(&idf()),
            None,
        )
        .unwrap();
        assert_eq!(p, idf());
        assert_eq!(
            managed_purl(
                "x",
                &entry(None, LockSource::Other("mirror".into())),
                Some(&idf()),
                None
            ),
            Err(NoPurl::UnknownSource("mirror".into()))
        );
        let sub = with_subpath(&idf(), "components/mbedtls/mbedtls").unwrap();
        assert!(sub.as_str().ends_with("#components/mbedtls/mbedtls"));
        assert_eq!(with_subpath(&sub, "x"), None);
    }
}
