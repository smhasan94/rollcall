//! Package URLs for PlatformIO projects.
//!
//! There is no registered purl type for the PlatformIO registry (`pkg:platformio` is not one),
//! and `pkg:github` is read by osv-scanner as a GitHub Action, so registry packages are
//! `pkg:generic` with the registry as `repository_url`, as rollcall writes ESP Component
//! Registry components:
//!
//! | Package | purl |
//! |---------|------|
//! | a registry library, platform or package (`.piopm` has an owner) | `pkg:generic/<owner>/<name>@<version>?repository_url=https://registry.platformio.org` |
//! | a library installed from a repository (`.piopm` `spec.uri`) | `pkg:generic/<name>@<version>?vcs_url=<uri>` (`git+` added when missing) |
//! | a library installed from an archive URL (`.zip`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar`) | `pkg:generic/<name>@<version>?download_url=<uri>` |
//! | a library installed from a local path (`file://`, `symlink://`, a path) | none (a warning: a host path is not an identifier) |
//! | anything else (no owner, no URI) | none (a warning) |
//! | a framework rollcall's table knows | the table's upstream purl, e.g. `pkg:generic/arduino-esp32@2.0.17?vcs_url=git+https://github.com/espressif/arduino-esp32` |
//!
//! A library's upstream purl, `pkg:generic/<name>@<version>?vcs_url=git+<repository>` from its
//! `library.json` `repository`, is recorded as `purl` evidence, not as the component's purl:
//! the registry's version usually equals the upstream release, but rollcall cannot check it.

use packageurl::PackageUrl;

use super::ini::{PackageSpec, parse_spec};
use crate::model::{IdError, Purl};

fn build(
    namespace: Option<&str>,
    name: &str,
    version: Option<&str>,
    qualifier: (&str, &str),
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
    purl.add_qualifier(qualifier.0, qualifier.1.to_owned())
        .map_err(err)?;
    Purl::new(&purl.to_string())
}

/// `pkg:generic/<owner>/<name>@<version>?repository_url=<registry>`.
pub fn registry_purl(
    owner: &str,
    name: &str,
    version: Option<&str>,
    registry: &str,
) -> Result<Purl, IdError> {
    build(Some(owner), name, version, ("repository_url", registry))
}

/// `url` as a purl `vcs_url`: `git+` added to a plain `https://` or `http://` URL.
pub fn vcs_url(url: &str) -> String {
    let url = url.trim();
    if url.starts_with("git+") || url.starts_with("git@") || url.starts_with("git://") {
        url.to_owned()
    } else {
        format!("git+{url}")
    }
}

/// Why a package installed from a URI has no purl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoPurl {
    /// A local path (`file://`, `symlink://`, or a path): a host path is not an identifier.
    Local,
    /// Not a URL rollcall can name.
    Unknown,
    /// The model rejected the purl built.
    Invalid(String),
}

/// The purl of a package installed from `uri` (a `.piopm` `spec.uri`, or a `platform` or
/// `platform_packages` URL): `vcs_url` for a repository, `download_url` for an archive, none
/// for a local path.
pub fn source_purl(name: &str, version: Option<&str>, uri: &str) -> Result<Purl, NoPurl> {
    let invalid = |e: IdError| NoPurl::Invalid(e.to_string());
    match parse_spec(uri) {
        PackageSpec::Vcs { url, .. } => {
            build(None, name, version, ("vcs_url", &vcs_url(&url))).map_err(invalid)
        }
        PackageSpec::Archive { url, .. } => {
            build(None, name, version, ("download_url", url.trim())).map_err(invalid)
        }
        PackageSpec::Local { .. } => Err(NoPurl::Local),
        PackageSpec::Registry { .. } | PackageSpec::Unknown(_) => Err(NoPurl::Unknown),
    }
}

/// Why a source package has no purl, for a warning (never the path itself).
pub fn no_purl_reason(why: &NoPurl) -> String {
    match why {
        NoPurl::Local => "installed from a local path, which is not an identifier".to_owned(),
        NoPurl::Unknown => "installed from a source rollcall cannot name".to_owned(),
        NoPurl::Invalid(e) => format!("its purl is invalid ({e})"),
    }
}

/// A library's upstream purl from its `library.json` repository, when that is a remote
/// repository URL (never a local path).
pub fn upstream_purl(name: &str, version: &str, repository: &str) -> Option<Purl> {
    let r = repository.trim();
    let remote = r.starts_with("https://")
        || r.starts_with("http://")
        || r.starts_with("git+https://")
        || r.starts_with("git+http://")
        || r.starts_with("git@")
        || r.starts_with("git://");
    if !remote {
        return None;
    }
    match parse_spec(r) {
        PackageSpec::Vcs { url, .. } => {
            build(None, name, Some(version), ("vcs_url", &vcs_url(&url))).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_forms() {
        assert_eq!(
            registry_purl(
                "knolleary",
                "PubSubClient",
                Some("2.8"),
                "https://registry.platformio.org"
            )
            .unwrap()
            .as_str(),
            "pkg:generic/knolleary/PubSubClient@2.8?repository_url=https:%2F%2Fregistry.platformio.org"
        );
        // A name with a space is percent-encoded.
        assert!(
            registry_purl("adafruit", "Adafruit NeoPixel", Some("1.15.1"), "https://r")
                .unwrap()
                .as_str()
                .starts_with("pkg:generic/adafruit/Adafruit%20NeoPixel@1.15.1?")
        );
        assert_eq!(
            upstream_purl(
                "ArduinoJson",
                "7.2.1",
                "https://github.com/bblanchon/ArduinoJson.git"
            )
            .unwrap()
            .as_str(),
            "pkg:generic/ArduinoJson@7.2.1?vcs_url=git%2Bhttps:%2F%2Fgithub.com%2Fbblanchon%2FArduinoJson.git"
        );
        assert_eq!(upstream_purl("x", "1", "not a url"), None);
        assert_eq!(vcs_url("git+https://h/x"), "git+https://h/x");
        assert_eq!(vcs_url("git@h:x.git"), "git@h:x.git");
        assert!(
            source_purl("mylib", None, "https://github.com/me/mylib.git")
                .unwrap()
                .as_str()
                .starts_with("pkg:generic/mylib?vcs_url=git%2Bhttps")
        );
    }

    #[test]
    fn local_sources_get_no_purl_and_archives_a_download_url() {
        for local in [
            "file:///home/alice/libs/mylib",
            "symlink:///home/alice/libs/mylib",
            "/home/alice/libs/mylib",
            "../shared/mylib",
        ] {
            assert_eq!(
                source_purl("mylib", Some("1.0.0"), local),
                Err(NoPurl::Local),
                "{local}"
            );
        }
        let archive = source_purl(
            "mylib",
            Some("1.0.0"),
            "https://example.com/mylib-1.0.0.tar.gz",
        )
        .unwrap();
        assert_eq!(
            archive.as_str(),
            "pkg:generic/mylib@1.0.0?download_url=https:%2F%2Fexample.com%2Fmylib-1.0.0.tar.gz"
        );
        assert_eq!(upstream_purl("x", "1", "file:///home/alice/x"), None);
        assert_eq!(upstream_purl("x", "1", "git+file:///home/alice/x"), None);
    }
}
