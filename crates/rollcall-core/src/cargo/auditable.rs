//! A reader for the `.dep-v0` section `cargo auditable` embeds in a binary.
//!
//! The section holds the zlib-compressed JSON dependency list of exactly the crates that went
//! into the binary. It is extracted, decompressed and parsed by `auditable-info`, the
//! reference implementation from the `cargo auditable` project, with a bound on the
//! decompressed size (so a zip bomb is an error, not an allocation failure); rollcall then
//! checks there is exactly one root package. Every failure is an [`AuditableError`]; nothing
//! here panics on malformed input.

use auditable_info::Error as InfoError;
use serde::Deserialize;

/// The largest decompressed `.dep-v0` JSON accepted: 8 MiB, `auditable-info`'s default.
pub const MAX_DECOMPRESSED_BYTES: usize = 8 * 1024 * 1024;

/// The largest binary read: 512 MiB.
pub const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Why a binary's `.dep-v0` section could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditableError {
    /// The binary has no `.dep-v0` section.
    #[error("no .dep-v0 section: the binary was not built with `cargo auditable`")]
    NoAuditData,
    /// The binary is larger than [`MAX_BINARY_BYTES`].
    #[error("the binary is larger than {MAX_BINARY_BYTES} bytes")]
    BinaryTooLarge,
    /// The decompressed section is larger than [`MAX_DECOMPRESSED_BYTES`].
    #[error("the .dep-v0 section decompresses to more than {MAX_DECOMPRESSED_BYTES} bytes")]
    TooLarge,
    /// The file is not an object file `cargo auditable` writes to, or is truncated.
    #[error("not a readable object file: {0}")]
    NotAnObjectFile(String),
    /// The section is not valid zlib data.
    #[error("the .dep-v0 section is not valid zlib data: {0}")]
    Inflate(String),
    /// The decompressed section is not the expected JSON.
    #[error("the .dep-v0 section is not valid audit data: {0}")]
    Json(String),
    /// No package is marked `root`.
    #[error("the .dep-v0 section marks no package as the root")]
    NoRoot,
    /// More than one package is marked `root`.
    #[error("the .dep-v0 section marks {0} packages as the root")]
    MultipleRoots(usize),
}

/// The dependency list from a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepV0 {
    /// The packages, in the section's order.
    pub packages: Vec<DepPackage>,
}

impl DepV0 {
    /// The root package (the binary's own crate).
    pub fn root(&self) -> Option<&DepPackage> {
        self.packages.iter().find(|p| p.root)
    }
}

/// One package in `.dep-v0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepPackage {
    /// The crate name.
    pub name: String,
    /// The crate version.
    pub version: String,
    /// Where it came from.
    pub source: DepSource,
    /// Whether it was built for the target (`runtime`) or only for the build (`build`).
    pub kind: DepKind,
    /// Indices into [`DepV0::packages`] of what it depends on.
    pub dependencies: Vec<usize>,
    /// Whether it is the binary's own crate.
    pub root: bool,
}

/// A `.dep-v0` package source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepSource {
    /// crates.io.
    CratesIo,
    /// A git repository (`.dep-v0` records no URL or revision).
    Git,
    /// A path dependency or the root.
    Local,
    /// Another registry (no URL recorded).
    Registry,
    /// Something else, as written.
    Other(String),
}

impl DepSource {
    /// The class name, as [`SourceKind::class`](super::metadata::SourceKind::class) gives it
    /// for metadata (`Other` keeps its own text).
    pub fn class(&self) -> &str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Git => "git",
            Self::Local => "local",
            Self::Registry => "registry",
            Self::Other(other) => other,
        }
    }
}

/// The kind of a `.dep-v0` package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    /// Built for the target and linked (the default).
    Runtime,
    /// Built only for the host during the build (build scripts, proc macros).
    Build,
}

#[derive(Deserialize)]
struct RawDepV0 {
    packages: Vec<RawPackage>,
}

#[derive(Deserialize)]
struct RawPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    dependencies: Vec<usize>,
    #[serde(default)]
    root: bool,
}

/// Reads the `.dep-v0` section of `binary`.
pub fn read(binary: &[u8]) -> Result<DepV0, AuditableError> {
    if u64::try_from(binary.len()).map_or(true, |len| len > MAX_BINARY_BYTES) {
        return Err(AuditableError::BinaryTooLarge);
    }
    let json =
        auditable_info::json_from_slice(binary, MAX_DECOMPRESSED_BYTES).map_err(|e| match e {
            InfoError::NoAuditData => AuditableError::NoAuditData,
            InfoError::InputLimitExceeded => AuditableError::BinaryTooLarge,
            InfoError::OutputLimitExceeded => AuditableError::TooLarge,
            InfoError::BinaryParsing(e) => AuditableError::NotAnObjectFile(e.to_string()),
            InfoError::Decompression(e) => AuditableError::Inflate(e.to_string()),
            InfoError::Utf8(e) => AuditableError::Json(e.to_string()),
            InfoError::Io(e) => AuditableError::NotAnObjectFile(e.to_string()),
        })?;
    parse_json(&json)
}

/// Parses decompressed `.dep-v0` JSON (what `rust-audit-info` prints).
pub fn parse_json(json: &str) -> Result<DepV0, AuditableError> {
    let raw: RawDepV0 =
        serde_json::from_str(json).map_err(|e| AuditableError::Json(e.to_string()))?;
    let count = raw.packages.len();
    let mut packages = Vec::with_capacity(count);
    for p in raw.packages {
        if let Some(bad) = p.dependencies.iter().find(|&&i| i >= count) {
            return Err(AuditableError::Json(format!(
                "package {}@{} depends on index {bad}, but there are {count} packages",
                p.name, p.version
            )));
        }
        let source = match p.source.as_deref() {
            Some("crates.io") => DepSource::CratesIo,
            Some("git") => DepSource::Git,
            Some("local") => DepSource::Local,
            Some("registry") => DepSource::Registry,
            Some(other) => DepSource::Other(other.to_owned()),
            None => {
                return Err(AuditableError::Json(format!(
                    "package {}@{} has no source",
                    p.name, p.version
                )));
            }
        };
        let kind = match p.kind.as_deref() {
            None | Some("runtime") => DepKind::Runtime,
            Some("build") => DepKind::Build,
            Some(other) => {
                return Err(AuditableError::Json(format!(
                    "package {}@{} has unknown kind {other:?}",
                    p.name, p.version
                )));
            }
        };
        packages.push(DepPackage {
            name: p.name,
            version: p.version,
            source,
            kind,
            dependencies: p.dependencies,
            root: p.root,
        });
    }
    match packages.iter().filter(|p| p.root).count() {
        0 => Err(AuditableError::NoRoot),
        1 => Ok(DepV0 { packages }),
        n => Err(AuditableError::MultipleRoots(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage_are_errors() {
        assert!(read(b"").is_err());
        assert!(read(b"not an object file at all").is_err());
        // An ELF header, truncated.
        let mut elf = b"\x7fELF\x01\x01\x01\x00".to_vec();
        elf.resize(100, 0);
        assert!(read(&elf).is_err());
    }

    #[test]
    fn json_forms() {
        let ok = parse_json(
            r#"{"packages":[{"name":"a","version":"1.0.0","source":"crates.io","kind":"build"},
                {"name":"app","version":"0.1.0","source":"local","dependencies":[0],"root":true},
                {"name":"g","version":"0.2.0","source":"git"}],"format":1}"#,
        )
        .unwrap();
        assert_eq!(ok.root().unwrap().name, "app");
        assert_eq!(ok.packages[0].kind, DepKind::Build);
        assert_eq!(ok.packages[2].kind, DepKind::Runtime);
        assert_eq!(ok.packages[2].source, DepSource::Git);
        for bad in [
            "",
            "{}",
            "[]",
            r#"{"packages": 1}"#,
            r#"{"packages":[{"name":"a","version":"1","source":"local"}]}"#,
            r#"{"packages":[{"name":"a","version":"1","source":"local","root":true},{"name":"b","version":"1","source":"local","root":true}]}"#,
            r#"{"packages":[{"name":"a","version":"1","source":"local","root":true,"dependencies":[5]}]}"#,
            r#"{"packages":[{"name":"a","version":"1","root":true}]}"#,
            r#"{"packages":[{"name":"a","version":"1","source":"local","root":true,"kind":"dev"}]}"#,
            r#"{"packages":[{"name":"a","version":1,"source":"local","root":true}]}"#,
            r#"{"packages":[{"name":"a","version":"1","source":"local","root":true,"dependencies":[-1]}]}"#,
        ] {
            assert!(parse_json(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn no_audit_data_message_names_cargo_auditable() {
        let e = AuditableError::NoAuditData;
        assert!(e.to_string().contains("cargo auditable"));
    }

    mod props {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let _ = read(&bytes);
            }

            #[test]
            fn arbitrary_json_never_panics(text in ".{0,300}") {
                let _ = parse_json(&text);
            }

            #[test]
            fn arbitrary_bytes_after_an_elf_magic_never_panic(
                tail in proptest::collection::vec(any::<u8>(), 0..2048)
            ) {
                let mut bytes = b"\x7fELF\x01\x01\x01\x00".to_vec();
                bytes.extend(tail);
                let _ = read(&bytes);
            }
        }
    }
}
