//! SPDX 2.x tag-value parser for the documents `west spdx` writes.
//!
//! Parsing runs in two layers. [`tokenize`] turns the text into line-numbered `Tag: value`
//! records: `#` comments and blank lines are skipped, a `<text>…</text>` value may span lines,
//! and CRLF line endings are accepted. `assemble` then groups the records into the document
//! header, packages (a section starting at `PackageName`) and files (a section starting at
//! `FileName`); `Relationship` and `ExternalDocumentRef` lines are collected document-wide.
//! Tags the parser does not use are ignored.
//!
//! Nothing here panics: every malformed input is an [`SpdxError`] carrying the 1-based line.

use std::collections::BTreeMap;
use std::fmt;

/// A parsed SPDX 2.x tag-value document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdxDocument {
    /// `SPDXVersion`, e.g. `SPDX-2.3`.
    pub version: String,
    /// `DocumentName`.
    pub name: String,
    /// `DocumentNamespace`.
    pub namespace: String,
    /// The document's own `SPDXID`, normally `SPDXRef-DOCUMENT`.
    pub spdx_id: String,
    /// `Created`, if present.
    pub created: Option<String>,
    /// `ExternalDocumentRef` lines, in file order.
    pub external_document_refs: Vec<ExternalDocumentRef>,
    /// Packages, in file order.
    pub packages: Vec<SpdxPackage>,
    /// Files, in file order.
    pub files: Vec<SpdxFile>,
    /// Every `Relationship` line, in file order.
    pub relationships: Vec<Relationship>,
}

/// An `ExternalDocumentRef: DocumentRef-x <namespace> <algorithm>: <hex>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDocumentRef {
    /// The `DocumentRef-…` identifier.
    pub id: String,
    /// The referenced document's namespace URI.
    pub namespace: String,
    /// The referenced document's checksum.
    pub checksum: Checksum,
    /// The 1-based line.
    pub line: u32,
}

/// A package section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdxPackage {
    /// `PackageName`.
    pub name: String,
    /// `SPDXID`.
    pub spdx_id: String,
    /// The line of `PackageName`.
    pub line: u32,
    /// `PackageVersion`.
    pub version: Option<String>,
    /// `PackageDownloadLocation`.
    pub download_location: Option<String>,
    /// `PackageSupplier`, when it names an organisation, person or tool.
    pub supplier: Option<SpdxActor>,
    /// `PackageLicenseConcluded`.
    pub license_concluded: Option<String>,
    /// `PackageLicenseDeclared`.
    pub license_declared: Option<String>,
    /// Every `PackageLicenseInfoFromFiles`.
    pub license_info_from_files: Vec<String>,
    /// `FilesAnalyzed`, when it is `true` or `false`.
    pub files_analyzed: Option<bool>,
    /// `PackageVerificationCode`.
    pub verification_code: Option<String>,
    /// `PrimaryPackagePurpose`.
    pub primary_purpose: Option<String>,
    /// Every `ExternalRef`, in file order.
    pub external_refs: Vec<ExternalRef>,
    /// `PackageComment`.
    pub comment: Option<String>,
    /// The `SPDXID`s of the files that follow this package, in file order.
    pub file_ids: Vec<String>,
    /// The first line of each tag seen in this section.
    tag_lines: BTreeMap<String, u32>,
}

impl SpdxPackage {
    fn new(name: String, line: u32) -> Self {
        Self {
            name,
            spdx_id: String::new(),
            line,
            version: None,
            download_location: None,
            supplier: None,
            license_concluded: None,
            license_declared: None,
            license_info_from_files: Vec::new(),
            files_analyzed: None,
            verification_code: None,
            primary_purpose: None,
            external_refs: Vec::new(),
            comment: None,
            file_ids: Vec::new(),
            tag_lines: BTreeMap::new(),
        }
    }

    /// The first `ExternalRef` with this category and type (e.g. `PACKAGE-MANAGER`, `purl`).
    pub fn external_ref(&self, category: &str, ref_type: &str) -> Option<&ExternalRef> {
        self.external_refs
            .iter()
            .find(|r| r.category == category && r.ref_type == ref_type)
    }

    /// The 1-based line of the first occurrence of `tag` in this package's section.
    pub fn line_of(&self, tag: &str) -> Option<u32> {
        self.tag_lines.get(tag).copied()
    }
}

/// An `ExternalRef: <category> <type> <locator>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalRef {
    /// E.g. `PACKAGE-MANAGER` or `SECURITY`.
    pub category: String,
    /// E.g. `purl` or `cpe23Type`.
    pub ref_type: String,
    /// The reference itself, verbatim.
    pub locator: String,
    /// The 1-based line.
    pub line: u32,
}

/// A file section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdxFile {
    /// `FileName`.
    pub name: String,
    /// `SPDXID`.
    pub spdx_id: String,
    /// The line of `FileName`.
    pub line: u32,
    /// Every `FileChecksum`.
    pub checksums: Vec<Checksum>,
    /// `LicenseConcluded`.
    pub license_concluded: Option<String>,
    /// Every `LicenseInfoInFile`.
    pub license_info_in_file: Vec<String>,
    /// `FileCopyrightText`.
    pub copyright_text: Option<String>,
}

/// A checksum such as `SHA1: 30a2…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// The algorithm, e.g. `SHA1`.
    pub algorithm: String,
    /// The digest as written.
    pub hex: String,
}

/// A `Relationship: <subject> <KIND> <object>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    /// The element the relationship is about.
    pub subject: SpdxRef,
    /// E.g. `DESCRIBES`, `DEPENDENCY_OF`.
    pub kind: String,
    /// The related element.
    pub object: SpdxRef,
    /// The 1-based line.
    pub line: u32,
}

/// An element reference, optionally in another document (`DocumentRef-x:SPDXRef-y`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpdxRef {
    /// The `DocumentRef-…` prefix, if the element is in another document.
    pub document: Option<String>,
    /// The element id, e.g. `SPDXRef-zephyr-deps` (or `NONE` / `NOASSERTION`).
    pub id: String,
}

impl SpdxRef {
    fn parse(token: &str) -> Self {
        match token.split_once(':') {
            Some((document, id)) if document.starts_with("DocumentRef-") => Self {
                document: Some(document.to_owned()),
                id: id.to_owned(),
            },
            _ => Self {
                document: None,
                id: token.to_owned(),
            },
        }
    }
}

/// Who an actor field (e.g. `PackageSupplier`) names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpdxActorKind {
    /// `Organization: …`
    Organization,
    /// `Person: …`
    Person,
    /// `Tool: …`
    Tool,
}

/// An SPDX actor, e.g. `Organization: zephyrproject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpdxActor {
    /// Organisation, person or tool.
    pub kind: SpdxActorKind,
    /// The name, without any `(email)` suffix.
    pub name: String,
}

impl SpdxActor {
    fn parse(value: &str) -> Option<Self> {
        let (kind, rest) = value.split_once(':')?;
        let kind = match kind.trim() {
            "Organization" => SpdxActorKind::Organization,
            "Person" => SpdxActorKind::Person,
            "Tool" => SpdxActorKind::Tool,
            _ => return None,
        };
        let name = match rest.split_once('(') {
            Some((name, _email)) => name.trim(),
            None => rest.trim(),
        };
        if name.is_empty() {
            return None;
        }
        Some(Self {
            kind,
            name: name.to_owned(),
        })
    }
}

/// Why an SPDX document could not be parsed. Every variant with a line is 1-based.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpdxError {
    /// The input has no tag-value records at all.
    #[error("empty SPDX document")]
    Empty,
    /// A required document header tag is missing.
    #[error("missing document header tag {tag}")]
    MissingHeader {
        /// The missing tag.
        tag: &'static str,
    },
    /// `SPDXVersion` is not an SPDX 2.x version.
    #[error("line {line}: unsupported SPDXVersion {found:?} (expected SPDX-2.x)")]
    UnsupportedVersion {
        /// The line.
        line: u32,
        /// The version found.
        found: String,
    },
    /// A `<text>` value is never closed by `</text>`.
    #[error("line {line}: <text> block is not closed by </text>")]
    UnterminatedText {
        /// The line the block starts on.
        line: u32,
    },
    /// A line is not a `Tag: value` record.
    #[error("line {line}: expected `Tag: value`")]
    NoTagSeparator {
        /// The line.
        line: u32,
    },
    /// A package or file section has no `SPDXID` (typically a truncated document).
    #[error("line {line}: {tag} section has no SPDXID")]
    SectionWithoutSpdxId {
        /// The line the section starts on.
        line: u32,
        /// `PackageName` or `FileName`.
        tag: &'static str,
    },
    /// A second `SPDXID` in one section.
    #[error("line {line}: second SPDXID in one section")]
    DuplicateSpdxId {
        /// The line.
        line: u32,
    },
    /// A `Relationship` line is not `<subject> <KIND> <object>`.
    #[error("line {line}: malformed Relationship (expected `<subject> <KIND> <object>`)")]
    BadRelationship {
        /// The line.
        line: u32,
    },
    /// A checksum is not `<ALGORITHM>: <hex>`.
    #[error("line {line}: malformed checksum (expected `<ALGORITHM>: <hex>`)")]
    BadChecksum {
        /// The line.
        line: u32,
    },
    /// An `ExternalRef` or `ExternalDocumentRef` has the wrong number of fields.
    #[error("line {line}: malformed ExternalRef or ExternalDocumentRef")]
    BadExternalRef {
        /// The line.
        line: u32,
    },
}

/// One `Tag: value` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    /// The tag.
    pub tag: &'a str,
    /// The value, trimmed; for a `<text>` block, the text between the markers.
    pub value: String,
    /// The 1-based line the record starts on.
    pub line: u32,
}

fn line_number(index: usize) -> u32 {
    u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
}

/// Splits `text` into line-numbered `Tag: value` records.
pub fn tokenize(text: &str) -> Result<Vec<Record<'_>>, SpdxError> {
    let mut records = Vec::new();
    // A byte-order mark (e.g. from a Windows editor) is not part of the first tag.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split('\n').enumerate();
    while let Some((index, raw)) = lines.next() {
        let line = line_number(index);
        let content = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = content.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((tag, value)) = content.split_once(':') else {
            return Err(SpdxError::NoTagSeparator { line });
        };
        let tag = tag.trim();
        if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(SpdxError::NoTagSeparator { line });
        }
        let value = value.trim();
        let value = match value.strip_prefix("<text>") {
            None => value.to_owned(),
            Some(rest) => {
                if let Some((inside, _after)) = rest.split_once("</text>") {
                    inside.to_owned()
                } else {
                    let mut block = rest.to_owned();
                    let mut closed = false;
                    for (_, next) in lines.by_ref() {
                        let next = next.strip_suffix('\r').unwrap_or(next);
                        block.push('\n');
                        if let Some((inside, _after)) = next.split_once("</text>") {
                            block.push_str(inside);
                            closed = true;
                            break;
                        }
                        block.push_str(next);
                    }
                    if !closed {
                        return Err(SpdxError::UnterminatedText { line });
                    }
                    block
                }
            }
        };
        records.push(Record { tag, value, line });
    }
    Ok(records)
}

enum Section {
    None,
    Package(usize),
    File(usize),
}

/// Parses an SPDX 2.x tag-value document.
pub fn parse(text: &str) -> Result<SpdxDocument, SpdxError> {
    let records = tokenize(text)?;
    if records.is_empty() {
        return Err(SpdxError::Empty);
    }
    assemble(records)
}

fn assemble(records: Vec<Record<'_>>) -> Result<SpdxDocument, SpdxError> {
    let mut version: Option<(String, u32)> = None;
    let mut name = None;
    let mut namespace = None;
    let mut doc_id = None;
    let mut created = None;
    let mut external_document_refs = Vec::new();
    let mut packages: Vec<SpdxPackage> = Vec::new();
    let mut files: Vec<SpdxFile> = Vec::new();
    let mut relationships = Vec::new();
    let mut section = Section::None;
    let mut last_package: Option<usize> = None;

    for record in records {
        let Record { tag, value, line } = record;
        match tag {
            "PackageName" => {
                close(&section, &packages, &files)?;
                packages.push(SpdxPackage::new(value, line));
                let index = packages.len().saturating_sub(1);
                section = Section::Package(index);
                last_package = Some(index);
                continue;
            }
            "FileName" => {
                close(&section, &packages, &files)?;
                files.push(SpdxFile {
                    name: value,
                    spdx_id: String::new(),
                    line,
                    checksums: Vec::new(),
                    license_concluded: None,
                    license_info_in_file: Vec::new(),
                    copyright_text: None,
                });
                section = Section::File(files.len().saturating_sub(1));
                continue;
            }
            "Relationship" => {
                let fields: Vec<&str> = value.split_whitespace().collect();
                let [subject, kind, object] = fields.as_slice() else {
                    return Err(SpdxError::BadRelationship { line });
                };
                relationships.push(Relationship {
                    subject: SpdxRef::parse(subject),
                    kind: (*kind).to_owned(),
                    object: SpdxRef::parse(object),
                    line,
                });
                continue;
            }
            "ExternalDocumentRef" => {
                let fields: Vec<&str> = value.split_whitespace().collect();
                let [id, uri, algorithm, hex] = fields.as_slice() else {
                    return Err(SpdxError::BadExternalRef { line });
                };
                let algorithm = algorithm
                    .strip_suffix(':')
                    .filter(|a| !a.is_empty())
                    .ok_or(SpdxError::BadChecksum { line })?;
                external_document_refs.push(ExternalDocumentRef {
                    id: (*id).to_owned(),
                    namespace: (*uri).to_owned(),
                    checksum: Checksum {
                        algorithm: algorithm.to_owned(),
                        hex: (*hex).to_owned(),
                    },
                    line,
                });
                continue;
            }
            _ => {}
        }
        match section {
            Section::None => match tag {
                "SPDXVersion" => version = Some((value, line)),
                "DocumentName" => name = Some(value),
                "DocumentNamespace" => namespace = Some(value),
                "SPDXID" => doc_id = Some(value),
                "Created" => created = Some(value),
                _ => {}
            },
            Section::Package(index) => {
                let Some(package) = packages.get_mut(index) else {
                    continue;
                };
                package.tag_lines.entry(tag.to_owned()).or_insert(line);
                match tag {
                    "SPDXID" => {
                        if !package.spdx_id.is_empty() {
                            return Err(SpdxError::DuplicateSpdxId { line });
                        }
                        package.spdx_id = value;
                    }
                    "PackageVersion" => package.version = Some(value),
                    "PackageDownloadLocation" => package.download_location = Some(value),
                    "PackageSupplier" => package.supplier = SpdxActor::parse(&value),
                    "PackageLicenseConcluded" => package.license_concluded = Some(value),
                    "PackageLicenseDeclared" => package.license_declared = Some(value),
                    "PackageLicenseInfoFromFiles" => package.license_info_from_files.push(value),
                    "FilesAnalyzed" => {
                        package.files_analyzed = match value.as_str() {
                            "true" => Some(true),
                            "false" => Some(false),
                            _ => None,
                        }
                    }
                    "PackageVerificationCode" => package.verification_code = Some(value),
                    "PrimaryPackagePurpose" => package.primary_purpose = Some(value),
                    "PackageComment" => package.comment = Some(value),
                    "ExternalRef" => {
                        let fields: Vec<&str> = value.split_whitespace().collect();
                        let [category, ref_type, locator] = fields.as_slice() else {
                            return Err(SpdxError::BadExternalRef { line });
                        };
                        package.external_refs.push(ExternalRef {
                            category: (*category).to_owned(),
                            ref_type: (*ref_type).to_owned(),
                            locator: (*locator).to_owned(),
                            line,
                        });
                    }
                    _ => {}
                }
            }
            Section::File(index) => {
                let Some(file) = files.get_mut(index) else {
                    continue;
                };
                match tag {
                    "SPDXID" => {
                        if !file.spdx_id.is_empty() {
                            return Err(SpdxError::DuplicateSpdxId { line });
                        }
                        if let Some(package) = last_package.and_then(|i| packages.get_mut(i)) {
                            package.file_ids.push(value.clone());
                        }
                        file.spdx_id = value;
                    }
                    "FileChecksum" => {
                        let (algorithm, hex) = value
                            .split_once(':')
                            .map(|(a, h)| (a.trim(), h.trim()))
                            .filter(|(a, h)| !a.is_empty() && !h.is_empty())
                            .ok_or(SpdxError::BadChecksum { line })?;
                        file.checksums.push(Checksum {
                            algorithm: algorithm.to_owned(),
                            hex: hex.to_owned(),
                        });
                    }
                    "LicenseConcluded" => file.license_concluded = Some(value),
                    "LicenseInfoInFile" => file.license_info_in_file.push(value),
                    "FileCopyrightText" => file.copyright_text = Some(value),
                    _ => {}
                }
            }
        }
    }
    close(&section, &packages, &files)?;

    let (version, version_line) = version.ok_or(SpdxError::MissingHeader { tag: "SPDXVersion" })?;
    if !version.starts_with("SPDX-2.") {
        return Err(SpdxError::UnsupportedVersion {
            line: version_line,
            found: version,
        });
    }
    Ok(SpdxDocument {
        version,
        name: name.ok_or(SpdxError::MissingHeader {
            tag: "DocumentName",
        })?,
        namespace: namespace.ok_or(SpdxError::MissingHeader {
            tag: "DocumentNamespace",
        })?,
        spdx_id: doc_id.ok_or(SpdxError::MissingHeader { tag: "SPDXID" })?,
        created,
        external_document_refs,
        packages,
        files,
        relationships,
    })
}

/// Checks that the section being closed got an `SPDXID`.
fn close(section: &Section, packages: &[SpdxPackage], files: &[SpdxFile]) -> Result<(), SpdxError> {
    match *section {
        Section::None => Ok(()),
        Section::Package(index) => match packages.get(index) {
            Some(p) if p.spdx_id.is_empty() => Err(SpdxError::SectionWithoutSpdxId {
                line: p.line,
                tag: "PackageName",
            }),
            _ => Ok(()),
        },
        Section::File(index) => match files.get(index) {
            Some(f) if f.spdx_id.is_empty() => Err(SpdxError::SectionWithoutSpdxId {
                line: f.line,
                tag: "FileName",
            }),
            _ => Ok(()),
        },
    }
}

impl SpdxDocument {
    /// The package with this `SPDXID`.
    pub fn package_by_id(&self, spdx_id: &str) -> Option<&SpdxPackage> {
        self.packages.iter().find(|p| p.spdx_id == spdx_id)
    }

    /// The package with this `PackageName`.
    pub fn package_by_name(&self, name: &str) -> Option<&SpdxPackage> {
        self.packages.iter().find(|p| p.name == name)
    }
}

/// `None` for an absent value and for SPDX's `NOASSERTION` / `NONE`, else the value.
pub fn assertion(value: Option<&str>) -> Option<&str> {
    match value {
        None | Some("NOASSERTION" | "NONE" | "") => None,
        Some(v) => Some(v),
    }
}

/// A VCS download location such as `git+https://github.com/org/repo@<rev>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcsLocation {
    /// The VCS tool, e.g. `git`.
    pub scheme: String,
    /// The repository URL, e.g. `https://github.com/org/repo`.
    pub url: String,
    /// The revision after `@`, if any.
    pub revision: Option<String>,
}

impl fmt::Display for VcsLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}+{}", self.scheme, self.url)?;
        if let Some(revision) = &self.revision {
            write!(f, "@{revision}")?;
        }
        Ok(())
    }
}

/// Splits a `<vcs>+<url>[@<revision>][#<subpath>]` download location. `None` for
/// `NOASSERTION`, `NONE` and anything that is not in that form.
pub fn parse_download_location(value: &str) -> Option<VcsLocation> {
    let value = assertion(Some(value.trim()))?;
    let value = value.split_once('#').map_or(value, |(v, _)| v);
    let (scheme, rest) = value.split_once('+')?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let (_transport, after_scheme) = rest.split_once("://")?;
    // The revision is after the last `@` in the path, not an `@` in the authority.
    let path_start = after_scheme
        .find('/')
        .map_or(rest.len(), |slash| rest.len() - after_scheme.len() + slash);
    let (url, revision) = match rest.rfind('@') {
        Some(at) if at > path_start => {
            let url = rest.get(..at)?;
            let revision = rest.get(at + 1..)?;
            (url, (!revision.is_empty()).then(|| revision.to_owned()))
        }
        _ => (rest, None),
    };
    if url.is_empty() {
        return None;
    }
    Some(VcsLocation {
        scheme: scheme.to_owned(),
        url: url.to_owned(),
        revision,
    })
}

/// `SPDXRef-hal-nordic-sources` → `hal-nordic`: the id without `SPDXRef-` and without a
/// `-sources` or `-deps` suffix. `None` if the id does not start with `SPDXRef-`.
pub fn spdx_id_stem(spdx_id: &str) -> Option<&str> {
    let rest = spdx_id.strip_prefix("SPDXRef-")?;
    Some(
        rest.strip_suffix("-sources")
            .or_else(|| rest.strip_suffix("-deps"))
            .unwrap_or(rest),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const HEADER: &str = "SPDXVersion: SPDX-2.3\n\
        DataLicense: CC0-1.0\n\
        SPDXID: SPDXRef-DOCUMENT\n\
        DocumentName: sample\n\
        DocumentNamespace: http://spdx.org/spdxdocs/sample\n\
        Creator: Tool: hand-written\n\
        Created: 2026-01-02T03:04:05Z\n";

    const SAMPLE: &str = "SPDXVersion: SPDX-2.3\n\
        DataLicense: CC0-1.0\n\
        SPDXID: SPDXRef-DOCUMENT\n\
        DocumentName: sample\n\
        DocumentNamespace: http://spdx.org/spdxdocs/sample\n\
        Creator: Tool: hand-written\n\
        Created: 2026-01-02T03:04:05Z\n\
        \n\
        Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-lib-sources\n\
        \n\
        ##### Package: lib\n\
        \n\
        PackageName: lib-sources\n\
        SPDXID: SPDXRef-lib-sources\n\
        PackageLicenseConcluded: MIT\n\
        PackageDownloadLocation: git+https://github.com/org/lib@0123456789abcdef0123456789abcdef01234567\n\
        PackageVersion: 0123456789abcdef0123456789abcdef01234567\n\
        PackageSupplier: Organization: org\n\
        ExternalRef: PACKAGE-MANAGER purl pkg:github/org/lib@v1.0.0\n\
        FilesAnalyzed: true\n\
        \n\
        FileName: ./src/lib.c\n\
        SPDXID: SPDXRef-File-lib.c\n\
        FileChecksum: SHA1: 30a27a1250f071006e4a9252eca37de2d47d6854\n\
        LicenseConcluded: MIT\n\
        LicenseInfoInFile: MIT\n\
        FileCopyrightText: <text>\n \
        * Copyright (c) 2026 Org\n\
        </text>\n";

    #[test]
    fn parses_minimal_document_header_and_package() {
        let doc = parse(SAMPLE).unwrap();
        assert_eq!(doc.version, "SPDX-2.3");
        assert_eq!(doc.name, "sample");
        assert_eq!(doc.namespace, "http://spdx.org/spdxdocs/sample");
        assert_eq!(doc.spdx_id, "SPDXRef-DOCUMENT");
        assert_eq!(doc.created.as_deref(), Some("2026-01-02T03:04:05Z"));
        assert_eq!(doc.packages.len(), 1);
        let p = &doc.packages[0];
        assert_eq!(p.name, "lib-sources");
        assert_eq!(p.spdx_id, "SPDXRef-lib-sources");
        assert_eq!(p.line, 13);
        assert_eq!(p.license_concluded.as_deref(), Some("MIT"));
        assert_eq!(
            p.supplier,
            Some(SpdxActor {
                kind: SpdxActorKind::Organization,
                name: "org".into()
            })
        );
        assert_eq!(p.files_analyzed, Some(true));
        assert_eq!(p.line_of("PackageVersion"), Some(17));
        let purl = p.external_ref("PACKAGE-MANAGER", "purl").unwrap();
        assert_eq!(purl.locator, "pkg:github/org/lib@v1.0.0");
        assert_eq!(purl.line, 19);
        assert_eq!(p.file_ids, ["SPDXRef-File-lib.c"]);
        assert_eq!(doc.files.len(), 1);
        assert_eq!(doc.package_by_id("SPDXRef-lib-sources"), Some(p));
        assert_eq!(doc.package_by_name("lib-sources"), Some(p));
        assert_eq!(spdx_id_stem(&p.spdx_id), Some("lib"));
        assert_eq!(spdx_id_stem("SPDXRef-hal-nordic-deps"), Some("hal-nordic"));
        assert_eq!(spdx_id_stem("DocumentRef-x"), None);
    }

    #[test]
    fn text_block_spans_lines_and_keeps_content() {
        let doc = parse(SAMPLE).unwrap();
        assert_eq!(
            doc.files[0].copyright_text.as_deref(),
            Some("\n * Copyright (c) 2026 Org\n")
        );
        let one_line = format!(
            "{HEADER}PackageName: p\nSPDXID: SPDXRef-p\nPackageComment: <text>a: b</text>\n"
        );
        let doc = parse(&one_line).unwrap();
        assert_eq!(doc.packages[0].comment.as_deref(), Some("a: b"));
    }

    #[test]
    fn relationship_with_external_document_ref() {
        let text = format!(
            "{HEADER}ExternalDocumentRef: DocumentRef-zephyr http://spdx.org/spdxdocs/z SHA1: 1a75fb0073ce8fdad17d678df3394cedbe94371b\n\
             Relationship: SPDXRef-File-a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-b\n"
        );
        let doc = parse(&text).unwrap();
        assert_eq!(doc.external_document_refs.len(), 1);
        let edr = &doc.external_document_refs[0];
        assert_eq!(edr.id, "DocumentRef-zephyr");
        assert_eq!(edr.namespace, "http://spdx.org/spdxdocs/z");
        assert_eq!(edr.checksum.algorithm, "SHA1");
        assert_eq!(doc.relationships.len(), 1);
        let r = &doc.relationships[0];
        assert_eq!(r.subject.document, None);
        assert_eq!(r.subject.id, "SPDXRef-File-a");
        assert_eq!(r.kind, "GENERATED_FROM");
        assert_eq!(r.object.document.as_deref(), Some("DocumentRef-zephyr"));
        assert_eq!(r.object.id, "SPDXRef-File-b");
        assert_eq!(r.line, 9);
    }

    #[test]
    fn file_checksum_keeps_algorithm_and_hex() {
        let doc = parse(SAMPLE).unwrap();
        assert_eq!(
            doc.files[0].checksums,
            [Checksum {
                algorithm: "SHA1".into(),
                hex: "30a27a1250f071006e4a9252eca37de2d47d6854".into()
            }]
        );
        let bad = format!("{HEADER}FileName: f\nSPDXID: SPDXRef-f\nFileChecksum: SHA1\n");
        assert_eq!(parse(&bad), Err(SpdxError::BadChecksum { line: 10 }));
    }

    #[test]
    fn noassertion_and_none_read_as_absent() {
        assert_eq!(assertion(Some("NOASSERTION")), None);
        assert_eq!(assertion(Some("NONE")), None);
        assert_eq!(assertion(None), None);
        assert_eq!(assertion(Some("MIT")), Some("MIT"));
        assert_eq!(parse_download_location("NOASSERTION"), None);
        assert_eq!(parse_download_location("NONE"), None);
    }

    #[test]
    fn download_location_splits_url_and_revision() {
        let loc = parse_download_location(
            "git+https://github.com/zephyrproject-rtos/zephyr@dccb09599635bdff17633fa7e9dab014b91dce90",
        )
        .unwrap();
        assert_eq!(loc.scheme, "git");
        assert_eq!(loc.url, "https://github.com/zephyrproject-rtos/zephyr");
        assert_eq!(
            loc.revision.as_deref(),
            Some("dccb09599635bdff17633fa7e9dab014b91dce90")
        );
        // An `@` in the authority is not a revision.
        let ssh = parse_download_location("git+ssh://git@example.com/r.git").unwrap();
        assert_eq!(ssh.url, "ssh://git@example.com/r.git");
        assert_eq!(ssh.revision, None);
        let sub = parse_download_location("git+https://h/r@v1#sub/dir").unwrap();
        assert_eq!(sub.revision.as_deref(), Some("v1"));
        assert_eq!(sub.to_string(), "git+https://h/r@v1");
        assert_eq!(
            parse_download_location("https://example.com/x.tar.gz"),
            None
        );
        assert_eq!(parse_download_location("git+"), None);
    }

    #[test]
    fn crlf_line_endings_are_accepted() {
        let crlf = SAMPLE.replace('\n', "\r\n");
        let doc = parse(&crlf).unwrap();
        let lf = parse(SAMPLE).unwrap();
        assert_eq!(doc.packages[0].version, lf.packages[0].version);
        assert_eq!(doc.files[0].copyright_text, lf.files[0].copyright_text);
        assert_eq!(doc.relationships, lf.relationships);
    }

    #[test]
    fn unknown_tags_are_ignored() {
        let text = format!(
            "{HEADER}FutureTag: whatever\nPackageName: p\nSPDXID: SPDXRef-p\nPackageHomePage: https://x\n"
        );
        let doc = parse(&text).unwrap();
        assert_eq!(doc.packages.len(), 1);
    }

    #[test]
    fn truncated_inside_text_block_is_error_with_line() {
        let cut = SAMPLE.find(" * Copyright").unwrap();
        assert_eq!(
            parse(&SAMPLE[..cut]),
            Err(SpdxError::UnterminatedText { line: 27 })
        );
    }

    #[test]
    fn package_without_spdxid_is_error() {
        let text = format!("{HEADER}PackageName: p\nPackageVersion: 1\n");
        assert_eq!(
            parse(&text),
            Err(SpdxError::SectionWithoutSpdxId {
                line: 8,
                tag: "PackageName"
            })
        );
        let text =
            format!("{HEADER}PackageName: p\nPackageVersion: 1\nFileName: f\nSPDXID: SPDXRef-f\n");
        assert!(matches!(
            parse(&text),
            Err(SpdxError::SectionWithoutSpdxId { line: 8, .. })
        ));
        let text = format!("{HEADER}PackageName: p\nSPDXID: SPDXRef-p\nSPDXID: SPDXRef-q\n");
        assert_eq!(parse(&text), Err(SpdxError::DuplicateSpdxId { line: 10 }));
    }

    #[test]
    fn line_without_tag_separator_is_error() {
        let text = format!("{HEADER}this line has no separator\n");
        assert_eq!(parse(&text), Err(SpdxError::NoTagSeparator { line: 8 }));
        let text = format!("{HEADER}bad tag: value\n");
        assert_eq!(parse(&text), Err(SpdxError::NoTagSeparator { line: 8 }));
        let text = format!("{HEADER}Relationship: a DESCRIBES\n");
        assert_eq!(parse(&text), Err(SpdxError::BadRelationship { line: 8 }));
        let text = format!("{HEADER}PackageName: p\nSPDXID: SPDXRef-p\nExternalRef: purl only\n");
        assert_eq!(parse(&text), Err(SpdxError::BadExternalRef { line: 10 }));
    }

    #[test]
    fn missing_or_unsupported_spdx_version_is_error() {
        let text = HEADER.replace("SPDXVersion: SPDX-2.3\n", "");
        assert_eq!(
            parse(&text),
            Err(SpdxError::MissingHeader { tag: "SPDXVersion" })
        );
        let text = HEADER.replace("SPDX-2.3", "SPDX-3.0");
        assert_eq!(
            parse(&text),
            Err(SpdxError::UnsupportedVersion {
                line: 1,
                found: "SPDX-3.0".into()
            })
        );
        let text = HEADER.replace("DocumentNamespace: http://spdx.org/spdxdocs/sample\n", "");
        assert_eq!(
            parse(&text),
            Err(SpdxError::MissingHeader {
                tag: "DocumentNamespace"
            })
        );
    }

    #[test]
    fn bom_is_stripped() {
        let with_bom = format!("\u{feff}{SAMPLE}");
        assert_eq!(parse(&with_bom), parse(SAMPLE));
        assert_eq!(parse(&with_bom).unwrap().version, "SPDX-2.3");
    }

    #[test]
    fn empty_input_is_error() {
        assert_eq!(parse(""), Err(SpdxError::Empty));
        assert_eq!(parse("\n\n  \n# only a comment\n"), Err(SpdxError::Empty));
    }

    #[test]
    fn every_prefix_of_sample_parses_or_errors_without_panic() {
        for end in 0..=SAMPLE.len() {
            if let Some(prefix) = SAMPLE.get(..end) {
                let _ = parse(prefix);
            }
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse(&text);
        }

        #[test]
        fn arbitrary_tag_lines_never_panic(lines in proptest::collection::vec(
            "(SPDXVersion|SPDXID|PackageName|FileName|Relationship|ExternalRef|FileChecksum|ExternalDocumentRef|FileCopyrightText|X)?:? ?(<text>|</text>|SPDX-2.3|[a-zA-Z0-9:@+/ .-]{0,20})",
            0..30,
        )) {
            let _ = parse(&lines.join("\n"));
            let _ = parse_download_location(&lines.concat());
        }
    }
}
