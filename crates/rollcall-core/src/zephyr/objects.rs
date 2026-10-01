//! Which Zephyr source file each object in the linker map was compiled from.
//!
//! `spdx/build.spdx` lists every library the build produced (`FileName: ./zephyr/subsys/
//! bluetooth/host/libsubsys__bluetooth__host.a`) with a `GENERATED_FROM` relationship to each
//! source file it was compiled from, in `spdx/zephyr.spdx` (`DocumentRef-zephyr:SPDXRef-File-
//! hci-core.c`). The map names each linked object as `archive(member)`, where CMake names the
//! member after its source file (`hci_core.c.obj`). Joining the two gives each archive
//! member's source path, relative to the Zephyr repository, which is what the subsystem table
//! lists. This is the only way to attribute `libzephyr.a`, which collects files from
//! `lib/os`, `subsys/logging`, `subsys/shell` and many other directories.
//!
//! Only files of the Zephyr package (`SPDXRef-zephyr-sources`) are used: module libraries
//! (`libmbedtls.a`) are compiled from module sources and belong to the module components.
//! `zephyr.spdx` names files relative to the west workspace (`./zephyr/subsys/…`); the Zephyr
//! checkout's path in the workspace is removed: the one the `west list` gives, when every
//! file of the Zephyr package is under it, else the files' common directory.
//!
//! Without `build.spdx`, an archive under `zephyr/<dir>/` (CMake's binary directory for the
//! sources in `<dir>/`) is taken to hold `<dir>/<member's source name>`; `zephyr/libzephyr.a`
//! and loose objects stay unattributed.

use std::collections::{BTreeMap, BTreeSet};

use super::spdx::SpdxDocument;
use crate::linker_map::{LinkerMap, ObjectId, ObjectUsage, normalise_path};

/// The SPDXID of the Zephyr package in `zephyr.spdx`.
const ZEPHYR_SOURCES_ID: &str = "SPDXRef-zephyr-sources";
/// The document reference `west spdx` gives `zephyr.spdx` in `build.spdx`.
const ZEPHYR_DOCUMENT_REF: &str = "DocumentRef-zephyr";
/// CMake's binary directory for Zephyr's own libraries, relative to the build directory.
const ZEPHYR_BINARY_DIR: &str = "zephyr/";

/// A source file an object may have been compiled from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Source {
    /// The path relative to the Zephyr repository, e.g. `subsys/bluetooth/host/hci_core.c`.
    pub path: String,
    /// The line of the `GENERATED_FROM` relationship in `build.spdx`, when attributed by it.
    pub line: Option<u32>,
}

/// An object of the map and the Zephyr sources it may have been compiled from.
#[derive(Debug, Clone)]
pub(super) struct Object<'m> {
    /// The object.
    pub id: &'m ObjectId,
    /// What the map says about it.
    pub usage: &'m ObjectUsage,
    /// The candidate sources: none (unattributed: not Zephyr code, or unknown), one, or
    /// several when the archive has more than one source of that file name.
    pub sources: Vec<Source>,
}

/// Each archive's Zephyr sources, keyed by the archive's normalised build-relative path.
type ArchiveSources = BTreeMap<String, Vec<Source>>;

/// The Zephyr package's files: SPDXID → path relative to the Zephyr repository. `zephyr_dir`
/// is the Zephyr checkout's path in the workspace, if known.
fn zephyr_files<'d>(
    zephyr_spdx: &'d SpdxDocument,
    zephyr_dir: Option<&str>,
) -> BTreeMap<&'d str, String> {
    let Some(package) = zephyr_spdx.package_by_id(ZEPHYR_SOURCES_ID) else {
        return BTreeMap::new();
    };
    let ids: BTreeSet<&str> = package.file_ids.iter().map(String::as_str).collect();
    let files: Vec<(&str, String)> = zephyr_spdx
        .files
        .iter()
        .filter(|f| ids.contains(f.spdx_id.as_str()))
        .map(|f| (f.spdx_id.as_str(), normalise_path(&f.name)))
        .collect();
    // The common directory prefix: the Zephyr checkout's path in the workspace.
    let mut prefix: Option<Vec<&str>> = None;
    for (_, path) in &files {
        let mut dirs: Vec<&str> = path.split('/').collect();
        dirs.pop();
        prefix = Some(match prefix {
            None => dirs,
            Some(common) => common
                .iter()
                .zip(&dirs)
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| *a)
                .collect(),
        });
    }
    let common = prefix.map_or(0, |p| p.len());
    // The west list's path, when it holds every file.
    let known = zephyr_dir
        .map(normalise_path)
        .filter(|dir| !dir.is_empty() && dir != "..")
        .filter(|dir| {
            files.iter().all(|(_, path)| {
                path.strip_prefix(dir.as_str())
                    .is_some_and(|r| r.starts_with('/'))
            })
        })
        .map(|dir| dir.split('/').count());
    let depth = known.unwrap_or(common);
    files
        .iter()
        .map(|(id, path)| {
            let relative = path.split('/').skip(depth).collect::<Vec<_>>().join("/");
            (*id, relative)
        })
        .collect()
}

/// Each archive in `build.spdx` → the Zephyr sources it was generated from.
fn archive_sources(
    build_spdx: &SpdxDocument,
    zephyr_spdx: &SpdxDocument,
    zephyr_dir: Option<&str>,
) -> ArchiveSources {
    let files = zephyr_files(zephyr_spdx, zephyr_dir);
    // `zephyr.spdx`'s reference in `build.spdx`: the one with its namespace, else the name
    // `west spdx` uses.
    let document_ref = build_spdx
        .external_document_refs
        .iter()
        .find(|r| r.namespace == zephyr_spdx.namespace)
        .map_or(ZEPHYR_DOCUMENT_REF, |r| r.id.as_str());
    let names: BTreeMap<&str, String> = build_spdx
        .files
        .iter()
        .map(|f| (f.spdx_id.as_str(), normalise_path(&f.name)))
        .collect();
    let mut out: ArchiveSources = BTreeMap::new();
    for relationship in &build_spdx.relationships {
        if relationship.kind != "GENERATED_FROM"
            || relationship.subject.document.is_some()
            || relationship.object.document.as_deref() != Some(document_ref)
        {
            continue;
        }
        let (Some(archive), Some(path)) = (
            names.get(relationship.subject.id.as_str()),
            files.get(relationship.object.id.as_str()),
        ) else {
            continue;
        };
        out.entry(archive.clone()).or_default().push(Source {
            path: path.clone(),
            line: Some(relationship.line),
        });
    }
    for sources in out.values_mut() {
        sources.sort();
        sources.dedup_by(|a, b| a.path == b.path);
    }
    out
}

/// The file name of a `/`-separated path.
fn file_name(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}

/// The source `id` would be under CMake's layout: `zephyr/<dir>/lib<x>.a(<name>.obj)` →
/// `<dir>/<name>`. The layout mirrors the source tree for `zephyr_library()` directories
/// (`subsys/…`, `drivers/…`, `lib/…`), but not everywhere: Zephyr adds `arch/` and `soc/`
/// with an explicit binary directory, so their libraries sit under `zephyr/arch/arch/<arch>/…`
/// and `zephyr/soc/soc/<soc>/…`. Those give paths such as `arch/arch/arm/core/x.c` that no
/// table entry lists, so they stay in the `zephyr` package, which is where they belong.
fn layout_source(id: &ObjectId) -> Option<Source> {
    let archive = id.archive.as_deref()?;
    let dir = archive.strip_prefix(ZEPHYR_BINARY_DIR)?.rsplit_once('/')?.0;
    Some(Source {
        path: format!("{dir}/{}", id.source_name()),
        line: None,
    })
}

/// Every object of `map` with the Zephyr sources it may have been compiled from, in
/// [`ObjectId`] order.
pub(super) fn attribute<'m>(
    map: &'m LinkerMap,
    build_spdx: Option<&SpdxDocument>,
    zephyr_spdx: &SpdxDocument,
    zephyr_dir: Option<&str>,
) -> Vec<Object<'m>> {
    let archives = build_spdx.map(|doc| archive_sources(doc, zephyr_spdx, zephyr_dir));
    map.objects()
        .map(|(id, usage)| {
            let sources = match (&archives, id.archive.as_deref()) {
                (_, None) => Vec::new(),
                (Some(archives), Some(archive)) => archives
                    .get(archive)
                    .map(|sources| {
                        sources
                            .iter()
                            .filter(|s| file_name(&s.path) == id.source_name())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
                (None, Some(_)) => layout_source(id).into_iter().collect(),
            };
            Object { id, usage, sources }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker_map;
    use crate::zephyr::spdx;

    const ZEPHYR_SPDX: &str = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: zephyr-sources
DocumentNamespace: http://spdx.org/spdxdocs/x/zephyr

PackageName: zephyr-sources
SPDXID: SPDXRef-zephyr-sources
PackageDownloadLocation: NOASSERTION

FileName: ./zephyr/subsys/bluetooth/host/hci_core.c
SPDXID: SPDXRef-File-hci-core.c

FileName: ./zephyr/subsys/logging/log_core.c
SPDXID: SPDXRef-File-log-core.c

FileName: ./zephyr/lib/os/sem.c
SPDXID: SPDXRef-File-sem.c

FileName: ./zephyr/kernel/sem.c
SPDXID: SPDXRef-File-sem.c-1

PackageName: mbedtls-sources
SPDXID: SPDXRef-mbedtls-sources
PackageDownloadLocation: NOASSERTION

FileName: ./modules/crypto/mbedtls/library/aes.c
SPDXID: SPDXRef-File-aes.c
";

    const BUILD_SPDX: &str = "\
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: build
DocumentNamespace: http://spdx.org/spdxdocs/x/build
ExternalDocumentRef: DocumentRef-zephyr http://spdx.org/spdxdocs/x/zephyr SHA1: 0000000000000000000000000000000000000000

PackageName: zephyr
SPDXID: SPDXRef-zephyr
PackageDownloadLocation: NOASSERTION

FileName: ./zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a
SPDXID: SPDXRef-File-libsubsys--bluetooth--host.a

FileName: ./zephyr/libzephyr.a
SPDXID: SPDXRef-File-libzephyr.a

FileName: ./modules/mbedtls/libmbedtls.a
SPDXID: SPDXRef-File-libmbedtls.a

Relationship: SPDXRef-File-libsubsys--bluetooth--host.a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-hci-core.c
Relationship: SPDXRef-File-libzephyr.a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-log-core.c
Relationship: SPDXRef-File-libzephyr.a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-sem.c
Relationship: SPDXRef-File-libzephyr.a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-sem.c-1
Relationship: SPDXRef-File-libmbedtls.a GENERATED_FROM DocumentRef-zephyr:SPDXRef-File-aes.c
";

    const MAP: &str = "\
Linker script and memory map

text            0x00001000      0x400
 .text.a        0x00001000       0x10 zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)
 .text.b        0x00001010       0x10 zephyr/libzephyr.a(log_core.c.obj)
 .text.c        0x00001020       0x10 zephyr/libzephyr.a(sem.c.obj)
 .text.d        0x00001030       0x10 modules/mbedtls/libmbedtls.a(aes.c.obj)
 .text.e        0x00001040       0x10 zephyr/CMakeFiles/x.dir/isr_tables.c.obj
";

    fn sources<'a>(objects: &'a [Object<'_>], member: &str) -> Vec<&'a str> {
        objects
            .iter()
            .find(|o| o.id.member == member)
            .map(|o| o.sources.iter().map(|s| s.path.as_str()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn member_resolves_to_dir_via_build_spdx() {
        let map = linker_map::parse(MAP).unwrap();
        let zephyr = spdx::parse(ZEPHYR_SPDX).unwrap();
        let build = spdx::parse(BUILD_SPDX).unwrap();
        let objects = attribute(&map, Some(&build), &zephyr, None);
        assert_eq!(
            sources(&objects, "hci_core.c.obj"),
            ["subsys/bluetooth/host/hci_core.c"]
        );
        // A libzephyr.a member, only attributable through build.spdx.
        assert_eq!(
            sources(&objects, "log_core.c.obj"),
            ["subsys/logging/log_core.c"]
        );
        let hci = objects
            .iter()
            .find(|o| o.id.member == "hci_core.c.obj")
            .unwrap();
        assert_eq!(hci.sources.first().and_then(|s| s.line), Some(21));
        // A loose object is unattributed.
        assert!(sources(&objects, "zephyr/CMakeFiles/x.dir/isr_tables.c.obj").is_empty());
    }

    #[test]
    fn ambiguous_basename_keeps_all_candidates() {
        let map = linker_map::parse(MAP).unwrap();
        let zephyr = spdx::parse(ZEPHYR_SPDX).unwrap();
        let build = spdx::parse(BUILD_SPDX).unwrap();
        let objects = attribute(&map, Some(&build), &zephyr, None);
        assert_eq!(
            sources(&objects, "sem.c.obj"),
            ["kernel/sem.c", "lib/os/sem.c"]
        );
    }

    #[test]
    fn module_sources_are_excluded() {
        let map = linker_map::parse(MAP).unwrap();
        let zephyr = spdx::parse(ZEPHYR_SPDX).unwrap();
        let build = spdx::parse(BUILD_SPDX).unwrap();
        let objects = attribute(&map, Some(&build), &zephyr, None);
        // aes.c is in the mbedtls package, not Zephyr's.
        assert!(sources(&objects, "aes.c.obj").is_empty());
    }

    #[test]
    fn cmake_layout_fallback_without_build_spdx() {
        let map = linker_map::parse(MAP).unwrap();
        let zephyr = spdx::parse(ZEPHYR_SPDX).unwrap();
        let objects = attribute(&map, None, &zephyr, None);
        assert_eq!(
            sources(&objects, "hci_core.c.obj"),
            ["subsys/bluetooth/host/hci_core.c"]
        );
        // libzephyr.a and module archives outside zephyr/ stay unattributed.
        assert!(sources(&objects, "log_core.c.obj").is_empty());
        assert!(sources(&objects, "aes.c.obj").is_empty());
        let hci = objects
            .iter()
            .find(|o| o.id.member == "hci_core.c.obj")
            .unwrap();
        assert_eq!(hci.sources.first().and_then(|s| s.line), None);
    }

    #[test]
    fn workspace_prefix_is_the_common_directory() {
        let nested = ZEPHYR_SPDX.replace("./zephyr/", "./deps/zephyr/");
        let zephyr = spdx::parse(&nested).unwrap();
        let files = zephyr_files(&zephyr, None);
        assert_eq!(
            files.get("SPDXRef-File-log-core.c").map(String::as_str),
            Some("subsys/logging/log_core.c")
        );
        // Module files are not the Zephyr package's.
        assert!(!files.contains_key("SPDXRef-File-aes.c"));
    }

    #[test]
    fn west_list_path_of_zephyr_is_used_when_it_holds_every_file() {
        // Every Zephyr file here is under `zephyr/subsys/`, so the common directory is
        // `zephyr/subsys`; the west list's `zephyr` is right.
        let narrow = ZEPHYR_SPDX
            .replace("./zephyr/lib/os/sem.c", "./zephyr/subsys/os/sem.c")
            .replace("./zephyr/kernel/sem.c", "./zephyr/subsys/kernel/sem.c");
        let zephyr = spdx::parse(&narrow).unwrap();
        let path = |dir| {
            zephyr_files(&zephyr, dir)
                .get("SPDXRef-File-log-core.c")
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(path(None), "logging/log_core.c");
        assert_eq!(path(Some("zephyr")), "subsys/logging/log_core.c");
        assert_eq!(path(Some("./zephyr/")), "subsys/logging/log_core.c");
        // A path that does not hold every file (e.g. a T2 manifest repository) is ignored.
        assert_eq!(path(Some("app")), "logging/log_core.c");
        assert_eq!(path(Some("zephyr/subsys/logging")), "logging/log_core.c");
    }
}
