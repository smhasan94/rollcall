//! The subsystem split and blob detection: which [table](super::table) subsystems and which
//! prebuilt libraries the link map shows in the image.
//!
//! The rules (also in `docs/esp-idf.md`, *Subsystems*):
//!
//! 1. A subsystem is *enabled* when one of its table symbols is `y` or `m` in `sdkconfig`.
//!    An `sdkconfig` alone cannot say what is linked: ESP-IDF keeps a symbol such as
//!    `CONFIG_MBEDTLS_TLS_ENABLED` set in every project that builds the component.
//! 2. It is *present* when, in the link map, an object of one of its archives is linked
//!    ([`ObjectUsage::is_linked`](crate::linker_map::ObjectUsage::is_linked), the same rule
//!    as the Zephyr split) and that object is not one of its `glue` source files.
//! 3. An enabled and present subsystem is emitted. An enabled one with nothing linked, and a
//!    present one that is not enabled, are left in `esp-idf` with a [`Note`].
//! 4. A *blob* is an archive under one of the table's blob directories of the ESP-IDF tree
//!    (the map's absolute path, relative to the build's `idf_path`) with a linked object.

use std::collections::BTreeMap;

use super::sdkconfig::SdkConfig;
use super::table::{BlobDir, EspIdfTable, TableSubsystem};
use crate::linker_map::{LinkerMap, ObjectId};
use crate::zephyr::Note;

/// A subsystem the split emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSubsystem<'t> {
    /// The table entry.
    pub subsystem: &'t TableSubsystem,
    /// Each enabling symbol that is set, with its `sdkconfig` line.
    pub symbols: Vec<(&'t str, Option<u32>)>,
    /// The first linked object (in object order), cited by its build-relative archive
    /// (`esp-idf/lwip/liblwip.a(tcp.c.obj)`), never an absolute path.
    pub object: String,
    /// That line.
    pub line: u32,
}

/// A linked prebuilt library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundBlob<'t> {
    /// Its table directory.
    pub dir: &'t BlobDir,
    /// Its path relative to the ESP-IDF tree, e.g. `components/esp_wifi/lib/esp32/libpp.a`.
    pub path: String,
    /// The first linked object of it (in object order), cited relative to the ESP-IDF tree
    /// (`esp-idf/components/esp_wifi/lib/esp32/libpp.a(pp.o)`), never an absolute path.
    pub object: String,
    /// The map line that links it.
    pub line: u32,
}

/// What [`split`] found.
#[derive(Debug, Default)]
pub struct SplitOutcome<'t> {
    /// Emitted subsystems, in name order.
    pub subsystems: Vec<FoundSubsystem<'t>>,
    /// Linked blobs, in path order.
    pub blobs: Vec<FoundBlob<'t>>,
    /// Why subsystems were left in `esp-idf`, sorted.
    pub notes: Vec<Note>,
}

/// Whether the map's `archive` is the build-relative `table_archive`: equal, or, when the
/// map used absolute paths, the same file under `build_dir`.
fn is_archive(archive: &str, table_archive: &str, build_dir: Option<&str>) -> bool {
    archive == table_archive
        || build_dir
            .and_then(|b| super::purl::relative_to(archive, b))
            .is_some_and(|rel| rel == table_archive)
}

/// How evidence cites an object of `archive`: `archive(member)` with a path that does not
/// depend on where the build or the tree lives.
fn cite(archive: &str, object: &ObjectId) -> String {
    format!("{archive}({})", object.member)
}

/// Splits: see the [module docs](self). `map_location` is how notes cite the map;
/// `idf_path` and `build_dir` are the paths `project_description.json` gives.
pub fn split<'t>(
    table: &'t EspIdfTable,
    config: &SdkConfig,
    map: &LinkerMap,
    idf_path: Option<&str>,
    build_dir: Option<&str>,
    map_location: &str,
) -> SplitOutcome<'t> {
    let mut outcome = SplitOutcome::default();
    // The first linked object of each subsystem, and of each blob.
    let mut linked: BTreeMap<&str, (String, u32)> = BTreeMap::new();
    let mut blobs: BTreeMap<String, (&BlobDir, String, u32)> = BTreeMap::new();
    for (object, usage) in map.linked_objects() {
        let (Some(archive), Some(section)) = (&object.archive, usage.first_linked()) else {
            continue;
        };
        for subsystem in &table.subsystems {
            if let Some(table_archive) = subsystem
                .archives
                .iter()
                .find(|a| is_archive(archive, a, build_dir))
                && !subsystem.glue.contains(object.source_name())
            {
                linked
                    .entry(subsystem.name.as_str())
                    .or_insert_with(|| (cite(table_archive, object), section.line));
            }
        }
        if let Some(rel) = idf_path.and_then(|root| super::purl::relative_to(archive, root))
            && let Some(dir) = table.blob_dir(rel)
        {
            blobs
                .entry(rel.to_owned())
                .or_insert_with(|| (dir, cite(&format!("esp-idf/{rel}"), object), section.line));
        }
    }
    for subsystem in &table.subsystems {
        let symbols: Vec<(&str, Option<u32>)> = subsystem
            .symbols
            .iter()
            .filter(|s| config.is_set(s))
            .map(|s| (s.as_str(), config.line(s)))
            .collect();
        let found = linked.get(subsystem.name.as_str());
        match (symbols.is_empty(), found) {
            (false, Some((object, line))) => outcome.subsystems.push(FoundSubsystem {
                subsystem,
                symbols,
                object: object.clone(),
                line: *line,
            }),
            (false, None) => outcome.notes.push(Note::new(
                map_location,
                format!(
                    "subsystem {} is enabled by {} but nothing from {} was linked; not emitted",
                    subsystem.name,
                    symbols
                        .iter()
                        .map(|(s, _)| *s)
                        .collect::<Vec<_>>()
                        .join(", "),
                    subsystem.archives.join(", ")
                ),
            )),
            (true, Some((object, line))) => outcome.notes.push(Note::new(
                format!("{map_location}:{line}"),
                format!(
                    "{object} is linked, but subsystem {} is not enabled ({} not set); it stays in esp-idf",
                    subsystem.name,
                    subsystem.symbols.join(", ")
                ),
            )),
            (true, None) => {}
        }
    }
    outcome.blobs = blobs
        .into_iter()
        .map(|(path, (dir, object, line))| FoundBlob {
            dir,
            path,
            object,
            line,
        })
        .collect();
    outcome.notes.sort();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp_idf::{sdkconfig, table};
    use crate::linker_map;

    /// hello_world links only the SHA port shims of libmbedcrypto.a; the Wi-Fi build links
    /// Mbed TLS proper, lwIP, the Wi-Fi glue and two Wi-Fi blobs; liblwip.a is also linked in
    /// a build that does not enable it.
    fn map(wifi: bool) -> LinkerMap {
        let mut text = String::from(
            "Archive member included to satisfy reference by file (symbol)\n\n\
             Discarded input sections\n\n\
             Linker script and memory map\n\n\
             .flash.text     0x400d0000     0x1000\n \
             .text.a        0x400d0000       0x10 esp-idf/mbedtls/mbedtls/library/libmbedcrypto.a(esp_sha256.c.obj)\n",
        );
        if wifi {
            text.push_str(
                " .text.b        0x400d0010       0x10 esp-idf/mbedtls/mbedtls/library/libmbedtls.a(ssl_tls.c.obj)\n \
                 .text.c        0x400d0020       0x10 esp-idf/lwip/liblwip.a(tcp.c.obj)\n \
                 .text.d        0x400d0030       0x10 esp-idf/esp_wifi/libesp_wifi.a(wifi_init.c.obj)\n \
                 .text.e        0x400d0040       0x10 /opt/esp/idf/components/esp_wifi/lib/esp32/libpp.a(pp.o)\n \
                 .text.f        0x400d0050       0x10 /opt/esp/idf/components/esp_phy/lib/esp32/libphy.a(phy.o)\n \
                 .text.g        0x400d0060        0x0 /opt/esp/idf/components/esp_coex/lib/esp32/libcoexist.a(coexist.o)\n",
            );
        }
        linker_map::parse(&text).unwrap()
    }

    fn names<'a>(o: &'a SplitOutcome<'_>) -> Vec<&'a str> {
        o.subsystems
            .iter()
            .map(|s| s.subsystem.name.as_str())
            .collect()
    }

    #[test]
    fn glue_alone_does_not_make_mbedtls_present() {
        let t = table::builtin().unwrap();
        let c = sdkconfig::parse("CONFIG_MBEDTLS_TLS_ENABLED=y\n").unwrap();
        let o = split(
            &t,
            &c,
            &map(false),
            Some("/opt/esp/idf"),
            None,
            "build/x.map",
        );
        assert!(o.subsystems.is_empty());
        assert!(o.blobs.is_empty());
        assert_eq!(o.notes.len(), 1);
        assert!(
            o.notes[0]
                .message
                .contains("subsystem mbedtls is enabled by CONFIG_MBEDTLS_TLS_ENABLED")
        );
    }

    #[test]
    fn enabled_and_linked_subsystems_and_linked_blobs_are_found() {
        let t = table::builtin().unwrap();
        let c = sdkconfig::parse(
            "CONFIG_MBEDTLS_TLS_ENABLED=y\nCONFIG_ESP_WIFI_ENABLED=y\n# CONFIG_LWIP_ENABLE is not set\n",
        )
        .unwrap();
        let o = split(
            &t,
            &c,
            &map(true),
            Some("/opt/esp/idf/"),
            None,
            "build/x.map",
        );
        assert_eq!(names(&o), ["mbedtls", "wifi"]);
        let mbedtls = &o.subsystems[0];
        assert_eq!(
            mbedtls.object,
            "esp-idf/mbedtls/mbedtls/library/libmbedtls.a(ssl_tls.c.obj)"
        );
        assert_eq!(mbedtls.symbols, [("CONFIG_MBEDTLS_TLS_ENABLED", Some(1))]);
        let blobs: Vec<&str> = o.blobs.iter().map(|b| b.path.as_str()).collect();
        // libcoexist.a is in the map with an empty section only: not linked.
        assert_eq!(
            blobs,
            [
                "components/esp_phy/lib/esp32/libphy.a",
                "components/esp_wifi/lib/esp32/libpp.a"
            ]
        );
        assert_eq!(
            o.blobs[1].object,
            "esp-idf/components/esp_wifi/lib/esp32/libpp.a(pp.o)"
        );
        assert!(
            o.notes
                .iter()
                .any(|n| n.message.contains("subsystem lwip is not enabled")),
            "{:?}",
            o.notes
        );
        // Without the build's idf_path no blob can be told apart.
        let o = split(&t, &c, &map(true), None, None, "build/x.map");
        assert!(o.blobs.is_empty());
    }

    #[test]
    fn absolute_archive_paths_under_the_build_dir_match() {
        let t = table::builtin().unwrap();
        let c = sdkconfig::parse("CONFIG_LWIP_ENABLE=y\n").unwrap();
        let m = linker_map::parse(
            "Linker script and memory map\n\n.text 0x0 0x10\n .text.a 0x400d0000 0x10 /p/build/esp-idf/lwip/liblwip.a(tcp.c.obj)\n",
        )
        .unwrap();
        let o = split(&t, &c, &m, None, Some("/p/build"), "build/x.map");
        assert_eq!(names(&o), ["lwip"]);
        // Cited by the build-relative archive, not the absolute path.
        assert_eq!(o.subsystems[0].object, "esp-idf/lwip/liblwip.a(tcp.c.obj)");
        let o = split(&t, &c, &m, None, Some("/q/build"), "build/x.map");
        assert!(o.subsystems.is_empty());
    }
}
