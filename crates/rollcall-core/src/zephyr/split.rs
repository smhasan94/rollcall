//! The subsystem split: one subcomponent of `zephyr` per subsystem that is both enabled in
//! `.config` and has at least one object linked into the image.
//!
//! See `docs/subsystems.md` (*The split*) for the rules; in short:
//!
//! 1. A subsystem is *enabled* when one of its table symbols is `y` or `m`
//!    ([`SubsystemTable::enabled_in`]).
//! 2. Each object of the map is attributed to the most specific enabled subsystem whose
//!    source path contains the object's source file ([`super::objects`]). An object whose
//!    candidate sources point at different subsystems is attributed to none.
//! 3. An enabled subsystem with at least one *linked* attributed object
//!    ([`ObjectUsage::is_linked`](crate::linker_map::ObjectUsage::is_linked)) is emitted. One
//!    with none (its code was garbage-collected, or never compiled) is dropped with a
//!    [`Note`].
//! 4. Linked objects under a disabled subsystem's paths stay in the `zephyr` package (the
//!    table's symbols do not model every CMake condition), with a note.

use std::collections::BTreeMap;

use packageurl::PackageUrl;

use super::Note;
use super::kconfig::Kconfig;
use super::map::evidence;
use super::objects::{Object, Source};
use crate::model::{Component, ComponentKind, EvidenceField, IdError, Purl};
use crate::subsystems::{Subsystem, SubsystemTable};

/// Evidence source for a linked object.
pub(super) const LINKER_MAP_SOURCE: &str = "linker-map";
/// Where the map is, relative to the build directory.
pub(super) const LINKER_MAP: &str = "zephyr/zephyr.map";
const WEST_SPDX: &str = "west-spdx";
const KCONFIG: &str = "kconfig";
const BUILD_SPDX: &str = "spdx/build.spdx";
const CONFIG: &str = "zephyr/.config";

/// Confidences, in basis points.
const KCONFIG_SYMBOL: u16 = 6000;
const LINKED_OBJECT: u16 = 8000;
const GENERATED_FROM: u16 = 8000;

/// What [`split`] decided.
#[derive(Debug, Default)]
pub(super) struct SplitOutcome {
    /// One component per emitted subsystem, in name order.
    pub components: Vec<Component>,
    /// Why subsystems or objects were left out, in name order.
    pub notes: Vec<Note>,
}

/// Whether `path` is `source` or lies under the directory `source`.
fn is_under(path: &str, source: &str) -> bool {
    path == source
        || path
            .strip_prefix(source)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The subsystem among `candidates` with the longest source path containing `path`.
fn best_match<'t>(path: &str, candidates: &[&'t Subsystem]) -> Option<&'t Subsystem> {
    candidates
        .iter()
        .flat_map(|s| {
            s.sources
                .iter()
                .filter(|source| is_under(path, source))
                .map(move |source| (source.len(), *s))
        })
        .max_by(|(a, x), (b, y)| a.cmp(b).then_with(|| y.name.cmp(&x.name)))
        .map(|(_, s)| s)
}

/// Objects attributed to one subsystem.
#[derive(Default)]
struct Attributed<'o, 'm> {
    /// Linked objects and the source each was compiled from, in object order.
    linked: Vec<(&'o Object<'m>, &'o Source)>,
    /// Objects in the map but not linked.
    unlinked: usize,
}

/// Splits the `zephyr` package: see the [module docs](self).
pub(super) fn split(
    table: &SubsystemTable,
    config: &Kconfig,
    objects: &[Object<'_>],
    parent: &Component,
) -> Result<SplitOutcome, IdError> {
    let enabled = table.enabled_in(config);
    let all: Vec<&Subsystem> = table.subsystems.iter().collect();
    let mut attributed: BTreeMap<&str, Attributed<'_, '_>> = BTreeMap::new();
    let mut under_disabled: BTreeMap<&str, Vec<&Object<'_>>> = BTreeMap::new();
    let mut outcome = SplitOutcome::default();

    for object in objects {
        // The distinct owners of the object's candidate sources (normally one source).
        let mut by_owner: BTreeMap<Option<&str>, (Option<&Subsystem>, &Source)> = BTreeMap::new();
        for source in &object.sources {
            let owner = best_match(&source.path, &enabled);
            by_owner
                .entry(owner.map(|s| s.name.as_str()))
                .or_insert((owner, source));
        }
        let owners: Vec<(Option<&Subsystem>, &Source)> = by_owner.into_values().collect();
        match owners.as_slice() {
            [] => {}
            [(Some(subsystem), source)] => {
                let entry = attributed.entry(subsystem.name.as_str()).or_default();
                if object.usage.is_linked() {
                    entry.linked.push((object, source));
                } else {
                    entry.unlinked = entry.unlinked.saturating_add(1);
                }
            }
            [(None, source)] => {
                if object.usage.is_linked()
                    && let Some(disabled) = best_match(&source.path, &all)
                {
                    under_disabled
                        .entry(disabled.name.as_str())
                        .or_default()
                        .push(object);
                }
            }
            _ => {
                if object.usage.is_linked() {
                    let paths: Vec<&str> = object.sources.iter().map(|s| s.path.as_str()).collect();
                    outcome.notes.push(Note::new(
                        LINKER_MAP,
                        format!(
                            "{}: compiled from one of {}, which are in different subsystems; left in the zephyr package",
                            object.id,
                            paths.join(", ")
                        ),
                    ));
                }
            }
        }
    }

    for subsystem in &enabled {
        let Some(found) = attributed
            .get(subsystem.name.as_str())
            .filter(|a| !a.linked.is_empty())
        else {
            let unlinked = attributed
                .get(subsystem.name.as_str())
                .map_or(0, |a| a.unlinked);
            outcome.notes.push(Note::new(
                LINKER_MAP,
                format!(
                    "subsystem {} is enabled by {} but no object compiled from {} was linked ({unlinked} in the map without code or data in the image); not emitted",
                    subsystem.name,
                    enabling_symbols(subsystem, config).join(", "),
                    subsystem.sources.join(", "),
                ),
            ));
            continue;
        };
        outcome
            .components
            .push(subsystem_component(subsystem, config, found, parent)?);
    }

    for (name, objects) in under_disabled {
        let symbols = table
            .get(name)
            .map(|s| s.symbols.join(", "))
            .unwrap_or_default();
        let first = objects
            .first()
            .map(|o| o.id.to_string())
            .unwrap_or_default();
        outcome.notes.push(Note::new(
            LINKER_MAP,
            format!(
                "{} linked object(s) compiled from the sources of subsystem {name} (first {first}), which is not enabled ({symbols} not set); they stay in the zephyr package",
                objects.len()
            ),
        ));
    }
    outcome.notes.sort();
    Ok(outcome)
}

/// `CONFIG_X (zephyr/.config:N)` for every table symbol of `subsystem` that is set.
fn enabling_symbols(subsystem: &Subsystem, config: &Kconfig) -> Vec<String> {
    subsystem
        .symbols
        .iter()
        .filter(|symbol| config.is_set(symbol))
        .map(|symbol| match config.get(symbol) {
            Some(entry) => format!("{symbol} ({CONFIG}:{})", entry.line),
            None => symbol.clone(),
        })
        .collect()
}

/// The parent's purl with `subpath` (`pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/
/// bluetooth/host`), when the parent has a purl without a subpath.
fn purl_with_subpath(parent: Option<&Purl>, subpath: &str) -> Option<Purl> {
    let mut purl: PackageUrl<'_> = parent?.as_str().parse().ok()?;
    if purl.subpath().is_some() {
        return None;
    }
    purl.with_subpath(subpath.to_owned()).ok()?;
    Purl::new(&purl.to_string()).ok()
}

/// The component for an emitted subsystem: a `library` named after it, with the parent's
/// version and supplier, the parent's purl with the primary source path as subpath, the
/// table's CPE, and evidence from `.config`, the map and `build.spdx`.
fn subsystem_component(
    subsystem: &Subsystem,
    config: &Kconfig,
    found: &Attributed<'_, '_>,
    parent: &Component,
) -> Result<Component, IdError> {
    let mut component = Component::new(ComponentKind::Library, &subsystem.name)?;
    component.version = parent.version.clone();
    component.supplier = parent.supplier.clone();
    component.purl = subsystem
        .primary_source()
        .and_then(|primary| purl_with_subpath(parent.purl.as_ref(), primary));
    component.cpe = subsystem.cpe.clone();
    for symbol in subsystem.symbols.iter().filter(|s| config.is_set(s)) {
        let line = config.get(symbol).map(|e| e.line);
        component.evidence.insert(evidence(
            EvidenceField::Name,
            KCONFIG,
            symbol,
            KCONFIG_SYMBOL,
            Some(CONFIG),
            line,
        )?);
    }
    if let Some((object, source)) = found.linked.first() {
        let line = object.usage.first_linked().map(|s| s.line);
        component.evidence.insert(evidence(
            EvidenceField::Name,
            LINKER_MAP_SOURCE,
            &object.id.to_string(),
            LINKED_OBJECT,
            Some(LINKER_MAP),
            line,
        )?);
        if source.line.is_some() {
            component.evidence.insert(evidence(
                EvidenceField::Name,
                WEST_SPDX,
                &source.path,
                GENERATED_FROM,
                Some(BUILD_SPDX),
                source.line,
            )?);
        }
    }
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker_map::{self, ObjectId};
    use crate::subsystems;
    use crate::zephyr::kconfig;

    const TABLE: &str = "\
format: rollcall-subsystems/1
zephyr:
  tag: v4.4.2
  commit: dccb09599635bdff17633fa7e9dab014b91dce90
subsystems:
  - name: bluetooth-host
    description: BT host
    symbols: [CONFIG_BT_HCI_HOST]
    sources: [subsys/bluetooth/common, subsys/bluetooth/host]
    reasons: [size]
    rationale: Large.
  - name: filesystem
    description: FS
    symbols: [CONFIG_FILE_SYSTEM]
    sources: [subsys/fs]
    reasons: [size]
    rationale: Large.
  - name: littlefs
    description: littlefs glue
    symbols: [CONFIG_FILE_SYSTEM_LITTLEFS]
    sources: [subsys/fs/littlefs_fs.c]
    module: littlefs
    cpe: 'cpe:2.3:a:littlefs_project:littlefs:*:*:*:*:*:*:*:*'
    reasons: [upstream-library]
    rationale: Glue.
  - name: logging
    description: Logging
    symbols: [CONFIG_LOG]
    sources: [subsys/logging]
    reasons: [size]
    rationale: Large.
  - name: shell
    description: Shell
    symbols: [CONFIG_SHELL]
    sources: [subsys/shell]
    reasons: [size]
    rationale: Large.
";

    /// The map: hci_core linked; log_core only discarded; shell.c linked; fs.c and
    /// littlefs_fs.c linked.
    const MAP: &str = "\
Discarded input sections

 .text.log      0x00000000       0x40 zephyr/libzephyr.a(log_core.c.obj)

Linker script and memory map

text            0x00001000      0x400
 .text.a        0x00001000       0x10 zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)
 .text.b        0x00001010       0x10 zephyr/libzephyr.a(shell.c.obj)
 .text.c        0x00001020       0x10 zephyr/subsys/fs/libsubsys__fs.a(fs.c.obj)
 .text.d        0x00001030       0x10 zephyr/subsys/fs/libsubsys__fs.a(littlefs_fs.c.obj)
 .text.e        0x00001040        0x0 zephyr/libzephyr.a(log_core.c.obj)
";

    fn table() -> SubsystemTable {
        subsystems::load_str(TABLE).unwrap()
    }

    fn config(symbols: &[&str]) -> Kconfig {
        let text: String = symbols.iter().map(|s| format!("{s}=y\n")).collect();
        kconfig::parse(&text).unwrap()
    }

    fn parent() -> Component {
        let mut zephyr = Component::new(ComponentKind::OperatingSystem, "zephyr").unwrap();
        zephyr.version = Some("4.4.2".to_owned());
        zephyr.purl = Some(Purl::new("pkg:github/zephyrproject-rtos/zephyr@v4.4.2").unwrap());
        zephyr.supplier = Some(crate::model::Supplier::new("zephyrproject").unwrap());
        zephyr
    }

    fn source_of(id: &ObjectId) -> Vec<Source> {
        let dir = match id.archive.as_deref() {
            Some("zephyr/libzephyr.a") => match id.member.as_str() {
                "log_core.c.obj" => "subsys/logging",
                "shell.c.obj" => "subsys/shell",
                _ => return Vec::new(),
            },
            Some(a) => a
                .strip_prefix("zephyr/")
                .and_then(|a| a.rsplit_once('/'))
                .map_or("", |(d, _)| d),
            None => return Vec::new(),
        };
        vec![Source {
            path: format!("{dir}/{}", id.source_name()),
            line: Some(7),
        }]
    }

    fn objects(map: &linker_map::LinkerMap) -> Vec<Object<'_>> {
        map.objects()
            .map(|(id, usage)| Object {
                id,
                usage,
                sources: source_of(id),
            })
            .collect()
    }

    fn names(outcome: &SplitOutcome) -> Vec<&str> {
        outcome.components.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn enabled_and_linked_is_emitted() {
        let map = linker_map::parse(MAP).unwrap();
        let config = config(&["CONFIG_BT_HCI_HOST", "CONFIG_SHELL"]);
        let out = split(&table(), &config, &objects(&map), &parent()).unwrap();
        assert_eq!(names(&out), ["bluetooth-host", "shell"]);
    }

    #[test]
    fn enabled_but_no_linked_objects_is_dropped_with_note() {
        let map = linker_map::parse(MAP).unwrap();
        let config = config(&["CONFIG_LOG", "CONFIG_SHELL"]);
        let out = split(&table(), &config, &objects(&map), &parent()).unwrap();
        assert_eq!(names(&out), ["shell"]);
        // The others are about bluetooth-host, filesystem and littlefs code left in zephyr.
        let dropped: Vec<&Note> = out
            .notes
            .iter()
            .filter(|n| n.message.starts_with("subsystem "))
            .collect();
        let [note] = dropped.as_slice() else {
            panic!("{:?}", out.notes)
        };
        assert_eq!(note.location, "zephyr/zephyr.map");
        assert_eq!(
            note.message,
            "subsystem logging is enabled by CONFIG_LOG (zephyr/.config:1) but no object \
             compiled from subsys/logging was linked (1 in the map without code or data in \
             the image); not emitted"
        );
    }

    #[test]
    fn linked_but_kconfig_off_is_noted_and_not_emitted() {
        let map = linker_map::parse(MAP).unwrap();
        let config = config(&["CONFIG_SHELL"]);
        let out = split(&table(), &config, &objects(&map), &parent()).unwrap();
        assert_eq!(names(&out), ["shell"]);
        let messages: Vec<&str> = out.notes.iter().map(|n| n.message.as_str()).collect();
        assert_eq!(messages.len(), 3, "{messages:?}");
        assert!(
            messages.iter().any(|m| m.starts_with(
                "1 linked object(s) compiled from the sources of subsystem bluetooth-host (first zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)), which is not enabled (CONFIG_BT_HCI_HOST not set)"
            )),
            "{messages:?}"
        );
        // fs.c is filesystem's; littlefs_fs.c is littlefs's, the more specific path.
        assert!(
            messages.iter().any(|m| m.contains(
                "subsystem filesystem (first zephyr/subsys/fs/libsubsys__fs.a(fs.c.obj))"
            )),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains(
                "subsystem littlefs (first zephyr/subsys/fs/libsubsys__fs.a(littlefs_fs.c.obj))"
            )),
            "{messages:?}"
        );
    }

    #[test]
    fn nested_sources_prefer_the_most_specific_enabled_entry() {
        let map = linker_map::parse(MAP).unwrap();
        // Both enabled: each file goes to its most specific entry.
        let both = config(&["CONFIG_FILE_SYSTEM", "CONFIG_FILE_SYSTEM_LITTLEFS"]);
        let out = split(&table(), &both, &objects(&map), &parent()).unwrap();
        assert_eq!(names(&out), ["filesystem", "littlefs"]);
        let littlefs = out
            .components
            .iter()
            .find(|c| c.name == "littlefs")
            .unwrap();
        let linked: Vec<&str> = littlefs
            .evidence
            .iter()
            .filter(|e| e.source() == LINKER_MAP_SOURCE)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            linked,
            ["zephyr/subsys/fs/libsubsys__fs.a(littlefs_fs.c.obj)"]
        );
        // Only the enclosing entry enabled: it takes both files.
        let outer = config(&["CONFIG_FILE_SYSTEM"]);
        let out = split(&table(), &outer, &objects(&map), &parent()).unwrap();
        assert_eq!(names(&out), ["filesystem"]);
        assert!(
            !out.notes.iter().any(|n| n.message.contains("fs")),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn ambiguous_object_is_not_counted() {
        let map = linker_map::parse(MAP).unwrap();
        let mut objects = objects(&map);
        for object in &mut objects {
            if object.id.member == "shell.c.obj" {
                object.sources.push(Source {
                    path: "subsys/logging/shell.c".to_owned(),
                    line: Some(8),
                });
                object.sources.sort();
            }
        }
        let config = config(&["CONFIG_LOG", "CONFIG_SHELL"]);
        let out = split(&table(), &config, &objects, &parent()).unwrap();
        assert!(names(&out).is_empty(), "{:?}", names(&out));
        assert!(
            out.notes.iter().any(|n| n.message
                == "zephyr/libzephyr.a(shell.c.obj): compiled from one of subsys/logging/shell.c, subsys/shell/shell.c, which are in different subsystems; left in the zephyr package"),
            "{:?}",
            out.notes
        );
    }

    #[test]
    fn identity_purl_cpe_and_evidence_derive_from_parent() {
        let map = linker_map::parse(MAP).unwrap();
        let config = config(&["CONFIG_BT_HCI_HOST", "CONFIG_FILE_SYSTEM_LITTLEFS"]);
        let out = split(&table(), &config, &objects(&map), &parent()).unwrap();
        let bt = out
            .components
            .iter()
            .find(|c| c.name == "bluetooth-host")
            .unwrap();
        assert_eq!(bt.kind, ComponentKind::Library);
        assert_eq!(bt.version.as_deref(), Some("4.4.2"));
        assert_eq!(
            bt.supplier.as_ref().map(|s| s.name()),
            Some("zephyrproject")
        );
        assert_eq!(
            bt.purl.as_ref().map(Purl::as_str),
            Some("pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/common")
        );
        assert_eq!(bt.cpe, None);
        assert!(bt.licence.is_none() && bt.components.is_empty());
        let mut evidence: Vec<(String, String, String)> = bt
            .evidence
            .iter()
            .map(|e| {
                (
                    e.source().to_owned(),
                    e.value.clone(),
                    e.occurrence
                        .as_ref()
                        .map(|o| format!("{}:{}", o.location(), o.line().unwrap_or(0)))
                        .unwrap_or_default(),
                )
            })
            .collect();
        evidence.sort();
        assert_eq!(
            evidence,
            [
                (
                    "kconfig".to_owned(),
                    "CONFIG_BT_HCI_HOST".to_owned(),
                    "zephyr/.config:1".to_owned()
                ),
                (
                    "linker-map".to_owned(),
                    "zephyr/subsys/bluetooth/host/libsubsys__bluetooth__host.a(hci_core.c.obj)"
                        .to_owned(),
                    "zephyr/zephyr.map:8".to_owned()
                ),
                (
                    "west-spdx".to_owned(),
                    "subsys/bluetooth/host/hci_core.c".to_owned(),
                    "spdx/build.spdx:7".to_owned()
                ),
            ]
        );
        let littlefs = out
            .components
            .iter()
            .find(|c| c.name == "littlefs")
            .unwrap();
        assert_eq!(
            littlefs.cpe.as_ref().map(|c| c.as_str()),
            Some("cpe:2.3:a:littlefs_project:littlefs:*:*:*:*:*:*:*:*")
        );
        // A parent without a purl gives none.
        let mut bare = parent();
        bare.purl = None;
        let out = split(&table(), &config, &objects(&map), &bare).unwrap();
        assert!(out.components.iter().all(|c| c.purl.is_none()));
    }

    #[test]
    fn empty_map_or_config_emits_nothing() {
        let map = linker_map::parse("Linker script and memory map\n").unwrap();
        let out = split(
            &table(),
            &config(&["CONFIG_SHELL"]),
            &objects(&map),
            &parent(),
        )
        .unwrap();
        assert!(out.components.is_empty());
        assert_eq!(out.notes.len(), 1);
        let map = linker_map::parse(MAP).unwrap();
        let out = split(&table(), &Kconfig::default(), &objects(&map), &parent()).unwrap();
        assert!(out.components.is_empty());
    }
}
