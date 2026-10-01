//! Checks on the seed database (`db/identifiers.yaml`) against the Zephyr manifests it covers.
//!
//! `tests/data/zephyr-manifest-pins.txt` lists every project pinned by Zephyr v4.2.0 to
//! v4.4.2; it is written only by `scripts/regen-version-tables.sh`, together with the generated
//! rows of the database, so these tests run offline.

mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::identify::{BUILTIN, Level, Outcome, Query, Resolver, VersionRule, builtin};

    /// The modules the seed covers: the ticket's list plus `cmsis_6`, `mbedtls-3.6` and
    /// `tf-psa-crypto`, which the fixtures or the v4.4 manifest pin.
    const SCOPED: [&str; 33] = [
        "cjson",
        "cmsis",
        "cmsis-dsp",
        "cmsis_6",
        "fatfs",
        "hal_espressif",
        "hal_nordic",
        "hal_nxp",
        "hal_rpi_pico",
        "hal_silabs",
        "hal_stm32",
        "hostap",
        "liblc3",
        "libmetal",
        "littlefs",
        "loramac-node",
        "lvgl",
        "mbedtls",
        "mbedtls-3.6",
        "mcuboot",
        "nanopb",
        "open-amp",
        "openthread",
        "percepio",
        "picolibc",
        "segger",
        "tf-m-tests",
        "tf-psa-crypto",
        "tinycrypt",
        "trusted-firmware-m",
        "uoscore-uedhoc",
        "zcbor",
        "zephyr",
    ];

    /// The modules whose upstream has a (non-deprecated) vendor:product in the NVD CPE
    /// dictionary, checked 2026-10-01 with `scripts/nvd-spot-check.sh`. Every other module has
    /// no cpe: none is constructed.
    pub(crate) const NVD_LISTED: [(&str, &str); 13] = [
        ("cjson", "cpe:2.3:a:davegamble:cjson:"),
        ("fatfs", "cpe:2.3:a:elm-chan:fatfs:"),
        ("hal_espressif", "cpe:2.3:a:espressif:esp-idf:"),
        ("hostap", "cpe:2.3:a:w1.fi:wpa_supplicant:"),
        ("loramac-node", "cpe:2.3:a:semtech:loramac-node:"),
        ("mbedtls", "cpe:2.3:a:trustedfirmware:mbed_tls:"),
        ("mbedtls-3.6", "cpe:2.3:a:trustedfirmware:mbed_tls:"),
        ("nanopb", "cpe:2.3:a:nanopb_project:nanopb:"),
        ("open-amp", "cpe:2.3:a:linaro:openamp:"),
        ("openthread", "cpe:2.3:o:google:openthread:"),
        ("tf-psa-crypto", "cpe:2.3:a:trustedfirmware:tf-psa-crypto:"),
        (
            "trusted-firmware-m",
            "cpe:2.3:o:trustedfirmware:trusted_firmware-m:",
        ),
        ("zephyr", "cpe:2.3:o:zephyrproject:zephyr:"),
    ];

    /// The `cpe_aliases` of the seed: further dictionary vendor:products NVD files the same
    /// project's CVEs under (NVD CVE API, 2026-10-01). `arm:tf-psa-crypto` also carries CVEs
    /// but is not in the CPE dictionary, so it is not an alias.
    const NVD_ALIASES: [(&str, &str); 4] = [
        ("cjson", "cpe:2.3:a:cjson_project:cjson:"),
        ("hostap", "cpe:2.3:a:w1.fi:hostapd:"),
        ("mbedtls", "cpe:2.3:a:arm:mbed_tls:"),
        ("mbedtls-3.6", "cpe:2.3:a:arm:mbed_tls:"),
    ];

    const PINS: &str = include_str!("../../tests/data/zephyr-manifest-pins.txt");

    /// One `zephyr-manifest-pins.txt` line.
    #[derive(Debug, PartialEq, Eq)]
    struct Pin<'a> {
        module: &'a str,
        revision: &'a str,
        releases: Vec<&'a str>,
    }

    /// Parses the pin list: `module revision url release...` per line, `#` comments.
    fn parse_pins(text: &str) -> Result<Vec<Pin<'_>>, String> {
        let mut pins = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(module), Some(revision), Some(url)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!(
                    "line {}: expected module revision url releases",
                    n + 1
                ));
            };
            if !url.starts_with("https://") {
                return Err(format!("line {}: {url:?} is not an https URL", n + 1));
            }
            let releases: Vec<&str> = fields.collect();
            if releases.is_empty() || releases.iter().any(|r| !r.starts_with('v')) {
                return Err(format!("line {}: expected releases like v4.4.2", n + 1));
            }
            pins.push(Pin {
                module,
                revision,
                releases,
            });
        }
        Ok(pins)
    }

    #[test]
    fn pins_parser_rejects_malformed_lines() {
        for bad in [
            "mbedtls",
            "mbedtls abc",
            "mbedtls abc ftp://x v4.4.2",
            "mbedtls abc https://x",
            "mbedtls abc https://x 4.4.2",
        ] {
            assert!(parse_pins(bad).is_err(), "{bad:?} accepted");
        }
        assert_eq!(parse_pins("# only a comment\n\n"), Ok(Vec::new()));
        assert_eq!(
            parse_pins("m r https://x v4.2.0 v4.2.1").unwrap(),
            [Pin {
                module: "m",
                revision: "r",
                releases: vec!["v4.2.0", "v4.2.1"],
            }]
        );
    }

    #[test]
    fn seed_lists_every_scoped_module_and_nothing_else() {
        let db = builtin().unwrap();
        let names: Vec<&str> = db.modules().map(|(name, _)| name).collect();
        assert_eq!(names, SCOPED);
    }

    #[test]
    fn seed_covers_every_manifest_pin_for_three_releases() {
        let pins = parse_pins(PINS).unwrap();
        // The pin list covers the pinned release (v4.4) and the previous two.
        let minors: BTreeSet<&str> = pins
            .iter()
            .flat_map(|p| p.releases.iter())
            .filter_map(|r| r.rsplit_once('.').map(|(minor, _)| minor))
            .collect();
        assert_eq!(minors, BTreeSet::from(["v4.2", "v4.3", "v4.4"]));

        let db = builtin().unwrap();
        let mut resolver = Resolver::new(&db);
        let mut resolved: BTreeMap<&str, usize> = BTreeMap::new();
        for pin in pins.iter().filter(|p| db.get(p.module).is_some()) {
            let query = Query {
                module: pin.module,
                revision: Some(pin.revision),
                path: None,
            };
            let Outcome::Identified(id) = resolver.resolve(&query, None) else {
                panic!("{} is in the seed", pin.module);
            };
            let what = format!("{} {} ({:?})", pin.module, pin.revision, pin.releases);
            assert!(id.version.is_some(), "{what}: {:?}", id.note);
            assert_eq!(id.level, Level::High, "{what}");
            assert!(id.purl.is_some(), "{what}: {:?}", id.note);
            assert_eq!(id.note, None, "{what}");
            *resolved.entry(pin.module).or_default() += 1;
        }
        // Every seeded module but cjson (not pinned by these releases) and zephyr (the
        // manifest itself) has at least one pin, and so a table row.
        let expected: BTreeSet<&str> = SCOPED
            .iter()
            .copied()
            .filter(|m| !["cjson", "zephyr"].contains(m))
            .collect();
        assert_eq!(resolved.keys().copied().collect::<BTreeSet<_>>(), expected);
        // Every manual table row is a pinned revision: the tables hold nothing stale.
        let pinned: BTreeSet<(&str, &str)> = pins.iter().map(|p| (p.module, p.revision)).collect();
        for (module, entry) in db.modules() {
            if let VersionRule::Manual { table } = &entry.version_rule {
                for (revision, _) in table.iter() {
                    assert!(
                        pinned.contains(&(module, revision.as_str())),
                        "{module} {revision} is not pinned by v4.2.0 to v4.4.2"
                    );
                }
            }
        }
    }

    #[test]
    fn seed_templates_render_to_valid_purl_and_cpe() {
        let db = builtin().unwrap();
        for (module, entry) in db.modules() {
            let versions: Vec<String> = match &entry.version_rule {
                VersionRule::Manual { table } => table.iter().map(|(_, v)| v.clone()).collect(),
                _ => vec!["1.2.3".to_owned()],
            };
            for version in versions {
                let purl = entry.purl.render(&version);
                assert!(purl.is_ok(), "{module} {version}: {purl:?}");
                if let Some(cpe) = &entry.cpe {
                    let cpe = cpe.render(&version);
                    assert!(cpe.is_ok(), "{module} {version}: {cpe:?}");
                }
            }
        }
    }

    #[test]
    fn seed_upstream_purls_use_generic_type() {
        let db = builtin().unwrap();
        for (module, entry) in db.modules() {
            let purl = entry.purl.render("1.0.0").unwrap();
            assert!(
                purl.as_str().starts_with("pkg:generic/"),
                "{module}: {}",
                purl.as_str()
            );
        }
    }

    #[test]
    fn seed_cpes_are_exactly_the_nvd_listed_pairs() {
        let db = builtin().unwrap();
        let listed: BTreeMap<&str, &str> = NVD_LISTED.into_iter().collect();
        for (module, entry) in db.modules() {
            match (listed.get(module), &entry.cpe) {
                (Some(prefix), Some(cpe)) => {
                    let rendered = cpe.render("1.0.0").unwrap();
                    assert!(
                        rendered.as_str().starts_with(prefix),
                        "{module}: {} is not {prefix}…",
                        rendered.as_str()
                    );
                }
                (None, None) => {
                    // The reason is recorded next to the entry.
                    let block = module_block(module);
                    assert!(
                        block.contains("# No cpe: ") && block.contains("Checked 2026-10-01"),
                        "{module} has no cpe and no reason:\n{block}"
                    );
                }
                (Some(_), None) => panic!("{module} is NVD-listed but has no cpe"),
                (None, Some(cpe)) => {
                    panic!("{module} has a constructed cpe {}", cpe.as_str())
                }
            }
        }
    }

    #[test]
    fn seed_cpe_aliases_are_exactly_the_nvd_listed_aliases() {
        let db = builtin().unwrap();
        let mut found = Vec::new();
        for (module, entry) in db.modules() {
            for alias in &entry.cpe_aliases {
                let rendered = alias.render("1.0.0").unwrap();
                let prefix = NVD_ALIASES
                    .iter()
                    .find(|(m, p)| *m == module && rendered.as_str().starts_with(p))
                    .unwrap_or_else(|| panic!("{module}: unexpected alias {}", alias.as_str()));
                found.push(*prefix);
            }
        }
        assert_eq!(found, NVD_ALIASES);
    }

    /// The text of `module`'s entry in the seed file.
    fn module_block(module: &str) -> String {
        let head = format!("  {module}:");
        BUILTIN
            .lines()
            .skip_while(|l| *l != head)
            .take_while(|l| *l == head || l.starts_with("    "))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn seed_table_rows_are_quoted_inside_generated_markers() {
        const BEGIN: &str = "# BEGIN generated by scripts/regen-version-tables.sh; do not edit";
        const END: &str = "# END generated";
        let db = builtin().unwrap();
        for (module, entry) in db.modules() {
            let block = module_block(module);
            let VersionRule::Manual { table } = &entry.version_rule else {
                assert!(!block.contains(BEGIN), "{module}: markers without a table");
                continue;
            };
            let lines: Vec<&str> = block.lines().map(str::trim).collect();
            let begin = lines.iter().position(|l| *l == BEGIN);
            let end = lines.iter().position(|l| *l == END);
            let (Some(begin), Some(end)) = (begin, end) else {
                panic!("{module}: no generated markers\n{block}");
            };
            assert!(begin < end, "{module}");
            let mut rows = 0;
            for line in lines.iter().skip_while(|l| **l != "table:").skip(1) {
                if line.starts_with('#') {
                    continue;
                }
                // 'revision': 'version'  # comment
                let quoted = line.starts_with('\'')
                    && line
                        .split_once(": ")
                        .is_some_and(|(k, v)| k.ends_with('\'') && v.starts_with('\''));
                assert!(quoted, "{module}: unquoted row {line:?}");
                rows += 1;
            }
            assert_eq!(rows, table.iter().count(), "{module}");
        }
    }
}
