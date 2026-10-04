//! The model and CycloneDX documentation cover their required sections.

const MODEL_DOCS: &str = include_str!("../src/model/mod.rs");

#[test]
fn model_docs_explain_evidence_and_confidence() {
    for heading in [
        "//! # Hierarchy",
        "//! # Evidence",
        "//! # Confidence",
        "//! # Determinism and bom-refs",
        "//! # Internal JSON form",
    ] {
        assert!(
            MODEL_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?}"
        );
    }
    let section = |name: &str| -> String {
        MODEL_DOCS
            .lines()
            .skip_while(|l| l.trim_end() != format!("//! # {name}"))
            .skip(1)
            .take_while(|l| !l.starts_with("//! # "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let evidence = section("Evidence");
    for term in ["source", "technique", "occurrence", "confidence"] {
        assert!(evidence.contains(term), "Evidence section lacks {term:?}");
    }
    let confidence = section("Confidence");
    for term in ["basis points", "maximum"] {
        assert!(
            confidence.contains(term),
            "Confidence section lacks {term:?}"
        );
    }
}

const CYCLONEDX_DOCS: &str = include_str!("../src/cyclonedx/mod.rs");

#[test]
fn cyclonedx_docs_have_mapping_section() {
    for heading in [
        "//! # Mapping",
        "//! # Determinism",
        "//! # Not represented",
    ] {
        assert!(
            CYCLONEDX_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?} in cyclonedx/mod.rs"
        );
    }
    let mapping: String = CYCLONEDX_DOCS
        .lines()
        .skip_while(|l| l.trim_end() != "//! # Mapping")
        .skip(1)
        .take_while(|l| !l.starts_with("//! # "))
        .collect::<Vec<_>>()
        .join("\n");
    for term in [
        "metadata.component",
        "rollcall:image-kind",
        "rollcall:evidence-source",
        "rollcall:evidence`",
        "rollcall:opaque",
        "dependencies",
        "evidence.identity",
        "evidence.occurrences",
        "evidence.licenses",
        "firmware",
    ] {
        assert!(mapping.contains(term), "Mapping section lacks {term:?}");
    }
}

const ZEPHYR_DOCS: &str = include_str!("../src/zephyr/mod.rs");

#[test]
fn zephyr_docs_have_mapping_and_warnings_sections() {
    for heading in [
        "//! # Inputs",
        "//! # Mapping",
        "//! # Warnings",
        "//! # Determinism",
    ] {
        assert!(
            ZEPHYR_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?} in zephyr/mod.rs"
        );
    }
    let section = |name: &str| -> String {
        ZEPHYR_DOCS
            .lines()
            .skip_while(|l| l.trim_end() != format!("//! # {name}"))
            .skip(1)
            .take_while(|l| !l.starts_with("//! # "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let inputs = section("Inputs");
    for term in [
        "build_info.yml",
        "spdx/zephyr.spdx",
        "spdx/app.spdx",
        "spdx/build.spdx",
        "spdx/modules-deps.spdx",
        "zephyr/.config",
        "--west-list",
    ] {
        assert!(inputs.contains(term), "Inputs section lacks {term:?}");
    }
    let mapping = section("Mapping");
    for term in [
        "operating-system",
        "library",
        "application",
        "revision",
        "purl",
        "cpe",
        "--include-sdk",
        "dependencies",
        "west-spdx",
        "west-list",
        "kconfig",
        "build-info",
    ] {
        assert!(mapping.contains(term), "Mapping section lacks {term:?}");
    }
    let warnings = section("Warnings");
    for term in ["Warning", "order", "ZephyrError"] {
        assert!(warnings.contains(term), "Warnings section lacks {term:?}");
    }
}

const SUBSYSTEMS_DOCS: &str = include_str!("../src/subsystems/mod.rs");
const SUBSYSTEMS_GUIDE: &str = include_str!("../../../docs/subsystems.md");

#[test]
fn subsystems_docs_have_schema_and_lint_sections() {
    for heading in ["//! # Schema", "//! # Lint rules", "//! # Determinism"] {
        assert!(
            SUBSYSTEMS_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?} in subsystems/mod.rs"
        );
    }
    for term in [
        "cve-history",
        "size",
        "upstream-library",
        "scanners",
        "unknown-symbol",
        "unknown-source",
        "pin-mismatch",
        "scripts/verify-subsystems.sh",
    ] {
        assert!(
            SUBSYSTEMS_DOCS.contains(term),
            "subsystems/mod.rs lacks {term:?}"
        );
        assert!(
            SUBSYSTEMS_GUIDE.contains(term),
            "docs/subsystems.md lacks {term:?}"
        );
    }
}

/// The body of `heading` (e.g. `## The split`) in docs/subsystems.md, up to the next heading
/// of the same or a higher level.
fn subsystems_section(heading: &str) -> String {
    let level = heading.split(' ').next().unwrap_or_default().len();
    SUBSYSTEMS_GUIDE
        .lines()
        .skip_while(|l| l.trim_end() != heading)
        .skip(1)
        .take_while(|l| {
            let hashes = l.chars().take_while(|c| *c == '#').count();
            hashes == 0 || hashes > level
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// SHA-108: docs/subsystems.md explains the split and how to add a subsystem.
#[test]
fn subsystems_doc_has_required_sections() {
    let required: [(&str, &[&str]); 8] = [
        (
            "## The split",
            &["Kconfig", "linker map", "--gc-sections", "phantom"],
        ),
        (
            "### Inputs",
            &[
                "zephyr/.config",
                "zephyr/zephyr.map",
                "spdx/build.spdx",
                "GENERATED_FROM",
            ],
        ),
        (
            "### Algorithm",
            &[
                "Enabled",
                "linked",
                "libzephyr.a",
                "most specific",
                "/DISCARD/",
            ],
        ),
        (
            "### What is emitted",
            &[
                "library",
                "subpath",
                "linker-map",
                "kconfig",
                "west-spdx",
                "match.subsystem",
            ],
        ),
        (
            "### Notes and warnings",
            &["note", "--verbose", "not emitted"],
        ),
        (
            "## Adding a subsystem",
            &[
                "subsystems.yaml",
                "zephyr-subsystems.txt",
                "scripts/regen-golden.sh",
                "scripts/verify-subsystems.sh",
            ],
        ),
        ("## Blobs", &["softdevice", "image:", "blob manifest"]),
        ("## Limitations", &["GNU ld", "lld", "-flto", "build.spdx"]),
    ];
    for (heading, terms) in required {
        let body = subsystems_section(heading);
        assert!(
            !body.trim().is_empty(),
            "docs/subsystems.md lacks {heading:?}"
        );
        for term in terms {
            assert!(body.contains(term), "{heading:?} lacks {term:?}");
        }
    }
}

const IDENTIFIERS_DOC: &str = include_str!("../../../docs/identifiers.md");

/// The body of `## <name>` in docs/identifiers.md.
fn identifiers_section(name: &str) -> String {
    IDENTIFIERS_DOC
        .lines()
        .skip_while(|l| l.trim_end() != format!("## {name}"))
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn identifiers_doc_has_required_sections() {
    assert!(IDENTIFIERS_DOC.starts_with("# Identifiers\n"));
    let required: [(&str, &[&str]); 6] = [
        (
            "PURL convention",
            &["pkg:generic", "vcs_url", "GitHub Actions", "pkg:github"],
        ),
        (
            "CPE convention",
            &[
                "NVD CPE dictionary",
                "No CPE is constructed",
                "# No cpe:",
                "cpe_aliases",
                "Which CPE wins",
                "syft:cpe23",
                "evidence.identity",
            ],
        ),
        (
            "Version derivation",
            &[
                "git_tag",
                "file_regex",
                "manual",
                "scripts/regen-version-tables.sh",
                "# BEGIN generated",
                "zephyr-manifest-pins.txt",
            ],
        ),
        (
            "Scanner behaviour",
            &["cpe-match", "osv-scanner", "expected-cves.txt"],
        ),
        (
            "NVD spot-check",
            &["scripts/nvd-spot-check.sh", "totalResults"],
        ),
        ("Module table", &["| Module |"]),
    ];
    for (heading, terms) in required {
        let body = identifiers_section(heading);
        assert!(!body.trim().is_empty(), "missing section ## {heading}");
        for term in terms {
            assert!(body.contains(term), "## {heading} lacks {term:?}");
        }
    }
    // At least five CPEs are spot-checked against the dictionary, each found.
    let checked = identifiers_section("NVD spot-check")
        .lines()
        .filter(|l| {
            l.starts_with("| `cpe:2.3:") && !l.ends_with("| 0 | 0 |") && !l.ends_with("| 0 |")
        })
        .count();
    assert!(checked >= 5, "{checked} spot-checked CPEs");
}

#[test]
fn identifiers_doc_lists_every_seeded_module() {
    let db = rollcall_core::identify::builtin().unwrap();
    let table = identifiers_section("Module table");
    for (module, entry) in db.modules() {
        let row = table
            .lines()
            .find(|l| l.starts_with(&format!("| `{module}` |")))
            .unwrap_or_else(|| panic!("{module} is not in the module table"));
        let cpe_cell = row.trim_end_matches(" |").rsplit(" | ").next().unwrap();
        match &entry.cpe {
            Some(cpe) => {
                // `a:vendor:product` of each template: the cpe, then its aliases.
                let pair = |t: &str| {
                    let parts: Vec<&str> = t.split(':').skip(2).take(3).collect();
                    format!("`{}`", parts.join(":"))
                };
                let mut want = pair(cpe.as_str());
                for alias in &entry.cpe_aliases {
                    want.push_str(&format!(", alias {}", pair(alias.as_str())));
                }
                assert_eq!(cpe_cell, want, "{module}");
            }
            None => assert!(
                cpe_cell.starts_with("none: ") && cpe_cell.len() > "none: ".len() + 10,
                "{module}: no CPE and no reason in {row:?}"
            ),
        }
    }
}

const VALIDATE_DOCS: &str = include_str!("../../../docs/validate.md");

/// `docs/validate.md` cites, for every check of every built-in profile, the source document
/// and the clause the profile encodes, and describes every check in the catalogue.
#[test]
fn validate_docs_cite_source_and_clause_for_every_profile_check() {
    let profiles = rollcall_core::validate::builtin_profiles();
    assert!(!profiles.is_empty());
    for profile in &profiles {
        let heading = format!("`{}`", profile.id);
        assert!(VALIDATE_DOCS.contains(&heading), "no section for {heading}");
        for source in &profile.sources {
            assert!(
                VALIDATE_DOCS.contains(&source.document),
                "{}: source {:?} not cited",
                profile.id,
                source.document
            );
            if let Some(url) = &source.url {
                assert!(
                    VALIDATE_DOCS.contains(url.as_str()),
                    "{}: {url}",
                    profile.id
                );
            }
        }
        for check in &profile.checks {
            // One table row per check: `| `id` | clause |`.
            let row = format!("| `{}` | {} |", check.id, check.cite.clause);
            assert!(
                VALIDATE_DOCS.lines().any(|l| l.starts_with(&row)),
                "{}: no citation row starting {row:?}",
                profile.id
            );
        }
    }
    for check in rollcall_core::validate::CHECKS {
        assert!(
            VALIDATE_DOCS.contains(&format!("### `{}`", check.id)),
            "check {} not described",
            check.id
        );
    }
}

const VALIDATE_MODULE_DOCS: &str = include_str!("../src/validate/mod.rs");

#[test]
fn validate_module_docs_have_required_sections() {
    for heading in [
        "//! # Checks",
        "//! # Profiles",
        "//! # Report",
        "//! # Determinism",
    ] {
        assert!(
            VALIDATE_MODULE_DOCS
                .lines()
                .any(|l| l.trim_end() == heading),
            "missing section {heading:?} in validate/mod.rs"
        );
    }
}

const VEX_DOCS: &str = include_str!("../src/vex/mod.rs");

#[test]
fn vex_docs_have_mapping_signing_and_determinism_sections() {
    let section = |heading: &str| -> String {
        assert!(
            VEX_DOCS.lines().any(|l| l.trim_end() == heading),
            "missing section {heading:?} in vex/mod.rs"
        );
        VEX_DOCS
            .lines()
            .skip_while(|l| l.trim_end() != heading)
            .skip(1)
            .take_while(|l| !l.starts_with("//! # "))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let formats = section("//! # Output formats");
    for term in [
        "OpenVEX",
        "CycloneDX VEX",
        "purl",
        "BOM-Link",
        "affects[].ref",
        "impact_statement",
        "action_statement",
        "rollcall:rule",
        "Embedded",
        "--embed",
        "incremented",
        "union",
    ] {
        assert!(
            formats.contains(term),
            "Output formats section lacks {term:?}"
        );
    }
    let signing = section("//! # Signing");
    for term in ["Ed25519", "rollcall-signature/1", "cosign"] {
        assert!(signing.contains(term), "Signing section lacks {term:?}");
    }
    let determinism = section("//! # Determinism");
    for term in ["--id", "--timestamp", "document_id"] {
        assert!(
            determinism.contains(term),
            "Determinism section lacks {term:?}"
        );
    }
}

/// `docs/vex-rules.md` (SHA-115), read from the repository.
fn vex_rules_doc() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/vex-rules.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of `doc` from the heading `start` up to the next heading of the same or a
/// higher level.
fn md_section<'a>(doc: &'a str, start: &str) -> Vec<&'a str> {
    let level = start.chars().take_while(|c| *c == '#').count();
    let mut lines = doc.lines().skip_while(|l| *l != start);
    let Some(_) = lines.next() else {
        panic!("missing heading {start:?}")
    };
    lines
        .take_while(|l| {
            let hashes = l.chars().take_while(|c| *c == '#').count();
            !(hashes > 0 && hashes <= level && l.chars().nth(hashes) == Some(' '))
        })
        .collect()
}

/// The fenced blocks of `lang` in `lines`.
fn fenced(lines: &[&str], lang: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in lines {
        match &mut current {
            None if *line == format!("```{lang}") => current = Some(Vec::new()),
            Some(block) if *line == "```" => {
                blocks.push(block.join("\n") + "\n");
                current = None;
            }
            Some(block) => block.push(line),
            None => {}
        }
    }
    blocks
}

/// The rule reference, the starter pack, the lint and the glossary are there, and exactly five
/// worked examples each show their input, the rule and the resulting statement, the
/// statement as `rollcall vex` commands with their output (which
/// `scripts/check-doc-examples.sh` runs and checks). Whether the prose is plain is for a
/// human reviewer.
#[test]
fn vex_rules_doc_has_reference_and_five_worked_examples() {
    let doc = vex_rules_doc();
    for heading in [
        "# VEX rules",
        "## Running `rollcall vex`",
        "## Rule format",
        "### How rules are applied",
        "### Missing evidence is never \"off\"",
        "## Starter pack",
        "## Checking your rules",
        "## Worked examples",
        "## Glossary",
    ] {
        assert!(doc.lines().any(|l| l == heading), "missing {heading:?}");
    }
    let format = md_section(&doc, "## Rule format").join("\n");
    for field in [
        "`id`",
        "`priority`",
        "`match.name`",
        "`match.purl`",
        "`match.subsystem`",
        "`match.cves`",
        "`match.versions`",
        "`when`",
        "`status`",
        "`justification`",
        "`detail`",
        "`kconfig_off: CONFIG_X`",
        "`kconfig_equals: {CONFIG_X: value}`",
        "`symbol_not_linked: name`",
        "`cargo_feature_off: name`",
        "`version_in: \"<range>\"`",
    ] {
        assert!(format.contains(field), "Rule format lacks {field}");
    }
    let examples: Vec<&str> = doc
        .lines()
        .filter(|l| l.starts_with("### Example "))
        .collect();
    assert_eq!(examples.len(), 5, "{examples:?}");
    for (i, heading) in examples.iter().enumerate() {
        assert!(
            heading.starts_with(&format!("### Example {}: ", i + 1)),
            "{heading}"
        );
        let body = md_section(&doc, heading);
        let subs: Vec<&str> = body
            .iter()
            .copied()
            .filter(|l| l.starts_with("#### "))
            .collect();
        assert_eq!(
            subs,
            ["#### Input", "#### Rule", "#### Resulting statement"],
            "{heading}"
        );
        let rule = md_section(&doc, heading)
            .into_iter()
            .skip_while(|l| *l != "#### Rule")
            .collect::<Vec<_>>();
        assert_eq!(fenced(&rule, "yaml").len(), 1, "{heading}: one rule");
        let result = body
            .iter()
            .copied()
            .skip_while(|l| *l != "#### Resulting statement")
            .collect::<Vec<_>>();
        let consoles = fenced(&result, "console");
        assert!(!consoles.is_empty(), "{heading}: no console example");
        assert!(
            consoles.iter().any(|c| c.contains("$ rollcall vex ")),
            "{heading}: no rollcall vex command"
        );
    }
    // The starter pack table lists every rule, and the Bluetooth snapshot is dated.
    let pack = md_section(&doc, "## Starter pack").join("\n");
    let rules = rollcall_core::vex::parse_rules(
        rollcall_identifiers::VEX_RULES_YAML,
        rollcall_identifiers::VEX_RULES_FILE_NAME,
    )
    .unwrap();
    for rule in &rules.rules {
        assert!(
            pack.contains(&format!("| `{}` |", rule.id)),
            "{} not in the table",
            rule.id
        );
    }
    assert!(
        pack.contains("2026-09-29") && pack.contains("2026-10-03 (UTC)"),
        "undated snapshot"
    );
    assert!(
        pack.contains("scripts/capture-findings.sh --bluetooth-cves"),
        "the snapshot must say how to re-run it"
    );
    let glossary = md_section(&doc, "## Glossary").join("\n");
    for term in [
        "**SBOM**",
        "**Sysbuild**",
        "**purl**",
        "**CPE**",
        "**PSA Crypto**",
    ] {
        assert!(glossary.contains(term), "Glossary lacks {term}");
    }
}

/// Each example's rule is the rule the pack (or `typo.rules.yml`) really has, so the docs do
/// not drift from the data. The Bluetooth example shows one CVE of the rule's list.
#[test]
fn vex_rules_doc_example_rules_match_the_pack() {
    use rollcall_core::vex::{RuleSet, parse_rules};
    let doc = vex_rules_doc();
    let pack = parse_rules(
        rollcall_identifiers::VEX_RULES_YAML,
        rollcall_identifiers::VEX_RULES_FILE_NAME,
    )
    .unwrap();
    let typo_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/vex/typo.rules.yml");
    let typo = parse_rules(
        &std::fs::read_to_string(typo_path).unwrap(),
        "typo.rules.yml",
    )
    .unwrap();
    let mut known = RuleSet::default();
    known.rules.extend(pack.rules);
    known.rules.extend(typo.rules);
    let headings: Vec<&str> = doc
        .lines()
        .filter(|l| l.starts_with("### Example "))
        .collect();
    for heading in headings {
        let rule_lines: Vec<&str> = md_section(&doc, heading)
            .into_iter()
            .skip_while(|l| *l != "#### Rule")
            .collect();
        let [yaml] = fenced(&rule_lines, "yaml")
            .try_into()
            .unwrap_or_else(|v: Vec<String>| panic!("{heading}: {} yaml blocks", v.len()));
        let shown = parse_rules(&format!("version: 1\nrules:\n{yaml}"), heading)
            .unwrap_or_else(|e| panic!("{e}"));
        let [shown] = shown.rules.as_slice() else {
            panic!("{heading}: one rule expected")
        };
        let real = known
            .rules
            .iter()
            .find(|r| r.id == shown.id)
            .unwrap_or_else(|| panic!("{heading}: no rule {}", shown.id));
        if shown.id == "zephyr-bluetooth-off" {
            assert!(shown.target.cves.is_subset(&real.target.cves), "{heading}");
            let mut trimmed = real.clone();
            trimmed.target.cves = shown.target.cves.clone();
            assert_eq!(shown, &trimmed, "{heading}");
        } else {
            assert_eq!(shown, real, "{heading}");
        }
    }
}

const CARGO_DOCS: &str = include_str!("../src/cargo/mod.rs");

#[test]
fn cargo_docs_have_inputs_mapping_warnings_and_determinism_sections() {
    for heading in [
        "//! # Inputs",
        "//! # Mapping",
        "//! # Warnings",
        "//! # Determinism",
    ] {
        assert!(
            CARGO_DOCS.contains(heading),
            "missing section {heading:?} in cargo/mod.rs"
        );
    }
    // The purl forms and the scope the ticket fixes are documented.
    for needle in [
        "pkg:cargo/<name>@<version>",
        "pkg:generic/<name>@<version>?vcs_url=git+<url>@<commit>",
        "Scope::Excluded",
        "unified features",
    ] {
        assert!(CARGO_DOCS.contains(needle), "cargo/mod.rs lacks {needle:?}");
    }
}
