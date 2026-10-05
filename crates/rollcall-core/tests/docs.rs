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

// SHA-134: the Zephyr gap analysis (docs/zephyr-gaps.md) and its outreach drafts
// (docs/outreach/). The console examples themselves are run by
// `scripts/check-doc-examples.sh docs/zephyr-gaps.md` and the http(s) links checked by
// `scripts/check-doc-links.sh`; these tests check the structure and the in-tree links.

/// The repository root.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file of the repository, by its path from the root.
fn repo_file(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const ZEPHYR_GAPS: &str = "docs/zephyr-gaps.md";

/// The outreach drafts, each a row of the outreach log.
const OUTREACH_DRAFTS: [&str; 3] = [
    "docs/outreach/zephyr-rfc-120474-comment.md",
    "docs/outreach/zephyr-working-group-thread.md",
    "docs/outreach/firmware-sbom-talk.md",
];

/// The `##` sections of docs/zephyr-gaps.md, in order.
const ZEPHYR_GAPS_SECTIONS: [&str; 13] = [
    "## How to reproduce",
    "## What west spdx produces",
    "## Gap 1: Identifiers",
    "## Gap 2: Subsystem split",
    "## Gap 3: MCUboot and sysbuild",
    "## Gap 4: Blobs",
    "## Gap 5: CycloneDX",
    "## rollcall as the companion",
    "## Proposals upstream",
    "## Outreach log",
    "## Responses",
    "## References",
    // Not a section of its own: the end of the list, so the order check covers the last one.
    "",
];

/// The sections that make claims about `west spdx` and back them with console examples.
const ZEPHYR_GAPS_CLAIM_SECTIONS: [&str; 6] = [
    "## What west spdx produces",
    "## Gap 1: Identifiers",
    "## Gap 2: Subsystem split",
    "## Gap 3: MCUboot and sysbuild",
    "## Gap 4: Blobs",
    "## Gap 5: CycloneDX",
];

/// SHA-134 AC1: the gap analysis has every section of the plan, pinned to the fixtures'
/// Zephyr and west versions, each section covering its topic.
#[test]
fn zephyr_gaps_doc_has_required_sections() {
    let doc = repo_file(ZEPHYR_GAPS);
    assert!(doc.starts_with("# Zephyr `west spdx` gap analysis\n"));
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    let wanted: Vec<&str> = ZEPHYR_GAPS_SECTIONS
        .iter()
        .copied()
        .filter(|h| !h.is_empty())
        .collect();
    assert_eq!(headings, wanted, "the ## sections, in order");

    // Pinned to the versions the fixtures were built with.
    let manifest: serde_json::Value =
        serde_json::from_str(&repo_file("fixtures/zephyr/MANIFEST.json")).unwrap();
    let tag = manifest["zephyr"]["tag"].as_str().unwrap();
    let commit = manifest["zephyr"]["commit"].as_str().unwrap();
    let west = manifest["west"]["version"].as_str().unwrap();
    let intro = doc
        .lines()
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(intro.contains(&format!("**Zephyr {tag}**")), "pin {tag}");
    assert!(
        intro.contains(&format!("`{}`", &commit[..8])),
        "pin {commit}"
    );
    assert!(
        intro.contains(&format!("**west {west}**")),
        "pin west {west}"
    );
    assert!(
        intro.contains("On `main`"),
        "the On `main` notes are explained"
    );

    let required: [(&str, &[&str]); 12] = [
        (
            "## How to reproduce",
            &[
                "cargo build -p rollcall",
                "scripts/check-doc-examples.sh docs/zephyr-gaps.md",
                "scripts/check-doc-links.sh docs/zephyr-gaps.md",
                "scripts/regen-fixtures.sh",
                "hand-written",
            ],
        ),
        (
            "## What west spdx produces",
            &[
                "SPDX-2.3",
                "zephyr.spdx",
                "app.spdx",
                "build.spdx",
                "modules-deps.spdx",
                "GENERATED_FROM",
                "**On `main`:**",
                "--init",
                "--spdx-version",
            ],
        ),
        (
            "## Gap 1: Identifiers",
            &[
                "security.external-references",
                "PackageVersion",
                "--identifier-db",
                "pkg:github/Mbed-TLS/mbedtls@v4.1.0",
                "pkg:generic/",
                "GitHub Actions",
                "trustedfirmware",
                "syft:cpe23",
                "cpe:2.3:o:zephyrproject:zephyr",
                "operating-system",
                "#117299",
                "#105915",
                "#53479",
                "identifiers.md",
                "known-scanner-behaviour",
            ],
        ),
        (
            "## Gap 2: Subsystem split",
            &[
                "^PackageName: zephyr$",
                "bluetooth-controller",
                "bluetooth-host",
                "tls-sockets",
                "fixtures/zephyr-smp",
                "subsystems.md",
                "subpath",
            ],
        ),
        (
            "## Gap 3: MCUboot and sysbuild",
            &[
                "#105917",
                "#120474",
                "build_info.yml",
                "--sysbuild",
                "rollcall:image-kind",
                "bootloader",
                "application",
                "bom-ref",
                "byte-identical",
                "random UUID",
            ],
        ),
        (
            "## Gap 4: Blobs",
            &[
                "blobs:",
                "walker.py",
                "--blob-manifest",
                "crates/rollcall-core/tests/data/blobs/blobs.yaml",
                "hand-written test data",
                "rollcall:opaque",
                "SHA-256",
            ],
        ),
        (
            "## Gap 5: CycloneDX",
            &[
                "SPDX 2.2 or 2.3",
                "CycloneDX 1.6",
                "rollcall validate --schema",
                "--profile all",
                "**On `main`:**",
            ],
        ),
        (
            "## rollcall as the companion",
            &[
                "west build",
                "west spdx",
                "rollcall generate --zephyr build --sysbuild",
                "west rollcall -d BUILD_DIR [--sysbuild] [-o FILE]",
                "**not built yet**",
            ],
        ),
        (
            "## Proposals upstream",
            &["1. **", "2. **", "3. **", "4. **", "CPE part `o`"],
        ),
        (
            "## Outreach log",
            &["| Venue | Draft | Posted | Link | Status |"],
        ),
        ("## Responses", &["None yet"]),
        (
            "## References",
            &[
                "https://github.com/zephyrproject-rtos/zephyr/issues/120474",
                "https://github.com/zephyrproject-rtos/zephyr/issues/117299",
                "https://github.com/zephyrproject-rtos/zephyr/issues/105915",
                "https://github.com/zephyrproject-rtos/zephyr/issues/105917",
                "https://github.com/zephyrproject-rtos/zephyr/issues/53479",
                "https://github.com/CycloneDX/specification/issues/1122",
                "migration-guide-4.5.rst",
            ],
        ),
    ];
    for (heading, terms) in required {
        let body = md_section(&doc, heading).join("\n");
        assert!(!body.trim().is_empty(), "{heading} is empty");
        for term in terms {
            assert!(body.contains(term), "{heading} lacks {term:?}");
        }
    }
    // Exactly four proposals.
    let proposals = md_section(&doc, "## Proposals upstream");
    let numbered = proposals
        .iter()
        .filter(|l| l.len() > 3 && l.as_bytes()[0].is_ascii_digit() && l[1..].starts_with(". **"))
        .count();
    assert_eq!(numbered, 4, "four proposals");
}

/// SHA-134 TP1: every claim section shows commands against the fixtures, in console blocks
/// that `scripts/check-doc-examples.sh` can run (each block starts with a `$ ` command), and
/// every gap shows what rollcall does with a `rollcall` command.
#[test]
fn zephyr_gaps_every_gap_section_has_a_console_example() {
    let doc = repo_file(ZEPHYR_GAPS);
    for heading in ZEPHYR_GAPS_CLAIM_SECTIONS {
        let body = md_section(&doc, heading);
        let consoles = fenced(&body, "console");
        assert!(!consoles.is_empty(), "{heading}: no console example");
        for block in &consoles {
            assert!(
                block.starts_with("$ "),
                "{heading}: a console block must start with a `$ ` command:\n{block}"
            );
        }
        let commands: Vec<&str> = consoles
            .iter()
            .flat_map(|b| b.lines())
            .filter(|l| l.starts_with("$ "))
            .collect();
        assert!(
            commands.iter().any(|c| c.contains("fixtures/")),
            "{heading}: no command reads the fixtures"
        );
        if heading.starts_with("## Gap ") {
            assert!(
                commands.iter().any(|c| c.starts_with("$ rollcall ")),
                "{heading}: no rollcall command"
            );
        }
        // Console blocks are the only examples that are run, so no shell block may hide a
        // claim in a gap section.
        if heading != "## What west spdx produces" {
            assert!(
                fenced(&body, "sh").is_empty(),
                "{heading}: use a console block"
            );
        }
    }
    // The whole document parses for check-doc-examples: every console block is closed and
    // starts with a command.
    let all: Vec<&str> = doc.lines().collect();
    let total = fenced(&all, "console").len();
    assert!(total >= 15, "{total} console blocks");
}

/// GitHub's anchor for a heading's text: lower case, punctuation other than `-` and `_`
/// dropped, spaces as `-`.
fn github_slug(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | ' '))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// The anchors of the headings of a Markdown document, numbered as GitHub numbers repeats.
fn heading_anchors(markdown: &str) -> std::collections::BTreeSet<String> {
    use pulldown_cmark::{Event, Parser, Tag, TagEnd};
    let mut anchors = std::collections::BTreeSet::new();
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    let mut current: Option<String> = None;
    for event in Parser::new(markdown) {
        match event {
            Event::Start(Tag::Heading { .. }) => current = Some(String::new()),
            Event::Text(t) | Event::Code(t) => {
                if let Some(h) = &mut current {
                    h.push_str(&t);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(h) = current.take() {
                    let base = github_slug(h.trim());
                    let n = seen.entry(base.clone()).or_insert(0);
                    anchors.insert(if *n == 0 {
                        base.clone()
                    } else {
                        format!("{base}-{n}")
                    });
                    *n += 1;
                }
            }
            _ => {}
        }
    }
    anchors
}

/// The link targets of a Markdown document (inline, reference and autolinks, and images).
fn link_targets(markdown: &str) -> Vec<String> {
    use pulldown_cmark::{Event, Parser, Tag};
    Parser::new(markdown)
        .filter_map(|event| match event {
            Event::Start(Tag::Link { dest_url, .. })
            | Event::Start(Tag::Image { dest_url, .. }) => Some(dest_url.to_string()),
            _ => None,
        })
        .collect()
}

/// SHA-134 TP2 (in-tree half): every relative link in the gap analysis and the outreach
/// drafts names a file or directory that exists, and every `#anchor` a heading of its
/// target. (http(s) links are checked by `scripts/check-doc-links.sh`, which needs the
/// network.)
#[test]
fn zephyr_gaps_doc_links_resolve_in_tree() {
    let root = repo_root();
    let mut docs = vec![ZEPHYR_GAPS];
    docs.extend(OUTREACH_DRAFTS);
    let mut local = 0;
    let mut external = 0;
    for doc in docs {
        let text = repo_file(doc);
        let dir = root.join(doc).parent().unwrap().to_path_buf();
        for target in link_targets(&text) {
            if target.contains("://") || target.starts_with("mailto:") {
                assert!(
                    target.starts_with("https://"),
                    "{doc}: {target} is not https"
                );
                external += 1;
                continue;
            }
            local += 1;
            let (path, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target.as_str(), None),
            };
            let file = if path.is_empty() {
                root.join(doc)
            } else {
                dir.join(path)
            };
            assert!(file.exists(), "{doc}: {target}: {} missing", file.display());
            if let Some(anchor) = anchor {
                let md = std::fs::read_to_string(&file)
                    .unwrap_or_else(|e| panic!("{doc}: {target}: {e}"));
                assert!(
                    heading_anchors(&md).contains(anchor),
                    "{doc}: {target}: no heading #{anchor} in {}",
                    file.display()
                );
            }
        }
    }
    assert!(local >= 30, "{local} in-tree links");
    assert!(external >= 20, "{external} external links");
}

/// The body of `## <name>` in `doc`, up to the next `## ` heading.
fn h2_body<'a>(doc: &'a str, name: &str) -> Vec<&'a str> {
    md_section(doc, &format!("## {name}"))
}

/// SHA-134 AC2 (drafts): the three outreach drafts exist, say where they go and what to do
/// before posting, link the gap analysis, and carry no tool attribution. The RFC comment is
/// under 250 words and answers the RFC's sysbuild question.
#[test]
fn zephyr_gaps_outreach_drafts_exist_and_link_the_doc() {
    for draft in OUTREACH_DRAFTS {
        let text = repo_file(draft);
        assert!(text.starts_with("# "), "{draft}: no title");
        assert!(text.contains("**Venue"), "{draft}: no venue");
        assert!(
            text.contains("**Before posting:**"),
            "{draft}: no posting note"
        );
        assert!(
            link_targets(&text)
                .iter()
                .any(|t| t.starts_with("../zephyr-gaps.md")),
            "{draft}: does not link the gap analysis"
        );
        // What gets posted (everything from the first `## `) links by GitHub URL, since a
        // relative link means nothing outside the repo.
        let body = text.split_once("\n## ").map_or("", |(_, b)| b);
        for target in link_targets(body) {
            assert!(
                !target.starts_with("../") && !target.starts_with("./"),
                "{draft}: relative link {target} in the postable text"
            );
        }
        for banned in [
            "Claude",
            "Anthropic",
            "AI-generated",
            "Generated with",
            "ChatGPT",
        ] {
            assert!(!text.contains(banned), "{draft}: contains {banned:?}");
        }
    }

    let rfc = repo_file(OUTREACH_DRAFTS[0]);
    assert!(rfc.contains("https://github.com/zephyrproject-rtos/zephyr/issues/120474"));
    let comment = h2_body(&rfc, "Comment").join("\n");
    let words = comment.split_whitespace().count();
    assert!(
        (50..250).contains(&words),
        "the RFC comment has {words} words"
    );
    for term in [
        "sysbuild",
        "build_info.yml",
        "#105917",
        "CycloneDX/specification#1122",
    ] {
        assert!(comment.contains(term), "the RFC comment lacks {term:?}");
    }
    assert!(
        comment.contains("](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md"),
        "the RFC comment links the gap analysis"
    );
    // No pitch: the comment answers the RFC's question and does not name the tool. Link
    // targets are left out: the gap analysis URL names the repository, the prose must not.
    let prose = link_targets(&comment)
        .iter()
        .fold(comment.clone(), |text, target| text.replace(target, ""));
    assert!(
        !prose.to_lowercase().contains("rollcall"),
        "the RFC comment names rollcall"
    );
    assert!(
        !comment.contains("west rollcall"),
        "the RFC comment offers west rollcall"
    );

    let thread = repo_file(OUTREACH_DRAFTS[1]);
    assert!(!h2_body(&thread, "Title").join("").trim().is_empty());
    let post = h2_body(&thread, "Post").join("\n");
    for term in [
        "**Identifiers.**",
        "**Subsystems.**",
        "**Sysbuild.**",
        "**Blobs.**",
        "**CycloneDX.**",
        "`west rollcall`",
        "Security Working Group",
    ] {
        assert!(
            post.contains(term) || thread.contains(term),
            "the thread lacks {term:?}"
        );
    }

    let talk = repo_file(OUTREACH_DRAFTS[2]);
    let sections: Vec<&str> = talk.lines().filter(|l| l.starts_with("## ")).collect();
    for (i, n) in (1..=10).enumerate() {
        assert!(
            sections
                .get(i)
                .is_some_and(|s| s.starts_with(&format!("## {n}. "))),
            "talk section {n}: {sections:?}"
        );
    }
    assert_eq!(sections.get(10), Some(&"## purl questions"));
    let questions = h2_body(&talk, "purl questions");
    for n in 1..=4 {
        assert!(
            questions.iter().any(|l| l.starts_with(&format!("{n}. **"))),
            "purl question {n}"
        );
    }
    for venue in [
        "CycloneDX/specification/discussions",
        "#cyclonedx",
        "SBOM Everywhere SIG",
        "purl-spec/discussions",
    ] {
        assert!(talk.contains(venue), "the talk lacks venue {venue:?}");
    }
}

/// SHA-134 AC2/AC3 bookkeeping: the outreach log has the fixed columns and one row per
/// draft in docs/outreach/, and a row marked posted has its link.
#[test]
fn zephyr_gaps_outreach_log_has_fixed_columns() {
    let doc = repo_file(ZEPHYR_GAPS);
    let log = md_section(&doc, "## Outreach log");
    let table: Vec<&str> = log.iter().copied().filter(|l| l.starts_with('|')).collect();
    assert_eq!(
        table.first().copied(),
        Some("| Venue | Draft | Posted | Link | Status |")
    );
    assert!(
        table.get(1).is_some_and(|l| l.starts_with("|---")),
        "no delimiter row"
    );
    let rows = &table[2..];
    let mut on_disk: Vec<String> = std::fs::read_dir(repo_root().join("docs/outreach"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".md"))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = Vec::new();
    for row in rows {
        let cells: Vec<&str> = row
            .trim()
            .trim_start_matches('|')
            .trim_end_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert_eq!(cells.len(), 5, "{row}");
        let [venue, draft, posted, link, status] = cells[..] else {
            unreachable!()
        };
        assert!(!venue.is_empty() && !status.is_empty(), "{row}");
        let target = draft
            .split_once("](outreach/")
            .and_then(|(_, rest)| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("{row}: draft cell is not a link into outreach/"));
        listed.push(target.to_string());
        if !posted.is_empty() {
            assert!(link.contains("https://"), "{row}: posted without a link");
        }
    }
    listed.sort();
    assert_eq!(listed, on_disk, "one log row per draft");
    let expected: Vec<String> = OUTREACH_DRAFTS
        .iter()
        .map(|d| d.trim_start_matches("docs/outreach/").to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(listed, expected);
}

// SHA-129: the ESP-IDF guide (docs/esp-idf.md) and the ingester's module docs. The guide's
// console examples are run by `scripts/check-doc-examples.sh docs/esp-idf.md` (CI job
// docs-examples).

const ESP_IDF_DOCS: &str = include_str!("../src/esp_idf/mod.rs");

/// The `##` sections of docs/esp-idf.md, in order.
const ESP_IDF_GUIDE_SECTIONS: [&str; 11] = [
    "## Usage",
    "## Inputs",
    "## Mapping",
    "## Subsystems",
    "## Package URLs",
    "## Blobs",
    "## Auto-detect",
    "## Warnings",
    "## Determinism",
    "## Limitations",
    "## Fixtures",
];

#[test]
fn esp_idf_guide_covers_inputs_mapping_split_blobs_and_fixtures() {
    let doc = repo_file("docs/esp-idf.md");
    assert!(doc.starts_with("# ESP-IDF\n"));
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(headings, ESP_IDF_GUIDE_SECTIONS);
    for sub in ["### Regenerating", "### Bumping the pin"] {
        assert!(doc.lines().any(|l| l == sub), "missing {sub}");
    }
    for needle in [
        "--esp-idf",
        "--build",
        "--idf-path",
        "$IDF_PATH",
        "--verbose",
        "dependencies.lock",
        "sdkconfig",
        "idf_component.yml",
        "project_description.json",
        "esp_idf_version.h",
        "pkg:generic/<namespace>/<name>@<version>?repository_url=https://components.espressif.com",
        "pkg:generic/esp-idf@<version>?vcs_url=git+https://github.com/espressif/esp-idf",
        "rollcall:opaque",
        "Espressif Systems",
        "SHA-256",
        "scripts/regen-fixtures-esp-idf.sh",
        "--check-stable",
        "sha256:dfa2d076c796769c07c155eba6c672b9f395aec943b2ba3701b73379b5f9e884",
        "examples/protocols/https_request",
        "examples/get-started/hello_world",
        "CI is canonical",
        "```console",
    ] {
        assert!(doc.contains(needle), "docs/esp-idf.md lacks {needle:?}");
    }
    // Every subsystem of the table is in the guide's subsystem table.
    for subsystem in rollcall_core::esp_idf::table::builtin().unwrap().subsystems {
        assert!(
            doc.contains(&format!("| `{}` |", subsystem.name)),
            "docs/esp-idf.md does not list subsystem {}",
            subsystem.name
        );
    }
    // The module docs have the sections every ingester documents.
    for heading in [
        "//! # Inputs",
        "//! # Mapping",
        "//! # Warnings",
        "//! # Determinism",
    ] {
        assert!(
            ESP_IDF_DOCS.contains(heading),
            "missing section {heading:?} in esp_idf/mod.rs"
        );
    }
    // The guide is linked from the README and the fixtures doc.
    for (file, link) in [
        ("README.md", "docs/esp-idf.md"),
        ("docs/fixtures.md", "esp-idf.md"),
    ] {
        assert!(
            repo_file(file).contains(link),
            "{file} does not link {link}"
        );
    }
}

// SHA-131: the PlatformIO guide (docs/platformio.md), the docs index's ecosystem comparison
// table (docs/README.md), and an Auto-detect section in every ecosystem's guide. The console
// examples are run by `scripts/check-doc-examples.sh docs/platformio.md docs/README.md
// docs/zephyr.md docs/cargo.md` (CI job docs-examples).

const PLATFORMIO_DOCS: &str = include_str!("../src/platformio/mod.rs");

/// The `##` sections of docs/platformio.md, in order.
const PLATFORMIO_GUIDE_SECTIONS: [&str; 9] = [
    "## Usage",
    "## Inputs",
    "## Mapping",
    "## Package URLs",
    "## Auto-detect",
    "## Warnings",
    "## Determinism",
    "## Limitations",
    "## Fixtures",
];

/// The four ecosystems: (name, guide, input flag, detection signal).
const ECOSYSTEMS: [(&str, &str, &str, &str); 4] = [
    ("zephyr", "docs/zephyr.md", "--zephyr DIR", "build_info.yml"),
    ("cargo", "docs/cargo.md", "--cargo DIR", "Cargo.toml"),
    ("esp-idf", "docs/esp-idf.md", "--esp-idf DIR", "sdkconfig"),
    (
        "platformio",
        "docs/platformio.md",
        "--platformio DIR",
        "platformio.ini",
    ),
];

#[test]
fn platformio_guide_covers_inputs_mapping_purls_detection_and_fixtures() {
    let doc = repo_file("docs/platformio.md");
    assert!(doc.starts_with("# PlatformIO\n"));
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(headings, PLATFORMIO_GUIDE_SECTIONS);
    for sub in ["### Regenerating", "### Bumping the pins"] {
        assert!(doc.lines().any(|l| l == sub), "missing {sub}");
    }
    for needle in [
        "--platformio",
        "--env",
        "--pio-core",
        "$PLATFORMIO_CORE_DIR",
        "--ecosystem",
        "rollcall detect",
        "platformio.ini",
        "library.json",
        ".piopm",
        "platform.json",
        "package.json",
        "extends",
        "${sysenv.NAME}",
        "lib_deps",
        "platform_packages",
        "pkg:generic/<owner>/<name>@<version>?repository_url=https://registry.platformio.org",
        "pkg:generic/arduino-esp32@<version>?vcs_url=git+https://github.com/espressif/arduino-esp32",
        "scope: excluded",
        "framework = espidf",
        "scripts/regen-fixtures-platformio.sh",
        "--check-stable",
        "sha256:9901e0a8d75037d8242ed43155cbcb2d1f61be1356383d8054afb59fd50e39c4",
        "--require-hashes",
        "6.1.18",
        "6.10.0",
        "3.20017.241212",
        "2.0.17",
        "CI is canonical",
        "```console",
    ] {
        assert!(doc.contains(needle), "docs/platformio.md lacks {needle:?}");
    }
    // Every framework package of the table is in the guide's table.
    for f in rollcall_core::platformio::table::builtin()
        .unwrap()
        .frameworks
    {
        assert!(
            doc.contains(&format!("| `{}` |", f.package)),
            "docs/platformio.md does not list {}",
            f.package
        );
    }
    for heading in [
        "//! # Inputs",
        "//! # Mapping",
        "//! # Package URLs",
        "//! # Warnings",
        "//! # Determinism",
    ] {
        assert!(
            PLATFORMIO_DOCS.contains(heading),
            "missing section {heading:?} in platformio/mod.rs"
        );
    }
    for (file, link) in [
        ("README.md", "docs/platformio.md"),
        ("docs/fixtures.md", "platformio.md"),
        ("docs/README.md", "platformio.md"),
    ] {
        assert!(
            repo_file(file).contains(link),
            "{file} does not link {link}"
        );
    }
}

#[test]
fn docs_index_has_ecosystem_comparison_table_for_all_four() {
    let doc = repo_file("docs/README.md");
    let table = md_section(&doc, "## Ecosystems");
    let rows: Vec<&str> = table
        .iter()
        .copied()
        .filter(|l| l.starts_with("| `"))
        .collect();
    assert_eq!(rows.len(), 4, "{rows:#?}");
    let header = table
        .iter()
        .find(|l| l.starts_with("| Ecosystem"))
        .expect("a table header");
    for column in ["Input flag", "Auto-detect signal", "Inputs read", "Guide"] {
        assert!(header.contains(column), "no {column} column: {header}");
    }
    for ((name, guide, flag, signal), row) in ECOSYSTEMS.iter().zip(&rows) {
        assert!(row.starts_with(&format!("| `{name}` |")), "{row}");
        assert!(row.contains(flag), "{name}: {row} lacks {flag}");
        assert!(row.contains(signal), "{name}: {row} lacks {signal}");
        let file = guide.trim_start_matches("docs/");
        assert!(
            row.contains(&format!("]({file})")),
            "{name}: {row} does not link {file}"
        );
        assert!(repo_root().join(guide).is_file(), "{guide} does not exist");
    }
    // Every guide the index links exists.
    for target in link_targets(&doc) {
        if target.starts_with("http") {
            continue;
        }
        let path = target.split('#').next().unwrap();
        assert!(
            repo_root().join("docs").join(path).exists(),
            "docs/README.md links {target}, which does not exist"
        );
    }
}

#[test]
fn every_ecosystem_guide_documents_auto_detect() {
    for (name, guide, flag, signal) in ECOSYSTEMS {
        let doc = repo_file(guide);
        let section = md_section(&doc, "## Auto-detect").join("\n");
        assert!(
            !section.trim().is_empty(),
            "{guide} has no ## Auto-detect section"
        );
        for needle in ["rollcall generate DIR", signal] {
            assert!(
                section.contains(needle),
                "{guide}: Auto-detect lacks {needle:?}"
            );
        }
        assert!(
            section.contains("$ rollcall detect") && section.contains(&format!("\n{name}\n")),
            "{guide}: Auto-detect has no `rollcall detect` example printing {name}"
        );
        assert!(
            doc.contains(flag.split(' ').next().unwrap()),
            "{guide} lacks {flag}"
        );
    }
    // The README's Auto-detect section names every signal.
    let readme = repo_file("README.md");
    let section = md_section(&readme, "### Auto-detect").join("\n");
    for (name, _, _, signal) in ECOSYSTEMS {
        assert!(
            section.contains(&format!("`{name}`")) && section.contains(signal),
            "README Auto-detect lacks {name}"
        );
    }
}

// SHA-125: the docs site (book.toml, docs/SUMMARY.md, scripts/mdbook-repo-links.py), the
// getting-started pages, the FAQ and the release documents (CHANGELOG.md, SECURITY.md,
// docs/versioning.md, docs/releases/). The site itself is built by `scripts/build-docs.sh`
// and its links checked by `scripts/check-site-links.sh` (CI workflow docs.yml); the
// quickstart's console examples are run by `scripts/check-doc-examples.sh docs/quickstart.md`.

/// Every Markdown file under `docs/`, relative to `docs/`, sorted.
fn docs_markdown_files() -> Vec<String> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<String>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("readable directory entry").path();
            if path.is_dir() {
                walk(&path, base, out);
            } else if path.extension().is_some_and(|x| x == "md") {
                let rel = path.strip_prefix(base).expect("under docs/");
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let base = repo_root().join("docs");
    let mut out = Vec::new();
    walk(&base, &base, &mut out);
    out.sort();
    out
}

/// The `version` of `[workspace.package]` in the workspace `Cargo.toml` (`key` = "version"),
/// or its `rust-version`.
fn workspace_package_field(key: &str) -> String {
    let cargo = repo_file("Cargo.toml");
    let mut in_section = false;
    for line in cargo.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line == "[workspace.package]";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return v.trim().trim_matches('"').to_string();
        }
    }
    panic!("Cargo.toml [workspace.package] has no {key}")
}

/// The released versions of CHANGELOG.md (`## [x.y.z] - date` headings), newest first, with
/// their dates.
fn changelog_releases() -> Vec<(semver::Version, String)> {
    repo_file("CHANGELOG.md")
        .lines()
        .filter_map(|l| l.strip_prefix("## ["))
        .filter(|l| !l.starts_with("Unreleased]"))
        .map(|l| {
            let (version, rest) = l.split_once("] - ").unwrap_or_else(|| {
                panic!("CHANGELOG heading `## [{l}` is not `## [x.y.z] - YYYY-MM-DD`")
            });
            let version = semver::Version::parse(version)
                .unwrap_or_else(|e| panic!("CHANGELOG version {version:?}: {e}"));
            (version, rest.to_string())
        })
        .collect()
}

/// The newest released version in CHANGELOG.md, which the docs pin (`v0.1.0`).
fn top_release() -> semver::Version {
    changelog_releases()
        .into_iter()
        .next()
        .expect("CHANGELOG.md has a released version")
        .0
}

/// The fenced blocks of `lang` anywhere in `doc`, with what follows the language on the fence
/// line ignored.
fn fenced_blocks(doc: &str, lang: &str) -> Vec<String> {
    let lines: Vec<&str> = doc.lines().collect();
    fenced(&lines, lang)
}

/// SHA-125 (docs site): docs/SUMMARY.md, the site's table of contents, links every Markdown
/// file under docs/ exactly once and nothing else, so no page is missing from the site.
#[test]
fn summary_lists_every_docs_page_exactly_once() {
    let summary = repo_file("docs/SUMMARY.md");
    let mut listed = std::collections::BTreeMap::<String, usize>::new();
    for target in link_targets(&summary) {
        assert!(
            !target.contains("://") && !target.contains('#'),
            "SUMMARY.md links {target}: only pages, without anchors"
        );
        *listed.entry(target).or_default() += 1;
    }
    for (page, n) in &listed {
        assert_eq!(*n, 1, "SUMMARY.md lists {page} {n} times");
    }
    let files: Vec<String> = docs_markdown_files()
        .into_iter()
        .filter(|f| f != "SUMMARY.md")
        .collect();
    let listed: Vec<String> = listed.into_keys().collect();
    let missing: Vec<&String> = files.iter().filter(|f| !listed.contains(f)).collect();
    let extra: Vec<&String> = listed.iter().filter(|f| !files.contains(f)).collect();
    assert!(
        missing.is_empty(),
        "docs pages not in SUMMARY.md: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "SUMMARY.md lists files that do not exist: {extra:?}"
    );
    // The introduction is the docs index.
    assert!(
        summary.contains("\n[Introduction](README.md)\n"),
        "SUMMARY.md does not start with the docs index as its introduction"
    );
    for page in [
        "quickstart.md",
        "zephyr.md",
        "contributing-identifiers.md",
        "vex-rules.md",
        "ci.md",
        "faq-cra-cisa.md",
        "versioning.md",
        "releases/v0.1.0.md",
    ] {
        assert!(files.iter().any(|f| f == page), "docs/{page} is missing");
    }
}

/// SHA-125 (quickstart, TP1): the quickstart has the five steps in order (install, prepare,
/// generate, validate, report), each install route as one `sh` block pinned to the released
/// version, the example build in a `sh` block, and the generate, validate and report commands
/// as console examples (which `scripts/check-doc-examples.sh` runs). The clean-machine
/// workflow follows exactly these blocks.
#[test]
fn quickstart_doc_has_install_prepare_generate_validate_report_sections() {
    let doc = repo_file("docs/quickstart.md");
    let version = top_release();
    let tag = format!("v{version}");
    let headings = [
        "# Quickstart",
        "## 1. Install rollcall",
        "### Release binary (Linux and macOS)",
        "### cargo",
        "### pip",
        "## 2. Prepare a build directory",
        "### Your own Zephyr build",
        "### No build at hand: the example build",
        "## 3. Generate the SBOM",
        "## 4. Validate it",
        "## 5. Report on it",
    ];
    let mut last = 0;
    for heading in headings {
        let at = doc
            .lines()
            .position(|l| l == heading)
            .unwrap_or_else(|| panic!("quickstart lacks {heading:?}"));
        assert!(at >= last, "{heading:?} is out of order");
        last = at;
    }
    let sh = |heading: &str| -> String {
        let blocks = fenced(&md_section(&doc, heading), "sh");
        assert_eq!(blocks.len(), 1, "{heading}: expected one sh block");
        blocks[0].clone()
    };
    let tarball = sh("### Release binary (Linux and macOS)");
    for needle in [
        format!("VERSION={tag}"),
        "SHA256SUMS".to_string(),
        "sha256sum --check".to_string(),
        "rollcall-$VERSION-$TARGET.tar.gz".to_string(),
        // The archive holds one directory, rollcall-<tag>-<target>/ (SHA-124's
        // scripts/package-release.sh), with the binary inside it.
        "install -m 0755 \"rollcall-$VERSION-$TARGET/rollcall\"".to_string(),
        "rollcall --version".to_string(),
    ] {
        assert!(
            tarball.contains(&needle),
            "tarball install lacks {needle:?}"
        );
    }
    let tarball_section = md_section(&doc, "### Release binary (Linux and macOS)").join("\n");
    for target in ["linux-amd64", "linux-arm64", "darwin-universal"] {
        assert!(
            tarball_section.contains(target),
            "tarball install does not name {target}"
        );
    }
    assert!(
        tarball_section.contains(&format!("rollcall-{tag}-windows-amd64.zip"))
            && tarball_section.contains(&format!("rollcall-{tag}-windows-amd64\\rollcall.exe")),
        "tarball install does not name the Windows zip and the binary's path in it"
    );
    assert!(
        sh("### cargo").contains(&format!(
            "cargo install rollcall --locked --version {version}"
        )),
        "cargo install is not pinned to {version}"
    );
    assert!(
        sh("### pip").contains(&format!("pip install rollcall=={version}")),
        "pip install is not pinned to {version}"
    );
    let example = sh("### No build at hand: the example build");
    assert!(
        example.contains(&format!("archive/refs/tags/{tag}.tar.gz"))
            && example.contains(&format!("rollcall-{version}/fixtures/zephyr/tls")),
        "the example build is not taken from the {tag} source archive"
    );
    assert!(
        repo_root()
            .join("fixtures/zephyr/tls/domains.yaml")
            .exists(),
        "fixtures/zephyr/tls is not a sysbuild build"
    );
    let own = sh("### Your own Zephyr build");
    for needle in [
        "west spdx --init",
        "--sysbuild",
        "CONFIG_BUILD_OUTPUT_META",
        "west list",
    ] {
        assert!(own.contains(needle), "own-build steps lack {needle:?}");
    }
    let console = |heading: &str| -> String {
        let blocks = fenced(&md_section(&doc, heading), "console");
        assert!(!blocks.is_empty(), "{heading}: no console example");
        blocks.join("")
    };
    assert!(console("## 3. Generate the SBOM").contains("$ rollcall generate fixtures/zephyr/tls"));
    let validate = console("## 4. Validate it");
    assert!(
        validate.contains("$ rollcall validate --schema product.cdx.json\n")
            && validate.contains("product.cdx.json: valid CycloneDX 1.6\n"),
        "the validate example does not show a valid SBOM"
    );
    assert!(console("## 5. Report on it").contains("$ rollcall report --format md"));
    // The clean-machine run follows these blocks for all three install routes.
    let workflow = repo_file(".github/workflows/quickstart-clean.yml");
    assert!(workflow.contains("method: [tarball, cargo, pip]"));
    assert!(workflow.contains("scripts/quickstart-clean.sh"));
    assert!(
        !workflow.contains("actions/checkout"),
        "the clean-machine run must not check out the repository"
    );
}

/// SHA-125 (CI recipe): every use of the Action in docs/ci.md is pinned to the release tag,
/// downloads that release's binary, and passes only inputs action/action.yml declares; the
/// tuning table names only real inputs too.
#[test]
fn ci_recipe_doc_pins_the_action_to_the_release_tag_and_uses_real_inputs() {
    let tag = format!("v{}", top_release());
    let action: yaml_serde::Value =
        yaml_serde::from_str(&repo_file("action/action.yml")).expect("action.yml parses");
    let inputs: std::collections::BTreeSet<String> = action
        .get("inputs")
        .and_then(|i| i.as_mapping())
        .expect("action.yml has inputs")
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .collect();
    let doc = repo_file("docs/ci.md");
    assert!(
        !doc.contains("action@main"),
        "docs/ci.md uses the Action at @main"
    );
    let workflows = fenced_blocks(&doc, "yaml");
    assert!(!workflows.is_empty(), "docs/ci.md has no workflow");
    let mut uses = 0;
    for block in &workflows {
        let workflow: yaml_serde::Value =
            yaml_serde::from_str(block).unwrap_or_else(|e| panic!("docs/ci.md workflow: {e}"));
        let jobs = workflow
            .get("jobs")
            .and_then(|j| j.as_mapping())
            .expect("the workflow has jobs");
        for job in jobs.values() {
            for step in job
                .get("steps")
                .and_then(|s| s.as_sequence())
                .expect("each job has steps")
            {
                let Some(name) = step.get("uses").and_then(|u| u.as_str()) else {
                    continue;
                };
                if let Some(r) = name.strip_prefix("smhasan94/rollcall/action@") {
                    uses += 1;
                    assert_eq!(r, tag, "the Action is pinned to {r}, not {tag}");
                    let with = step
                        .get("with")
                        .and_then(|w| w.as_mapping())
                        .expect("the Action step has `with`");
                    for key in with.keys().filter_map(|k| k.as_str()) {
                        assert!(
                            inputs.contains(key),
                            "docs/ci.md passes unknown input {key}"
                        );
                    }
                    assert_eq!(
                        with.get("rollcall-version").and_then(|v| v.as_str()),
                        Some(tag.as_str()),
                        "rollcall-version is not the release tag"
                    );
                } else {
                    assert!(
                        name.split_once('@').is_some_and(
                            |(_, r)| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit())
                        ),
                        "{name} is not pinned to a commit SHA"
                    );
                }
            }
        }
    }
    assert!(uses >= 1, "docs/ci.md never uses the Action");
    let tuning = md_section(&doc, "## Tuning");
    let mut keys = 0;
    for line in tuning.iter().filter(|l| l.starts_with('|')) {
        let cell = line.rsplit('|').nth(1).unwrap_or_default();
        for code in cell.split('`').skip(1).step_by(2) {
            if let Some((key, _)) = code.split_once(": ") {
                keys += 1;
                assert!(inputs.contains(key), "Tuning names unknown input {key}");
            }
        }
    }
    assert!(keys >= 5, "Tuning names {keys} inputs");
}

/// SHA-125 (FAQ): the FAQ carries the not-legal-advice disclaimer, every question (an H2
/// ending in `?`) ends with a `Source:` or `Sources:` line naming a primary source from the
/// list at the top, and that list links EUR-Lex, CISA (the same documents and URLs as
/// docs/validate.md), NTIA and CycloneDX.
#[test]
fn faq_doc_cites_a_primary_source_per_question_and_disclaims_legal_advice() {
    let doc = repo_file("docs/faq-cra-cisa.md");
    let disclaimer: String = doc
        .lines()
        .take_while(|l| l.starts_with('>') || l.starts_with('#') || l.is_empty())
        .filter_map(|l| l.strip_prefix('>'))
        .collect::<Vec<_>>()
        .join(" ");
    let disclaimer = disclaimer.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        disclaimer.starts_with("**Not legal advice.**")
            && disclaimer.contains("It is not legal advice"),
        "the FAQ does not open with its disclaimer: {disclaimer:?}"
    );
    let validate = repo_file("docs/validate.md");
    for url in [
        "https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
        "https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom",
        "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf",
    ] {
        assert!(doc.contains(url), "the FAQ does not cite {url}");
        assert!(
            validate.contains(url),
            "docs/validate.md does not cite {url}"
        );
    }
    for url in [
        "https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom",
        "https://cyclonedx.org/docs/1.6/json/",
    ] {
        assert!(doc.contains(url), "the FAQ does not cite {url}");
    }
    for title in [
        "Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 (Cyber Resilience Act), OJ L, 2024/2847, 20.11.2024",
        "2026 Minimum Elements for a Software Bill of Materials (SBOM), version 2.1, July 29, 2026",
    ] {
        assert!(
            doc.contains(title),
            "the FAQ does not cite {title:?} as validate.md does"
        );
        assert!(validate.contains(title), "docs/validate.md lacks {title:?}");
    }
    let sources = [
        "CRA",
        "CISA 2026",
        "NTIA 2021",
        "CycloneDX 1.6",
        "BSI TR-03183-2",
    ];
    let questions: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    assert!(questions.len() >= 8, "{} questions", questions.len());
    let mut cited = std::collections::BTreeSet::new();
    for question in questions {
        assert!(question.ends_with('?'), "{question:?} is not a question");
        let body = md_section(&doc, question).join("\n");
        let source = body
            .split("\n\n")
            .filter(|p| p.starts_with("Source: ") || p.starts_with("Sources: "))
            .last()
            .unwrap_or_else(|| panic!("{question:?} cites no source"));
        let named: Vec<&str> = sources
            .iter()
            .copied()
            .filter(|s| source.contains(s))
            .collect();
        assert!(
            !named.is_empty(),
            "{question:?}: {source:?} names no primary source"
        );
        cited.extend(named);
    }
    for source in ["CRA", "CISA 2026", "NTIA 2021", "CycloneDX 1.6"] {
        assert!(cited.contains(source), "no answer cites {source}");
    }
}

/// SHA-125 (release hygiene): CHANGELOG.md follows Keep a Changelog (title, `[Unreleased]`
/// first, released versions newest first with ISO dates, only its section names, a link
/// reference per version), and its top released entry is the workspace version. While the
/// workspace is still at a 0.0.x placeholder or a pre-release (before the v0.1.0 bump), the
/// 0.1.0 entry must exist instead.
#[test]
fn changelog_top_entry_matches_workspace_version_and_keep_a_changelog_layout() {
    let doc = repo_file("CHANGELOG.md");
    assert_eq!(doc.lines().next(), Some("# Changelog"));
    assert!(doc.contains("[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/)"));
    let h2: Vec<&str> = doc.lines().filter(|l| l.starts_with("## ")).collect();
    assert_eq!(
        h2.first(),
        Some(&"## [Unreleased]"),
        "[Unreleased] is not first"
    );
    let releases = changelog_releases();
    assert!(!releases.is_empty(), "no released version");
    for (version, date) in &releases {
        let ok = date.len() == 10
            && date.char_indices().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            });
        assert!(ok, "{version}: date {date:?} is not YYYY-MM-DD");
        assert!(
            doc.lines()
                .any(|l| l.starts_with(&format!("[{version}]: https://"))),
            "{version} has no link reference"
        );
    }
    assert!(doc.lines().any(|l| l.starts_with("[Unreleased]: https://")));
    for pair in releases.windows(2) {
        assert!(
            pair[0].0 > pair[1].0,
            "{} is listed above {}",
            pair[0].0,
            pair[1].0
        );
        assert!(
            pair[0].1 >= pair[1].1,
            "{} is dated before {}",
            pair[0].0,
            pair[1].0
        );
    }
    for line in doc.lines().filter(|l| l.starts_with("### ")) {
        assert!(
            [
                "### Added",
                "### Changed",
                "### Deprecated",
                "### Removed",
                "### Fixed",
                "### Security"
            ]
            .contains(&line),
            "{line:?} is not a Keep a Changelog section"
        );
    }
    let workspace = semver::Version::parse(&workspace_package_field("version"))
        .expect("the workspace version is semver");
    let placeholder = (workspace.major == 0 && workspace.minor == 0) || !workspace.pre.is_empty();
    if placeholder {
        assert!(
            releases
                .iter()
                .any(|(v, _)| *v == semver::Version::new(0, 1, 0)),
            "the workspace is at {workspace} (before the v0.1.0 bump) and CHANGELOG.md has no 0.1.0 entry"
        );
    } else {
        assert_eq!(
            releases[0].0, workspace,
            "the top released CHANGELOG entry is not the workspace version"
        );
    }
    let notes = format!("docs/releases/v{}.md", releases[0].0);
    assert!(repo_root().join(&notes).exists(), "{notes} is missing");
    // The release notes link the release's CHANGELOG entry by the anchor of its heading, so
    // a date change in the heading cannot leave the link stale.
    for (version, date) in &releases {
        let notes = format!("docs/releases/v{version}.md");
        let Ok(text) = std::fs::read_to_string(repo_root().join(&notes)) else {
            continue;
        };
        let anchor = github_slug(&format!("[{version}] - {date}"));
        assert!(
            heading_anchors(&doc).contains(&anchor),
            "CHANGELOG.md has no heading anchor #{anchor}"
        );
        let changelog_links: Vec<String> = link_targets(&text)
            .into_iter()
            .filter(|t| t.starts_with("../../CHANGELOG.md"))
            .collect();
        assert!(
            !changelog_links.is_empty(),
            "{notes} does not link CHANGELOG.md"
        );
        for link in changelog_links {
            assert_eq!(
                link,
                format!("../../CHANGELOG.md#{anchor}"),
                "{notes} links {link}, not the CHANGELOG heading of {version}"
            );
        }
    }
}

/// SHA-125 (release hygiene): SECURITY.md sends reporters to GitHub's private vulnerability
/// reporting, has the supported-versions table with the current release series, and says
/// what to expect and what is in scope.
#[test]
fn security_policy_names_private_vulnerability_reporting() {
    let doc = repo_file("SECURITY.md");
    for heading in [
        "# Security policy",
        "## Supported versions",
        "## Reporting a vulnerability",
        "## What to expect",
        "## Scope",
    ] {
        assert!(
            doc.lines().any(|l| l == heading),
            "SECURITY.md lacks {heading:?}"
        );
    }
    assert!(doc.contains("private vulnerability reporting"));
    assert!(doc.contains("https://github.com/smhasan94/rollcall/security/advisories/new"));
    assert!(doc.contains("Do not open a public issue"));
    let release = top_release();
    let series = format!("| {}.{}.x ", release.major, release.minor);
    assert!(
        md_section(&doc, "## Supported versions")
            .iter()
            .any(|l| l.starts_with(&series) && l.contains("Yes")),
        "the supported-versions table does not support {series}"
    );
}

/// SHA-125 (release hygiene): docs/versioning.md states the MSRV as the workspace
/// `rust-version`, rust-toolchain.toml is not older than it, and the page has the release
/// runbook.
#[test]
fn versioning_policy_states_msrv_equal_to_cargo_rust_version() {
    let doc = repo_file("docs/versioning.md");
    let msrv = workspace_package_field("rust-version");
    assert!(
        doc.contains(&format!("**Rust {msrv}**")),
        "docs/versioning.md does not state the MSRV as Rust {msrv}"
    );
    let parse = |v: &str| -> Vec<u64> {
        v.split('.')
            .map(|p| p.parse().unwrap_or_else(|e| panic!("version {v:?}: {e}")))
            .collect()
    };
    let toolchain = repo_file("rust-toolchain.toml");
    let channel = toolchain
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .expect("rust-toolchain.toml has a channel")
        .trim_matches('"');
    assert!(
        parse(channel) >= parse(&msrv),
        "rust-toolchain.toml {channel} is older than the MSRV {msrv}"
    );
    assert!(doc.contains(&format!("rust-toolchain.toml` ({channel})")));
    for heading in ["## Semantic versioning", "## MSRV", "## Releasing"] {
        assert!(
            doc.lines().any(|l| l == heading),
            "versioning.md lacks {heading:?}"
        );
    }
    let releasing = md_section(&doc, "## Releasing").join("\n");
    for needle in [
        "[Releasing rollcall](release.md)",
        "CHANGELOG.md",
        "docs/releases/vX.Y.Z.md",
        "scripts/release-version.sh check v0.1.0",
        "`cargo deny check` and `cargo doc`",
        "quickstart-clean.yml",
        ".lycheeignore",
    ] {
        assert!(releasing.contains(needle), "Releasing lacks {needle:?}");
    }
}

/// SHA-125 (release notes, AC3): the v0.1.0 notes, which the release workflow publishes as the
/// GitHub Release body, say the output is CycloneDX 1.6 only with SPDX deferred to #37 and a
/// lossy converter named, list the known limitations (including Arduino-ESP32 2.0.17's open
/// CVEs), and name the follow-ups #33, #35 and #37.
#[test]
fn release_notes_v0_1_0_say_cyclonedx_only_and_name_follow_ups() {
    let doc = repo_file("docs/releases/v0.1.0.md");
    assert_eq!(doc.lines().next(), Some("# rollcall v0.1.0"));
    for needle in [
        "**CycloneDX 1.6 JSON only**",
        "[#37](https://github.com/smhasan94/rollcall/issues/37)",
        "cyclonedx convert --input-file sbom.cdx.json",
        "**lossy**",
        "Arduino-ESP32 2.0.17",
        "has open CVEs",
        "SHA256SUMS",
        "gh attestation verify",
        "cargo install rollcall",
        "pip install rollcall==0.1.0",
        "smhasan94/rollcall/action@v0.1.0",
    ] {
        assert!(doc.contains(needle), "release notes lack {needle:?}");
    }
    for asset in [
        "rollcall-v0.1.0-linux-amd64.tar.gz",
        "rollcall-v0.1.0-linux-arm64.tar.gz",
        "rollcall-v0.1.0-darwin-universal.tar.gz",
        "rollcall-v0.1.0-windows-amd64.zip",
    ] {
        assert!(doc.contains(asset), "release notes do not list {asset}");
    }
    let limitations = md_section(&doc, "## Known limitations").join("\n");
    for needle in [
        "zephyr-gaps.md",
        "esp-idf.md",
        "platformio.md",
        "Arduino-ESP32 2.0.17",
    ] {
        assert!(
            limitations.contains(needle),
            "Known limitations lack {needle:?}"
        );
    }
    let follow_ups = md_section(&doc, "## Follow-ups").join("\n");
    for issue in [33, 35, 37] {
        assert!(
            follow_ups.contains(&format!(
                "[#{issue}](https://github.com/smhasan94/rollcall/issues/{issue})"
            )),
            "Follow-ups lack #{issue}"
        );
    }
    let changelog = repo_file("CHANGELOG.md");
    assert!(changelog.contains("[docs/releases/v0.1.0.md](docs/releases/v0.1.0.md)"));
}

/// SHA-125 (docs site): book.toml builds the site from docs/ under /rollcall/, fails on a
/// SUMMARY.md typo, and runs the link preprocessor after mdBook's `links`; the identifier-DB
/// guide is CONTRIBUTING.md's section, included by anchor; the build and link-check scripts
/// pin mdBook and lychee by version and SHA-256; and docs.yml runs them with every action
/// pinned to a commit SHA.
#[test]
fn book_toml_sources_docs_and_registers_the_link_preprocessor() {
    let book = repo_file("book.toml");
    let has = |line: &str| book.lines().any(|l| l.trim() == line);
    for line in [
        "src = \"docs\"",
        "create-missing = false",
        "[preprocessor.repo-links]",
        "command = \"python3 scripts/mdbook-repo-links.py\"",
        "after = [\"links\"]",
        "site-url = \"/rollcall/\"",
        "git-repository-url = \"https://github.com/smhasan94/rollcall\"",
    ] {
        assert!(has(line), "book.toml lacks {line:?}");
    }
    assert!(repo_root().join("scripts/mdbook-repo-links.py").exists());

    let guide = repo_file("docs/contributing-identifiers.md");
    assert!(guide.contains(
        "<!-- repo-links: base=../CONTRIBUTING.md -->\n{{#include ../CONTRIBUTING.md:identifier-db}}\n<!-- repo-links: end -->"
    ));
    let contributing = repo_file("CONTRIBUTING.md");
    let start = contributing
        .find("ANCHOR: identifier-db")
        .expect("CONTRIBUTING.md has the identifier-db anchor");
    let end = contributing
        .find("ANCHOR_END: identifier-db")
        .expect("CONTRIBUTING.md closes the identifier-db anchor");
    let section = &contributing[start..end];
    assert!(section.contains("### 1. Check that the module is missing and pinned"));
    assert!(section.contains("<!-- example:end -->"));

    let sha256_pins = |script: &str, var: &str| {
        let text = repo_file(script);
        assert!(
            text.lines().any(|l| l.starts_with(&format!("{var}="))),
            "{script} does not pin {var}"
        );
        let hashes: Vec<&str> = text
            .lines()
            .filter_map(|l| {
                l.trim()
                    .split_once(") echo ")
                    .map(|(_, h)| h.trim_end_matches(" ;;"))
            })
            .collect();
        assert!(
            hashes.len() >= 4,
            "{script}: {} pinned SHA-256s",
            hashes.len()
        );
        for h in hashes {
            assert!(
                h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()),
                "{script}: {h:?} is not a SHA-256"
            );
        }
    };
    sha256_pins("scripts/build-docs.sh", "MDBOOK_VERSION");
    sha256_pins("scripts/check-site-links.sh", "LYCHEE_VERSION");

    let workflow = repo_file(".github/workflows/docs.yml");
    for needle in [
        "scripts/build-docs.sh --install",
        "scripts/check-site-links.sh --install",
        "python3 scripts/mdbook-repo-links.py --self-test",
        "name: Check site links (lychee)",
        "name: Verify live",
        "path: target/book",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
    ] {
        assert!(workflow.contains(needle), "docs.yml lacks {needle:?}");
    }
    for workflow in ["docs.yml", "quickstart-clean.yml"] {
        let text = repo_file(&format!(".github/workflows/{workflow}"));
        for line in text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("- uses: "))
        {
            let (_, r) = line.split_once('@').expect("uses names a ref");
            let sha = r.split_whitespace().next().unwrap_or_default();
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{workflow}: {line} is not pinned to a commit SHA"
            );
        }
    }
    let ci = repo_file(".github/workflows/ci.yml");
    for needle in [
        "python3 scripts/mdbook-repo-links.py --self-test",
        "tags: [\"v*\"]",
        "EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25",
        "docs/quickstart.md\n",
    ] {
        assert!(ci.contains(needle), "ci.yml lacks {needle:?}");
    }
}

/// Runs `scripts/tolerate-pending-release-link.sh TAG RC REPORT` with `rows` (check-doc-links
/// table rows: where, result, target, detail) as the report; its exit code.
fn tolerate_pending_release_link(tag: &str, rc: &str, rows: &[(&str, &str, &str, &str)]) -> i32 {
    let dir = tempfile::tempdir().expect("temporary directory");
    let mut report = String::from("LINK                  RESULT  TARGET  DETAIL\n");
    for (place, result, target, detail) in rows {
        report.push_str(&format!("{place:<20}  {result:<6}  {target}  {detail}\n"));
    }
    let failed = rows.iter().any(|r| r.1 == "FAIL");
    report.push_str(if failed {
        "\ncheck-doc-links: FAIL\n"
    } else {
        "\ncheck-doc-links: PASS (1 checked, 0 skipped)\n"
    });
    let path = dir.path().join("links.txt");
    std::fs::write(&path, report).expect("write the report");
    let out = std::process::Command::new("bash")
        .arg(repo_root().join("scripts/tolerate-pending-release-link.sh"))
        .args([tag, rc])
        .arg(&path)
        .output()
        .expect("bash runs");
    out.status.code().expect("exited with a code")
}

/// SHA-125 (ci.yml docs-links, the tag-only step): on a release tag's own CI run only an HTTP
/// 404 on exactly that tag's GitHub Release page is tolerated (release.yml creates it after
/// the run); every other failure fails the step.
#[test]
fn tag_run_tolerates_only_this_tags_release_page_404() {
    const URL: &str = "https://github.com/smhasan94/rollcall/releases/tag/v0.1.0";
    let this_404 = (
        "CHANGELOG.md:69",
        "FAIL",
        URL,
        "HTTP 404 https://github.com/smhasan94/rollcall/releases/tag/v0.1.0",
    );
    let ok_row = (
        "SECURITY.md:3",
        "PASS",
        "https://semver.org/",
        "HTTP 200 https://semver.org/",
    );
    // Tolerated: this tag's release page answers 404, everything else passes.
    assert_eq!(
        tolerate_pending_release_link("v0.1.0", "1", &[ok_row, this_404]),
        0
    );
    // A clean run passes.
    assert_eq!(tolerate_pending_release_link("v0.1.0", "0", &[ok_row]), 0);
    // Rejected: the same URL failing any other way.
    let other_failures = [
        (
            "CHANGELOG.md:69",
            "FAIL",
            URL,
            "HTTP 500 https://github.com/smhasan94/rollcall/releases/tag/v0.1.0",
        ),
        (
            "CHANGELOG.md:69",
            "FAIL",
            URL,
            "HTTP 0 (curl exit 6: Could not resolve host: github.com)",
        ),
        (
            "CHANGELOG.md:69",
            "FAIL",
            URL,
            "HTTP 404 https://github.com/smhasan94/rollcall/releases (redirected up to a parent page)",
        ),
        // Another tag's release page.
        (
            "CHANGELOG.md:70",
            "FAIL",
            "https://github.com/smhasan94/rollcall/releases/tag/v9.9.9",
            "HTTP 404 https://github.com/smhasan94/rollcall/releases/tag/v9.9.9",
        ),
        // Another URL.
        (
            "docs/ci.md:10",
            "FAIL",
            "https://github.com/smhasan94/rollcall-example-zephyr",
            "HTTP 404 https://github.com/smhasan94/rollcall-example-zephyr",
        ),
        // A link inside the repository.
        (
            "docs/versioning.md:5",
            "FAIL",
            "release.md#nope",
            "no heading for #nope in docs/release.md",
        ),
    ];
    for row in other_failures {
        assert_eq!(
            tolerate_pending_release_link("v0.1.0", "1", &[row]),
            1,
            "tolerated {row:?}"
        );
        // Not tolerated alongside this tag's 404 either.
        assert_eq!(
            tolerate_pending_release_link("v0.1.0", "1", &[this_404, row]),
            1,
            "tolerated {row:?} next to the pending release page"
        );
    }
    // The 404 of v0.1.0's page is not tolerated on another tag's run.
    assert_eq!(tolerate_pending_release_link("v0.2.0", "1", &[this_404]), 1);
    // Exit 1 without any failing row is not a link failure it understands.
    assert_eq!(tolerate_pending_release_link("v0.1.0", "1", &[ok_row]), 1);
    // A setup error of check-doc-links.sh keeps its code; bad arguments are a usage error.
    assert_eq!(tolerate_pending_release_link("v0.1.0", "2", &[]), 2);
    assert_eq!(tolerate_pending_release_link("main", "1", &[this_404]), 2);
    assert_eq!(tolerate_pending_release_link("v0.1.0", "x", &[this_404]), 2);
}

/// SHA-124 (ci.yml docs-links): the tag-only online check of the release documents runs on
/// release tags such as v0.1.0 but is skipped for pre-release tags (any `-`, e.g.
/// v0.1.0-rc.1), whose run would hit the final release's not-yet-existing pages.
#[test]
fn tag_run_release_link_step_skips_pre_release_tags() {
    let ci = repo_file(".github/workflows/ci.yml");
    let step = ci
        .split("\n      - name: ")
        .find(|s| s.starts_with("Check the release documents' links (release tags)\n"))
        .expect("ci.yml has the tag-only release-links step");
    let condition = step
        .lines()
        .find_map(|l| l.trim().strip_prefix("if: "))
        .expect("the tag-only release-links step has an if:");
    assert_eq!(
        condition,
        "startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-')"
    );
}

#[cfg(unix)]
/// Runs `scripts/check-doc-links.sh` (online) on a document linking each URL of `table`, with a
/// fake `curl` first on PATH answering from `table` (URL, final status, curl exit code, final
/// URL); its exit code and stdout.
fn check_doc_links_with_fake_curl(table: &[(&str, u16, i32, &str)]) -> (i32, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("temporary directory");
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).expect("bin directory");
    let fake = bin.join("curl");
    std::fs::write(
        &fake,
        r#"#!/usr/bin/env bash
# Fake curl: the URL is the last argument; FAKE_CURL_TABLE has `url status rc effective` rows.
url="${!#}"
while read -r u status rc effective; do
    if [[ "$u" == "$url" ]]; then
        printf '%s %s' "$status" "$effective"
        [[ "$rc" -eq 0 ]] || echo "curl: ($rc) fake failure" >&2
        exit "$rc"
    fi
done <"$FAKE_CURL_TABLE"
echo "fake curl: no row for $url" >&2
exit 99
"#,
    )
    .expect("write the fake curl");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let rows: String = table
        .iter()
        .map(|(url, status, rc, effective)| format!("{url} {status} {rc} {effective}\n"))
        .collect();
    let table_path = dir.path().join("table.txt");
    std::fs::write(&table_path, rows).expect("write the table");
    let doc: String = table
        .iter()
        .map(|(url, ..)| format!("- [link]({url})\n"))
        .collect();
    let doc_path = dir.path().join("doc.md");
    std::fs::write(&doc_path, doc).expect("write the document");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = std::process::Command::new("bash")
        .arg(repo_root().join("scripts/check-doc-links.sh"))
        .arg(&doc_path)
        .env("PATH", path)
        .env("FAKE_CURL_TABLE", &table_path)
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("bash runs");
    (
        out.status.code().expect("exited with a code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// SHA-125 (CI docs-links): a host listed in scripts/link-check-blocked-hosts.txt (it rejects
/// GitHub's CI runners) gets SKIP for an HTTP 403 and only for that; anything else from it
/// still fails, and a 403 from any other host fails.
#[cfg(unix)]
#[test]
fn check_doc_links_skips_only_a_403_from_a_host_that_blocks_ci() {
    let blocked = repo_file("scripts/link-check-blocked-hosts.txt");
    assert!(
        blocked
            .lines()
            .any(|l| l.split('#').next().unwrap_or_default().trim() == "www.cisa.gov"),
        "www.cisa.gov is not listed"
    );
    const CISA: &str = "https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom";
    const OK: &str = "https://example.org/page";

    // A 403 from the listed host is skipped; the run passes and counts it as skipped.
    let (code, out) = check_doc_links_with_fake_curl(&[(CISA, 403, 0, CISA), (OK, 200, 0, OK)]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.lines().any(|l| l.contains("SKIP") && l.contains(CISA) && l.contains(
            "HTTP 403 from a host that blocks CI runners (listed in scripts/link-check-blocked-hosts.txt)"
        )),
        "{out}"
    );
    assert!(
        out.contains("check-doc-links: PASS (1 checked, 1 skipped)"),
        "{out}"
    );

    // Every other result from the listed host fails.
    for (status, rc, effective, why) in [
        (404, 0, CISA, "a 404"),
        (503, 0, CISA, "a 503"),
        (0, 6, "", "a curl error (DNS)"),
        (
            403,
            0,
            "https://www.cisa.gov/resources-tools",
            "a 403 after a redirect up to a parent page",
        ),
        (
            403,
            0,
            "https://blocked.example.net/elsewhere",
            "a 403 after a redirect to an unlisted host",
        ),
    ] {
        let (code, out) =
            check_doc_links_with_fake_curl(&[(CISA, status, rc, effective), (OK, 200, 0, OK)]);
        assert_eq!(code, 1, "{why} on the listed host passed:\n{out}");
        assert!(
            out.lines().any(|l| l.contains("FAIL") && l.contains(CISA)),
            "{why}: {out}"
        );
        assert!(out.contains("check-doc-links: FAIL"), "{why}: {out}");
    }

    // A 403 from a host that is not listed fails.
    const OTHER: &str = "https://www.example.com/forbidden";
    let (code, out) = check_doc_links_with_fake_curl(&[(OTHER, 403, 0, OTHER), (OK, 200, 0, OK)]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.lines().any(|l| l.contains("FAIL") && l.contains(OTHER)),
        "{out}"
    );
}
