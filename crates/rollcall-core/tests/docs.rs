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
