//! VEX rules and their evaluation: which scanner findings affect the product, and why.
//!
//! [`evaluate`] takes the product (from the SBOM or the model), [`BuildEvidence`] (e.g. the
//! Kconfig `.config`), scanner [`Finding`]s (grype or osv-scanner JSON, see
//! [`parse_findings`]) and a [`RuleSet`] (see [`parse_rules`]). It returns a [`Report`]: a VEX
//! [`Statement`] for every finding a rule decides, and an [`Unresolved`] entry, with a rule
//! template to fill in, for every other finding. [`Report::to_json`] writes rollcall's own
//! `rollcall-vex/1` JSON; [`to_openvex`], [`to_cyclonedx_vex`] and [`embed`] render the same
//! statements as standard VEX (see [Output formats](#output-formats)), and [`sign()`] signs
//! the result (see [Signing](#signing)).
//!
//! # Rule format
//!
//! ```yaml
//! version: 1
//! rules:
//!   - id: mbedtls-dtls-compiled-out        # required, unique, [A-Za-z0-9._-]+
//!     priority: 10                          # optional, default 0; tie-break only
//!     match:                                # at least one of purl | name | subsystem
//!       purl: "pkg:github/mbed-tls/mbedtls@*"   # a purl, or a glob where * matches anything
//!       name: mbedtls                       # exact component name
//!       subsystem: bluetooth-host           # a Zephyr subsystem subcomponent (see below)
//!       cves: [CVE-2022-35409]              # optional; the finding's id or any alias
//!       versions: ">=2.28.0, <2.28.5"       # optional semver range (Cargo syntax)
//!     when:                                 # optional; every condition must hold
//!       - kconfig_off: CONFIG_MBEDTLS_SSL_PROTO_DTLS
//!       - kconfig_equals: {CONFIG_MBEDTLS_CFG_FILE: config-mbedtls.h}
//!       - cargo_feature_off: dtls
//!       - symbol_not_linked: mbedtls_ssl_parse_client_hello
//!       - version_in: "<2.28.1"
//!     status: not_affected                  # not_affected | affected | fixed | under_investigation
//!     justification: code_not_present       # required for not_affected, else not allowed
//!     detail: "DTLS is compiled out."
//! ```
//!
//! Each condition is a one-key mapping. `kconfig_equals` compares the symbol's value exactly
//! as the `.config` writes it (`y`, `n` for `is not set`, `m`, a number, a hex number as text
//! such as `0x10`, or a string's contents without its quotes); the rule's value is taken as
//! the text written, and a duplicate key is an error. `justification` accepts the CycloneDX 1.6 values and
//! the OpenVEX ones and keeps the word written; it is mapped to the other vocabulary only when
//! rendered (see [`Justification`]). Unknown keys, statuses, justifications and conditions are
//! errors located at their line ([`RuleError`]). `match.name` and `match.subsystem` are
//! compared exactly and must not have leading or trailing whitespace. A `match.purl` glob is
//! compared case-sensitively with the canonical purl, so write it in canonical form (see
//! [`PurlPattern`]).
//!
//! `match.subsystem` must name an entry of the built-in subsystem table
//! ([`crate::subsystems::builtin`]); any other name (e.g. a misspelt `bluetooth_host`) is a
//! [`RuleError`] at the rule's line, never a rule that silently matches nothing.
//! `match.subsystem` matches a nested subcomponent by name: the subsystems Zephyr ingestion
//! splits out of the `zephyr` component (`bluetooth-host`, `ip-stack`, …; see
//! `docs/subsystems.md`). A rule naming a subsystem the SBOM does not contain matches
//! nothing. Findings are joined to components by purl, cpe or name and version, so a
//! subsystem rule applies only to findings joined to that subcomponent: by its purl (Zephyr's
//! with a subpath, e.g. `pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/host`),
//! its cpe (the subsystem table's, if any) or its name and version. **Real scanner findings
//! for Zephyr do not join subsystems today:** grype and osv-scanner report Zephyr CVEs against
//! the CPE `cpe:2.3:o:zephyrproject:zephyr:…`, which only the `zephyr` component carries, so a
//! `match.subsystem` rule never applies to them; it applies to findings that target a
//! subsystem's purl.
//!
//! Evidence for `cargo_feature_off` and `symbol_not_linked` ([`BuildEvidence`]'s feature set
//! and per-image linked-symbol sets) can be given through the library but not yet through
//! `rollcall vex`,
//! so from the CLI those conditions are always unknown and their rules leave findings
//! unresolved (needs evidence). [`linked_functions`](crate::linker_map::linked_functions)
//! reads a linked-symbol set from a GNU ld map.
//!
//! Because a `kconfig_off` symbol missing from the `.config` is unknown, a misspelt symbol
//! never yields a statement; [`lint_rules`] reports such symbols (see the [`lint`] module).
//! rollcall ships a starter rule pack, `rollcall_identifiers::VEX_RULES_YAML` (`rollcall vex
//! --starter-rules`); `docs/vex-rules.md` describes it with worked examples.
//!
//! Versions (`match.versions`, `version_in`) compare the component's *effective version*
//! ([`effective_version`]): its `version` if that is a release version (`v` prefix and a short
//! `major.minor` allowed); unknown if it has a pre-release, build or git-describe suffix
//! (`v3.7.0-123-gabc`, `-rc1`); otherwise (a git SHA, including an all-digit one of 7 or more
//! digits, or no version) the release version in its purl, if any. An unknown version makes
//! `version_in` unknown, and makes a rule with `match.versions` lack evidence rather than
//! silently not match.
//!
//! # Semantics
//!
//! 1. **Join.** A finding is about every component whose purl equals the finding's; failing
//!    that, whose cpe is one of the finding's; failing that, whose name (ignoring ASCII case)
//!    and version are equal. A finding for no component is unresolved
//!    ([`Reason::ComponentNotInSbom`]).
//! 2. **Merge.** For each component, findings whose ids and aliases connect (the same CVE
//!    reported by grype and osv-scanner, or a RUSTSEC and a GHSA advisory aliasing one CVE)
//!    become one entry. Its id is the lowest `CVE-` id in the set, else the lowest id; the
//!    others are its aliases.
//! 3. **Match.** A rule applies when every given `match` field matches and no `when`
//!    condition is false. A condition whose evidence is missing is *unknown*, never true: a
//!    `.config` without the symbol, or no `.config` for the component's image, does not prove
//!    anything is off. Kconfig and linked symbols are per image: a component is judged only
//!    by the evidence of its own image (MCUboot's mbedtls by MCUboot's `.config` and map, not
//!    the application's).
//! 4. **Precedence.** Among applicable rules, the most specific win ([`Specificity`]: naming
//!    CVEs beats not; then a version range beats none; then exact purl beats purl glob beats
//!    name or subsystem); among equally specific rules the highest `priority` wins.
//! 5. **Outcome.** If any winning rule has an unknown condition, the finding is unresolved
//!    ([`Reason::NeedsEvidence`]). If the winners agree on status and justification (words
//!    that map identically in both vocabularies agree), one statement cites them all. If they disagree, a [`Warning`](crate::Warning) names every
//!    one of them and the finding is unresolved ([`Reason::Conflict`]). With no applicable
//!    rule it is unresolved ([`Reason::NoRule`]).
//!
//! # Output formats
//!
//! The renderers never re-evaluate: each [`Statement`] of the report becomes one OpenVEX
//! statement and one `affects` entry of a CycloneDX vulnerability. Unresolved findings are
//! not rendered (they are not claims). Status and justification words are mapped by
//! [`Status::openvex`], [`Status::cyclonedx_state`], [`Justification::openvex`] and
//! [`Justification::cyclonedx`].
//!
//! - **OpenVEX** ([`to_openvex`], v0.2.0): each statement's product `@id` is the component's
//!   purl exactly as the SBOM spells it (what grype's `--vex` matches against); a component
//!   without a purl gets its BOM-Link (or `bom-ref`) and a warning. The rule's `detail` is
//!   the `impact_statement` of a `not_affected` statement, the `action_statement` of an
//!   `affected` one (which OpenVEX requires; [`DEFAULT_ACTION`] when the rule has no
//!   detail), and the `status_notes` otherwise. `author` is `--author`, else the SBOM
//!   product's supplier, else `rollcall` with a warning (the author should be the party
//!   responsible for the statements).
//! - **CycloneDX VEX** ([`to_cyclonedx_vex`], 1.6): a standalone BOM with no components
//!   whose `metadata.component` summarises the SBOM's product and whose
//!   `vulnerabilities[].affects[].ref` are BOM-Links (`urn:cdx:<serial>/<version>#<bom-ref>`)
//!   into the SBOM, so the SBOM needs a lowercase `urn:uuid:` `serialNumber` and a
//!   `version` of at least 1 (an SBOM with a malformed one is rejected for every format). Statements with the same
//!   id, status, justification and detail are one vulnerability affecting several
//!   components. `source` is NVD for `CVE-` ids, else OSV; aliases are `references`. Each
//!   vulnerability carries `rollcall:rule` and `rollcall:evidence` properties and, when it
//!   has a justification, [`OPENVEX_JUSTIFICATION_PROPERTY`] so the many-to-one mapping
//!   loses nothing. A grouped vulnerability's `rollcall:rule` and `rollcall:evidence`
//!   properties are the union, sorted and without duplicates, of its statements' rules and
//!   evidence.
//! - **Embedded** ([`embed`]): the SBOM with a `vulnerabilities` array like the CycloneDX
//!   VEX one but citing bare `bom-ref`s, and its `version` incremented by one (CycloneDX 1.6:
//!   a modified BOM's version SHOULD be incremented; `serialNumber` is kept). Only those two
//!   token spans change: the top-level `version` value is rewritten in place and the array
//!   is appended before the closing `}` (or replaces an existing empty `vulnerabilities:
//!   []`); every other byte is kept. An SBOM without `version` is implicitly version 1 and
//!   gets `"version": 2` appended next to the array. A non-empty `vulnerabilities` is
//!   refused. The SBOM is never VEX-bearing unless asked for: `rollcall generate` writes no
//!   `vulnerabilities`, and `rollcall vex` without `--embed` never touches the SBOM.
//!
//! # Signing
//!
//! [`sign()`] makes a detached Ed25519 signature (`rollcall-signature/1` JSON, see the
//! [`sign`](mod@sign) module) over a rendered document's exact bytes; [`verify`] reports a
//! modified document, a different key, or an invalid signature as distinct
//! [`VerifyError`]s. Sigstore keyless signing is done by the CLI through `cosign`.
//!
//! # Determinism
//!
//! Rendered documents depend only on the report, the SBOM and [`VexOptions`]: the document
//! id is `--id` or [`document_id`] (derived from the document kind, the statements and the
//! SBOM's serial number and version, not the timestamp, so an OpenVEX and a CycloneDX VEX
//! document never share a derived id), and the timestamp is `--timestamp` or the current
//! time.
//!
//! The report depends only on the contents of the inputs, not on their order: findings,
//! statements, unresolved entries and warnings are sorted. `bom-ref`s are the input
//! document's own ([`evaluate_document`]) or rollcall's content-derived ones ([`evaluate`]),
//! and evidence cites a `.config` by the stable label `<image>/zephyr/.config`
//! ([`kconfig_label`]), never by the path it was read from.

mod evaluate;
mod evidence;
mod findings;
pub mod lint;
mod pattern;
mod render;
mod rules;
mod sbom;
pub mod sign;
mod version;

pub use evaluate::{
    ComponentRef, Package, REPORT_SCHEMA, Reason, Report, Statement, Unresolved, evaluate,
    evaluate_document,
};
pub use evidence::{BuildEvidence, Verdict, kconfig_label};
pub use findings::{
    Finding, Findings, FindingsError, Scanner, parse_findings, parse_grype, parse_osv,
};
pub use lint::{
    KconfigSymbols, LintFinding, LintKind, SymbolReference, lint_duplicate_ids, lint_rules,
};
pub use pattern::{PurlPattern, Specificity};
pub use render::{
    DEFAULT_ACTION, DocumentKind, OPENVEX_CONTEXT, OPENVEX_JUSTIFICATION_PROPERTY, Rendered,
    VexError, VexOptions, document_id, embed, to_cyclonedx_vex, to_openvex,
};
pub use rules::{
    CONDITIONS, Condition, Justification, Match, RULES_VERSION, Rule, RuleError, RuleSet, Status,
    parse_rules, parse_rules_bytes, template,
};
pub use sbom::SbomIndex;
pub use sign::{
    DetachedSignature, PemForm, SigningKey, VerifyError, VerifyingKey, Zeroizing, sign, verify,
};
pub use version::{VersionKind, VersionRange, classify_version, effective_version, parse_version};
