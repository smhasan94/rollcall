//! VEX rules and their evaluation: which scanner findings affect the product, and why.
//!
//! [`evaluate`] takes the product (from the SBOM or the model), [`BuildEvidence`] (e.g. the
//! Kconfig `.config`), scanner [`Finding`]s (grype or osv-scanner JSON, see
//! [`parse_findings`]) and a [`RuleSet`] (see [`parse_rules`]). It returns a [`Report`]: a VEX
//! [`Statement`] for every finding a rule decides, and an [`Unresolved`] entry, with a rule
//! template to fill in, for every other finding. Rendering statements as CycloneDX VEX or
//! OpenVEX is separate (SHA-113); [`Report::to_json`] writes rollcall's own
//! `rollcall-vex/1` JSON.
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
//!       subsystem: net                      # reserved (see below)
//!       cves: [CVE-2022-35409]              # optional; the finding's id or any alias
//!       versions: ">=2.28.0, <2.28.5"       # optional semver range (Cargo syntax)
//!     when:                                 # optional; every condition must hold
//!       - kconfig_off: CONFIG_MBEDTLS_SSL_PROTO_DTLS
//!       - cargo_feature_off: dtls
//!       - symbol_not_linked: mbedtls_ssl_parse_client_hello
//!       - version_in: "<2.28.1"
//!     status: not_affected                  # not_affected | affected | fixed | under_investigation
//!     justification: code_not_present       # required for not_affected, else not allowed
//!     detail: "DTLS is compiled out."
//! ```
//!
//! Each condition is a one-key mapping. `justification` accepts the CycloneDX 1.6 values and
//! the OpenVEX ones and keeps the word written; it is mapped to the other vocabulary only when
//! rendered (see [`Justification`]). Unknown keys, statuses, justifications and conditions are
//! errors located at their line ([`RuleError`]). `match.name` and `match.subsystem` are
//! compared exactly and must not have leading or trailing whitespace. A `match.purl` glob is
//! compared case-sensitively with the canonical purl, so write it in canonical form (see
//! [`PurlPattern`]).
//!
//! `match.subsystem` is **reserved** until the Zephyr kernel package is split into subsystems
//! (SHA-108): it matches a nested subcomponent by name, but no ingester produces those yet, so
//! a rule using it matches nothing today and the report carries a warning naming the rule.
//!
//! Evidence for `cargo_feature_off` and `symbol_not_linked` ([`BuildEvidence`]'s feature and
//! linked-symbol sets) can be given through the library but not yet through `rollcall vex`,
//! so from the CLI those conditions are always unknown and their rules leave findings
//! unresolved (needs evidence).
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
//!    anything is off. Kconfig is per image: a component is judged only by the `.config` of
//!    its own image (MCUboot's mbedtls by MCUboot's `.config`, not the application's).
//! 4. **Precedence.** Among applicable rules, the most specific win ([`Specificity`]: naming
//!    CVEs beats not; then a version range beats none; then exact purl beats purl glob beats
//!    name or subsystem); among equally specific rules the highest `priority` wins.
//! 5. **Outcome.** If any winning rule has an unknown condition, the finding is unresolved
//!    ([`Reason::NeedsEvidence`]). If the winners agree on status and justification (words
//!    that map identically in both vocabularies agree), one statement cites them all. If they disagree, a [`Warning`](crate::Warning) names every
//!    one of them and the finding is unresolved ([`Reason::Conflict`]). With no applicable
//!    rule it is unresolved ([`Reason::NoRule`]).
//!
//! # Determinism
//!
//! The report depends only on the contents of the inputs, not on their order: findings,
//! statements, unresolved entries and warnings are sorted. `bom-ref`s are the input
//! document's own ([`evaluate_document`]) or rollcall's content-derived ones ([`evaluate`]),
//! and evidence cites a `.config` by the stable label `<image>/zephyr/.config`
//! ([`kconfig_label`]), never by the path it was read from.

mod evaluate;
mod evidence;
mod findings;
mod pattern;
mod rules;
mod version;

pub use evaluate::{
    ComponentRef, Package, REPORT_SCHEMA, Reason, Report, Statement, Unresolved, evaluate,
    evaluate_document,
};
pub use evidence::{BuildEvidence, Verdict, kconfig_label};
pub use findings::{
    Finding, Findings, FindingsError, Scanner, parse_findings, parse_grype, parse_osv,
};
pub use pattern::{PurlPattern, Specificity};
pub use rules::{
    CONDITIONS, Condition, Justification, Match, RULES_VERSION, Rule, RuleError, RuleSet, Status,
    parse_rules, parse_rules_bytes, template,
};
pub use version::{VersionKind, VersionRange, classify_version, effective_version, parse_version};
