# Handing rollcall's findings to cra-clock (CSAF 2.0)

rollcall hands its vulnerability findings to cra-clock as a CSAF 2.0 document with the VEX
profile (`csaf_vex`), written by `rollcall csaf`. This page is the handoff contract: what
rollcall writes, what a consumer can rely on, and how to check that an import shows the same
findings and statuses.

> **Status.** cra-clock is not built yet, so no document has been imported into it. Until it
> is, secvisogram's validator (`@secvisogram/csaf-validator-lib`, pinned in
> `scripts/csaf-validator/`) stands in as the consumer: the old-mbedTLS document loads in it,
> and its findings and statuses match `rollcall scan` row for row (see
> [Import test](#import-test-old-mbedtls)). Run the cra-clock steps there once cra-clock exists.

## The pipeline

```sh
# 1. The SBOM (here the hand-written old-mbedTLS model; for a real build, --zephyr …).
rollcall generate --model crates/rollcall-core/tests/data/old-mbedtls.model.json \
  --timestamp 2026-01-02T03:04:05Z -o old-mbedtls.cdx.json

# 2. Findings (live: rollcall scan --json, or grype/osv-scanner JSON; here the captures).
# 3. VEX statements (rollcall vex, or any OpenVEX / CycloneDX VEX document).

# 4. The CSAF document.
rollcall csaf old-mbedtls.cdx.json \
  --scan crates/rollcall-core/tests/data/findings/old-mbedtls.grype.json \
  --scan crates/rollcall-core/tests/data/findings/old-mbedtls.osv.json \
  --vex crates/rollcall-core/tests/golden/vex/old-mbedtls.openvex.json \
  --publisher "Example Devices Ltd" --publisher-namespace https://devices.example \
  --timestamp 2026-01-02T03:04:05Z -o old-mbedtls.csaf.json

# 5. The reference rows to compare the consumer's view with.
scripts/csaf-summary.sh old-mbedtls.csaf.json
```

Step 4 writes exactly `crates/rollcall-core/tests/golden/csaf/old-mbedtls.csaf.json`.
`scripts/csaf-check.sh` does steps 1 to 4 for every fixture with captured findings, runs the
official validator over the results, and checks one row of step 5.

## What rollcall guarantees

- **Valid CSAF 2.0.** Two layers:
  - In CI (job `csaf`, `scripts/csaf-check.sh`), the documents of every fixture with captured
    findings pass the official validator library `@secvisogram/csaf-validator-lib` 2.1.6: the
    strict CSAF 2.0 JSON schema (with the CVSS schemas it references) and the full mandatory
    test suite of CSAF 2.0 §6.1.
  - At runtime, `rollcall csaf` refuses to write a document that fails the vendored
    (non-strict) OASIS CSAF 2.0 schema or one of the 12 mandatory tests it implements itself:
    6.1.1, 6.1.2, 6.1.6, 6.1.23, 6.1.33 and the VEX-profile tests 6.1.27.4, .5, .7, .8, .9,
    .10 and .11. The rest of §6.1 is checked only in CI, on the fixtures.
- **Statements are about the firmware.** Every status, flag, threat and remediation names a
  relationship product "component as part of the product" (CSAF 2.0 §3.2.3.4), with id
  `<component bom-ref>@<product bom-ref>`, never the bare component: "CVE-X does not affect
  mbedtls 2.28.0 *in this firmware*", not "mbedtls 2.28.0 is not affected". A finding on the
  product itself names the product.
- **Stable identifiers.** Each component's product id is its SBOM `bom-ref`, and its
  `product_identification_helper.purl` and `.cpe` are the SBOM's `purl` and `cpe`, byte for
  byte (not re-canonicalised). A consumer can join SBOM and CSAF on any of them. VEX
  statements that name a component by `bom-ref` or BOM-Link use the same `bom-ref`; OpenVEX
  purls are matched canonically, so an OpenVEX document may spell a purl differently from
  the SBOM (CSAF always carries the SBOM's spelling).
- **Only what the findings are about.** The product tree holds the product and the
  components the vulnerabilities name (each with its relationship product), so every product
  id it defines is used.
- **One entry per vulnerability.** `vulnerabilities[]` has one entry per finding id: `cve` for
  a CVE, else `ids[]` (`system_name` is the id's prefix, e.g. `GHSA`, `RUSTSEC`), with the
  other ids and aliases in `ids[]` too.
- **Statuses equal `rollcall scan`'s triage** on the same inputs (see the table below).
- **Deterministic.** The same input contents, input file names (generated texts cite a VEX
  document by its name), options and rollcall version give the same bytes. The default
  `tracking.id` is derived from the content (`rollcall-csaf-<16 hex>`), and every date is
  `--timestamp`.
- **One revision.** `tracking.version` is always `1`, with a single revision-history entry.
  Because the default `tracking.id` changes with the findings, a series of updates to one
  advisory must pass the same `--id` every time; numbered revisions are a follow-up.

## Mapping

| `rollcall scan` triage | VEX claim | CSAF `product_status` | Also written |
|------------------------|-----------|-----------------------|--------------|
| affected | `affected` (CycloneDX `exploitable`) | `known_affected` | a remediation (below) |
| suppressed | `not_affected` | `known_not_affected` | a flag from the justification (below), and an `impact` threat with the impact statement when there is one (or a generated one when there is no flag) |
| suppressed | `false_positive` (CycloneDX) | `known_not_affected` | an `impact` threat saying it is a false positive |
| suppressed | `fixed` (CycloneDX `resolved`, `resolved_with_pedigree`) | `fixed` | |
| unresolved | none, `under_investigation` (`in_triage`), or conflicting claims | `under_investigation` | |

| Claim | CSAF remediation category |
|-------|---------------------------|
| CycloneDX `analysis.response` `update` or `rollback` | `vendor_fix` |
| CycloneDX `analysis.response` `workaround_available` | `workaround` |
| CycloneDX `analysis.response` `will_not_fix` or `can_not_fix` | `no_fix_planned` |
| no response (whether or not the scanners know a version fixed upstream) | `none_available`: no fixed firmware exists yet. The generated text names the upstream fix when there is one ("upgrade to a version fixed upstream: X"); `mitigation` is not used, as it does not resolve the vulnerability (CSAF 2.0 §3.2.3.12.1) |

The remediation's details are the claim's action statement (OpenVEX `action_statement`,
CycloneDX `analysis.detail`, `rollcall-vex/1` `detail`), else a generated text. The impact
statement is OpenVEX `impact_statement` (for `not_affected`), CycloneDX `analysis.detail` or
`rollcall-vex/1` `detail`; OpenVEX `status_notes` is the fallback for either.

| VEX justification | CSAF flag |
|-------------------|-----------|
| `component_not_present` | `component_not_present` |
| `vulnerable_code_not_present`, CycloneDX `code_not_present` | `vulnerable_code_not_present` |
| `vulnerable_code_not_in_execute_path`, CycloneDX `code_not_reachable` | `vulnerable_code_not_in_execute_path` |
| `vulnerable_code_cannot_be_controlled_by_adversary`, CycloneDX `requires_configuration`, `requires_dependency`, `requires_environment` | `vulnerable_code_cannot_be_controlled_by_adversary` |
| `inline_mitigations_already_exist`, CycloneDX `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`, `protected_by_mitigating_control` | `inline_mitigations_already_exist` |

| SBOM | CSAF `product_tree` |
|------|---------------------|
| `metadata.component` (the product) | `branches`: `vendor` (its supplier, when given) → `product_name` → `product_version` (when versioned) → the product, `product_id` = its `bom-ref` |
| each component a vulnerability names (an image or a component, at any depth) | `full_product_names[]`, `product_id` = its `bom-ref`, name `<name> <version>`, `product_identification_helper` = its `purl` and `cpe` |
| the same component, as part of the product | `relationships[]`: `default_component_of` (`optional_component_of` for scope `optional`) the product, `product_id` `<component bom-ref>@<product bom-ref>`. Flat, whatever the SBOM's nesting |

Left out, with a warning each (printed by `rollcall csaf` also when nothing is left to
export): findings about packages the SBOM does not list, and about components of scope
`excluded` (not part of the product). Also left out: components no finding names, scanner
severities and CVSS scores (scanners' severity words are not CVSS), licences, hashes and
evidence. No TLP label is written unless `--tlp` is given.

The official validator's **optional** tests (§6.2) that still warn on rollcall's documents:
6.2.2 (no remediation for products under investigation), 6.2.3 (no CVSS score), 6.2.10 (no
TLP label unless `--tlp`), 6.2.11 (no canonical URL: rollcall does not know where the
document will be published) and 6.2.16 (the relationship products carry no identification
helper: the purl and CPE are on the component they name). None of them is mandatory.

## What cra-clock needs to do (the import contract)

To show "the same findings and statuses", an importer must:

1. Accept a CSAF 2.0 JSON document with `document.category` `csaf_vex`.
2. Key each finding by `vulnerabilities[].cve`, else by `vulnerabilities[].ids[].text`.
3. Resolve each product id in a status to the component it is about: a relationship
   product's `product_reference` (the component; `relates_to_product_reference` is the
   firmware), or the product itself. Match that component to the SBOM's by its
   `product_identification_helper.purl` (and/or `.cpe`), compared as strings.
4. Take each product's status from the `product_status` list it is in: `known_affected`,
   `known_not_affected`, `fixed` or `under_investigation`.
5. Optionally show the flags (justifications), `impact` threats and remediations attached to
   each product.
6. Treat documents with the same `tracking.id` as versions of one advisory (rollcall writes
   `tracking.version` `1` every time; pass a stable `--id` for a series).

## Import test (old-mbedTLS)

1. Produce the document: `scripts/csaf-check.sh --install` (writes
   `.cache/csaf/old-mbedtls.csaf.json`, byte-identical to the golden), or step 4 above.
2. Print the reference rows: `scripts/csaf-summary.sh .cache/csaf/old-mbedtls.csaf.json`.
   Each row is `vulnerability  status  product_id  purl  cpe` (the product id is the
   relationship product; the purl and CPE are its component's); the old-mbedTLS document has
   23 rows (1 `known_affected`, 3 `known_not_affected`, 19 `under_investigation`), all on
   `pkg:github/mbed-tls/mbedtls@v2.28.0`.
3. Load the document in the consumer:
   - **Stand-in (run, SHA-132):** `node scripts/csaf-validator/validate.mjs
     .cache/csaf/old-mbedtls.csaf.json` passes (the strict schema and every mandatory test).
     The validator checks the document but shows no findings, so the comparison in step 4
     uses the rows of step 2.
   - **cra-clock (once it exists):** import the same file into a local instance.
4. Compare the consumer's findings with `rollcall scan` on the same SBOM, captures and VEX:
   the same vulnerabilities, each with the same status on the same product (purl and CPE),
   with scan triage mapped as in [Mapping](#mapping). For the stand-in, all 23 rows match.
   The full commands and log are on SHA-132.
5. For cra-clock, attach to its ticket: the import log, a screenshot of cra-clock's findings
   view, and the output of step 2.

For the real Zephyr build, do the same with `.cache/csaf/zephyr-old-mbedtls.csaf.json` (13
rows: the Mbed TLS 3.6.4 CVEs, all `under_investigation`, on the build's Mbed TLS component).
