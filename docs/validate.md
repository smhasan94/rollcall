# `rollcall validate`: schema and regulator profiles

`rollcall validate FILE` checks a CycloneDX 1.6 JSON document. It takes at least one of:

- `--schema`: validate against the vendored CycloneDX 1.6 JSON schema.
- `--profile NAME|PATH`: run the checks of a regulator profile. `NAME` is `cisa-2026`, `cra`,
  or `all` (both). A value that contains a path separator or ends in `.yaml`/`.yml` is the
  path of a profile file in the format below.

Both flags together run both. `--json` prints one JSON object on stdout instead of text. The
profile checks read any CycloneDX JSON document, not only ones rollcall wrote. A document of
the wrong shape gets findings, not a crash.

```sh
rollcall validate --schema --profile all product.cdx.json
rollcall validate --profile cra --json product.cdx.json > validate.json
```

## Output

**Text.**

- On a pass, stdout gets `<file>: valid CycloneDX 1.6` (for `--schema`) and/or
  `<file>: passes cisa-2026, cra (<n> checks, <w> warnings)`.
- On a failure, stderr gets `<file>: <e> error(s), <w> warning(s) against <profiles>`
  followed by one line per finding. Schema violations are reported as before.
- Warnings on a passing document are still listed on stderr.

Each finding line has this form. This is the first line for the stripped fixture
(`rollcall validate --profile all tests/golden/validate/clean.stripped.cdx.json`), byte for
byte; the test `stripped_document_fails_naming_both_components` checks that it matches:

```
  error    component.supplier  component:929a445c0e3c76a5f601071900b671b9  littlefs@2.9.0: no supplier (manufacturer.name and supplier.name missing). Fix: set manufacturer.name or supplier.name to the organisation that supplies this component. [cisa-2026: Data Fields, Component Data: Component Producer (p. 10); cra: section 5.2.2, Table 3: Component creator (lenient: name accepted, see profile header)]
```

The severity is padded to 7 columns, followed by two spaces.

The line gives:

- the severity;
- the check id;
- the component's `bom-ref`, or a JSON pointer when the component has no `bom-ref` or the
  finding is about the document;
- `name@version`;
- what is wrong;
- the fix;
- the clause each requiring profile cites.

**`--json`** prints exactly one object on stdout. On success, and when there are findings, stderr
is empty. Usage and input errors (exits 64, 65 and 66) and an internal error (exit 70)
print a `rollcall validate: …` message on stderr instead, and no JSON. If stdout cannot be
written, the exit code is 74.

```json
{
  "file": "product.cdx.json",
  "profile": {
    "checks_run": 12,
    "errors": 0,
    "findings": [],
    "profiles": ["cisa-2026", "cra"],
    "warnings": 0
  },
  "rollcall-validate": 1,
  "schema": { "checked": true, "violations": [] }
}
```

- `profile` is `null` without `--profile`.
- `schema.checked` is `false` without `--schema`.
- Each finding has these fields:
  - `profiles`, `check`, `severity` (`error` | `warning`);
  - `ref` (omitted when there is none), `path` (JSON pointer), `name`, `version`;
  - `message`, `fix`;
  - `citations`, a list of `{profile, document, url, clause}`.
- `rollcall-validate` is the version of this shape.

**Order.** Findings are sorted the same way on every run:

1. document-level findings first;
2. then by component, in document order (`metadata.component`, then `components[]` in
   pre-order);
3. then by check, in the catalogue order below;
4. then by JSON pointer and message.

When `all` names two profiles that need the same check with identical parameters, the check
runs once. Its findings list both profiles, at the stricter of the two severities. A check
whose parameters differ between the two profiles runs once per parameter set.

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Passed. Warnings alone still pass. |
| 1 | A schema violation, or an error-severity finding. |
| 64 | Usage error: neither `--schema` nor `--profile`, or an unknown profile name. |
| 65 | The document is not JSON, or the profile file is malformed. |
| 66 | The document or the profile file is missing or unreadable. |
| 70 | Internal error: the report cannot be serialised. |
| 74 | Output cannot be written. |

## Profiles

The built-in profiles live in `crates/rollcall-core/profiles/*.yaml` and are compiled into the
binary. To encode new regulator guidance:

1. Write a new YAML file there.
2. Add one line to the `BUILTIN` registry in `validate/profile.rs`.

A test fails if a file in that directory is not registered. A profile file can also be used
directly with `--profile path/to/profile.yaml`. New code is needed only when the guidance asks
for a check the catalogue below does not have.

```yaml
format: rollcall-profile/1
id: cra                      # [a-z0-9][a-z0-9.-]*, not "all"
title: EU Cyber Resilience Act (Regulation (EU) 2024/2847), Annex I Part II
sources:                     # the documents the checks cite
  - key: cra
    document: "Regulation (EU) 2024/2847 … (Cyber Resilience Act), OJ L, 2024/2847, 20.11.2024"
    url: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
checks:                      # each catalogue check at most once
  - id: graph.top-level-complete
    severity: error          # error | warning
    cite: { source: cra, clause: "Annex I, Part II, point (1): …" }
    params: {}               # only the check's own parameters, with the right types
```

The loader never panics. Each of the following is an error naming the problem:

- empty, truncated or non-YAML input, or a list where a map is expected;
- unknown keys, or the wrong `format`;
- a bad `id`, or an empty title or clause;
- an unknown or duplicated check;
- an unknown source key, or a duplicated source;
- an unknown parameter, or a parameter of the wrong type or value.

A parameter given explicitly with its default value is dropped at load time, so it groups
with the same check where the parameter is omitted and does not produce duplicate findings. A
`Profile` built in code rather than loaded from YAML may name a check that is not in the
catalogue; validation reports that as an error finding with the unknown check id, rather than
skipping it.

## Check catalogue

Component checks apply to `metadata.component` (the root) and to every `components[]` entry at
any depth. They take `include_root` (default `true`) to leave the root out. A string field
counts only if it is a non-empty string; any other type is treated as absent.

### `document.timestamp`

`metadata.timestamp` is present and is an RFC 3339 date-time.
Fix: set it to the time the SBOM was produced. `rollcall generate --timestamp` fixes it for
reproducible builds.

### `document.author`

The document names who produced it. The parameter `accept` lists which sources count
(default: all three):

- `authors`: a `metadata.authors[]` entry with a name or email;
- `tools`: a named entry in `metadata.tools.components[]`, `metadata.tools.services[]` or the
  legacy `metadata.tools[]`;
- `manufacturer`: `metadata.manufacturer.name`.

Fix: name the entity that produced the SBOM.

### `document.root`

`metadata.component` is present and has a `bom-ref`. This is the component the SBOM
describes, and the dependency graph starts there.
Fix: add `metadata.component` with a `bom-ref`.

### `component.name`

Every component has a `name`.

### `component.version`

Every component has a `version`.

### `component.supplier`

Every component names who supplies it. The parameter `accept` lists which fields count:

- `supplier`: `supplier.name`;
- `manufacturer`: `manufacturer.name`;
- `authors`: a component `authors[]` entry with a name or email;
- `publisher`: the component's `publisher`.

The default is `supplier`. `authors` and `publisher` are opt-in; neither built-in profile uses
them.

### `component.identifier`

Every component has a unique identifier. The parameter `fields` lists which ones count, from
`purl`, `cpe`, `swid` (`swid.tagId`), `omniborId` and `swhid`. The default is `purl` and `cpe`.
Fix: add one. For Zephyr modules, `rollcall generate --identifier-db` supplies purl and cpe.

### `component.hash`

Every component has a `hashes[]` entry whose `alg` is in the parameter `algorithms`. The list
is CycloneDX algorithm names; when it is empty, any algorithm counts.
Fix: add a digest of the component's deliverable file.

### `graph.refs-resolve`

Every `dependencies[].ref` and every `dependsOn` entry is the `bom-ref` of a component or of a
service (`services[]`, at any depth) in the document. No `bom-ref` is used twice across
components and services; a duplicate is reported at its second use.

### `graph.reachable`

Every component is reachable from the root through `dependencies` edges. When the parameter
`nesting_is_dependency` is `true` (the default, and both profiles set it), a nested
`components[]` entry also counts as an edge from its parent, since CycloneDX nesting expresses
inclusion. Each unreachable component (an orphan) is one finding.
Fix: add the component to the `dependsOn` of the component that includes it, or to the
root's. Edges through a `ref` that names nothing do not count. Edges may pass through
services, but services themselves need not be reachable, and no component check applies to
them.

### `graph.top-level-complete`

The root has a `dependencies[]` entry, and its `dependsOn` lists every top-level
`components[]` entry. A top-level component without a `bom-ref` cannot be listed, so it fails.

### `image.represented`

The document has at least one top-level component; if it has none, that is an error. Each
top-level component should be a firmware image:

- `type` `firmware`, or
- a property `rollcall:image-kind` with the value `bootloader`, `application` or `blob`.

A top-level component that is neither is a **warning**, whatever the profile's severity.
Images rollcall writes always satisfy this.

## Built-in profile `cisa-2026`

The source is **CISA, NSA, FBI et al., 2026 Minimum Elements for a Software Bill of
Materials (SBOM), version 2.1, July 29, 2026**. It is joint guidance by CISA with NSA, FBI and
the co-authoring agencies listed in the document. It replaces the 2021 NTIA minimum elements
and was finalised from the 22 August 2025 public-comment draft.
URL: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom
(the PDF is `2026_cisa_sbom_minimum_elements_508c.pdf`).

The profile file cites it as:

- `cisa`: CISA, NSA, FBI et al., 2026 Minimum Elements for a Software Bill of Materials (SBOM), version 2.1, July 29, 2026

Page numbers are those of that PDF. The "Data Fields" section has two parts: "SBOM Metadata",
which starts on p. 8, and "Component Data", which starts on p. 10. Appendix A, Table 1 (p. 19)
lists every data field with its definition.

| Check | Clause | Notes |
|-------|--------|-------|
| `document.timestamp` | Data Fields, SBOM Metadata: SBOM Timestamp (p. 9) | "Record of the date and time of the most recent update to the SBOM data". The content "should adhere to RFC 9557", which extends RFC 3339. |
| `document.author` | Data Fields, SBOM Metadata: SBOM Author (p. 8) and SBOM Tool Name (p. 9) (lenient: a tool is accepted, see docs/validate.md) | **Decided: lenient.** This is looser than CISA, which defines SBOM Author as "the entity operating the tool to generate the SBOM, not the tool itself" and has SBOM Tool Name as a separate element. The profile accepts `metadata.authors`, `metadata.manufacturer` or `metadata.tools`. The trade-off: the strict setting, `accept: [authors, manufacturer]`, would fail rollcall's own output, which names only the tool. The leniency is deliberate until `rollcall generate --author` exists. |
| `document.root` | Data Fields (p. 8) and Component Data (p. 10): the target component, the component for which the SBOM is generated | The data fields describe "the target component … and all subcomponents". The 2026 document has no separate "Primary Component" field. |
| `component.name` | Data Fields, Component Data: Component Name (p. 12) | |
| `component.version` | Data Fields, Component Data: Component Version (p. 13) | The document asks for "unknown" to be stated explicitly when the producer gives no version. A literal `unknown` passes this check. |
| `component.supplier` | Data Fields, Component Data: Component Producer (p. 10) | Component Producer replaces the 2021 "Supplier Name". CycloneDX `manufacturer` is the closest field and `supplier` is the 2021 one, so `accept: [supplier, manufacturer]`. |
| `component.identifier` | Data Fields, Component Data: Component Identifiers (p. 12) | "at least one software identifier … such as … CPE … and … PURL". The profile counts purl and cpe, per this ticket's scope. The document also allows OmniBOR, SWHID and others, so adding them to `fields` is a data change. |
| `component.hash` | Data Fields, Component Data: Component Hash Value and Component Hash Algorithm (p. 11) | The hash is of "an executable component artifact", and the algorithm "should be approved by a relevant authority, such as NIST". The profile accepts SHA-2 and SHA-3 (SHA-256/384/512, SHA3-256/384/512), not MD5, SHA-1, BLAKE or Streebog. |
| `graph.refs-resolve` | Data Fields, Component Data: Component Dependency Relationship (p. 11) | The element "supports the capability to build a dependency graph". Dangling refs break that graph. |
| `graph.reachable` | Data Fields, Component Data: Component Dependency Relationship (p. 11); Practices and Processes: Coverage (p. 13) | Coverage: "information for all components that make up the target software, including transitive dependencies". |

**Not checked yet.** These 2026 elements are outside this ticket's scope:

- SBOM Author Signature, SBOM Data Format Name, SBOM Data Format Version, SBOM Generation
  Context, SBOM Tool Version and SBOM Version. The data format and version are implied by
  `--schema`.
- Component License.
- The Practices and Processes elements, other than Coverage.

## Built-in profile `cra`

The sources are:

- **Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024
  (Cyber Resilience Act), OJ L, 2024/2847, 20.11.2024**,
  https://eur-lex.europa.eu/eli/reg/2024/2847/oj
- **BSI TR-03183-2, Cyber Resilience Requirements for Manufacturers and Products, Part 2:
  Software Bill of Materials (SBOM), version 2.1.0, 2025-08-20**,
  https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf

The profile file cites them as:

- `cra`: Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 (Cyber Resilience Act), OJ L, 2024/2847, 20.11.2024
- `bsi`: BSI TR-03183-2, Cyber Resilience Requirements for Manufacturers and Products, Part 2: Software Bill of Materials (SBOM), version 2.1.0, 2025-08-20
- `rollcall`: rollcall CRA-oriented requirement (SHA-118), documented in docs/validate.md; not a clause of the Regulation or of BSI TR-03183-2

  URL: https://github.com/smhasan94/rollcall/blob/main/docs/validate.md. This source is used
  only where the check is rollcall's own requirement, not a clause of either document.

**What passing `cra` means.** Passing `cra` means passing rollcall's CRA-oriented checks. It is
not a claim of full conformance with every cited BSI TR-03183-2 clause. The profile header in
`cra.yaml` lists the points where the checks are deliberately looser than BSI. These are
decided, not open questions:

- **Hash algorithm.** `component.hash` accepts SHA-256/384/512 and SHA3-256/384/512; BSI asks
  for SHA-512.
- **Email or URL.** `document.author` and `component.supplier` accept a name; BSI asks for the
  creator's email address or URL.
- **Identifiers.** `component.identifier` requires a purl or cpe on every component as
  rollcall's own requirement; BSI asks for other identifiers only "if it exists".

The Regulation itself asks for an SBOM in four places:

- **Annex I, Part II, point (1)** (vulnerability handling requirements). Manufacturers shall
  identify and document the vulnerabilities and components contained in the product,
  "including by drawing up a software bill of materials in a commonly used and
  machine-readable format covering at the very least the top-level dependencies".
- **Article 3, point (39)** defines a software bill of materials as "a formal record containing
  details and supply chain relationships of components included in the software elements of a
  product with digital elements".
- **Annex VII**, points 2(b) and 8, puts the SBOM in the technical documentation, to be given
  to a market surveillance authority on a reasoned request.
- **Article 13(24)** lets the Commission specify "the format and elements of the software bill
  of materials" by implementing act. **To confirm:** no such implementing act has been adopted
  as of this writing.

The Regulation does not list per-component fields. For those, the `cra` profile cites BSI
TR-03183-2, the German federal technical guideline written for the CRA's SBOM requirement.
That guideline is CRA-aligned guidance, not the Regulation's text. To check the Regulation
literally, remove the `bsi`-cited checks from `cra.yaml`; that is a data change.

| Check | Clause | Notes |
|-------|--------|-------|
| `document.timestamp` | section 5.2.1, Table 2: Timestamp | "Date and time of the SBOM data compilation". |
| `document.author` | section 5.2.1, Table 2: Creator of the SBOM (lenient: name accepted, see profile header) | **Decided: lenient** (see *What passing `cra` means*). BSI asks for the creator's email address, or a URL if there is none. This check accepts `metadata.authors`, `metadata.manufacturer` or `metadata.tools` by name. |
| `document.root` | Annex I, Part II, point (1): the top-level dependencies of the product (inference: the product is the root) | **Inference.** The Regulation does not name a root component. Top-level dependencies imply a product they hang from, which BSI section 5.1 calls the "primary component". |
| `component.name` | section 5.2.2, Table 3: Component name | |
| `component.version` | section 5.2.2, Table 3: Component version | |
| `component.supplier` | section 5.2.2, Table 3: Component creator (lenient: name accepted, see profile header) | **Decided: lenient** (see *What passing `cra` means*). BSI asks for the creator's email address or URL. This check requires `supplier.name` or `manufacturer.name`. |
| `component.identifier` | every component has a unique identifier, PURL or CPE (related: BSI TR-03183-2 section 5.2.4, Table 5, Other unique identifiers, required there only if it exists) | **Decided: rollcall's own requirement**, cited to the `rollcall` source. The ticket's scope asks for "a unique identifier (PURL or CPE)" on every component, at error severity. BSI section 5.2.4 is only a related reference: it lists CPE and purl as *additional* fields, required "if it exists". |
| `component.hash` | section 5.2.2, Table 3: Hash value of the deployable component (lenient: SHA-256 and up accepted, BSI asks for SHA-512; see profile header) | **Decided: lenient** (see *What passing `cra` means*). BSI requires the hash of the deployable component "as SHA-512". The profile accepts SHA-256/384/512 and SHA3-256/384/512. To follow BSI strictly, set `algorithms: [SHA-512]`; that is a data change. |
| `graph.refs-resolve` | section 5.2.2, Table 3: Dependencies on other components | |
| `graph.reachable` | section 5.1: Level of detail; section 5.2.2, Table 3: Dependencies on other components | BSI section 5.1 requires "recursive dependency resolution … for each component included in the scope of delivery". |
| `graph.top-level-complete` | Annex I, Part II, point (1): an SBOM covering at the very least the top-level dependencies of the product | BSI section 5.2.2 also requires that "the completeness of this enumeration MUST be clearly indicated". |
| `image.represented` | Annex I, Part II, point (1) and Article 3, point (39): the components contained in the product (to confirm) | **Open interpretation note.** This is an interpretation: each firmware image a product ships (bootloader, application, blob) is a component contained in it, so each must appear as a top-level component. |

**Not checked yet.** These BSI fields are outside this ticket's scope:

- filename;
- distribution licences;
- the executable, archive and structured properties;
- the SBOM-URI, source code URI and deployable-form URI.

## Citation decisions and open notes

**Decided** (lenient on purpose, recorded above):

1. `cisa-2026` `document.author`: a tool alone satisfies it. This is looser than CISA and
   deliberate until `rollcall generate --author` exists. Tightening it is tracked in
   [issue #14](https://github.com/smhasan94/rollcall/issues/14).
2. `cra` `document.author` and `component.supplier`: a name is accepted where BSI asks for an
   email address or URL.
3. `cra` `component.hash`: SHA-256 and up are accepted where BSI asks for SHA-512.
4. `cra` `component.identifier`: a purl or cpe is required as rollcall's own requirement. BSI
   asks for other identifiers only "if it exists".

Items 2 to 4 are listed in the `cra.yaml` profile header and under *What passing `cra` means*.

**Inference**: `cra` `document.root` reads "top-level dependencies of the product" as
implying the product is the root.

**Still to confirm** (open interpretation notes, not decisions):

1. `cra` `image.represented`: whether firmware images count as "components contained in the
   product".
2. CRA Article 13(24): whether an implementing act on SBOM format and elements has been
   adopted. This could not be verified here.

## Fixtures

The fixture that passes both profiles with zero warnings is
`crates/rollcall-core/tests/golden/clean.cdx.json`. It is rendered by `rollcall generate` from
the **hand-written** model `crates/rollcall-core/tests/data/clean.model.json`.

rollcall's real Zephyr builds cannot pass yet. The goldens under `tests/golden/zephyr/`, and
the tls sysbuild product generated with `--identifier-db` and `--product`, fail on genuinely
missing data:

- `component.hash`: the Zephyr ingestion records no hashes on the product, images or source
  modules.
- `component.version`, `component.supplier` and `component.identifier`: the images have no
  version, supplier or identifier, and neither does the product unless `--product` gives a
  version.

They pass every document and graph check. The test
`zephyr_goldens_fail_only_component_fields_until_issue_14` pins exactly this set of failing
checks. The gap is tracked as
[issue #14](https://github.com/smhasan94/rollcall/issues/14).

The stripped fixture is `tests/golden/validate/clean.stripped.cdx.json`: the clean document
with `supplier` and `hashes` removed from `mbedtls` and `littlefs`. Its expected `--profile all`
report is `clean.stripped.findings.json`. Both files are written only by
`scripts/regen-golden.sh`.
