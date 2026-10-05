# FAQ: what the CRA and CISA ask of an SBOM

> **Not legal advice.** This page explains, in plain language, what the documents it cites say
> about software bills of materials (SBOMs), and what rollcall does about each point. It is
> not legal advice and does not tell you whether your product complies with any law. Read the
> cited text itself, and ask a qualified lawyer about your own obligations.

Every answer cites the primary source it rests on. The sources are:

- **CRA**: [Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 (Cyber Resilience Act), OJ L, 2024/2847, 20.11.2024](https://eur-lex.europa.eu/eli/reg/2024/2847/oj), on EUR-Lex.
- **CISA 2026**: [CISA, NSA, FBI et al., 2026 Minimum Elements for a Software Bill of Materials (SBOM), version 2.1, July 29, 2026](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom).
  Page numbers are those of its PDF, as in [validate](validate.md#built-in-profile-cisa-2026).
- **NTIA 2021**: [NTIA, The Minimum Elements For a Software Bill of Materials (SBOM), July 12, 2021](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom).
- **CycloneDX 1.6**: the [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/),
  published as [ECMA-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/),
  1st edition (June 2024). The 2nd edition (December 2025) is CycloneDX 1.7.
- **BSI TR-03183-2**: [BSI TR-03183-2, Cyber Resilience Requirements for Manufacturers and Products, Part 2: Software Bill of Materials (SBOM), version 2.1.0, 2025-08-20](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf),
  the German federal guideline written with the CRA in mind (its first version dates from 2023).
  It is guidance, not the Regulation.

## Does the CRA require an SBOM?

Yes, for manufacturers of products with digital elements placed on the EU market. Among the
vulnerability handling requirements, manufacturers shall "identify and document
vulnerabilities and components contained in products with digital elements, including by
drawing up a software bill of materials in a commonly used and machine-readable format
covering at the very least the top-level dependencies of the products".

"At the very least" sets a floor, not a target. BSI TR-03183-2 and CISA 2026 (Coverage, p. 13)
both expect the full tree of transitive dependencies, and rollcall writes the whole graph the
build shows it.

Who is covered: the duty falls on the *manufacturer*, whoever places the finished product on
the market under their own name or trademark. Some products are outside the Regulation
because other EU rules already cover them: medical devices, motor vehicles, certified aviation
products and marine equipment. Spare parts that replace identical parts, and products made
exclusively for national security or defence, are also excluded.

Sources: CRA, Annex I, Part II, point (1); Article 2; Article 3, point (13); BSI TR-03183-2;
CISA 2026, Practices and Processes.

## What does the CRA mean by "software bill of materials"?

"A formal record containing details and supply chain relationships of components included in
the software elements of a product with digital elements". In firmware terms: a list of what
went into the image (the RTOS, the bootloader, libraries, vendor blobs) and which part
contains which.

Source: CRA, Article 3, point (39).

## Which fields does the CRA require in the SBOM?

The Regulation itself lists none. It asks for a "commonly used and machine-readable format"
covering "at the very least the top-level dependencies", and lets the Commission specify "the
format and elements of the software bill of materials" later, by implementing act. As of
October 2026 no such implementing act has been adopted; check EUR-Lex before relying on this.

Until then, the most detailed CRA-aligned guidance is BSI TR-03183-2, which lists required
fields per component (name, version, creator, hash, dependencies, licence and more). rollcall's
`cra` profile checks the Regulation's top-level-dependency rule and the BSI fields, and says
which is which ([validate](validate.md#built-in-profile-cra)).

Sources: CRA, Annex I, Part II, point (1), and Article 13(24); BSI TR-03183-2, section 5.2.2,
Table 3.

## Do I have to publish the SBOM?

The Regulation does not require it. The SBOM is part of the product's technical documentation
(Annex VII, point 2(b)), and is handed to a market surveillance authority on a reasoned request
where that is necessary to check compliance (point 8). You keep the technical documentation
for at least 10 years after the product is placed on the market, or for its support period if
that is longer. If you decide to make the SBOM available to users, the information that
accompanies the product says where to find it.

Sources: CRA, Annex VII, points 2(b) and 8; Article 13(13); Annex II, point 9.

## When do the CRA's obligations apply?

The Regulation, including the SBOM requirement in Annex I, applies from 11 December 2027.
Products placed on the market before that date fall under it only if they are substantially
modified afterwards. One exception: the reporting obligations of Article 14 (notifying actively
exploited vulnerabilities and severe incidents) apply from 11 September 2026, to new and
already-marketed products alike.

Sources: CRA, Article 71(2); Article 69(2) and (3).

## Does the SBOM duty cover open-source components?

The SBOM covers the components contained in the product, wherever they came from. Separately,
a manufacturer that finds a vulnerability in an integrated component, "including in an open
source-component", shall report it to whoever maintains that component.

Sources: CRA, Annex I, Part II, point (1); Article 13(6).

## What are the CISA minimum elements?

A list of what an SBOM should contain, published by the US Cybersecurity and Infrastructure
Security Agency (CISA) together with the NSA, the FBI and fifteen partner agencies from other
countries, including Germany's BSI and France's ANSSI. The 2026 version replaces the NTIA 2021
list. It is guidance, not a law. Its
data fields are in two groups (Appendix A, Table 1, p. 19, lists each with its definition):

- **SBOM metadata**: SBOM Author, SBOM Timestamp, SBOM Tool Name, SBOM Author Signature, SBOM
  Data Format Name and Version, SBOM Generation Context, SBOM Tool Version and SBOM Version.
- **Component data**: Component Producer, Component Name, Component Version, Component
  Identifiers, Component Hash Value and Algorithm, Component Dependency Relationship, and
  Component License.

It also has practices, such as Coverage (p. 13): "information for all components that make up
the target software, including transitive dependencies".

Source: CISA 2026, Data Fields and Practices and Processes; Appendix A, Table 1 (p. 19) lists
every field.

## What did the NTIA 2021 minimum elements ask for?

Seven data fields: Supplier Name, Component Name, Version of the Component, Other Unique
Identifiers, Dependency Relationship, Author of SBOM Data, and Timestamp. Plus automation
support (a machine-readable format such as SPDX or CycloneDX) and practices: frequency, depth,
known unknowns, distribution and delivery, access control, and accommodation of mistakes. Much
existing tooling and many contracts still name this list.

Source: NTIA 2021, sections Data Fields, Automation Support and Practices and Processes.

## Where does each element go in CycloneDX 1.6?

| Element (CISA 2026 / NTIA 2021) | CycloneDX 1.6 field | rollcall fills it from |
|---------------------------------|---------------------|------------------------|
| SBOM Author / Author of SBOM Data | `metadata.authors`, `metadata.manufacturer` | not yet (`metadata.tools` names rollcall as the tool; there is no `generate --author` option yet) |
| SBOM Tool Name | `metadata.tools.components[]` | always |
| SBOM Timestamp / Timestamp | `metadata.timestamp` | the time of generation, or `--timestamp` |
| Component Producer / Supplier Name | `components[].supplier`, `manufacturer` | the identifier database, for the modules it knows (Zephyr's today); not yet the product or its images ([issue #14](https://github.com/smhasan94/rollcall/issues/14)) |
| Component Name, Version | `components[].name`, `version` | the build's inputs |
| Component Identifiers / Other Unique Identifiers | `components[].purl`, `cpe` | the identifier database |
| Component Hash | `components[].hashes[]` | binary blobs only (ESP-IDF blobs, `merge --blob-manifest`); not Zephyr images yet |
| Component Dependency Relationship | `dependencies[]` and nested `components[]` | the build's structure |
| Component License | `components[].licenses[]` | the build's inputs, where they record one |

Source: CycloneDX 1.6 JSON reference, the `metadata`, `components` and `dependencies`
properties.

## Is CycloneDX a "commonly used and machine-readable format"?

The CRA does not name formats. CycloneDX is a published standard (ECMA-424) with a JSON schema.
NTIA 2021 names it, with SPDX and SWID, under Automation Support, and CISA 2026 asks every SBOM
to state its data format and version (SBOM Data Format Name and SBOM Data Format Version).
rollcall writes CycloneDX 1.6 JSON only; SPDX output is deferred
([issue #37](https://github.com/smhasan94/rollcall/issues/37)).

Sources: CycloneDX 1.6 (ECMA-424); NTIA 2021, Automation Support; CISA 2026, Data Fields;
Appendix A, Table 1 (p. 19); CRA, Annex I, Part II, point (1).

## So what do I actually need to do?

For the SBOM part of the CRA, as a firmware manufacturer:

- Produce a machine-readable SBOM for every release you place on the market, covering at least
  every top-level dependency (`rollcall generate` writes CycloneDX 1.6 JSON).
- Keep it with the product's technical documentation, ready to hand to a market surveillance
  authority on request, for at least 10 years after the product is placed on the market or for
  its support period, whichever is longer.
- If you choose to give users the SBOM, say where to find it in the information that comes with
  the product.
- Run `rollcall validate --schema --profile cra` (and `--profile cisa-2026` if you sell into the
  US), fix what it reports, then read what the profiles do not check.
- Update the SBOM whenever the components change, so it keeps matching what you ship.

Sources: CRA, Annex I, Part II, point (1); Article 13(13); Annex VII, points 2(b) and 8; Annex
II, point 9; CISA 2026, Practices and Processes.

## Does a "valid" SBOM from rollcall mean my product complies?

No. `rollcall validate --schema` proves the document is well-formed CycloneDX 1.6.
`--profile cisa-2026` and `--profile cra` check some of the fields above (not, for example,
Component License or SBOM Author Signature; [validate](validate.md) lists what each profile
checks and what it does not), and passing them means passing rollcall's checks, not compliance
with any law: the CRA asks for much more than an SBOM
(secure design, vulnerability handling, updates, reporting), and the profiles are deliberately
lenient in places, each listed in [validate](validate.md#citation-decisions-and-open-notes).

Sources: CRA, Article 13 and Annex I; CISA 2026, Data Fields.
