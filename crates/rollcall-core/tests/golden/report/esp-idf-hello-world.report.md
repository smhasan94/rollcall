# Readiness report: hello\_world 1

This report checks how ready the software bill of materials (SBOM) of hello\_world 1 is to hand to a customer or regulator. Its readiness score is 35 out of 100. The SBOM lists 3 items in total: the product, 1 firmware image and 1 software component. 2 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 1 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 6 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**35 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 2 of 3 | 16.66 |
| Hashed | 15 | 0 of 3 | 0.00 |
| Licensed | 15 | 1 of 3 | 5.00 |
| Validation (CISA 2026, CRA) | 25 | 0 of 3 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **35.18** |

## Coverage

Over 3 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 2 of 3 (66.66%) |
| CPE | 1 of 3 (33.33%) |
| PURL or CPE | 2 of 3 (66.66%) |
| Hash | 0 of 3 (0.00%) |
| Licence | 1 of 3 (33.33%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| hello\_world (product) | 1 | firmware | no | no | no | no |
| hello\_world (image) | 1 | firmware | yes | no | no | no |
| hello\_world / esp-idf | 5.5.1 | framework | yes | yes | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 6 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | hello\_world (product) | no hash |
| error | component.identifier | hello\_world (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | hello\_world (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | hello\_world (image) | no hash |
| error | component.supplier | hello\_world (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | hello\_world / esp-idf | no hash |

## Warnings

None.
