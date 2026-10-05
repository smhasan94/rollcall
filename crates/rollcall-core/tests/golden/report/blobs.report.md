# Readiness report: blobs-demo 1.0.0

This report checks how ready the software bill of materials (SBOM) of blobs-demo 1.0.0 is to hand to a customer or regulator. Its readiness score is 51 out of 100. The SBOM lists 3 items in total: the product, 2 firmware images and 0 software components. 1 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 2 a file hash that proves exactly which file was shipped, and 2 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 4 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0-rc.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**51 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 1 of 3 | 8.33 |
| Hashed | 15 | 2 of 3 | 10.00 |
| Licensed | 15 | 2 of 3 | 10.00 |
| Validation (CISA 2026, CRA) | 25 | 1 of 3 | 8.33 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **51.85** |

## Coverage

Over 3 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 1 of 3 (33.33%) |
| CPE | 0 of 3 (0.00%) |
| PURL or CPE | 1 of 3 (33.33%) |
| Hash | 2 of 3 (66.66%) |
| Licence | 2 of 3 (66.66%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| blobs-demo (product) | 1.0.0 | firmware | no | no | no | no |
| libphy (image) | 5.2.1 | library | yes | no | yes | yes |
| s140\_nrf52\_softdevice (image) | 7.3.0 | firmware | no | no | yes | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 4 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | blobs-demo (product) | no hash |
| error | component.identifier | blobs-demo (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | blobs-demo (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.identifier | s140\_nrf52\_softdevice (image) | no unique identifier (cpe, purl missing) |

## Warnings

None.
