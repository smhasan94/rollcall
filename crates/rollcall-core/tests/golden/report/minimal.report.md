# Readiness report: sensor-node 1.0.0

This report checks how ready the software bill of materials (SBOM) of sensor-node 1.0.0 is to hand to a customer or regulator. Its readiness score is 44 out of 100. The SBOM lists 4 items in total: the product, 1 firmware image and 2 software components. 3 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 1 a file hash that proves exactly which file was shipped, and 2 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 7 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**44 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 3 of 4 | 18.75 |
| Hashed | 15 | 1 of 4 | 3.75 |
| Licensed | 15 | 2 of 4 | 7.50 |
| Validation (CISA 2026, CRA) | 25 | 0 of 4 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **44.44** |

## Coverage

Over 4 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 3 of 4 (75.00%) |
| CPE | 2 of 4 (50.00%) |
| PURL or CPE | 3 of 4 (75.00%) |
| Hash | 1 of 4 (25.00%) |
| Licence | 2 of 4 (50.00%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| sensor-node (product) | 1.0.0 | firmware | no | no | no | no |
| sensor-app (image) | 1.0.0 | firmware | yes | no | yes | no |
| sensor-app / littlefs | 2.9.0 | library | yes | yes | no | yes |
| sensor-app / tinycrypt | 0.2.8 | library | yes | yes | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 7 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | sensor-node (product) | no hash |
| error | component.identifier | sensor-node (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | sensor-app (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | sensor-app / littlefs | no hash |
| error | component.supplier | sensor-app / littlefs | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | sensor-app / tinycrypt | no hash |
| error | component.supplier | sensor-app / tinycrypt | no supplier (manufacturer.name and supplier.name missing) |

## Warnings

None.
