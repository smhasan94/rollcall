# Readiness report: sensor-node 1.0.0

This report checks how ready the software bill of materials (SBOM) of sensor-node 1.0.0 is to hand to a customer or regulator. Its readiness score is 100 out of 100. The SBOM lists 8 items in total: the product, 3 firmware images and 4 software components. 8 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 8 a file hash that proves exactly which file was shipped, and 8 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6 and meets every CISA 2026 and EU Cyber Resilience Act minimum element rollcall checks. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**100 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 8 of 8 | 25.00 |
| Hashed | 15 | 8 of 8 | 15.00 |
| Licensed | 15 | 8 of 8 | 15.00 |
| Validation (CISA 2026, CRA) | 25 | 8 of 8 | 25.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **100.00** |

## Coverage

Over 8 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 7 of 8 (87.50%) |
| CPE | 4 of 8 (50.00%) |
| PURL or CPE | 8 of 8 (100.00%) |
| Hash | 8 of 8 (100.00%) |
| Licence | 8 of 8 (100.00%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| sensor-node (product) | 1.0.0 | firmware | yes | yes | yes | yes |
| mcuboot (image) | 2.1.0 | firmware | yes | no | yes | yes |
| sensor-app (image) | 1.0.0 | firmware | yes | no | yes | yes |
| sensor-app / littlefs | 2.9.0 | library | yes | no | yes | yes |
| sensor-app / mbedtls | 3.6.4 | library | yes | yes | yes | yes |
| sensor-app / zephyr | 4.2.0 | operating-system | yes | yes | yes | yes |
| radio-fw (image) | 6.0.0 | firmware | yes | no | yes | yes |
| radio-fw / sdc | 6.0.0 | firmware | no | yes | yes | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: passed, 0 error(s), 0 warning(s).

## Warnings

None.
