# Readiness report: beacon

This report checks how ready the software bill of materials (SBOM) of beacon is to hand to a customer or regulator. Its readiness score is 41 out of 100. The SBOM lists 22 items in total: the product, 2 firmware images and 19 software components. 19 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 9 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 31 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**41 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 19 of 22 | 21.59 |
| Hashed | 15 | 0 of 22 | 0.00 |
| Licensed | 15 | 9 of 22 | 6.13 |
| Validation (CISA 2026, CRA) | 25 | 0 of 22 | 0.00 |
| Modules resolved | 10 | 12 of 12 | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **41.91** |

## Coverage

Over 22 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 19 of 22 (86.36%) |
| CPE | 6 of 22 (27.27%) |
| PURL or CPE | 19 of 22 (86.36%) |
| Hash | 0 of 22 (0.00%) |
| Licence | 9 of 22 (40.90%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| beacon (product) | — | firmware | no | no | no | no |
| mcuboot (image) | — | firmware | no | no | no | yes |
| mcuboot / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| mcuboot / cmsis\_6 | 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 | library | yes | no | no | no |
| mcuboot / hal\_nordic | 44fd3d44b15cb75f80a25b4679f91d2787e28664 | library | yes | no | no | yes |
| mcuboot / mbedtls | a3e190fe44c78d1ba67f55979e1257328cc7d0d8 | library | yes | yes | no | yes |
| mcuboot / mcuboot | 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 | library | yes | no | no | yes |
| mcuboot / tf-psa-crypto | dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 | library | yes | yes | no | yes |
| mcuboot / zephyr | 4.4.2 | operating-system | yes | yes | no | yes |
| mcuboot / zephyr / logging | 4.4.2 | library | yes | no | no | no |
| mcuboot / zephyr / mbedtls-integration | 4.4.2 | library | yes | no | no | no |
| beacon (image) | — | firmware | no | no | no | yes |
| beacon / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| beacon / cmsis\_6 | 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 | library | yes | no | no | no |
| beacon / hal\_nordic | 44fd3d44b15cb75f80a25b4679f91d2787e28664 | library | yes | no | no | yes |
| beacon / mbedtls | a3e190fe44c78d1ba67f55979e1257328cc7d0d8 | library | yes | yes | no | no |
| beacon / mcuboot | 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 | library | yes | no | no | no |
| beacon / tf-psa-crypto | dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 | library | yes | yes | no | no |
| beacon / zephyr | 4.4.2 | operating-system | yes | yes | no | yes |
| beacon / zephyr / bluetooth-controller | 4.4.2 | library | yes | no | no | no |
| beacon / zephyr / bluetooth-host | 4.4.2 | library | yes | no | no | no |
| beacon / zephyr / logging | 4.4.2 | library | yes | no | no | no |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 31 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | beacon (product) | no hash |
| error | component.identifier | beacon (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | beacon (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | beacon (product) | no version |
| error | component.hash | mcuboot (image) | no hash |
| error | component.identifier | mcuboot (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | mcuboot (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | mcuboot (image) | no version |
| error | component.hash | mcuboot / cmsis | no hash |
| error | component.hash | mcuboot / cmsis\_6 | no hash |
| error | component.hash | mcuboot / hal\_nordic | no hash |
| error | component.hash | mcuboot / mbedtls | no hash |
| error | component.hash | mcuboot / mcuboot | no hash |
| error | component.hash | mcuboot / tf-psa-crypto | no hash |
| error | component.hash | mcuboot / zephyr | no hash |
| error | component.hash | mcuboot / zephyr / logging | no hash |
| error | component.hash | mcuboot / zephyr / mbedtls-integration | no hash |
| error | component.hash | beacon (image) | no hash |
| error | component.identifier | beacon (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | beacon (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | beacon (image) | no version |
| error | component.hash | beacon / cmsis | no hash |
| error | component.hash | beacon / cmsis\_6 | no hash |
| error | component.hash | beacon / hal\_nordic | no hash |
| error | component.hash | beacon / mbedtls | no hash |
| error | component.hash | beacon / mcuboot | no hash |
| error | component.hash | beacon / tf-psa-crypto | no hash |
| error | component.hash | beacon / zephyr | no hash |
| error | component.hash | beacon / zephyr / bluetooth-controller | no hash |
| error | component.hash | beacon / zephyr / bluetooth-host | no hash |
| error | component.hash | beacon / zephyr / logging | no hash |

## Warnings

None.
