# Readiness report: with\_mcuboot

This report checks how ready the software bill of materials (SBOM) of with\_mcuboot is to hand to a customer or regulator. Its readiness score is 42 out of 100. The SBOM lists 19 items in total: the product, 2 firmware images and 16 software components. 16 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 9 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 28 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**42 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 16 of 19 | 21.05 |
| Hashed | 15 | 0 of 19 | 0.00 |
| Licensed | 15 | 9 of 19 | 7.10 |
| Validation (CISA 2026, CRA) | 25 | 0 of 19 | 0.00 |
| Modules resolved | 10 | 12 of 12 | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **42.39** |

## Coverage

Over 19 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 16 of 19 (84.21%) |
| CPE | 6 of 19 (31.57%) |
| PURL or CPE | 16 of 19 (84.21%) |
| Hash | 0 of 19 (0.00%) |
| Licence | 9 of 19 (47.36%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| with\_mcuboot (product) | — | firmware | no | no | no | no |
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
| with\_mcuboot (image) | — | firmware | no | no | no | yes |
| with\_mcuboot / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| with\_mcuboot / cmsis\_6 | 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 | library | yes | no | no | no |
| with\_mcuboot / hal\_nordic | 44fd3d44b15cb75f80a25b4679f91d2787e28664 | library | yes | no | no | yes |
| with\_mcuboot / mbedtls | a3e190fe44c78d1ba67f55979e1257328cc7d0d8 | library | yes | yes | no | no |
| with\_mcuboot / mcuboot | 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 | library | yes | no | no | no |
| with\_mcuboot / tf-psa-crypto | dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 | library | yes | yes | no | no |
| with\_mcuboot / zephyr | 4.4.2 | operating-system | yes | yes | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 28 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | with\_mcuboot (product) | no hash |
| error | component.identifier | with\_mcuboot (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | with\_mcuboot (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | with\_mcuboot (product) | no version |
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
| error | component.hash | with\_mcuboot (image) | no hash |
| error | component.identifier | with\_mcuboot (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | with\_mcuboot (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | with\_mcuboot (image) | no version |
| error | component.hash | with\_mcuboot / cmsis | no hash |
| error | component.hash | with\_mcuboot / cmsis\_6 | no hash |
| error | component.hash | with\_mcuboot / hal\_nordic | no hash |
| error | component.hash | with\_mcuboot / mbedtls | no hash |
| error | component.hash | with\_mcuboot / mcuboot | no hash |
| error | component.hash | with\_mcuboot / tf-psa-crypto | no hash |
| error | component.hash | with\_mcuboot / zephyr | no hash |

## Warnings

None.
