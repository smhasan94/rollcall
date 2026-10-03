# Readiness report: http\_server

This report checks how ready the software bill of materials (SBOM) of http\_server is to hand to a customer or regulator. Its readiness score is 42 out of 100. The SBOM lists 28 items in total: the product, 2 firmware images and 25 software components. 25 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 11 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 37 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**42 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 25 of 28 | 22.32 |
| Hashed | 15 | 0 of 28 | 0.00 |
| Licensed | 15 | 11 of 28 | 5.89 |
| Validation (CISA 2026, CRA) | 25 | 0 of 28 | 0.00 |
| Modules resolved | 10 | 12 of 12 | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **42.46** |

## Coverage

Over 28 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 25 of 28 (89.28%) |
| CPE | 6 of 28 (21.42%) |
| PURL or CPE | 25 of 28 (89.28%) |
| Hash | 0 of 28 (0.00%) |
| Licence | 11 of 28 (39.28%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| http\_server (product) | — | firmware | no | no | no | no |
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
| http\_server (image) | — | firmware | no | no | no | yes |
| http\_server / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| http\_server / cmsis\_6 | 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 | library | yes | no | no | no |
| http\_server / hal\_nordic | 44fd3d44b15cb75f80a25b4679f91d2787e28664 | library | yes | no | no | yes |
| http\_server / mbedtls | a3e190fe44c78d1ba67f55979e1257328cc7d0d8 | library | yes | yes | no | yes |
| http\_server / mcuboot | 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 | library | yes | no | no | no |
| http\_server / tf-psa-crypto | dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 | library | yes | yes | no | yes |
| http\_server / zephyr | 4.4.2 | operating-system | yes | yes | no | yes |
| http\_server / zephyr / filesystem | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / ip-stack | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / json | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / logging | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / mbedtls-integration | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / networking-core | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / shell | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / tls-sockets | 4.4.2 | library | yes | no | no | no |
| http\_server / zephyr / usb-device | 4.4.2 | library | yes | no | no | no |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 37 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | http\_server (product) | no hash |
| error | component.identifier | http\_server (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | http\_server (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | http\_server (product) | no version |
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
| error | component.hash | http\_server (image) | no hash |
| error | component.identifier | http\_server (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | http\_server (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | http\_server (image) | no version |
| error | component.hash | http\_server / cmsis | no hash |
| error | component.hash | http\_server / cmsis\_6 | no hash |
| error | component.hash | http\_server / hal\_nordic | no hash |
| error | component.hash | http\_server / mbedtls | no hash |
| error | component.hash | http\_server / mcuboot | no hash |
| error | component.hash | http\_server / tf-psa-crypto | no hash |
| error | component.hash | http\_server / zephyr | no hash |
| error | component.hash | http\_server / zephyr / filesystem | no hash |
| error | component.hash | http\_server / zephyr / ip-stack | no hash |
| error | component.hash | http\_server / zephyr / json | no hash |
| error | component.hash | http\_server / zephyr / logging | no hash |
| error | component.hash | http\_server / zephyr / mbedtls-integration | no hash |
| error | component.hash | http\_server / zephyr / networking-core | no hash |
| error | component.hash | http\_server / zephyr / shell | no hash |
| error | component.hash | http\_server / zephyr / tls-sockets | no hash |
| error | component.hash | http\_server / zephyr / usb-device | no hash |

## Warnings

None.
