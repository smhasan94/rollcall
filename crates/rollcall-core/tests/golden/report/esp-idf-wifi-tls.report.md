# Readiness report: https\_request 1

This report checks how ready the software bill of materials (SBOM) of https\_request 1 is to hand to a customer or regulator. Its readiness score is 57 out of 100. The SBOM lists 14 items in total: the product, 7 firmware images and 6 software components. 13 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 6 a file hash that proves exactly which file was shipped, and 11 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 17 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**57 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 13 of 14 | 23.21 |
| Hashed | 15 | 6 of 14 | 6.42 |
| Licensed | 15 | 11 of 14 | 11.78 |
| Validation (CISA 2026, CRA) | 25 | 0 of 14 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **57.14** |

## Coverage

Over 14 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 13 of 14 (92.85%) |
| CPE | 3 of 14 (21.42%) |
| PURL or CPE | 13 of 14 (92.85%) |
| Hash | 6 of 14 (42.85%) |
| Licence | 11 of 14 (78.57%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| https\_request (product) | 1 | firmware | no | no | no | no |
| https\_request (image) | 1 | firmware | yes | no | no | no |
| https\_request / esp-idf | 5.5.1 | framework | yes | yes | no | yes |
| https\_request / esp-idf / esp-tls | 5.5.1 | library | yes | no | no | yes |
| https\_request / esp-idf / lwip | 2.2.0d | library | yes | yes | no | yes |
| https\_request / esp-idf / mbedtls | 3.6.4 | library | yes | yes | no | yes |
| https\_request / esp-idf / wifi | 5.5.1 | library | yes | no | no | yes |
| https\_request / protocol\_examples\_common | 5.5.1 | library | yes | no | no | no |
| libcore (image) | 5.5.1 | library | yes | no | yes | yes |
| libespnow (image) | 5.5.1 | library | yes | no | yes | yes |
| libnet80211 (image) | 5.5.1 | library | yes | no | yes | yes |
| libphy (image) | 5.5.1 | library | yes | no | yes | yes |
| libpp (image) | 5.5.1 | library | yes | no | yes | yes |
| librtc (image) | 5.5.1 | library | yes | no | yes | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 17 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | https\_request (product) | no hash |
| error | component.identifier | https\_request (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | https\_request (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | https\_request (image) | no hash |
| error | component.supplier | https\_request (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | https\_request / esp-idf | no hash |
| error | component.hash | https\_request / esp-idf / esp-tls | no hash |
| error | component.hash | https\_request / esp-idf / lwip | no hash |
| error | component.hash | https\_request / esp-idf / mbedtls | no hash |
| error | component.hash | https\_request / esp-idf / wifi | no hash |
| error | component.hash | https\_request / protocol\_examples\_common | no hash |
| error | graph.top-level-complete | libcore (image) | top-level component is not listed in the root's dependsOn |
| error | graph.top-level-complete | libespnow (image) | top-level component is not listed in the root's dependsOn |
| error | graph.top-level-complete | libnet80211 (image) | top-level component is not listed in the root's dependsOn |
| error | graph.top-level-complete | libphy (image) | top-level component is not listed in the root's dependsOn |
| error | graph.top-level-complete | libpp (image) | top-level component is not listed in the root's dependsOn |
| error | graph.top-level-complete | librtc (image) | top-level component is not listed in the root's dependsOn |

## Warnings

None.
