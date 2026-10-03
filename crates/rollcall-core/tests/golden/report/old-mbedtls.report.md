# Readiness report: old-tls-node 1.0.0

This report checks how ready the software bill of materials (SBOM) of old-tls-node 1.0.0 is to hand to a customer or regulator. Its readiness score is 31 out of 100. The SBOM lists 4 items in total: the product, 1 firmware image and 2 software components. 2 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 2 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 14 problems to fix and 0 recommendations. A vulnerability scan was supplied: 23 known vulnerabilities affect this product's components; 20 are still open (3 critical, 8 high) and 3 closed by VEX statements (not affected or fixed).

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**31 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 2 of 4 | 12.50 |
| Hashed | 15 | 0 of 4 | 0.00 |
| Licensed | 15 | 2 of 4 | 7.50 |
| Validation (CISA 2026, CRA) | 25 | 0 of 4 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | 3 of 23 | 1.30 |
| **Total** | 100 | scan supplied | **31.30** |

## Coverage

Over 4 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 2 of 4 (50.00%) |
| CPE | 2 of 4 (50.00%) |
| PURL or CPE | 2 of 4 (50.00%) |
| Hash | 0 of 4 (0.00%) |
| Licence | 2 of 4 (50.00%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| old-tls-node (product) | 1.0.0 | firmware | no | no | no | no |
| old-tls-app (image) | 1.0.0 | firmware | no | no | no | no |
| old-tls-app / mbedtls | 2.28.0 | library | yes | yes | no | yes |
| old-tls-app / zephyr | 3.7.0 | operating-system | yes | yes | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

23 finding(s): 23 in the SBOM (20 open, 3 closed by VEX), 0 for packages not in the SBOM.

| Open, by severity | Count |
| --- | ---: |
| Critical | 3 |
| High | 8 |
| Medium | 9 |
| Low | 0 |
| Unknown | 0 |

| Vulnerability | Severity | Item | Package | Status | VEX |
| --- | --- | --- | --- | --- | --- |
| CVE-2022-35409 | critical | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | closed | not\_affected |
| CVE-2022-46393 | critical | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | closed | not\_affected |
| CVE-2025-47917 | critical | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2026-34872 | critical | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2026-34877 | critical | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2021-43666 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | — |
| CVE-2021-45451 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2023-43615 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2023-52353 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2024-23775 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | closed | not\_affected |
| CVE-2024-28960 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-48965 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-52496 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2026-25835 | high | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2022-46392 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | affected |
| CVE-2024-23170 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-27809 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-27810 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-52497 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-54764 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-59438 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2025-66442 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |
| CVE-2026-34871 | medium | old-tls-app / mbedtls | pkg:github/mbed-tls/mbedtls@v2.28.0 | open | under\_investigation |

## VEX coverage

22 statement(s), 0 matching no finding; 22 of the findings in the SBOM have a statement (95.65%).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 14 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | old-tls-node (product) | no hash |
| error | component.identifier | old-tls-node (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | old-tls-node (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | old-tls-app (image) | no hash |
| error | component.identifier | old-tls-app (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | old-tls-app (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | old-tls-app (image) | not reachable from the root product:cb91904541becd528b35755f21604693 through dependencies or nesting |
| error | graph.top-level-complete | old-tls-app (image) | top-level component is not listed in the root's dependsOn |
| error | component.hash | old-tls-app / mbedtls | no hash |
| error | component.supplier | old-tls-app / mbedtls | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | old-tls-app / mbedtls | not reachable from the root product:cb91904541becd528b35755f21604693 through dependencies or nesting |
| error | component.hash | old-tls-app / zephyr | no hash |
| error | component.supplier | old-tls-app / zephyr | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | old-tls-app / zephyr | not reachable from the root product:cb91904541becd528b35755f21604693 through dependencies or nesting |

## Warnings

None.
