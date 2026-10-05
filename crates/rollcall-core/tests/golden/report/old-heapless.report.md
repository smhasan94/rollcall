# Readiness report: rust-node 1.0.0

This report checks how ready the software bill of materials (SBOM) of rust-node 1.0.0 is to hand to a customer or regulator. Its readiness score is 23 out of 100. The SBOM lists 3 items in total: the product, 1 firmware image and 1 software component. 1 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 1 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 11 problems to fix and 0 recommendations. A vulnerability scan was supplied: 1 known vulnerability affects this product's components; 1 is still open (0 critical, 1 high) and 0 closed by VEX statements (not affected or fixed).

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0-rc.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**23 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 1 of 3 | 8.33 |
| Hashed | 15 | 0 of 3 | 0.00 |
| Licensed | 15 | 1 of 3 | 5.00 |
| Validation (CISA 2026, CRA) | 25 | 0 of 3 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | 0 of 1 | 0.00 |
| **Total** | 100 | scan supplied | **23.33** |

## Coverage

Over 3 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 1 of 3 (33.33%) |
| CPE | 0 of 3 (0.00%) |
| PURL or CPE | 1 of 3 (33.33%) |
| Hash | 0 of 3 (0.00%) |
| Licence | 1 of 3 (33.33%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| rust-node (product) | 1.0.0 | firmware | no | no | no | no |
| rust-app (image) | 1.0.0 | firmware | no | no | no | no |
| rust-app / heapless | 0.5.0 | library | yes | no | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

1 finding(s): 1 in the SBOM (1 open, 0 closed by VEX), 0 for packages not in the SBOM.

| Open, by severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| Unknown | 0 |

| Vulnerability | Severity | Item | Package | Status | VEX |
| --- | --- | --- | --- | --- | --- |
| CVE-2020-36464 | high | rust-app / heapless | heapless@0.5.0 | open | — |

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 11 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | rust-node (product) | no hash |
| error | component.identifier | rust-node (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | rust-node (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | rust-app (image) | no hash |
| error | component.identifier | rust-app (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | rust-app (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | rust-app (image) | not reachable from the root product:448059ca4bed3a0f40b3864ef013cb1d through dependencies or nesting |
| error | graph.top-level-complete | rust-app (image) | top-level component is not listed in the root's dependsOn |
| error | component.hash | rust-app / heapless | no hash |
| error | component.supplier | rust-app / heapless | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | rust-app / heapless | not reachable from the root product:448059ca4bed3a0f40b3864ef013cb1d through dependencies or nesting |

## Warnings

None.
