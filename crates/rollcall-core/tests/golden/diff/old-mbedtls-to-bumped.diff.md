## rollcall: mbedtls

✅ **No new open findings at or above high.**

This report checks how ready the software bill of materials (SBOM) of mbedtls is to hand to a customer or regulator. Its readiness score is 42 out of 100. The SBOM lists 10 items in total: the product, 1 firmware image and 8 software components. 8 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 4 a licence. 2 modules are not in rollcall's identifier database, so their identity may be incomplete (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 21 problems to fix and 0 recommendations. A vulnerability scan was supplied: 0 known vulnerabilities affect this product's components; 0 are still open (0 critical, 0 high) and 0 closed by VEX statements (not affected or fixed).

Readiness score: **42 / 100** (base: 32 / 100).

### New findings

None.

### Fixed findings

| Severity | ID | Component | Version |
| --- | --- | --- | --- |
| critical | CVE-2026-34872 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| critical | CVE-2026-34873 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| critical | CVE-2026-34875 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| critical | CVE-2026-34877 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| high | CVE-2026-25833 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| high | CVE-2026-25835 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| high | CVE-2026-34874 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| high | CVE-2026-34876 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| medium | CVE-2025-54764 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| medium | CVE-2025-59438 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| medium | CVE-2025-66442 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| medium | CVE-2026-25834 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| medium | CVE-2026-34871 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 |

### Triage changes

None.

### Components

0 added, 0 removed, 1 changed.

| Change | Component | Base version | Head version |
| --- | --- | --- | --- |
| changed | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 |

### Base

Compared with the base branch's build of mbedtls.

Diff schema `rollcall-diff/1`; the SBOM, VEX, scan, report and diff JSON are in the workflow run's artifact.
