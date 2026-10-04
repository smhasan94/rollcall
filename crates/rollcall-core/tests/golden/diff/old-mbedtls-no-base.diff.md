## rollcall: mbedtls

❌ **8 new open findings at or above high**: the check fails.

This report checks how ready the software bill of materials (SBOM) of mbedtls is to hand to a customer or regulator. Its readiness score is 32 out of 100. The SBOM lists 10 items in total: the product, 1 firmware image and 8 software components. 8 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 4 a licence. 2 modules are not in rollcall's identifier database, so their identity may be incomplete (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 21 problems to fix and 0 recommendations. A vulnerability scan was supplied: 13 known vulnerabilities affect this product's components; 13 are still open (4 critical, 4 high) and 0 closed by VEX statements (not affected or fixed).

Readiness score: **32 / 100** (no base score).

### New findings

| Severity | ID | Component | Version | Fixed in | Triage |
| --- | --- | --- | --- | --- | --- |
| critical | CVE-2026-34872 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| critical | CVE-2026-34873 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6, 4.1.0 | unresolved |
| critical | CVE-2026-34875 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| critical | CVE-2026-34877 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| high | CVE-2026-25833 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| high | CVE-2026-25835 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| high | CVE-2026-34874 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| high | CVE-2026-34876 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| medium | CVE-2025-54764 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.5 | unresolved |
| medium | CVE-2025-59438 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.5 | unresolved |
| medium | CVE-2025-66442 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | — | unresolved |
| medium | CVE-2026-25834 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |
| medium | CVE-2026-34871 | mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | 3.6.6 | unresolved |

### Fixed findings

None.

### Triage changes

None.

### Components

No base SBOM to compare with.

### Base

No base artifact was found for this pull request's base branch: every open finding counts as new.

Diff schema `rollcall-diff/1`; the SBOM, VEX, scan, report and diff JSON are in the workflow run's artifact.
