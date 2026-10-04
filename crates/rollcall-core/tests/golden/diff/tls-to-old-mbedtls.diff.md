## rollcall: mbedtls

❌ **8 new open findings at or above high**: the check fails.

This report checks how ready the software bill of materials (SBOM) of mbedtls is to hand to a customer or regulator. Its readiness score is 32 out of 100. The SBOM lists 10 items in total: the product, 1 firmware image and 8 software components. 8 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 4 a licence. 2 modules are not in rollcall's identifier database, so their identity may be incomplete (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 21 problems to fix and 0 recommendations. A vulnerability scan was supplied: 13 known vulnerabilities affect this product's components; 13 are still open (4 critical, 4 high) and 0 closed by VEX statements (not affected or fixed).

Readiness score: **32 / 100** (base: 36 / 100).

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

10 added, 18 removed, 0 changed.

| Change | Component | Base version | Head version |
| --- | --- | --- | --- |
| added | mbedtls (image) | — | — |
| added | mbedtls (product) | — | — |
| added | mbedtls / cmsis | — | 512cc7e895e8491696b61f7ba8066b4a182569b8 |
| added | mbedtls / cmsis-6 | — | 06d952b6713a2ca41c9224a62075e4059402a151 |
| added | mbedtls / hal-nordic | — | 9587b1dcb83d24ab74e89837843a5f7d573f7059 |
| added | mbedtls / mbedtls | — | 85440ef5fffa95d0e9971e9163719189cf34d979 |
| added | mbedtls / mcuboot | — | 4eba8087fa606db801455f14d185255bc8c49467 |
| added | mbedtls / zephyr | — | 4.2.0 |
| added | mbedtls / zephyr / logging | — | 4.2.0 |
| added | mbedtls / zephyr / mbedtls-integration | — | 4.2.0 |
| removed | http\_server (image) | — | — |
| removed | http\_server (product) | — | — |
| removed | http\_server / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | — |
| removed | http\_server / cmsis\_6 | 30a859f44ef8ab4dc8f84b03ed586fd16ccf9d74 | — |
| removed | http\_server / hal\_nordic | 44fd3d44b15cb75f80a25b4679f91d2787e28664 | — |
| removed | http\_server / mbedtls | a3e190fe44c78d1ba67f55979e1257328cc7d0d8 | — |
| removed | http\_server / mcuboot | 6d3b3d2c38ab20c242e5b9abb04d050086383eb2 | — |
| removed | http\_server / tf-psa-crypto | dc575a2ddcc8cb16275d24c42a52eaf79ebe2231 | — |
| removed | http\_server / zephyr | 4.4.2 | — |
| removed | http\_server / zephyr / filesystem | 4.4.2 | — |
| removed | http\_server / zephyr / ip-stack | 4.4.2 | — |
| removed | http\_server / zephyr / json | 4.4.2 | — |
| removed | http\_server / zephyr / logging | 4.4.2 | — |
| removed | http\_server / zephyr / mbedtls-integration | 4.4.2 | — |
| removed | http\_server / zephyr / networking-core | 4.4.2 | — |
| removed | http\_server / zephyr / shell | 4.4.2 | — |
| removed | http\_server / zephyr / tls-sockets | 4.4.2 | — |
| removed | http\_server / zephyr / usb-device | 4.4.2 | — |

### Base

Compared with the base branch's build of http\_server.

Diff schema `rollcall-diff/1`; the SBOM, VEX, scan, report and diff JSON are in the workflow run's artifact.
