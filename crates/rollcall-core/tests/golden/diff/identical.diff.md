## rollcall: mbedtls

✅ **No new open findings at or above high.**

This report checks how ready the software bill of materials (SBOM) of mbedtls is to hand to a customer or regulator. Its readiness score is 32 out of 100. The SBOM lists 10 items in total: the product, 1 firmware image and 8 software components. 8 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 4 a licence. 2 modules are not in rollcall's identifier database, so their identity may be incomplete (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 21 problems to fix and 0 recommendations. A vulnerability scan was supplied: 13 known vulnerabilities affect this product's components; 13 are still open (4 critical, 4 high) and 0 closed by VEX statements (not affected or fixed).

Readiness score: **32 / 100** (base: 32 / 100).

### New findings

None.

### Fixed findings

None.

### Triage changes

None.

### Components

No changes.

### Base

Compared with the base branch's build of mbedtls.

Diff schema `rollcall-diff/1`; the SBOM, VEX, scan, report and diff JSON are in the workflow run's artifact.
