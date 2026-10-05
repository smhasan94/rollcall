# Readiness report: arduino-mqtt

This report checks how ready the software bill of materials (SBOM) of arduino-mqtt is to hand to a customer or regulator. Its readiness score is 42 out of 100. The SBOM lists 7 items in total: the product, 1 firmware image and 5 software components. 6 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 3 a licence. No unresolved modules. The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 16 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0-rc.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**42 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 6 of 7 | 21.42 |
| Hashed | 15 | 0 of 7 | 0.00 |
| Licensed | 15 | 3 of 7 | 6.42 |
| Validation (CISA 2026, CRA) | 25 | 0 of 7 | 0.00 |
| Modules resolved | 10 | no modules (full marks) | 10.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **42.06** |

## Coverage

Over 7 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 6 of 7 (85.71%) |
| CPE | 1 of 7 (14.28%) |
| PURL or CPE | 6 of 7 (85.71%) |
| Hash | 0 of 7 (0.00%) |
| Licence | 3 of 7 (42.85%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| arduino-mqtt (product) | — | firmware | no | no | no | no |
| arduino-mqtt (image) | — | firmware | yes | no | no | no |
| arduino-mqtt / arduino-esp32 | 2.0.17 | framework | yes | yes | no | yes |
| arduino-mqtt / bblanchon/ArduinoJson | 7.2.1 | library | yes | no | no | no |
| arduino-mqtt / knolleary/PubSubClient | 2.8 | library | yes | no | no | no |
| arduino-mqtt / mathertel/OneButton | 2.6.1 | library | yes | no | no | yes |
| arduino-mqtt / espressif32 | 6.10.0 | platform | yes | no | no | yes |

## Unresolved modules

None: every module is in the identifier database and every component has a PURL or CPE.

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 16 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | arduino-mqtt (product) | no hash |
| error | component.identifier | arduino-mqtt (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | arduino-mqtt (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | arduino-mqtt (product) | no version |
| error | component.hash | arduino-mqtt (image) | no hash |
| error | component.supplier | arduino-mqtt (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | arduino-mqtt (image) | no version |
| error | component.hash | arduino-mqtt / arduino-esp32 | no hash |
| error | component.hash | arduino-mqtt / bblanchon/ArduinoJson | no hash |
| error | component.supplier | arduino-mqtt / bblanchon/ArduinoJson | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | arduino-mqtt / knolleary/PubSubClient | no hash |
| error | component.supplier | arduino-mqtt / knolleary/PubSubClient | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | arduino-mqtt / mathertel/OneButton | no hash |
| error | component.supplier | arduino-mqtt / mathertel/OneButton | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | arduino-mqtt / espressif32 | no hash |
| error | component.supplier | arduino-mqtt / espressif32 | no supplier (manufacturer.name and supplier.name missing) |

## Warnings

None.
