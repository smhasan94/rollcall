# Readiness report: mbedtls

This report checks how ready the software bill of materials (SBOM) of mbedtls is to hand to a customer or regulator. Its readiness score is 37 out of 100. The SBOM lists 19 items in total: the product, 2 firmware images and 16 software components. 16 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 0 a file hash that proves exactly which file was shipped, and 9 a licence. 4 modules are not in rollcall's identifier database, so their identity may be incomplete (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 38 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.1.0. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**37 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 16 of 19 | 21.05 |
| Hashed | 15 | 0 of 19 | 0.00 |
| Licensed | 15 | 9 of 19 | 7.10 |
| Validation (CISA 2026, CRA) | 25 | 0 of 19 | 0.00 |
| Modules resolved | 10 | 6 of 10 | 6.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **37.95** |

## Coverage

Over 19 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 16 of 19 (84.21%) |
| CPE | 4 of 19 (21.05%) |
| PURL or CPE | 16 of 19 (84.21%) |
| Hash | 0 of 19 (0.00%) |
| Licence | 9 of 19 (47.36%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| mbedtls (product) | — | firmware | no | no | no | no |
| mcuboot (image) | — | firmware | no | no | no | yes |
| mcuboot / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| mcuboot / cmsis-6 | 06d952b6713a2ca41c9224a62075e4059402a151 | library | yes | no | no | no |
| mcuboot / hal-nordic | 9587b1dcb83d24ab74e89837843a5f7d573f7059 | library | yes | no | no | yes |
| mcuboot / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | library | yes | yes | no | yes |
| mcuboot / mcuboot | 4eba8087fa606db801455f14d185255bc8c49467 | library | yes | no | no | yes |
| mcuboot / zephyr | 4.2.0 | operating-system | yes | yes | no | yes |
| mcuboot / zephyr / logging | 4.2.0 | library | yes | no | no | no |
| mcuboot / zephyr / mbedtls-integration | 4.2.0 | library | yes | no | no | no |
| mbedtls (image) | — | firmware | no | no | no | yes |
| mbedtls / cmsis | 512cc7e895e8491696b61f7ba8066b4a182569b8 | library | yes | no | no | no |
| mbedtls / cmsis-6 | 06d952b6713a2ca41c9224a62075e4059402a151 | library | yes | no | no | no |
| mbedtls / hal-nordic | 9587b1dcb83d24ab74e89837843a5f7d573f7059 | library | yes | no | no | yes |
| mbedtls / mbedtls | 85440ef5fffa95d0e9971e9163719189cf34d979 | library | yes | yes | no | yes |
| mbedtls / mcuboot | 4eba8087fa606db801455f14d185255bc8c49467 | library | yes | no | no | no |
| mbedtls / zephyr | 4.2.0 | operating-system | yes | yes | no | yes |
| mbedtls / zephyr / logging | 4.2.0 | library | yes | no | no | no |
| mbedtls / zephyr / mbedtls-integration | 4.2.0 | library | yes | no | no | no |

## Unresolved modules

| Item | Version | Why |
| --- | --- | --- |
| mbedtls / cmsis-6 | 06d952b6713a2ca41c9224a62075e4059402a151 | module not in the identifier database |
| mbedtls / hal-nordic | 9587b1dcb83d24ab74e89837843a5f7d573f7059 | module not in the identifier database |
| mcuboot / cmsis-6 | 06d952b6713a2ca41c9224a62075e4059402a151 | module not in the identifier database |
| mcuboot / hal-nordic | 9587b1dcb83d24ab74e89837843a5f7d573f7059 | module not in the identifier database |

Identifier database entries to fill in and add under `modules:` (one per name):

```yaml
  cmsis-6:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:github/zephyrproject-rtos/cmsis_6@v{version}"    # from the module URL: point it at the upstream repository, not a Zephyr fork
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "06d952b6713a2ca41c9224a62075e4059402a151": ""    # the upstream release this revision corresponds to
```

```yaml
  hal-nordic:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:github/zephyrproject-rtos/hal_nordic@v{version}"    # from the module URL: point it at the upstream repository, not a Zephyr fork
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "9587b1dcb83d24ab74e89837843a5f7d573f7059": ""    # the upstream release this revision corresponds to
```

## Findings

No vulnerability scan was supplied (`--scan`); vulnerabilities were not assessed.

## VEX coverage

No VEX document was supplied (`--vex`).

## Validation

- CycloneDX 1.6 schema: valid.
- Profiles `cisa-2026`, `cra`: failed, 38 error(s), 0 warning(s).

| Severity | Check | Item | Problem |
| --- | --- | --- | --- |
| error | component.hash | mbedtls (product) | no hash |
| error | component.identifier | mbedtls (product) | no unique identifier (cpe, purl missing) |
| error | component.supplier | mbedtls (product) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | mbedtls (product) | no version |
| error | component.hash | mcuboot (image) | no hash |
| error | component.identifier | mcuboot (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | mcuboot (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | mcuboot (image) | no version |
| error | component.hash | mcuboot / cmsis | no hash |
| error | component.hash | mcuboot / cmsis-6 | no hash |
| error | component.supplier | mcuboot / cmsis-6 | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mcuboot / hal-nordic | no hash |
| error | component.supplier | mcuboot / hal-nordic | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mcuboot / mbedtls | no hash |
| error | component.hash | mcuboot / mcuboot | no hash |
| error | component.hash | mcuboot / zephyr | no hash |
| error | component.supplier | mcuboot / zephyr | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mcuboot / zephyr / logging | no hash |
| error | component.supplier | mcuboot / zephyr / logging | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mcuboot / zephyr / mbedtls-integration | no hash |
| error | component.supplier | mcuboot / zephyr / mbedtls-integration | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mbedtls (image) | no hash |
| error | component.identifier | mbedtls (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | mbedtls (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | mbedtls (image) | no version |
| error | component.hash | mbedtls / cmsis | no hash |
| error | component.hash | mbedtls / cmsis-6 | no hash |
| error | component.supplier | mbedtls / cmsis-6 | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mbedtls / hal-nordic | no hash |
| error | component.supplier | mbedtls / hal-nordic | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mbedtls / mbedtls | no hash |
| error | component.hash | mbedtls / mcuboot | no hash |
| error | component.hash | mbedtls / zephyr | no hash |
| error | component.supplier | mbedtls / zephyr | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mbedtls / zephyr / logging | no hash |
| error | component.supplier | mbedtls / zephyr / logging | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | mbedtls / zephyr / mbedtls-integration | no hash |
| error | component.supplier | mbedtls / zephyr / mbedtls-integration | no supplier (manufacturer.name and supplier.name missing) |

## Warnings

None.
