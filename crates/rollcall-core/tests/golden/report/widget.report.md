# Readiness report: widget 1.0.0

This report checks how ready the software bill of materials (SBOM) of widget 1.0.0 is to hand to a customer or regulator. Its readiness score is 15 out of 100. The SBOM lists 11 items in total: the product, 3 firmware images and 7 software components. 3 of them carry an identifier (a PURL or CPE) that vulnerability databases can match, 2 a file hash that proves exactly which file was shipped, and 3 a licence. 1 module is not in rollcall's identifier database, so its identity may be incomplete (see Unresolved modules). 4 components have no PURL or CPE, so scanners cannot match them (see Unresolved modules). The SBOM is valid CycloneDX 1.6; the CISA 2026 and EU Cyber Resilience Act checks found 38 problems to fix and 0 recommendations. No vulnerability scan was supplied, so known vulnerabilities were not checked and are not part of the score.

Generated 2026-01-02T03:04:05Z by rollcall 0.0.1. Report schema `rollcall-report/1`; see `docs/report.md` for how the score is calculated.

## Score

**15 / 100**

| Category | Weight | Result | Points |
| --- | ---: | --- | ---: |
| Identified (PURL or CPE) | 25 | 3 of 11 | 6.81 |
| Hashed | 15 | 2 of 11 | 2.72 |
| Licensed | 15 | 3 of 11 | 4.09 |
| Validation (CISA 2026, CRA) | 25 | 0 of 11 | 0.00 |
| Modules resolved | 10 | 0 of 1 | 0.00 |
| Vulnerabilities closed | 10 | not assessed (no scan supplied) | — |
| **Total** | 90 | no scan supplied; out of 90, scaled to 100 | **15.15** |

## Coverage

Over 11 items (the product, its images and every component).

| Measure | Items |
| --- | --- |
| PURL | 3 of 11 (27.27%) |
| CPE | 1 of 11 (9.09%) |
| PURL or CPE | 3 of 11 (27.27%) |
| Hash | 2 of 11 (18.18%) |
| Licence | 3 of 11 (27.27%) |

## Components

| Item | Version | Type | PURL | CPE | Hash | Licence |
| --- | --- | --- | --- | --- | --- | --- |
| widget (product) | 1.0.0 | firmware | no | no | no | no |
| mcuboot (image) | 2.1.0 | firmware | no | no | yes | no |
| mcuboot / mbedtls | 3.6.0 | library | no | no | no | no |
| mcuboot / tinycrypt | 0.2.8 | library | no | no | no | no |
| widget-app (image) | 1.0.0 | firmware | no | no | no | yes |
| widget-app / cmsis | 5.9.0 | library | yes | no | no | no |
| widget-app / mbedtls | 3.6.0 | library | yes | no | no | yes |
| widget-app / zephyr | 3.7.0 | operating-system | yes | yes | no | yes |
| widget-app / zephyr / kernel | — | library | no | no | no | no |
| radio-fw (image) | — | firmware | no | no | no | no |
| radio-fw / sdc | — | firmware | no | no | yes | no |

## Unresolved modules

| Item | Version | Why |
| --- | --- | --- |
| mcuboot / mbedtls | 3.6.0 | no PURL or CPE |
| mcuboot / tinycrypt | 0.2.8 | no PURL or CPE |
| radio-fw / sdc | — | no PURL or CPE |
| widget-app / mbedtls | 3.6.0 | module not in the identifier database |
| widget-app / zephyr / kernel | — | no PURL or CPE |

Identifier database entries to fill in and add under `modules:` (one per name):

```yaml
  kernel:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:generic/kernel@{version}"    # prefer pkg:github/<owner>/<repo>@v{version} for the upstream repository
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "<revision>": ""    # replace <revision> with the module's git revision (without one the module stays Low), and give its upstream release
```

```yaml
  mbedtls:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:generic/mbedtls@{version}"    # prefer pkg:github/<owner>/<repo>@v{version} for the upstream repository
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "3.6.0": ""    # the upstream release this revision corresponds to
```

```yaml
  sdc:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:generic/sdc@{version}"    # prefer pkg:github/<owner>/<repo>@v{version} for the upstream repository
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "<revision>": ""    # replace <revision> with the module's git revision (without one the module stays Low), and give its upstream release
```

```yaml
  tinycrypt:
    upstream:
      name: ""        # upstream project name
      homepage: ""    # project homepage URL (or delete this line)
      supplier: ""    # who publishes it upstream (or delete this line)
    purl: "pkg:generic/tinycrypt@{version}"    # prefer pkg:github/<owner>/<repo>@v{version} for the upstream repository
    cpe: "cpe:2.3:a:<vendor>:<product>:{version}:*:*:*:*:*:*:*"    # NVD vendor and product (or delete this line)
    version_rule:
      kind: manual
      table:
        "0.2.8": ""    # the upstream release this revision corresponds to
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
| error | component.hash | widget (product) | no hash |
| error | component.identifier | widget (product) | no unique identifier (cpe, purl missing) |
| error | component.identifier | mcuboot (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | mcuboot (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | mcuboot (image) | not reachable from the root product:6cfdd60d1daa8e80f7b0de40692994d8 through dependencies or nesting |
| error | graph.top-level-complete | mcuboot (image) | top-level component is not listed in the root's dependsOn |
| error | component.hash | mcuboot / mbedtls | no hash |
| error | component.identifier | mcuboot / mbedtls | no unique identifier (cpe, purl missing) |
| error | component.supplier | mcuboot / mbedtls | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | mcuboot / mbedtls | not reachable from the root product:6cfdd60d1daa8e80f7b0de40692994d8 through dependencies or nesting |
| error | component.hash | mcuboot / tinycrypt | no hash |
| error | component.identifier | mcuboot / tinycrypt | no unique identifier (cpe, purl missing) |
| error | component.supplier | mcuboot / tinycrypt | no supplier (manufacturer.name and supplier.name missing) |
| error | graph.reachable | mcuboot / tinycrypt | not reachable from the root product:6cfdd60d1daa8e80f7b0de40692994d8 through dependencies or nesting |
| error | component.hash | widget-app (image) | no hash |
| error | component.identifier | widget-app (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | widget-app (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | widget-app / cmsis | no hash |
| error | component.supplier | widget-app / cmsis | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | widget-app / mbedtls | no hash |
| error | component.supplier | widget-app / mbedtls | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | widget-app / zephyr | no hash |
| error | component.supplier | widget-app / zephyr | no supplier (manufacturer.name and supplier.name missing) |
| error | component.hash | widget-app / zephyr / kernel | no hash |
| error | component.identifier | widget-app / zephyr / kernel | no unique identifier (cpe, purl missing) |
| error | component.supplier | widget-app / zephyr / kernel | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | widget-app / zephyr / kernel | no version |
| error | component.hash | radio-fw (image) | no hash |
| error | component.identifier | radio-fw (image) | no unique identifier (cpe, purl missing) |
| error | component.supplier | radio-fw (image) | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | radio-fw (image) | no version |
| error | graph.reachable | radio-fw (image) | not reachable from the root product:6cfdd60d1daa8e80f7b0de40692994d8 through dependencies or nesting |
| error | graph.top-level-complete | radio-fw (image) | top-level component is not listed in the root's dependsOn |
| error | component.hash | radio-fw / sdc | no hash with an accepted algorithm (has SHA-1; accepted: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512) |
| error | component.identifier | radio-fw / sdc | no unique identifier (cpe, purl missing) |
| error | component.supplier | radio-fw / sdc | no supplier (manufacturer.name and supplier.name missing) |
| error | component.version | radio-fw / sdc | no version |
| error | graph.reachable | radio-fw / sdc | not reachable from the root product:6cfdd60d1daa8e80f7b0de40692994d8 through dependencies or nesting |

## Warnings

None.
