# Contributing a module to the identifier database

The identifier database tells rollcall which upstream project each Zephyr module is, so that
every module in an SBOM carries a purl and, where NVD lists one, a CPE. A module the database
does not know shows up as unresolved in `rollcall generate` warnings and in the readiness
report. Adding one is the most common contribution.

The guide below is the "Adding a module to the identifier database" section of
[CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-module-to-the-identifier-database), included on
the docs site so there is one copy. The conventions behind it are in
[Identifiers](identifiers.md).

<!-- repo-links: base=../CONTRIBUTING.md -->
{{#include ../CONTRIBUTING.md:identifier-db}}
<!-- repo-links: end -->
