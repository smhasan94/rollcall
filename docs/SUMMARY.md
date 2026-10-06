# Summary

<!-- The docs site's table of contents (book.toml, scripts/build-docs.sh). Every Markdown file
under docs/ is listed here exactly once; the test summary_lists_every_docs_page_exactly_once
checks it. -->

[Introduction](README.md)

# Getting started

- [Quickstart](quickstart.md)
- [Installing](installing.md)
- [Command-line reference](cli.md)
- [CI with the GitHub Action](ci.md)
- [FAQ: what the CRA and CISA ask of an SBOM](faq-cra-cisa.md)

# Ecosystems

- [Zephyr (sysbuild and MCUboot)](zephyr.md)
  - [Subsystems](subsystems.md)
  - [What west spdx leaves out](zephyr-gaps.md)
  - [Build fixtures](fixtures.md)
- [Cargo](cargo.md)
- [ESP-IDF](esp-idf.md)
- [PlatformIO](platformio.md)

# Identifiers

- [Identifier database](identifiers.md)
  - [Contributing a module](contributing-identifiers.md)

# Validation, VEX and scanning

- [Validate: schema and regulator profiles](validate.md)
- [VEX rules](vex-rules.md)
- [Scanning](scan.md)
- [Readiness report](report.md)
- [Diff and the pull-request comment](diff.md)
- [CSAF handoff to cra-clock](cra-clock.md)

# Crypto inventory

- [Cryptographic inventory (CBOM)](assay.md)
  - [Algorithm catalogue](catalogue.md)

# Project

- [Building from source](building.md)
- [Versioning, MSRV and releasing](versioning.md)
  - [Releasing rollcall](release.md)
- [Release notes v0.1.0](releases/v0.1.0.md)
- [Outreach: Zephyr working-group thread](outreach/zephyr-working-group-thread.md)
  - [Zephyr RFC #120474 comment](outreach/zephyr-rfc-120474-comment.md)
  - [Firmware SBOM talk](outreach/firmware-sbom-talk.md)
