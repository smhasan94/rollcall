# Readiness report

`rollcall report` says how ready an SBOM is to hand to a customer or a regulator:

```sh
rollcall report product.cdx.json --format md \
  [--scan grype.json]... [--vex vex.json]... [--timestamp 2026-01-02T03:04:05Z] [-o report.md]
```

`--format md` writes GitHub-flavoured Markdown for people; `--format json` writes
`rollcall-report/1` JSON for machines, described by [`report-schema.json`](report-schema.json)
(JSON Schema draft 2020-12). Both start with the same plain-language summary.

## What the report holds

From a Zephyr sysbuild build, with grype's findings and a VEX document:

```sh
rollcall generate --zephyr build --sysbuild --west-list west-list.txt --identify -o product.cdx.json
rollcall report product.cdx.json --format md \
  --scan grype.json --vex vex.cdx.json --timestamp 2026-01-02T03:04:05Z -o report.md
```

It opens with a plain-language summary, then gives a score out of 100, coverage (the share
of the product, images and components with a PURL, CPE, hash and licence), one row per
component, unresolved modules with a paste-ready identifier-database stub each, open
findings by severity (`--scan`: grype or osv-scanner JSON, repeatable), VEX coverage
(`--vex`: any `rollcall vex` output format, repeatable), and the CycloneDX schema and
`cisa-2026`/`cra` profile results. The score is integer basis points rounded down, so only
a perfect SBOM scores 100: identified 25, hashed 15, licensed 15, validation 25, modules
resolved 10, vulnerabilities closed 10 (not assessed without `--scan`, and left out of the
total). [Score](#score) documents the formula and [Inputs](#inputs) every input. The output
is deterministic and leaves out the SBOM's serial number, timestamp and the input paths, so
two builds' reports diff cleanly. The exit code is 0 whenever a report is written, whatever
the score.

## Inputs

- **The SBOM** (positional): a CycloneDX 1.6 JSON document, e.g. from `rollcall generate`.
  Ingest Zephyr builds with `--identify` (or `--identifier-db`) so modules are resolved;
  otherwise every module is listed as unresolved.
- **`--scan FILE`** (repeatable): grype `-o json` or osv-scanner `--format json`, detected
  from the content. Findings are joined to components as `rollcall vex` joins them (purl,
  then CPE, then name and version) and merged across scanners. A finding for a package the
  SBOM does not list is counted as `not-in-sbom`. Severities are normalised
  case-insensitively: `low` and `negligible` are low, `medium` and `moderate` medium, `high`
  high, `critical` critical, anything else (including a CVSS number) unknown.

  `--scan` also reads `rollcall scan --json` output (`rollcall-scan/1`, detected by its
  `"schema"`). Each of its findings is read as one scanner finding on the SBOM component
  `rollcall scan` joined it to (its name, version and purl; a finding with no component
  keeps the reported package and stays `not-in-sbom`), with its id, aliases and fixed
  versions. Its severity is the scanner's own word for the scan's (highest) severity, so a
  report from `rollcall scan --json` output is identical to one from the same grype and
  osv-scanner output given raw. The scan's VEX triage (`triage`, `vex`) is **not** used:
  only the report's own `--vex` documents close findings, so the VEX coverage counts
  statements the report can see. When the scan suppressed findings, a warning says how
  many and asks for the same documents with `--vex`; a scanner the scan records as
  `failed` or `skipped` is warned about too, since its findings are missing.
- **`--vex FILE`** (repeatable): `rollcall vex` output in any format: `rollcall-vex/1`,
  OpenVEX, a CycloneDX VEX BOM, or an SBOM with embedded `vulnerabilities` (`--embed`),
  detected from the content. A statement matches a finding when one of its ids is the
  finding's id or alias and it names the finding's component by `bom-ref` (bare, or as a
  BOM-Link fragment) or purl. A BOM-Link into a different SBOM (another serial number) is a
  warning and is not applied; the BOM-Link's version is not compared (`rollcall vex
  --embed` increments the SBOM's version but keeps its serial number). A CycloneDX
  `affects[].ref` starting with `pkg:` is matched both as a `bom-ref` and as a purl, and an
  OpenVEX product may give only `identifiers.purl` instead of an `@id`. A finding is **closed** when at least one statement matches
  it and every matching statement is `not_affected` or `fixed` (CycloneDX `not_affected`,
  `false_positive`, `resolved`, `resolved_with_pedigree`); otherwise it is **open**.

The exit code is 0 whenever a report is written, whatever the score. A usage error (no
`--format`, a bad `--timestamp`) is exit 64, a malformed input 65, a missing input 66, a
report that cannot be serialised 70, and a report that cannot be written 74.

Inputs are named in the report (warnings, error messages) by file name only, never by the
path they were read from.

## Score

The score is out of 100, computed in integer basis points and rounded down, so only a
perfect result scores 100. *Items* are every node of the SBOM: the product, each image and
every component at any depth (Zephyr subsystems included).

| Category | Weight | Earned by |
|----------|-------:|-----------|
| Identified | 25 | share of items with a purl or a CPE |
| Hashed | 15 | share of items with at least one hash |
| Licensed | 15 | share of items with a licence |
| Validation | 25 | share of items with no `cisa-2026` or `cra` profile finding (a document-level finding counts against the product); **0** if the SBOM breaks the CycloneDX 1.6 schema |
| Modules resolved | 10 | share of Zephyr modules the identifier database resolved; full marks when there are none |
| Vulnerabilities | 10 | share of the findings in the SBOM that VEX closes; full marks when there are none |

Each category earns `weight × 10000 × numerator / denominator` units of 1/10000 point,
rounded down (the full weight when the denominator is 0). The score in basis points is the
sum over the assessed categories divided by their total weight, rounded down; the score is
that divided by 100, rounded down.

Without `--scan`, *Vulnerabilities* is **not assessed**: it is left out of the total weight
(the score is out of 90, scaled to 100), and the summary says that no scan was supplied.
CPE coverage is reported but not scored on its own.

For example, an SBOM with 4 items, 2 of them identified and licensed, none hashed, every
item with a profile finding, no modules, and 3 of 23 findings closed by VEX scores
`(125000 + 0 + 75000 + 0 + 100000 + 13043) / 100 = 3130` basis points: **31**.

## Unresolved modules

A component is a **Zephyr module** when its evidence comes from `west list`, or Kconfig
names it with a `CONFIG_ZEPHYR_<MODULE>_MODULE` symbol. A module the identifier database
did not resolve (no `identifier-db` evidence) is unresolved, and so is any other component
with neither a purl nor a CPE. Each entry carries a paste-ready identifier-database stub,
prefilled from the module's GitHub purl and version; the Markdown prints one stub per
module name.

## Determinism

The report depends only on the inputs' contents and `--timestamp`. Rows follow the model's
sorted order (product, each image, its components depth-first); unresolved entries,
findings and warnings are sorted. The SBOM's serial number and timestamp and the input
paths are not in the report (inputs are named by file name), so two builds' reports diff
cleanly: a dependency bump changes only that component's lines and the totals. Rows are
identified by path (names from the image down, without versions).

Schema-violation paths (`validation.schema.violations[].path`) are JSON pointers into the
SBOM, so they are positional: reordering the SBOM's arrays changes them. Profile findings
about a node carry its path instead of a pointer, and are sorted by node.

The Markdown uses LF line endings and escapes every value from the inputs, so a name cannot
break a table or start a link or raw HTML. The JSON is two-space-indented with keys in a
fixed order and every field present (`null` when absent).

## Schema versioning

`schema` is `rollcall-report/1`. Adding, removing or retyping a field is a new version
(`rollcall-report/2`) with a new schema file; `additionalProperties: false` throughout makes
any drift fail validation.
