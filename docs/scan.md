# `rollcall scan`: normalised findings, VEX triage and exit codes

`rollcall scan SBOM` runs the vulnerability scanners installed on `PATH` (grype and/or
osv-scanner) on a CycloneDX 1.6 SBOM and prints one normalised list of findings, triaged with
any VEX documents you give it. The exit code is meant for a CI gate.

```sh
rollcall scan product.cdx.json
rollcall scan product.cdx.json --vex product.openvex.json --fail-on high
rollcall scan product.cdx.json --scanner grype --json > scan.json
rollcall scan product.cdx.json --db-path .cache/scan-db --fail-on critical --fail-on-unresolved
```

| Flag | Meaning |
|------|---------|
| `--vex FILE` | A VEX document (repeatable): OpenVEX, CycloneDX VEX (a standalone VEX BOM, or an SBOM with embedded `vulnerabilities`, e.g. from `rollcall vex --embed`) or `rollcall-vex/1` (`rollcall vex`'s own report). The format is detected from the content. |
| `--scanner grype\|osv\|auto` | Which scanners to run. `auto` (the default) runs every one found on `PATH` and skips, with a warning, one that is not installed. Naming one makes it required. |
| `--db-path DIR` | Scan offline with pre-downloaded databases (see [Offline scans](#offline-scans)). |
| `--fail-on SEVERITY` | Exit 1 if an open finding is at or above `critical`, `high`, `medium`, `low` or `unknown`. Without it, findings never cause exit 1. |
| `--fail-on-unresolved` | Exit 2 if a finding is unresolved. |
| `--json` | Print the `rollcall-scan/1` JSON report instead of the table. |

Warnings (a skipped scanner, an unusable VEX statement, conflicting claims) and scanner
errors go to stderr as `rollcall scan: …`. When open findings have an unknown severity,
stderr also says how many: `rollcall scan: N open finding(s) have unknown severity; only
--fail-on unknown fails on them`.

## What a finding is

Each scanner's output is parsed (grype `-o json`, osv-scanner `--format json`) and joined to
the SBOM's components exactly as `rollcall vex` does: by purl, else by CPE, else by name and
version. Reports of one vulnerability on one component are merged, across scanners and across
advisory ids that alias each other (a RUSTSEC and a GHSA advisory naming one CVE). Each
finding has:

- **id**: the lowest `CVE-` id among the merged ids and aliases, else the lowest id. The
  others are its **aliases**.
- **component**: the SBOM component's `bom-ref`, name, version and purl; `null` when the
  scanner reported a package the SBOM does not list.
- **severity**: the highest any scanner gave, normalised to five levels (lowest first):

  | Severity | Scanner words |
  |----------|---------------|
  | `unknown` | anything else, or none |
  | `low` | `low`, `negligible` |
  | `medium` | `medium`, `moderate` |
  | `high` | `high` |
  | `critical` | `critical` |

  `unknown` is the lowest level: it fails only `--fail-on unknown`.
- **fixed_versions** from every scanner, and **sources**: each scanner report merged into it
  (scanner, the id it used, its severity as written).

So when grype and osv-scanner both report a vulnerability on a component, they produce the
same id and component, and `rollcall scan` shows one finding with both sources.

## VEX triage

A claim applies to a finding when it names the finding's id or one of its aliases, and the
finding's component: by `bom-ref`, by a BOM-Link into this SBOM
(`urn:cdx:<serial>/<version>#<bom-ref>`), or by purl (as the SBOM spells it, or the same purl
in canonical form).

- **OpenVEX**: a product's `subcomponents`, when it has any, are what the claim is about; a
  warning says so when the product itself is not this SBOM's `metadata.component` (by
  `bom-ref`, BOM-Link or purl). `identifiers.cpe23`/`cpe22` are ignored, with a warning.
  Statements form a timeline: a statement's time is its `last_updated`, else its
  `timestamp`, else the document's `timestamp`, and for each vulnerability and product only
  a document's latest statements count. So `under_investigation` followed by a later
  `not_affected` is simply suppressed. Statements with the same time can still conflict.
- **CycloneDX**: a plain `affects[].ref` names a component of the VEX document itself, so
  when the document has a `serialNumber` the ref is read as a BOM-Link into it (its
  `version`, default 1). It applies to the scanned SBOM only when the serial numbers match:
  an SBOM with embedded `vulnerabilities` applies to itself, while a standalone VEX BOM's
  plain refs (into its own, different serial number) are not applied, with a warning. A
  document without a `serialNumber` is taken to describe the scanned SBOM.
  `affects[].versions` are ignored, with a warning: the claim applies to the referenced
  component as a whole.

| Claims | Triage | Counts toward |
|--------|--------|---------------|
| `not_affected`, `fixed` (CycloneDX `resolved`, `resolved_with_pedigree`) or `false_positive` | **suppressed** | nothing |
| `affected` (CycloneDX `exploitable`) | **affected** | `--fail-on` |
| `under_investigation` (CycloneDX `in_triage`), no claim, or claims that disagree on the status | **unresolved** | `--fail-on`, `--fail-on-unresolved` |

Suppressed findings are **shown, not hidden**: they keep their row in the table and their
entry in the JSON, with `triage: suppressed` and the claims that suppressed them, and they
never count toward `--fail-on` or `--fail-on-unresolved`. Without `--vex` every finding is
unresolved. Claims that disagree on the status leave the finding unresolved with a warning
naming both documents. Any two different statuses disagree, even two that would each
suppress the finding (`not_affected` and `fixed`). Claims from different documents can
always disagree, whatever their times; within one OpenVEX document only statements with
the same time can. A BOM-Link into a different SBOM (another
serial number) is not applied, with a warning; one into another version of this SBOM is
applied, with a warning.

## Output

The table has one row per finding, highest severity first, then a summary:

```
SEVERITY  ID              COMPONENT  VERSION  FIXED  TRIAGE      VEX  SOURCES
high      CVE-2020-36464  heapless   0.5.0    0.6.1  unresolved  -    grype,osv-scanner

1 finding(s): 0 suppressed, 0 affected, 1 unresolved; open: 0 critical, 1 high, 0 medium, 0 low, 0 unknown
scanners: grype 0.119.0 (ok), osv-scanner 2.6.0 (ok)
```

`--json` prints `rollcall-scan/1`: `schema`, `sbom` (`serialNumber`, `version`), `scanners`
(`name`, `version`, `status`: `ok`, `skipped` or `failed`, `offline`), `findings` (`id`,
`aliases`, `component`, `package`, `severity`, `fixed_versions`, `sources`, `triage`, `vex`),
`summary` (`total`, `suppressed`, `affected`, `unresolved`, `open_by_severity`) and
`warnings`. The schema is documented in the `rollcall_core::scan` module docs. Findings are
sorted by severity (highest first), then id, then `bom-ref`; the report has no timestamp and
no host paths (a VEX document is cited by its file name), so two runs with the same scanner
databases diff cleanly. On exit 3 the report is still printed, with what the other scanners
found.

`rollcall report --scan` reads this JSON too (see [report.md](report.md)); it closes
findings only with its own `--vex`, not with the scan's triage.

## Exit codes

| Exit | Meaning |
|------|---------|
| 0 | clean: no gate failed |
| 1 | an open (not suppressed) finding at or above `--fail-on` |
| 2 | an unresolved finding, with `--fail-on-unresolved` |
| 3 | a scanner is missing (named with `--scanner`, or none found with `auto`) or failed, or its output cannot be read |
| 64 | usage error (no SBOM, an unknown flag or value) |
| 65 | the SBOM or a `--vex` document is malformed |
| 66 | the SBOM, a `--vex` document or the `--db-path` directory is missing or unreadable |
| 70 | internal error: the JSON report cannot be serialised |
| 74 | the report cannot be written, or the temporary directory for the scanners' SBOM copy cannot be created |

When several apply, 3 wins over 1, and 1 over 2.

## Scanner configuration

grype is run with `-c` pointing at an empty configuration file that `rollcall scan` writes
next to its copy of the SBOM, so grype reads none of the caller's configuration files
(`.grype.yaml` or `.grype/config.yaml` in the working directory, `~/.grype.yaml`, …). An
`ignore:` rule there would drop findings from grype's output, hiding them instead of
showing them suppressed; a `fail-on-severity` would make grype exit 1, which would look
like a scanner failure. Use `--vex` to triage findings and `--fail-on` to gate.
`GRYPE_*` environment variables still apply (see [Offline scans](#offline-scans)).

## Offline scans

With `--db-path DIR`, nothing is fetched:

- grype runs with `GRYPE_DB_CACHE_DIR=DIR/grype` and `GRYPE_DB_AUTO_UPDATE=false`.
- osv-scanner runs with `--offline --offline-vulnerabilities` and
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=DIR/osv-scanner`.

Download the databases while you still have the network:

```sh
GRYPE_DB_CACHE_DIR=DIR/grype grype db update
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=DIR/osv-scanner \
  osv-scanner scan source -L product.cdx.json --offline-vulnerabilities \
  --download-offline-databases --format json > /dev/null
```

osv-scanner downloads one database per ecosystem the SBOM's packages are in, so prime it
with the SBOMs you will scan. Observed with osv-scanner 2.6.0: offline, an SBOM with a
package in an ecosystem whose database was not downloaded fails (exit 127, `no offline version
of the OSV database is available`), which `rollcall scan` reports as exit 3; an SBOM with no
package osv-scanner can identify exits 128 with no output, which `rollcall scan` treats as no
findings, with a warning.

**grype's database age check stays on.** grype refuses a database built more than 120 hours
ago (`max-allowed-built-age`), so a stale `--db-path` fails the scan (exit 3) rather than
silently reporting against old data. Refresh the database, or relax the check with grype's
own environment variables, which `rollcall scan` passes through:
`GRYPE_DB_MAX_ALLOWED_BUILT_AGE=240h` (a longer limit) or `GRYPE_DB_VALIDATE_AGE=false` (no
limit).

CI runs this in the `scan` job: it installs the pinned grype 0.119.0 and osv-scanner 2.6.0
(SHA-256-verified), runs the scanner integration tests, primes the databases, then blocks the
network with `iptables`/`ip6tables` (checked with `curl`) and scans with `--db-path`.

## Known scanner behaviour

grype (verified with 0.119.0) silently ignores CycloneDX components of type
`operating-system`. It treats them as distro information, not packages, so it does not scan
them for vulnerabilities. rollcall labels components accurately anyway: how an RTOS kernel
such as Zephyr is typed is decided at ingestion. osv-scanner is unaffected.

## Known limitations

- **Zephyr SBOMs have no grype/osv-scanner overlap today.** osv-scanner maps `pkg:github`
  purls to the "GitHub Actions" ecosystem and does not read CPEs, so it finds nothing for
  Zephyr modules; grype matches them by CPE, but skips components of type
  `operating-system`, such as `zephyr` itself. The overlap is tested on a Cargo package
  (`heapless` 0.5.0, CVE-2020-36464).
- The scanners are run as found on `PATH`; there is no timeout, and no option to download
  databases or to read VEX embedded in the scanned SBOM itself (pass it with `--vex`).
