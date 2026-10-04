# `rollcall diff`

`rollcall diff` compares a build (the **head**, e.g. a pull request) with its base branch's
build (the **base**): which components were added, removed or changed, which vulnerability
findings are new, fixed or re-triaged, and whether the pull request may merge. Its Markdown is
the pull-request comment [`rollcall-action`](../action/README.md) posts; its JSON is
`rollcall-diff/1` (schema [`diff-schema.json`](diff-schema.json)).

```sh
rollcall diff \
  --sbom sbom.cdx.json --scan scan.json --report report.json \
  --base-sbom base/sbom.cdx.json --base-scan base/scan.json --base-report base/report.json \
  --fail-on high --format md -o comment.md
```

## Inputs

| Flag | Input |
|------|-------|
| `--sbom` | The head's CycloneDX 1.6 SBOM (`rollcall generate`). Required |
| `--scan` | The head's `rollcall scan --json` report (`rollcall-scan/1`). Without it findings are not compared |
| `--report` | The head's `rollcall report --format json` report (`rollcall-report/1`), for its summary and score |
| `--base-sbom` | The base's SBOM. Without it there is no base |
| `--base-scan` | The base's scan (needs `--base-sbom`) |
| `--base-report` | The base's readiness report (needs `--base-sbom`) |
| `--fail-on` | `critical`, `high`, `medium`, `low` or `unknown`: the gate's threshold. Without it nothing is gated |
| `--format` | `md` or `json`. Required |
| `-o` | Write here instead of stdout (atomically) |

Scans are read for their findings only; the scan's own VEX triage (`triage`: `suppressed`,
`affected`, `unresolved`) is what the diff and the gate use, so scan with `--vex`.

## Components

Each SBOM is read as the readiness report reads it: one row per node (the product, each image,
every component at any depth), identified by its **path** (names from the image down, without
versions) and its level (`product`, `image`, `component`). At each path and level, rows with
the same version and the same purl and CPE presence cancel out. When exactly one row is left on
each side it is **changed** (a version bump, or a purl or CPE gained or lost); otherwise what is
left in the head is **added** and what is left in the base **removed**. A path can hold several
rows, e.g. two versions of one crate.

## Findings

A head finding is the same as a base finding when both are on a component (or, for a package
the SBOM does not list, a package) of the same **name** and they share an id or alias. The
`bom-ref` and the version are not compared, so bumping a component that still has an old CVE
does not make that CVE new, and a finding reported under its GHSA id in one scan and its CVE id
in the other still matches. Head findings are matched most severe first, each to a base
finding at the same component path if there is one, else at any path; each base finding
matches at most once (so two copies of a component with the same CVE stay two findings).

- **New**: head findings with no match. Without a base, or with a base SBOM but no base scan,
  every head finding is new, and `base.reason` says why.
- **Fixed**: base findings with no match.
- **Triage changes**: matched findings whose triage changed (e.g. a new VEX rule suppressed
  one).

## Gate

With `--fail-on SEVERITY`, the gate counts the new findings that are open (triage
`affected` or `unresolved`, not `suppressed`) and at or above `SEVERITY`, `unknown` being the
lowest level. If any is counted, `gate.outcome` is `findings` and `rollcall diff` exits 1;
otherwise `clean` and exit 0. Findings below the threshold, and suppressed ones, are still
listed. A finding the base already had never counts, whatever its severity.

## Exit codes

| Exit | Meaning |
|------|---------|
| 0 | The diff was written; no new open finding at or above `--fail-on` (or no `--fail-on`) |
| 1 | The diff was written; a new open finding is at or above `--fail-on` |
| 64 | Usage error (no `--format`, `--base-scan` or `--base-report` without `--base-sbom`, an unknown severity) |
| 65 | An input is malformed: an SBOM that is not readable CycloneDX 1.6, a scan or report that is not JSON, has the wrong `schema`, or has a field of the wrong type |
| 66 | An input file is missing or unreadable |
| 70 | The diff cannot be serialised |
| 74 | The output cannot be written |

## Output

The Markdown starts with `## rollcall: PRODUCT VERSION`, a one-line verdict (✅ or ❌ with the
count of new open findings at or above the threshold), the head report's summary and its score
against the base's, then `### New findings`, `### Fixed findings`, `### Triage changes`,
`### Components` and `### Base`. Each table shows at most 50 rows and counts the rest; every
input value is escaped, so a component name cannot inject HTML or break a table.

The JSON (`rollcall-diff/1`) has every field always present (absent values are `null`):
`schema`, `product`, `base` (`present`, `product`, `reason`), `summary`, `score` (`head`,
`base`), `components` (`added`, `removed`, `changed`), `findings` (`scanned`, `head_total`,
`head_open`, `new`, `fixed`, `changed`) and `gate` (`fail_on`, `new_open_at_or_above`,
`outcome`).

## Determinism

The diff depends only on the inputs' contents: findings are sorted most severe first, then by
id, component and version; components by path, level and version. It carries no timestamp and
no file path, so the same inputs give byte-identical output. The goldens under
`crates/rollcall-core/tests/golden/diff/` are written only by `scripts/regen-golden.sh`.
