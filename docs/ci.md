# CI with the GitHub Action

The rollcall Action runs the whole pipeline on every push and pull request: it generates the
SBOM, validates it, scans it with grype, applies VEX, writes the readiness report and, on a
pull request, posts one comment comparing the build with the base branch's and fails the check
when the pull request adds a vulnerability at or above the severity you choose. Its inputs,
outputs and permissions are documented in full in
[action/README.md](../action/README.md); this page is the recipe.

[rollcall-example-zephyr](https://github.com/smhasan94/rollcall-example-zephyr) is a complete
repository wired up this way: a Zephyr sysbuild application with MCUboot, built in CI, with a
readiness badge in its README.
In this repository, `.github/workflows/rollcall-example.yml` runs the Action on rollcall's own
fixtures.

## The workflow

Copy this into `.github/workflows/rollcall.yml`. The build steps are yours; the Action only
needs the build directory, prepared as in the [quickstart](quickstart.md#2-prepare-a-build-directory)
(`west spdx --init` before the build, `west spdx` and `west list` after it).

```yaml
name: rollcall

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read        # check out the repository
  pull-requests: write  # post and update the comment
  actions: read         # download the base branch's artifact

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      # Your build: west spdx --init, west build --sysbuild, west spdx, west list
      # (rollcall-example-zephyr's scripts/build.sh does exactly this).
      - run: scripts/build.sh
      - uses: smhasan94/rollcall/action@v0.1.0
        id: rollcall
        with:
          build-dir: build
          rollcall-version: v0.1.0
          fail-on: high
```

- `uses: smhasan94/rollcall/action@v0.1.0` pins the Action to the release, and
  `rollcall-version: v0.1.0` makes it download that release's `rollcall` binary (checked
  against the release's `SHA256SUMS`) instead of compiling it. For a stronger pin, use the
  tag's commit SHA in `uses:`.
- `build-dir` is the sysbuild top-level directory: the Action sees `domains.yaml` and makes one
  product of MCUboot and the application, and reads `west-list.txt` there.
- The workflow must run on `push` to `main` as well as on `pull_request`: the push runs upload
  the artifact each pull request is compared with.

## What you get

- The job summary and the pull-request comment: the readiness score, what changed between the
  base and the pull request (components added, removed or bumped; vulnerabilities new, fixed
  or re-triaged), and the gate's verdict. See [Diff and the pull-request comment](diff.md).
- An artifact named `rollcall` with `sbom.cdx.json`, `vex.openvex.json`, `scan.json`,
  `report.md`, `report.json`, `validate.json`, `diff.json` and `comment.md`.
- Outputs for later steps: `steps.rollcall.outputs.score`, `sbom`, `report`, `gate` and
  `new-findings`.

## Tuning

| You want | Set |
|----------|-----|
| Fail only on critical findings | `fail-on: critical` |
| Report findings but never fail | `fail-on: none` |
| Also fail pushes to `main` on every open finding | `gate-on-push: true` |
| Your own VEX rules, after the starter pack | `vex-rules: vex/rules.yml` (see [VEX rules](vex-rules.md)) |
| Name and version the product | `product: my-device@1.4.0` |
| Reproducible SBOM bytes | `timestamp: 2026-01-02T03:04:05Z` |
| Several builds in one repository | one job per build, each with its own `artifact-name` |

For a Cargo, ESP-IDF or PlatformIO build, point `build-dir` at the project; `ecosystem: auto`
(the default) tells them apart.

## A readiness badge

The `score` output can feed a [shields.io endpoint badge](https://shields.io/badges/endpoint-badge)
without any external service: a second job writes a small JSON file to an orphan `badges`
branch, and the README shows

```markdown
![CRA readiness](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FOWNER%2FREPO%2Fbadges%2Frollcall.json)
```

rollcall-example-zephyr's `.github/workflows/rollcall.yml` (its `badge` job) and
`scripts/badge.sh` do this; copy them. The badge job needs `contents: write` and runs on pushes
to `main` only, so pull requests from forks never get a write token.

## Without the Action

Any CI can run the same steps with the `rollcall` binary from the [quickstart](quickstart.md):

```sh
rollcall generate build --identify -o sbom.cdx.json
rollcall validate --schema sbom.cdx.json
rollcall report --format md -o report.md sbom.cdx.json
```

`rollcall validate` exits 1 on an invalid SBOM, so the job fails. For the scan, VEX and
pull-request diff, see [Scanning](scan.md), [VEX rules](vex-rules.md) and
[Diff](diff.md).

`rollcall diff` can also be run on its own:

```sh
rollcall diff --sbom sbom.cdx.json --scan scan.json --report report.json \
  --base-sbom base/sbom.cdx.json --base-scan base/scan.json --base-report base/report.json \
  --fail-on high --format md -o comment.md
```
