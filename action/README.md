# rollcall-action

A GitHub Action that turns a firmware build into a CycloneDX 1.6 SBOM, OpenVEX statements, a
vulnerability scan and a readiness report, and, on pull requests, posts one comment comparing
the build with the base branch's and fails the check when the pull request adds findings at or
above a severity you choose.

For each build it runs:

1. `rollcall generate` (Zephyr, Cargo, ESP-IDF or PlatformIO, detected from the build
   directory by `rollcall detect`);
2. `rollcall validate --schema` (an invalid SBOM fails the job) and
   `rollcall validate --profile all` (CISA 2026 and CRA findings, recorded only);
3. grype (pinned, SHA-256-verified) on the SBOM, then `rollcall vex` with the starter rule pack
   and your rules, then `rollcall scan` triaged with that VEX;
4. `rollcall report` (Markdown and JSON);
5. `rollcall diff` against the base branch's artifact: the comment and the gate.

The SBOM, VEX, scan, report, validation findings, diff and comment are uploaded as one workflow
artifact.

## Quick start

Copy this into `.github/workflows/rollcall.yml` and set `build-dir` to your build:

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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false
      # ... build your firmware here (west build --sysbuild, cargo auditable build, ...) ...
      - uses: smhasan94/rollcall/action@main # pin to a release tag or commit SHA
        with:
          build-dir: build
          fail-on: high
```

The workflow must run on `push` to the base branch as well as on `pull_request`: the push runs
upload the artifact that pull requests are compared with.

## Inputs

| Input | Default | Meaning |
|-------|---------|---------|
| `build-dir` | (required) | The build (must not start with `-`; write `./-dir`). Zephyr: the build directory holding `build_info.yml` (a sysbuild top-level directory when it holds `domains.yaml`). Cargo: the package directory (`Cargo.toml`, needs `Cargo.lock`), or a directory holding captured `cargo-metadata.json`. ESP-IDF: the project directory (`sdkconfig`, built in `build/`). PlatformIO: the project directory (`platformio.ini`), after `pio run` |
| `ecosystem` | `auto` | `auto`, `zephyr`, `cargo`, `esp-idf` or `platformio`. `auto` runs `rollcall detect`, the detection `rollcall generate DIR` uses: `build_info.yml` means Zephyr; `Cargo.toml` (run `cargo metadata`) or `cargo-metadata.json` (read it) Cargo; `sdkconfig` with `build/project_description.json` ESP-IDF; `platformio.ini` PlatformIO. A directory that several match fails (exit 64) listing them, and one that none matches fails (exit 66); set `ecosystem` to choose |
| `identifiers-version` | `embedded` | The identifier database for Zephyr modules: `embedded` (built into rollcall), or a `db_version` such as `1.1.0`, downloaded from the release `identifiers-v<db_version>` and verified against its `SHA256SUMS` |
| `fail-on` | `high` | Fail the check when the pull request adds an open finding (not suppressed by VEX) at or above `critical`, `high`, `medium`, `low` or `unknown`; `none` never fails. Findings below the threshold are still listed in the comment |
| `gate-on-push` | `false` | Also enforce the gate outside pull requests (e.g. a push to the base branch, where there is no base and every open finding counts as new). By default the outcome is only noted there |
| `vex-rules` | | Your VEX rules files, one path per line (see `docs/vex-rules.md`) |
| `starter-rules` | `true` | Apply rollcall's starter VEX rule pack first |
| `west-list` | `BUILD-DIR/west-list.txt` if present | Zephyr: `west list -f "{name} {path} {revision} {url}"` output |
| `sysbuild` | `auto` | Zephyr: `auto` (a sysbuild when `domains.yaml` is present), `true` or `false` |
| `product` | | Name the product `NAME[@VERSION]` (any ecosystem) |
| `elf` | | Cargo: the binary built with `cargo auditable`, so only the crates it links are listed |
| `target` | | Cargo package directory: the target triple to resolve crates for |
| `env` | | PlatformIO: the environment to describe (default: the one `default_envs` names, else the project's only one) |
| `pio-core` | | PlatformIO: the core directory the build used, read for the installed platform and framework versions (`rollcall generate --pio-core`). After `pio run` on the runner that is `~/.platformio` (a leading `~/` is the runner's home). Without it, the versions come from exact pins in `platformio.ini`, and are unknown (a warning) for a range |
| `scanner` | `grype` | `grype`, or `auto`: grype and osv-scanner (both pinned) |
| `rollcall-version` | `source` | `source`: build rollcall from the action's own checkout (cached per action repository and ref); or a release tag such as `v0.1.0`: download `rollcall-<tag>-<os>-<arch>.tar.gz` (`darwin-universal` on both Macs) and verify it against the release's `SHA256SUMS` |
| `artifact-name` | `rollcall` | The workflow artifact's name. The base is the base branch's artifact of the same name, and the comment is keyed on it, so give each job its own |
| `comment` | `true` | Post (or update) the pull-request comment |
| `github-token` | `${{ github.token }}` | Token for the comment and the base artifact |
| `timestamp` | now | A fixed RFC 3339 timestamp for the SBOM, VEX and report (reproducible output) |
| `out-dir` | `.rollcall-action` | Where every output file is written |

## Outputs

| Output | Meaning |
|--------|---------|
| `ecosystem` | The ecosystem described: `zephyr`, `cargo`, `esp-idf` or `platformio` |
| `sbom` | Path of the CycloneDX 1.6 SBOM (`sbom.cdx.json`) |
| `vex` | Path of the OpenVEX document (`vex.openvex.json`) |
| `scan` | Path of the `rollcall-scan/1` report, triaged with that VEX (`scan.json`) |
| `report` | Path of the readiness report (`report.md`; `report.json` beside it) |
| `comment` | Path of the pull-request comment (`comment.md`) |
| `score` | The readiness score out of 100 |
| `new-findings` | How many findings are new against the base |
| `gate` | `clean`, or `findings` when a new open finding is at or above `fail-on` |

## Exit codes

The generate step exits with `rollcall`'s own exit code when `rollcall detect` or
`rollcall generate` fails, so a failed job says why: 64 for a usage error (a directory several
ecosystems match, a flag of another ecosystem, an unknown `env`), 65 for a malformed input, 66
for a missing one (a directory no ecosystem matches, or not the one `ecosystem` names). Other
failures of the step exit 1, with an error annotation naming the command.

## The comment and the gate

On a pull request the action looks up this workflow's latest completed `push` run on the base
branch (the same workflow file, up to five runs back), downloads its artifact named
`artifact-name`, and runs `rollcall diff` (see [`docs/diff.md`](../docs/diff.md)):

- **Components** are compared by path (names from the image down): a version bump is one
  changed row.
- **Findings** are matched by component name and any shared vulnerability id or alias, so a
  bumped component that still has an old CVE does not report it as new. New, fixed and
  re-triaged findings are listed, most severe first (50 rows per table; the rest are in the
  artifact).
- **The gate** counts new findings that VEX did not suppress and that are at or above
  `fail-on`. Any such finding fails the job, after the comment is posted and the artifact
  uploaded, with an error naming the vulnerabilities.

**No base artifact means every open finding is new.** That happens on the first pull request
before the workflow has run on the base branch, when the base run's artifact has expired, or
when `artifact-name` differs. The comment says so.

**On a push** (or any event other than `pull_request`) there is no base either, so every open
finding of the build would count as new, and the base branch would go red right after a green
pull request merged. The gate is therefore not enforced there by default: the step notes the
outcome and passes, and the SBOM, diff and artifact are produced as usual. Set
`gate-on-push: true` to fail pushes on every open finding at or above `fail-on`.

The comment begins with a hidden marker, `<!-- rollcall-action:ARTIFACT-NAME -->`. A re-run
finds the comment it posted before and updates it in place instead of adding another. "Its"
comment is the first that starts with the marker and is authored by the token's own user,
which the action asks the API (`/user`) for; the default workflow token cannot ask, and then
the comment must be a bot's (`github-actions[bot]`). So with the default token or a personal
access token a re-run updates the comment, and someone else's comment that quotes the marker
is never touched.

**Threat model.** On a pull request, your own build steps run the pull request's code before
the action does, so a collaborator who can push a branch can change the build, the build
directory or the workflow itself. The gate is a quality gate against accidentally adding a
vulnerable dependency, not a defence against a malicious collaborator; enforce that with
branch protection and review.

**Pull requests from forks** get a read-only token: the comment cannot be posted, so the
action prints a notice and carries on, and the gate still applies. The comment is also in the
job summary and the artifact. The action never uses `pull_request_target`.

## Permissions

| Permission | Why |
|------------|-----|
| `contents: read` | Check out the repository |
| `pull-requests: write` | Post and update the comment |
| `actions: read` | List the base branch's workflow runs and download their artifact |

## Runner prerequisites

GitHub's hosted Ubuntu and macOS runners have everything. A self-hosted runner needs `bash`,
`curl`, `tar`, `jq` and `gh` on `PATH`, plus `rustup` and `cargo` for
`rollcall-version: source`. grype (and, with `scanner: auto`, osv-scanner) is downloaded and
verified by the action.

## rollcall version

With `rollcall-version: source` (the default) the action builds rollcall from the checkout the
action itself came from, so `uses: smhasan94/rollcall/action@<sha>` runs exactly that commit's
rollcall. The Rust toolchain comes from `rust-toolchain.toml` (rustup installs it on GitHub's
runners); the build is cached under a key made of the runner OS and the action's own repository
and ref (never your repository's files), with older builds seeding a new key. With a release tag the action downloads that release's binary
instead and verifies it against the release's `SHA256SUMS`.

## Running the scripts locally

Every step is a script under [`scripts/`](scripts/) that reads its inputs from `RC_*`
environment variables, so a step can be run by hand, e.g.

```sh
ROLLCALL_BIN=target/debug/rollcall RC_BUILD_DIR=fixtures/zephyr/tls RC_OUT_DIR=/tmp/out \
  action/scripts/pipeline.sh
RC_OUT_DIR=/tmp/out ROLLCALL_BIN=target/debug/rollcall RC_FAIL_ON=high action/scripts/diff.sh
```

(grype and jq must be on `PATH`). `crates/rollcall/tests/action.rs` runs them this way with
a fake grype and a fake `gh`.
