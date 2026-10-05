# rollcall

rollcall turns the output of a firmware build into a software bill of materials (SBOM): a
CycloneDX 1.6 JSON file that lists everything inside your firmware image. Regulations such as
the EU Cyber Resilience Act (CRA) and the CISA minimum elements ask for one, and a useful SBOM
needs more than a list of names. rollcall gives each component a real package identifier (purl
and CPE) that vulnerability scanners can match, breaks the Zephyr kernel down into the
subsystems your build actually linked, merges bootloader, application and vendor blobs into one
product, writes VEX statements for vulnerabilities that cannot affect your build, and checks
the result against the CRA and CISA requirements. It is a command-line tool that runs on your
machine or in CI, plus a GitHub Action.

**Status:** v0.1. Zephyr (including sysbuild and MCUboot) comes first; Cargo, ESP-IDF and
PlatformIO builds are supported too.

## Install

Pick one. Each gives you a `rollcall` command.

- **Release binary** (Linux, macOS, Windows): download it from the
  [GitHub Releases](https://github.com/smhasan94/rollcall/releases) page and check it against
  `SHA256SUMS`.
- **cargo** (Rust 1.91 or newer): `cargo install rollcall --locked`
- **pip** (Python 3.9 or newer; downloads and verifies the release binary on first run):
  `pip install rollcall`

[Installing](https://github.com/smhasan94/rollcall/blob/main/docs/installing.md) has the
details: what each archive holds, checksums and attestations, and how the pip wrapper caches
the binary.

## Quick start

Start from a Zephyr sysbuild build directory prepared with `west spdx` and `west list`
([quickstart, step 2](https://github.com/smhasan94/rollcall/blob/main/docs/quickstart.md#2-prepare-a-build-directory)
shows how, and has an example build if you have none):

```sh
rollcall detect build                                  # prints: zephyr
rollcall generate build --identify -o sbom.cdx.json    # write the SBOM
rollcall validate --schema sbom.cdx.json               # check it against CycloneDX 1.6
rollcall validate --profile all sbom.cdx.json          # check it against the CRA and CISA rules
rollcall report --format md -o report.md sbom.cdx.json # a readiness report with a score
```

The [quickstart](https://github.com/smhasan94/rollcall/blob/main/docs/quickstart.md) walks
through each step and what the output means.

## What you get

| Command | What it does |
|---------|--------------|
| [`generate`](https://github.com/smhasan94/rollcall/blob/main/docs/cli.md#usage) | Build an SBOM from a [Zephyr](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr.md), [Cargo](https://github.com/smhasan94/rollcall/blob/main/docs/cargo.md), [ESP-IDF](https://github.com/smhasan94/rollcall/blob/main/docs/esp-idf.md) or [PlatformIO](https://github.com/smhasan94/rollcall/blob/main/docs/platformio.md) build |
| [`merge`](https://github.com/smhasan94/rollcall/blob/main/docs/cli.md#merging) | Combine bootloader, application and binary-blob SBOMs into one product |
| [`validate`](https://github.com/smhasan94/rollcall/blob/main/docs/validate.md) | Check an SBOM against the CycloneDX 1.6 schema and the CRA and CISA profiles |
| [`vex`](https://github.com/smhasan94/rollcall/blob/main/docs/vex-rules.md) | Mark vulnerabilities your build is not affected by, from rules and Kconfig evidence |
| [`scan`](https://github.com/smhasan94/rollcall/blob/main/docs/scan.md) | Run grype and osv-scanner on an SBOM and apply your VEX, with exit codes for CI |
| [`report`](https://github.com/smhasan94/rollcall/blob/main/docs/report.md) | Write a readiness report (Markdown or JSON) with a score out of 100 |
| [`diff`](https://github.com/smhasan94/rollcall/blob/main/docs/diff.md) | Compare a build with its base branch's: components and vulnerabilities |
| [`csaf`](https://github.com/smhasan94/rollcall/blob/main/docs/cra-clock.md#rollcall-csaf) | Export scan and VEX results as a CSAF 2.0 VEX advisory |
| [`detect`](https://github.com/smhasan94/rollcall/blob/main/docs/cli.md#auto-detect) | Say which ecosystem a build or project directory is |

Every flag and exit code is in the
[command-line reference](https://github.com/smhasan94/rollcall/blob/main/docs/cli.md).
The same input always gives a byte-identical SBOM.

## GitHub Action

The Action generates, validates and scans the SBOM, applies VEX, writes the report and, on a
pull request, posts a comment and fails the check on new findings at or above `fail-on`:

```yaml
steps:
  - uses: actions/checkout@v4
  - run: scripts/build.sh  # your build: west spdx --init, west build, west spdx, west list
  - uses: smhasan94/rollcall/action@v0.1.0
    with:
      build-dir: build
      rollcall-version: v0.1.0
      fail-on: high
```

The job needs `pull-requests: write` to post the comment and `actions: read` to fetch the
base branch's results.

[CI with the GitHub Action](https://github.com/smhasan94/rollcall/blob/main/docs/ci.md) has
the full workflow, and [action/README.md](https://github.com/smhasan94/rollcall/blob/main/action/README.md)
every input and output.

## Documentation

The guides are in [`docs/`](https://github.com/smhasan94/rollcall/tree/main/docs) and are
published as a site at <https://smhasan94.github.io/rollcall/>. Good places to start:

- [Quickstart](https://github.com/smhasan94/rollcall/blob/main/docs/quickstart.md)
- [Command-line reference](https://github.com/smhasan94/rollcall/blob/main/docs/cli.md)
- [FAQ: what the CRA and CISA ask of an SBOM](https://github.com/smhasan94/rollcall/blob/main/docs/faq-cra-cisa.md)
- [Identifier database](https://github.com/smhasan94/rollcall/blob/main/docs/identifiers.md)
- [VEX rules](https://github.com/smhasan94/rollcall/blob/main/docs/vex-rules.md)
- [Building from source](https://github.com/smhasan94/rollcall/blob/main/docs/building.md)
- [All guides](https://github.com/smhasan94/rollcall/blob/main/docs/README.md)

## Contributing, security and licence

- **Contributing:** see [CONTRIBUTING.md](https://github.com/smhasan94/rollcall/blob/main/CONTRIBUTING.md).
- **Security:** report vulnerabilities privately, as described in [SECURITY.md](https://github.com/smhasan94/rollcall/blob/main/SECURITY.md).
- **Licence:** Apache-2.0; see [LICENSE](https://github.com/smhasan94/rollcall/blob/main/LICENSE).
