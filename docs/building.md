# Building from source

How the repository is laid out, how to build and test it, and where the vendored schemas come
from. How to contribute is in [CONTRIBUTING.md](../CONTRIBUTING.md); the real-build fixtures
are in [Build fixtures](fixtures.md).

## Workspace layout

| Crate            | Purpose                                                        |
|------------------|----------------------------------------------------------------|
| `rollcall`       | The `rollcall` binary (`cargo install rollcall`).              |
| `rollcall-core`  | Component-graph model and ingestion.                           |
| `rollcall-assay` | Cryptographic inventory (CycloneDX CBOM), run as `rollcall assay`. |
| `rollcall-identifiers` | The identifier database (data only), versioned on its own (`db_version`). |

`python/` holds the `pip install rollcall` wrapper (see [Installing](installing.md)).

## Building

```sh
cargo build && cargo test
```

Golden files (`crates/rollcall-core/tests/golden/`, including the Zephyr ingestion goldens in
`golden/zephyr/`) are never edited by hand. Regenerate all of
them, and re-run the tests that compare against them, with one command:

```sh
scripts/regen-golden.sh
```

`scripts/smoke-scan.sh --install` (needs the network) downloads pinned, SHA-256-verified
releases of grype and osv-scanner into `.cache/tools/`, renders the fixtures in
`crates/rollcall-core/tests/data/`, and checks that both scanners load them without
warnings, see every component, and report zero findings for the minimal fixture. It prints a
PASS/FAIL table and runs in CI as the `smoke` job.

## CycloneDX schema

The official CycloneDX 1.6 JSON schemas (`bom-1.6.schema.json`, `spdx.schema.json`,
`jsf-0.82.schema.json`) are vendored verbatim in `crates/rollcall-core/schema/cyclonedx/`,
pinned to CycloneDX/specification tag `1.6.2` (commit
`e833d732337dd33aceb45ff1991f896796f1e5e7`), and compiled into the binary, so validation
never uses the network. `SOURCE.md` there records the URLs and SHA-256s. To re-fetch them,
run `scripts/vendor-cyclonedx-schema.sh`, which refuses any file whose SHA-256 does not match.

The CSAF 2.0 JSON schema (OASIS CSAF v2.0 OS, `csaf_json_schema.json`) and the FIRST CVSS
v2.0, v3.0 and v3.1 schemas it references are vendored the same way in
`crates/rollcall-core/schema/csaf/` (URLs and SHA-256s in its `SOURCE.md`), fetched and
checked by `scripts/vendor-csaf-schema.sh`.
