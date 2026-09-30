# Hand-written model fixtures

The `*.model.json` files here are **hand-written internal-model fixtures** in rollcall's
`rollcall-model/1` JSON form. They are not artefacts of a real firmware build, which is why
they live here and not under the workspace's `fixtures/` directory (reserved for real-build
output produced by `scripts/regen-fixtures.sh`).

| File | What it is | Used by |
|------|------------|---------|
| `minimal.model.json` | `sensor-node` 1.0.0: one application image (`sensor-app`) with `littlefs` 2.9.0 and `tinycrypt` 0.2.8, every node under `components[]` carrying a `pkg:generic` purl. It has no known-vulnerable components, so scanners should report **zero findings**. | `tests/cyclonedx.rs` (schema validation, golden `tests/golden/minimal.cdx.json`), `rollcall-cli` `tests/generate.rs` and `tests/validate.rs`, and `scripts/smoke-scan.sh` (grype and osv-scanner must load it without warnings and find nothing) |
| `widget.model.json` | A verbatim copy of `tests/golden/base.json`: three images (bootloader, application, blob), nested subcomponents, evidence from several sources, and dependency edges. | Same tests (golden `tests/golden/widget.cdx.json`) and `scripts/smoke-scan.sh` (loaded without warnings; findings are not asserted) |

Every file here must parse with `Product::from_json`. Every `*.model.json` is rendered and
schema-validated by `every_fixture_output_validates_against_schema_1_6`, so adding a fixture
here adds it to that test automatically.
