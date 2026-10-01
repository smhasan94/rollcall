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

## `blobs/` — hand-written blob test data

The files under `blobs/` are **hand-written** test inputs for the blob manifest
(`rollcall merge --blob-manifest`). None of them comes from a real build; the "binaries" are
a few bytes of text standing in for vendor files, so their SHA-256s can be pinned in tests.
`.gitattributes` marks them `-text` so checkout never changes a byte.

| File | What it is | Used by |
|------|------------|---------|
| `blobs.yaml` | A manifest with two entries: the fake SoftDevice (name, version and supplier left to the built-in recogniser, licence given) and `libphy.a` (every key given, `license` spelling). | `tests/blob.rs` (golden `tests/golden/blobs.cdx.json`), `rollcall-cli` `tests/merge.rs` |
| `s140_nrf52_7.3.0_softdevice.hex` | A fake Nordic SoftDevice: four Intel-HEX-shaped text lines, not a real image. Its SHA-256 (`sha256sum`) is pinned in `fake_softdevice_hash_matches_sha256sum`. | same |
| `libphy.a` | A fake Espressif PHY library: an `!<arch>` line and a note. | same |
| `bad-*.yaml` | Malformed manifests: missing `path`, unknown key, missing blob file, duplicate entry, truncated YAML, invalid licence, unrecognised file with no name. | `tests/blob.rs` (`malformed_manifest_and_missing_file_error_never_panic`) |
| `bad-kind.yaml` | A manifest whose `kind` is `bogus` (only `firmware` and `library` are valid). | `tests/blob.rs` (`malformed_manifest_and_missing_file_error_never_panic`, `manifest_kind_library_firmware_and_bogus`) |

## `identifiers-stub.yaml` — hand-written identifier database

A **hand-written** identifier database (`rollcall generate --identifier-db`), not real-build
output. It maps `cmsis` (a `git_tag` rule), `mbedtls` and `tf-psa-crypto` (`manual` rules
keyed by the revisions in `fixtures/zephyr/*/west-list.txt`), and deliberately leaves out the
fixtures' other modules (`cmsis_6`, `hal_nordic`, `mcuboot`).

| File | What it is | Used by |
|------|------------|---------|
| `identifiers-stub.yaml` | Three entries; the fixtures' other three modules are unmapped on purpose. | `tests/identify.rs` (every fixture module resolves or is reported unknown exactly once), `rollcall-cli` `tests/generate_zephyr.rs` (`--identifier-db`) |
