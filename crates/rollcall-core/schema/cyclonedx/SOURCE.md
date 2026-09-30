# Vendored CycloneDX 1.6 JSON schemas

These files are verbatim copies of the official CycloneDX JSON schemas. Never edit them. They
are fetched and checked only by `scripts/vendor-cyclonedx-schema.sh`, which refuses any file
whose SHA-256 does not match the table below.

- Repository: <https://github.com/CycloneDX/specification>
- Tag: `1.6.2`
- Commit: `e833d732337dd33aceb45ff1991f896796f1e5e7`

| File | URL | SHA-256 |
|------|-----|---------|
| `bom-1.6.schema.json` | <https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/bom-1.6.schema.json> | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| `spdx.schema.json` | <https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/spdx.schema.json> | `c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6` |
| `jsf-0.82.schema.json` | <https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/jsf-0.82.schema.json> | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

`bom-1.6.schema.json` refers to the other two by relative `$ref`; rollcall registers them under
`http://cyclonedx.org/schema/<file>` (the BOM schema's `$id` base) and validates offline. The
`rollcall-core` unit test `vendored_schemas_match_recorded_sha256` re-checks these hashes.
