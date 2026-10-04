# Vendored CSAF 2.0 and CVSS JSON schemas

These files are verbatim copies of the official CSAF 2.0 JSON schema and the FIRST CVSS
schemas it references. Never edit them. They are fetched and checked only by
`scripts/vendor-csaf-schema.sh`, which refuses any file whose SHA-256 does not match the
table below.

- CSAF: OASIS Common Security Advisory Framework Version 2.0, OASIS Standard
  (<https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html>). The schema is
  identical to `csaf_2.0/json_schema/csaf_json_schema.json` in
  <https://github.com/oasis-tcs/csaf> at commit `e0da5a98af185acce66e1ef4c2686c8f215703b2`.
- CVSS: the JSON schemas FIRST publishes for CVSS v2.0, v3.0 and v3.1.

| File | URL | SHA-256 |
|------|-----|---------|
| `csaf_json_schema.json` | <https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json> | `29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262` |
| `cvss-v2.0.json` | <https://www.first.org/cvss/cvss-v2.0.json> | `cd1a7c0815b7a47dc12fb7dded10622b96d562841f7bc6d2d8765c5d937a28f2` |
| `cvss-v3.0.json` | <https://www.first.org/cvss/cvss-v3.0.json> | `b2b587e5dfa6d9a4be89e25cb593df04f14e7ffbe8fe5b167ceee17b6097d919` |
| `cvss-v3.1.json` | <https://www.first.org/cvss/cvss-v3.1.json> | `77ff3df106e4588e2bb5c9cf0237f962c62d35c5002443c4bf7cc7ca16ee171f` |

The CSAF schema is JSON Schema draft 2020-12 and refers to the CVSS schemas by absolute
`$ref` (`https://www.first.org/cvss/cvss-v{2.0,3.0,3.1}.json`); rollcall registers them under
exactly those URIs and validates offline. The CVSS v2.0 and v3.0 schemas are draft-04 and
v3.1 is draft-07; each is read under the draft its own `$schema` names. The `rollcall-core`
unit test `vendored_csaf_schemas_match_recorded_sha256` re-checks these hashes.
