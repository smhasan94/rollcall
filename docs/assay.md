# Cryptographic inventory (CBOM)

`rollcall assay` writes a build's cryptographic inventory: the algorithms, protocols,
certificates and keys it contains, each with the evidence that it is there and how sure
rollcall is. The output is a CycloneDX 1.6 **CBOM** (a cryptography bill of materials: a BOM
whose `cryptographic-asset` components carry `cryptoProperties`) or a Markdown table.

```sh
rollcall assay --build build --product widget@1.2.3 -o widget.cbom.json
rollcall assay --model product.model.json --format md -o crypto.md
```

**This version has no detectors.** `rollcall assay --source/--build/--elf` checks its inputs and
writes a valid but empty CBOM (see [Inputs](#inputs)). What is in place is the model, the
CycloneDX writer and reader, and the Markdown summary, which a model written by hand (or by
another tool, in the `rollcall-model/1` JSON form) can already use through `--model`.

## Flags

| Flag | Meaning |
|------|---------|
| `--model FILE` | Render a model (`rollcall-model/1` JSON) whose `cryptographic-asset` components carry crypto assets. Conflicts with the four flags below |
| `--source DIR` | The source tree to take the inventory of |
| `--build DIR` | The build directory |
| `--elf FILE` | The linked ELF image |
| `--product NAME[@VERSION]` | The product the inventory is of; required with `--source`, `--build` and `--elf` |
| `--format cyclonedx\|md` | A CycloneDX 1.6 CBOM (the default) or a Markdown summary |
| `--timestamp RFC3339` | The document timestamp (default: now), so output can be byte-identical |
| `--serial-number URN` | The CBOM's serial number (default: derived from the model's content) |
| `-o, --output FILE` | Write here instead of stdout |

At least one of `--model`, `--source`, `--build` and `--elf` is required. Exit codes: 0 when
the output is written, 64 for a usage error (no input, `--source`/`--build`/`--elf` without
`--product`, `--model` with any of them), 65 for a malformed `--model`, 66 for a missing input
or one of the wrong kind (a `--build` that is a file, an `--elf` that is a directory), 74 when
the output cannot be written.

## Inputs

With `--source`, `--build` and/or `--elf`, `assay` checks each exists and is a directory
(`--source`, `--build`) or a file (`--elf`), then runs its detectors. In this version there
are none, so the CBOM is the product `--product` names with no components, and its
`metadata.properties` say so:

```json
{"name": "rollcall:assay:detectors", "value": "none"}
```

and stderr has one note:

```text
rollcall assay: note: no cryptographic-asset detectors in this version; the inventory is empty
```

so an empty inventory is never mistaken for a build without cryptography. The exit code is 0.

With `--model`, the model is written as it is, with no `rollcall:assay:detectors` property.

## The model

A crypto asset is a component of kind `cryptographic-asset` with a `crypto` object: the
CycloneDX `cryptoProperties` (`assetType`, the one property block that matches it, and an
optional `oid`) plus an `evidence` array. An asset sits under the component that implements it
(`AES-128-GCM` under `mbedtls`); a protocol, certificate or key that belongs to the image sits
under the image.

| `assetType` | Block | Fields rollcall models |
|-------------|-------|------------------------|
| `algorithm` | `algorithmProperties` | `primitive`, `parameterSetIdentifier`, `executionEnvironment`, `implementationPlatform`, `mode`, `cryptoFunctions`, `classicalSecurityLevel`, `nistQuantumSecurityLevel` |
| `protocol` | `protocolProperties` | `type`, `version` |
| `certificate` | `certificateProperties` | `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter` (RFC 3339), `certificateFormat`, `certificateExtension` |
| `related-crypto-material` | `relatedCryptoMaterialProperties` | `type`, `id`, `state`, `size`, `format` |

Every field is optional and is left out, never written as `null`, when absent; a
`nistQuantumSecurityLevel` of 0 is written as `0`. Not modelled: `curve`, `padding`,
`certificationLevel`, `cipherSuites`, `ikev2TransformTypes`, the `*Ref` links and the
related material's dates and `securedBy`. Key material (`value`) is never modelled: rollcall
does not carry secrets.

Each evidence entry has a **locator**, a **detector**, a **confidence** and a one-line
**reason** (at most 200 characters):

```json
{
  "locator": {
    "kind": "kconfig-symbol",
    "location": "build/zephyr/.config",
    "line": 812,
    "symbol": "CONFIG_MBEDTLS_CIPHER_MODE_GCM"
  },
  "detector": "kconfig",
  "confidence": "high",
  "reason": "CONFIG_MBEDTLS_CIPHER_MODE_GCM=y builds GCM into mbedtls"
}
```

An asset needs at least one entry; its confidence is the highest of its entries.

## Evidence and confidence in CycloneDX

| Model | CycloneDX 1.6 |
|-------|---------------|
| `source-line` locator (`src/x.c:42`) | method technique `source-code-analysis` |
| `elf-symbol` locator (`zephyr.elf mbedtls_gcm_setkey`) | method technique `binary-analysis` |
| `kconfig-symbol` locator (`zephyr/.config:812 CONFIG_…`) | method technique `manifest-analysis` |
| `cargo-feature` locator (`Cargo.toml chacha20poly1305[default]`) | method technique `manifest-analysis` |
| confidence `high` / `medium` / `low` | method `confidence` 0.9 / 0.6 / 0.3 |
| each evidence entry | one `evidence.identity[]` `name` method (`value` = the locator as text) and one `evidence.occurrences[]` entry (`location`, `line`, `symbol`, `additionalContext` = the reason) |
| each detector | property `rollcall:evidence-source` |
| each evidence entry, whole | property `rollcall:crypto-evidence` (compact JSON), from which the reader rebuilds the asset losslessly |

The word (`high`, `medium`, `low`) is the source of truth; the number is what CycloneDX
holds. A CBOM another tool wrote (with `cryptoProperties` but no `rollcall:crypto-evidence`
properties) is read with its assets as plain `cryptographic-asset` components, each with a
warning.

## Example

The repository's hand-written CBOM model
[`sensor-node.cbom.model.json`](../crates/rollcall-core/tests/data/cbom/sensor-node.cbom.model.json)
has every asset type, locator kind and confidence level:

```sh
rollcall assay --model crates/rollcall-core/tests/data/cbom/sensor-node.cbom.model.json \
    --timestamp 2026-01-02T03:04:05Z -o sensor-node.cbom.json
rollcall validate --schema sensor-node.cbom.json
rollcall assay --model crates/rollcall-core/tests/data/cbom/sensor-node.cbom.model.json \
    --format md --timestamp 2026-01-02T03:04:05Z
```

The outputs are the goldens
[`sensor-node.cbom.json`](../crates/rollcall-core/tests/golden/cbom/sensor-node.cbom.json) and
[`sensor-node.cbom.md`](../crates/rollcall-core/tests/golden/cbom/sensor-node.cbom.md). The
Markdown has one row per asset and evidence entry:

| Column | What it holds |
|--------|---------------|
| Asset | The component's name (and version) |
| Type | The `assetType` |
| Details | The asset's properties, e.g. `ae · 128 · gcm · … · NIST 1 · OID 2.16.840.1.101.3.4.1.6` |
| In | Where it sits: the image and component path, e.g. `sensor-app / mbedtls@3.6.0` |
| Evidence | The locator, e.g. `build/zephyr/.config:812 CONFIG_MBEDTLS_CIPHER_MODE_GCM` |
| Confidence | `high`, `medium` or `low` |
| Reason | The one-line reason |

## Validating a CBOM

`rollcall validate --schema` checks a CBOM against the CycloneDX 1.6 schema like any other
document. The `--profile cisa-2026` and `--profile cra` checks are SBOM minimum-element
profiles (supplier, version, identifiers and hashes on every component) and are not meant for
a CBOM: a crypto asset has no supplier or hash of its own, so they would report it.
