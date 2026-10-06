# Configuration detectors

`rollcall assay --build DIR` reads the Kconfig output of a build and reports the cryptography
it configures: the algorithms mbedTLS and PSA Crypto are built with, the TLS versions and
cipher suites, MCUboot's image signature and encryption, Bluetooth LE security, hardware
crypto drivers, and on ESP-IDF the secure boot scheme and flash encryption. These are the
`kconfig` (Zephyr) and `sdkconfig` (ESP-IDF) detectors; the CBOM names whichever ran in its
`rollcall:assay:detectors` property. See [assay.md](assay.md) for the command itself.

```sh
rollcall assay --build build --product sensor-node@1.2.0 -o sensor-node.cbom.json
rollcall assay --build fixtures/esp-idf/wifi-tls --product wifi-tls --format md
```

## Build layouts

| `--build` is | Recognised by | Files read |
|--------------|---------------|------------|
| a Zephyr sysbuild top-level build | `build_info.yml` and `domains.yaml` | `<image>/zephyr/.config` for each image `build_info.yml` lists under `cmake.images`, and the top-level `zephyr/.config` (the `SB_CONFIG_*` settings) if it is there |
| a Zephyr image build | `build_info.yml` | `zephyr/.config` |
| an ESP-IDF project | `sdkconfig` and `build/project_description.json` | `sdkconfig` |
| an ESP-IDF build directory | `project_description.json` | `../sdkconfig` |

Recognition is the same as `rollcall generate DIR` uses ([auto-detect](cli.md#auto-detect)).
Any other directory is not an error: `assay` prints a note that no configuration detector ran
and exits 0.

In a recognised Zephyr build a missing `.config` is a missing input (exit 66). A malformed
`.config` or `sdkconfig` (a line that is neither `SYMBOL=value`, `# SYMBOL is not set`, a
comment nor blank; an unterminated string; text that is not UTF-8), a malformed
`build_info.yml` or `project_description.json`, or a sysbuild image list that cannot be used is
a malformed input (exit 65), naming the file and, for a Kconfig file, the line.

## Where assets go

Each asset is a `cryptographic-asset` component under a library component under an image:

| Configuration | Image |
|---------------|-------|
| the Zephyr `MAIN` image, a single-image Zephyr build, an ESP-IDF `sdkconfig` | `application:<--product name>` |
| an image whose `.config` has `CONFIG_MCUBOOT=y`, and the sysbuild `SB_CONFIG_*` MCUboot settings | `bootloader:mcuboot` |
| any other sysbuild image | `application:<image name>` |
| ESP-IDF app signatures the bootloader verifies at boot (`CONFIG_SECURE_SIGNED_ON_BOOT`) | `bootloader:bootloader` |
| ESP-IDF app signatures the app verifies on an OTA update (`CONFIG_SECURE_SIGNED_ON_UPDATE`) | `application:<--product name>` |

A sysbuild image other than `MAIN` whose name is the `--product` name would land in the same
`application:<name>` image as `MAIN`. That is a malformed input (exit 65) naming
`build_info.yml`; pass another `--product`.

The library is the rule's: `mbedtls`, `psa-crypto`, `mcuboot`, `zephyr-bluetooth`,
`zephyr-crypto-<driver>`, `bootloader_support`. The asset's name is the catalogue algorithm
and parameter set (`RSA-PSS-2048`, `ECDSA-secp256r1`, `HMAC-SHA-256`), or the algorithm alone
when the configuration does not say the size (`AES-GCM`: PSA Crypto's `PSA_WANT_ALG_GCM` does
not fix a key size, so none is invented). A protocol is `TLS-1.2`. Every property comes from
the [algorithm catalogue](catalogue.md); a symbol that enables a hardware engine sets
`executionEnvironment: hardware`.

Each asset carries one evidence entry per symbol that put it there: a `kconfig-symbol`
locator `file:line SYMBOL` (the file relative to `--build`), detector `kconfig` or
`sdkconfig`, confidence `high`, and the rule's one-line reason. When several rules emit the
same asset in the same image and library (`CONFIG_PSA_WANT_ALG_ECDSA` and
`CONFIG_PSA_WANT_ALG_DETERMINISTIC_ECDSA`), it appears once with every rule's evidence. A
sysbuild `SB_CONFIG_BOOT_SIGNATURE_TYPE_RSA` or `SB_CONFIG_SIGNATURE_TYPE="RSA"` adds its
evidence to MCUboot's `RSA-PSS-2048` rather than standing beside it.

## What is mapped

The mapping is data: `crates/rollcall-assay/db/config-zephyr.yaml` and
`crates/rollcall-assay/db/config-esp-idf.yaml`. A test checks both against the algorithm
catalogue, so every algorithm and parameter set they name exists.

| Category | Symbols |
|----------|---------|
| MCUboot signature | `CONFIG_BOOT_SIGNATURE_TYPE_RSA` with `CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN` (RSA-PSS, sized), `_ECDSA_P256` (ECDSA-secp256r1), `_ED25519` and `_PURE` (Ed25519); sysbuild `SB_CONFIG_BOOT_SIGNATURE_TYPE_*` and `SB_CONFIG_SIGNATURE_TYPE`; `_NONE` is the note "MCUboot does not verify image signatures" |
| MCUboot image hash | `CONFIG_BOOT_IMG_HASH_ALG_SHA256/384/512` |
| MCUboot encryption | `CONFIG_BOOT_ENCRYPT_IMAGE` with `_RSA` (RSA-OAEP-2048), `_EC256` (ECDH-secp256r1, HKDF-SHA-256, HMAC-SHA-256) or `_X25519` (X25519, with `CONFIG_BOOT_HMAC_SHA256/512`); `CONFIG_BOOT_ENCRYPT_ALG_AES_128/256` (AES-CTR) |
| keelsign post-quantum TLVs | see [keelsign](#keelsign-provisional) |
| PSA Crypto (Zephyr 4) | `CONFIG_PSA_WANT_ALG_*`, with `CONFIG_PSA_WANT_KEY_TYPE_AES`/`_CHACHA20` for the ciphers and `CONFIG_PSA_WANT_ECC_*`, `CONFIG_PSA_WANT_DH_RFC7919_*` and the `PSA_WANT_ALG_SHA*` hashes choosing curves, groups and hashes; the p256-m driver; the PQCP ML-DSA driver (`ML-DSA-87` with `CONFIG_TF_PSA_CRYPTO_PQCP_MLDSA_87_ENABLED`, unsized `ML-DSA` without it) |
| legacy mbedTLS (Zephyr 3) | `CONFIG_MBEDTLS_RSA_C` with `_PKCS1_V15`/`_V21`, `CONFIG_MBEDTLS_SHA224/256/384/512`, `CONFIG_MBEDTLS_CIPHER_AES_ENABLED` with the mode switches, `CONFIG_MBEDTLS_ECDH_C`/`_ECDSA_C` with `CONFIG_MBEDTLS_ECP_DP_*`, `_HKDF_C`, `_DHM_C`, `_LMS(_C)` |
| legacy mbedTLS (nRF Connect SDK) | nrf_security's `Kconfig.legacy` names: `CONFIG_MBEDTLS_AES_C` with `_CIPHER_MODE_CBC`/`_CTR` or `_CCM_C`/`_GCM_C`, `_CHACHAPOLY_C`, `_SHA224_C`/`_SHA256_C`/`_SHA384_C`/`_SHA512_C`, and the names it shares with Zephyr 3 (`_RSA_C`, `_ECDH_C`, `_ECDSA_C`, `_ECP_DP_*`, `_HKDF_C`, `_DHM_C`); `_CIPHER_MODE_XTS`, `_CMAC_C`, `_CHACHA20_C`, `_MD5_C`, `_SHA1_C` and `_ECJPAKE_C` are notes. The padding, table-size and key-length options and every `*_ALT` are not mapped: they do not decide whether an algorithm is built |
| TLS | `CONFIG_MBEDTLS_SSL_PROTO_TLS1_2/1_3` and `CONFIG_MBEDTLS_TLS_VERSION_1_2/1_3` (protocol assets); every `CONFIG_MBEDTLS_CIPHERSUITE_*` (its key exchange, signature, cipher and PRF or HKDF hash); `CONFIG_MBEDTLS_KEY_EXCHANGE_*`, only with TLS 1.2 on, `CONFIG_MBEDTLS_SSL_PROTO_TLS1_2` (Zephyr 4.3 and later, every nRF Connect SDK) or `CONFIG_MBEDTLS_TLS_VERSION_1_2` (Zephyr 3.x to 4.2): these are TLS 1.2 key exchanges, which mbedTLS drops without TLS 1.2, and Kconfig does not tie them to TLS (MCUboot's mbedTLS sets one without TLS) |
| Bluetooth LE | `CONFIG_BT_SMP` (LE Secure Connections ECDH-secp256r1, and an AES-CMAC note, unless `CONFIG_BT_SMP_LEGACY_PAIR_ONLY`; legacy pairing AES-ECB-128 unless `CONFIG_BT_SMP_SC_ONLY`), `CONFIG_BT_ECC`, `CONFIG_BT_PRIVACY`, `CONFIG_BT_HOST_CRYPTO`, `CONFIG_BT_CTLR_ECDH`, `CONFIG_BT_CTLR_LE_ENC` (AES-CCM-128 in hardware). `CONFIG_BT_CTLR_CRYPTO` only says the controller has a crypto engine and is not reported |
| hardware drivers | the Zephyr `drivers/crypto` drivers (`CONFIG_CRYPTO_NRF_ECB`, `_ESP32_AES/SHA`, `_STM32`, `_STM32_HASH`, `_INTEL_SHA`, `_NPCX_SHA`, `_IT8XXX2_SHA`, …): AES-ECB for an AES engine, SHA2-256 for a hash engine, in hardware; `CONFIG_NRF_SECURITY` with the CryptoCell or CRACEN PSA driver marks the PSA algorithms it accelerates (CryptoCell's hashes only up to SHA-256) |
| ESP-IDF mbedTLS | `CONFIG_MBEDTLS_AES_C` with `_GCM_C`/`_CCM_C`, `_CHACHA20_C` with `_POLY1305_C`, `_SHA512_C`, `_SHA3_C`, `_ECDH_C`/`_ECDSA_C` with `_ECP_DP_*`, `_HKDF_C`, `_DHM_C`, `CONFIG_MBEDTLS_KEY_EXCHANGE_*` with `_SSL_PROTO_TLS1_2`, `_SSL_PROTO_TLS1_2/1_3`; SHA2-256, which ESP-IDF always builds, through `CONFIG_MBEDTLS_HARDWARE_SHA` (in hardware when `y`, in software when `n`); `CONFIG_MBEDTLS_HARDWARE_AES` puts AES in hardware, `_HARDWARE_SHA` SHA2-256 and, where `CONFIG_SOC_SHA_SUPPORT_SHA384`/`_SHA512` say so, SHA2-384/512; `CONFIG_MBEDTLS_HARDWARE_MPI` only speeds up big-number arithmetic and is a note, not hardware RSA |
| ESP-IDF secure boot | `CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME` (RSA-PSS-3072), `_ECDSA_V2_SCHEME` with `CONFIG_SECURE_BOOT_ECDSA_KEY_LEN_*_BITS`, `_ECDSA_SCHEME` (v1, ECDSA-secp256r1), each with SHA2-256: under `bootloader:bootloader` with `CONFIG_SECURE_SIGNED_ON_BOOT`, under the application with `CONFIG_SECURE_SIGNED_ON_UPDATE` (signed apps without secure boot, RSA or ECDSA v2, are checked by the app only); `# CONFIG_SECURE_BOOT is not set` is the note "secure boot not enabled" |
| ESP-IDF flash encryption | `CONFIG_SECURE_FLASH_ENC_ENABLED` (a note: XTS-AES, or on the original ESP32, `CONFIG_IDF_TARGET_ESP32`, its own AES-256 scheme with a per-block key tweak) and its mode, `CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT/RELEASE` (a note); not set is the note "flash encryption not enabled" |

Symbols that are set but say nothing about which algorithms are built (log levels, buffer and
heap sizes, module switches such as `CONFIG_ZEPHYR_MBEDTLS_MODULE`, key-file paths, capability
flags such as `CONFIG_SOC_SECURE_BOOT_SUPPORTED`) give no asset and no note.

### Not in the catalogue yet

An algorithm the catalogue does not list (MD5, SHA-1, RIPEMD-160, DES and 3DES, Blowfish, XTEA,
Camellia, ARIA, CMAC and AES-CMAC, the ChaCha20 stream cipher, CTR-DRBG, HMAC-DRBG, AES key wrap, AES-XTS and
XTS-AES, ESP32 flash encryption, the TLS 1.2 PRF, EC-JPAKE, the secp192,
secp224, Koblitz and Brainpool curves, curve448) is never reported as an asset. Its symbol
gives a note instead, for example:

```text
rollcall assay: note: http_server/zephyr/.config:333: CONFIG_PSA_WANT_ALG_SHA_1 enables SHA-1, which the algorithm catalogue does not list yet; not reported
```

### Notes

Besides those, `assay` notes which crypto API each image's mbedTLS uses (the PSA Crypto API,
the legacy mbedTLS API, or both, with the symbol that shows it), and a value of the wrong type
for a symbol a rule reads: a string where MCUboot's RSA key length belongs gives an asset
without a parameter set and a note; an integer where `y` or `n` belongs is ignored with a note.
A parameter set the catalogue lacks (an RSA length of 1024) gives an asset without a parameter
set and a note. A configuration header Kconfig does not generate gives a note too (see
[Compiled out](#compiled-out)). Notes are sorted and never repeated.

## The rule format

```yaml
format: rollcall-config-rules/1
detector: kconfig                     # the evidence detector
api:                                  # which crypto API an image uses (a note)
  psa: [CONFIG_MBEDTLS_PSA_CRYPTO_C]
  legacy: [CONFIG_MBEDTLS_RSA_C]
dimensions:                           # a curve, group or hash chosen by its own symbols
  ecdh-curve:
    - {symbol: CONFIG_PSA_WANT_ECC_SECP_R1_256, parameter_set: secp256r1}
    - {symbol: CONFIG_PSA_WANT_ECC_MONTGOMERY_255, algorithm: X25519, parameter_set: X25519}
    - {symbol: CONFIG_PSA_WANT_ECC_SECP_K1_256, uncatalogued: secp256k1}
rules:
  - id: psa-ecdh                      # unique
    when: [CONFIG_PSA_WANT_ALG_ECDH]  # every one y or m
    when_any: []                      # at least one y or m; each one on is evidence too
    when_value: {}                    # string options equal to these values
    when_off: []                      # every one explicitly n or "is not set"
    unless: []                        # none of these y or m
    library: psa-crypto
    image: {kind: bootloader, name: bootloader}   # optional: not the file's image
    emit:
      - AES-GCM-128                   # an asset name: algorithm and parameter set
      - {algorithm: ECDH, parameter_set_from: {dimension: ecdh-curve}}
      - {algorithm: RSA-PSS, parameter_set_from: {int: CONFIG_BOOT_SIGNATURE_TYPE_RSA_LEN}}
      - {algorithm: HSS, parameter_set_from: {string: CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET}}
      - {algorithm: AES-CCM, parameter_set: "128", hardware: true}
    protocol: {type: tls, version: "1.2"}
    uncatalogued: [SHA-1]             # a note, never an asset
    note: secure boot not enabled     # a note
    reason: one line of at most 200 characters, the evidence reason
hardware:                             # symbols that put a library's algorithms in hardware
  - when: [CONFIG_MBEDTLS_HARDWARE_AES]
    library: mbedtls
    algorithms: [AES-CCM, AES-GCM, SHA2-256]   # an algorithm (every set) or one set
    reason: mbedTLS runs AES in the AES accelerator (CONFIG_MBEDTLS_HARDWARE_AES)
compiled_out:                         # explicitly-off symbols that compile algorithms out
  - when_all_off: [CONFIG_PSA_WANT_ALG_CBC_NO_PADDING, CONFIG_PSA_WANT_ALG_CBC_PKCS7]
    library: psa-crypto               # the library they are compiled out of
    algorithms: [AES-CBC]
custom_config:                        # a header Kconfig does not generate: no compiled-out list
  - symbol: CONFIG_MBEDTLS_USER_CONFIG_FILE
    defaults: [""]                    # the values that mean Kconfig's own configuration
    libraries: [mbedtls, psa-crypto]
```

A dimension emits one asset for each of its symbols that is on, or one asset without a
parameter set when none of its catalogued choices is on; an `uncatalogued` choice that is on
gives a note. Unknown keys, a symbol that is not `CONFIG_…` or `SB_CONFIG_…`, a duplicate id, a
rule with no condition or no effect, an emitting rule without a library or reason, a reason
over 200 characters, an unknown dimension, a compiled-out rule without a library, a
custom-config entry without libraries or defaults, and a hardware, compiled-out or
custom-config library that no rule emits under (a typo such as `mbedtsl`) are load errors; an
algorithm or parameter set the catalogue does not have, or an `uncatalogued` name it does
have, is a lint finding. Each finding names the file and, where it can be found, the line of
the rule or entry (`config-zephyr.yaml:412: psa-ecdh: …`). The built-in files have neither.

`when_any` lets one rule stand for "this, with any of these": the TLS 1.2 key-exchange rules
say `when: [CONFIG_MBEDTLS_KEY_EXCHANGE_RSA_ENABLED]` and `when_any:
[CONFIG_MBEDTLS_SSL_PROTO_TLS1_2, CONFIG_MBEDTLS_TLS_VERSION_1_2]`, and the asset's evidence
has the key-exchange symbol and whichever TLS symbol is on.

## Compiled out

Besides assets, the detectors build a **compiled-out list**. It records every image they
evaluated and, per image, the algorithms whose `compiled_out` rule has every symbol explicitly
off, each with the **library** it is compiled out of: `CONFIG_MBEDTLS_CIPHER_MODE_CBC=n`
compiles AES-CBC out of `mbedtls`; `CONFIG_PSA_WANT_ALG_CBC_NO_PADDING` and
`CONFIG_PSA_WANT_ALG_CBC_PKCS7` both not set compile it out of `psa-crypto`. A symbol that is
not in the file at all never counts: absent is unknown, not off. An algorithm the image's own
configuration emits is never compiled out of it.

The list says nothing about other implementations: `# CONFIG_PSA_WANT_ALG_RSA_PSS is not set`
means PSA Crypto lacks RSA-PSS, not that TinyCrypt, wpa_supplicant's internal crypto, a vendored
`aes.c` or MCUboot's bootutil does.

When an image's configuration names a header Kconfig does not generate, that header can turn
algorithms back on, so the image gets no `mbedtls` or `psa-crypto` entries and a note says
why. That is a `CONFIG_MBEDTLS_USER_CONFIG_FILE`, `CONFIG_MBEDTLS_CONFIG_FILE`,
`CONFIG_MBEDTLS_CFG_FILE`, `CONFIG_TF_PSA_CRYPTO_CONFIG_FILE`,
`CONFIG_TF_PSA_CRYPTO_USER_CONFIG_FILE`, `CONFIG_MBEDTLS_PSA_CRYPTO_CONFIG_FILE` or
`CONFIG_MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE` naming anything but the generated headers (or,
for the user files and the deprecated `CONFIG_MBEDTLS_CFG_FILE`, being non-empty): Zephyr's
`config-tls-generic.h` (Zephyr 3.x to 4.1), `config-mbedtls.h` (Zephyr 4.2 and later) and
`config-tf-psa-crypto.h` (Zephyr 4.4), and nRF Connect SDK nrf_security's `nrf-config.h`,
`nrf-psa-crypto-config.h` and `nrf-psa-crypto-user-config.h` (named by
`CONFIG_MBEDTLS_PSA_CRYPTO_*CONFIG_FILE` in NCS 2.9 to 3.3, and by the
`CONFIG_TF_PSA_CRYPTO_*CONFIG_FILE` defaults in NCS 3.4). MCUboot's `mcuboot-mbedtls-cfg.h`
is one of these. A file of your own named like one of the generated headers and placed earlier on the
include path cannot be seen this way.

`rollcall_assay::assay` returns the list as `Inventory::compiled_out` (and the crypto API of
each image as `Inventory::apis`). The source-code detector uses it through
`rollcall_assay::config::apply_compiled_out`, for a finding with `source-line` evidence of an
algorithm compiled out of some library of its image:

- under that library (`library:<name>`), with only `source-line` evidence: removed;
- under that library, with other non-configuration evidence too (an ELF symbol, a Cargo
  feature): kept, with its `source-line` entries lowered to confidence `low`;
- under another library, or under none: kept, with its `source-line` entries lowered to
  confidence `low`, never removed;
- with configuration (`kconfig-symbol`) evidence: never touched.

Each removal and each lowering is returned with the action, the libraries and the symbols and
lines behind it.

`CompiledOut::everywhere` gives what is compiled out of the same library in every evaluated
image, for a finding that cannot be placed in one. An image that compiles nothing out, such as
the baseline fixture's application, makes it empty.

## keelsign (provisional)

keelsign adds post-quantum image signatures to MCUboot as TLVs: 0x4BA1 for ML-DSA-44, 0x4BA2
for ML-DSA-65 and 0x4BA3 for an HSS/LMS signature. The rules recognise them by these symbols:

| Symbol | Asset |
|--------|-------|
| `CONFIG_BOOT_KEELSIGN_MLDSA44=y` | `ML-DSA-44` |
| `CONFIG_BOOT_KEELSIGN_MLDSA65=y` | `ML-DSA-65` |
| `CONFIG_BOOT_KEELSIGN_LMS_HSS=y` with `CONFIG_BOOT_KEELSIGN_LMS_PARAMETER_SET="LMS_SHA256_M32_H10"` | `HSS-LMS_SHA256_M32_H10` (the parameter set as written; one the catalogue lacks gives `HSS` and a note) |

**These symbol names are provisional.** They are placeholders until keelsign's MCUboot
integration settles its Kconfig, and live in a marked section of `config-zephyr.yaml` so they
can be renamed in one place. The assets go under `bootloader:mcuboot / mcuboot`, beside
MCUboot's own signature.

## Determinism

The same build gives the same inventory: files are read in a fixed order, every collection is
sorted, evidence paths are relative to `--build`, notes are sorted and de-duplicated, and every
`bom-ref` is derived from the asset's place in the model.
