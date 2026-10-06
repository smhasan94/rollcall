# Expected configuration inventories (SHA-144)

Hand-written test data, not generated, and not fixtures: the files here are the expected
output of the configuration detectors (`rollcall_assay::config::detect_build`) for the real
fixture builds under `fixtures/`, which they are checked against by
`crates/rollcall-assay/tests/config.rs`. Each line was checked against the fixture's own
`.config` or `sdkconfig`: the symbol, its value and its line. When a rule or a fixture changes,
edit these files by hand and review the diff like code.

| File | Fixture | `--product` |
|------|---------|-------------|
| `zephyr-baseline.expected` | `fixtures/zephyr/baseline` | `baseline` |
| `zephyr-tls.expected` | `fixtures/zephyr/tls` | `tls` |
| `zephyr-bt.expected` | `fixtures/zephyr/bt` | `bt` |
| `zephyr-smp-smp-bt.expected` | `fixtures/zephyr-smp/smp-bt` | `smp-bt` |
| `zephyr-smp-smp-serial.expected` | `fixtures/zephyr-smp/smp-serial` | `smp-serial` |
| `zephyr-old-mbedtls.expected` | `fixtures/zephyr-old-mbedtls/old-mbedtls` | `old-mbedtls` |
| `esp-idf-wifi-tls.expected` | `fixtures/esp-idf/wifi-tls` | `wifi-tls` |
| `esp-idf-hello-world.expected` | `fixtures/esp-idf/hello-world` | `hello-world` |

## Format

Every file starts with the line `# hand-written test data, SHA-144, not generated`. Lines
starting with `#` and blank lines are ignored. The others come in three groups, in this order:

```text
asset IMAGE / LIBRARY / ASSET [hardware] | LOCATOR, LOCATOR, ...
compiled-out IMAGE LIBRARY ALGORITHM
note TEXT
```

- `asset`: one line per crypto asset, in model order (image, then library, then asset name).
  `IMAGE` is `kind:name` (`bootloader:mcuboot`, `application:<product>`), `LIBRARY` the
  component the asset sits under, `ASSET` its component name (`RSA-PSS-2048`, `AES-GCM`,
  `TLS-1.2`). `[hardware]` marks `executionEnvironment: hardware`. The locators are every
  evidence entry's `file:line SYMBOL`, the file relative to the build directory, each once, in
  file and line order. Every entry is detector `kconfig` (Zephyr) or `sdkconfig` (ESP-IDF) at
  confidence `high`; the test checks that separately.
- `compiled-out`: one line per library and algorithm (and parameter set, when the entry has
  one) that an explicitly-off symbol compiles out of the image: `IMAGE LIBRARY ALGORITHM`,
  the library being `psa-crypto` for a `PSA_WANT` symbol and `mbedtls` for an mbedTLS module
  switch.
- `note`: the inventory's notes, as the detector sorts them (plain string order).
