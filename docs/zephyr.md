# Zephyr

`rollcall generate --zephyr` turns a Zephyr build directory into a CycloneDX 1.6 SBOM. It reads
`west spdx`'s documents, `west list` output, the Kconfig `.config`, the link map and
`build_info.yml`. It splits the `zephyr` component into the subsystems the build enabled and
linked, and resolves west modules to upstream purls and CPEs. A sysbuild build (MCUboot and the
application) becomes one product.

## Usage

```sh
west spdx --init -d build && west build --sysbuild && west spdx -d build
west list -f "{name} {path} {revision} {url}" > build/west-list.txt
rollcall generate --zephyr build --sysbuild --west-list build/west-list.txt --identify -o sbom.cdx.json
```

Pass the image build directory (the one holding `build_info.yml` and `spdx/`), or a sysbuild
top-level directory with `--sysbuild`. The flags, mapping and warnings are in the
[README](../README.md#zephyr-ingestion). The module docs of `rollcall_core::zephyr` have the
full mapping.

## Auto-detect

`rollcall generate DIR` treats DIR as Zephyr when it holds `build_info.yml`. When `domains.yaml`
is there too, DIR is a sysbuild top-level directory (`--sysbuild` is implied). Its
`west-list.txt`, if present, is the west list. `--identify`, `--include-sdk` and the
identifier database flags are not inferred; pass them with DIR as with `--zephyr`.

```console
$ rollcall detect fixtures/zephyr/tls
zephyr
$ rollcall detect fixtures/zephyr/tls/http_server
zephyr
```

Every ecosystem's signal is in the [docs index](README.md#ecosystems).

## Further reading

- [subsystems.md](subsystems.md): the subsystem split and how to add a subsystem.
- [zephyr-gaps.md](zephyr-gaps.md): what `west spdx` leaves out.
- [identifiers.md](identifiers.md): module identifiers.
- [fixtures.md](fixtures.md): the Zephyr fixtures.
