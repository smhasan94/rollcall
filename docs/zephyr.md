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
top-level directory with `--sysbuild`. The flags, mapping and warnings are under
[Ingestion](#ingestion) below. The module docs of `rollcall_core::zephyr` have the
full mapping.

## Ingestion

Pass the *image* build directory, the one holding `build_info.yml` and `spdx/` (with
sysbuild that is `build/<app>/`, not `build/`; the top-level directory is refused with a
message naming the image directory to use), or the sysbuild top-level directory with
`--sysbuild`, which reads the image list from its `build_info.yml` (`domains.yaml` is not
used), ingests every image (`--west-list` and `--include-sdk` apply to each) and merges them
under a product named after the `MAIN` application, unless `--product` names it. Warnings are prefixed with the image
name. Two images that ingest to the same image (e.g. a second MCUboot build next to
`mcuboot`, both `bootloader:mcuboot`) are an error naming both directories (exit 65). Run `west spdx --init -d <build>` before the
build and `west spdx -d <build>` after it to create `spdx/`.

- Required: `build_info.yml` and `spdx/zephyr.spdx`.
- Optional, each with a `rollcall generate: warning: …` line on stderr when missing (the
  exit code stays 0): `spdx/app.spdx`, `spdx/build.spdx`, `spdx/modules-deps.spdx`,
  `zephyr/.config`, and the `--west-list` file. A `--west-list` file that is named but
  missing is an error.
- The application is the product and its one `application` image. An MCUboot build
  (`CONFIG_MCUBOOT=y`) is instead a `bootloader` image named `mcuboot`. Zephyr is an
  `operating-system` component versioned by its release (e.g. `4.4.2`), with the commit it
  was built from recorded as `pkg:github/zephyrproject-rtos/zephyr@<sha>` purl evidence.
- Every west module appears exactly once as a `library` component whose version is the git
  revision it was built at (from `west list`, else from `zephyr.spdx`), with the upstream
  purl, cpe and supplier from `modules-deps.spdx` when the module declares them, and a purl
  pinned to the revision otherwise.
- `spdx/zephyr.spdx` decides which modules exist. A `west list` row for Zephyr itself (as in a
  T2 workspace, where the application is the manifest repository) becomes evidence on the
  Zephyr component; any other row that is not a module of the build is ignored with a warning.
- `--include-sdk` adds the toolchain as an `application` component (`zephyr-sdk`, versioned
  `major.minor` from `CONFIG_TOOLCHAIN_ZEPHYR_<M>_<N>`).
- `west list` output comes from `west list -f "{name} {path} {revision} {url}"` run in the
  west workspace.

Every fact carries evidence naming the file and line it came from. The full mapping is in the
`rollcall_core::zephyr` module docs.

With `--zephyr`, the `zephyr` component is split into one `library` subcomponent per Zephyr
subsystem (Bluetooth host, IP stack, USB, logging, …) that the build's `zephyr/.config`
enables *and* whose code `zephyr/zephyr.map` (the GNU ld map) shows was linked; libraries are
traced to their sources through `spdx/build.spdx`. A subsystem that is enabled but whose code
was garbage-collected is left out, and `--verbose` prints a `rollcall generate: note: …` line
saying so; notes never change the SBOM. Without the map or `.config`, `zephyr` is not split
(a warning). How the split works and how to add a subsystem is in
[subsystems.md](subsystems.md).

`--identify` resolves each module to its upstream purl and CPE with the identifier database:
see [identifiers.md](identifiers.md#using-the-database). What `west spdx` leaves out and how
rollcall fills it, with every claim reproducible against the fixtures:
[zephyr-gaps.md](zephyr-gaps.md).

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
