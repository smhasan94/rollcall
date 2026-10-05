# Quickstart

From a Zephyr build directory to a validated CycloneDX 1.6 SBOM and a readiness report, in five
steps and about ten minutes. You need a terminal on Linux or macOS (Windows: see the zip in
step 1), `curl`, and either a Zephyr build of your own or the example build from step 2.

The commands below are the ones rollcall's CI runs: every `$ ` command in a console block is
run against the example build, and its output must match what is shown (`scripts/check-doc-examples.sh docs/quickstart.md`).
A separate job follows this page, as published, on a clean machine (`scripts/quickstart-clean.sh`).

## 1. Install rollcall

Pick one of the three. Each gives a `rollcall` command; check it with `rollcall --version`.

### Release binary (Linux and macOS)

The binaries are static and need nothing else. Set `TARGET` to `linux-amd64`, `linux-arm64` or
`darwin-universal` (any Mac). Each archive holds one directory, `rollcall-<version>-<target>/`,
with the `rollcall` binary, `LICENSE` and `README.md`.

```sh
VERSION=v0.1.0
TARGET=linux-amd64
curl -fsSLO "https://github.com/smhasan94/rollcall/releases/download/$VERSION/rollcall-$VERSION-$TARGET.tar.gz"
curl -fsSLO "https://github.com/smhasan94/rollcall/releases/download/$VERSION/SHA256SUMS"
grep " rollcall-$VERSION-$TARGET.tar.gz\$" SHA256SUMS | sha256sum --check
tar -xzf "rollcall-$VERSION-$TARGET.tar.gz"
mkdir -p "$HOME/.local/bin"
install -m 0755 "rollcall-$VERSION-$TARGET/rollcall" "$HOME/.local/bin/rollcall"
export PATH="$HOME/.local/bin:$PATH"
rollcall --version
```

On macOS, `sha256sum --check` is `shasum -a 256 --check`. `sha256sum --check` must print
`rollcall-v0.1.0-<target>.tar.gz: OK`; anything else means the download is not the released
file, so stop there. Each binary also has a build provenance attestation:
`gh attestation verify rollcall-$VERSION-$TARGET.tar.gz --repo smhasan94/rollcall`.

On Windows, download `rollcall-v0.1.0-windows-amd64.zip` and `SHA256SUMS` from the same release,
compare `Get-FileHash rollcall-v0.1.0-windows-amd64.zip` with its line in `SHA256SUMS`, and
extract it: the binary is `rollcall-v0.1.0-windows-amd64\rollcall.exe`. Put `rollcall.exe` in
a directory on your `PATH` (for example `%USERPROFILE%\bin`, added to `PATH` in the system
settings), or run it by its full path.

### cargo

Needs Rust 1.91 or newer (from [rustup.rs](https://rustup.rs)). This compiles rollcall, which
takes a few minutes.

```sh
cargo install rollcall --locked --version 0.1.0
rollcall --version
```

### pip

Needs Python 3.9 or newer. The package is a small wrapper: on first run it downloads the
release binary for your platform, checks it against the SHA-256 recorded in the package, and
runs it.

```sh
python3 -m venv "$HOME/.venvs/rollcall"
. "$HOME/.venvs/rollcall/bin/activate"
pip install rollcall==0.1.0
rollcall --version
```

## 2. Prepare a build directory

rollcall reads what a Zephyr build leaves behind: `west spdx`'s documents, the Kconfig
`.config`, the link map and `build_info.yml`, plus the output of `west list`. `west spdx` only
works if it was initialised *before* the build, so this step is a rebuild.

### Your own Zephyr build

In your west workspace, for a sysbuild build (MCUboot and your application) of `app/`:

```sh
west spdx --init -d build/app
west spdx --init -d build/mcuboot
west build -b nrf52840dk/nrf52840 --sysbuild -d build app -- \
  -DCONFIG_BUILD_OUTPUT_META=y -Dmcuboot_CONFIG_BUILD_OUTPUT_META=y
west spdx -d build/app
west spdx -d build/mcuboot
west list -f "{name} {path} {revision} {url}" > build/west-list.txt
```

Replace `app` (the image directory is named after your application's directory) and the board
with yours. `west spdx` stops unless every image, MCUboot included, was built with
`CONFIG_BUILD_OUTPUT_META` (set in each image's configuration, or as above on the command line).
`west spdx --init` is needed on Zephyr v4.4 and earlier. Without sysbuild, it is
`west spdx --init -d build`, `west build ... -- -DCONFIG_BUILD_OUTPUT_META=y`,
`west spdx -d build`.
Steps 3 to 5 then use `build` where they say `fixtures/zephyr/tls`.
[What west spdx leaves out](zephyr-gaps.md) explains what each input adds.

### No build at hand: the example build

rollcall's repository holds real Zephyr v4.4.2 builds for the nRF52840 DK
([Build fixtures](fixtures.md)). This takes one of them, an HTTPS server with MCUboot, into
`fixtures/zephyr/tls` in the current directory:

```sh
curl -fsSL https://github.com/smhasan94/rollcall/archive/refs/tags/v0.1.0.tar.gz |
  tar -xz --strip-components=1 rollcall-0.1.0/fixtures/zephyr/tls
ls fixtures/zephyr/tls
```

`ls` lists `build_info.yml`, `domains.yaml`, `http_server`, `mcuboot`, `west-list.txt` and
`zephyr`.

## 3. Generate the SBOM

Point `rollcall generate` at the sysbuild directory. It sees `domains.yaml` and makes one
product of the two images, reads `west-list.txt` beside it, and with `--identify` resolves every
west module to its upstream purl and CPE:

```console
$ rollcall generate fixtures/zephyr/tls --identify -o product.cdx.json
```

It prints nothing on stdout. On stderr it prints warnings about anything it could not
resolve; for this build, two notes that the identifier database and `west spdx` disagree on
tf-psa-crypto's CPE (rollcall keeps both). The same command spelled out is
`rollcall generate --zephyr fixtures/zephyr/tls --sysbuild --west-list fixtures/zephyr/tls/west-list.txt --identify -o product.cdx.json`.
Add `--timestamp 2026-01-02T03:04:05Z` for byte-identical output across runs.

## 4. Validate it

```console
$ rollcall validate --schema product.cdx.json
product.cdx.json: valid CycloneDX 1.6
```

That is a validated SBOM: it conforms to the CycloneDX 1.6 JSON schema.

The regulator profiles go further and check each component for the fields the CISA 2026
minimum elements and the EU Cyber Resilience Act guidance ask for:

```sh
rollcall validate --profile all product.cdx.json
```

For this build they report 37 errors and exit 1: the product and its two images have no
version, supplier, identifier or hash, and no component has a hash, because a Zephyr build does
not record them. `--product NAME@VERSION` on `generate` fills in part of it. Each finding names
the field, the fix and the clause that asks for it;
[validate](validate.md) has the details and [the FAQ](faq-cra-cisa.md) what the rules ask for.

## 5. Report on it

```console
$ rollcall report --format md -o report.md product.cdx.json
$ grep -o 'Its readiness score is [0-9]* out of 100' report.md
Its readiness score is 42 out of 100
```

`report.md` is a page for people: the score, what each part of it measures, every component
with its identifiers, and what to fix first. `--format json` gives the same for machines. Add
`--scan` with a grype or osv-scanner result to include known vulnerabilities
([Scanning](scan.md)).

## Next steps

- Run all of this on every push and pull request: [CI with the GitHub Action](ci.md).
- Mark vulnerabilities that do not affect your build: [VEX rules](vex-rules.md).
- A module rollcall could not resolve: [Contributing a module](contributing-identifiers.md).
- Other ecosystems: [Cargo](cargo.md), [ESP-IDF](esp-idf.md), [PlatformIO](platformio.md).
