# VEX rules

A vulnerability scanner such as grype reads your SBOM and lists every known vulnerability
(CVE) for every component version in it. Many of those do not affect your firmware, because
the code with the bug was never built into it. Zephyr and Mbed TLS are configured with
Kconfig: if Bluetooth is switched off, no Bluetooth code is compiled, and no Bluetooth CVE
can affect the image.

A **VEX statement** records that decision: "CVE-X does not affect component Y in this
product, because the vulnerable code is not present". `rollcall vex` writes VEX statements
from **rules**. A rule says which findings it is about and what must be true of the build
for its statement to hold. rollcall checks that against **evidence** from the build itself,
such as each image's Kconfig `.config` file. When the evidence is missing, rollcall makes no
claim.

This page covers:

- [Running `rollcall vex`](#running-rollcall-vex)
- [Rule format](#rule-format): every field, and how rules are applied
- [Starter pack](#starter-pack): the rules rollcall ships
- [Checking your rules](#checking-your-rules): `rollcall vex lint`
- [Worked examples](#worked-examples): five real CVEs against real builds
- [Glossary](#glossary)

## Running `rollcall vex`

`rollcall vex` needs the SBOM, the scanner's findings and some rules. Give each image's
`.config` as evidence, named by the image's name in the SBOM:

```sh
rollcall generate --zephyr build --sysbuild -o product.cdx.json
grype sbom:product.cdx.json -o json > grype.json
rollcall vex --sbom product.cdx.json \
  --kconfig mcuboot=build/mcuboot/zephyr/.config \
  --kconfig app=build/app/zephyr/.config \
  --findings grype.json --starter-rules --rules my-rules.yml -o vex.json
```

- `--starter-rules` adds rollcall's own [starter pack](#starter-pack).
- `--rules FILE` adds your rules. Repeat it for more files. A rule id may appear only once
  across all of them, starter pack included.
- `--format openvex` or `--format cyclonedx` writes a standard VEX document instead of
  rollcall's report. See the README for those formats and for signing.

The report (`rollcall-vex/1` JSON) has a `statements` list and an `unresolved` list. Each
unresolved finding says why no rule decided it, with a rule template you can fill in. A
summary of the unresolved findings goes to stderr. Unresolved findings do not change the
exit code.

## Rule format

A rules file is YAML with a `version` and a list of `rules`:

```yaml
version: 1
rules:
  - id: mbedtls-dtls-compiled-out
    priority: 0
    match:
      name: mbedtls
      cves: [CVE-2022-35409]
      versions: "<2.28.2"
    when:
      - kconfig_off: CONFIG_MBEDTLS_SSL_PROTO_DTLS
      - kconfig_equals: {CONFIG_MBEDTLS_CFG_FILE: config-mbedtls.h}
    status: not_affected
    justification: code_not_present
    detail: DTLS is compiled out (CONFIG_MBEDTLS_SSL_PROTO_DTLS is not set).
```

| Field | Required | Meaning |
|-------|----------|---------|
| `version` | yes | The format version. Always `1`. |
| `id` | yes | A unique name for the rule: letters, digits, `.`, `_` and `-`. |
| `priority` | no | A whole number, default `0`. Breaks ties between equally specific rules: higher wins. |
| `match.name` | one of the three | The component's exact name, for example `mbedtls` or `zephyr`. |
| `match.purl` | one of the three | The component's purl, or a pattern where `*` matches anything, for example `pkg:github/mbed-tls/mbedtls@*`. |
| `match.subsystem` | one of the three | A Zephyr subsystem split out of the `zephyr` component, for example `bluetooth-host` (see `docs/subsystems.md`). |
| `match.cves` | no | The vulnerability ids the rule is about. A finding matches if its id or any alias is listed. Leave it out to match every vulnerability of the component. |
| `match.versions` | no | A version range, in Cargo's syntax: `"<3.6.5"`, `">=2.28.0, <2.28.5"`. |
| `when` | no | A list of conditions. Every one must be true. Each is a one-line mapping (below). |
| `status` | yes | `not_affected`, `affected`, `fixed` or `under_investigation`. |
| `justification` | for `not_affected` only | Why the component is not affected. `code_not_present` is the usual one here. CycloneDX and OpenVEX words are both accepted; each is translated when the other format is written. |
| `detail` | no | A sentence for the reader of the VEX statement. Say which setting decides it. |

The conditions:

| Condition | True when | Evidence |
|-----------|-----------|----------|
| `kconfig_off: CONFIG_X` | `CONFIG_X` is `n` or `is not set` in the `.config` of the component's own image | `--kconfig IMAGE=FILE` |
| `kconfig_equals: {CONFIG_X: value}` | `CONFIG_X` has exactly this value in that `.config`. Values are compared as text, as the `.config` writes them. A bool is `y`, `n` or `m`; `is not set` counts as `n`. A string is compared without its quotes. Hex is text too, so `0x10` and `16` differ. Write one key per condition. | `--kconfig IMAGE=FILE` |
| `symbol_not_linked: name` | the function `name` is not linked into the component's own image. Use it only for the functions [described below](#using-symbol_not_linked). | the library only, for now |
| `cargo_feature_off: name` | the Cargo feature `name` is not enabled | the library only, for now |
| `version_in: "<range>"` | the component's version is in the range | the SBOM |

### How rules are applied

For each finding, rollcall:

1. finds the component in the SBOM that the finding is about;
2. keeps the rules whose `match` fits that component and finding;
3. drops a rule if any of its conditions is false;
4. picks the most specific of the rules left: one that names CVEs beats one that does not,
   then one with a version range, then one with an exact purl. `priority` breaks a tie.

Then:

- if the chosen rule's conditions are all true, you get a statement;
- if one of them could not be checked, the finding stays unresolved (`needs_evidence`);
- if two equally specific rules disagree, rollcall warns and the finding stays unresolved
  (`conflict`);
- if no rule is left, the finding stays unresolved (`no_rule`).

### Missing evidence is never "off"

A condition with no evidence is **unknown**, and unknown is never true. These are all
unknown:

- the image has no `--kconfig` file;
- the `.config` does not mention the symbol at all.

The second case matters. A `.config` lists only the symbols that build could see. A symbol
it does not mention may be misspelt, renamed in your Zephyr version, or hidden by a
dependency. None of these proves the code is out, so rollcall leaves the finding unresolved
rather than claim `not_affected`. The other side of this: a typo in a rule makes the rule
silently useless. [`rollcall vex lint`](#checking-your-rules) finds those.

Evidence is per image. In a sysbuild product, MCUboot's Mbed TLS is judged by MCUboot's
`.config` (and linker map), and the application's by the application's.

`rollcall vex` cannot read linker maps or Cargo features yet. From the command line,
`symbol_not_linked` and `cargo_feature_off` are always unknown, so their rules leave
findings unresolved. The library (`rollcall_core::vex`) can take that evidence:
`rollcall_core::linker_map::linked_functions` reads an image's linked functions from its GNU
ld map.

### Using `symbol_not_linked`

A function can be in the image without the linker map naming it. So use `symbol_not_linked`
only for a function that is:

- not `static`;
- built with `-ffunction-sections`, as Zephyr builds its code;
- not placed in a custom section, such as `.ramfunc` or `.itcm`;
- called only from other source files: the compiler may inline a function into a caller in
  its own file and drop the separate copy;
- not a C-runtime function: the toolchain's `libc.a` and `libgcc.a` are built without
  function sections, so the map does not say which of their functions are linked.

Use it for a function that a whole subsystem is entered through, such as a handshake state
machine, so that its absence means the subsystem is absent. Do not use it for small
helpers.

rollcall gives no answer at all, rather than one that could miss a function, when:

- the map is incomplete: it lacks the `OUTPUT(…)` line GNU ld writes near the end of the
  memory map (so it was cut short), or it places nothing in the image;
- the map shows link-time optimisation: GCC's `ltrans` objects, or ld's
  `(symbol from plugin)` marker, which Clang's LTO through GNU ld leaves too;
- some code was built without function sections, outside the toolchain's `libc.a` and
  `libgcc.a`. Only those two are exempt: a map that links the toolchain's `libc_nano.a`,
  `libm.a` or `libnosys.a` gets no answer.

## Starter pack

`--starter-rules` loads `vex-rules.yaml`, which ships with the identifier database
(`crates/rollcall-identifiers/db/vex-rules.yaml`). Every rule gives `not_affected` /
`code_not_present`, and only on evidence from your build. Each CVE was checked against its
NVD record and its advisory (Mbed TLS or Zephyr GHSA); the file's comments cite them. It is
a starting point, not a security assessment of your product. Read each rule before you rely
on it.

| Rule | Component | CVEs | When | Notes |
|------|-----------|------|------|-------|
| `mbedtls-tls13-compiled-out` | `mbedtls` before 3.6.5 | CVE-2026-34873 | `CONFIG_MBEDTLS_TLS_VERSION_1_3` off, and the stock configuration file (below) | TLS 1.3 server session resumption. |
| `mbedtls-x509-write-compiled-out` | `mbedtls` before 3.6.5 | CVE-2026-34874 | `CONFIG_MBEDTLS_X509_CSR_WRITE_C` and `CONFIG_MBEDTLS_X509_CRT_WRITE_C` off, and the stock configuration file | A crash when writing a certificate or request's name. |
| `mbedtls-tls-server-not-linked` | `mbedtls` | CVE-2026-34873 | `mbedtls_ssl_handshake_server_step` and `mbedtls_ssl_tls13_handshake_server_step` not linked | Needs linker-map evidence. |
| `mbedtls-tls-client-not-linked` | `mbedtls` | CVE-2026-25832, CVE-2026-25834, CVE-2026-50580 | `mbedtls_ssl_handshake_client_step` and `mbedtls_ssl_tls13_handshake_client_step` not linked | Needs linker-map evidence. |
| `zephyr-bluetooth-off` | `zephyr` | 13 Bluetooth CVEs (listed in the file) | `CONFIG_BT` off | A dated snapshot, see below. |
| `zephyr-mcumgr-serial-off` | `zephyr` | CVE-2026-10648 | `CONFIG_UART_MCUMGR` and `CONFIG_SHELL` off | The MCUmgr serial and shell transports. |
| `zephyr-filesystem-off` | `zephyr` | CVE-2020-13598 (FAT), CVE-2020-13599 (littlefs), CVE-2026-7007 (ext2) | `CONFIG_FILE_SYSTEM_LIB_LINK` off | No file system library is built. |

Things to know about the pack:

- **The Mbed TLS Kconfig rules need Zephyr's own configuration file.** Zephyr turns its
  Kconfig symbols into Mbed TLS options in one file, `config-mbedtls.h`. So the rules also
  check that `CONFIG_MBEDTLS_CFG_FILE` is `"config-mbedtls.h"`, and that
  `CONFIG_CUSTOM_MBEDTLS_CFG_FILE` and `CONFIG_MBEDTLS_USER_CONFIG_ENABLE` are off. This
  matters for MCUboot: it switches to its own file, `mcuboot-mbedtls-cfg.h`, when it uses
  TinyCrypt, or Mbed TLS that is not built in. One case these checks cannot see: an
  application that puts its own file named `config-mbedtls.h` earlier on the include path
  shadows Zephyr's. Do not use the pack's Mbed TLS rules for such a build.
- **The Mbed TLS Kconfig rules are for Zephyr v4.2 and earlier.** Zephyr v4.3 renamed the
  symbols they rely on, so they match Mbed TLS versions before 3.6.5 only (Zephyr v4.2 ships
  3.6.4).
- **No PSA Crypto rule.** With TF-M (`CONFIG_BUILD_WITH_TFM`), PSA Crypto is built from the
  same Mbed TLS module into the secure image, even when the application's
  `CONFIG_MBEDTLS_PSA_CRYPTO_C` is off. On boards without TrustZone, the `.config` does not
  mention `CONFIG_BUILD_WITH_TFM` at all, so a build cannot prove TF-M is absent.
- **The TLS client and server rules rarely fire on a TLS image.** Zephyr has no switch for
  the TLS client or server alone, and the linker keeps both: `mbedtls_ssl_handshake_step`
  calls both state machines. The TLS sample in `fixtures/`, a server, links the client
  handshake too. So these rules fire only when that side's handshake really is not in the
  image, which on stock Zephyr usually means the image does not use TLS at all. From the
  command line they always leave their findings unresolved, as they need the linker map.
- **The Bluetooth list is a snapshot.** It holds every Zephyr CVE whose description names a
  file under `subsys/bluetooth/`. grype 0.119.0 matched them on 2026-10-03 (UTC), with the
  vulnerability database built 2026-09-29. It scanned Zephyr 4.4.2
  (`cpe:2.3:o:zephyrproject:zephyr:4.4.2`, from `fixtures/zephyr/bt`) and Zephyr 4.2.0
  (`…:4.2.0`, from `fixtures/zephyr-old-mbedtls/old-mbedtls`). grype skips CPE matching for
  a component typed as an operating system, which is how rollcall types `zephyr`. So the
  SBOMs were scanned with that component retyped as a library.
  `scripts/capture-findings.sh --bluetooth-cves` repeats this and prints the list. Newer
  Bluetooth CVEs are not covered until they are added.
- **MCUmgr:** the bug in CVE-2026-10648 is in `serial_util.c`. The UART transports (they need
  `CONFIG_UART_MCUMGR`) and the shell transport (it needs `CONFIG_SHELL`) build that file, so
  both must be off. The test-only dummy transports do not build it. The CVE affects Zephyr
  4.4.0 only.
- **File systems:** `CONFIG_FILE_SYSTEM` is not enough on its own. FAT, littlefs and ext2
  are under `CONFIG_FILE_SYSTEM_LIB_LINK`, which can be set without it.
- **Scanners and Zephyr:** for the reason above, grype reports no Zephyr CVEs for rollcall's
  SBOMs today. The Zephyr rules apply as soon as a scanner reports them; the examples below
  use small hand-written findings files for now.

## Checking your rules

`rollcall vex lint` checks that every `kconfig_off` and `kconfig_equals` symbol in your rules
exists, so a typo cannot silently disable a rule. It also reports a rule id that another
file, or the starter pack, already uses:

```sh
rollcall vex lint my-rules.yml --starter-rules --kconfig build/app/zephyr/.config
rollcall vex lint my-rules.yml --zephyr-tree ~/zephyrproject/zephyr
```

It needs a list of known symbols, from one of these (not both):

- `--kconfig FILE`: the symbols written in a build's `.config`. This works offline. But a
  `.config` lists only the symbols that build could see, so lint may warn about a valid
  symbol that a dependency hid. Give the `.config` of more builds, or use `--zephyr-tree`.
- `--zephyr-tree DIR`: the symbols a Zephyr checkout's Kconfig files define. This is the
  authoritative list for that Zephyr version. Repeat it to accept the symbols of several
  releases.

`--starter-rules` loads the starter pack so its rule ids are checked against yours. Its own
symbols are always checked with `--zephyr-tree`. With `--kconfig` they are checked only if
you add `--lint-starter-symbols` (which cannot be combined with `--zephyr-tree`): a build
without Mbed TLS hides all the Mbed TLS symbols.

Lint also warns about a `kconfig_equals` value such as `true`, `no` or `~`: YAML may suggest
it, but a `.config` writes a bool as `y`, `n` or `m`, so the condition would never be true.

Each warning goes to stderr, one per line, and a summary goes to stdout. The exit code is 0
when there is no warning and 1 when there is any. It is 64 for a usage error (no rules, no
symbol list, or both lists), 65 for a malformed rules file, `.config` or tree `VERSION`, and
66 for a missing one.

The starter pack is clean against the `.config` files of all the builds under `fixtures/`
(`--lint-starter-symbols`, as CI checks), and against a Zephyr v4.2.0 tree. Against a Zephyr
v4.3 or later tree, lint warns about `CONFIG_CUSTOM_MBEDTLS_CFG_FILE`: that symbol is gone
there, and the Mbed TLS rules it guards do not apply to those releases anyway.

## Worked examples

Each example uses a real build from `fixtures/` and a CVE that really affects that build's
version. Every command below runs in CI (`scripts/check-doc-examples.sh`), from a scratch
directory where `fixtures/` and `crates/` are the repository's. The text after a command is
its exact output; warnings on stderr are not shown.

### Example 1: TLS 1.3 compiled out of Mbed TLS

#### Input

The build `fixtures/zephyr-old-mbedtls/old-mbedtls` is Zephyr v4.2.0 with MCUboot. Both
images contain Mbed TLS 3.6.4. grype reports 13 Mbed TLS CVEs for it, including
CVE-2026-34873 (client impersonation while resuming a TLS 1.3 session). The findings file is
real grype output. First make the SBOM:

```console
$ rollcall generate --zephyr fixtures/zephyr-old-mbedtls/old-mbedtls --sysbuild \
    --west-list fixtures/zephyr-old-mbedtls/old-mbedtls/west-list.txt \
    --identifier-db crates/rollcall-identifiers/db/identifiers.yaml \
    --timestamp 2026-01-02T03:04:05Z -o old-mbedtls.cdx.json
$ grep -n -e TLS_VERSION_1_3 -e 'MBEDTLS_CFG_FILE=' fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/zephyr/.config
289:CONFIG_MBEDTLS_CFG_FILE="config-mbedtls.h"
299:# CONFIG_MBEDTLS_TLS_VERSION_1_3 is not set
```

#### Rule

From the starter pack:

```yaml
- id: mbedtls-tls13-compiled-out
  match:
    name: mbedtls
    cves: [CVE-2026-34873]
    versions: "<3.6.5"
  when:
    - kconfig_off: CONFIG_MBEDTLS_TLS_VERSION_1_3
    - kconfig_equals: {CONFIG_MBEDTLS_CFG_FILE: config-mbedtls.h}
    - kconfig_off: CONFIG_CUSTOM_MBEDTLS_CFG_FILE
    - kconfig_off: CONFIG_MBEDTLS_USER_CONFIG_ENABLE
  status: not_affected
  justification: code_not_present
  detail: >-
    TLS 1.3 is compiled out: the image uses Zephyr's config-mbedtls.h
    (CONFIG_MBEDTLS_CFG_FILE) with CONFIG_MBEDTLS_TLS_VERSION_1_3 not set, so
    MBEDTLS_SSL_PROTO_TLS1_3 is not defined and the TLS 1.3 code, session resumption
    included, is not built.
```

#### Resulting statement

One statement per image, each citing that image's own `.config`:

```console
$ rollcall vex --sbom old-mbedtls.cdx.json \
    --kconfig mbedtls=fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr-old-mbedtls/old-mbedtls/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/zephyr-old-mbedtls.grype.json \
    --starter-rules \
  | jq '.statements[] | select(.vulnerability == "CVE-2026-34873") | {vulnerability, component: .component.name, status, justification, detail, evidence}'
{
  "vulnerability": "CVE-2026-34873",
  "component": "mbedtls",
  "status": "not_affected",
  "justification": "code_not_present",
  "detail": "TLS 1.3 is compiled out: the image uses Zephyr's config-mbedtls.h (CONFIG_MBEDTLS_CFG_FILE) with CONFIG_MBEDTLS_TLS_VERSION_1_3 not set, so MBEDTLS_SSL_PROTO_TLS1_3 is not defined and the TLS 1.3 code, session resumption included, is not built.",
  "evidence": [
    "mbedtls/zephyr/.config:288: CONFIG_CUSTOM_MBEDTLS_CFG_FILE is not set",
    "mbedtls/zephyr/.config:289: CONFIG_MBEDTLS_CFG_FILE is \"config-mbedtls.h\"",
    "mbedtls/zephyr/.config:299: CONFIG_MBEDTLS_TLS_VERSION_1_3 is not set",
    "mbedtls/zephyr/.config:360: CONFIG_MBEDTLS_USER_CONFIG_ENABLE is not set"
  ]
}
{
  "vulnerability": "CVE-2026-34873",
  "component": "mbedtls",
  "status": "not_affected",
  "justification": "code_not_present",
  "detail": "TLS 1.3 is compiled out: the image uses Zephyr's config-mbedtls.h (CONFIG_MBEDTLS_CFG_FILE) with CONFIG_MBEDTLS_TLS_VERSION_1_3 not set, so MBEDTLS_SSL_PROTO_TLS1_3 is not defined and the TLS 1.3 code, session resumption included, is not built.",
  "evidence": [
    "mcuboot/zephyr/.config:23: CONFIG_MBEDTLS_CFG_FILE is \"config-mbedtls.h\"",
    "mcuboot/zephyr/.config:376: CONFIG_CUSTOM_MBEDTLS_CFG_FILE is not set",
    "mcuboot/zephyr/.config:386: CONFIG_MBEDTLS_TLS_VERSION_1_3 is not set",
    "mcuboot/zephyr/.config:453: CONFIG_MBEDTLS_USER_CONFIG_ENABLE is not set"
  ]
}
```

With `--format cyclonedx` the same decision is `analysis.state: not_affected` and
`analysis.justification: code_not_present`; OpenVEX calls the justification
`vulnerable_code_not_present`.

### Example 2: Bluetooth switched off

#### Input

Two Zephyr v4.4.2 builds with MCUboot: `fixtures/zephyr/baseline` (no Bluetooth) and
`fixtures/zephyr/bt` (a Bluetooth beacon). CVE-2026-11368 is a use-after-free in the
Bluetooth host's ATT layer, and NVD lists Zephyr 4.4.0 and later, before 4.5.0, as affected. The findings
file is hand-written in grype's format (see [Starter pack](#starter-pack) for why).

```console
$ rollcall generate --zephyr fixtures/zephyr/baseline --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o baseline.cdx.json
$ rollcall generate --zephyr fixtures/zephyr/bt --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o bt.cdx.json
$ jq -c '.matches[] | [.vulnerability.id, .artifact.purl]' \
    crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-bluetooth.grype.json
["CVE-2026-11368","pkg:github/zephyrproject-rtos/zephyr@v4.4.2"]
$ grep -n -e '^CONFIG_BT=' -e '^# CONFIG_BT is' fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    fixtures/zephyr/bt/beacon/zephyr/.config
fixtures/zephyr/baseline/with_mcuboot/zephyr/.config:1111:# CONFIG_BT is not set
fixtures/zephyr/bt/beacon/zephyr/.config:1264:CONFIG_BT=y
```

#### Rule

From the starter pack (CVE list shortened here; the full list is in the file):

```yaml
- id: zephyr-bluetooth-off
  match:
    name: zephyr
    cves: [CVE-2026-11368]
  when:
    - kconfig_off: CONFIG_BT
  status: not_affected
  justification: code_not_present
  detail: >-
    Bluetooth is compiled out: CONFIG_BT is not set, so nothing under
    subsys/bluetooth/ is built.
```

#### Resulting statement

On the baseline build, both images are not affected:

```console
$ rollcall vex --sbom baseline.cdx.json \
    --kconfig with_mcuboot=fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr/baseline/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-bluetooth.grype.json \
    --starter-rules \
  | jq -c '.statements[] | [.vulnerability, .status, .justification, .evidence[0]]'
["CVE-2026-11368","not_affected","code_not_present","with_mcuboot/zephyr/.config:1111: CONFIG_BT is not set"]
["CVE-2026-11368","not_affected","code_not_present","mcuboot/zephyr/.config:1530: CONFIG_BT is not set"]
```

On the beacon, the application builds Bluetooth, so the rule does not apply there and the
finding stays unresolved. MCUboot, which has no Bluetooth, still gets its statement:

```console
$ rollcall vex --sbom bt.cdx.json \
    --kconfig beacon=fixtures/zephyr/bt/beacon/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr/bt/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-bluetooth.grype.json \
    --starter-rules \
  | jq -c '{statements: [.statements[] | .evidence[0]], unresolved: [.unresolved[] | .reason.kind]}'
{"statements":["mcuboot/zephyr/.config:1527: CONFIG_BT is not set"],"unresolved":["no_rule"]}
```

### Example 3: no file system (ext2)

#### Input

CVE-2026-7007 is a divide by zero when Zephyr mounts a crafted ext2 image. NVD lists Zephyr
3.5.0 and later, before 4.5.0, as affected, so the v4.4.2 builds are in range. The baseline build has no
file system. The TLS build (`fixtures/zephyr/tls`, an HTTPS server) does have one in its
application, though not ext2.

```console
$ rollcall generate --zephyr fixtures/zephyr/tls --sysbuild \
    --timestamp 2026-01-02T03:04:05Z -o tls.cdx.json
$ grep -n 'FILE_SYSTEM_LIB_LINK' fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    fixtures/zephyr/tls/http_server/zephyr/.config
fixtures/zephyr/baseline/with_mcuboot/zephyr/.config:1160:# CONFIG_FILE_SYSTEM_LIB_LINK is not set
fixtures/zephyr/tls/http_server/zephyr/.config:1865:CONFIG_FILE_SYSTEM_LIB_LINK=y
```

#### Rule

From the starter pack:

```yaml
- id: zephyr-filesystem-off
  match:
    name: zephyr
    cves: [CVE-2020-13598, CVE-2020-13599, CVE-2026-7007]
  when:
    - kconfig_off: CONFIG_FILE_SYSTEM_LIB_LINK
  status: not_affected
  justification: code_not_present
  detail: >-
    File systems are compiled out: CONFIG_FILE_SYSTEM_LIB_LINK is not set, so no file
    system library (FAT, littlefs, ext2) is built.
```

#### Resulting statement

On the baseline build, both images:

```console
$ rollcall vex --sbom baseline.cdx.json \
    --kconfig with_mcuboot=fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr/baseline/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-ext2.grype.json \
    --starter-rules \
  | jq -c '.statements[] | [.vulnerability, .status, .justification, .evidence[0]]'
["CVE-2026-7007","not_affected","code_not_present","with_mcuboot/zephyr/.config:1160: CONFIG_FILE_SYSTEM_LIB_LINK is not set"]
["CVE-2026-7007","not_affected","code_not_present","mcuboot/zephyr/.config:1580: CONFIG_FILE_SYSTEM_LIB_LINK is not set"]
```

On the TLS build, only MCUboot. The application links file system code, so this rule makes
no claim about it, even though ext2 itself is off there. A narrower rule on
`CONFIG_FILE_SYSTEM_EXT2` could cover that case.

```console
$ rollcall vex --sbom tls.cdx.json \
    --kconfig http_server=fixtures/zephyr/tls/http_server/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr/tls/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-ext2.grype.json \
    --starter-rules \
  | jq -c '.statements[] | [.vulnerability, .status, .justification, .evidence[0]]'
["CVE-2026-7007","not_affected","code_not_present","mcuboot/zephyr/.config:1577: CONFIG_FILE_SYSTEM_LIB_LINK is not set"]
```

### Example 4: a typo in a rule

#### Input

The same baseline build and Bluetooth finding as example 2, with a hand-written rule whose
symbol is misspelt: `CONFIG_BTT` instead of `CONFIG_BT`. No `.config` has `CONFIG_BTT`.

#### Rule

`crates/rollcall-core/tests/data/vex/typo.rules.yml`:

```yaml
- id: zephyr-bluetooth-off-typo
  match:
    name: zephyr
    cves: [CVE-2026-11368]
  when:
    - kconfig_off: CONFIG_BTT
  status: not_affected
  justification: code_not_present
  detail: Bluetooth is compiled out (CONFIG_BTT is not set).
```

#### Resulting statement

None. The condition is unknown, so the finding stays unresolved and says why:

```console
$ rollcall vex --sbom baseline.cdx.json \
    --kconfig with_mcuboot=fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr/baseline/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/starter/zephyr-4.4.2-bluetooth.grype.json \
    --rules crates/rollcall-core/tests/data/vex/typo.rules.yml \
  | jq -c '{statements: (.statements | length), missing: [.unresolved[] | .reason.missing[]]}'
{"statements":0,"missing":["rule `zephyr-bluetooth-off-typo`: kconfig_off: CONFIG_BTT: CONFIG_BTT is not in with_mcuboot/zephyr/.config","rule `zephyr-bluetooth-off-typo`: kconfig_off: CONFIG_BTT: CONFIG_BTT is not in mcuboot/zephyr/.config"]}
```

The lint catches the typo before you ship the rule (its warning is on stderr, shown here with
`2>&1`):

```console
$ rollcall vex lint crates/rollcall-core/tests/data/vex/typo.rules.yml \
    --kconfig fixtures/zephyr/baseline/with_mcuboot/zephyr/.config \
    --kconfig fixtures/zephyr/baseline/mcuboot/zephyr/.config 2>&1 || echo "exit $?"
crates/rollcall-core/tests/data/vex/typo.rules.yml: rule zephyr-bluetooth-off-typo: unknown-kconfig-symbol: unknown Kconfig symbol CONFIG_BTT: not in the given .config files (misspelt, renamed, or hidden by an unmet dependency), so this condition is never true and the rule never applies
1 rules file(s), 1 rule(s), checked against 2 .config file(s); 1 finding(s)
exit 1
```

### Example 5: X.509 writing compiled out of Mbed TLS

#### Input

The old-mbedTLS build and real grype output from example 1. One of its Mbed TLS 3.6.4 CVEs,
CVE-2026-34874, is a NULL pointer write in `mbedtls_x509_string_to_names()`. Only the code
that writes certificates and certificate requests calls it, and that code is built only with
`CONFIG_MBEDTLS_X509_CSR_WRITE_C` or `CONFIG_MBEDTLS_X509_CRT_WRITE_C`. The build has
neither:

```console
$ grep -n -e X509_CSR_WRITE_C -e X509_CRT_WRITE_C fixtures/zephyr-old-mbedtls/old-mbedtls/*/zephyr/.config
fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/zephyr/.config:370:# CONFIG_MBEDTLS_X509_CSR_WRITE_C is not set
fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/zephyr/.config:372:# CONFIG_MBEDTLS_X509_CRT_WRITE_C is not set
fixtures/zephyr-old-mbedtls/old-mbedtls/mcuboot/zephyr/.config:463:# CONFIG_MBEDTLS_X509_CSR_WRITE_C is not set
fixtures/zephyr-old-mbedtls/old-mbedtls/mcuboot/zephyr/.config:465:# CONFIG_MBEDTLS_X509_CRT_WRITE_C is not set
```

#### Rule

From the starter pack:

```yaml
- id: mbedtls-x509-write-compiled-out
  match:
    name: mbedtls
    cves: [CVE-2026-34874]
    versions: "<3.6.5"
  when:
    - kconfig_off: CONFIG_MBEDTLS_X509_CSR_WRITE_C
    - kconfig_off: CONFIG_MBEDTLS_X509_CRT_WRITE_C
    - kconfig_equals: {CONFIG_MBEDTLS_CFG_FILE: config-mbedtls.h}
    - kconfig_off: CONFIG_CUSTOM_MBEDTLS_CFG_FILE
    - kconfig_off: CONFIG_MBEDTLS_USER_CONFIG_ENABLE
  status: not_affected
  justification: code_not_present
  detail: >-
    X.509 writing is compiled out: the image uses Zephyr's config-mbedtls.h
    (CONFIG_MBEDTLS_CFG_FILE) with CONFIG_MBEDTLS_X509_CSR_WRITE_C and
    CONFIG_MBEDTLS_X509_CRT_WRITE_C not set, so MBEDTLS_X509_CREATE_C is not defined and
    mbedtls_x509_string_to_names() is not built.
```

#### Resulting statement

One statement per image:

```console
$ rollcall vex --sbom old-mbedtls.cdx.json \
    --kconfig mbedtls=fixtures/zephyr-old-mbedtls/old-mbedtls/mbedtls/zephyr/.config \
    --kconfig mcuboot=fixtures/zephyr-old-mbedtls/old-mbedtls/mcuboot/zephyr/.config \
    --findings crates/rollcall-core/tests/data/findings/zephyr-old-mbedtls.grype.json \
    --starter-rules \
  | jq -c '.statements[] | select(.rules == ["mbedtls-x509-write-compiled-out"]) | [.vulnerability, .status, .justification, (.evidence[] | select(contains("WRITE")))]'
["CVE-2026-34874","not_affected","code_not_present","mbedtls/zephyr/.config:370: CONFIG_MBEDTLS_X509_CSR_WRITE_C is not set","mbedtls/zephyr/.config:372: CONFIG_MBEDTLS_X509_CRT_WRITE_C is not set"]
["CVE-2026-34874","not_affected","code_not_present","mcuboot/zephyr/.config:463: CONFIG_MBEDTLS_X509_CSR_WRITE_C is not set","mcuboot/zephyr/.config:465: CONFIG_MBEDTLS_X509_CRT_WRITE_C is not set"]
```

The other eleven Mbed TLS CVEs stay unresolved. One of them, CVE-2026-25834, is a TLS client
bug; the starter pack's client rule needs linker-map evidence, which the command line cannot
give yet.

## Glossary

- **SBOM**: a software bill of materials, the list of components in your firmware.
  `rollcall generate` writes one in CycloneDX format.
- **Sysbuild**: Zephyr's way of building several images at once, such as MCUboot and the
  application; `rollcall generate --sysbuild` puts them all in one SBOM.
- **Image**: one program in the firmware, such as the MCUboot bootloader or the
  application. Each has its own `.config` and linker map.
- **Kconfig**: Zephyr's configuration system. A build's settings are in the image's
  `zephyr/.config` file, one `CONFIG_…` symbol per line.
- **purl**: a package URL, a standard name for a component and its version, such as
  `pkg:github/zephyrproject-rtos/zephyr@v4.4.2`.
- **CPE**: the naming scheme NVD uses for products, such as
  `cpe:2.3:o:zephyrproject:zephyr:4.4.2`. Scanners match CVEs to components by purl or CPE.
- **CVE**: a public identifier for one vulnerability, such as CVE-2026-34873.
- **Finding**: one scanner report that a CVE affects a component of the SBOM.
- **Evidence**: a fact from the build that a rule's condition is checked against.
- **VEX statement**: a vulnerability's status for one component, with a justification and
  a detail.
- **`code_not_present`**: the justification "the vulnerable code is not in the product".
- **Unresolved**: a finding no rule decided. rollcall makes no claim about it.
- **PSA Crypto**: the cryptography API Mbed TLS provides alongside its older one; TF-M can
  provide it from a separate, secure image.
