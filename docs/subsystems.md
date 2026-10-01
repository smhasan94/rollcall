# Zephyr subsystems

`rollcall generate --zephyr` splits the single `zephyr` component (the Zephyr kernel package,
which covers far more than the kernel) into one subcomponent per subsystem that the build both
enabled in Kconfig and linked into the image: Bluetooth, the IP stack, USB, file systems,
logging, the shell, and so on. Each becomes its own component, with its own source path and,
where one exists, its own CPE, so a scanner or a VEX rule can tell a Bluetooth CVE from a
networking one.

The split is driven by a table, `crates/rollcall-core/db/subsystems.yaml`, which maps each
Zephyr subsystem that rollcall reports as its own component to the Kconfig symbols that enable
it and the source paths that implement it. It is compiled into rollcall and ships only with
it: unlike the identifier database (`crates/rollcall-identifiers/db/identifiers.yaml`, released
on its own with a `db_version`), it describes the pinned Zephyr tree, so it changes with
rollcall's Zephyr pin. It is hand-maintained; it is not a build fixture.

The loader and lint are `rollcall_core::subsystems`; its module docs are the reference. The
split itself is in `rollcall_core::zephyr` (`split.rs`, `objects.rs`), and the GNU ld map
parser is `rollcall_core::linker_map`.

## The split

A subsystem is emitted only when the build *compiled it in* and *linked some of it*. Kconfig
alone is not enough: a symbol can be set while the linker garbage-collects every function of
the subsystem (`--gc-sections`), and an SBOM that lists code that is not in the image sends
vulnerability triage after phantoms. So rollcall cross-checks Kconfig against the linker map.

### Inputs

All from the image build directory:

| File | Used for |
|------|----------|
| `zephyr/.config` | which subsystems are enabled: any of an entry's `symbols` set to `y` or `m` |
| `zephyr/zephyr.map` | which objects were linked: the GNU ld map's `Linker script and memory map` |
| `spdx/build.spdx` | which source files each library was compiled from: `GENERATED_FROM` relationships from each `.a` to `zephyr.spdx` files |
| `spdx/zephyr.spdx` | the source files' paths in the Zephyr repository (`FileName: ./zephyr/subsys/logging/log_core.c`) |

Without `zephyr/zephyr.map` (a warning: `zephyr/zephyr.map: not found; zephyr is not split into
subsystems`), with a map that is not a GNU ld map (a warning), or without `zephyr/.config` (a
warning), `zephyr` is not split. A GNU ld map with a malformed address or size is an error
naming the file and line (exit 65).

### Algorithm

1. **Enabled.** A subsystem is enabled when one of its `symbols` is `y` or `m` in `.config`.
2. **Linked objects.** The map lists every input section the linker placed, as
   `path/libx.a(member.c.obj)`. An object is *linked* when at least one of its sections with a
   non-zero size sits in an allocated output section: sections under `/DISCARD/`, in
   `Discarded input sections`, of size zero, or in non-allocated sections (`.debug_*`,
   `.comment`, `.ARM.attributes`, …) do not count. An archive member listed only under
   `Archive member included …` was pulled in but then garbage-collected.
3. **Attribution.** Each archive member is joined to its source file through `build.spdx`:
   the archive's `GENERATED_FROM` sources, filtered to the one whose file name is the member's
   (`hci_core.c.obj` → `hci_core.c`). This is the only way to attribute `libzephyr.a`, which
   collects files from `lib/os`, `subsys/logging`, `subsys/shell`, `lib/utils` and more. Only
   files of the Zephyr package are used; module libraries (`libmbedtls.a`) belong to their
   module components. Without `build.spdx`, an archive under `zephyr/<dir>/` is taken to hold
   `<dir>/<source>` (CMake's layout) and `libzephyr.a` stays unattributed.
4. **Owner.** Each object's source file belongs to the enabled entry with the most specific
   (longest) source path containing it: `subsys/fs/littlefs_fs.c` goes to `littlefs` when it is
   enabled, else to `filesystem`. An object whose candidate sources (two files of the same name
   in one archive) belong to different subsystems is attributed to none.
5. **Emit.** An enabled subsystem that owns at least one linked object becomes a subcomponent of
   `zephyr`. An enabled subsystem that owns none is dropped, with a note.

### What is emitted

Each emitted subsystem is a `library` component nested under `zephyr`:

| Field | Value |
|-------|-------|
| `name` | the table entry's `name`, e.g. `bluetooth-host` |
| `version`, `supplier` | `zephyr`'s |
| `purl` | `zephyr`'s purl with the entry's primary source path as subpath: `pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/host`. The primary source is the entry's `subpath`, else its first source; set `subpath` when the first source is a directory the subsystem shares (`subsys/bluetooth/common`, `subsys/usb/common`) |
| `cpe` | the entry's `cpe`, if any (never `zephyr`'s, so a scanner does not report every Zephyr CVE again against each subsystem) |
| evidence (`name`) | `kconfig`: each enabling symbol that is set, at `zephyr/.config:<line>`; `linker-map`: the first linked object, at `zephyr/zephyr.map:<line>` of its first section; `west-spdx`: that object's source file, at the `GENERATED_FROM` line of `spdx/build.spdx` |

Subcomponents are nested, so they add no dependency edges (in CycloneDX each is listed in
`dependencies` with an empty `dependsOn`, as every component is). Their `bom-ref`s derive from
their path (product, image, `zephyr`, subsystem), so they are stable across runs. A VEX rule
can target one with `match.subsystem: <name>`.

### Notes and warnings

Decisions that are not problems with the inputs are *notes*, not warnings: the SBOM is
unchanged by them and they are printed only with `rollcall generate --verbose`
(`rollcall generate: note: …`). They are:

- an enabled subsystem with nothing linked, which is not emitted, e.g. (wrapped here):

  ```text
  rollcall generate: note: zephyr/zephyr.map: subsystem bluetooth-host is enabled by
  CONFIG_BT_HCI_HOST (zephyr/.config:LINE) but no object compiled from subsys/bluetooth/common,
  subsys/bluetooth/crypto, subsys/bluetooth/host, subsys/bluetooth/lib, subsys/bluetooth/services
  was linked (N in the map without code or data in the image); not emitted
  ```

- linked objects under a disabled subsystem's sources, which stay in the `zephyr` package
  (see *Enabling symbols and compiled files* below);
- an object whose source is ambiguous between subsystems.

A missing or unusable map or `.config` is a warning, because the SBOM is then less detailed.

## Adding a subsystem

1. Find the enabling symbols and source paths in the Zephyr tree at the pinned tag. Prefer the
   symbol that gates the subsystem's `add_subdirectory`/`zephyr_library` in CMake, and list
   every directory (or single file) that only that subsystem compiles.
2. Add the entry to `crates/rollcall-core/db/subsystems.yaml` in name order, with its reasons
   and a rationale that gives the evidence (see *Schema* and *Reasons* below).
3. Run `cargo test -p rollcall-core --test subsystems` (offline: fixtures) and
   `scripts/verify-subsystems.sh` (the pinned tree).
4. If a fixture build compiles the subsystem in, update the hand-audited list
   `crates/rollcall-core/tests/data/zephyr-subsystems.txt` (read the build's `.config` and the
   memory-map part of its `zephyr.map`, and cite one linked line), then run
   `scripts/regen-golden.sh` and review the golden diff: the new subcomponent appears under
   `zephyr` in each affected golden, and nothing else changes.

## Blobs

Prebuilt vendor binaries are not compiled from Zephyr sources, so the split never attributes
them; they are listed in a blob manifest (`rollcall merge --blob-manifest`, see the README).
A manifest entry's optional `image:` names the image the blob belongs to, and the blob becomes
a dependency of that image instead of the product root. For example, the Nordic SoftDevice
controller library that an nRF Bluetooth application links, and the SoftDevice image flashed
with it:

```yaml
blobs:
  - path: libsoftdevice_controller_multirole.a   # linked into the beacon application
    name: softdevice_controller
    version: 6.1.0
    supplier: Nordic Semiconductor ASA
    kind: library
    image: beacon
  - path: s140_nrf52_7.3.0_softdevice.hex        # name, version, supplier recognised
    image: beacon
```

Each blob is hashed (SHA-256) and marked opaque (`rollcall:opaque`): rollcall does not look
inside it.

## Limitations

- Only GNU ld maps are read. LLVM lld and vendor linkers write other formats: a warning, and no
  split. With link-time optimisation (`-flto`) the map names LTO partitions instead of the
  original objects, so most code is unattributed and those subsystems are dropped with a note.
- `libzephyr.a` members can only be attributed through `spdx/build.spdx`; without it,
  subsystems compiled into `libzephyr.a` (logging, shell, `json`, …) are dropped with a note.
- `zephyr.spdx` names files relative to the west workspace; the Zephyr checkout's path in it
  is taken to be the common directory of the Zephyr package's files.
- Two sources with the same file name in one archive cannot be told apart in the map; when
  they belong to different subsystems the object is attributed to neither (a note).

## The table

### Schema

```yaml
format: rollcall-subsystems/1
zephyr:                           # the Zephyr release every entry was verified against
  tag: v4.4.2
  commit: dccb09599635bdff17633fa7e9dab014b91dce90
subsystems:                       # a sequence, in name order
  - name: bluetooth-host          # [a-z0-9][a-z0-9-]*, unique
    description: Bluetooth LE host
    symbols: [CONFIG_BT_HCI_HOST] # any one set to y or m means compiled in; sorted
    sources:                      # relative to the zephyr repository root; sorted
      - subsys/bluetooth/common   # a directory or a single file
      - subsys/bluetooth/host
    subpath: subsys/bluetooth/host  # optional: the primary source (default: the first)
    module: null                  # optional: the west project whose library this wraps
    cpe: null                     # optional: the subsystem's own CPE
    reasons: [cve-history, size]  # at least one
    rationale: >-                 # the evidence for the reasons
      ...
```

#### Reasons

Each entry says why it is its own component rather than part of the Zephyr kernel package:

| Reason             | Meaning |
|--------------------|---------|
| `cve-history`      | The code itself (not an upstream library it wraps) has had CVEs. Cite their IDs (`CVE-YYYY-N`) in the rationale; each must be listed in the pinned tree's `doc/security/vulnerabilities.rst` (checked by the tree tests). |
| `size`             | The sources hold more than 2,000 lines of C at the pinned revision (checked by the tree tests). |
| `upstream-library` | The entry wraps a separately versioned upstream project (named by `module`) that scanners and VEX track on their own, under its own identity. The entry must still own Zephyr-side `.c` files (the glue); a module with no glue in the Zephyr tree is not a subsystem. |

Source paths may nest (a file inside another entry's directory; the more specific path is the
better match), but two entries may not list the same path.

### Enabling symbols and compiled files

An entry's symbols say when the subsystem *as a whole* is compiled in; they are not a full model
of Zephyr's CMake gating. Files under a subsystem's paths can be compiled while none of its
symbols is set; such files stay in the Zephyr kernel package and are not attributed to the
disabled subsystem. Known cases at the pinned revision:

- `subsys/net/ip`: `net_core.c`, `net_if.c`, `net_timeout.c` and `utils.c` (and more with
  `CONFIG_NET_NATIVE`) are compiled with `CONFIG_NETWORKING` even without `CONFIG_NET_IP`.
- `subsys/bluetooth/common` and `subsys/bluetooth/lib` are compiled with any `CONFIG_BT`,
  including a controller-only build without `CONFIG_BT_HCI_HOST`.
- `subsys/fs/fcb` is compiled with `CONFIG_FCB` even without `CONFIG_FILE_SYSTEM`.
- `subsys/pm/policy/policy_latency.c` is compiled with `CONFIG_PM_POLICY_LATENCY_STANDALONE`
  even without `CONFIG_PM` or `CONFIG_PM_DEVICE`.

The symbols are deliberately not widened to cover these: a wider symbol would claim the whole
subsystem for a build that compiled only a few of its files.

### Lint rules

Every load runs the structural rules; any finding is an error naming the file, the entry's line,
the subsystem and the rule, e.g.
`subsystems.yaml:12: shell: subsystem shell is listed twice (lines 6 and 12) [duplicate-name]`.

| Rule | Fails when |
|------|-----------|
| `wrong-format` | `format` is not `rollcall-subsystems/1` |
| `bad-pin` | the tag is empty or the commit is not 40 lowercase hex digits |
| `duplicate-name` | two entries share a name |
| `bad-name` | a name is not `[a-z0-9][a-z0-9-]*` |
| `not-sorted` | entries, symbols or sources are out of order |
| `empty-description`, `empty-rationale` | the text is empty |
| `empty-symbols`, `empty-sources`, `empty-reasons` | the list is empty |
| `bad-symbol` | a symbol is not `CONFIG_[A-Z0-9_]+` |
| `bad-source-path` | a path is absolute, uses `\`, ends with `/`, or has an empty, `.` or `..` segment |
| `duplicate-symbol`, `duplicate-source`, `duplicate-reason` | something is listed twice (a source in one entry or in two) |
| `bad-subpath` | `subpath` is not one of the entry's `sources` |
| `bad-module` | `module` is not a west project name |
| `bad-cpe` | `cpe` is not a valid CPE |

Against the pinned Zephyr checkout:

| Rule | Fails when |
|------|-----------|
| `unknown-symbol` | no `config`/`menuconfig` stanza in a `Kconfig*` file defines the symbol (outside `.git` and the top-level `doc`, `samples` and `tests`; `Kconfig.defconfig*` files only set defaults and are skipped) |
| `unknown-source` | the path does not exist |
| `pin-mismatch` | the tree's `VERSION` is not the table's tag |

### Changing an entry

Change it in place and follow *Adding a subsystem* from step 3.

When the fixtures move to a new Zephyr release, update `zephyr.tag` and `zephyr.commit` to
match `fixtures/zephyr/MANIFEST.json` (`table_pin_matches_fixture_manifest` checks it) and re-run
the tree check.

### Checking against the pinned tree

```sh
scripts/verify-subsystems.sh
```

reads the pinned tag and commit from `fixtures/zephyr/MANIFEST.json`, uses the Zephyr checkout
at `$ROLLCALL_ZEPHYR_TREE` (default `.cache/zephyr-workspace/zephyr`, the
`scripts/regen-fixtures.sh` workspace), shallow-clones the tag there if it is missing (network),
refuses a checkout at any other commit, and runs the `#[ignore]`d tree tests of
`crates/rollcall-core/tests/subsystems.rs`. CI runs it in the `subsystems` job.
