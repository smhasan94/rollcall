# Zephyr subsystem table

`crates/rollcall-core/db/subsystems.yaml` maps each Zephyr subsystem that rollcall reports as
its own component to the Kconfig symbols that enable it and the source paths that implement it.
It ships next to the identifier database (`crates/rollcall-core/db/identifiers.yaml`) and is
compiled into rollcall. It is hand-maintained; it is not a build fixture.

The loader and lint are `rollcall_core::subsystems`; its module docs are the reference.

## Schema

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
      - subsys/bluetooth/host     # a directory or a single file
    module: null                  # optional: the west project whose library this wraps
    cpe: null                     # optional: the subsystem's own CPE
    reasons: [cve-history, size]  # at least one
    rationale: >-                 # the evidence for the reasons
      ...
```

### Reasons

Each entry says why it is its own component rather than part of the Zephyr kernel package:

| Reason             | Meaning |
|--------------------|---------|
| `cve-history`      | The code itself (not an upstream library it wraps) has had CVEs. Cite their IDs (`CVE-YYYY-N`) in the rationale; each must be listed in the pinned tree's `doc/security/vulnerabilities.rst` (checked by the tree tests). |
| `size`             | The sources hold more than 2,000 lines of C at the pinned revision (checked by the tree tests). |
| `upstream-library` | The entry wraps a separately versioned upstream project (named by `module`) that scanners and VEX track on their own, under its own identity. The entry must still own Zephyr-side `.c` files (the glue); a module with no glue in the Zephyr tree is not a subsystem. |

Source paths may nest (a file inside another entry's directory; the more specific path is the
better match), but two entries may not list the same path.

## Enabling symbols and compiled files

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

## Lint rules

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
| `bad-module` | `module` is not a west project name |
| `bad-cpe` | `cpe` is not a valid CPE |

Against the pinned Zephyr checkout:

| Rule | Fails when |
|------|-----------|
| `unknown-symbol` | no `config`/`menuconfig` stanza in a `Kconfig*` file defines the symbol (outside `.git` and the top-level `doc`, `samples` and `tests`; `Kconfig.defconfig*` files only set defaults and are skipped) |
| `unknown-source` | the path does not exist |
| `pin-mismatch` | the tree's `VERSION` is not the table's tag |

## Adding or changing an entry

1. Find the enabling symbols and source paths in the Zephyr tree at the pinned tag.
2. Add the entry in name order, with its reasons and a rationale that gives the evidence.
3. Run `cargo test -p rollcall-core --test subsystems` (offline: fixtures) and
   `scripts/verify-subsystems.sh` (the pinned tree).

When the fixtures move to a new Zephyr release, update `zephyr.tag` and `zephyr.commit` to
match `fixtures/zephyr/MANIFEST.json` (`table_pin_matches_fixture_manifest` checks it) and re-run
the tree check.

## Checking against the pinned tree

```sh
scripts/verify-subsystems.sh
```

reads the pinned tag and commit from `fixtures/zephyr/MANIFEST.json`, uses the Zephyr checkout
at `$ROLLCALL_ZEPHYR_TREE` (default `.cache/zephyr-workspace/zephyr`, the
`scripts/regen-fixtures.sh` workspace), shallow-clones the tag there if it is missing (network),
refuses a checkout at any other commit, and runs the `#[ignore]`d tree tests of
`crates/rollcall-core/tests/subsystems.rs`. CI runs it in the `subsystems` job.
