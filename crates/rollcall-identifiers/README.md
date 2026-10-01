# rollcall-identifiers

The identifier database of [rollcall](https://github.com/smhasan94/rollcall): for each Zephyr
module, its upstream project, purl and CPE templates, and how to derive the upstream version
of the fork revision a build pins. `db/identifiers.yaml` is the data; this crate only embeds
it (`rollcall_identifiers::IDENTIFIERS_YAML`). The schema, loader and resolver are in
`rollcall_core::identify`.

## Versioning

The crate version **is** the database's `db_version` (the `db_version:` line of
`db/identifiers.yaml`), independent of rollcall's own version:

- **MINOR** (1.0.0 → 1.1.0): modules added;
- **PATCH** (1.1.0 → 1.1.1): entries fixed (a purl, a CPE, a table row);
- **MAJOR** (1.x → 2.0.0): a schema change. Only a rollcall that reads that schema accepts it.

Each rollcall pins a minimum (`MIN_DB_VERSION`, 1.0.0) and a major version (1), and accepts
any database in that range without a rollcall release. `rollcall identifiers lint` fails when
`db_version` and the crate version differ.

## Installing a newer database without a new rollcall

Each release also ships as `rollcall-identifiers-<db_version>.tar.gz`
(`scripts/package-identifiers.sh`, byte-identical on every run with the same python3/zlib
build; distribution: see https://github.com/smhasan94/rollcall/issues/16), laid out for the
cache directory:

```sh
mkdir -p ~/.cache/rollcall/identifiers        # or $ROLLCALL_CACHE_DIR/rollcall/identifiers
tar -xzf rollcall-identifiers-1.1.0.tar.gz -C ~/.cache/rollcall/identifiers
rollcall --version                            # identifiers 1.1.0 (cache …)
rollcall generate --zephyr build --sysbuild --west-list west-list.txt --identify
```

rollcall uses the newest compatible database in the cache that is newer than the one it
embeds, skipping (on Unix) anything writable by group or others and symlinks out of the
cache. `--identifiers PATH` or `$ROLLCALL_IDENTIFIERS` names one explicitly; the value
`embedded` pins the embedded one.

## Contributing

See `CONTRIBUTING.md` at the repository root: adding a module takes one entry, one row in the
version-table script, and `scripts/lint-identifiers.sh`.

Licence: Apache-2.0.
