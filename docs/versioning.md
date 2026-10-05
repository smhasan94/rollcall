# Versioning, MSRV and releasing

## Semantic versioning

rollcall follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Every
release is listed in [CHANGELOG.md](../CHANGELOG.md), in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) layout, and has release notes under
[releases/](releases/v0.1.0.md).

What counts as the public interface, and so as a breaking change when it changes
incompatibly:

- the command line: subcommands, flags, their defaults, and the exit codes in the
  [README](../README.md#exit-codes);
- the output formats: the CycloneDX 1.6 document rollcall writes (which fields it fills and the
  `rollcall:` property names), and the versioned JSON shapes (`rollcall-report/1`,
  `rollcall-scan/1`, `rollcall-validate` 1, the diff and the `rollcall-model/1` input);
- determinism: the same input, rollcall version and identifier database give a byte-identical
  SBOM when the timestamp and serial number are fixed (`--timestamp`, `--serial-number`);
- the GitHub Action's inputs and outputs.

**Before 1.0** (the 0.x series), a breaking change bumps the minor version (0.1.x to 0.2.0) and
everything else the patch version. From 1.0 the usual rules apply. Library crates
(`rollcall-core`, `rollcall-assay`, `rollcall-cli`) share the workspace version but their Rust
APIs are not a stable interface before 1.0.

The identifier database is versioned on its own: its `db_version`, which is the
`rollcall-identifiers` crate's version, follows the rules in
[Identifiers](identifiers.md). A new module is a minor release of the database.

## MSRV

The minimum supported Rust version is **Rust 1.91**, the `rust-version` in the workspace
`Cargo.toml`. `cargo install rollcall` works with it or anything newer.

- Raising the MSRV is a minor version bump before 1.0, with a CHANGELOG entry, and the
  `rust-version` in `Cargo.toml` and this page change together (a test checks they agree).
- Development and CI use the toolchain pinned in `rust-toolchain.toml` (1.91.1), which may be
  newer than the MSRV but never older.

## Supported versions

Only the latest minor release gets fixes, including security fixes; see
[SECURITY.md](../SECURITY.md).

## Releasing

The steps, for a release `X.Y.Z` (tag `vX.Y.Z`). Pushing the tag is what publishes, so
everything before it is a pull request like any other.

1. **Changelog and notes.** In `CHANGELOG.md`, move the `[Unreleased]` entries under
   `## [X.Y.Z] - YYYY-MM-DD` and add its link reference. Write the release notes in
   `docs/releases/vX.Y.Z.md`: the release workflow uses that file as the GitHub Release body,
   and the docs site lists it. Set the release date in CHANGELOG.md to the day you tag, and the
   anchor in the release notes' CHANGELOG link to match it (`CHANGELOG.md#xyz---yyyy-mm-dd`,
   GitHub's anchor for the heading); the changelog test fails while they disagree.
2. **Version.** Set `version` in `[workspace.package]` and in the path dependencies of
   `[workspace.dependencies]` in `Cargo.toml` to `X.Y.Z`, and the Python wrapper's version in
   `python/pyproject.toml`; then `cargo update -w`. The changelog test checks that the top
   released entry matches the workspace version.
3. **Check.** From the workspace root:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo deny --all-features --locked check
   RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps --locked
   scripts/build-docs.sh --install && scripts/check-site-links.sh
   ```

4. **Merge, then tag** the merge commit on `main`:

   ```sh
   git tag -a vX.Y.Z -m "rollcall vX.Y.Z"
   git push origin vX.Y.Z
   ```

5. **Watch the tag's workflows.** `release.yml` builds the binaries
   (`rollcall-vX.Y.Z-{linux-amd64,linux-arm64,darwin-universal}.tar.gz`,
   `rollcall-vX.Y.Z-windows-amd64.zip`), writes `SHA256SUMS`, attests their build provenance,
   creates the GitHub Release and publishes the crates and the Python wrapper. `ci.yml` runs
   on the tag too, so `cargo deny check` and `cargo doc` with `-D warnings` are recorded for
   the tagged commit.
6. **After the release.** The docs site deploys from `main` (`docs.yml`); its "Verify live" step
   checks the published pages. Run the clean-machine quickstart against the live site:
   `gh workflow run quickstart-clean.yml` (it follows the published page with the release
   binary, `cargo install` and `pip install`). Move
   [rollcall-example-zephyr](https://github.com/smhasan94/rollcall-example-zephyr) to
   `uses: smhasan94/rollcall/action@vX.Y.Z` with `rollcall-version: vX.Y.Z`. Remove the lines
   of `.lycheeignore` whose pages now exist (the tag, the release, the example repository, the
   live site), so the link check covers them from then on.
