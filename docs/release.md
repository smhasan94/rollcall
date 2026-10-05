# Releasing rollcall

A release is a `v<version>` tag on `main`. `.github/workflows/release.yml` does everything
from there: binaries, checksums, the GitHub Release, crates.io, PyPI and the install checks.
This page is the runbook: the one-time setup, the steps for each release, and what to do when
a step fails.

## What a release publishes

| Where | What |
|---|---|
| GitHub Release `v<version>` | `rollcall-v<version>-linux-amd64.tar.gz`, `-linux-arm64.tar.gz` (static, musl), `-darwin-universal.tar.gz` (arm64 + x86_64), `-windows-amd64.zip`, and `SHA256SUMS`; a build-provenance attestation for each asset |
| crates.io | `rollcall-identifiers` (at its own version, the database's `db_version`), `rollcall-core`, `rollcall-assay`, `rollcall` (the binary; `cargo install rollcall`) |
| PyPI (and TestPyPI for a pre-release) | `rollcall`, the wrapper: a pure-Python wheel and sdist at the PEP 440 version (`0.1.0rc1` for `v0.1.0-rc.1`) |

Each archive holds one directory, `rollcall-v<version>-<platform>/`, with the binary, `LICENSE`
and `README.md`; `scripts/package-release.sh` writes it, byte-identical for the same binary
and `SOURCE_DATE_EPOCH` (the tagged commit's time). The binaries are built with
`cargo build --profile dist --locked` (fat LTO, one codegen unit, symbols stripped), with the
build paths remapped.

The wrapper wheel carries `release.json`: the SHA-256 of every platform's asset, taken from
that release's `SHA256SUMS` by `python/scripts/embed-release.py` when the workflow builds it.
The wrapper verifies its one download against it, so the checksum it trusts arrives inside the
wheel pip has already verified, not alongside the binary. A checkout has no `release.json`
(it is gitignored), so a wrapper built from one refuses to download anything.

## One-time setup

Before the first release (each item is done once, by a maintainer, in the registries' and
GitHub's web settings):

1. **crates.io.** `rollcall-identifiers` has never been published, and trusted publishing can
   only be configured for a crate that exists, so publish it once by hand:
   `cargo publish -p rollcall-identifiers --locked`. Then, for each of `rollcall-identifiers`,
   `rollcall-core`, `rollcall-assay` and `rollcall`, add a trusted publisher: repository
   `smhasan94/rollcall`, workflow `release.yml`, environment `crates-io`. (Alternatively, a
   `CARGO_REGISTRY_TOKEN` repository secret with the `publish-update` scope for these crates;
   when it is set the workflow uses it instead of trusted publishing.)
2. **PyPI.** Add a trusted publisher to the `rollcall` project: repository
   `smhasan94/rollcall`, workflow `release.yml`, environment `pypi`.
3. **TestPyPI.** The same, as a pending publisher if the project does not exist there yet,
   with environment `testpypi`.
4. **GitHub.** Create the environments `crates-io`, `pypi` and `testpypi` (Settings →
   Environments). Required reviewers on them are optional: they make every publish wait for an
   approval.

## Making a release

1. Bump the version everywhere it is written, in one commit on a branch:
   - `Cargo.toml`: `[workspace.package] version`, and the `version` of `rollcall-core` and
     `rollcall-assay` in `[workspace.dependencies]`;
   - `python/pyproject.toml`: `version`, in PEP 440 form;
   - `python/src/rollcall/__init__.py`: `__version__` (PEP 440) and `TAG`;
   - `Cargo.lock` (`cargo build` updates it).

   `scripts/release-version.sh check v<version>` must pass; CI's `publish-dry-run` job runs it
   (without the tag) on every change, with `cargo publish --workspace --dry-run --locked` and a
   wheel build.
2. Write the release notes as `docs/releases/v<version>.md`, with the CHANGELOG date and
   anchor set as [Versioning](versioning.md#releasing) describes. The docs site lists the file
   and the release uses it as its body; `release.yml` falls back to GitHub's generated notes
   only if the file is missing.
3. Merge, then tag the merge commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "rollcall v0.1.0"
   git push origin v0.1.0
   ```

4. Watch the `Release` run. Its jobs, in order:
   - **preflight**: `scripts/release-version.sh check "$TAG"` (outputs the version, its PEP 440
     form and whether it is a pre-release), then `cargo publish --workspace --dry-run --locked`;
   - **build** (four runners): build, check `rollcall --version` (and that Linux binaries are
     static), package;
   - **assemble**: `scripts/release-sums.sh dist "$TAG"` (exactly the four assets); if the
     release already has assets (a re-run), `scripts/release-upload.sh adopt` replaces this
     run's with the published ones, so the wheel always embeds what the release serves; the wrapper
     wheel and sdist, the wrapper's unit tests, then the wheel installed in a fresh venv against
     the real assets served locally (`scripts/install-check-pip.sh --wheel`), and a wheel built
     with `embed-release.py --tamper` that must refuse them (`scripts/install-check-tamper.sh`);
   - **github-release** (`scripts/release-upload.sh check`, then `publish`): create the
     release if it does not exist (`--verify-tag`, `--prerelease` for `-alpha`/`-beta`/`-rc`
     versions), then attest and upload the assets, `SHA256SUMS` last, only if the release has
     no assets yet. A release whose `SHA256SUMS` is identical is left alone (no upload, no new
     attestation); one with a different `SHA256SUMS` fails the job, because published assets
     are never replaced;
   - **publish-crates** (`scripts/publish-crates.sh`), and **publish-pypi** (for a
     pre-release after **publish-testpypi**);
   - **install-check** (`install-check.yml`): `cargo install rollcall` and `pip install
     rollcall` (Python 3.9 and 3.12) on Ubuntu 24.04 and macOS 15, a tampered wrapper against
     the published release (`pip-tamper`), and the Windows binary's `--help` on Windows Server
     2025.

A pre-release (`v0.1.0-rc.1`) is published for real on crates.io and PyPI (crates.io has no
test registry), but `cargo install rollcall` and `pip install rollcall` ignore pre-releases
unless the version is given (`cargo install rollcall --version 0.1.0-rc.1`, `pip install
rollcall==0.1.0rc1`).

## When a step fails

Every job is idempotent, so the remedy is to fix the cause and re-run the failed jobs:
`gh run rerun <run-id> --failed`. That re-uses the run's own assets and wheel, so it is the safe
remedy once anything has been published. Actions → Release → Run workflow with the tag (or
"Re-run all jobs") rebuilds the binaries from the tag; use it only for a release whose
github-release job never ran. If the release already has assets, the rebuild is discarded in
favour of the published assets (the binaries are not guaranteed to be byte-identical, and the
wheel on PyPI embeds the published `SHA256SUMS`), so even then nothing published changes.

- **preflight** fails when the tag and the versions disagree; the error names each file. Fix the
  versions, delete and re-push the tag (nothing has been published yet).
- **build** or **assemble**: nothing has been published yet. Fix on `main` and re-tag, or
  re-run if the failure was transient.
- **github-release**: an existing release is kept as it is (notes and edits included). Its
  assets are uploaded only while it has no `SHA256SUMS` (an earlier run stopped part-way), and
  are never replaced afterwards: `release <tag> already has different assets (SHA256SUMS
  differ); a changed binary needs a new version` means a fix needs a new version, not a
  re-upload.
- **publish-crates**: `scripts/publish-crates.sh` asks crates.io for each crate's version first
  and skips those already there, so a re-run continues where the last one stopped. When a
  publish fails it stops and prints, for example:

  ```text
  ::error::publish-crates: cargo publish failed for rollcall-assay 0.1.0 (exit 101); nothing after it was attempted
  publish-crates: published: rollcall-core@0.1.0
  publish-crates: already on crates.io: rollcall-identifiers@1.0.0
  publish-crates: failed: rollcall-assay@0.1.0
  publish-crates: not attempted: rollcall@0.1.0
  ```

  If crates.io does not answer 200 or 404 for a version (an outage, rate limiting) after three
  attempts, it exits 2 without publishing anything more. A crate version, once published, can
  only be yanked, never replaced: a broken one needs a new version.
- **publish-pypi / publish-testpypi** skip files already uploaded, so re-running is safe. Like
  crates.io, PyPI never accepts a different file under a published version.
- **install-check** can fail just after publishing while the indexes catch up (the scripts
  retry for about five minutes). Re-run it alone with Actions → Install check → Run workflow
  (`tag`, and `test_pypi` to install from TestPyPI).

## Database-only releases and name reservations

`rollcall-identifiers` is versioned on its own (its version is the database's `db_version`); a
database-only release is `cargo publish -p rollcall-identifiers` plus the tarball from
`scripts/package-identifiers.sh` (see [Database versions](identifiers.md#database-versions)).
Check the 0.0.1 name reservations with
`ROLLCALL_CRATES_OWNER=<crates.io login> ./scripts/check-names.sh`.

## Checking a release by hand

```sh
scripts/install-check-cargo.sh v0.1.0
scripts/install-check-pip.sh v0.1.0             # --test-pypi for TestPyPI
gh release download v0.1.0 -p SHA256SUMS
python3 python/scripts/embed-release.py --sums SHA256SUMS --tag v0.1.0 --tamper
uv build python --wheel --out-dir tampered
scripts/install-check-tamper.sh v0.1.0 --wheel tampered/*.whl
rm python/src/rollcall/release.json
```

and on Windows, `./scripts/install-check-windows.ps1 -Tag v0.1.0` in PowerShell. The tamper
check needs a wrapper whose `TAG` is the release's (a checkout of the tag).
