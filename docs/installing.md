# Installing

Each release (from v0.1.0) ships the same `rollcall` binary three ways:

```sh
# From crates.io: builds from source (Rust 1.91 or newer).
cargo install rollcall --locked

# From PyPI: on first run, downloads the release binary for this platform, checks its
# SHA-256 and caches it.
pip install rollcall

# Or download it from the GitHub Release (static binaries for Linux x86_64 and aarch64, a
# universal binary for macOS, and Windows x86_64), with its checksum.
curl -fsSLO https://github.com/smhasan94/rollcall/releases/download/v0.1.0/rollcall-v0.1.0-linux-amd64.tar.gz
curl -fsSLO https://github.com/smhasan94/rollcall/releases/download/v0.1.0/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf rollcall-v0.1.0-linux-amd64.tar.gz
rollcall-v0.1.0-linux-amd64/rollcall --version
```

The [quickstart](quickstart.md#1-install-rollcall) walks through each route step by step,
including Windows.

## Release binaries

The release assets are `rollcall-<tag>-<platform>.tar.gz` for `linux-amd64`, `linux-arm64`
and `darwin-universal`, and `rollcall-<tag>-windows-amd64.zip`; each holds a directory of the
same name with the binary, `LICENSE` and `README.md`. `SHA256SUMS` lists all four, and each
asset has a GitHub build-provenance attestation (`gh attestation verify <file> --repo
smhasan94/rollcall`). The macOS binary is not notarised: a copy downloaded with a browser is
quarantined by Gatekeeper (`xattr -d com.apple.quarantine rollcall` releases it); `curl`,
`cargo install` and `pip install` are not affected.

## The pip wrapper

The PyPI package (`python/`) is a pure-Python wrapper with no dependencies (Python 3.9 or
newer). Its version is the release's, in PEP 440 form (`0.1.0rc1` for `v0.1.0-rc.1`), and it
holds the SHA-256 of every platform's asset, recorded at release time. The first `rollcall`
command downloads the asset for this platform from the GitHub Release, refuses it unless its
SHA-256 matches (exit 65: `rollcall: checksum mismatch for <asset>: expected <sha256>, got
<sha256>; the download was discarded`), and caches the binary in
`<cache>/rollcall/bin/<tag>/<platform>/`, where `<cache>` is `$ROLLCALL_CACHE_DIR`, else
`$XDG_CACHE_HOME`, else `~/.cache` (`%LOCALAPPDATA%` on Windows), as for the
[identifier database](identifiers.md#database-versions). Later runs start the cached binary
directly. A platform with no release binary, or a download that fails, exits 69.
`ROLLCALL_BIN` runs a given binary instead, and `ROLLCALL_RELEASE_BASE_URL` downloads from a
mirror.

## Name reservations

The 0.0.1 releases of `rollcall`, `rollcall-core`, `rollcall-cli` and `rollcall-assay` on
crates.io and `rollcall` on PyPI are placeholders that reserved the names; later releases
install the real tool. `rollcall-cli` stays a 0.0.1 placeholder: the binary crate is
`rollcall`.
