# rollcall

rollcall turns firmware build metadata into CRA-grade CycloneDX SBOMs:
https://github.com/smhasan94/rollcall

This package installs the `rollcall` command:

```sh
pip install rollcall
rollcall --version
```

rollcall itself is a Rust binary. On first run this package downloads the release binary for
your platform (Linux x86_64 or aarch64, macOS, Windows x86_64) from the GitHub Release of the
same version, checks it against the SHA-256 recorded in this package when the release was
built, and caches it; later runs start it directly. A download whose checksum does not match
is deleted and the command exits 65 with `rollcall: checksum mismatch for ...`.

- The cache is `$ROLLCALL_CACHE_DIR/rollcall`, else `$XDG_CACHE_HOME/rollcall`, else
  `~/.cache/rollcall` (`%LOCALAPPDATA%\rollcall` on Windows).
- `ROLLCALL_BIN=/path/to/rollcall` runs that binary instead.
- `ROLLCALL_RELEASE_BASE_URL` downloads the release assets from a mirror.

No dependencies; Python 3.9 or newer. Without network access on first run, install the binary
another way: `cargo install rollcall`, or the archives on the GitHub Release.
