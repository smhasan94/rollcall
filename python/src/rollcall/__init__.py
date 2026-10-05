"""The `rollcall` command for pip: downloads the matching rollcall release binary on first run.

The binary comes from the GitHub release `TAG` and is checked against the SHA-256 recorded in
this package at build time (``release.json``) before it is ever run. See ``rollcall._cli``.
"""

# The PEP 440 form of the Rust workspace version; scripts/release-version.sh checks they agree.
__version__ = "0.0.1"
# The GitHub release whose binaries this wrapper runs.
TAG = "v0.0.1"
