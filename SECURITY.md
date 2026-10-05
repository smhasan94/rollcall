# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes |
| 0.0.1   | No (name-reservation placeholders, no code) |

Fixes, including security fixes, go into the latest minor release only; see
[docs/versioning.md](docs/versioning.md).

## Reporting a vulnerability

Please report vulnerabilities **privately**, through GitHub's private vulnerability reporting:
open <https://github.com/smhasan94/rollcall/security/advisories/new> (the "Report a
vulnerability" button on the repository's Security tab). GitHub's guide:
[Privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Do not open a public issue, pull request or discussion for a vulnerability.

Include what you can of:

- the affected version (`rollcall --version`) or commit, and how you installed it (release
  binary, `cargo install`, `pip install`, the Action);
- what an attacker can do, and the input or setup that triggers it (a minimal file is best);
- whether it is already public.

## What to expect

- An acknowledgement within 3 working days.
- An assessment, and a fix or a plan, within 30 days of the acknowledgement for confirmed
  issues; a fix or a public statement within 90 days.
- Coordinated disclosure: the fix is released first, then a GitHub security advisory (with a
  CVE where one applies) credits you unless you prefer otherwise.

## Scope

In scope: the `rollcall` binary and crates, the release binaries and their checksums, the
`pip install rollcall` wrapper (download and verification), and the GitHub Action in
`action/`. Examples: a crafted build directory, SBOM, VEX or scanner file that makes rollcall
run code, write outside its output, or hang; a way to make the wrapper or the Action run a
binary that does not match the published `SHA256SUMS`; a token exposed by the Action.

Out of scope: vulnerabilities **in your firmware** that rollcall reports (that is rollcall
working), and inaccurate SBOM content (a wrong version or identifier is a bug; please open an
ordinary issue).

## Dependencies

`cargo deny check` (configuration in `deny.toml`) runs in CI on every pull request, on `main`
and on release tags: it fails on RustSec advisories, yanked crates, licences outside the
allow-list and crates from unknown registries or git sources.
