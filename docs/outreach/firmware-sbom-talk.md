# Talk outline and posts: firmware SBOM problems

A short presentation (about 15 minutes) of the problems firmware SBOMs have, and of the
identifier conventions rollcall uses, with a request for feedback on purl type choices.

- **Venues:**
  - CycloneDX: a thread in
    [CycloneDX specification Discussions](https://github.com/CycloneDX/specification/discussions)
    and a link in OWASP Slack `#cyclonedx` (invite: <https://owasp.org/slack/invite>).
  - OpenSSF: offered as a talk at a meeting of the
    [SBOM Everywhere SIG](https://github.com/ossf/sbom-everywhere).
  - Package URL: a thread in
    [purl-spec Discussions](https://github.com/package-url/purl-spec/discussions) with the
    questions in [purl questions](#purl-questions).
- **Before posting:** the links in the talk and posts are already URLs on GitHub;
  record each post's URL in the [outreach log](../zephyr-gaps.md#outreach-log).

## 1. Who I am and why firmware

I build SBOMs for microcontroller firmware (Zephyr, MCUboot, vendor blobs). The EU Cyber
Resilience Act makes these SBOMs mandatory for many products, and today they are mostly
built by hand.

## 2. What a firmware product looks like

One product is several images (bootloader, application, radio firmware), each linking an
RTOS, forked third-party libraries and opaque binaries. The build system knows all of this;
the SBOM should say it.

## 3. Problem: fork revisions

Zephyr and many vendor SDKs build libraries from their own forks, pinned by commit. The
SBOM's version is then a commit hash, and scanners cannot look it up. rollcall keeps the
commit as the version and records the upstream release it carries in the purl, with the
fork's purl kept as evidence ([Gap 1](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md#gap-1-identifiers)).

## 4. Problem: one kernel, many subsystems

The RTOS is one repository and one CPE, but many of its CVEs are in a subsystem (Bluetooth,
networking, USB) that a given build may not include. rollcall emits each built-in subsystem
as a subcomponent with a purl subpath, which makes evidence-backed "code not present" VEX
statements possible ([Gap 2](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md#gap-2-subsystem-split)).

## 5. Problem: blobs

Vendor binaries are shipped but never compiled, so source-based SBOM tools miss them.
rollcall adds them from a manifest as opaque components with a SHA-256
([Gap 4](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md#gap-4-blobs)).

## 6. Problem: one product, several images

Bootloader and application are built together but described separately. rollcall merges
them into one product with content-derived `bom-ref`s, so the same build gives a
byte-identical SBOM ([Gap 3](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md#gap-3-mcuboot-and-sysbuild)).

## 7. The identifier database conventions

- purl: `pkg:generic/<upstream>@<version>?vcs_url=git+<upstream repository>` for C
  libraries that are in no package registry.
- CPE: only when the vendor:product is in the NVD CPE dictionary, never made up, with
  aliases when NVD files one project under two vendors (Mbed TLS).
- Details: [docs/identifiers.md](https://github.com/smhasan94/rollcall/blob/main/docs/identifiers.md).

## 8. What scanners do with these

grype matches these C libraries on their CPE, and it skips CycloneDX `operating-system`
components, so an RTOS typed as an operating system is not scanned. osv-scanner matches on
the purl ecosystem, and neither `pkg:generic` nor `pkg:github` maps to C library advisories
([Scanner behaviour](https://github.com/smhasan94/rollcall/blob/main/docs/identifiers.md#scanner-behaviour)).

## 9. Questions for the community

The four purl and typing questions below, and: is a nested `firmware` component per image
under a `firmware` product the right CycloneDX shape for a multi-image product?

## 10. Where to find it

The gap analysis with reproducible commands ([docs/zephyr-gaps.md](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md)),
and rollcall itself (Apache-2.0).

## purl questions

Title: Purl type for C libraries built from a fork, and for an RTOS kernel

I would like feedback on four choices I made for firmware SBOMs, before they spread
further:

1. **Upstream C libraries with no registry.** Is
   `pkg:generic/mbedtls@3.6.4?vcs_url=git+https://github.com/Mbed-TLS/mbedtls` the right
   form? Or is `pkg:github/Mbed-TLS/mbedtls@v3.6.4` preferred, given that osv-scanner reads
   the `github` type as GitHub Actions?
2. **The fork that was actually built.** Should the fork be its own purl
   (`pkg:github/zephyrproject-rtos/mbedtls@<commit>`), recorded as evidence of the upstream
   one, or expressed as a qualifier on the upstream purl?
3. **Subsystems of one repository.** Is a subpath
   (`pkg:github/zephyrproject-rtos/zephyr@v4.4.2#subsys/bluetooth/host`) an acceptable way
   to name a part of a repository that was built in?
4. **An RTOS kernel.** Should Zephyr be typed as an operating system (matching its NVD CPE
   part `o`) or as a library linked into the application, which is closer to how it is
   built and is what scanners will look at?
