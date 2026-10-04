# Thread draft: Zephyr SBOM gaps

- **Venue:** a new thread in
  [Zephyr GitHub Discussions](https://github.com/zephyrproject-rtos/zephyr/discussions)
  (category "Ideas" or "General"), cross-posted as a short link in the Zephyr Discord
  `#security` channel (<https://chat.zephyrproject.org>), and offered as an agenda item for
  the [Security Working Group](https://github.com/zephyrproject-rtos/zephyr/wiki/Security-Working-Group)
  meeting.
- **Before posting:** replace the relative links to the gap analysis with their URLs on
  GitHub (`https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md`) once it is
  merged, then record the thread's URL in the [outreach log](../zephyr-gaps.md#outreach-log).

## Title

`west spdx` and firmware SBOMs: five gaps, four proposals, and an offer of help

## Post

I build SBOMs for Zephyr products and have been comparing what `west spdx` gives with what
vulnerability management and the EU Cyber Resilience Act need. `west spdx` is a solid base:
file-level hashes and licences, straight from the build system. I wrote up where it stops,
with every claim reproducible from real v4.4.2 build output:
[gap analysis](../zephyr-gaps.md).

The short version:

1. **Identifiers.** Only modules that declare `security.external-references` in
   `module.yml` get a purl or CPE. In a v4.4.2 nRF52840 build that is 2 of 6 (mbedtls,
   tf-psa-crypto). Module versions are fork commits, which scanners cannot look up
   (#117299, #53479). Mbed TLS CVEs are split across two NVD vendors, and the module names
   one.
2. **Subsystems.** Zephyr is one package with one CPE, so a reader cannot tell a Bluetooth
   build from one without Bluetooth, which is what most "not affected" decisions need.
3. **Sysbuild.** Output is per image, with no product-level document, and the default
   namespace is a random UUID per run (#105917; also relevant to RFC #120474).
4. **Blobs.** `module.yml` already describes blobs (path, SHA-256, version, licence), but
   `west spdx` does not include them.
5. **CycloneDX.** Output is SPDX only.

What I would like to propose, each useful on its own:

1. Every manifest module declares external references naming its upstream release.
2. Under sysbuild, `west spdx` writes per-domain documents plus a product document, with an
   identity derived from the build.
3. A shared convention for naming the subsystems built into an image.
4. Guidance on typing the kernel: Zephyr's CPE is part `o`, and some scanners skip
   operating-system components entirely.

I maintain rollcall (Apache-2.0), which reads `west spdx` output and fills these gaps today
as a companion, not a replacement. If it would be welcome, I am happy to contribute a
`west rollcall` extension command (sketched in the write-up, not built yet), or to help
with any of the proposals directly in `west spdx`. Feedback on any of it, including "this
belongs elsewhere", is very welcome.
