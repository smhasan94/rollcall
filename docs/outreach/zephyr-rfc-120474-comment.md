# Comment draft: Zephyr RFC #120474

- **Venue:** a comment on
  [zephyrproject-rtos/zephyr#120474](https://github.com/zephyrproject-rtos/zephyr/issues/120474),
  "RFC: Bind authorized safety context to west spdx build outputs using SRAC".
- **Scope:** answers only the RFC's open question "Which build identity should be the
  authoritative product context across sysbuild and multi-image builds?". No tool pitch.
- **Before posting:** the comment's link to the gap analysis is already its URL on GitHub;
  record the comment's URL in the [outreach log](../zephyr-gaps.md#outreach-log).

## Comment

On the open question of which build identity should be the product context under sysbuild,
here is what I see in a v4.4.2 sysbuild build (nrf52840dk, MCUboot plus an application),
in case it helps:

- `west spdx` runs per image directory, so MCUboot and the application each get four
  documents, and nothing at the sysbuild top level says they ship together (#105917).
- By default each run's namespace is `http://spdx.org/spdxdocs/zephyr-<uuid4>`
  (`spdx.py` line 103 in v4.4.2), so regenerating the SBOM for an unchanged build gives a
  new identity. A sidecar bound to that namespace would look stale after a rebuild.
- The sysbuild top level already lists the images and their roles in `build_info.yml`
  (`MAIN`, `BOOTLOADER`).

So one option is to make the product context the sysbuild top level: its image list, plus
each image's documents identified by content (hashes) rather than a random namespace.
Assertions could then bind per image and never leak between images or rebuilds.

The commands and output behind each point are in this
[gap analysis](https://github.com/smhasan94/rollcall/blob/main/docs/zephyr-gaps.md#gap-3-mcuboot-and-sysbuild). On the CycloneDX side, the
SRAC mapping proposed for CycloneDX 2.0 in CycloneDX/specification#1122 points each
assessment at its affected elements (`risks.risks[].affects[]`); a product-level build
identity would give those references one stable subject to attach to.
