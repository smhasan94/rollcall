# rollcall

rollcall is a host-side Rust CLI and GitHub Action that turns firmware build metadata into
CRA-grade CycloneDX 1.6 SBOMs: PURL/CPE identifiers, a subsystem breakdown of the Zephyr kernel
package, bootloader + app + blob merged into one product hierarchy, and VEX statements. A
crypto-inventory module ships as `rollcall assay` and emits a CycloneDX 1.6 CBOM.

Licence: Apache-2.0.

## Plan

The plan lives in Linear, team **Shakooky** (key `SHA`), in two projects:

- **rollcall** — epics SHA-16 through SHA-24. v0.1 (Zephyr only, E1–E7) targets 2026-10-23.
- **rollcall-assay** — epics SHA-25 through SHA-30, starting once rollcall v0.1 ships.

Each epic has sub-issue tickets with **Scope**, **Acceptance criteria** and **Test plan** as
checkboxes, plus due dates. A ticket is Done only when every box is ticked and review has no
blocking findings.

## Workspace layout

One Cargo workspace:

- `rollcall-core` — component-graph model and ingestion.
- `rollcall-cli` — the binary `rollcall` (`generate | validate | merge | vex | scan | assay`).
- `rollcall-assay` — crypto inventory (CBOM), invoked as `rollcall assay`.

Ecosystems, in order: Zephyr first (`west spdx`, `west list`, Kconfig `.config`, MCUboot via
sysbuild), then Cargo, ESP-IDF, PlatformIO.

Distribution: crates.io, GitHub Releases binaries, a `pip install rollcall` wrapper, and the
`rollcall-action` GitHub Action.

## Conventions

- **Deterministic output.** The same input produces a byte-identical SBOM. Sort everything with
  stable keys; derive `bom-ref`s from content, never from randomness or iteration order.
  Timestamps and serial numbers/IDs are overridable (e.g. `--timestamp`) so golden tests are
  stable.
- **Parsers never panic.** Every parser has malformed-input tests (truncated, empty, wrong
  encoding, unexpected types) and returns an error instead of panicking. No `unwrap`/`expect`
  on input-derived data.
- **Golden files are regenerated only by script**, never edited by hand. Review the golden diff
  like code.
- **Fixtures under `fixtures/` come from real builds** via `scripts/regen-fixtures.sh` and are
  never hand-edited. (Hand-written *model* fixtures that a ticket explicitly calls for live
  outside `fixtures/` and say so.)
- **`cargo clippy --all-targets -- -D warnings` is clean**, along with `cargo fmt --check` and
  `cargo test`.
- **Every acceptance criterion and test-plan case has a named test** (or, where the item is not
  testable in code — e.g. a name reservation — a named, re-runnable command whose output is
  recorded on the ticket).
- **One ticket per branch and PR.** Branch name = the ticket's Linear `gitBranchName`; commit
  messages and PR titles carry the ticket ID.

## Per-ticket loop

Run with `/ticket SHA-NN` (see `.claude/commands/ticket.md`). Models: planning and code review
run on Claude Fable 5.1 (`planner`, `reviewer`); implementing and testing run on Claude Opus 5.5
(`implementer`, `verifier`). Summary:

1. **Start** — fetch the ticket, move it to In Progress, check out its `gitBranchName`.
2. **Plan** — the `planner` subagent writes files/functions to create or change; a table mapping
   every AC and test-plan item to the test that proves it; risks. Post as a Linear comment and
   wait for "go" (skip the wait if the user said "autopilot" earlier in the session).
3. **Implement** — delegate the approved plan to the `implementer` subagent.
4. **Verify** — run the `verifier` subagent; FAILs go back to the implementer with evidence
   until every item passes.
5. **Review** — run the `reviewer` subagent; blocking and should-fix findings go to the
   implementer; re-verify anything touched.
6. **Close** — tick the passed checkboxes on Linear, post the verification table and review
   summary as a comment, commit with the ticket ID, open a PR, move the ticket to In Review.

Never tick a box without a verifier PASS backed by evidence from a command that was actually run.
