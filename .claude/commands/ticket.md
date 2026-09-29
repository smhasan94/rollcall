---
description: Run the plan → implement → verify → review → close loop for one rollcall Linear ticket
argument-hint: SHA-NN
---

Run the per-ticket loop for Linear ticket **$ARGUMENTS** (team Shakooky). Follow `CLAUDE.md`.

## 1. Start

- Fetch $ARGUMENTS from Linear, including its parent epic. Read Scope, Acceptance criteria,
  Test plan and due date.
- Move $ARGUMENTS to **In Progress**.
- From an up-to-date `main`, check out a branch named exactly the ticket's `gitBranchName`.

## 2. Plan

Delegate planning to the `planner` subagent (Claude Fable 5.1), passing the ticket and epic text
verbatim. The plan must contain:

- Files and functions to create or change.
- A table mapping **every** Acceptance-criteria and Test-plan checkbox (verbatim) to the named
  test, script or command that proves it.
- Risks and open questions.

Check the table covers every checkbox before posting; send it back to the planner if not.
Post the plan as a Linear comment on $ARGUMENTS, then stop and wait for the user's "go".
If the user said "autopilot" earlier in this session, proceed without waiting.

## 3. Implement

Delegate the approved plan to the `implementer` subagent, passing the ticket text and the plan
verbatim. Do not implement it yourself.

## 4. Verify

Run the `verifier` subagent with the ticket's checkboxes, the plan's mapping table and the
branch. Send every FAIL back to the `implementer` with the verifier's evidence, then re-verify.
Repeat until every item is PASS. Report any BLOCKED item to the user (e.g. needs credentials or
a human action) instead of looping on it.

## 5. Review

Run the `reviewer` subagent. Send blocking and should-fix findings to the `implementer`; then
re-run the `verifier` on every checkbox whose code or tests were touched. Nits are listed in the
PR, not fixed unless trivial and in scope.

## 6. Close

- Tick on Linear only the checkboxes the verifier recorded as PASS.
- Post a Linear comment with the verification table and the review summary.
- Commit with the ticket ID in the message (e.g. `$ARGUMENTS: <summary>`), push, and open a PR
  titled with the ticket ID whose body contains the verification table and review summary.
- Move $ARGUMENTS to **In Review**.

## Rules

- Never tick a box without a verifier PASS backed by evidence from a command actually run.
- One ticket per branch and PR; never widen scope beyond the ticket.
- Leave BLOCKED or FAIL boxes unticked and say so in the comment and the PR.
