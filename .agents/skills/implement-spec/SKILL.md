---
name: implement-spec
description: Implements one Drifti SPEC end to end without changing unrelated architecture. Use when claiming a ready Jira task in project KAN, or when the user asks to implement a SPEC, a SPEC-00N contract, or Drifti work driven by an implementation specification.
---

# Implement a Drifti SPEC

Primary rule: Drifti is developed from explicit contracts. Implement the requested SPEC. Do not invent product behavior or silently change architecture.

The Rust workspace is not initialized. Do not add `Cargo.toml`, crate directories, or `drifti` commands unless the current task explicitly asks to initialize the crate or implement that SPEC in code.

## Workflow

Normal implementation work starts from Jira project `KAN`. Do not choose an arbitrary SPEC as the entrypoint. The full lifecycle is in the [Development Playbook](../../../docs/development-playbook.md).

```text
Jira READY task
  ↓
claim (En progreso)
  ↓
Read linked SPEC
  ↓
Identify affected crates
  ↓
Check RFC invariants
  ↓
Plan smallest coherent change
  ↓
Implement
  ↓
Tests
  ↓
fmt / clippy
  ↓
Jira comment + En revisión + phase-validation
  ↓
validate-spec
  ↓
security-review
  ↓
phase-ready-to-merge
```

1. Query project `KAN` with Atlassian MCP and select only a task labeled `ready`.
2. Confirm it has no unresolved **Blocks / is blocked by** dependency. Do not claim an issue labeled `blocked`.
3. Read the task and its linked Confluence SPEC.
4. Move the issue to **En progreso** and comment that it is claimed, including the branch or worktree when available.
5. Read only additional RFC or design context required by that SPEC.
6. Identify the affected crates.
7. Check RFC invariants. Do not change an RFC decision implicitly. If implementation requires an architectural change, surface the conflict.
8. Plan the smallest coherent change.
9. Implement only the task and SPEC scope.
10. Add automated tests for applicable acceptance criteria.
11. Run the relevant tests.
12. When a Rust workspace exists, run `cargo fmt --check`.
13. When supported, run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
14. Comment on Jira with the change summary, affected files or crates, commands run, acceptance-criteria status, and deviations.
15. Move the issue to **En revisión** and set `phase-validation`.
16. Hand off to [validate-spec](../validate-spec/SKILL.md), then [security-review](../security-review/SKILL.md).

Skip this Jira lifecycle only for a read-only investigation the user requested, when the user explicitly says not to use Jira, or when the work repairs the Jira or Atlassian integration.

Do not implement future SPECs opportunistically unless the current SPEC requires them.

## Context order

Load context in this order. Do not load every product document.

1. [Development Playbook](../../../docs/development-playbook.md), for workflow and agent rules.
2. The SPEC linked from the claimed Jira task, as the implementation contract.
3. Referenced dependency SPECs, only when their public types or behavior are needed.
4. RFC-001, only for architectural boundaries relevant to the change.
5. Design System, when CLI, output, or product language is affected.
6. PRD, only when product intent remains ambiguous.

## Before coding

- Summarize the affected crates.
- Identify the acceptance criteria.
- Identify architectural risks.

## Rules

- Claim the Jira task before editing code, and keep its status aligned with the work.
- Read the linked SPEC before designing the change.
- Load RFC and Design context only when needed.
- Add automated tests for acceptance criteria when possible.
- Report deviations explicitly.
- `drifti-core` must not depend on Linux APIs, ptrace, SQLite, or CLI rendering.

## Report

- Requirements implemented.
- Affected crates.
- Tests added.
- Commands run.
- Acceptance criteria status.
- Unresolved deviations.
- Any required follow-up SPEC or RFC change.

The session that implemented the change does not declare the SPEC complete. An independent pass uses [validate-spec](../validate-spec/SKILL.md) and [security-review](../security-review/SKILL.md) before the pull request.

Move the issue to **Completado** only after merge or explicit accepted completion. Then inspect directly blocked successors and, when every blocker is complete, remove `blocked` and add `ready`. Do not report the task as finished until Jira shows the current phase.
