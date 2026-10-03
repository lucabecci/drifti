---
name: implement-spec
description: Implements one Drifti SPEC end to end without changing unrelated architecture. Use when the user asks to implement a SPEC, a SPEC-00N contract, or Drifti work driven by an implementation specification.
---

# Implement a Drifti SPEC

Primary rule: Drifti is developed from explicit contracts. Implement the requested SPEC. Do not invent product behavior or silently change architecture.

The Rust workspace is not initialized. Do not add `Cargo.toml`, crate directories, or `drifti` commands unless the current task explicitly asks to initialize the crate or implement that SPEC in code.

## Workflow

```text
Read SPEC
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
Validate acceptance criteria
  ↓
Report
```

1. Read the requested SPEC.
2. Read only additional RFC or design context required by that SPEC.
3. Identify the affected crates.
4. Check RFC invariants. Do not change an RFC decision implicitly. If implementation requires an architectural change, surface the conflict.
5. Plan the smallest coherent change.
6. Implement that change.
7. Add automated tests for applicable acceptance criteria.
8. Run the relevant tests.
9. When a Rust workspace exists, run `cargo fmt --check`.
10. When supported, run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
11. Validate the acceptance criteria.
12. Report incomplete acceptance criteria and deviations.

Do not implement future SPECs opportunistically unless the current SPEC requires them.

## Context order

Load context in this order. Do not load every product document.

1. [Development Playbook](../../../docs/development-playbook.md), for workflow and agent rules.
2. The requested SPEC, as the implementation contract.
3. Referenced dependency SPECs, only when their public types or behavior are needed.
4. RFC-001, only for architectural boundaries relevant to the change.
5. Design System, when CLI, output, or product language is affected.
6. PRD, only when product intent remains ambiguous.

## Before coding

- Summarize the affected crates.
- Identify the acceptance criteria.
- Identify architectural risks.

## Rules

- Read the requested SPEC first.
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
