---
name: validate-spec
description: Validates a Drifti implementation against its current SPEC before changing code. Use when the user asks to review a SPEC implementation, check acceptance criteria, or validate scope against SPEC-00N.
---

# Validate a SPEC

Review first. Modify later. Do not edit code in the initial pass.

The same agent that implemented a change does not declare it complete without this independent validation. Read the current SPEC before judging the diff.

## Report

```text
Acceptance Criteria

[PASS] AC-01
[PASS] AC-02
[FAIL] AC-03

Missing:
- normalization property test

Unexpected scope:
- Linux-specific type leaked into drifti-core
```

Return:

- `PASS` or `FAIL` for every acceptance criterion.
- Missing tests.
- Architecture boundary violations.
- Unexpected scope.
- Deterministic or security issues.

Then apply [security-review](../security-review/SKILL.md).

## Boundaries

- A SPEC may refine implementation details and must not silently override an RFC.
- `drifti-core` must not depend on Linux APIs, ptrace, SQLite, or CLI rendering.
- Observed behavior is not authorized behavior.
- A generated contract is a proposal until a human reviews it.

## Definition of done

- [ ] Implementation satisfies the current SPEC.
- [ ] Automatable acceptance criteria have tests.
- [ ] Relevant negative and security tests exist.
- [ ] No architecture boundary was changed silently.
- [ ] `cargo fmt` passes when a Rust workspace exists.
- [ ] `cargo clippy` passes for the affected workspace scope when a Rust workspace exists.
- [ ] Relevant tests pass.
- [ ] This review is clean, or deviations are documented.
- [ ] `security-review` findings are resolved or explicitly accepted.

Do not initialize the Rust toolchain in order to mark `cargo fmt` or `cargo clippy` done.
