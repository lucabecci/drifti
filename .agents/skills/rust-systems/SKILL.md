---
name: rust-systems
description: Applies Drifti systems-programming conventions to Rust code. Use when writing, reviewing, or refactoring Rust in Drifti, including unsafe blocks, error types, bounded buffers, coverage, and platform boundaries.
---

# Drifti Rust conventions

Prefer strongly typed domain models, explicit errors, bounded buffers, deterministic behavior, and small interfaces.

Avoid stringly-typed domain logic.

`drifti-core` is initialized. Do not add other crates unless the current task explicitly asks.

## Boundaries

- `drifti-core` holds the portable domain model, policy, learning, and drift logic. It must not depend on Linux APIs, ptrace, SQLite, or CLI rendering.
- `drifti-observer` holds platform-neutral observation interfaces and semantic events.
- Linux-specific ptrace and `/proc` code belongs in `drifti-observer-linux`.
- SQLite persistence belongs in `drifti-store`.
- CLI parsing, orchestration, and rendering belong in `drifti-cli`.
- Platform-specific behavior stays behind a clear boundary.

## Unsafe and resources

- Minimize `unsafe`.
- Every `unsafe` block requires a local `SAFETY` explanation and focused tests around its assumptions.
- Bound memory and channels.
- Bound remote process memory reads.
- Propagate errors explicitly.

## Coverage

No silent degradation of coverage.

- Every unsupported observation path must degrade coverage.
- Never silently drop an event.
- `UNKNOWN` is not `DENIED`.
- `INDETERMINATE` is never success.

## Tests

- Tests must be deterministic.
- Network tests use local servers and must not depend on the public internet.
- Security-sensitive behavior requires negative tests.
- Use property-based tests when invariants matter more than individual examples.
- Containment and equality semantics in `drifti-core` require property tests.
- Linux observer tests use controlled fixture binaries.

Once source files exist, start them with the license header required by [AGENTS.md](../../../AGENTS.md).
