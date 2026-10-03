# AGENTS.md

Instructions for coding agents working on Drifti.

The operating workflow is the [Development Playbook](docs/development-playbook.md). Read it before SPEC-driven work. Project skills live in [`.agents/skills/`](.agents/skills/).

## Project

Drifti is a local-first developer tool for capability contracts and drift detection. It learns what authority an AI agent exercised, turns that into a reviewable contract, and checks later runs against it. Luca Becci (<beccibrian@gmail.com>) is the author and maintainer.

Drifti is a Rust developer-security tool for capability contracts and capability drift detection in AI agents. It is not an agent framework, a coding agent, a sandbox, or an observability product that stops at raw events. The core abstractions are the capability, the capability contract, and capability drift.

The Rust toolchain is intentionally not initialized. Do not add `Cargo.toml`, `rust-toolchain.toml`, `src/`, `rustfmt.toml`, `clippy.toml`, crate directories, or other crate files unless the current task explicitly asks to initialize the crate. Do not implement `drifti` commands unless the task asks for that. Do not add a nested `AGENTS.md` until the crate it governs exists.

## Source of truth

Product behavior is defined in this order:

1. Accepted RFCs
2. Implementation SPECs
3. Drifti Design System
4. PRD

A SPEC may refine implementation details but must not silently change an RFC decision. If implementation requires changing an architectural decision, surface the conflict instead of hiding the change in code.

PRD, RFC, Design System, and SPEC text currently live in Confluence. Agents implement a SPEC; they do not invent product behavior.

## Architecture

The MVP workspace is divided into:

- `drifti-core` — portable domain model, policy, learning, and drift logic.
- `drifti-observer` — platform-neutral observation interfaces and semantic events.
- `drifti-observer-linux` — Linux-specific ptrace and `/proc` implementation.
- `drifti-store` — SQLite persistence.
- `drifti-cli` — CLI parsing, orchestration, and rendering.

`drifti-core` must not depend on Linux APIs, ptrace, SQLite, or CLI rendering.

These crates are the target layout. They are not created until a task explicitly initializes the Rust workspace.

## Product constraints

These constraints override convenience:

- Policy decisions are deterministic. An LLM must not approve a capability, edit a trusted contract, suppress a violation, or sit on the enforcement path.
- AI output stays advisory. Label observed fact, deterministic result, and AI interpretation as separate things.
- Prefer the narrowest honest capability. Do not widen `./src/**` into `./**`, or a specific host into `*`, without an explicit reason.
- A generated contract is a proposal until a human reviews it. Observation alone never grants authority.
- Do not store secret values. A capability may name `AWS_SECRET_ACCESS_KEY`; it must not store the key.
- Execution traces belong under `.drifti/` and stay local. Do not commit that directory. `drifti.yaml`, once it exists, is the contract and stays in Git.

## Security invariants

Never silently:

- drop observation events,
- convert incomplete coverage into successful verification,
- treat observed behavior as authorized behavior,
- broaden a capability beyond what evidence supports,
- persist secret values,
- treat an AI explanation as a policy decision.

`UNKNOWN` is not `DENIED`.
`INDETERMINATE` is never success.

The MVP observes and verifies. It is not a sandbox and must not claim to enforce isolation.

## Rust expectations

These apply once the workspace exists:

- Prefer strongly typed domain models, explicit errors, bounded buffers, deterministic behavior, and small interfaces.
- Avoid stringly-typed domain logic.
- Minimize `unsafe`. Every `unsafe` block requires a local `SAFETY` explanation and focused tests around its assumptions.

Use the [`rust-systems`](.agents/skills/rust-systems/SKILL.md) skill when writing or reviewing Rust.

## SPEC-driven changes

Use [`implement-spec`](.agents/skills/implement-spec/SKILL.md) to implement one SPEC.

1. Read the requested SPEC.
2. Read only additional RFC or design context required by that SPEC.
3. Implement the smallest coherent change satisfying it.
4. Add automated tests for applicable acceptance criteria.
5. Run relevant tests.
6. When a Rust workspace exists, run `cargo fmt --check`.
7. When supported, run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
8. Report incomplete acceptance criteria.

Do not implement future SPECs opportunistically unless required for the current one.

Before a SPEC is called done, an independent pass uses [`validate-spec`](.agents/skills/validate-spec/SKILL.md) and [`security-review`](.agents/skills/security-review/SKILL.md). The same session that implemented the change does not declare it complete.

SPEC-001, SPEC-002, and SPEC-003 land sequentially. Do not parallelize work that depends on unresolved shared domain types.

## Testing

Tests must be deterministic.

Network tests use local servers and must not depend on the public internet.

Security-sensitive behavior requires negative tests.

Use property-based tests when invariants matter more than individual examples.

## Canonical vocabulary

Use these terms as written:

- Capability
- Capability Profile
- Capability Contract
- Capability Drift
- Execution
- Evidence
- Coverage
- `ALLOWED`
- `DENIED`
- `UNKNOWN`
- `INDETERMINATE`

## Nested AGENTS.md

Do not create a nested `AGENTS.md` for every crate by default. Add one only when local constraints differ materially from these rules and the crate exists.

`drifti-core/AGENTS.md`, when that crate exists:

```text
No OS-specific concepts.
No storage-specific concepts.
No CLI concepts.

Domain APIs must be typed and deterministic.
Containment and equality semantics require property tests.
```

`drifti-observer-linux/AGENTS.md`, when that crate exists:

```text
Linux-specific code is allowed here.

Every unsupported observation path must degrade coverage.
Never silently drop an event.
Remote process memory reads must be bounded.
Unsafe code requires a SAFETY justification.
Tests use controlled fixture binaries.
```

## Language

Write repository documentation in English.

## Commits

Follow Conventional Commits 1.0.0. The local `commit-msg` hook rejects other subjects, and pull request titles are checked the same way.

```text
<type>[optional scope][optional !]: <description>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

- Use the imperative mood: `feat: detect an unseen filesystem capability`.
- Do not end the subject with a period.
- Keep the subject within 100 characters.
- Use a lowercase scope when one helps: `fix(contract): keep secret values out of traces`.
- Mark a breaking change with `!` or a footer line `BREAKING CHANGE: ...`.

In a fresh clone, enable the hook before committing:

```sh
./scripts/setup-git.sh
```

Human-facing detail lives in [CONTRIBUTING.md](CONTRIBUTING.md). If the hook and that document disagree, the hook is what Git enforces; update both together.

## License header

Once source files exist, start them with:

```text
Copyright 2026 Luca Becci
SPDX-License-Identifier: MIT OR Apache-2.0
```

Contributions are dual licensed under MIT OR Apache-2.0 unless the contributor explicitly states otherwise.

## Safety

- Do not commit secrets, tokens, private keys, or `.drifti/` traces.
- Do not describe vulnerabilities in public issues or commits. Follow [SECURITY.md](SECURITY.md).
- Do not initialize Rust tooling unless the task asks for it.
