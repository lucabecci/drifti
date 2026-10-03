# Drifti Development Playbook

**Purpose:** define how AI-assisted development should operate on Drifti: what context to load, which skills to use, how `AGENTS.md` is structured, how SPEC-driven implementation works, and when multi-agent workflows are appropriate.

**Primary rule:** Drifti is developed from explicit contracts. Agents implement a SPEC; they do not invent product behavior or silently change architecture.

This file is the in-repository copy of the [Development Playbook — Agents, Skills & Workflow](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/163989/Development+Playbook+Agents+Skills+Workflow). The enforced agent instructions live in [AGENTS.md](../AGENTS.md). Project skills live in [`.agents/skills/`](../.agents/skills/).

The Rust workspace is not initialized. Do not add `Cargo.toml`, crate directories, or nested crate `AGENTS.md` files unless the current task explicitly asks to initialize them. Product documents other than this playbook still live in Confluence.

## Source of truth

Development decisions follow this precedence:

1. Accepted RFCs
2. Implementation SPECs
3. Drifti Design System
4. PRD

A SPEC may refine implementation details but must not silently override an RFC. If implementation requires changing an architectural decision, surface the conflict and update the architecture deliberately.

### Core project documents

- [PRD-001: Capability contracts for AI agents.](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/393225/PRD-001+Capability+contracts+for+AI+agents.)
- [RFC-001 — Drifti Core Architecture](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/327689/RFC-001+Drifti+Core+Architecture)
- [Design System: Drifti Entire Architecture](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/491534/Design+System+Drifti+Entire+Architecture)
- [Implementation Specs](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/327705/Implementation+Specs)

## Recommended repository structure

```text
drifti/
├── AGENTS.md
├── Cargo.toml
│
├── docs/
│   ├── development-playbook.md
│   └── specs/
│
├── .agents/
│   └── skills/
│       ├── implement-spec/
│       │   └── SKILL.md
│       ├── rust-systems/
│       │   └── SKILL.md
│       ├── validate-spec/
│       │   └── SKILL.md
│       └── security-review/
│           └── SKILL.md
│
└── crates/
    ├── drifti-core/
    │   └── AGENTS.md
    ├── drifti-observer/
    ├── drifti-observer-linux/
    │   └── AGENTS.md
    ├── drifti-store/
    └── drifti-cli/
```

`Cargo.toml` and `crates/` are the target workspace. They are absent until a task explicitly initializes the crate.

## AGENTS.md strategy

Use a small root `AGENTS.md` for project-wide invariants and add nested `AGENTS.md` files only where a crate has genuinely different rules.

The root [AGENTS.md](../AGENTS.md) is the enforced copy. It keeps this playbook's product guidance and the repository rules this playbook does not replace: Conventional Commits, the license header, and the uninitialized Rust toolchain.

### Root AGENTS.md responsibilities

- Source-of-truth precedence.
- Workspace boundaries.
- Security invariants.
- Rust engineering expectations.
- SPEC-driven change workflow.
- Testing expectations.
- Canonical product vocabulary.

### Product guidance the root file must contain

```text
# Drifti Agent Instructions

Drifti is a Rust developer-security tool for capability contracts and capability drift detection in AI agents.

## Source of truth

Product behavior is defined in this order:

1. Accepted RFCs
2. Implementation SPECs
3. Drifti Design System
4. PRD

A SPEC may refine implementation details but must not silently change an RFC decision.

If implementation requires changing an architectural decision, surface the conflict instead of hiding the change in code.

## Architecture

The MVP workspace is divided into:

- drifti-core — portable domain model, policy, learning and drift logic.
- drifti-observer — platform-neutral observation interfaces and semantic events.
- drifti-observer-linux — Linux-specific ptrace and /proc implementation.
- drifti-store — SQLite persistence.
- drifti-cli — CLI parsing, orchestration and rendering.

drifti-core must not depend on Linux APIs, ptrace, SQLite or CLI rendering.

## Security invariants

Never silently:

- drop observation events,
- convert incomplete coverage into successful verification,
- treat observed behavior as authorized behavior,
- broaden a capability beyond what evidence supports,
- persist secret values,
- treat an AI explanation as a policy decision.

UNKNOWN is not DENIED.
INDETERMINATE is never success.

The MVP observes and verifies. It is not a sandbox and must not claim to enforce isolation.

## Rust expectations

Prefer strongly typed domain models, explicit errors, bounded buffers, deterministic behavior and small interfaces.

Avoid stringly-typed domain logic.

Minimize unsafe. Every unsafe block requires a local SAFETY explanation and focused tests around its assumptions.

## SPEC-driven changes

1. Read the requested SPEC.
2. Read only additional RFC/design context required by that SPEC.
3. Implement the smallest coherent change satisfying it.
4. Add automated tests for applicable acceptance criteria.
5. Run relevant tests.
6. Run cargo fmt --check.
7. Run cargo clippy --workspace --all-targets --all-features -- -D warnings when supported.
8. Report incomplete acceptance criteria.

Do not implement future SPECs opportunistically unless required for the current one.

## Testing

Tests must be deterministic.

Network tests use local servers and must not depend on the public internet.

Security-sensitive behavior requires negative tests.

Use property-based tests when invariants matter more than individual examples.

## Canonical vocabulary

Capability
Capability Profile
Capability Contract
Capability Drift
Execution
Evidence
Coverage
ALLOWED
DENIED
UNKNOWN
INDETERMINATE
```

### Nested AGENTS.md

Do not create a nested `AGENTS.md` for every crate by default. Add one only when local constraints differ materially from the root rules, and only once that crate exists.

**drifti-core/AGENTS.md**

```text
No OS-specific concepts.
No storage-specific concepts.
No CLI concepts.

Domain APIs must be typed and deterministic.
Containment and equality semantics require property tests.
```

**drifti-observer-linux/AGENTS.md**

```text
Linux-specific code is allowed here.

Every unsupported observation path must degrade coverage.
Never silently drop an event.
Remote process memory reads must be bounded.
Unsafe code requires a SAFETY justification.
Tests use controlled fixture binaries.
```

## Initial skill catalog

Start with four focused skills. Avoid a large catalog until repeated workflows justify it.

| Skill | Path | Purpose |
| --- | --- | --- |
| `implement-spec` | [SKILL.md](../.agents/skills/implement-spec/SKILL.md) | Implement one SPEC end to end |
| `rust-systems` | [SKILL.md](../.agents/skills/rust-systems/SKILL.md) | Apply Drifti Rust conventions |
| `validate-spec` | [SKILL.md](../.agents/skills/validate-spec/SKILL.md) | Check an implementation against its SPEC |
| `security-review` | [SKILL.md](../.agents/skills/security-review/SKILL.md) | Attack observation and policy assumptions |

### 1. implement-spec

**Purpose:** implement one Drifti SPEC end-to-end without changing unrelated architecture.

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

Core rules:

- Read the requested SPEC first.
- Load RFC/Design context only when needed.
- Do not change RFC decisions implicitly.
- Add automated tests for acceptance criteria when possible.
- Report deviations explicitly.

### 2. rust-systems

**Purpose:** apply Drifti's systems-programming conventions to Rust code.

- Strongly typed APIs.
- Explicit error propagation.
- Bounded memory and channels.
- Minimal unsafe.
- Local SAFETY comments for every unsafe block.
- Platform-specific behavior isolated behind clear boundaries.
- Property tests for domain invariants.
- No silent degradation of coverage.

### 3. validate-spec

**Purpose:** independently validate an implementation against the current SPEC before fixing it.

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

The validator should review first and modify later. The same agent that implemented a change should not immediately declare it complete without an independent validation pass.

### 4. security-review

**Purpose:** attack the security assumptions of an implementation rather than simply checking that it works.

Review specifically for:

- false COMPLETE coverage,
- silent event loss,
- TOCTOU assumptions,
- symlink/path normalization bugs,
- unbounded remote memory reads,
- unsafe-code assumptions,
- over-generalized capabilities,
- secret persistence,
- process escape,
- deny/allow precedence errors,
- false security claims.

## Drifti Spec Loop

Use a small three-role workflow rather than a large agent organization.

```text
SPEC-NNN
                    │
                    ▼
              IMPLEMENTER
              implement-spec
                    │
                    ▼
                code/tests
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
    SPEC REVIEW         SECURITY REVIEW
    validate-spec       security-review
          │                   │
          └─────────┬─────────┘
                    ▼
                 findings
                    │
                    ▼
               IMPLEMENTER
                   fixes
                    │
                    ▼
             final validation
                    │
                    ▼
                   PR
```

### Roles

- **Builder:** implements the current SPEC.
- **Reviewer:** checks acceptance criteria and scope boundaries.
- **Security Reviewer:** challenges security assumptions and missing negative cases.

## BMAD / agent frameworks

Do not introduce a full BMAD-style process initially.

Drifti already has:

- PRD,
- architecture RFC,
- design system,
- implementation SPECs.

The remaining need is execution, validation and security review. A full framework would duplicate planning artifacts and increase ceremony.

If a framework is evaluated later, use only its build/review layer and compare it against the lightweight Drifti Spec Loop. Adopt it only if it measurably improves throughput or review quality.

## Parallel development and worktrees

Parallel agents are useful only after shared primitives stabilize.

### Sequential first

```text
SPEC-001 Capability IR
        ↓
SPEC-002 Policy Engine
        ↓
SPEC-003 Contract Schema
```

These define shared primitives and should land sequentially.

### Parallelize after core boundaries stabilize

Once core contracts are stable, independent work may move to worktrees:

```text
main
 │
 ├── worktree/spec-004-observer-api
 ├── worktree/spec-006-storage
 └── worktree/security-review
```

Do not parallelize work that requires unresolved shared domain types.

## Cursor + Atlassian MCP workflow

### Context-loading rule

For a new implementation task, the agent should fetch context in this order:

1. **This Development Playbook** for workflow and agent rules.
2. **The requested SPEC** as the implementation contract.
3. **Referenced dependency SPECs** only when their public types/behavior are needed.
4. **RFC-001** only for architectural boundaries relevant to the change.
5. **Design System** when CLI/output/product language is affected.
6. **PRD** only when product intent remains ambiguous.

Do not load every Confluence document into every prompt. Use progressive context loading.

### Recommended implementation prompt

```text
Implement SPEC-00N for Drifti.

Use the Drifti Development Playbook as the operating workflow.
Fetch SPEC-00N from Confluence and treat it as the implementation contract.
Fetch only dependency specs or RFC sections required by the change.

Before coding:
- summarize the affected crates,
- identify the acceptance criteria,
- identify any architectural risks.

Then implement the smallest coherent change.
Add deterministic tests for applicable acceptance criteria.
Run fmt, clippy and affected tests.

Do not modify architectural decisions silently.
Do not implement future SPECs unless required by this one.

At completion report:
- requirements implemented,
- tests added,
- commands run,
- acceptance criteria status,
- unresolved deviations.
```

### Recommended review prompt

```text
Validate the current implementation against SPEC-00N.

Do not modify code initially.

Return:
- PASS/FAIL for every acceptance criterion,
- missing tests,
- architecture boundary violations,
- unexpected scope,
- deterministic/security issues.

Then run the Drifti security-review checklist and identify any false guarantees or incomplete observation behavior.
```

## Pull request expectations

Each implementation PR should identify:

- SPEC implemented.
- Affected crates.
- Acceptance criteria completed.
- Tests added.
- Security-relevant assumptions.
- Known limitations.
- Any required follow-up SPEC/RFC change.

## Definition of done for a SPEC

- [ ] Implementation satisfies the current SPEC.
- [ ] Automatable acceptance criteria have tests.
- [ ] Relevant negative/security tests exist.
- [ ] No architecture boundary was changed silently.
- [ ] `cargo fmt` passes.
- [ ] `cargo clippy` passes for affected workspace scope.
- [ ] Relevant tests pass.
- [ ] `validate-spec` review is clean or deviations are documented.
- [ ] `security-review` findings are resolved or explicitly accepted.

`cargo fmt` and `cargo clippy` apply once a Rust workspace exists. Until then, do not initialize the toolchain to satisfy this checklist.

## Operating principle

> **SPEC → implement → validate → security review → fix → test → PR.**

Keep the workflow small, explicit and repeatable. Add more agent roles or frameworks only after a real bottleneck appears.
