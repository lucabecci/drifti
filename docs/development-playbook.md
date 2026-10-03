# Drifti Development Playbook

**Purpose:** define how AI-assisted development should operate on Drifti: what context to load, which skills to use, how `AGENTS.md` is structured, how SPEC-driven implementation works, and when multi-agent workflows are appropriate.

**Primary rule:** Drifti is developed from explicit contracts. Agents implement a SPEC; they do not invent product behavior or silently change architecture.

This file is the in-repository copy of the [Development Playbook — Agents, Skills & Workflow](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/163989/Development+Playbook+Agents+Skills+Workflow). The enforced agent instructions live in [AGENTS.md](../AGENTS.md). Project skills live in [`.agents/skills/`](../.agents/skills/).

`drifti-core` is initialized. Do not add other crate directories, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, or nested `AGENTS.md` files unless the current task explicitly asks. Product documents other than this playbook still live in Confluence.

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

`Cargo.toml` and `crates/drifti-core` exist. The other crates are absent until a task explicitly initializes them.

## AGENTS.md strategy

Use a small root `AGENTS.md` for project-wide invariants and add nested `AGENTS.md` files only where a crate has genuinely different rules.

The root [AGENTS.md](../AGENTS.md) is the enforced copy. It keeps this playbook's product guidance and the repository rules this playbook does not replace: Conventional Commits, the license header, and the rule that further crates and toolchain files are added only when a task asks.

### Root AGENTS.md responsibilities

- Source-of-truth precedence.
- Workspace boundaries.
- Security invariants.
- Rust engineering expectations.
- SPEC-driven change workflow.
- Jira task lifecycle.
- Branch, worktree, and pull request lifecycle.
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

`cargo fmt` and `cargo clippy` apply to the existing workspace. Do not add other crates or a toolchain file only to satisfy this checklist.

## Operating principle

> **SPEC → implement → validate → security review → fix → test → PR.**

Keep the workflow small, explicit and repeatable. Add more agent roles or frameworks only after a real bottleneck appears.

## Jira execution layer

**Project:** Drifti (`KAN`) — <https://lucabecci.atlassian.net/jira/software/projects/KAN/boards/1>

Jira is the execution/control layer. Confluence remains the source of truth for product, architecture and SPEC behavior.

### Board model

The current team-managed Kanban board exposes four native statuses:

- **Tareas por hacer**
- **En progreso**
- **En revisión**
- **Completado**

Agent phases that do not have dedicated Jira statuses are represented with labels.

```text
Tareas por hacer + ready
        ↓
En progreso
        ↓
En revisión + phase-validation
        ↓
En revisión + phase-security-review
        ↓
En revisión + phase-ready-to-merge
        ↓
Completado
```

A blocked issue remains in **Tareas por hacer** with label `blocked`. Agents must not claim blocked issues.

### Agent task-claim protocol

1. Query project `KAN` for issues with label `ready`.
2. Check Jira dependency links and confirm the issue is not blocked.
3. Read the linked Confluence SPEC and this Development Playbook.
4. Move the issue to **En progreso** before changing code.
5. Implement only the ticket/SPEC scope.
6. Comment implementation results, tests and acceptance-criteria status in Jira.
7. Move to **En revisión** and replace the phase label with `phase-validation`.
8. After validation, set `phase-security-review`.
9. After validation and security review pass, set `phase-ready-to-merge`.
10. Move to **Completado** only after accepted completion/merge.

### Backlog hierarchy

- Each implementation SPEC is represented by one Jira Epic (`KAN-1` through `KAN-10`).
- Implementation work is represented by Tasks under the corresponding Epic.
- Jira **Blocks** links encode implementation ordering and cross-SPEC dependencies.
- Only tasks that can be started safely receive the `ready` label.

### MVP release groups

| Release | SPECs |
| --- | --- |
| `v0.1-core` | SPEC-001 to SPEC-003 |
| `v0.1-observation` | SPEC-004 to SPEC-006 |
| `v0.1-intelligence` | SPEC-007 to SPEC-008 |
| `v0.1-product` | SPEC-009 to SPEC-010 |

### Recommended MCP prompt

```text
Take the next READY task from Jira project KAN.

Before coding:
1. Verify it has label ready and no unresolved blocking issue.
2. Move it to En progreso.
3. Read the linked Confluence SPEC.
4. Read the Drifti Development Playbook.
5. Identify acceptance criteria and affected crates.

Implement the smallest coherent change.
Run relevant tests, cargo fmt and cargo clippy.

When implementation is complete:
- comment what changed, tests run and acceptance-criteria status,
- move the issue to En revisión,
- set phase-validation,
- do not mark it Completado until validation/security review and merge are complete.
```

## Mandatory Atlassian Task Protocol

**This protocol is mandatory for every implementation task.** Agents must use Atlassian MCP as part of the task lifecycle. The developer should not need to repeat these instructions in each prompt.

### Task source rule

For normal implementation work, an agent must not begin by choosing arbitrary work from the repository or from a SPEC directly.

The default entrypoint is Jira project `KAN`.

```text
Jira READY task
      ↓
claim
      ↓
Confluence context
      ↓
implementation
      ↓
Jira progress update
      ↓
validation
      ↓
security review
      ↓
merge
      ↓
Jira DONE
```

### Mandatory lifecycle

1. Use Atlassian MCP to query project `KAN`.
2. Select only a task carrying label `ready`.
3. Verify the task has no unresolved Jira **Blocks / is blocked by** dependency.
4. Read the task description and its linked Confluence SPEC.
5. Read this Development Playbook if it has not already been loaded in the current agent context.
6. Move the Jira task to **En progreso** before editing code.
7. Comment on the issue that the task has been claimed, including the implementation branch/worktree when available.
8. Implement only the scope described by the task and linked SPEC.
9. Run required tests, `cargo fmt --check` and relevant `cargo clippy`.
10. Comment on Jira with:
    - summary of changes,
    - files/crates affected,
    - tests and commands executed,
    - acceptance criteria status,
    - known limitations or deviations.
11. Move the task to **En revisión** and set label `phase-validation`.
12. Run the `validate-spec` workflow. Add the validation result to Jira.
13. If validation fails, move the issue back to **En progreso**, fix the findings and repeat validation.
14. When validation passes, replace the phase label with `phase-security-review`.
15. Run the `security-review` workflow. Add findings/result to Jira.
16. If security review fails, move back to **En progreso** and resolve findings.
17. When both reviews pass, set `phase-ready-to-merge`.
18. After merge or explicit accepted completion, move the issue to **Completado**.
19. Inspect Jira dependencies. For each directly blocked successor whose blockers are now complete, remove `blocked` and add `ready`.

`cargo fmt` and `cargo clippy` apply to the existing workspace. Do not add other crates or a toolchain file only to satisfy this lifecycle.

### Visibility requirement

Jira must reflect reality. An agent must not keep working while leaving the issue in a stale phase.

- Working on code → **En progreso**.
- Waiting for SPEC validation → **En revisión + phase-validation**.
- Waiting for security review → **En revisión + phase-security-review**.
- Approved and waiting for merge → **En revisión + phase-ready-to-merge**.
- Merged/accepted → **Completado**.

### Exceptions

The Jira lifecycle may be skipped only for:

- read-only investigation explicitly requested by the user,
- very small emergency fixes when the user explicitly says not to create/use Jira work,
- work whose purpose is itself to repair Jira/Atlassian integration.

Otherwise, Atlassian MCP usage is mandatory.

### Agent completion rule

An agent must not report a task as finished until the Jira issue has been updated with the implementation result and current lifecycle phase.

### Mandatory Jira / Atlassian MCP rule for AGENTS.md

The following rule is included in the repository root [AGENTS.md](../AGENTS.md):

```text
## Mandatory Jira task lifecycle

Jira project KAN is the execution source of truth for Drifti development.

For normal implementation work, always use Atlassian MCP.

Before editing code:
1. Take only a Jira task labeled ready.
2. Confirm all blocking Jira dependencies are complete.
3. Read the linked Confluence SPEC.
4. Move the issue to En progreso.
5. Comment that the task has been claimed.

During and after implementation:
- keep Jira status aligned with actual work,
- comment implementation summary, tests and acceptance criteria,
- move to En revisión + phase-validation,
- run validate-spec,
- then phase-security-review,
- then phase-ready-to-merge,
- only move to Completado after merge/accepted completion.

When completing a task, inspect its blocked successors and promote newly unblocked work from blocked to ready.

Do not report implementation work as complete until Jira has been updated.

Exceptions require an explicit user instruction or a read-only investigation task.
```

## Mandatory Branch & Worktree Convention

**This convention is mandatory for every implementation task.** Branch creation is part of the Jira claim lifecycle and must happen before code changes.

### Branch rule

Each Jira implementation task maps to exactly one branch unless the user explicitly approves an exception.

```text
<type>/<JIRA-KEY>-<short-title-kebab-case>
```

Examples:

```text
chore/KAN-11-bootstrap-drifti-core
feat/KAN-12-capability-resource-model
fix/KAN-42-path-normalization-symlink
```

### Allowed branch types

| Type | Use |
| --- | --- |
| `feat` | New product capability or functional behavior. |
| `fix` | Bug fix. |
| `chore` | Bootstrap, tooling, configuration, maintenance. |
| `docs` | Documentation-only changes. |
| `refactor` | Internal code restructuring without new behavior. |
| `test` | Test-only changes. |
| `perf` | Performance-focused changes. |
| `ci` | CI/CD and automation changes. |

### Naming constraints

- The Jira key is mandatory and uppercase, for example `KAN-12`.
- The short title must be concise, descriptive and use kebab-case.
- Do not repeat unnecessary words from the Epic/SPEC name.
- Do not use spaces, underscores or arbitrary personal prefixes.
- Do not reuse the same branch for a later Jira task.

### Creation timing

The sequence is mandatory:

```text
claim Jira task
    ↓
move to En progreso
    ↓
create branch
    ↓
comment branch/worktree on Jira
    ↓
begin code changes
```

Agents must never modify implementation code before the task is claimed and the branch exists.

### Main branch protection rule

Agents must never perform normal implementation work directly on `main`.

Every implementation change must originate from a Jira-linked task branch.

### Parallel work and worktrees

When multiple READY tasks are implemented in parallel, each task must use its own branch and dedicated worktree.

Recommended convention:

```text
branch:
feat/KAN-13-filesystem-normalization

worktree:
../drifti-kan-13
```

Never run multiple implementation agents against the same working tree or branch.

### Jira visibility

The claim comment must include:

- branch name,
- worktree path when used,
- agent/runtime identity when useful.

Example:

```text
Claimed for implementation.

Branch:
feat/KAN-13-filesystem-normalization

Worktree:
../drifti-kan-13
```

### Pull request rule

- Every implementation pull request must reference its Jira key.
- The pull request scope should match one Jira task whenever practical.
- A pull request must not silently include unrelated future tasks.

### Completion rule

After merge or accepted completion:

1. Update Jira with the final implementation result.
2. Move the issue to **Completado**.
3. Inspect blocked successors and promote newly unblocked tasks from `blocked` to `ready`.
4. Do not reuse the merged branch for another task.

### Mandatory AGENTS.md branch rule

The repository root [AGENTS.md](../AGENTS.md) includes the following rule:

```text
## Mandatory branch and worktree lifecycle

Every Jira implementation task must use its own branch.

Before changing code:
1. Claim a READY task from Jira project KAN.
2. Move it to En progreso.
3. Create a branch using:
   <type>/<JIRA-KEY>-<short-title-kebab-case>
4. Comment the branch name in Jira.
5. If parallel work is used, create a dedicated worktree and comment its path.

Allowed branch types:
- feat
- fix
- chore
- docs
- refactor
- test
- perf
- ci

Examples:
- chore/KAN-11-bootstrap-drifti-core
- feat/KAN-12-capability-resource-model
- fix/KAN-42-path-normalization-symlink

Never work directly on main.
Never reuse a task branch for another Jira task.
One Jira task should map to one branch and one focused PR whenever practical.
Every PR must reference the Jira key.

For parallel work, use one dedicated worktree per task/branch.
Recommended worktree naming:
../drifti-kan-<number>

Do not report implementation complete until Jira reflects the final phase and result.
```
