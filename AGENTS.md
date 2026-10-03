# AGENTS.md

Instructions for coding agents working on Drifti.

## Project

Drifti is a local-first developer tool for capability contracts and drift detection. It learns what authority an AI agent exercised, turns that into a reviewable contract, and checks later runs against it. Luca Becci (<beccibrian@gmail.com>) is the author and maintainer.

Drifti is not an agent framework, a coding agent, a sandbox, or an observability product that stops at raw events. The core abstractions are the capability, the capability contract, and capability drift.

The Rust toolchain is intentionally not initialized. Do not add `Cargo.toml`, `rust-toolchain.toml`, `src/`, `rustfmt.toml`, `clippy.toml`, or other crate files unless the current task explicitly asks to initialize the crate. Do not implement `drifti` commands unless the task asks for that.

## Product constraints

These constraints override convenience:

- Policy decisions are deterministic. An LLM must not approve a capability, edit a trusted contract, suppress a violation, or sit on the enforcement path.
- AI output stays advisory. Label observed fact, deterministic result, and AI interpretation as separate things.
- Prefer the narrowest honest capability. Do not widen `./src/**` into `./**`, or a specific host into `*`, without an explicit reason.
- A generated contract is a proposal until a human reviews it. Observation alone never grants authority.
- Do not store secret values. A capability may name `AWS_SECRET_ACCESS_KEY`; it must not store the key.
- Execution traces belong under `.drifti/` and stay local. Do not commit that directory. `drifti.yaml`, once it exists, is the contract and stays in Git.

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
