---
name: security-review
description: Reviews Drifti changes for false coverage, silent event loss, capability over-generalization, secret persistence, and other observation-security failures. Use when reviewing Drifti security assumptions, observation coverage, policy decisions, or when the user asks for a Drifti security review.
---

# Drifti security review

Attack the security assumptions of the implementation. Do not stop at checking that the happy path works.

Do not describe vulnerability details intended for a public issue or commit. Follow [SECURITY.md](../../../SECURITY.md).

## Review specifically for

- false `COMPLETE` coverage,
- silent event loss,
- TOCTOU assumptions,
- symlink and path normalization bugs,
- unbounded remote memory reads,
- unsafe-code assumptions,
- over-generalized capabilities,
- secret persistence,
- process escape,
- deny/allow precedence errors,
- false security claims.

## Invariants

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

Policy decisions are deterministic. An LLM must not approve a capability, edit a trusted contract, suppress a violation, or sit on the enforcement path.

Prefer the narrowest honest capability. A generated contract is a proposal until a human reviews it. A capability may name a secret such as `AWS_SECRET_ACCESS_KEY`; it must not store the secret value.

## Output

For each finding, name the assumption it breaks, the evidence in the change, and whether it is resolved or must be explicitly accepted.
