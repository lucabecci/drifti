# Long-form technical post — outline

**Working title:** From ambient authority to capability contracts: what Drifti v0.1 actually verifies

## 1. Problem

- Agents inherit broad OS authority; reviewers lack a stable artifact for “allowed behavior.”
- Logs show events; they do not give a **contract** or **drift** against an accepted baseline.

## 2. Core concepts (RFC vocabulary)

- Capability, capability profile, capability contract, capability drift
- Observation vs authorization; proposal vs trusted contract

## 3. Architecture (MVP)

- `drifti-observer-linux` → semantic events
- `drifti-store` → local evidence
- `drifti-core` → policy + drift
- `drifti-cli` → observe / learn / generate / verify / diff

## 4. Walkthrough

- `init`, `doctor`, one observed run, learn, generate, human review of YAML, verify second run
- Exit codes: 121 violation, 122 incomplete coverage, 123 bad contract

## 5. Honest limits (v0.1)

- ptrace coverage incomplete; no macOS native observer; not enforcement/isolation
- UNKNOWN vs DENIED; indeterminate ≠ success

## 6. What’s next

- macOS (SPEC-011 deferred), richer coverage, tighter CI stories

## 7. CTA

- GitHub, `docs/linux/README.md`, feedback channels
