# Hacker News — draft (Show HN)

**Title (pick one):**

- Show HN: Drifti – capability contracts and drift detection for AI agents (Linux)
- Show HN: Drifti – turn what your agent actually did into a reviewable contract

**Body:**

I built Drifti because agents often run with ambient authority: broad filesystem, network, and process access with no durable record of what was “allowed.”

Drifti observes a command you wrap (`drifti observe -- ./agent.sh`), learns a **capability profile**, helps you draft **`drifti.yaml`**, and on later runs **`drifti verify`** compares behavior to that contract. Drift is explicit: added/removed/changed capabilities, not vibes.

It is **local-first** (SQLite under `.drifti/`), **deterministic** (no LLM on the enforcement path), and **not a sandbox**—it records and checks, it does not isolate.

v0.1 is **Linux-only** (ptrace). Coverage is often incomplete; verify may report indeterminate rather than a false “all good.”

GitHub: https://github.com/lucabecci/drifti  
Site: https://drifti.dev

I’d love feedback from people running agents in CI or on dev machines—especially where contracts would help your review workflow.
