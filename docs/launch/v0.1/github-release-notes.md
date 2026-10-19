# Drifti v0.1.0 — Linux (early adopters)

**Drifti** learns what authority an AI agent actually exercised, turns that into a **human-reviewed capability contract** (`drifti.yaml`), and checks later runs for **capability drift**. It is not a sandbox and not a coding agent.

## Install (Linux x86_64)

Download `drifti-0.1.0-x86_64-unknown-linux-gnu.tar.gz` from the assets below, verify `SHA256SUMS`, then:

```sh
tar -xzf drifti-0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd drifti-0.1.0-x86_64-unknown-linux-gnu
./drifti --help
```

Or build from source: [docs/linux/README.md](https://github.com/lucabecci/drifti/blob/main/docs/linux/README.md).

## Quick start

```sh
drifti init
drifti doctor
drifti observe -- ./your-command
drifti learn
drifti generate --write   # review drifti.yaml before trusting
drifti verify -- ./your-command
```

## What v0.1 includes

- Linux ptrace observation (`observe`, `verify`)
- Local SQLite history (`.drifti/`)
- Contract learning and drift diff against `drifti.yaml`
- Deterministic policy; exit codes 121/122/123 for violation / incomplete / bad contract

## Known limits

- Observation coverage is often **incomplete** on ptrace; verify may exit **122** without a violation—that is intentional.
- **macOS** builds the CLI but does not observe yet.
- Contracts are **proposals** until you review and commit them.

## Links

- Repository: https://github.com/lucabecci/drifti
- Site: https://drifti.dev
- Security: https://github.com/lucabecci/drifti/blob/main/SECURITY.md

MIT OR Apache-2.0
