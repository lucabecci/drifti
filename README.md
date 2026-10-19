# Drifti

Capability contracts and drift detection for AI agents.

Drifti learns what an AI agent actually needs, turns that into an explicit capability contract, and detects when later behavior drifts outside it.

Know when your agents cross the line.

Authored and maintained by Luca Becci.

## Status

**v0.1 MVP — Linux early adopters.** The workspace ships `drifti-core`, `drifti-observer`, `drifti-observer-linux`, `drifti-store`, and the **`drifti` CLI**. Observation and verification run on **Linux** (ptrace). macOS builds the CLI but native observation is not available yet.

There is no published binary release on GitHub yet; build from source (see below).

## Build

Requires Rust **1.84** or newer.

```sh
cargo build -p drifti-cli --release
./target/release/drifti --help
```

Full workspace checks:

```sh
cargo test --workspace --all-targets
```

Linux install and workflow detail: [docs/linux/README.md](docs/linux/README.md).

## Quick start (Linux)

```sh
drifti init
drifti doctor
drifti observe -- ./your-command
drifti learn
drifti generate --write   # review drifti.yaml before trusting
drifti verify -- ./your-command
```

Traces stay under `.drifti/` locally. Put the reviewed contract in `drifti.yaml` and commit it like any other policy file.

## What it does

Drifti sits between observation and enforcement. It answers what authority an agent should have, and whether that authority changed. It does not replace a sandbox, and it is not a coding agent.

```text
Observe → Learn → Capability contract → Verify → Detect drift
```

The trust boundary is deterministic. An LLM is never required to use Drifti, and it never approves a capability or changes a trusted contract.

## Workspace

| Crate | Role |
|-------|------|
| `drifti-core` | Capabilities, policy, contracts, learning, drift |
| `drifti-observer` | Platform-neutral observation types |
| `drifti-observer-linux` | Linux ptrace backend |
| `drifti-store` | SQLite execution history |
| `drifti-cli` | `drifti` command |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

`SPDX-License-Identifier: MIT OR Apache-2.0`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Guidance for coding agents](AGENTS.md)
- [Development Playbook](docs/development-playbook.md)
- [LLM-readable index](llms.txt)
