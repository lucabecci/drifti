# Drifti

Capability contracts and drift detection for AI agents.

Drifti learns what an AI agent actually needs, turns that into an explicit capability contract, and detects when later behavior drifts outside it.

Know when your agents cross the line.

Authored and maintained by Luca Becci.

## Status

The CLI is not implemented, and the Rust toolchain is not initialized. There is nothing to build or install.

## What it does

Drifti sits between observation and enforcement. It answers what authority an agent should have, and whether that authority changed. It does not replace a sandbox, and it is not a coding agent.

```text
Observe → Learn → Capability contract → Verify → Detect drift
```

The trust boundary is deterministic. An LLM is never required to use Drifti, and it never approves a capability or changes a trusted contract.

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
- [LLM-readable index](llms.txt)
