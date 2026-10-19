# Drifti on Linux

Drifti v0.1 targets **Linux x86_64** (and other Linux targets the workspace builds on) for observation and verification. macOS builds the CLI but **does not** run `observe` or `verify` yet (see [macOS prerequisites](../macos/README.md)).

## Requirements

- Rust **1.84+** (see root `Cargo.toml` / CI)
- Kernel with ptrace and `/proc` as used by `drifti-observer-linux`
- Permission to trace child processes (check Yama `ptrace_scope` via `drifti doctor`)

Drifti is **not** a sandbox. It records semantic capability evidence and compares runs to a human-reviewed contract.

## Prebuilt binary (GitHub Releases)

Tagged releases publish a **Linux x86_64** tarball (`drifti-<version>-x86_64-unknown-linux-gnu.tar.gz`) and `SHA256SUMS`. See [Releases](https://github.com/lucabecci/drifti/releases). v0.1 tags are marked **pre-release** (early adopters).

```sh
tar -xzf drifti-0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd drifti-0.1.0-x86_64-unknown-linux-gnu
./drifti doctor
```

## Build from source

```sh
git clone https://github.com/lucabecci/drifti.git
cd drifti
cargo build -p drifti-cli --release
```

Binary: `target/release/drifti`

Optional: add that directory to `PATH`, or `cargo install --path crates/drifti-cli --locked` (local install from checkout).

## Quick start

From your project repository:

```sh
drifti init
drifti doctor
drifti observe -- ./your-agent-or-script.sh
drifti learn
drifti generate          # preview proposed drifti.yaml
drifti generate --write  # write proposal; review before trusting
# edit and accept drifti.yaml in git as your capability contract
drifti verify -- ./your-agent-or-script.sh
drifti diff
```

State and traces live under **`.drifti/`** (gitignored). The contract file is **`drifti.yaml`** in the repo root (commit after human review).

## Exit codes (verify / observe)

| Code | Meaning |
|------|---------|
| 0 | Success (or child exit propagated when Drifti does not override) |
| 2 | Usage / actionable CLI error |
| 120 | Internal / preflight failure (e.g. observer not ready) |
| 121 | Capability violation on verify |
| 122 | Incomplete or indeterminate observation coverage |
| 123 | Invalid or unusable `drifti.yaml` |

## MVP limitations (honest)

- Linux ptrace observation often reports **incomplete coverage**. Verify may return **122** even when no explicit violation was seen. That is intentional: Drifti must not claim success without sufficient evidence.
- Policy is deterministic; contracts are **proposals** until you review and trust `drifti.yaml`.
- Prebuilt Linux x86_64 tarballs appear on GitHub Releases when a `v*` tag is pushed; other platforms build from source.

## Tests

```sh
cargo test --workspace --all-targets
```

Linux-only acceptance tests include observer and verify matrices under `crates/drifti-observer-linux` and `crates/drifti-cli`.
