# drifti-cli

CLI parsing, orchestration, and rendering live here.

- No domain policy, learning, drift diff, or observer ptrace in this crate.
- No SQLite or Linux-only APIs.
- Command handlers call `ApplicationServices`; do not embed domain rules in `cli.rs`.
