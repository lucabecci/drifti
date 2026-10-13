# macOS observation prerequisites (SPEC-011)

Drifti’s native macOS lane depends on Apple-granted entitlements and maintainer-controlled signing. Product behavior lives in Confluence; this directory holds **non-secret** preparation and validation material for distribution work.

## Confluence sources

| Document | Purpose |
|----------|---------|
| [SPEC-011 — Native macOS Observation and Launch Readiness](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/4128790) | Implementation contract for the macOS observer lane |
| [RFC-007](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/4128771) | Architecture decisions for native macOS observation |
| [Research — macOS observation](https://lucabecci.atlassian.net/wiki/spaces/~5e5ee73f27b3910afc2fba2c/pages/4685825) | Feasibility and experiment notes (G3 evidence belongs here when sanitized) |

## Repository artifacts

| File | Audience |
|------|----------|
| [signing-prerequisites.md](signing-prerequisites.md) | Maintainers: routes, gates, blockers |
| [account-holder-entitlement-request.md](account-holder-entitlement-request.md) | Account holder: Apple entitlement request package |
| [g3-evidence-template.md](g3-evidence-template.md) | Checklist for closing G3 without leaking secrets |

## Scripts

| Script | Role |
|--------|------|
| [`../../scripts/macos/inspect-signing-metadata.sh`](../../scripts/macos/inspect-signing-metadata.sh) | Read-only inspection of signed binaries (entitlements, Team ID) |

## Security

- Do **not** commit `.p12`, provisioning profiles, API keys, or approval tokens.
- Store credentials only in the maintainer’s approved secret store.
- Agents must **not** submit entitlement requests or accept Apple agreements on behalf of the account holder.
