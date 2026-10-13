# Account-holder package: Endpoint Security client entitlement

**Purpose:** text the account holder can adapt when requesting `com.apple.developer.endpoint-security.client` from Apple. Do not send automatically from CI or agents.

## Product summary

**Drifti** is a local-first developer security tool. It learns which capabilities an AI coding agent exercised during a run, turns that into a human-reviewed **capability contract**, and detects **capability drift** on later runs. macOS observation is one platform lane; it is not a consumer surveillance product.

## Why Endpoint Security

Drifti needs deterministic, local observation of **child processes** launched by a developer command (same trust model as Linux ptrace today):

- Filesystem read/write/metadata attempts on observed descendants
- Process execution (spawn tree under the traced root)
- Network connect/listen where the approved prototype applies

Drifti does **not** require kernel patches, SIP off, or global machine monitoring outside the user-invoked observation session.

## Process-tree scope

- **In scope:** descendants of a single user-started root process (the command after `drifti observe -- …`), bounded by SPEC-011.
- **Out of scope:** system-wide daemons, other users’ sessions, keystroke logging, screen capture, arbitrary memory dumps, or exfiltration of file **contents**.

Observation events are semantic (operation + resource identity), aligned with RFC-001. Secret **values** are never persisted.

## Privacy and data handling

- Traces stay under the project’s `.drifti/` directory on the developer machine.
- No default cloud upload; no LLM on the enforcement path.
- Coverage may be `INCOMPLETE` or `UNSUPPORTED`; Drifti must not treat that as authorization success.

## Proposed bundle IDs

| Binary | Bundle ID (draft) |
|--------|-------------------|
| Minimal ES validation client | `dev.drifti.observer.es-client` |
| Future integrated observer | `dev.drifti.observer.macos` (later SPEC) |

Distribution: **Developer ID**, notarized pkg/dmg for developers.

## Open questions for Apple (record answers in Research)

1. **System extension vs in-process ES client** for a developer tool that only traces explicit child trees.
2. Whether **Network Extension** is the correct capability for connect/listen observation vs ES network events alone.
3. Any additional entitlements required when SIP is enabled on macOS 14+ test targets.

## Network Extension (prototype lane)

For KAN-85, the team may need a **Network Extension**–backed prototype on a controlled test machine. Request should state:

- Localhost and lab-only targets during validation
- No interception of third-party user traffic outside the observed agent run
- Explicit teardown when observation ends

Document the chosen profile ID and capability set in Research after Apple responds (names only, not `.provisionprofile` files in Git).

## Submission checklist (account holder)

- [ ] Apple Developer Program membership active for Team ID ______
- [ ] Entitlement request drafted from this page
- [ ] Request submitted (date ______, reference ______)
- [ ] Grant recorded in Research (reference only)
- [ ] Developer ID Application certificate issued and stored in secret store
- [ ] Provisioning profiles created for draft bundle IDs
- [ ] Minimal ES client signed, notarized (if required for test), validated on SIP-enabled Mac
- [ ] Sanitized G3 evidence attached per [g3-evidence-template.md](g3-evidence-template.md)
