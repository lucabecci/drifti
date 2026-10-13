# Signing and entitlement prerequisites (KAN-83 / SPEC-011 T1)

This task prepares the **maintainer and account-holder package** for macOS Endpoint Security (ES) and the candidate **Network Extension** prototype. It does **not** authorize shipping unratified product behavior or bypassing SIP.

## Distribution route (target)

| Item | Planned value | Notes |
|------|---------------|-------|
| Distribution | **Developer ID Application** + notarization | Outside Mac App Store for developer tooling |
| Primary entitlement | `com.apple.developer.endpoint-security.client` | Requires Apple approval per team |
| Network prototype | **Network Extension** capability (exact profile TBD with Apple) | Separate from ES; used for connect/listen validation (KAN-85) |
| Test machine | Dedicated Mac, **SIP enabled**, standard user + admin for one-time approvals | No standing `csrutil disable` |
| Secret storage | Maintainer password manager / CI secret store | Never Git |

## Proposed bundle identities (draft)

Replace `TEAMID` with the Apple Developer Team ID when known. These IDs are **proposals** until registered in the developer portal and reflected in RFC-007 / Research.

| Component | Bundle ID (draft) | Role |
|-----------|-------------------|------|
| ES client (minimal validation binary) | `dev.drifti.observer.es-client` | KAN-84 preflight: subscribe, process tree, stream lifecycle |
| Network prototype helper | `dev.drifti.observer.net-prototype` | KAN-85: controlled connect/listen observation |
| CLI (existing) | `dev.drifti.cli` (future) | User-facing `drifti` binary; not part of T1 signing proof |

System extension vs **descendants-only ES client** is an open architecture question (RFC-007). T1 should produce evidence for the **smallest** grant that satisfies SPEC-011 AC-01 and AC-15 without over-broad process visibility.

## Approval state machine

Track explicitly in Jira / Confluence Research (no secrets):

```text
[ ] Request prepared     — account-holder package complete (this repo + Confluence)
[ ] Request submitted    — Apple Developer contact / form sent (date, ticket ref)
[ ] Apple grant          — entitlement visible on team; reference ID only
[ ] Provisioning         — profiles created; profile **names** recorded, files in secret store
[ ] Signed runtime OK    — minimal ES client starts under SIP; sanitized log attached
[ ] Network NE usable    — or documented blocker for KAN-85
```

**KAN-83 does not close on “prepared” or “submitted” alone** (SPEC-011 G3). Successors KAN-84 and KAN-85 stay blocked until **Signed runtime OK** (and network route resolved or blocked with evidence).

## Unavailable prerequisites (record honestly)

| Prerequisite | Status (update in Research) | Impact |
|--------------|----------------------------|--------|
| ES client entitlement grant | _Pending account holder_ | Blocks KAN-84 |
| Network Extension profile | _Pending_ | Blocks KAN-85 |
| Developer ID cert in secret store | _Maintainer_ | Blocks reproducible signing |
| Notarization credentials | _Maintainer_ | Blocks distribution smoke |

## Validation (non-destructive)

1. Build or obtain a **minimal** native ES client signed with the approved profile.
2. On the SIP-enabled test Mac, run [`scripts/macos/inspect-signing-metadata.sh`](../../scripts/macos/inspect-signing-metadata.sh) on the binary.
3. Record startup outcome:
   - **Permitted:** ES client loads, subscription attempt returns expected capability (sanitized stdout/stderr snippet in Research).
   - **Missing entitlement:** controlled failure message (no silent success).
4. Repeat for the network prototype binary or record NE blocker.

Do not disable SIP, inject into unrelated processes, or store host traces under `.drifti/` in Git.

## Traceability

| SPEC-011 AC | This document |
|-------------|---------------|
| AC-01 | Account holder route + bundle IDs + approval state machine |
| AC-15 | Signed startup evidence template → [g3-evidence-template.md](g3-evidence-template.md) |

## External dependency

The **account holder** (Luca Becci) must perform Apple submission and hold certificates. Agents prepare text and checklists only.
