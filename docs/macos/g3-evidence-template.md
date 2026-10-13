# G3 evidence template (sanitized)

Copy this section into Confluence **Research** when validating signed macOS clients. **Never** paste private keys, profile XML, or full provisioning UUIDs tied to secrets.

## Metadata

| Field | Value |
|-------|-------|
| Date (UTC) | |
| Tester | |
| macOS version | |
| SIP status | `csrutil status` → enabled |
| Drifti commit / tag | |
| Binary path (local) | _not committed_ |

## Signing inspection

Command (see repo script):

```sh
./scripts/macos/inspect-signing-metadata.sh /path/to/SignedBinary
```

Record:

| Check | Result |
|-------|--------|
| TeamIdentifier | |
| Authority chain | Developer ID Application → … |
| `com.apple.developer.endpoint-security.client` present | yes / no |
| Other entitlements (names only) | |

## Runtime preflight

| Scenario | Expected | Observed | Pass? |
|----------|----------|----------|-------|
| ES client start with valid profile | Subscribe or explicit ES API success | | |
| ES client without entitlement (control) | Clean failure, no fake coverage | | |
| Network prototype (if applicable) | Connect/listen test per KAN-85 plan | | |

Attach **redacted** log excerpts only (no home paths with usernames if avoidable).

## Approval references (non-secret)

| Stage | Reference |
|-------|-----------|
| Apple grant | Ticket / email id |
| Profile name | |
| Notarization staple id | optional |

## Blocker template (if grant pending)

```text
External dependency: Apple entitlement grant pending since <date>.
KAN-83 remains open; KAN-84/KAN-85 blocked.
Next action: <account holder step>.
```
