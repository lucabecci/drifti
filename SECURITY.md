# Security policy

Drifti v0.1 is available as **source builds** on Linux; there is no signed or versioned binary release channel yet. Reports are welcome.

## Reporting a vulnerability

Email Luca Becci at <beccibrian@gmail.com>. Do not open a public issue, pull request, or commit that describes the problem.

Include enough detail to reproduce the issue, and an estimate of impact if you have one. You will receive an acknowledgement when the report is seen. Please allow a few days for a first response.

Once the repository is on GitHub, you can also use private vulnerability reporting if it is enabled. Until then, email is the private channel.

## Supported versions

**Supported for security reports:** `main` and the latest v0.1 source tag when published. Pre-release builds from `main` are best-effort; prefer reporting against a commit SHA you run in production.

## Observation data

Drifti is specified to record which capabilities an agent exercised, not the secret values it may have seen. Local traces live under `.drifti/` and are gitignored. A report that the tool stored a credential, token, or secret value is a vulnerability. Send it through the private channel above.
