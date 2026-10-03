# Security policy

Drifti does not have a published release yet. Reports are still welcome.

## Reporting a vulnerability

Email Luca Becci at <beccibrian@gmail.com>. Do not open a public issue, pull request, or commit that describes the problem.

Include enough detail to reproduce the issue, and an estimate of impact if you have one. You will receive an acknowledgement when the report is seen. Please allow a few days for a first response.

Once the repository is on GitHub, you can also use private vulnerability reporting if it is enabled. Until then, email is the private channel.

## Supported versions

No version is supported yet. `drifti-core` exists, and there is no release.

## Observation data

Drifti is specified to record which capabilities an agent exercised, not the secret values it may have seen. Local traces live under `.drifti/` and are gitignored. A report that the tool stored a credential, token, or secret value is a vulnerability. Send it through the private channel above.
