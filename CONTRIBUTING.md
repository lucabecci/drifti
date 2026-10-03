# Contributing to Drifti

Thanks for your interest in Drifti. The project is authored and maintained by Luca Becci.

Drifti is a local-first tool for capability contracts and drift detection. The CLI is not implemented yet, so contributions at this stage are documentation, governance, and workflow changes.

## License

Drifti is dual licensed under the Apache License, Version 2.0 and the MIT license. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

When source files exist, start them with:

```text
Copyright 2026 Luca Becci
SPDX-License-Identifier: MIT OR Apache-2.0
```

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Report unacceptable behavior to <beccibrian@gmail.com>.

## AI-assisted contributions

Assistance from coding agents is welcome. You remain the author of the change: understand it, test it when there is something to test, and describe it accurately. Do not submit generated changes you cannot explain.

Agents follow the [Development Playbook](docs/development-playbook.md). Normal implementation work starts from a Jira task labeled `ready` in project `KAN`, on a branch named `<type>/<JIRA-KEY>-<short-title-kebab-case>`, then implements that task's SPEC, validates its acceptance criteria, and reviews the security assumptions before opening one pull request for that task. Do not invent product behavior or change an architectural decision inside a code change.

## Conventional Commits

Commit subjects and pull request titles follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

```text
<type>[optional scope][optional !]: <description>

[optional body]

[optional footer(s)]
```

Types:

| Type | Use for |
| --- | --- |
| `feat` | A user-visible addition |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `style` | Formatting that does not change behavior |
| `refactor` | A behavior-preserving restructure |
| `perf` | A performance improvement |
| `test` | Tests only |
| `build` | Build system or dependencies |
| `ci` | Continuous integration |
| `chore` | Maintenance that is not a user-facing change |
| `revert` | Reverting an earlier commit |

Rules:

- Write the description in the imperative mood: `feat: add session handle`.
- Do not end the description with a period.
- Keep the subject within 100 characters.
- A scope, when present, is lowercase: `fix(runtime): handle an empty tool result`.
- Mark a breaking change with `!` after the type or scope, or with a `BREAKING CHANGE:` footer.

Examples:

```text
feat: detect an unseen filesystem capability

fix(contract): keep secret values out of traces

docs: describe the contribution workflow

feat!: change capability contract evaluation
```

A `commit-msg` hook checks the subject locally. Pull request titles are checked in GitHub Actions. Prefer squash merges, and use the pull request title as the squash commit message, so history stays conventional.

### Enable the local hook

Git does not run committed hooks until this clone points at them:

```sh
./scripts/setup-git.sh
```

That sets `core.hooksPath` to `.githooks` and the commit template to `.gitmessage` for this repository only.

## Security

Do not file public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md).
