# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- Canonical executable identity and CIDR network addresses in `drifti-core`.
- Filesystem anchors and lexical path normalization in `drifti-core`.
- Typed MVP capability actions and resources in `drifti-core`.
- `drifti-core` crate skeleton, serde boundary, and architecture test harness.
- Development Playbook for SPEC-driven agent work, with project skills for implementation, Rust conventions, spec validation, and security review.

### Changed

- Require Jira project KAN as the execution source for implementation tasks, including claim, review phases, and promotion of unblocked successors.
- Require one Jira-linked branch and pull request per implementation task, with a dedicated worktree for parallel work.
