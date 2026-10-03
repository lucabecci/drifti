# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- SPEC-001 property suite for normalization, equality, containment, serialization, and cross-resource rejection in `drifti-core`.
- Policy decisions, allow and deny rules, and evaluation results in `drifti-core`.
- Capability identity limited to action plus normalized resource, with a lossless serde round trip, in `drifti-core`.
- Deterministic resource containment in `drifti-core`, including exact matches and recursive filesystem prefixes.
- Canonical executable identity and CIDR network addresses in `drifti-core`.
- Filesystem anchors and lexical path normalization in `drifti-core`.
- Typed MVP capability actions and resources in `drifti-core`.
- `drifti-core` crate skeleton, serde boundary, and architecture test harness.
- Development Playbook for SPEC-driven agent work, with project skills for implementation, Rust conventions, spec validation, and security review.

### Changed

- Require Jira project KAN as the execution source for implementation tasks, including claim, review phases, and promotion of unblocked successors.
- Require one Jira-linked branch and pull request per implementation task, with a dedicated worktree for parallel work.
