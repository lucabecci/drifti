# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## [Unreleased]

### Added

- Deterministic serialization of a version-1 contract into stable `drifti.yaml` text in `drifti-core`.
- Compilation of a parsed version-1 contract into typed filesystem, executable, and network policy rules in `drifti-core`.
- YAML parsing of a version-1 contract document, with an explicit failure for any other version, in `drifti-core`.
- Version-1 contract document model for filesystem, process, and network allow and deny rules in `drifti-core`.
- SPEC-002 evaluation matrix for allow, deny, unknown, action mismatch, resource-domain mismatch, and indeterminate coverage in `drifti-core`.
- Coverage-aware policy evaluation: non-complete coverage returns `INDETERMINATE` and cannot become `ALLOWED`, while an explicit deny still wins, in `drifti-core`.
- Deterministic policy evaluation with deny-over-allow precedence in `drifti-core`.
- Exact and recursive-prefix policy rule matching in `drifti-core`.
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
