// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy evaluation for verify (domain logic stays in drifti-core).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use drifti_core::capability::Capability;
use drifti_core::policy::{CompiledPolicy, Coverage, Decision, Evaluation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySummary {
    pub denied: bool,
    pub indeterminate: bool,
    pub evaluations: Vec<(Capability, Evaluation)>,
}

/// Evaluates each exercised capability. `UNKNOWN` alone is not a violation.
#[must_use]
pub fn evaluate_exercised(
    policy: &CompiledPolicy,
    capabilities: impl IntoIterator<Item = Capability>,
    coverage: Coverage,
) -> VerifySummary {
    let mut denied = false;
    let mut indeterminate = false;
    let mut evaluations = Vec::new();
    for capability in capabilities {
        let evaluation = policy.evaluate(&capability, coverage);
        match evaluation.decision() {
            Decision::Denied => denied = true,
            Decision::Indeterminate => indeterminate = true,
            Decision::Allowed | Decision::Unknown => {}
        }
        evaluations.push((capability, evaluation));
    }
    VerifySummary {
        denied,
        indeterminate,
        evaluations,
    }
}

/// When global coverage is not [`Coverage::Complete`], verification must not succeed
/// unless a deny was already recorded (including zero exercised capabilities).
#[must_use]
pub fn apply_coverage_guard(mut summary: VerifySummary, coverage: Coverage) -> VerifySummary {
    if !coverage.is_complete() && !summary.denied {
        summary.indeterminate = true;
    }
    summary
}

#[cfg(test)]
mod tests {
    use drifti_core::capability::Capability;
    use drifti_core::policy::{CompiledPolicy, Coverage, Rule, RuleId};
    use drifti_core::resource::{FileResource, FilesystemAnchor};

    use super::{apply_coverage_guard, evaluate_exercised};

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn allow_all() -> CompiledPolicy {
        CompiledPolicy::new(vec![Rule::allow(
            RuleId::new("allow-src").expect("id"),
            read("src/**"),
        )])
    }

    #[test]
    fn unknown_without_deny_is_not_violation() {
        let policy = CompiledPolicy::new(Vec::new());
        let summary = evaluate_exercised(&policy, [read("docs/readme.md")], Coverage::Complete);
        assert!(!summary.denied);
        assert!(!summary.indeterminate);
    }

    #[test]
    fn denied_maps_violation() {
        let policy = CompiledPolicy::new(vec![Rule::deny(
            RuleId::new("deny-docs").expect("id"),
            read("docs/**"),
        )]);
        let summary = evaluate_exercised(&policy, [read("docs/readme.md")], Coverage::Complete);
        assert!(summary.denied);
    }

    #[test]
    fn incomplete_coverage_yields_indeterminate_not_denied() {
        let summary = evaluate_exercised(&allow_all(), [read("src/lib.rs")], Coverage::Incomplete);
        assert!(!summary.denied);
        assert!(summary.indeterminate);
    }

    #[test]
    fn empty_exercised_with_incomplete_coverage_is_indeterminate() {
        let summary = apply_coverage_guard(
            evaluate_exercised(&allow_all(), [], Coverage::Incomplete),
            Coverage::Incomplete,
        );
        assert!(!summary.denied);
        assert!(summary.indeterminate);
    }
}
