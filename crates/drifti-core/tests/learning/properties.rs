// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use drifti_core::learning::{CapabilityAttempt, EligibleExecution, LearningInput};
use drifti_core::observation::Outcome;
use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};

use super::support::{
    baseline_canonical, candidate_scope_canonical, execution_id, failure, mixed, repo_read, success,
};

fn deterministic_runner() -> TestRunner {
    let config = ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
}

fn arb_learning_selection() -> impl Strategy<Value = Vec<EligibleExecution>> {
    prop::collection::vec(
        (
            prop::collection::vec(proptest::char::range('a', 'z'), 1..=8),
            prop::collection::vec(
                (
                    prop::collection::vec(proptest::char::range('a', 'z'), 1..=6),
                    any::<bool>(),
                    any::<u64>(),
                ),
                1..=4,
            ),
        ),
        1..=5,
    )
    .prop_map(|executions| {
        executions
            .into_iter()
            .enumerate()
            .map(|(index, (exec_chars, attempts))| {
                let exec_id = format!("exec-{index}-{}", String::from_iter(exec_chars));
                let attempts = attempts.into_iter().map(|(path_chars, success, seen)| {
                    let path = format!("src/{}.rs", String::from_iter(path_chars));
                    let capability = repo_read(&path);
                    if success {
                        CapabilityAttempt::at(capability, Outcome::Success, seen)
                    } else {
                        CapabilityAttempt::at(capability, Outcome::Failure, seen)
                    }
                });
                EligibleExecution::new(execution_id(&exec_id), attempts)
            })
            .collect::<Vec<_>>()
    })
}

#[test]
fn input_permutation_does_not_change_learning_semantics() {
    let mut runner = deterministic_runner();
    runner
        .run(&arb_learning_selection(), |executions| {
            let forward = LearningInput::select(executions.clone());
            let reverse = LearningInput::select(executions.into_iter().rev());
            prop_assert_eq!(baseline_canonical(&forward), baseline_canonical(&reverse));
            prop_assert_eq!(
                forward.aggregate().canonical_text(),
                reverse.aggregate().canonical_text()
            );
            Ok(())
        })
        .expect("learning permutation");
}

#[test]
fn candidate_input_permutation_is_stable() {
    let paths = ["src/a.rs", "src/b.rs", "src/c.rs", "docs/readme.md"];
    let capabilities: Vec<_> = paths.iter().map(|path| repo_read(path)).collect();
    let forward = candidate_scope_canonical(capabilities.clone());
    let reverse = candidate_scope_canonical(capabilities.into_iter().rev());
    assert_eq!(forward, reverse);
}

#[test]
fn failures_never_enter_baseline_under_permutation() {
    let sensitive = repo_read(".ssh/id_rsa");
    let allowed = repo_read("src/lib.rs");
    let executions = [
        success("run-1", allowed.clone(), 1),
        failure("run-2", sensitive.clone(), 2),
        mixed(
            "run-3",
            [
                CapabilityAttempt::at(allowed.clone(), Outcome::Success, 3),
                CapabilityAttempt::at(sensitive, Outcome::Failure, 4),
            ],
        ),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let selection = order.map(|index| executions[index].clone());
        let input = LearningInput::select(selection);
        let baseline: Vec<_> = input.baseline().iter().cloned().collect();
        assert_eq!(baseline, vec![allowed.clone()]);
    }
}
