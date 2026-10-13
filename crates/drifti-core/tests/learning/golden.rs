// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{
    aggregate, baseline_canonical, candidate_scope_canonical, fixture_duplicate_observations,
    fixture_failed_sensitive_attempt, fixture_repeated_across_runs,
    fixture_repo_generalization_inputs, fixture_sensitive_repo_paths, fixture_stable_presentation,
    presented_canonical, repo_read,
};

#[test]
fn golden_baseline_collapses_duplicate_observations() {
    let input = fixture_duplicate_observations();
    assert_eq!(
        baseline_canonical(&input),
        "filesystem.read file repo src/lib.rs\n"
    );
}

#[test]
fn golden_aggregate_counts_duplicate_observations() {
    let profile = aggregate(&fixture_duplicate_observations());
    assert_eq!(
        profile.canonical_text(),
        "total_eligible_runs 1\n\
         filesystem.read file repo src/lib.rs 1 2 10 20\n"
    );
}

#[test]
fn golden_aggregate_repeated_capability_across_runs() {
    let profile = aggregate(&fixture_repeated_across_runs());
    assert_eq!(
        profile.canonical_text(),
        "total_eligible_runs 3\n\
         filesystem.read file repo src/main.rs 3 3 1 3\n"
    );
}

#[test]
fn golden_failed_attempts_stay_out_of_baseline() {
    let input = fixture_failed_sensitive_attempt();
    assert_eq!(
        baseline_canonical(&input),
        "filesystem.read file repo src/ok.rs\n"
    );
    assert_eq!(input.failed_evidence().count(), 1);
    let profile = aggregate(&input);
    assert_eq!(
        profile.canonical_text(),
        "total_eligible_runs 2\n\
         filesystem.read file repo src/ok.rs 1 1 1 1\n"
    );
}

#[test]
fn golden_repo_generalization_candidate_scope() {
    assert_eq!(
        candidate_scope_canonical(fixture_repo_generalization_inputs()),
        "filesystem.read file repo src/**\n"
    );
}

#[test]
fn golden_sensitive_paths_stay_exact_in_candidate_scope() {
    assert_eq!(
        candidate_scope_canonical(fixture_sensitive_repo_paths()),
        "filesystem.read file repo .ssh/id_rsa\n\
         filesystem.read file repo .ssh/known_hosts\n"
    );
}

#[test]
fn golden_presented_profile_stable_class() {
    assert_eq!(
        presented_canonical(&fixture_stable_presentation()),
        "total_eligible_runs 4\n\
         filesystem.read file repo src/stable.rs runs=4 obs=4 class=stable\n"
    );
}

#[test]
fn golden_baseline_profile_frequency_is_presence_not_authorization() {
    let input = fixture_repeated_across_runs();
    let profile = input.baseline_profile();
    let capability = repo_read("src/main.rs");
    assert_eq!(profile.frequency_of(&capability), Some(1));
}
