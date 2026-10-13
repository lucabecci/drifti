// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-007 acceptance and authorization-separation matrix (KAN-67).
//!
//! Criteria covered here:
//! 1. Deterministic learning input from eligible executions.
//! 2. Failed attempts never enter the default learned baseline.
//! 3. Learning, aggregation, presentation, and candidate scopes are not policy.
//! 4. Narrowest-safe repository-local path generalization.
//! 5. Forbidden automatic broadening (sensitive paths, home-root, process wildcards, CIDR).
//! 6. Identical eligible histories produce identical profiles and candidate scopes.
//!
//! Detailed goldens and property tests live in `tests/learning/` (KAN-66).

use std::net::{IpAddr, Ipv4Addr};

use drifti_core::capability::Capability;
use drifti_core::generalization::generalize_candidates;
use drifti_core::learning::{
    CapabilityAttempt, EligibleExecution, EligibleExecutionId, LearningInput,
};
use drifti_core::learning_guard::guarded_learning_candidates;
use drifti_core::observation::Outcome;
use drifti_core::policy::{CompiledPolicy, Coverage, Decision};
use drifti_core::presentation::{PresentationClass, PresentationThresholds};
use drifti_core::resource::{FileResource, FilesystemAnchor};

fn execution_id(text: &str) -> EligibleExecutionId {
    EligibleExecutionId::new(text).expect("execution id")
}

fn repo_read(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn success(execution: &str, capability: Capability, seen: u64) -> EligibleExecution {
    EligibleExecution::new(
        execution_id(execution),
        [CapabilityAttempt::at(capability, Outcome::Success, seen)],
    )
}

fn failure(execution: &str, capability: Capability, seen: u64) -> EligibleExecution {
    EligibleExecution::new(
        execution_id(execution),
        [CapabilityAttempt::at(capability, Outcome::Failure, seen)],
    )
}

fn candidate_scope_text(candidates: impl IntoIterator<Item = Capability>) -> String {
    guarded_learning_candidates(candidates)
        .into_iter()
        .map(|capability| format!("{:?}", capability))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[test]
fn matrix_criterion_1_deterministic_learning_input_selection() {
    let cap_a = repo_read("src/a.rs");
    let cap_b = repo_read("src/b.rs");
    let forward = LearningInput::select([
        success("run-2", cap_b.clone(), 2),
        success("run-1", cap_a.clone(), 1),
    ]);
    let reverse = LearningInput::select([
        success("run-1", cap_a.clone(), 1),
        success("run-2", cap_b.clone(), 2),
    ]);
    assert_eq!(forward, reverse);
    assert_eq!(
        forward.aggregate().canonical_text(),
        reverse.aggregate().canonical_text()
    );
}

#[test]
fn matrix_criterion_2_failed_attempts_never_enter_baseline() {
    let allowed = repo_read("src/ok.rs");
    let sensitive = repo_read(".ssh/id_rsa");
    let input = LearningInput::select([
        success("run-ok", allowed.clone(), 1),
        failure("run-deny", sensitive, 2),
    ]);
    let baseline: Vec<_> = input.baseline().iter().cloned().collect();
    assert_eq!(baseline, vec![allowed]);
    assert_eq!(input.failed_evidence().count(), 1);
}

#[test]
fn matrix_criterion_3_learning_metadata_is_not_authorization() {
    let capability = repo_read("src/learned.rs");
    let input = LearningInput::select([
        success("run-1", capability.clone(), 1),
        success("run-2", capability.clone(), 2),
        success("run-3", capability.clone(), 3),
        success("run-4", capability, 4),
    ]);
    let aggregated = input.aggregate();
    let presented = aggregated
        .present(PresentationThresholds::default())
        .expect("thresholds");
    let stable = presented
        .class_of(&repo_read("src/learned.rs"))
        .expect("presented");
    assert_eq!(stable, PresentationClass::Stable);

    let learned = repo_read("src/learned.rs");
    let policy = CompiledPolicy::new(Vec::new());
    let evaluation = policy.evaluate(&learned, Coverage::Complete);
    assert_eq!(evaluation.decision(), Decision::Unknown);
    assert_ne!(evaluation.decision(), Decision::Allowed);

    let profile = input.baseline_profile();
    assert_eq!(profile.frequency_of(&learned), Some(1));
    assert_ne!(stable.as_str(), Decision::Allowed.as_str());
}

#[test]
fn matrix_criterion_4_narrowest_safe_repo_generalization() {
    let generalized = generalize_candidates([
        repo_read("src/domain/mod.rs"),
        repo_read("src/domain/lib.rs"),
    ]);
    assert_eq!(generalized, vec![repo_read("src/domain/**")]);

    let unrelated = generalize_candidates([repo_read("src/a.rs"), repo_read("docs/b.md")]);
    assert_eq!(unrelated.len(), 2);
}

#[test]
fn matrix_criterion_5_forbidden_broadening_paths_rejected() {
    let ssh =
        guarded_learning_candidates([repo_read(".ssh/id_rsa"), repo_read(".ssh/known_hosts")]);
    assert_eq!(ssh.len(), 2);

    let home = Capability::filesystem_read(
        FileResource::new(FilesystemAnchor::Home, "project/a.rs").expect("home"),
    );
    let home_generalized = guarded_learning_candidates([
        home.clone(),
        Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "project/b.rs").expect("home"),
        ),
    ]);
    assert_eq!(home_generalized.len(), 2);
    assert!(home_generalized.contains(&home));

    let hosts = [
        Capability::network_connect(drifti_core::resource::NetworkResource::new(
            drifti_core::resource::NetworkProtocol::Tcp,
            drifti_core::resource::NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            443,
        )),
        Capability::network_connect(drifti_core::resource::NetworkResource::new(
            drifti_core::resource::NetworkProtocol::Tcp,
            drifti_core::resource::NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            443,
        )),
    ];
    assert_eq!(guarded_learning_candidates(hosts.clone()).len(), 2);
    assert!(guarded_learning_candidates(hosts).iter().all(|cap| {
        !matches!(
            cap.resource(),
            drifti_core::resource::Resource::Network(net)
            if matches!(net.address(), drifti_core::resource::NetworkAddress::Cidr(_))
        )
    }));
}

#[test]
fn matrix_criterion_6_identical_histories_produce_identical_outputs() {
    let cap_a = repo_read("src/a.rs");
    let cap_b = repo_read("src/b.rs");
    let cap_c = repo_read("src/c.rs");
    let history = [
        success("run-1", cap_a.clone(), 1),
        success("run-2", cap_b.clone(), 2),
        success("run-3", cap_c.clone(), 3),
    ];
    let first = LearningInput::select(history.clone());
    let second = LearningInput::select(history);
    assert_eq!(
        first.aggregate().canonical_text(),
        second.aggregate().canonical_text()
    );

    let candidates = [cap_a, cap_b, cap_c];
    assert_eq!(
        candidate_scope_text(candidates.clone()),
        candidate_scope_text(candidates)
    );
}

#[test]
fn matrix_learning_sources_stay_inside_drifti_core_boundary() {
    for (name, source) in [
        ("learning.rs", include_str!("../src/learning.rs")),
        (
            "learning_guard.rs",
            include_str!("../src/learning_guard.rs"),
        ),
        ("presentation.rs", include_str!("../src/presentation.rs")),
        (
            "generalization.rs",
            include_str!("../src/generalization.rs"),
        ),
    ] {
        for token in ["ptrace", "rusqlite", "clap::", "std::os::unix", "/proc"] {
            assert!(
                !source.contains(token),
                "{name} contains forbidden token {token}"
            );
        }
    }
}
