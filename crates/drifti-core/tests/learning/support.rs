// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use drifti_core::capability::Capability;
use drifti_core::learning::{
    AggregatedProfile, CapabilityAttempt, EligibleExecution, EligibleExecutionId, LearningInput,
};
use drifti_core::learning_guard::guarded_learning_candidates;
use drifti_core::observation::Outcome;
use drifti_core::presentation::{PresentationThresholds, PresentedProfile};
use drifti_core::resource::{
    FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol, Resource,
};

pub fn execution_id(text: &str) -> EligibleExecutionId {
    EligibleExecutionId::new(text).expect("execution id")
}

pub fn repo_read(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

pub fn success(execution: &str, capability: Capability, seen: u64) -> EligibleExecution {
    EligibleExecution::new(
        execution_id(execution),
        [CapabilityAttempt::at(capability, Outcome::Success, seen)],
    )
}

pub fn failure(execution: &str, capability: Capability, seen: u64) -> EligibleExecution {
    EligibleExecution::new(
        execution_id(execution),
        [CapabilityAttempt::at(capability, Outcome::Failure, seen)],
    )
}

pub fn mixed(
    execution: &str,
    attempts: impl IntoIterator<Item = CapabilityAttempt>,
) -> EligibleExecution {
    EligibleExecution::new(execution_id(execution), attempts)
}

/// Fixture: duplicate successful observations of one capability inside one run.
pub fn fixture_duplicate_observations() -> LearningInput {
    LearningInput::select([EligibleExecution::new(
        execution_id("run-duplicate"),
        [
            CapabilityAttempt::at(repo_read("src/lib.rs"), Outcome::Success, 10),
            CapabilityAttempt::at(repo_read("src/lib.rs"), Outcome::Success, 20),
        ],
    )])
}

/// Fixture: the same capability across three eligible runs.
pub fn fixture_repeated_across_runs() -> LearningInput {
    let capability = repo_read("src/main.rs");
    LearningInput::select([
        success("run-a", capability.clone(), 1),
        success("run-b", capability.clone(), 2),
        success("run-c", capability, 3),
    ])
}

/// Fixture: one success and one failed attempt on a sensitive path.
pub fn fixture_failed_sensitive_attempt() -> LearningInput {
    LearningInput::select([
        success("run-ok", repo_read("src/ok.rs"), 1),
        failure("run-deny", repo_read(".ssh/id_rsa"), 2),
    ])
}

/// Fixture: repo-local paths that generalize to `src/**`.
pub fn fixture_repo_generalization_inputs() -> Vec<Capability> {
    vec![
        repo_read("src/a.rs"),
        repo_read("src/b.rs"),
        repo_read("src/c.rs"),
    ]
}

/// Fixture: sensitive repo paths that must stay exact.
pub fn fixture_sensitive_repo_paths() -> Vec<Capability> {
    vec![repo_read(".ssh/id_rsa"), repo_read(".ssh/known_hosts")]
}

pub fn resource_identity(resource: &Resource) -> String {
    match resource {
        Resource::File(file) => {
            let anchor = match file.anchor() {
                FilesystemAnchor::Repo => "repo",
                FilesystemAnchor::Home => "home",
                FilesystemAnchor::Temp => "temp",
                FilesystemAnchor::Absolute => "abs",
            };
            format!("file {anchor} {}", file.file_path())
        }
        Resource::Executable(executable) => format!("executable {}", executable.identity()),
        Resource::Network(network) => {
            let protocol = match network.protocol() {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
            };
            let address = match network.address() {
                NetworkAddress::Ip(address) => address.to_string(),
                NetworkAddress::Cidr(cidr) => {
                    format!("{}/{}", cidr.address(), cidr.prefix_length())
                }
            };
            format!("network {protocol} {address} {}", network.port())
        }
    }
}

pub fn capability_identity_line(capability: &Capability) -> String {
    format!(
        "{} {}",
        capability.action().as_str(),
        resource_identity(capability.resource())
    )
}

pub fn baseline_canonical(input: &LearningInput) -> String {
    let lines: Vec<String> = input
        .baseline()
        .iter()
        .map(capability_identity_line)
        .collect();
    format!("{}\n", lines.join("\n"))
}

pub fn candidate_scope_canonical(candidates: impl IntoIterator<Item = Capability>) -> String {
    let lines: Vec<String> = guarded_learning_candidates(candidates)
        .into_iter()
        .map(|capability| capability_identity_line(&capability))
        .collect();
    format!("{}\n", lines.join("\n"))
}

pub fn presented_canonical(profile: &PresentedProfile) -> String {
    let mut text = format!("total_eligible_runs {}\n", profile.total_eligible_runs());
    for entry in profile.entries() {
        let stats = entry.statistics();
        text.push_str(&format!(
            "{} {} runs={} obs={} class={}\n",
            entry.capability().action().as_str(),
            resource_identity(entry.capability().resource()),
            stats.runs_observed(),
            stats.observation_count(),
            entry.class().as_str(),
        ));
    }
    text
}

pub fn aggregate(input: &LearningInput) -> AggregatedProfile {
    input.aggregate()
}

pub fn fixture_stable_presentation() -> PresentedProfile {
    let capability = repo_read("src/stable.rs");
    let selection = LearningInput::select([
        success("run-1", capability.clone(), 1),
        success("run-2", capability.clone(), 2),
        success("run-3", capability.clone(), 3),
        success("run-4", capability, 4),
    ]);
    selection
        .aggregate()
        .present(PresentationThresholds::default())
        .expect("thresholds")
}
