// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Run-to-run drift through exercised observation capabilities.

use crate::capability::Capability;
use crate::diff::{diff, DriftDiff};
use crate::observation::{capability_from_observation, ObservedEvent};
use crate::resource::FilesystemRoots;

/// Collects capabilities from observations that were exercised.
///
/// Failed attempts are skipped. Observations that do not map to a capability
/// are skipped without turning incomplete mapping into authority.
#[must_use]
pub fn exercised_capabilities_from_events(
    events: impl IntoIterator<Item = ObservedEvent>,
    roots: &FilesystemRoots,
) -> Vec<Capability> {
    events
        .into_iter()
        .filter(|event| event.was_exercised())
        .filter_map(|event| {
            capability_from_observation(event.operation(), event.resource(), roots).ok()
        })
        .collect()
}

/// Compares two runs through exercised capabilities.
#[must_use]
pub fn diff_runs(
    reference_events: impl IntoIterator<Item = ObservedEvent>,
    current_events: impl IntoIterator<Item = ObservedEvent>,
    roots: &FilesystemRoots,
) -> DriftDiff {
    diff(
        exercised_capabilities_from_events(reference_events, roots),
        exercised_capabilities_from_events(current_events, roots),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::*;
    use crate::capability::Capability;
    use crate::drift::DriftFinding;
    use crate::observation::{ObservedEvent, ObservedResource, Operation, Outcome};
    use crate::profile::{CapabilityProfile, ProfileEntry};
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, FilesystemRoots, NetworkAddress,
        NetworkProtocol, NetworkResource,
    };

    fn roots() -> FilesystemRoots {
        FilesystemRoots::new("/work/repo", "/home/user", "/tmp").expect("roots")
    }

    fn exercised_read(path: &str) -> ObservedEvent {
        ObservedEvent::new(
            Operation::FilesystemRead,
            ObservedResource::file(path).expect("path"),
            Outcome::Success,
        )
    }

    fn failed_read(path: &str) -> ObservedEvent {
        ObservedEvent::new(
            Operation::FilesystemRead,
            ObservedResource::file(path).expect("path"),
            Outcome::Failure,
        )
    }

    #[test]
    fn failed_attempts_are_not_authority() {
        let roots = roots();
        let exercised = exercised_read("/work/repo/src/lib.rs");
        let failed = failed_read("/work/repo/src/secret.rs");
        let capabilities = exercised_capabilities_from_events([exercised.clone(), failed], &roots);
        assert_eq!(capabilities.len(), 1);
        assert_eq!(
            capabilities[0],
            Capability::filesystem_read(
                FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file")
            )
        );

        let comparison = diff_runs([exercised], [], &roots);
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            &[DriftFinding::removed(capabilities[0].clone())]
        );
    }

    #[test]
    fn run_and_profile_adapters_share_structural_findings() {
        let roots = roots();
        let read = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/a.rs").expect("file"),
        );
        let write = Capability::filesystem_write(
            FileResource::new(FilesystemAnchor::Repo, "src/b.rs").expect("file"),
        );
        let reference_profile = CapabilityProfile::from_entries([
            ProfileEntry::new(read.clone(), 3),
            ProfileEntry::new(write.clone(), 1),
        ]);
        let current_profile = CapabilityProfile::from_entries([
            ProfileEntry::new(read.clone(), 9),
            ProfileEntry::new(
                Capability::filesystem_read(
                    FileResource::new(FilesystemAnchor::Repo, "src/c.rs").expect("file"),
                ),
                2,
            ),
        ]);

        let reference_run = [
            exercised_read("/work/repo/src/a.rs"),
            ObservedEvent::new(
                Operation::FilesystemWrite,
                ObservedResource::file("/work/repo/src/b.rs").expect("path"),
                Outcome::Success,
            ),
        ];
        let current_run = [
            exercised_read("/work/repo/src/a.rs"),
            exercised_read("/work/repo/src/c.rs"),
        ];

        let from_profiles = reference_profile.diff_with(&current_profile);
        let from_runs = diff_runs(reference_run, current_run, &roots);
        assert_eq!(from_profiles, from_runs);
        assert!(from_profiles
            .findings()
            .expect("classified")
            .findings()
            .iter()
            .all(|finding| finding.severity().is_none()));
    }

    fn deterministic_runner() -> TestRunner {
        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
    }

    #[test]
    fn profile_frequency_does_not_change_run_equivalent_diff() {
        let mut runner = deterministic_runner();
        runner
            .run(
                &(any::<u64>(), any::<u64>()),
                |(left_frequency, right_frequency)| {
                    let capability = Capability::filesystem_read(
                        FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file"),
                    );
                    let left = CapabilityProfile::from_entries([ProfileEntry::new(
                        capability.clone(),
                        left_frequency,
                    )]);
                    let right = CapabilityProfile::from_entries([ProfileEntry::new(
                        capability.clone(),
                        right_frequency,
                    )]);
                    prop_assert_eq!(&left, &right);
                    let comparison = left.diff_with(&right);
                    prop_assert!(comparison.is_empty());
                    prop_assert_eq!(
                        comparison.findings().expect("classified").findings(),
                        &[] as &[DriftFinding]
                    );
                    Ok(())
                },
            )
            .expect("frequency ignored");
    }

    #[test]
    fn maps_process_and_network_observations() {
        let roots = roots();
        let execute = ObservedEvent::new(
            Operation::ProcessExecute,
            ObservedResource::executable("git").expect("exe"),
            Outcome::Success,
        );
        let connect = ObservedEvent::new(
            Operation::NetworkConnect,
            ObservedResource::network(Ipv4Addr::LOCALHOST.to_string(), 443).expect("endpoint"),
            Outcome::Success,
        );
        let capabilities = exercised_capabilities_from_events([execute, connect], &roots);
        assert_eq!(capabilities.len(), 2);
        assert_eq!(
            capabilities[0],
            Capability::process_execute(ExecutableResource::new("git").expect("git"))
        );
        assert_eq!(
            capabilities[1],
            Capability::network_connect(NetworkResource::new(
                NetworkProtocol::Tcp,
                NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                443,
            ))
        );
    }
}
