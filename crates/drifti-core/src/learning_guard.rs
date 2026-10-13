// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Forbidden broadening guards for learned candidate capabilities.
//!
//! [`guarded_learning_candidates`] runs [`generalize_candidates`] and then
//! drops proposals that would widen authority beyond observed evidence. Guards
//! are not [`policy::Decision::Allowed`](crate::policy::Decision::Allowed).

use std::collections::BTreeMap;

use crate::capability::Capability;
use crate::diff::CapabilityKey;
use crate::generalization::generalize_candidates;
use crate::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, Resource,
};

/// Proposes learning candidates after repo-local generalization and forbidden-broadening guards.
///
/// Identical inputs deduplicate. Output order follows capability identity.
#[must_use]
pub fn guarded_learning_candidates(
    candidates: impl IntoIterator<Item = Capability>,
) -> Vec<Capability> {
    let mut observed = BTreeMap::<CapabilityKey, Capability>::new();
    for capability in candidates {
        observed
            .entry(CapabilityKey::new(capability.clone()))
            .or_insert(capability);
    }
    generalize_candidates(observed.values().cloned())
        .into_iter()
        .filter(|proposal| guard_allows(proposal, &observed))
        .collect()
}

fn guard_allows(proposal: &Capability, observed: &BTreeMap<CapabilityKey, Capability>) -> bool {
    !forbidden_resource_shape(proposal.resource())
        && !invented_network_cidr(proposal, observed)
        && observed.values().any(|capability| {
            capability.action() == proposal.action()
                && proposal.resource().contains(capability.resource())
        })
}

fn forbidden_resource_shape(resource: &Resource) -> bool {
    match resource {
        Resource::File(file) => forbidden_file_shape(file),
        Resource::Executable(executable) => forbidden_executable_shape(executable),
        Resource::Network(_) => false,
    }
}

fn forbidden_file_shape(file: &FileResource) -> bool {
    if file.anchor() != FilesystemAnchor::Repo && file.is_recursive() {
        return true;
    }
    if file.anchor() == FilesystemAnchor::Home
        && matches!(file.file_path(), "**" | "/**" | "home/**")
    {
        return true;
    }
    false
}

fn forbidden_executable_shape(executable: &ExecutableResource) -> bool {
    let identity = executable.identity();
    identity.contains('*') || identity.contains("**")
}

fn invented_network_cidr(
    proposal: &Capability,
    observed: &BTreeMap<CapabilityKey, Capability>,
) -> bool {
    let Resource::Network(proposed) = proposal.resource() else {
        return false;
    };
    if !matches!(proposed.address(), NetworkAddress::Cidr(_)) {
        return false;
    }
    !observed.contains_key(&CapabilityKey::new(proposal.clone()))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::capability::Capability;
    use crate::policy::Decision;
    use crate::resource::{
        Cidr, ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource,
    };

    use super::{forbidden_resource_shape, guarded_learning_candidates};

    fn repo_read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    #[test]
    fn home_paths_are_never_generalized_to_a_recursive_home_root() {
        let home_a = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "project/a.rs").expect("home"),
        );
        let home_b = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "project/b.rs").expect("home"),
        );
        let guarded = guarded_learning_candidates([home_a.clone(), home_b.clone()]);
        assert_eq!(guarded.len(), 2);
        assert!(guarded.contains(&home_a));
        assert!(guarded.contains(&home_b));
    }

    #[test]
    fn sensitive_repo_paths_stay_exact() {
        let left = repo_read(".ssh/id_rsa");
        let right = repo_read(".ssh/known_hosts");
        let guarded = guarded_learning_candidates([left.clone(), right.clone()]);
        assert_eq!(guarded.len(), 2);
        assert!(guarded.contains(&left));
        assert!(guarded.contains(&right));
    }

    #[test]
    fn process_identities_are_never_wildcarded() {
        let exact = Capability::process_execute(ExecutableResource::new("git").expect("exe"));
        let guarded = guarded_learning_candidates([exact.clone()]);
        assert_eq!(guarded, vec![exact]);
    }

    #[test]
    fn process_wildcard_shapes_are_forbidden() {
        let git = Capability::process_execute(ExecutableResource::new("git").expect("exe"));
        assert!(!forbidden_resource_shape(git.resource()));
        let wildcard = Capability::process_execute(ExecutableResource::new("git*").expect("exe"));
        assert!(forbidden_resource_shape(wildcard.resource()));
    }

    #[test]
    fn non_repo_recursive_proposals_fail_closed() {
        let home_recursive = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "project/**").expect("home"),
        );
        assert!(forbidden_resource_shape(home_recursive.resource()));
        assert!(guarded_learning_candidates([home_recursive]).is_empty());
    }

    #[test]
    fn network_hosts_are_not_aggregated_into_cidr() {
        let first = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            443,
        ));
        let second = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            443,
        ));
        let guarded = guarded_learning_candidates([first.clone(), second.clone()]);
        assert_eq!(guarded.len(), 2);
        assert!(guarded.contains(&first));
        assert!(guarded.contains(&second));
    }

    #[test]
    fn observed_cidr_passes_through_unchanged() {
        let cidr = Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("cidr");
        let capability = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::Cidr(cidr),
            443,
        ));
        let guarded = guarded_learning_candidates([capability.clone()]);
        assert_eq!(guarded, vec![capability]);
    }

    #[test]
    fn invented_cidr_proposals_are_dropped() {
        let cidr = Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("cidr");
        let invented = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::Cidr(cidr),
            443,
        ));
        let observed = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            443,
        ));
        let guarded = guarded_learning_candidates([observed]);
        assert!(!guarded.iter().any(|cap| cap == &invented));
    }

    #[test]
    fn repo_generalization_still_applies_under_guards() {
        let guarded = guarded_learning_candidates([
            repo_read("src/a.rs"),
            repo_read("src/b.rs"),
            repo_read("src/c.rs"),
        ]);
        assert_eq!(guarded, vec![repo_read("src/**")]);
    }

    #[test]
    fn guarded_output_is_not_a_policy_decision() {
        let guarded = guarded_learning_candidates([repo_read("src/a.rs")]);
        let rendered = format!("{guarded:?}");
        for decision in Decision::ALL {
            assert!(
                !rendered.contains(decision.as_str()),
                "{}",
                decision.as_str()
            );
        }
    }
}
