// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract-to-contract drift with separate allow and deny comparison.

use std::collections::BTreeSet;

use crate::contract::{
    resolve_comparable_capabilities, AcceptedContract, UncomparableContractRule,
};
use crate::diff::{diff, DriftDiff};
use crate::policy::RuleEffect;

/// Structural drift between two accepted contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDrift {
    allow: DriftDiff,
    deny: DriftDiff,
    uncompared_reference: BTreeSet<UncomparableContractRule>,
    uncompared_current: BTreeSet<UncomparableContractRule>,
}

impl ContractDrift {
    /// Allow-list structural findings.
    #[must_use]
    pub fn allow(&self) -> &DriftDiff {
        &self.allow
    }

    /// Deny-list structural findings.
    #[must_use]
    pub fn deny(&self) -> &DriftDiff {
        &self.deny
    }

    /// Rules on the reference contract that stayed outside comparison.
    #[must_use]
    pub fn uncompared_reference(&self) -> &BTreeSet<UncomparableContractRule> {
        &self.uncompared_reference
    }

    /// Rules on the current contract that stayed outside comparison.
    #[must_use]
    pub fn uncompared_current(&self) -> &BTreeSet<UncomparableContractRule> {
        &self.uncompared_current
    }

    /// Whether every comparable set matches and every rule was comparable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
            && self.deny.is_empty()
            && self.uncompared_reference.is_empty()
            && self.uncompared_current.is_empty()
    }

    /// Whether any rule text could not enter structural comparison.
    #[must_use]
    pub fn has_uncompared_rules(&self) -> bool {
        !self.uncompared_reference.is_empty() || !self.uncompared_current.is_empty()
    }
}

/// Compares two accepted contracts.
///
/// Allow rules are compared only with allow rules. Deny rules are compared
/// only with deny rules. A deny capability never enters the allow diff.
#[must_use]
pub fn diff_contracts(reference: &AcceptedContract, current: &AcceptedContract) -> ContractDrift {
    let (reference_allow, uncompared_reference_allow) =
        resolve_comparable_capabilities(reference.document(), RuleEffect::Allow);
    let (current_allow, uncompared_current_allow) =
        resolve_comparable_capabilities(current.document(), RuleEffect::Allow);
    let (reference_deny, uncompared_reference_deny) =
        resolve_comparable_capabilities(reference.document(), RuleEffect::Deny);
    let (current_deny, uncompared_current_deny) =
        resolve_comparable_capabilities(current.document(), RuleEffect::Deny);

    let allow = diff(reference_allow, current_allow);
    let deny = diff(reference_deny, current_deny);
    let uncompared_reference = uncompared_reference_allow
        .into_iter()
        .chain(uncompared_reference_deny)
        .collect();
    let uncompared_current = uncompared_current_allow
        .into_iter()
        .chain(uncompared_current_deny)
        .collect();

    ContractDrift {
        allow,
        deny,
        uncompared_reference,
        uncompared_current,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::*;
    use crate::capability::Capability;
    use crate::contract::{
        AllowDenyRules, AuthoringResource, ContractDocument, ContractVersion, FilesystemContract,
        NetworkContract, ProcessContract,
    };
    use crate::drift::DriftFinding;
    use crate::resource::{
        FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol, NetworkResource,
    };

    fn resource(text: &str) -> AuthoringResource {
        AuthoringResource::new(text).expect("resource")
    }

    fn rules(allow: &[&str], deny: &[&str]) -> AllowDenyRules {
        AllowDenyRules::new(
            allow.iter().copied().map(resource).collect(),
            deny.iter().copied().map(resource).collect(),
        )
    }

    fn accepted(allow_read: &[&str], deny_read: &[&str]) -> AcceptedContract {
        let document = ContractDocument::new(
            ContractVersion::V1,
            FilesystemContract::new(rules(allow_read, deny_read), AllowDenyRules::empty()),
            ProcessContract::new(AllowDenyRules::empty()),
            NetworkContract::new(AllowDenyRules::empty(), AllowDenyRules::empty()),
        );
        AcceptedContract::loaded(document)
    }

    #[test]
    fn allow_and_deny_are_not_mixed() {
        let src = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/**").expect("file"),
        );
        let secrets = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "secrets/**").expect("file"),
        );
        let reference = accepted(&["./src/**"], &[]);
        let current = accepted(&["./src/**"], &["./secrets/**"]);
        let comparison = diff_contracts(&reference, &current);

        assert!(comparison.allow().is_empty());
        assert_eq!(
            comparison.deny().findings().expect("classified").findings(),
            &[DriftFinding::added(secrets.clone())]
        );

        let swapped = diff_contracts(
            &accepted(&["./src/**"], &["./secrets/**"]),
            &accepted(&["./src/**"], &[]),
        );
        assert!(swapped.allow().is_empty());
        assert_eq!(
            swapped.deny().findings().expect("classified").findings(),
            &[DriftFinding::removed(secrets)]
        );

        let allow_only = diff_contracts(
            &accepted(&["./src/**"], &[]),
            &accepted(&["./src/**", "./docs/**"], &[]),
        );
        assert!(allow_only.deny().is_empty());
        assert_eq!(
            allow_only
                .allow()
                .findings()
                .expect("classified")
                .findings(),
            &[DriftFinding::added(Capability::filesystem_read(
                FileResource::new(FilesystemAnchor::Repo, "docs/**").expect("file")
            ))]
        );
        let _ = src;
    }

    #[test]
    fn uncompared_rules_block_empty_success() {
        let reference = accepted(&["./src/**"], &[]);
        let current = accepted(&["./src/**", "./src/*.rs"], &[]);
        let comparison = diff_contracts(&reference, &current);
        assert!(comparison.allow().is_empty());
        assert!(comparison.deny().is_empty());
        assert_eq!(comparison.uncompared_reference().len(), 0);
        assert_eq!(comparison.uncompared_current().len(), 1);
        assert_eq!(
            comparison
                .uncompared_current()
                .iter()
                .next()
                .expect("rule")
                .authoring(),
            "./src/*.rs"
        );
        assert!(comparison.has_uncompared_rules());
        assert!(!comparison.is_empty());
    }

    #[test]
    fn contract_capabilities_match_direct_diff_for_allow() {
        let reference = accepted(&["./src/**"], &[]);
        let current = AcceptedContract::loaded(ContractDocument::new(
            ContractVersion::V1,
            FilesystemContract::new(
                rules(&["./src/**", "./docs/readme.md"], &[]),
                AllowDenyRules::empty(),
            ),
            ProcessContract::new(AllowDenyRules::empty()),
            NetworkContract::new(rules(&[], &["tcp://127.0.0.1:9"]), AllowDenyRules::empty()),
        ));
        let comparison = diff_contracts(&reference, &current);
        let added_read = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "docs/readme.md").expect("file"),
        );
        assert_eq!(
            comparison
                .allow()
                .findings()
                .expect("classified")
                .findings(),
            &[DriftFinding::added(added_read)]
        );
        let added_deny = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(Ipv4Addr::LOCALHOST.into()),
            9,
        ));
        assert_eq!(
            comparison.deny().findings().expect("classified").findings(),
            &[DriftFinding::added(added_deny)]
        );
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
    fn allow_deny_streams_stay_disjoint_under_random_documents() {
        let mut runner = deterministic_runner();
        runner
            .run(&any::<bool>(), |touch_allow| {
                let reference = accepted(&["./src/**"], &["./private/**"]);
                let current = if touch_allow {
                    accepted(&["./src/**", "./docs/**"], &["./private/**"])
                } else {
                    accepted(&["./src/**"], &["./private/**", "./tmp/**"])
                };
                let comparison = diff_contracts(&reference, &current);
                if touch_allow {
                    prop_assert!(!comparison.allow().is_empty());
                    prop_assert!(comparison.deny().is_empty());
                } else {
                    prop_assert!(comparison.allow().is_empty());
                    prop_assert!(!comparison.deny().is_empty());
                }
                prop_assert!(comparison.uncompared_reference().is_empty());
                prop_assert!(comparison.uncompared_current().is_empty());
                Ok(())
            })
            .expect("allow deny disjoint");
    }
}
