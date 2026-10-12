// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Normalized comparison of capability sets.
//!
//! Both sides pass through [`normalize_capability`] and are grouped by
//! [`CapabilityKey`] before any structural classification. Equivalent
//! capabilities share one canonical value, so they do not appear as drift.
//! [`diff`] of a set with itself is an empty [`crate::drift::DriftResult`].
//! A difference is kept as an unclassified comparison: this module does not
//! assign [`crate::drift::DriftKind`] and does not infer intent.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::capability::Capability;
use crate::drift::{cmp_capability, DriftResult};
use crate::resource::{
    ExecutableResource, FileResource, NetworkAddress, NetworkResource, Resource,
};

/// Identity of one capability after normalization.
///
/// Equality is the capability's own equality: action plus normalized resource.
/// Order is the deterministic identity order: action name, then resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapabilityKey {
    capability: Capability,
}

impl CapabilityKey {
    /// Builds the identity key of a capability, normalizing it first.
    #[must_use]
    pub fn new(capability: Capability) -> Self {
        Self::from_normalized(normalize_capability(capability))
    }

    /// Canonical capability this key names.
    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    fn from_normalized(capability: Capability) -> Self {
        Self { capability }
    }
}

impl PartialOrd for CapabilityKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CapabilityKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_capability(&self.capability, &other.capability)
    }
}

/// Capabilities grouped by identity, in identity order.
///
/// Duplicate observations of one capability occupy one entry. Input order does
/// not change the group. Values exist only through [`Self::normalize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCapabilitySet {
    entries: BTreeSet<CapabilityKey>,
}

impl NormalizedCapabilitySet {
    /// Normalizes each capability, then groups equal identities.
    #[must_use]
    pub fn normalize(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        let entries = capabilities
            .into_iter()
            .map(normalize_capability)
            .map(CapabilityKey::from_normalized)
            .collect();
        Self { entries }
    }

    /// Capabilities in identity order.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> + '_ {
        self.entries.iter().map(CapabilityKey::capability)
    }

    /// Number of distinct identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the group contains no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compares two sets that are already normalized.
    ///
    /// Identical groups produce an empty [`DriftResult`]. A difference does
    /// not receive a drift kind.
    #[must_use]
    pub fn diff_with(&self, current: &Self) -> DriftDiff {
        DriftDiff::from_normalized(self.clone(), current.clone())
    }
}

/// Projects a capability through the canonical resource constructors.
///
/// Capability constructors already store the normalized form. Running them
/// again is the comparison boundary: later classification sees this value,
/// not the spelling that was supplied to the constructor.
#[must_use]
pub fn normalize_capability(capability: Capability) -> Capability {
    let action = capability.action();
    let resource = renormalize_resource(capability.resource());
    let normalized = Capability::try_new(action, resource)
        .expect("normalization preserves the action and resource family of a capability");
    debug_assert_eq!(
        normalized, capability,
        "capability normalization must be idempotent"
    );
    normalized
}

fn renormalize_resource(resource: &Resource) -> Resource {
    match resource {
        Resource::File(file) => {
            let file = FileResource::new(file.anchor(), file.file_path())
                .expect("a stored file path is already normalized");
            Resource::File(file)
        }
        Resource::Executable(executable) => {
            let executable = ExecutableResource::new(executable.identity())
                .expect("a stored executable identity is already canonical");
            Resource::Executable(executable)
        }
        Resource::Network(network) => Resource::Network(NetworkResource::new(
            network.protocol(),
            renormalize_address(network.address()),
            network.port(),
        )),
    }
}

fn renormalize_address(address: NetworkAddress) -> NetworkAddress {
    match address {
        NetworkAddress::Ip(ip) => NetworkAddress::ip(ip),
        NetworkAddress::Cidr(cidr) => NetworkAddress::cidr(cidr.address(), cidr.prefix_length())
            .expect("a stored CIDR prefix stays inside its address family"),
    }
}

/// Result of comparing two capability sets after normalization.
///
/// [`DriftDiff::is_empty`] is the empty deterministic result: the canonical
/// groups match and the finding list is empty. When the groups differ, findings
/// stay absent. That state is not an empty result and it is not a drift kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftDiff {
    reference: NormalizedCapabilitySet,
    current: NormalizedCapabilitySet,
    findings: Option<DriftResult>,
}

impl DriftDiff {
    fn from_normalized(
        reference: NormalizedCapabilitySet,
        current: NormalizedCapabilitySet,
    ) -> Self {
        let findings = if reference == current {
            Some(DriftResult::empty())
        } else {
            None
        };
        Self {
            reference,
            current,
            findings,
        }
    }

    /// Normalized reference group.
    #[must_use]
    pub fn reference(&self) -> &NormalizedCapabilitySet {
        &self.reference
    }

    /// Normalized current group.
    #[must_use]
    pub fn current(&self) -> &NormalizedCapabilitySet {
        &self.current
    }

    /// Classified findings.
    ///
    /// `Some` empty result means the canonical sets match. `None` means the
    /// sets differ and no kind has been assigned.
    #[must_use]
    pub fn findings(&self) -> Option<&DriftResult> {
        self.findings.as_ref()
    }

    /// Whether this comparison is an empty deterministic result.
    ///
    /// True only when the normalized sets match and the finding list is empty.
    /// A difference that is not yet classified is not empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reference == self.current && self.findings.as_ref().is_some_and(DriftResult::is_empty)
    }

    /// Whether the canonical sets differ and no drift kind has been assigned.
    ///
    /// This is not success and it is not a structural finding.
    #[must_use]
    pub fn classification_pending(&self) -> bool {
        self.reference != self.current && self.findings.is_none()
    }
}

/// Normalizes `reference` and `current`, then compares the canonical groups.
///
/// Normalization and grouping finish before any structural classification.
/// Equivalent capabilities share one identity. This function does not assign
/// [`crate::drift::DriftKind`].
#[must_use]
pub fn diff(
    reference: impl IntoIterator<Item = Capability>,
    current: impl IntoIterator<Item = Capability>,
) -> DriftDiff {
    let reference = NormalizedCapabilitySet::normalize(reference);
    let current = NormalizedCapabilitySet::normalize(current);
    reference.diff_with(&current)
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::net::{IpAddr, Ipv4Addr};

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::{diff, normalize_capability, CapabilityKey, DriftDiff, NormalizedCapabilitySet};
    use crate::capability::Capability;
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource,
    };

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn write(path: &str) -> Capability {
        Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn assert_empty(comparison: &DriftDiff) {
        assert!(comparison.is_empty());
        assert!(!comparison.classification_pending());
        assert_eq!(comparison.reference(), comparison.current());
        let result = comparison
            .findings()
            .expect("identical sets have a finding result");
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
    }

    fn assert_pending(comparison: &DriftDiff) {
        assert!(!comparison.is_empty());
        assert!(comparison.classification_pending());
        assert!(comparison.findings().is_none());
        assert_ne!(comparison.reference(), comparison.current());
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

    fn arb_file() -> impl Strategy<Value = FileResource> {
        (
            prop_oneof![
                Just(FilesystemAnchor::Repo),
                Just(FilesystemAnchor::Home),
                Just(FilesystemAnchor::Temp),
                Just(FilesystemAnchor::Absolute),
            ],
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=12),
        )
            .prop_map(|(anchor, chars)| {
                let body: String = chars.into_iter().collect();
                let file_path = if anchor == FilesystemAnchor::Absolute {
                    format!("/{body}")
                } else {
                    body
                };
                FileResource::new(anchor, file_path).expect("generated file path")
            })
    }

    fn arb_executable() -> impl Strategy<Value = ExecutableResource> {
        proptest::collection::vec(proptest::char::range('a', 'z'), 1..=12).prop_map(|chars| {
            let identity: String = chars.into_iter().collect();
            ExecutableResource::new(identity).expect("generated executable")
        })
    }

    fn arb_ip() -> impl Strategy<Value = IpAddr> {
        prop_oneof![
            any::<u32>().prop_map(|bits| IpAddr::V4(Ipv4Addr::from(bits))),
            any::<[u8; 16]>().prop_map(|bits| IpAddr::V6(bits.into())),
        ]
    }

    fn arb_network() -> impl Strategy<Value = NetworkResource> {
        (
            prop_oneof![Just(NetworkProtocol::Tcp), Just(NetworkProtocol::Udp)],
            arb_ip(),
            any::<u16>(),
        )
            .prop_map(|(protocol, address, port)| {
                NetworkResource::new(protocol, NetworkAddress::ip(address), port)
            })
    }

    fn arb_capability() -> impl Strategy<Value = Capability> {
        prop_oneof![
            arb_file().prop_map(Capability::filesystem_read),
            arb_file().prop_map(Capability::filesystem_write),
            arb_file().prop_map(Capability::filesystem_metadata),
            arb_executable().prop_map(Capability::process_execute),
            arb_network().prop_map(Capability::network_connect),
            arb_network().prop_map(Capability::network_listen),
        ]
    }

    fn arb_capabilities() -> impl Strategy<Value = Vec<Capability>> {
        proptest::collection::vec(arb_capability(), 0..=6)
    }

    #[test]
    fn equivalent_spellings_share_one_canonical_representation() {
        let pairs = [
            (read("src/./lib.rs"), read("src/foo/../lib.rs")),
            (
                Capability::process_execute(ExecutableResource::new("./git").expect("exe")),
                Capability::process_execute(ExecutableResource::new("git").expect("name")),
            ),
            (
                Capability::network_connect(NetworkResource::new(
                    NetworkProtocol::Tcp,
                    NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8).expect("cidr"),
                    443,
                )),
                Capability::network_connect(NetworkResource::new(
                    NetworkProtocol::Tcp,
                    NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("net"),
                    443,
                )),
            ),
        ];
        for (left, right) in pairs {
            assert_eq!(left, right);
            assert_eq!(normalize_capability(left.clone()), right);
            assert_eq!(
                CapabilityKey::new(left.clone()),
                CapabilityKey::new(right.clone())
            );
            assert_eq!(
                NormalizedCapabilitySet::normalize([left.clone()]),
                NormalizedCapabilitySet::normalize([right.clone()])
            );
            assert_empty(&diff([left.clone()], [right.clone()]));
            let grouped = NormalizedCapabilitySet::normalize([left.clone(), right.clone(), left]);
            assert_eq!(grouped.len(), 1);
        }
    }

    #[test]
    fn diff_of_a_set_with_itself_is_empty() {
        let read_src = read("src/lib.rs");
        let write_src = write("src/lib.rs");
        let reference = [write_src.clone(), read_src.clone(), write_src.clone()];
        let current = [read_src.clone(), write_src.clone()];
        let comparison = diff(reference.clone(), current.clone());
        assert_empty(&comparison);
        assert_eq!(
            comparison.reference().iter().cloned().collect::<Vec<_>>(),
            vec![read_src.clone(), write_src.clone()]
        );
        assert_eq!(
            comparison,
            NormalizedCapabilitySet::normalize(reference)
                .diff_with(&NormalizedCapabilitySet::normalize(current))
        );
        assert_empty(&diff(Vec::<Capability>::new(), Vec::<Capability>::new()));
    }

    #[test]
    fn grouping_is_deterministic_and_keeps_distinct_actions() {
        let read_src = read("src/a.rs");
        let write_src = write("src/a.rs");
        assert_ne!(read_src.action(), write_src.action());
        let forward = NormalizedCapabilitySet::normalize([
            write_src.clone(),
            read_src.clone(),
            write_src.clone(),
        ]);
        let backward = NormalizedCapabilitySet::normalize([read_src.clone(), write_src.clone()]);
        assert_eq!(forward, backward);
        assert_eq!(
            forward.iter().cloned().collect::<Vec<_>>(),
            vec![read_src.clone(), write_src.clone()]
        );
        assert_pending(&diff([read_src.clone()], [write_src.clone()]));

        let metadata = Capability::filesystem_metadata(
            FileResource::new(FilesystemAnchor::Repo, "z.rs").expect("file"),
        );
        let execute =
            Capability::process_execute(ExecutableResource::new("aaa").expect("executable"));
        let connect = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            9,
        ));
        let ordered = NormalizedCapabilitySet::normalize([
            execute.clone(),
            connect.clone(),
            metadata.clone(),
        ]);
        assert_eq!(
            ordered.iter().cloned().collect::<Vec<_>>(),
            vec![metadata, connect, execute]
        );

        let repo = read("z.rs");
        let home = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "a.rs").expect("home"),
        );
        let anchors = NormalizedCapabilitySet::normalize([home.clone(), repo.clone()]);
        assert_eq!(
            anchors.iter().cloned().collect::<Vec<_>>(),
            vec![repo, home]
        );
    }

    #[test]
    fn differences_are_not_classified() {
        let child = read("src/lib.rs");
        let parent = read("src/**");
        assert!(parent.resource().contains(child.resource()));
        assert_ne!(child, parent);
        assert_pending(&diff([child.clone()], [parent.clone()]));
        assert_pending(&diff([parent.clone()], [child.clone()]));
        assert_pending(&diff(Vec::<Capability>::new(), [child.clone()]));
        assert_pending(&diff([child.clone()], Vec::<Capability>::new()));

        let other_action = write("src/**");
        assert_ne!(child.action(), other_action.action());
        assert_pending(&diff([child], [other_action]));
    }

    #[test]
    fn diff_of_a_value_with_itself_is_empty() {
        let mut runner = deterministic_runner();
        runner
            .run(&arb_capabilities(), |capabilities| {
                let comparison = diff(capabilities.clone(), capabilities.clone());
                prop_assert!(comparison.is_empty());
                prop_assert!(!comparison.classification_pending());
                prop_assert!(comparison.findings().expect("result").is_empty());
                let mut reversed = capabilities.clone();
                reversed.reverse();
                prop_assert!(diff(capabilities.clone(), reversed).is_empty());
                let mut duplicated = capabilities.clone();
                duplicated.extend(capabilities.iter().cloned());
                prop_assert!(diff(capabilities, duplicated).is_empty());
                Ok(())
            })
            .expect("diff identity");
    }

    #[test]
    fn normalization_does_not_change_diff_semantics() {
        let mut runner = deterministic_runner();
        runner
            .run(
                &(arb_capabilities(), arb_capabilities()),
                |(reference, current)| {
                    let normalized_reference: Vec<_> =
                        NormalizedCapabilitySet::normalize(reference.clone())
                            .iter()
                            .cloned()
                            .collect();
                    let normalized_current: Vec<_> =
                        NormalizedCapabilitySet::normalize(current.clone())
                            .iter()
                            .cloned()
                            .collect();
                    prop_assert_eq!(
                        diff(reference.clone(), current.clone()),
                        diff(normalized_reference, normalized_current)
                    );
                    let once = NormalizedCapabilitySet::normalize(reference.clone());
                    let twice = NormalizedCapabilitySet::normalize(once.iter().cloned());
                    prop_assert_eq!(once, twice);
                    for capability in reference {
                        prop_assert_eq!(normalize_capability(capability.clone()), capability);
                    }
                    Ok(())
                },
            )
            .expect("normalization boundary");
    }

    #[test]
    fn unequal_sets_stay_unclassified() {
        let mut runner = deterministic_runner();
        runner
            .run(
                &(arb_capabilities(), arb_capabilities()),
                |(reference, current)| {
                    let comparison = diff(reference.clone(), current.clone());
                    let same = NormalizedCapabilitySet::normalize(reference)
                        == NormalizedCapabilitySet::normalize(current);
                    prop_assert_eq!(comparison.is_empty(), same);
                    prop_assert_eq!(comparison.classification_pending(), !same);
                    if same {
                        prop_assert!(comparison.findings().expect("result").is_empty());
                    } else {
                        prop_assert!(comparison.findings().is_none());
                    }
                    let keys: Vec<_> = comparison
                        .reference()
                        .iter()
                        .map(|capability| CapabilityKey::new(capability.clone()))
                        .collect();
                    prop_assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]));
                    Ok(())
                },
            )
            .expect("unclassified difference");
    }

    #[test]
    fn capability_key_order_agrees_with_equality() {
        let mut runner = deterministic_runner();
        runner
            .run(&(arb_capability(), arb_capability()), |(left, right)| {
                let left_key = CapabilityKey::new(left.clone());
                let right_key = CapabilityKey::new(right.clone());
                prop_assert_eq!(
                    left_key.capability().clone(),
                    normalize_capability(left.clone())
                );
                prop_assert_eq!(
                    right_key.capability().clone(),
                    normalize_capability(right.clone())
                );
                prop_assert_eq!(
                    left_key == right_key,
                    normalize_capability(left) == normalize_capability(right)
                );
                prop_assert_eq!(
                    left_key.cmp(&right_key) == Ordering::Equal,
                    left_key == right_key
                );
                prop_assert_eq!(left_key.cmp(&right_key), right_key.cmp(&left_key).reverse());
                Ok(())
            })
            .expect("key order");
    }
}
