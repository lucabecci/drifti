// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Normalized comparison of capability sets.
//!
//! Both sides pass through [`normalize_capability`] and are grouped by
//! [`CapabilityKey`] before structural classification. Equivalent
//! capabilities share one canonical value, so they do not appear as drift.
//! [`diff`] of a set with itself is an empty [`crate::drift::DriftResult`].
//! An identity present only in the current set is
//! [`crate::drift::DriftKind::Added`]. An identity present only in the
//! reference set is [`crate::drift::DriftKind::Removed`]. The action is part
//! of the identity. This module does not classify containment as
//! [`crate::drift::DriftKind::Expanded`] or
//! [`crate::drift::DriftKind::Reduced`], and it does not infer intent.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::capability::Capability;
use crate::drift::{cmp_capability, DriftFinding, DriftResult};
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
    /// Identical groups produce an empty [`DriftResult`]. An identity on only
    /// one side is `ADDED` or `REMOVED`.
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
/// groups match and the finding list is empty. A capability present on only
/// one side is an `ADDED` or `REMOVED` finding. Containment does not change
/// that classification.
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
        let classified = exact_membership_findings(&reference, &current);
        debug_assert_eq!(reference == current, classified.is_empty());
        Self {
            reference,
            current,
            findings: Some(classified),
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

    /// Exact `ADDED` and `REMOVED` findings.
    ///
    /// `Some` empty result means the canonical sets match. `Some` with
    /// findings lists capabilities present on only one side. Exact membership
    /// does not leave the comparison without a result.
    #[must_use]
    pub fn findings(&self) -> Option<&DriftResult> {
        self.findings.as_ref()
    }

    /// Whether this comparison is an empty deterministic result.
    ///
    /// True only when the normalized sets match and the finding list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reference == self.current && self.findings.as_ref().is_some_and(DriftResult::is_empty)
    }

    /// Whether the canonical sets differ and no drift kind has been assigned.
    ///
    /// Exact `ADDED` and `REMOVED` membership is assigned before this is read,
    /// so an exact set change is not pending. This is not success and it is
    /// not a structural finding.
    #[must_use]
    pub fn classification_pending(&self) -> bool {
        self.reference != self.current && self.findings.is_none()
    }
}

/// Classifies identities that are present on exactly one side.
///
/// Identity is the action plus the normalized resource. Membership uses that
/// equality. A wider resource is not paired with a narrower one, and resource
/// text is not compared by prefix.
fn exact_membership_findings(
    reference: &NormalizedCapabilitySet,
    current: &NormalizedCapabilitySet,
) -> DriftResult {
    let removed = reference
        .entries
        .difference(&current.entries)
        .map(|key| DriftFinding::removed(key.capability().clone()));
    let added = current
        .entries
        .difference(&reference.entries)
        .map(|key| DriftFinding::added(key.capability().clone()));
    DriftResult::from_findings(removed.chain(added))
}

/// Normalizes `reference` and `current`, then classifies exact membership.
///
/// A capability present only in `current` is [`crate::drift::DriftKind::Added`].
/// A capability present only in `reference` is
/// [`crate::drift::DriftKind::Removed`]. The action is part of the identity,
/// so a different action is removal plus addition. Equivalent capabilities
/// share one identity and do not produce extra findings. The same canonical
/// set yields an empty result.
///
/// This comparison does not classify containment as
/// [`crate::drift::DriftKind::Expanded`] or
/// [`crate::drift::DriftKind::Reduced`], and it does not infer intent.
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
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::{diff, normalize_capability, CapabilityKey, DriftDiff, NormalizedCapabilitySet};
    use crate::capability::Capability;
    use crate::drift::{DriftFinding, DriftKind};
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

    fn keys(set: &NormalizedCapabilitySet) -> BTreeSet<CapabilityKey> {
        set.iter().cloned().map(CapabilityKey::new).collect()
    }

    fn assert_exact_membership(comparison: &DriftDiff) {
        assert!(
            !comparison.classification_pending(),
            "exact membership emits findings"
        );
        let result = comparison
            .findings()
            .expect("exact membership is classified");
        let findings = result.findings();
        assert!(
            findings.windows(2).all(|pair| pair[0] <= pair[1]),
            "findings are ordered"
        );
        let reference = keys(comparison.reference());
        let current = keys(comparison.current());
        let mut added = BTreeSet::new();
        let mut removed = BTreeSet::new();
        for finding in findings {
            assert!(finding.severity().is_none());
            match finding.kind() {
                DriftKind::Added => {
                    let capability = finding
                        .current()
                        .expect("added names the current capability")
                        .clone();
                    assert!(finding.reference().is_none());
                    assert!(
                        added.insert(CapabilityKey::new(capability)),
                        "duplicate added finding"
                    );
                }
                DriftKind::Removed => {
                    let capability = finding
                        .reference()
                        .expect("removed names the reference capability")
                        .clone();
                    assert!(finding.current().is_none());
                    assert!(
                        removed.insert(CapabilityKey::new(capability)),
                        "duplicate removed finding"
                    );
                }
                DriftKind::Expanded | DriftKind::Reduced => {
                    panic!("exact membership must not emit containment kinds");
                }
            }
        }
        let expected_added: BTreeSet<_> = current.difference(&reference).cloned().collect();
        let expected_removed: BTreeSet<_> = reference.difference(&current).cloned().collect();
        assert_eq!(added, expected_added);
        assert_eq!(removed, expected_removed);
        assert_eq!(added.len() + removed.len(), findings.len());
        assert_eq!(comparison.is_empty(), reference == current);
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
        let distinct_actions = diff([read_src.clone()], [write_src.clone()]);
        assert_exact_membership(&distinct_actions);
        assert_eq!(
            distinct_actions.findings().expect("classified").findings(),
            &[
                DriftFinding::added(write_src.clone()),
                DriftFinding::removed(read_src.clone()),
            ]
        );

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
    fn current_only_exact_capability_is_added() {
        let current = read("src/lib.rs");
        let comparison = diff(
            [current.clone(), current.clone()],
            [current.clone(), read("src/./lib.rs"), read("src/main.rs")],
        );
        let added = read("src/main.rs");
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            &[DriftFinding::added(added)]
        );
        assert!(comparison
            .findings()
            .expect("classified")
            .findings()
            .iter()
            .all(|finding| finding.kind() == DriftKind::Added));
        assert_exact_membership(&comparison);
    }

    #[test]
    fn reference_only_exact_capability_is_removed() {
        let removed = read("src/lib.rs");
        let kept = write("src/lib.rs");
        let comparison = diff(
            [removed.clone(), read("src/foo/../lib.rs"), kept.clone()],
            [kept.clone(), write("src/./lib.rs")],
        );
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            &[DriftFinding::removed(removed)]
        );
        assert!(comparison
            .findings()
            .expect("classified")
            .findings()
            .iter()
            .all(|finding| finding.kind() == DriftKind::Removed));
        assert_exact_membership(&comparison);
    }

    #[test]
    fn cross_action_change_is_not_expansion() {
        let read_file = read("src/lib.rs");
        let write_file = write("src/lib.rs");
        assert_ne!(read_file.action(), write_file.action());
        assert_eq!(read_file.resource(), write_file.resource());
        assert!(read_file.resource().contains(write_file.resource()));
        let comparison = diff([read_file.clone()], [write_file.clone()]);
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            &[
                DriftFinding::added(write_file),
                DriftFinding::removed(read_file),
            ]
        );
        assert_exact_membership(&comparison);

        let connect = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
        ));
        let listen = Capability::network_listen(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
        ));
        assert_ne!(connect.action(), listen.action());
        assert!(connect.resource().contains(listen.resource()));
        let endpoints = diff([connect.clone()], [listen.clone()]);
        assert_eq!(
            endpoints.findings().expect("classified").findings(),
            &[DriftFinding::added(listen), DriftFinding::removed(connect),]
        );
        assert_exact_membership(&endpoints);
    }

    #[test]
    fn same_action_inequality_is_not_containment_drift() {
        let child = read("src/lib.rs");
        let parent = read("src/**");
        assert_eq!(child.action(), parent.action());
        assert_ne!(child, parent);
        assert!(parent.resource().contains(child.resource()));
        let widened = diff([child.clone()], [parent.clone()]);
        assert_eq!(
            widened.findings().expect("classified").findings(),
            &[
                DriftFinding::added(parent.clone()),
                DriftFinding::removed(child.clone()),
            ]
        );
        let narrowed = diff([parent.clone()], [child.clone()]);
        assert_eq!(
            narrowed.findings().expect("classified").findings(),
            &[DriftFinding::added(child), DriftFinding::removed(parent),]
        );
        assert_exact_membership(&widened);
        assert_exact_membership(&narrowed);
    }

    #[test]
    fn string_prefix_is_not_expansion() {
        let shorter = FileResource::new(FilesystemAnchor::Repo, "src").expect("shorter");
        let longer = FileResource::new(FilesystemAnchor::Repo, "src2").expect("longer");
        let nested = FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("nested");
        assert!(longer.file_path().starts_with(shorter.file_path()));
        assert!(nested.file_path().starts_with(shorter.file_path()));
        assert!(!shorter.contains(&longer));
        assert!(!shorter.contains(&nested));
        let prefix = diff(
            [Capability::filesystem_read(shorter.clone())],
            [Capability::filesystem_read(longer)],
        );
        let directory = diff(
            [Capability::filesystem_read(shorter)],
            [Capability::filesystem_read(nested)],
        );
        assert_exact_membership(&prefix);
        assert_exact_membership(&directory);
        for comparison in [&prefix, &directory] {
            assert_eq!(comparison.findings().expect("classified").len(), 2);
            assert!(comparison
                .findings()
                .expect("classified")
                .findings()
                .iter()
                .all(|finding| {
                    matches!(finding.kind(), DriftKind::Added | DriftKind::Removed)
                }));
        }
    }

    #[test]
    fn equivalent_duplicates_do_not_duplicate_findings() {
        let canonical = read("src/lib.rs");
        let added = read("src/main.rs");
        let comparison = diff(
            [
                read("src/./lib.rs"),
                canonical.clone(),
                read("src/foo/../lib.rs"),
                canonical.clone(),
            ],
            [
                added.clone(),
                read("src/lib.rs"),
                read("src/./lib.rs"),
                added.clone(),
            ],
        );
        assert_eq!(comparison.reference().len(), 1);
        assert_eq!(comparison.current().len(), 2);
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            &[DriftFinding::added(added)]
        );
        assert_exact_membership(&comparison);

        let removed = write("src/lib.rs");
        let only_reference = diff(
            [removed.clone(), write("src/./lib.rs"), removed.clone()],
            Vec::<Capability>::new(),
        );
        assert_eq!(only_reference.reference().len(), 1);
        assert_eq!(
            only_reference.findings().expect("classified").findings(),
            &[DriftFinding::removed(removed)]
        );
        assert_exact_membership(&only_reference);
    }

    #[test]
    fn equal_input_sets_have_one_deterministic_result() {
        let read_a = read("a.rs");
        let read_b = read("b.rs");
        let read_c = read("c.rs");
        let write_a = write("a.rs");
        let write_b = write("b.rs");
        let shared = read("kept.rs");
        let forward = diff(
            [
                write_a.clone(),
                read_b.clone(),
                shared.clone(),
                read_b.clone(),
                read("./b.rs"),
            ],
            [
                read_a.clone(),
                write_b.clone(),
                shared.clone(),
                read("./a.rs"),
                write_b.clone(),
            ],
        );
        let reversed = diff(
            [shared.clone(), read_b.clone(), write_a.clone()],
            [write_b.clone(), shared, read_a.clone()],
        );
        let expected = [
            DriftFinding::added(read_a),
            DriftFinding::added(write_b),
            DriftFinding::removed(read_b),
            DriftFinding::removed(write_a.clone()),
        ];
        assert_eq!(forward, reversed);
        assert_eq!(
            forward.findings().expect("classified").findings(),
            &expected
        );
        assert_exact_membership(&forward);
        assert_exact_membership(&reversed);
        assert_empty(&diff(
            [write_a.clone(), read_c.clone(), write_a.clone()],
            [read("./c.rs"), write("./a.rs")],
        ));
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
    fn exact_membership_is_deterministic_and_only_added_or_removed() {
        let mut runner = deterministic_runner();
        runner
            .run(
                &(arb_capabilities(), arb_capabilities()),
                |(reference, current)| {
                    let comparison = diff(reference.clone(), current.clone());
                    prop_assert!(!comparison.classification_pending());
                    let result = comparison.findings().expect("classified");
                    let findings = result.findings();
                    let ordered = findings.windows(2).all(|pair| pair[0] <= pair[1]);
                    let only_exact = findings.iter().all(|finding| {
                        finding.severity().is_none()
                            && matches!(finding.kind(), DriftKind::Added | DriftKind::Removed)
                    });
                    prop_assert!(ordered);
                    prop_assert!(only_exact);
                    let reference_keys = keys(comparison.reference());
                    let current_keys = keys(comparison.current());
                    let added: BTreeSet<_> = findings
                        .iter()
                        .filter(|finding| finding.kind() == DriftKind::Added)
                        .map(|finding| {
                            CapabilityKey::new(finding.current().expect("current").clone())
                        })
                        .collect();
                    let removed: BTreeSet<_> = findings
                        .iter()
                        .filter(|finding| finding.kind() == DriftKind::Removed)
                        .map(|finding| {
                            CapabilityKey::new(finding.reference().expect("reference").clone())
                        })
                        .collect();
                    let added_count = added.len();
                    let removed_count = removed.len();
                    prop_assert_eq!(
                        added,
                        current_keys.difference(&reference_keys).cloned().collect()
                    );
                    prop_assert_eq!(
                        removed,
                        reference_keys.difference(&current_keys).cloned().collect()
                    );
                    prop_assert_eq!(added_count + removed_count, findings.len());
                    prop_assert_eq!(comparison.is_empty(), reference_keys == current_keys);

                    let mut reversed_reference = reference.clone();
                    reversed_reference.reverse();
                    let mut duplicated_current = current.clone();
                    duplicated_current.extend(current.iter().cloned());
                    prop_assert_eq!(
                        comparison.clone(),
                        diff(reversed_reference, duplicated_current)
                    );
                    Ok(())
                },
            )
            .expect("exact membership");
    }

    fn arb_nested_reads() -> impl Strategy<Value = (Capability, Capability)> {
        (
            prop_oneof![
                Just(FilesystemAnchor::Repo),
                Just(FilesystemAnchor::Home),
                Just(FilesystemAnchor::Temp),
                Just(FilesystemAnchor::Absolute),
            ],
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8),
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8),
        )
            .prop_map(|(anchor, parent_chars, child_chars)| {
                let parent_body: String = parent_chars.into_iter().collect();
                let child_body: String = child_chars.into_iter().collect();
                let (parent_path, child_path) = if anchor == FilesystemAnchor::Absolute {
                    (
                        format!("/{parent_body}/**"),
                        format!("/{parent_body}/{child_body}"),
                    )
                } else {
                    (
                        format!("{parent_body}/**"),
                        format!("{parent_body}/{child_body}"),
                    )
                };
                let parent = Capability::filesystem_read(
                    FileResource::new(anchor, parent_path).expect("parent"),
                );
                let child = Capability::filesystem_read(
                    FileResource::new(anchor, child_path).expect("child"),
                );
                (parent, child)
            })
    }

    #[test]
    fn containment_pairs_stay_exact_added_and_removed() {
        let mut runner = deterministic_runner();
        runner
            .run(&arb_nested_reads(), |(parent, child)| {
                prop_assert!(parent.resource().contains(child.resource()));
                prop_assert_ne!(&parent, &child);
                prop_assert_eq!(parent.action(), child.action());
                let narrowed = diff([parent.clone()], [child.clone()]);
                prop_assert_eq!(
                    narrowed.findings().expect("classified").findings(),
                    &[
                        DriftFinding::added(child.clone()),
                        DriftFinding::removed(parent.clone()),
                    ]
                );
                let widened = diff([child.clone()], [parent.clone()]);
                prop_assert_eq!(
                    widened.findings().expect("classified").findings(),
                    &[
                        DriftFinding::added(parent.clone()),
                        DriftFinding::removed(child.clone()),
                    ]
                );
                let write_child = Capability::filesystem_write(match child.resource() {
                    crate::resource::Resource::File(file) => file.clone(),
                    _ => panic!("nested read is a file"),
                });
                prop_assert_ne!(parent.action(), write_child.action());
                prop_assert!(parent.resource().contains(write_child.resource()));
                let crossed = diff([parent, child], [write_child.clone()]);
                let crossed_findings = crossed.findings().expect("classified").findings();
                let only_exact = crossed_findings
                    .iter()
                    .all(|finding| matches!(finding.kind(), DriftKind::Added | DriftKind::Removed));
                let records_added = crossed_findings.contains(&DriftFinding::added(write_child));
                prop_assert!(only_exact);
                prop_assert!(records_added);
                Ok(())
            })
            .expect("containment stays exact");
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
