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
//! reference set is [`crate::drift::DriftKind::Removed`]. When the action
//! matches and [`Resource::contains`] says one scope covers the other, the
//! pair is [`crate::drift::DriftKind::Expanded`] or
//! [`crate::drift::DriftKind::Reduced`]. A different action stays removal
//! plus addition. This module does not infer intent, and it does not compare
//! resource text by prefix.

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
/// groups match and the finding list is empty. An identity on only one side
/// is `ADDED` or `REMOVED`, unless typed containment pairs it with the other
/// side as `EXPANDED` or `REDUCED`.
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
        let classified = structural_findings(&reference, &current);
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

    /// Structural findings for this comparison.
    ///
    /// `Some` empty result means the canonical sets match. `Some` with
    /// findings lists `ADDED`, `REMOVED`, `EXPANDED`, and `REDUCED`.
    /// Membership and containment are classified before this is read.
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
    /// Membership and containment are assigned before this is read, so a
    /// structural set change is not pending. This is not success and it is
    /// not a structural finding.
    #[must_use]
    pub fn classification_pending(&self) -> bool {
        self.reference != self.current && self.findings.is_none()
    }
}

/// Classifies identities that are present on exactly one side.
///
/// Equal identities produce no finding. A same-action pair whose resources
/// nest under [`Resource::contains`] is `EXPANDED` or `REDUCED`, and that
/// capability is not also `ADDED` or `REMOVED`. Every other identity on one
/// side stays `ADDED` or `REMOVED`. Resource text is not compared by prefix.
fn structural_findings(
    reference: &NormalizedCapabilitySet,
    current: &NormalizedCapabilitySet,
) -> DriftResult {
    let reference_only: Vec<&Capability> = reference
        .entries
        .difference(&current.entries)
        .map(CapabilityKey::capability)
        .collect();
    let current_only: Vec<&Capability> = current
        .entries
        .difference(&reference.entries)
        .map(CapabilityKey::capability)
        .collect();
    let mut reference_paired = vec![false; reference_only.len()];
    let mut current_paired = vec![false; current_only.len()];
    let mut findings = Vec::new();

    for (reference_index, reference_capability) in reference_only.iter().enumerate() {
        for (current_index, current_capability) in current_only.iter().enumerate() {
            let Some(finding) = containment_finding(reference_capability, current_capability)
            else {
                continue;
            };
            reference_paired[reference_index] = true;
            current_paired[current_index] = true;
            findings.push(finding);
        }
    }

    for (index, capability) in reference_only.iter().enumerate() {
        if !reference_paired[index] {
            findings.push(DriftFinding::removed((*capability).clone()));
        }
    }
    for (index, capability) in current_only.iter().enumerate() {
        if !current_paired[index] {
            findings.push(DriftFinding::added((*capability).clone()));
        }
    }

    DriftResult::from_findings(findings)
}

/// Pairs one reference capability with one current capability.
///
/// The action and resource family must match, and the capabilities must not
/// be equal. [`Resource::contains`] decides the direction: current covering
/// reference is [`crate::drift::DriftKind::Expanded`], and reference covering
/// current is [`crate::drift::DriftKind::Reduced`]. A string prefix is not
/// enough.
fn containment_finding(reference: &Capability, current: &Capability) -> Option<DriftFinding> {
    if reference.action() != current.action()
        || reference.resource().kind() != current.resource().kind()
        || reference == current
    {
        return None;
    }
    if current.resource().contains(reference.resource()) {
        Some(DriftFinding::expanded(reference.clone(), current.clone()))
    } else if reference.resource().contains(current.resource()) {
        Some(DriftFinding::reduced(reference.clone(), current.clone()))
    } else {
        None
    }
}

/// Normalizes `reference` and `current`, then classifies structural drift.
///
/// A capability present only in `current` is [`crate::drift::DriftKind::Added`].
/// A capability present only in `reference` is
/// [`crate::drift::DriftKind::Removed`]. The action is part of the identity,
/// so a different action is removal plus addition even when one resource
/// covers the other.
///
/// The same action uses [`Resource::contains`]. Current covering reference is
/// [`crate::drift::DriftKind::Expanded`]. Reference covering current is
/// [`crate::drift::DriftKind::Reduced`]. Equal capabilities produce no
/// finding. A paired capability is not also added or removed. Scopes that do
/// not contain each other stay removal plus addition. Every compatible pair
/// is reported. Findings follow [`DriftFinding`] order. Severity stays unset.
/// This comparison does not infer intent.
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
    use proptest::test_runner::{TestCaseError, TestRng, TestRunner};

    use super::{diff, normalize_capability, CapabilityKey, DriftDiff, NormalizedCapabilitySet};
    use crate::capability::{Action, Capability};
    use crate::drift::{DriftFinding, DriftKind};
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource, Resource,
    };

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn write(path: &str) -> Capability {
        Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    fn assert_direction(narrow: Capability, wide: Capability) {
        assert_eq!(narrow.action(), wide.action());
        assert_ne!(narrow, wide);
        assert_eq!(narrow.resource().kind(), wide.resource().kind());
        assert!(wide.resource().contains(narrow.resource()));
        assert!(!narrow.resource().contains(wide.resource()));
        let expanded = diff([narrow.clone()], [wide.clone()]);
        let reduced = diff([wide.clone()], [narrow.clone()]);
        assert_eq!(
            expanded.findings().expect("classified").findings(),
            &[DriftFinding::expanded(narrow.clone(), wide.clone())]
        );
        assert_eq!(
            reduced.findings().expect("classified").findings(),
            &[DriftFinding::reduced(wide, narrow)]
        );
        for comparison in [&expanded, &reduced] {
            assert!(!comparison.is_empty());
            assert!(comparison
                .findings()
                .expect("classified")
                .findings()
                .iter()
                .all(|finding| finding.severity().is_none()));
        }
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

        let read_tree = read("src/**");
        let write_child = write("src/lib.rs");
        assert_ne!(read_tree.action(), write_child.action());
        assert_ne!(read_tree.resource(), write_child.resource());
        assert!(read_tree.resource().contains(write_child.resource()));
        let nested_actions = diff([read_tree.clone()], [write_child.clone()]);
        assert_eq!(
            nested_actions.findings().expect("classified").findings(),
            &[
                DriftFinding::added(write_child),
                DriftFinding::removed(read_tree),
            ]
        );
        assert_exact_membership(&nested_actions);
    }

    #[test]
    fn same_action_containment_is_expanded_or_reduced() {
        let child = read("src/lib.rs");
        let parent = read("src/**");
        assert_eq!(child.action(), parent.action());
        assert_ne!(child, parent);
        assert!(parent.resource().contains(child.resource()));
        assert!(!child.resource().contains(parent.resource()));
        let widened = diff([child.clone()], [parent.clone()]);
        assert_eq!(
            widened.findings().expect("classified").findings(),
            &[DriftFinding::expanded(child.clone(), parent.clone())]
        );
        let narrowed = diff([parent.clone()], [child.clone()]);
        assert_eq!(
            narrowed.findings().expect("classified").findings(),
            &[DriftFinding::reduced(parent, child)]
        );
        for comparison in [&widened, &narrowed] {
            assert!(!comparison.classification_pending());
            assert!(!comparison.is_empty());
            let findings = comparison.findings().expect("classified").findings();
            assert_eq!(findings.len(), 1);
            assert!(findings.iter().all(|finding| {
                finding.severity().is_none()
                    && matches!(finding.kind(), DriftKind::Expanded | DriftKind::Reduced)
            }));
        }
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
    fn recursive_filesystem_scopes_follow_containment_direction() {
        let file = read("src/domain/mod.rs");
        let domain = read("src/domain/**");
        let src = read("src/**");
        let root = read("**");
        let exact_src = read("src");
        let outside = read("srcdir/lib.rs");

        assert!(root.resource().contains(src.resource()));
        assert!(src.resource().contains(domain.resource()));
        assert!(domain.resource().contains(file.resource()));
        assert!(root.resource().contains(file.resource()));
        assert!(src.resource().contains(exact_src.resource()));
        assert!(!exact_src.resource().contains(file.resource()));
        assert!(!src.resource().contains(outside.resource()));
        assert!(!file.resource().contains(domain.resource()));

        for (narrow, wide) in [
            (file.clone(), domain.clone()),
            (domain.clone(), src.clone()),
            (src.clone(), root.clone()),
            (file.clone(), root.clone()),
            (exact_src, src.clone()),
            (file.clone(), src.clone()),
        ] {
            assert_direction(narrow, wide);
        }

        assert_empty(&diff([root.clone()], [read("**")]));
        assert_empty(&diff([read("src/./**")], [src]));
        assert_empty(&diff([read("src/domain/./mod.rs")], [file.clone()]));

        assert_direction(
            Capability::filesystem_read(
                FileResource::new(FilesystemAnchor::Absolute, "/etc/hosts").expect("hosts"),
            ),
            Capability::filesystem_read(
                FileResource::new(FilesystemAnchor::Absolute, "/etc/**").expect("etc"),
            ),
        );
        assert_direction(write("src/lib.rs"), write("src/**"));
        assert_direction(
            Capability::filesystem_metadata(
                FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file"),
            ),
            Capability::filesystem_metadata(
                FileResource::new(FilesystemAnchor::Repo, "src/**").expect("tree"),
            ),
        );

        let normalized_child = read("src/domain/./mod.rs");
        let normalized_parent = read("src/foo/../**");
        assert_eq!(normalized_child, file);
        assert_eq!(normalized_parent, read("src/**"));
        assert_direction(normalized_child, normalized_parent);
    }

    #[test]
    fn one_parent_with_several_children_emits_each_pair() {
        let parent = read("src/**");
        let first = read("src/a.rs");
        let second = read("src/b.rs");
        let nested = read("src/domain/**");
        let removed = read("docs/readme.md");
        let added = read("notes/todo.rs");
        for child in [&first, &second, &nested] {
            assert!(parent.resource().contains(child.resource()));
            assert!(!child.resource().contains(parent.resource()));
        }
        assert!(!parent.resource().contains(removed.resource()));
        assert!(!added.resource().contains(parent.resource()));
        assert!(!parent.resource().contains(added.resource()));

        let mut expected_widened = vec![
            DriftFinding::added(added.clone()),
            DriftFinding::removed(removed.clone()),
            DriftFinding::expanded(first.clone(), parent.clone()),
            DriftFinding::expanded(second.clone(), parent.clone()),
            DriftFinding::expanded(nested.clone(), parent.clone()),
        ];
        expected_widened.sort();
        let widened = diff(
            [
                removed.clone(),
                nested.clone(),
                first.clone(),
                second.clone(),
            ],
            [added.clone(), parent.clone()],
        );
        let widened_again = diff(
            [
                second.clone(),
                first.clone(),
                removed.clone(),
                nested.clone(),
            ],
            [parent.clone(), added.clone()],
        );
        assert_eq!(widened, widened_again);
        assert_eq!(
            widened.findings().expect("classified").findings(),
            expected_widened.as_slice()
        );
        assert!(widened
            .findings()
            .expect("classified")
            .findings()
            .iter()
            .all(|finding| finding.severity().is_none()));

        let mut expected_narrowed = vec![
            DriftFinding::added(added.clone()),
            DriftFinding::removed(removed.clone()),
            DriftFinding::reduced(parent.clone(), first.clone()),
            DriftFinding::reduced(parent.clone(), second.clone()),
            DriftFinding::reduced(parent.clone(), nested.clone()),
        ];
        expected_narrowed.sort();
        let narrowed = diff([parent.clone(), removed], [nested, second, added, first]);
        assert_eq!(
            narrowed.findings().expect("classified").findings(),
            expected_narrowed.as_slice()
        );
    }

    #[test]
    fn exact_identity_is_not_reclassified_by_a_nested_scope() {
        let parent = read("src/**");
        let child = read("src/lib.rs");
        assert!(parent.resource().contains(child.resource()));
        let removed = diff([parent.clone(), child.clone()], [parent.clone()]);
        assert_eq!(
            removed.findings().expect("classified").findings(),
            &[DriftFinding::removed(child.clone())]
        );
        let added = diff([parent.clone()], [child.clone(), parent.clone()]);
        assert_eq!(
            added.findings().expect("classified").findings(),
            &[DriftFinding::added(child.clone())]
        );
        assert_empty(&diff(
            [parent.clone(), child.clone()],
            [read("src/./lib.rs"), read("src/**")],
        ));
    }

    #[test]
    fn incomparable_scopes_stay_added_and_removed() {
        let src = read("src/**");
        let docs = read("docs/**");
        assert!(!src.resource().contains(docs.resource()));
        assert!(!docs.resource().contains(src.resource()));
        assert_exact_membership(&diff([src], [docs]));

        let left = read("src/a.rs");
        let right = read("src/b.rs");
        assert!(!left.resource().contains(right.resource()));
        assert!(!right.resource().contains(left.resource()));
        assert_exact_membership(&diff([left], [right]));

        let repo = read("src/**");
        let home = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "src/lib.rs").expect("home"),
        );
        assert_eq!(repo.action(), home.action());
        assert!(!repo.resource().contains(home.resource()));
        assert!(!home.resource().contains(repo.resource()));
        assert_exact_membership(&diff([repo], [home]));
    }

    #[test]
    fn non_file_inequality_does_not_invent_containment() {
        let cidr = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8).expect("cidr"),
            443,
        ));
        let host = Capability::network_connect(NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            443,
        ));
        assert_ne!(cidr, host);
        assert!(!cidr.resource().contains(host.resource()));
        assert!(!host.resource().contains(cidr.resource()));
        assert_exact_membership(&diff([cidr], [host]));

        let git = Capability::process_execute(ExecutableResource::new("git").expect("git"));
        let git_lfs =
            Capability::process_execute(ExecutableResource::new("git-lfs").expect("git-lfs"));
        let Resource::Executable(git_lfs_resource) = git_lfs.resource() else {
            panic!("git-lfs is an executable");
        };
        assert!(git_lfs_resource.identity().starts_with("git"));
        assert!(!git.resource().contains(git_lfs.resource()));
        assert!(!git_lfs.resource().contains(git.resource()));
        assert_exact_membership(&diff([git], [git_lfs]));

        let file = read("src/**");
        let executable =
            Capability::process_execute(ExecutableResource::new("src").expect("executable"));
        assert_ne!(file.resource().kind(), executable.resource().kind());
        assert!(!file.resource().contains(executable.resource()));
        assert!(!executable.resource().contains(file.resource()));
        assert_exact_membership(&diff([file], [executable]));
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
                    for reference_key in reference_keys.difference(&current_keys) {
                        for current_key in current_keys.difference(&reference_keys) {
                            let contained = same_action_strict_containment(
                                reference_key.capability(),
                                current_key.capability(),
                            );
                            prop_assert!(!contained);
                        }
                    }
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

    fn same_action_strict_containment(reference: &Capability, current: &Capability) -> bool {
        reference.action() == current.action()
            && reference.resource().kind() == current.resource().kind()
            && reference != current
            && (current.resource().contains(reference.resource())
                || reference.resource().contains(current.resource()))
    }

    fn file_of(capability: &Capability) -> FileResource {
        match capability.resource() {
            Resource::File(file) => file.clone(),
            Resource::Executable(_) | Resource::Network(_) => {
                panic!("filesystem containment uses a file resource")
            }
        }
    }

    fn filesystem_action(index: u8) -> Action {
        match index % 3 {
            0 => Action::FilesystemRead,
            1 => Action::FilesystemWrite,
            _ => Action::FilesystemMetadata,
        }
    }

    fn filesystem_capability(action: Action, file: FileResource) -> Capability {
        match action {
            Action::FilesystemRead => Capability::filesystem_read(file),
            Action::FilesystemWrite => Capability::filesystem_write(file),
            Action::FilesystemMetadata => Capability::filesystem_metadata(file),
            Action::ProcessExecute | Action::NetworkConnect | Action::NetworkListen => {
                panic!("filesystem containment uses a filesystem action")
            }
        }
    }

    fn contained_file(anchor: FilesystemAnchor, parts: &[String], recursive: bool) -> FileResource {
        let file_path = if parts.is_empty() {
            match (anchor, recursive) {
                (FilesystemAnchor::Absolute, true) => "/**".to_owned(),
                (FilesystemAnchor::Absolute, false) => "/".to_owned(),
                (_, true) => "**".to_owned(),
                (_, false) => ".".to_owned(),
            }
        } else {
            let joined = parts.join("/");
            let base = if anchor == FilesystemAnchor::Absolute {
                format!("/{joined}")
            } else {
                joined
            };
            if recursive {
                format!("{base}/**")
            } else {
                base
            }
        };
        FileResource::new(anchor, file_path).expect("contained file")
    }

    fn arb_anchor() -> impl Strategy<Value = FilesystemAnchor> {
        prop_oneof![
            Just(FilesystemAnchor::Repo),
            Just(FilesystemAnchor::Home),
            Just(FilesystemAnchor::Temp),
            Just(FilesystemAnchor::Absolute),
        ]
    }

    fn arb_component() -> impl Strategy<Value = String> {
        proptest::collection::vec(proptest::char::range('a', 'z'), 1..=4)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn arb_strict_filesystem_containment() -> impl Strategy<Value = (Capability, Capability)> {
        (
            arb_anchor(),
            proptest::collection::vec(arb_component(), 0..=3),
            proptest::collection::vec(arb_component(), 1..=3),
            any::<bool>(),
            any::<u8>(),
        )
            .prop_map(
                |(anchor, parent_parts, extra, child_recursive, action_index)| {
                    let mut child_parts = parent_parts.clone();
                    child_parts.extend(extra);
                    let action = filesystem_action(action_index);
                    let wide =
                        filesystem_capability(action, contained_file(anchor, &parent_parts, true));
                    let narrow = filesystem_capability(
                        action,
                        contained_file(anchor, &child_parts, child_recursive),
                    );
                    (wide, narrow)
                },
            )
    }

    fn arb_parent_and_children() -> impl Strategy<Value = (Capability, Vec<Capability>)> {
        (
            arb_anchor(),
            proptest::collection::vec(arb_component(), 0..=2),
            proptest::collection::vec(
                (
                    proptest::collection::vec(arb_component(), 1..=2),
                    any::<bool>(),
                ),
                1..=4,
            ),
        )
            .prop_map(|(anchor, parent_parts, children)| {
                let parent = filesystem_capability(
                    Action::FilesystemRead,
                    contained_file(anchor, &parent_parts, true),
                );
                let children = children
                    .into_iter()
                    .map(|(extra, recursive)| {
                        let mut parts = parent_parts.clone();
                        parts.extend(extra);
                        filesystem_capability(
                            Action::FilesystemRead,
                            contained_file(anchor, &parts, recursive),
                        )
                    })
                    .collect();
                (parent, children)
            })
    }

    fn arb_string_prefix_without_containment() -> impl Strategy<Value = (FileResource, FileResource)>
    {
        (
            any::<bool>(),
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8),
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=4),
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..=4),
        )
            .prop_map(|(nested, stem_chars, extra, name_chars)| {
                let stem: String = stem_chars.into_iter().collect();
                let (shorter, longer) = if nested {
                    let name: String = name_chars.into_iter().collect();
                    (stem.clone(), format!("{stem}/{name}"))
                } else {
                    let mut longer = stem.clone();
                    longer.extend(extra);
                    (stem, longer)
                };
                (
                    FileResource::new(FilesystemAnchor::Repo, shorter).expect("shorter"),
                    FileResource::new(FilesystemAnchor::Repo, longer).expect("longer"),
                )
            })
    }

    fn assert_only_added_and_removed(comparison: &DriftDiff) -> Result<(), TestCaseError> {
        let findings = comparison.findings().expect("classified").findings();
        prop_assert_eq!(findings.len(), 2);
        let membership = findings.iter().all(|finding| {
            finding.severity().is_none()
                && matches!(finding.kind(), DriftKind::Added | DriftKind::Removed)
        });
        let ordered = findings.windows(2).all(|pair| pair[0] <= pair[1]);
        prop_assert!(membership);
        prop_assert!(ordered);
        Ok(())
    }

    #[test]
    fn containment_direction_follows_resource_contains() {
        let mut runner = deterministic_runner();
        runner
            .run(&arb_strict_filesystem_containment(), |(wide, narrow)| {
                prop_assert!(wide.resource().contains(narrow.resource()));
                prop_assert!(!narrow.resource().contains(wide.resource()));
                prop_assert_ne!(&wide, &narrow);
                prop_assert_eq!(wide.action(), narrow.action());
                prop_assert_eq!(wide.resource().kind(), narrow.resource().kind());

                let expanded = diff([narrow.clone()], [wide.clone()]);
                prop_assert_eq!(
                    expanded.findings().expect("classified").findings(),
                    &[DriftFinding::expanded(narrow.clone(), wide.clone())]
                );
                let reduced = diff([wide.clone()], [narrow.clone()]);
                prop_assert_eq!(
                    reduced.findings().expect("classified").findings(),
                    &[DriftFinding::reduced(wide.clone(), narrow.clone())]
                );
                let severity_unset = expanded
                    .findings()
                    .expect("classified")
                    .findings()
                    .iter()
                    .chain(reduced.findings().expect("classified").findings())
                    .all(|finding| finding.severity().is_none());
                prop_assert!(severity_unset);
                prop_assert!(diff([wide.clone()], [wide.clone()]).is_empty());
                prop_assert!(diff([narrow.clone()], [narrow.clone()]).is_empty());

                let crossed = if narrow.action() == Action::FilesystemRead {
                    Capability::filesystem_write(file_of(&narrow))
                } else {
                    Capability::filesystem_read(file_of(&narrow))
                };
                prop_assert_ne!(wide.action(), crossed.action());
                prop_assert!(wide.resource().contains(crossed.resource()));
                let cross = diff([wide.clone()], [crossed.clone()]);
                prop_assert_eq!(
                    cross.findings().expect("classified").findings(),
                    &[DriftFinding::added(crossed), DriftFinding::removed(wide),]
                );
                Ok(())
            })
            .expect("containment direction");
    }

    #[test]
    fn several_children_follow_containment_without_membership_findings() {
        let mut runner = deterministic_runner();
        runner
            .run(&arb_parent_and_children(), |(parent, children)| {
                let distinct: Vec<_> = NormalizedCapabilitySet::normalize(children)
                    .iter()
                    .cloned()
                    .collect();
                prop_assert!(!distinct.is_empty());
                let mut reduced = Vec::new();
                let mut expanded = Vec::new();
                for child in &distinct {
                    prop_assert!(parent.resource().contains(child.resource()));
                    prop_assert!(!child.resource().contains(parent.resource()));
                    prop_assert_ne!(&parent, child);
                    reduced.push(DriftFinding::reduced(parent.clone(), child.clone()));
                    expanded.push(DriftFinding::expanded(child.clone(), parent.clone()));
                }
                reduced.sort();
                expanded.sort();
                let narrowed = diff([parent.clone()], distinct.clone());
                let widened = diff(distinct.clone(), [parent.clone()]);
                prop_assert_eq!(
                    narrowed.findings().expect("classified").findings(),
                    reduced.as_slice()
                );
                prop_assert_eq!(
                    widened.findings().expect("classified").findings(),
                    expanded.as_slice()
                );
                let mut reversed = distinct;
                reversed.reverse();
                prop_assert_eq!(narrowed, diff([parent.clone()], reversed.clone()));
                prop_assert_eq!(widened, diff(reversed, [parent]));
                Ok(())
            })
            .expect("several children");
    }

    #[test]
    fn string_prefix_without_contains_is_not_expanded() {
        let mut runner = deterministic_runner();
        runner
            .run(
                &arb_string_prefix_without_containment(),
                |(shorter, longer)| {
                    prop_assert!(longer.file_path().starts_with(shorter.file_path()));
                    prop_assert!(!shorter.contains(&longer));
                    prop_assert!(!longer.contains(&shorter));
                    let forward = diff(
                        [Capability::filesystem_read(shorter.clone())],
                        [Capability::filesystem_read(longer.clone())],
                    );
                    let backward = diff(
                        [Capability::filesystem_read(longer)],
                        [Capability::filesystem_read(shorter)],
                    );
                    assert_only_added_and_removed(&forward)?;
                    assert_only_added_and_removed(&backward)?;
                    Ok(())
                },
            )
            .expect("string prefix");
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
