// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural capability drift.
//!
//! [`DriftKind`] names `ADDED`, `REMOVED`, `EXPANDED`, and `REDUCED`.
//! A [`DriftFinding`] records one of those kinds. Constructing a finding does
//! not decide which kind a pair of capabilities has, and nothing here infers
//! intent. Severity metadata is optional. Comparison leaves it unset; a later
//! classification step may attach it.
//!
//! [`DriftResult`] stores findings in one order: kind, then reference identity,
//! then current identity, then severity. The same findings produce the same
//! sequence from any input order.

use std::cmp::Ordering;

use crate::capability::Capability;
use crate::resource::{
    FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol, NetworkResource, Resource,
};

/// Structural change between a reference capability state and a current one.
///
/// The names are the drift kinds from SPEC-008. This type does not classify a
/// pair of capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DriftKind {
    /// Present in the current state and absent from the reference.
    Added,
    /// Present in the reference and absent from the current state.
    Removed,
    /// Current resource scope contains more authority than the reference.
    Expanded,
    /// Current resource scope contains less authority than the reference.
    Reduced,
}

impl DriftKind {
    /// Every drift kind, in comparison order.
    pub const ALL: [Self; 4] = [Self::Added, Self::Removed, Self::Expanded, Self::Reduced];

    /// Stable kind name from SPEC-008.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "ADDED",
            Self::Removed => "REMOVED",
            Self::Expanded => "EXPANDED",
            Self::Reduced => "REDUCED",
        }
    }
}

/// One structural drift finding.
///
/// `S` is severity metadata supplied by a later classification step. The
/// default `()` means no severity is attached. [`DriftFinding::with_severity`]
/// records metadata without changing the kind or the capabilities. This type
/// does not rank resources and does not infer intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftFinding<S = ()> {
    kind: DriftKind,
    reference: Option<Capability>,
    current: Option<Capability>,
    severity: Option<S>,
}

impl DriftFinding {
    /// `ADDED` finding for one current capability. Severity is unset.
    #[must_use]
    pub fn added(current: Capability) -> Self {
        Self {
            kind: DriftKind::Added,
            reference: None,
            current: Some(current),
            severity: None,
        }
    }

    /// `REMOVED` finding for one reference capability. Severity is unset.
    #[must_use]
    pub fn removed(reference: Capability) -> Self {
        Self {
            kind: DriftKind::Removed,
            reference: Some(reference),
            current: None,
            severity: None,
        }
    }

    /// `EXPANDED` finding for a reference and current capability.
    ///
    /// The constructor stores the pair. It does not test containment.
    #[must_use]
    pub fn expanded(reference: Capability, current: Capability) -> Self {
        Self {
            kind: DriftKind::Expanded,
            reference: Some(reference),
            current: Some(current),
            severity: None,
        }
    }

    /// `REDUCED` finding for a reference and current capability.
    ///
    /// The constructor stores the pair. It does not test containment.
    #[must_use]
    pub fn reduced(reference: Capability, current: Capability) -> Self {
        Self {
            kind: DriftKind::Reduced,
            reference: Some(reference),
            current: Some(current),
            severity: None,
        }
    }
}

impl<S> DriftFinding<S> {
    /// Structural kind.
    #[must_use]
    pub fn kind(&self) -> DriftKind {
        self.kind
    }

    /// Reference capability, when this finding names one.
    #[must_use]
    pub fn reference(&self) -> Option<&Capability> {
        self.reference.as_ref()
    }

    /// Current capability, when this finding names one.
    #[must_use]
    pub fn current(&self) -> Option<&Capability> {
        self.current.as_ref()
    }

    /// Severity metadata, when a later step has attached it.
    #[must_use]
    pub fn severity(&self) -> Option<&S> {
        self.severity.as_ref()
    }

    /// Returns this finding with severity metadata attached.
    ///
    /// The kind and both capabilities stay as they are. Passing metadata does
    /// not classify the finding and does not infer why the change happened.
    #[must_use]
    pub fn with_severity<T>(self, severity: T) -> DriftFinding<T> {
        DriftFinding {
            kind: self.kind,
            reference: self.reference,
            current: self.current,
            severity: Some(severity),
        }
    }
}

impl<S: Ord> PartialOrd for DriftFinding<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<S: Ord> Ord for DriftFinding<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| cmp_option_capability(self.reference.as_ref(), other.reference.as_ref()))
            .then_with(|| cmp_option_capability(self.current.as_ref(), other.current.as_ref()))
            .then_with(|| self.severity.cmp(&other.severity))
    }
}

/// Ordered structural findings.
///
/// An empty result is the deterministic representation of no structural
/// change. Order follows [`Ord`] for [`DriftFinding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftResult<S = ()> {
    findings: Vec<DriftFinding<S>>,
}

impl<S> Default for DriftResult<S> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<S> DriftResult<S> {
    /// No findings.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    /// Findings in deterministic order.
    #[must_use]
    pub fn findings(&self) -> &[DriftFinding<S>] {
        &self.findings
    }

    /// Whether the finding list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Number of findings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.findings.len()
    }
}

impl<S: Ord> DriftResult<S> {
    /// Collects findings and sorts them.
    ///
    /// Input order does not change the stored sequence.
    #[must_use]
    pub fn from_findings(findings: impl IntoIterator<Item = DriftFinding<S>>) -> Self {
        let mut findings: Vec<_> = findings.into_iter().collect();
        findings.sort();
        Self { findings }
    }
}

/// Total order used to group capabilities by identity.
///
/// Equal capabilities compare equal. Action order is the SPEC-001 action name,
/// not the enum discriminant. Resource order is the resource family, then that
/// family's own fields.
#[must_use]
pub(crate) fn cmp_capability(left: &Capability, right: &Capability) -> Ordering {
    left.action()
        .as_str()
        .cmp(right.action().as_str())
        .then_with(|| cmp_resource(left.resource(), right.resource()))
}

fn cmp_option_capability(left: Option<&Capability>, right: Option<&Capability>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => cmp_capability(left, right),
    }
}

fn cmp_resource(left: &Resource, right: &Resource) -> Ordering {
    match (left, right) {
        (Resource::File(left), Resource::File(right)) => cmp_file(left, right),
        (Resource::Executable(left), Resource::Executable(right)) => {
            left.identity().cmp(right.identity())
        }
        (Resource::Network(left), Resource::Network(right)) => cmp_network(left, right),
        (Resource::File(_), Resource::Executable(_) | Resource::Network(_)) => Ordering::Less,
        (Resource::Executable(_), Resource::File(_)) => Ordering::Greater,
        (Resource::Executable(_), Resource::Network(_)) => Ordering::Less,
        (Resource::Network(_), Resource::File(_) | Resource::Executable(_)) => Ordering::Greater,
    }
}

fn cmp_file(left: &FileResource, right: &FileResource) -> Ordering {
    anchor_rank(left.anchor())
        .cmp(&anchor_rank(right.anchor()))
        .then_with(|| left.file_path().cmp(right.file_path()))
}

fn cmp_network(left: &NetworkResource, right: &NetworkResource) -> Ordering {
    protocol_rank(left.protocol())
        .cmp(&protocol_rank(right.protocol()))
        .then_with(|| cmp_address(left.address(), right.address()))
        .then_with(|| left.port().cmp(&right.port()))
}

fn cmp_address(left: NetworkAddress, right: NetworkAddress) -> Ordering {
    match (left, right) {
        (NetworkAddress::Ip(left), NetworkAddress::Ip(right)) => left.cmp(&right),
        (NetworkAddress::Cidr(left), NetworkAddress::Cidr(right)) => left
            .address()
            .cmp(&right.address())
            .then(left.prefix_length().cmp(&right.prefix_length())),
        (NetworkAddress::Ip(_), NetworkAddress::Cidr(_)) => Ordering::Less,
        (NetworkAddress::Cidr(_), NetworkAddress::Ip(_)) => Ordering::Greater,
    }
}

fn anchor_rank(anchor: FilesystemAnchor) -> u8 {
    match anchor {
        FilesystemAnchor::Repo => 0,
        FilesystemAnchor::Home => 1,
        FilesystemAnchor::Temp => 2,
        FilesystemAnchor::Absolute => 3,
    }
}

fn protocol_rank(protocol: NetworkProtocol) -> u8 {
    match protocol {
        NetworkProtocol::Tcp => 0,
        NetworkProtocol::Udp => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::{cmp_capability, DriftFinding, DriftKind, DriftResult};
    use crate::capability::Capability;
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource,
    };
    use std::cmp::Ordering;
    use std::net::{IpAddr, Ipv4Addr};

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct Sensitivity {
        rank: u8,
    }

    #[test]
    fn kind_names_and_order_follow_the_spec_list() {
        let mut kinds = DriftKind::ALL;
        kinds.sort();
        assert_eq!(kinds, DriftKind::ALL);
        assert_eq!(
            DriftKind::ALL.map(DriftKind::as_str),
            ["ADDED", "REMOVED", "EXPANDED", "REDUCED"]
        );
    }

    #[test]
    fn structural_constructors_leave_severity_unset() {
        let reference = read("src/lib.rs");
        let current = read("other.rs");
        assert!(!reference.resource().contains(current.resource()));
        let added = DriftFinding::added(current.clone());
        assert_eq!(added.kind(), DriftKind::Added);
        assert!(added.reference().is_none());
        assert_eq!(added.current(), Some(&current));
        assert!(added.severity().is_none());

        let removed = DriftFinding::removed(reference.clone());
        assert_eq!(removed.kind(), DriftKind::Removed);
        assert_eq!(removed.reference(), Some(&reference));
        assert!(removed.current().is_none());
        assert!(removed.severity().is_none());

        let expanded = DriftFinding::expanded(reference.clone(), current.clone());
        assert_eq!(expanded.kind(), DriftKind::Expanded);
        assert_eq!(expanded.reference(), Some(&reference));
        assert_eq!(expanded.current(), Some(&current));
        assert!(expanded.severity().is_none());

        let reduced = DriftFinding::reduced(reference.clone(), current.clone());
        assert_eq!(reduced.kind(), DriftKind::Reduced);
        assert_eq!(reduced.reference(), Some(&reference));
        assert_eq!(reduced.current(), Some(&current));
        assert!(reduced.severity().is_none());
    }

    #[test]
    fn severity_metadata_can_be_attached_later() {
        let current = read("src/lib.rs");
        let structural = DriftFinding::added(current.clone());
        let marked = structural.clone().with_severity(Sensitivity { rank: 2 });
        assert!(structural.severity().is_none());
        assert_eq!(marked.severity(), Some(&Sensitivity { rank: 2 }));
        assert_eq!(marked.kind(), DriftKind::Added);
        assert_eq!(marked.current(), Some(&current));
        assert!(marked.reference().is_none());
    }

    #[test]
    fn finding_order_does_not_depend_on_input_order() {
        let alpha = read("src/a.rs");
        let beta = read("src/b.rs");
        let expected = [
            DriftFinding::added(alpha.clone()),
            DriftFinding::added(beta.clone()),
            DriftFinding::removed(alpha.clone()),
            DriftFinding::expanded(alpha.clone(), beta.clone()),
            DriftFinding::reduced(beta.clone(), alpha.clone()),
        ];
        let reversed = DriftResult::from_findings(expected.iter().cloned().rev());
        let forward = DriftResult::from_findings(expected.clone());
        assert_eq!(forward, reversed);
        assert_eq!(forward.findings(), &expected);
        assert_eq!(DriftResult::<()>::from_findings([]), DriftResult::empty());
        assert!(DriftResult::<()>::default().is_empty());
    }

    #[test]
    fn severity_is_a_final_ordering_key() {
        let current = read("src/a.rs");
        let unset = DriftFinding::added(current.clone());
        let set = DriftFinding::added(current).with_severity(());
        let result = DriftResult::from_findings([set.clone(), unset.clone()]);
        assert_eq!(result.findings(), &[unset, set]);

        let low = DriftFinding::removed(read("src/a.rs")).with_severity(Sensitivity { rank: 1 });
        let high = DriftFinding::removed(read("src/a.rs")).with_severity(Sensitivity { rank: 2 });
        let ranked = DriftResult::from_findings([high.clone(), low.clone()]);
        assert_eq!(ranked.findings(), &[low, high]);
    }

    #[test]
    fn capability_order_uses_action_names() {
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
        assert_eq!(
            cmp_capability(&metadata, &connect),
            Ordering::Less,
            "filesystem.metadata precedes network.connect"
        );
        assert_eq!(cmp_capability(&connect, &execute), Ordering::Less);
        assert_eq!(cmp_capability(&metadata, &metadata), Ordering::Equal);
        let repo = read("z.rs");
        let home = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "a.rs").expect("home"),
        );
        assert_eq!(cmp_capability(&repo, &home), Ordering::Less);
    }
}
