// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable [`DriftFinding`] order for [`diff`] output (KAN-72).
//!
//! Finding order is the engine order for terminal and JSON consumers: kind,
//! then reference capability identity, then current capability identity, then
//! severity (unset from [`diff`]). Do not sort by severity; severity display
//! order belongs to a later CLI spec.

use std::net::{IpAddr, Ipv4Addr};

use drifti_core::capability::Capability;
use drifti_core::diff::{diff, NormalizedCapabilitySet};
use drifti_core::drift::{DriftFinding, DriftKind};
use drifti_core::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
    NetworkResource,
};

fn read(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn write(path: &str) -> Capability {
    Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

/// Widening reference side: children and cross-action read, no parent glob.
fn mixed_reference() -> Vec<Capability> {
    vec![
        read("docs/readme.md"),
        read("src/a.rs"),
        read("src/b.rs"),
        read("src/domain/**"),
        read("src/lib.rs"),
    ]
}

/// Widening current side: parent glob, membership, and cross-action write.
fn mixed_current() -> Vec<Capability> {
    vec![read("notes/todo.rs"), write("src/lib.rs"), read("src/**")]
}

fn expected_mixed_findings() -> Vec<DriftFinding> {
    let reference = mixed_reference();
    let current = mixed_current();
    let removed = reference[0].clone();
    let first = reference[1].clone();
    let second = reference[2].clone();
    let nested = reference[3].clone();
    let read_lib = reference[4].clone();
    let added = current[0].clone();
    let write_lib = current[1].clone();
    let parent = current[2].clone();

    let mut expected = vec![
        DriftFinding::added(added),
        DriftFinding::added(write_lib),
        DriftFinding::removed(removed),
        DriftFinding::expanded(first, parent.clone()),
        DriftFinding::expanded(second, parent.clone()),
        DriftFinding::expanded(nested, parent.clone()),
        DriftFinding::expanded(read_lib, parent),
    ];
    expected.sort();
    expected
}

fn mixed_union() -> Vec<Capability> {
    NormalizedCapabilitySet::normalize(mixed_reference().into_iter().chain(mixed_current()))
        .iter()
        .cloned()
        .collect()
}

const REFERENCE_PERMUTATIONS: [&[usize]; 8] = [
    &[0, 1, 2, 3, 4],
    &[4, 3, 2, 1, 0],
    &[2, 0, 4, 1, 3],
    &[1, 3, 0, 4, 2],
    &[3, 1, 4, 0, 2],
    &[0, 4, 2, 3, 1],
    &[4, 0, 3, 1, 2],
    &[2, 4, 1, 3, 0],
];

const CURRENT_PERMUTATIONS: [&[usize]; 8] = [
    &[0, 1, 2],
    &[2, 1, 0],
    &[1, 2, 0],
    &[0, 2, 1],
    &[2, 0, 1],
    &[1, 0, 2],
    &[0, 1, 2, 0],
    &[2, 2, 1, 0],
];

fn permute(capabilities: &[Capability], order: &[usize]) -> Vec<Capability> {
    order
        .iter()
        .map(|&index| capabilities[index].clone())
        .collect()
}

fn assert_findings_sorted(findings: &[DriftFinding]) {
    assert!(
        findings.windows(2).all(|pair| pair[0] <= pair[1]),
        "findings must follow DriftFinding Ord"
    );
    assert!(findings.iter().all(|finding| finding.severity().is_none()));
}

#[test]
fn diff_finding_order_is_stable_across_input_permutations() {
    let reference = mixed_reference();
    let current = mixed_current();
    let expected = expected_mixed_findings();
    let canonical = diff(reference.clone(), current.clone());
    let findings = canonical.findings().expect("classified").findings();
    assert_eq!(findings, expected.as_slice());
    assert_findings_sorted(findings);
    assert!(findings
        .iter()
        .any(|finding| finding.kind() == DriftKind::Added));
    assert!(findings
        .iter()
        .any(|finding| finding.kind() == DriftKind::Removed));
    assert!(findings
        .iter()
        .any(|finding| finding.kind() == DriftKind::Expanded));

    for (reference_order, current_order) in REFERENCE_PERMUTATIONS
        .iter()
        .zip(CURRENT_PERMUTATIONS.iter())
    {
        let permuted_reference = permute(&reference, reference_order);
        let permuted_current = permute(&current, current_order);
        let comparison = diff(permuted_reference, permuted_current);
        assert_eq!(
            comparison.findings().expect("classified").findings(),
            expected.as_slice()
        );
    }
}

#[test]
fn diff_of_mixed_set_with_itself_is_empty() {
    let set = mixed_union();
    let comparison = diff(set.clone(), set);
    assert!(comparison.is_empty());
    assert_eq!(
        comparison.findings().expect("classified").findings(),
        &[] as &[DriftFinding]
    );
}

#[test]
fn added_findings_order_by_action_name_not_enum_discriminant() {
    let metadata = Capability::filesystem_metadata(
        FileResource::new(FilesystemAnchor::Repo, "z.rs").expect("file"),
    );
    let filesystem_read = read("z.rs");
    let connect = Capability::network_connect(NetworkResource::new(
        NetworkProtocol::Tcp,
        NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        9,
    ));
    let execute = Capability::process_execute(ExecutableResource::new("aaa").expect("executable"));
    let comparison = diff(
        [],
        [
            execute.clone(),
            connect.clone(),
            filesystem_read.clone(),
            metadata.clone(),
        ],
    );
    assert_eq!(
        comparison.findings().expect("classified").findings(),
        &[
            DriftFinding::added(metadata),
            DriftFinding::added(filesystem_read),
            DriftFinding::added(connect),
            DriftFinding::added(execute),
        ]
    );
}

#[test]
fn expanded_and_reduced_use_repo_glob_paths() {
    let narrow = read("src/**");
    let wide = read("./**");
    assert_ne!(narrow, wide);
    let widened = diff([read("src/lib.rs")], [wide.clone()]);
    assert_eq!(
        widened.findings().expect("classified").findings(),
        &[DriftFinding::expanded(read("src/lib.rs"), wide.clone())]
    );
    let narrowed = diff([wide], [read("src/lib.rs")]);
    assert_eq!(
        narrowed.findings().expect("classified").findings(),
        &[DriftFinding::reduced(read("./**"), read("src/lib.rs"))]
    );
}
