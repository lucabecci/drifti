// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-008 drift algebra property tests (KAN-73).

use std::net::{IpAddr, Ipv4Addr};

use drifti_core::capability::{Action, Capability};
use drifti_core::diff::{diff, DriftDiff, NormalizedCapabilitySet};
use drifti_core::drift::{DriftFinding, DriftKind, DriftResult};
use drifti_core::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
    NetworkResource,
};
use drifti_core::severity::{attach_result, Severity};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRng, TestRunner};

fn read(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn write(path: &str) -> Capability {
    Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
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

fn arb_filesystem_containment_pair() -> impl Strategy<Value = (Capability, Capability)> {
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
                (narrow, wide)
            },
        )
}

fn arb_string_prefix_without_containment() -> impl Strategy<Value = (FileResource, FileResource)> {
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
    let only_membership = findings.iter().all(|finding| {
        finding.severity().is_none()
            && matches!(finding.kind(), DriftKind::Added | DriftKind::Removed)
    });
    prop_assert!(only_membership);
    Ok(())
}

fn assert_structural_order_preserved(
    structural: &DriftResult,
    classified: &DriftResult<Severity>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(structural.len(), classified.len());
    for (left, right) in structural
        .findings()
        .iter()
        .zip(classified.findings().iter())
    {
        prop_assert_eq!(left.kind(), right.kind());
        prop_assert_eq!(left.reference(), right.reference());
        prop_assert_eq!(left.current(), right.current());
        prop_assert!(right.severity().is_some());
    }
    Ok(())
}

#[test]
fn diff_of_a_value_with_itself_is_empty() {
    let single = read("src/lib.rs");
    assert!(diff([single.clone()], [single]).is_empty());

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
fn containment_expansion_and_reduction_are_inverses() {
    let mut runner = deterministic_runner();
    runner
        .run(&arb_filesystem_containment_pair(), |(narrow, wide)| {
            prop_assert_ne!(&narrow, &wide);
            prop_assert_eq!(narrow.action(), wide.action());
            prop_assert!(wide.resource().contains(narrow.resource()));
            prop_assert!(!narrow.resource().contains(wide.resource()));

            let expanded = diff([narrow.clone()], [wide.clone()]);
            let reduced = diff([wide.clone()], [narrow.clone()]);
            prop_assert_eq!(
                expanded.findings().expect("classified").findings(),
                &[DriftFinding::expanded(narrow.clone(), wide.clone())]
            );
            prop_assert_eq!(
                reduced.findings().expect("classified").findings(),
                &[DriftFinding::reduced(wide, narrow)]
            );
            Ok(())
        })
        .expect("containment inverses");
}

#[test]
fn normalization_does_not_change_diff_semantics() {
    let canonical = read("src/a.rs");
    let variants = [read("src/./a.rs"), read("src//a.rs"), read("src/a.rs")];
    for variant in &variants {
        assert_eq!(variant, &canonical);
        assert!(diff([variant.clone()], [canonical.clone()]).is_empty());
    }
    assert!(diff(variants, [canonical.clone()]).is_empty());

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
                Ok(())
            },
        )
        .expect("normalization boundary");
}

#[test]
fn cross_action_change_is_remove_plus_add() {
    let read_file = read("src/lib.rs");
    let write_file = write("src/lib.rs");
    let comparison = diff([read_file.clone()], [write_file.clone()]);
    assert_eq!(
        comparison.findings().expect("classified").findings(),
        &[
            DriftFinding::added(write_file),
            DriftFinding::removed(read_file),
        ]
    );
    assert!(comparison
        .findings()
        .expect("classified")
        .findings()
        .iter()
        .all(|finding| !matches!(finding.kind(), DriftKind::Expanded | DriftKind::Reduced)));

    let mut runner = deterministic_runner();
    runner
        .run(&arb_file(), |file| {
            let read_cap = Capability::filesystem_read(file.clone());
            let write_cap = Capability::filesystem_write(file);
            prop_assert_ne!(read_cap.action(), write_cap.action());
            prop_assert_eq!(read_cap.resource(), write_cap.resource());
            let comparison = diff([read_cap.clone()], [write_cap.clone()]);
            let findings = comparison.findings().expect("classified").findings();
            prop_assert_eq!(findings.len(), 2);
            let only_added_or_removed = findings
                .iter()
                .all(|finding| matches!(finding.kind(), DriftKind::Added | DriftKind::Removed));
            prop_assert!(only_added_or_removed);
            prop_assert_eq!(findings[0].kind(), DriftKind::Added);
            prop_assert_eq!(findings[1].kind(), DriftKind::Removed);
            prop_assert_eq!(findings[0].current(), Some(&write_cap));
            prop_assert_eq!(findings[1].reference(), Some(&read_cap));
            Ok(())
        })
        .expect("cross action");
}

#[test]
fn input_permutation_does_not_change_ordered_findings() {
    let mut runner = deterministic_runner();
    runner
        .run(
            &(arb_capabilities(), arb_capabilities()),
            |(reference, current)| {
                let canonical = diff(reference.clone(), current.clone());
                let structural = canonical.findings().expect("classified").clone();

                let mut reversed_reference = reference.clone();
                reversed_reference.reverse();
                let mut reversed_current = current.clone();
                reversed_current.reverse();
                let mut duplicated_reference = reference.clone();
                duplicated_reference.extend(reference.iter().cloned());
                let mut duplicated_current = current.clone();
                duplicated_current.extend(current.iter().cloned());

                for (left_reference, left_current) in [
                    (reversed_reference.clone(), current.clone()),
                    (reference.clone(), reversed_current.clone()),
                    (duplicated_reference, duplicated_current),
                    (reversed_reference.clone(), reversed_current.clone()),
                ] {
                    prop_assert_eq!(canonical.clone(), diff(left_reference, left_current));
                }

                let classified = attach_result(&structural);
                assert_structural_order_preserved(&structural, &classified)?;

                let shuffled = diff(reversed_reference, reversed_current);
                let shuffled_structural = shuffled.findings().expect("classified");
                prop_assert_eq!(structural.findings(), shuffled_structural.findings());
                assert_structural_order_preserved(
                    shuffled_structural,
                    &attach_result(shuffled_structural),
                )?;
                Ok(())
            },
        )
        .expect("input permutation");
}

#[test]
fn string_prefix_is_not_containment() {
    let src = FileResource::new(FilesystemAnchor::Repo, "src").expect("src");
    let src2 = FileResource::new(FilesystemAnchor::Repo, "src2").expect("src2");
    let src_a = FileResource::new(FilesystemAnchor::Repo, "src/a").expect("src/a");
    let src_a_dash_b = FileResource::new(FilesystemAnchor::Repo, "src/a-b").expect("src/a-b");
    for (shorter, longer) in [(src, src2), (src_a, src_a_dash_b)] {
        assert!(longer.file_path().starts_with(shorter.file_path()));
        assert!(!shorter.contains(&longer));
        let comparison = diff(
            [Capability::filesystem_read(shorter.clone())],
            [Capability::filesystem_read(longer.clone())],
        );
        assert_only_added_and_removed(&comparison).expect("prefix pair");
    }

    let mut runner = deterministic_runner();
    runner
        .run(
            &arb_string_prefix_without_containment(),
            |(shorter, longer)| {
                prop_assert!(longer.file_path().starts_with(shorter.file_path()));
                prop_assert!(!shorter.contains(&longer));
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
