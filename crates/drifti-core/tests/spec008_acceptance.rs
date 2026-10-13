// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-008 drift acceptance and authorization-separation matrix.
//!
//! Criteria:
//! 1. Typed containment drives EXPANDED/REDUCED (not string prefix alone).
//! 2. Normalization does not create or hide drift.
//! 3. Cross-action changes are REMOVED plus ADDED, not containment drift.
//! 4. `Diff(A, A)` is empty for direct diff and run/profile/contract adapters.
//! 5. Structural [`diff`] leaves severity unset; classification is a separate step.
//!
//! Property and golden detail live in `drift_properties`, `drift_golden`, and
//! `drift_order`.

use drifti_core::adapters::{diff_contracts, diff_profiles, diff_runs};
use drifti_core::capability::Capability;
use drifti_core::contract::{parse_contract, AcceptedContract};
use drifti_core::diff::diff;
use drifti_core::drift::{DriftFinding, DriftKind};
use drifti_core::observation::{ObservedEvent, ObservedResource, Operation, Outcome};
use drifti_core::profile::{CapabilityProfile, ProfileEntry};
use drifti_core::resource::{FileResource, FilesystemAnchor, FilesystemRoots};
use drifti_core::severity;

const MINIMAL_CONTRACT: &str = "\
version: 1

filesystem:
  read:
    allow:
      - ./src/**
  write:
    allow:
      - ./src/**

process:
  execute:
    allow:
      - /usr/bin/git

network:
  connect:
    allow:
      - tcp://203.0.113.1:443
";

fn read(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn write(path: &str) -> Capability {
    Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn roots() -> FilesystemRoots {
    FilesystemRoots::new("/work/repo", "/home/user", "/tmp").expect("roots")
}

fn findings(comparison: &drifti_core::diff::DriftDiff) -> &[DriftFinding] {
    comparison.findings().expect("classified").findings()
}

fn loaded_contract() -> AcceptedContract {
    let document = parse_contract(MINIMAL_CONTRACT).expect("parse");
    AcceptedContract::loaded(document)
}

#[test]
fn matrix_criterion_1_string_prefix_without_containment_is_not_expansion() {
    let comparison = diff([read("src/a.rs")], [read("srcdir/b.rs")]);
    assert_eq!(findings(&comparison).len(), 2);
    assert!(findings(&comparison)
        .iter()
        .all(|finding| { matches!(finding.kind(), DriftKind::Added | DriftKind::Removed) }));
}

#[test]
fn matrix_criterion_2_normalization_does_not_hide_drift() {
    let canonical = read("src/lib.rs");
    let alias = read("./src/lib.rs");
    assert!(diff([canonical.clone()], [alias.clone()]).is_empty());
    assert!(!diff([alias], [read("src/other.rs")]).is_empty());
}

#[test]
fn matrix_criterion_3_cross_action_change_is_removed_plus_added() {
    let comparison = diff([read("src/a.rs")], [write("src/a.rs")]);
    assert_eq!(findings(&comparison).len(), 2);
    assert!(findings(&comparison)
        .iter()
        .any(|finding| finding.kind() == DriftKind::Removed));
    assert!(findings(&comparison)
        .iter()
        .any(|finding| finding.kind() == DriftKind::Added));
    assert!(findings(&comparison)
        .iter()
        .all(|finding| !matches!(finding.kind(), DriftKind::Expanded | DriftKind::Reduced)));
}

#[test]
fn matrix_criterion_4_diff_of_a_set_with_itself_is_empty() {
    let set = [read("src/a.rs"), read("src/b.rs"), read("src/domain/**")];
    let comparison = diff(set.clone(), set);
    assert!(comparison.is_empty());
    assert_eq!(findings(&comparison), &[] as &[DriftFinding]);

    let roots = roots();
    let event = ObservedEvent::new(
        Operation::FilesystemRead,
        ObservedResource::file("/work/repo/src/lib.rs").expect("path"),
        Outcome::Success,
    );
    assert!(diff_runs([event.clone()], [event], &roots).is_empty());

    let capability = read("src/lib.rs");
    let left = CapabilityProfile::from_entries([ProfileEntry::new(capability.clone(), 1)]);
    let right = CapabilityProfile::from_entries([ProfileEntry::new(capability, 4)]);
    assert!(diff_profiles(&left, &right).is_empty());

    let contract = loaded_contract();
    assert!(diff_contracts(&contract, &contract).is_empty());
}

#[test]
fn matrix_criterion_5_structural_diff_leaves_severity_unset() {
    let comparison = diff([read("src/a.rs"), read("src/b.rs")], [read("src/**")]);
    assert!(findings(&comparison)
        .iter()
        .all(|finding| finding.severity().is_none()));

    let classified = severity::attach_result(comparison.findings().expect("classified"));
    assert!(classified
        .findings()
        .iter()
        .any(|finding| finding.severity().is_some()));
}

#[test]
fn matrix_typed_containment_classifies_expanded_and_reduced() {
    let parent = read("src/**");
    let child = read("src/lib.rs");
    let expanded = diff([child.clone()], [parent.clone()]);
    assert_eq!(
        findings(&expanded),
        &[DriftFinding::expanded(child.clone(), parent.clone())]
    );

    let reduced = diff([parent], [child]);
    assert_eq!(findings(&reduced).len(), 1);
    assert_eq!(findings(&reduced)[0].kind(), DriftKind::Reduced);
}
