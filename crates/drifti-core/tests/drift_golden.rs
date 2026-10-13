// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Concrete drift golden cases for containment, severity attachment, and adapters (KAN-73).

use drifti_core::adapters::{diff_profiles, diff_runs};
use drifti_core::capability::Capability;
use drifti_core::diff::diff;
use drifti_core::drift::{DriftFinding, DriftKind};
use drifti_core::observation::{ObservedEvent, ObservedResource, Operation, Outcome};
use drifti_core::profile::{CapabilityProfile, ProfileEntry};
use drifti_core::resource::{FileResource, FilesystemAnchor, FilesystemRoots};
use drifti_core::severity::{self, Severity};

fn read_repo(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn write_repo(path: &str) -> Capability {
    Capability::filesystem_write(FileResource::new(FilesystemAnchor::Repo, path).expect("file"))
}

fn read_home(path: &str) -> Capability {
    Capability::filesystem_read(FileResource::new(FilesystemAnchor::Home, path).expect("file"))
}

fn roots() -> FilesystemRoots {
    FilesystemRoots::new("/work/repo", "/home/user", "/tmp").expect("roots")
}

fn exercised_repo_read(host_path: &str) -> ObservedEvent {
    ObservedEvent::new(
        Operation::FilesystemRead,
        ObservedResource::file(host_path).expect("path"),
        Outcome::Success,
    )
}

fn findings(comparison: &drifti_core::diff::DriftDiff) -> &[DriftFinding] {
    comparison.findings().expect("classified").findings()
}

#[test]
fn golden_recursive_expansion_src_glob_to_repo_root() {
    let reference = read_repo("src/**");
    let current = read_repo("./**");
    let comparison = diff([reference.clone()], [current.clone()]);
    assert_eq!(
        findings(&comparison),
        &[DriftFinding::expanded(reference, current)]
    );
    assert!(findings(&comparison)
        .iter()
        .all(|finding| finding.severity().is_none()));
}

#[test]
fn golden_recursive_reduction_repo_root_to_src_glob() {
    let reference = read_repo("./**");
    let current = read_repo("src/**");
    let comparison = diff([reference.clone()], [current.clone()]);
    assert_eq!(
        findings(&comparison),
        &[DriftFinding::reduced(reference, current)]
    );
}

#[test]
fn golden_two_children_expand_into_one_parent_glob() {
    let reference_a = read_repo("src/a.rs");
    let reference_b = read_repo("src/b.rs");
    let parent = read_repo("src/**");
    let comparison = diff([reference_a.clone(), reference_b.clone()], [parent.clone()]);
    assert_eq!(
        findings(&comparison),
        &[
            DriftFinding::expanded(reference_a, parent.clone()),
            DriftFinding::expanded(reference_b, parent),
        ]
    );
}

#[test]
fn golden_cross_action_read_to_write_is_removed_then_added() {
    let read_lib = read_repo("src/lib.rs");
    let write_lib = write_repo("src/lib.rs");
    let comparison = diff([read_lib.clone()], [write_lib.clone()]);
    assert_eq!(
        findings(&comparison),
        &[
            DriftFinding::added(write_lib),
            DriftFinding::removed(read_lib),
        ]
    );
}

#[test]
fn golden_equivalent_normalized_paths_produce_empty_diff() {
    let reference = read_repo("src/./lib.rs");
    let current = read_repo("src/lib.rs");
    let comparison = diff([reference], [current]);
    assert!(comparison.is_empty());
    assert_eq!(findings(&comparison), &[] as &[DriftFinding]);
}

#[test]
fn golden_mixed_added_removed_expanded_in_engine_order() {
    let reference = [read_repo("docs/readme.md"), read_repo("src/lib.rs")];
    let current = [read_repo("notes/todo.rs"), read_repo("src/**")];
    let comparison = diff(reference, current);
    assert_eq!(
        findings(&comparison),
        &[
            DriftFinding::added(read_repo("notes/todo.rs")),
            DriftFinding::removed(read_repo("docs/readme.md")),
            DriftFinding::expanded(read_repo("src/lib.rs"), read_repo("src/**")),
        ]
    );
}

#[test]
fn golden_expansion_severity_attached_after_structural_diff() {
    let reference = read_repo("src/**");
    let current = read_repo("./**");
    let comparison = diff([reference.clone()], [current.clone()]);
    let structural = findings(&comparison);
    assert_eq!(structural.len(), 1);
    assert_eq!(structural[0].kind(), DriftKind::Expanded);
    assert!(structural[0].severity().is_none());

    let classified = severity::attach_result(comparison.findings().expect("classified"));
    let marked = classified.findings();
    assert_eq!(marked.len(), 1);
    assert_eq!(marked[0].kind(), DriftKind::Expanded);
    assert_eq!(marked[0].severity(), Some(&Severity::Medium));
}

#[test]
fn golden_home_ssh_key_added_then_critical_severity() {
    let added = read_home(".ssh/id_rsa");
    let comparison = diff([], [added.clone()]);
    assert_eq!(findings(&comparison), &[DriftFinding::added(added.clone())]);
    assert!(findings(&comparison)[0].severity().is_none());

    let classified = severity::attach_result(comparison.findings().expect("classified"));
    assert_eq!(classified.findings()[0].kind(), DriftKind::Added);
    assert_eq!(
        classified.findings()[0].severity(),
        Some(&Severity::Critical)
    );
}

#[test]
fn adapter_run_same_exercised_read_is_empty() {
    let roots = roots();
    let event = exercised_repo_read("/work/repo/src/lib.rs");
    let comparison = diff_runs([event.clone()], [event], &roots);
    assert!(comparison.is_empty());
    assert_eq!(findings(&comparison), &[] as &[DriftFinding]);
}

#[test]
fn adapter_profile_same_capability_is_empty() {
    let capability = read_repo("src/lib.rs");
    let left = CapabilityProfile::from_entries([ProfileEntry::new(capability.clone(), 2)]);
    let right = CapabilityProfile::from_entries([ProfileEntry::new(capability, 9)]);
    let comparison = diff_profiles(&left, &right);
    assert!(comparison.is_empty());
    assert_eq!(findings(&comparison), &[] as &[DriftFinding]);
}
