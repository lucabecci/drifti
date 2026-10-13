// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Narrow generalization of observed resources.
//!
//! Repository-local exact file capabilities with the same action may collapse to
//! the narrowest safe recursive prefix. Containment uses [`FileResource::contains`];
//! resource text is never compared by string prefix alone. Generalization never
//! crosses a [`FilesystemAnchor`], merges different actions, or broadens sensitive
//! directories. Output is deterministic and is not authorization.

use std::collections::{BTreeMap, HashMap};

use crate::capability::{Action, Capability};
use crate::diff::CapabilityKey;
use crate::resource::{FileResource, FilesystemAnchor, Resource};

/// Conservative candidate scopes from observed exact repo-local paths.
///
/// Non-filesystem capabilities, non-repo file capabilities, already recursive
/// repo paths, and sensitive exact paths pass through unchanged. Remaining
/// exact repo file capabilities group by action; a group of two or more
/// compatible paths may collapse to one recursive prefix when a safe prefix
/// exists. Single paths and incompatible groups stay exact.
///
/// Identical input capabilities deduplicate before grouping. Output order
/// follows capability identity order.
#[must_use]
pub fn generalize_candidates(candidates: impl IntoIterator<Item = Capability>) -> Vec<Capability> {
    let mut unique = BTreeMap::<CapabilityKey, Capability>::new();
    for capability in candidates {
        unique
            .entry(CapabilityKey::new(capability.clone()))
            .or_insert(capability);
    }

    let mut passthrough = Vec::new();
    let mut by_action: HashMap<Action, Vec<FileResource>> = HashMap::new();

    for capability in unique.into_values() {
        match generalize_bucket(&capability) {
            GeneralizeBucket::Passthrough => passthrough.push(capability),
            GeneralizeBucket::Mergeable(file) => {
                by_action.entry(capability.action()).or_default().push(file);
            }
        }
    }

    let mut output = passthrough;
    for (action, files) in by_action {
        output.extend(generalize_action_group(action, &files));
    }

    output.sort_by(|left, right| {
        CapabilityKey::new(left.clone()).cmp(&CapabilityKey::new(right.clone()))
    });
    output
}

enum GeneralizeBucket {
    Passthrough,
    Mergeable(FileResource),
}

fn generalize_bucket(capability: &Capability) -> GeneralizeBucket {
    let Resource::File(file) = capability.resource() else {
        return GeneralizeBucket::Passthrough;
    };
    if file.anchor() != FilesystemAnchor::Repo {
        return GeneralizeBucket::Passthrough;
    }
    if file.is_recursive() || touches_sensitive_directory(file.file_path()) {
        return GeneralizeBucket::Passthrough;
    }
    if !capability.action().accepts(capability.resource()) {
        return GeneralizeBucket::Passthrough;
    }
    GeneralizeBucket::Mergeable(file.clone())
}

fn generalize_action_group(action: Action, files: &[FileResource]) -> Vec<Capability> {
    if files.len() < 2 {
        return files
            .iter()
            .map(|file| capability_with_action(action, file.clone()))
            .collect();
    }

    let Some(prefix) = narrowest_safe_recursive_prefix(files) else {
        return files
            .iter()
            .map(|file| capability_with_action(action, file.clone()))
            .collect();
    };

    vec![capability_with_action(action, prefix)]
}

fn capability_with_action(action: Action, file: FileResource) -> Capability {
    match action {
        Action::FilesystemRead => Capability::filesystem_read(file),
        Action::FilesystemWrite => Capability::filesystem_write(file),
        Action::FilesystemMetadata => Capability::filesystem_metadata(file),
        Action::ProcessExecute | Action::NetworkConnect | Action::NetworkListen => {
            unreachable!("non-filesystem actions do not enter repo merge groups")
        }
    }
}

fn narrowest_safe_recursive_prefix(files: &[FileResource]) -> Option<FileResource> {
    if files.len() < 2 {
        return None;
    }

    let components: Vec<Vec<&str>> = files
        .iter()
        .filter_map(|file| exact_path_components(file.file_path()))
        .collect();
    if components.len() != files.len() {
        return None;
    }

    let shared = longest_common_prefix_len(&components);
    if shared == 0 {
        return None;
    }

    let prefix_text = directory_prefix(&components[0][..shared]);
    if touches_sensitive_directory(&prefix_text) {
        return None;
    }

    let prefix = FileResource::new(FilesystemAnchor::Repo, marked_recursive(&prefix_text)).ok()?;
    if files.iter().all(|file| prefix.contains(file)) {
        Some(prefix)
    } else {
        None
    }
}

fn exact_path_components(file_path: &str) -> Option<Vec<&str>> {
    if file_path.contains("**") {
        return None;
    }
    if file_path == "." {
        return Some(Vec::new());
    }
    Some(
        file_path
            .trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .collect(),
    )
}

fn longest_common_prefix_len(all: &[Vec<&str>]) -> usize {
    let Some(first) = all.first() else {
        return 0;
    };
    let mut shared = first.len();
    for path in all.iter().skip(1) {
        shared = shared.min(path.len());
        for index in 0..shared {
            if first[index] != path[index] {
                shared = index;
                break;
            }
        }
    }
    shared
}

fn directory_prefix(shared_components: &[&str]) -> String {
    if shared_components.is_empty() {
        ".".to_owned()
    } else {
        shared_components.join("/")
    }
}

fn marked_recursive(base: &str) -> String {
    match base {
        "." => "**".to_owned(),
        _ => format!("{base}/**"),
    }
}

fn touches_sensitive_directory(file_path: &str) -> bool {
    const SENSITIVE: [&str; 4] = [".ssh", ".aws", ".gnupg", ".kube"];
    exact_path_components(file_path)
        .is_some_and(|components| components.iter().any(|part| SENSITIVE.contains(part)))
}

#[cfg(test)]
mod tests {
    use crate::capability::Capability;
    use crate::policy::Decision;
    use crate::resource::{FileResource, FilesystemAnchor};

    use super::generalize_candidates;

    fn repo_file(path: &str) -> FileResource {
        FileResource::new(FilesystemAnchor::Repo, path).expect("file")
    }

    fn read(path: &str) -> Capability {
        Capability::filesystem_read(repo_file(path))
    }

    fn write(path: &str) -> Capability {
        Capability::filesystem_write(repo_file(path))
    }

    fn not_a_policy_decision(capabilities: Vec<Capability>) {
        trait NotAPolicyDecision {}
        impl NotAPolicyDecision for Capability {}
        impl NotAPolicyDecision for Vec<Capability> {}
        fn witness(_: &impl NotAPolicyDecision) {}
        fn assert_ne_allowed(decision: Decision) {
            assert_ne!(decision, Decision::Allowed);
        }
        witness(&capabilities);
        assert_ne_allowed(Decision::Denied);
    }

    #[test]
    fn compatible_repo_paths_use_the_narrowest_recursive_prefix() {
        let input = [
            read("src/domain/mod.rs"),
            read("src/domain/lib.rs"),
            read("src/other/app.rs"),
        ];
        let generalized = generalize_candidates(input.clone());
        assert_eq!(generalized.len(), 1);
        assert_eq!(generalized[0], read("src/**"));
        not_a_policy_decision(generalized.clone());

        let narrow = generalize_candidates([read("src/domain/mod.rs"), read("src/domain/lib.rs")]);
        assert_eq!(narrow, vec![read("src/domain/**")]);
    }

    #[test]
    fn generalization_never_crosses_resource_anchors() {
        let home = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, "src/lib.rs").expect("home"),
        );
        let repo = read("src/lib.rs");
        let generalized = generalize_candidates([home.clone(), repo.clone()]);
        assert_eq!(generalized.len(), 2);
        assert!(generalized.contains(&home));
        assert!(generalized.contains(&repo));
    }

    #[test]
    fn different_actions_are_never_merged() {
        let generalized =
            generalize_candidates([read("src/a.rs"), write("src/b.rs"), read("src/c.rs")]);
        assert_eq!(generalized.len(), 2);
        assert!(generalized.contains(&read("src/**")));
        assert!(generalized.contains(&write("src/b.rs")));
    }

    #[test]
    fn single_or_incompatible_paths_remain_exact() {
        assert_eq!(
            generalize_candidates([read("src/lib.rs")]),
            vec![read("src/lib.rs")]
        );
        let unrelated = generalize_candidates([read("src/a.rs"), read("docs/b.md")]);
        assert_eq!(unrelated.len(), 2);
        assert!(unrelated.contains(&read("src/a.rs")));
        assert!(unrelated.contains(&read("docs/b.md")));
        let root = generalize_candidates([read("a.rs"), read("b.rs")]);
        assert_eq!(root.len(), 2);
    }

    #[test]
    fn output_is_deterministic_regardless_of_input_order() {
        let a = read("src/domain/mod.rs");
        let b = read("src/domain/lib.rs");
        let c = read("src/other/app.rs");
        let forward = generalize_candidates([a.clone(), b.clone(), c.clone()]);
        let reverse = generalize_candidates([c, b, a]);
        assert_eq!(forward, reverse);
    }

    #[test]
    fn sensitive_directories_are_never_broadened() {
        let ssh = generalize_candidates([read(".ssh/id_rsa"), read(".ssh/known_hosts")]);
        assert_eq!(ssh.len(), 2);
        assert!(ssh.contains(&read(".ssh/id_rsa")));
        assert!(ssh.contains(&read(".ssh/known_hosts")));
        for dir in [".aws", ".gnupg", ".kube"] {
            let left = read(&format!("{dir}/one"));
            let right = read(&format!("{dir}/two"));
            let kept = generalize_candidates([left.clone(), right.clone()]);
            assert_eq!(kept.len(), 2);
            assert!(kept.contains(&left));
            assert!(kept.contains(&right));
        }
    }

    #[test]
    fn string_prefix_alone_does_not_merge_unrelated_paths() {
        let generalized = generalize_candidates([read("src/a.rs"), read("srcdir/b.rs")]);
        assert_eq!(generalized.len(), 2);
    }
}
