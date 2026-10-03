// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-001 property suite.
//!
//! These tests close the automatable acceptance criteria:
//! typed MVP domains, lossless capability serialization, equality and
//! containment, portable repository paths, and the absence of a Linux crate
//! dependency. The Linux boundary itself is `dependencies_stay_inside_the_domain_boundary`
//! in `boundary.rs`.

use std::net::{IpAddr, Ipv4Addr};

use drifti_core::capability::{Action, Capability};
use drifti_core::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, FilesystemRoots, NetworkAddress,
    NetworkProtocol, NetworkResource, Resource, ResourceError,
};
use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};

fn runner() -> TestRunner {
    let config = ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
}

fn roots(repo: &str) -> FilesystemRoots {
    FilesystemRoots::new(repo, "/home/dev", "/tmp").expect("roots")
}

fn under(root: &str, relative: &str) -> String {
    if relative == "." {
        root.to_owned()
    } else {
        format!("{root}/{relative}")
    }
}

fn component_strategy() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::collection::vec(
        prop_oneof![Just("src"), Just("lib.rs"), Just("."), Just(".."), Just("")],
        0..=6,
    )
}

#[test]
fn normalization_is_idempotent_and_repo_paths_are_portable() {
    let mut runner = runner();
    runner
        .run(&component_strategy(), |parts| {
            let supplied = parts.join("/");
            if supplied.is_empty() {
                return Ok(());
            }
            let first = match FileResource::new(FilesystemAnchor::Repo, supplied) {
                Ok(resource) => resource,
                Err(ResourceError::EscapesAnchor | ResourceError::NotRelative) => return Ok(()),
                Err(error) => panic!("unexpected file error: {error}"),
            };
            let again =
                FileResource::new(first.anchor(), first.file_path()).expect("normalized again");
            prop_assert_eq!(&first, &again);

            let one = roots("/checkouts/one");
            let two = roots("/checkouts/two");
            let from_one =
                FileResource::from_host_path(&one, under("/checkouts/one", first.file_path()))
                    .expect("checkout one");
            let from_two =
                FileResource::from_host_path(&two, under("/checkouts/two", first.file_path()))
                    .expect("checkout two");
            prop_assert_eq!(&from_one, &from_two);
            prop_assert_eq!(&from_one, &first);
            let repeated =
                FileResource::from_host_path(&one, from_one.host_path(&one)).expect("hosted again");
            prop_assert_eq!(&repeated, &from_one);
            Ok(())
        })
        .expect("normalization");
}

#[test]
fn executable_normalization_is_idempotent() {
    let mut runner = runner();
    runner
        .run(&component_strategy(), |parts| {
            let supplied = parts.join("/");
            if supplied.is_empty() {
                return Ok(());
            }
            match ExecutableResource::new(supplied) {
                Ok(executable) => {
                    let again = ExecutableResource::new(executable.identity()).expect("again");
                    prop_assert_eq!(executable, again);
                    Ok(())
                }
                Err(ResourceError::ExecutableEscape | ResourceError::EmptyExecutableIdentity) => {
                    Ok(())
                }
                Err(error) => panic!("unexpected executable error: {error}"),
            }
        })
        .expect("executable");
}

#[test]
fn equality_is_transitive_for_equivalent_paths() {
    let mut runner = runner();
    let names = proptest::collection::vec(proptest::char::range('a', 'z'), 1..=8);
    runner
        .run(&names, |chars| {
            let base: String = chars.into_iter().collect();
            let direct = FileResource::new(FilesystemAnchor::Repo, &base).expect("direct");
            let dotted =
                FileResource::new(FilesystemAnchor::Repo, format!("./{base}")).expect("dotted");
            let parented = FileResource::new(FilesystemAnchor::Repo, format!("{base}/x/.."))
                .expect("parented");
            prop_assert_eq!(&direct, &dotted);
            prop_assert_eq!(&dotted, &parented);
            prop_assert_eq!(&direct, &parented);

            let left = Capability::filesystem_read(direct);
            let middle = Capability::filesystem_read(dotted);
            let right = Capability::filesystem_read(parented);
            prop_assert_eq!(&left, &middle);
            prop_assert_eq!(&middle, &right);
            prop_assert_eq!(&left, &right);
            Ok(())
        })
        .expect("transitivity");
}

#[test]
fn containment_properties_hold_for_a_recursive_prefix() {
    let parent = FileResource::new(FilesystemAnchor::Repo, "src/**").expect("parent");
    let child = FileResource::new(FilesystemAnchor::Repo, "src/domain/lib.rs").expect("child");
    let outside = FileResource::new(FilesystemAnchor::Repo, "other/lib.rs").expect("outside");
    assert!(parent.contains(&parent));
    assert!(parent.contains(&child));
    assert!(!child.contains(&parent));
    assert!(!parent.contains(&outside));
    assert!(parent.contains(&child) && child.contains(&child) && parent.contains(&child));

    let executable = Resource::Executable(ExecutableResource::new("git").expect("git"));
    let network = Resource::Network(NetworkResource::new(
        NetworkProtocol::Tcp,
        NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        443,
    ));
    let file_resource = Resource::File(parent);
    assert!(!file_resource.contains(&executable));
    assert!(!file_resource.contains(&network));
    assert!(!executable.contains(&file_resource));
    assert!(!network.contains(&executable));
}

#[test]
fn serialization_round_trip_preserves_a_capability() {
    let capability = Capability::network_connect(NetworkResource::new(
        NetworkProtocol::Udp,
        NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8).expect("cidr"),
        53,
    ));
    let encoded = serde_json::to_string(&capability).expect("encode");
    let decoded = serde_json::from_str::<Capability>(&encoded).expect("decode");
    assert_eq!(decoded, capability);
    assert_eq!(decoded.action(), Action::NetworkConnect);
}

#[test]
fn cross_resource_pairs_are_rejected() {
    let file =
        Resource::File(FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file"));
    let executable = Resource::Executable(ExecutableResource::new("git").expect("git"));
    let network = Resource::Network(NetworkResource::new(
        NetworkProtocol::Tcp,
        NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        443,
    ));
    for action in Action::ALL {
        for resource in [&file, &executable, &network] {
            let result = Capability::try_new(action, resource.clone());
            assert_eq!(
                result.is_ok(),
                action.accepts(resource),
                "{}",
                action.as_str()
            );
        }
    }
}
