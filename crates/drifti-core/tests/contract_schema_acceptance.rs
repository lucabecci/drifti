// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-003 acceptance: round trip, golden YAML, version, and ordering.

use drifti_core::capability::Capability;
use drifti_core::contract::{
    parse_contract, serialize_contract, AcceptedContract, AllowDenyRules, AuthoringResource,
    ContractCompileError, ContractDocument, ContractParseError, ContractVersion,
    FilesystemContract, NetworkContract, ProcessContract,
};
use drifti_core::policy::{CompiledPolicy, Coverage, Decision};
use drifti_core::resource::{FileResource, FilesystemAnchor};

const SPEC_YAML: &str = "\
version: 1

filesystem:
  read:
    allow:
      - ./src/**
    deny:
      - ~/.ssh/**
  write:
    allow:
      - ./src/**

process:
  execute:
    allow:
      - /usr/bin/cargo

network:
  connect:
    allow:
      - tcp://203.0.113.0/24:443
";

fn resource(text: &str) -> AuthoringResource {
    AuthoringResource::new(text).expect("resource")
}

fn rules(allow: &[&str], deny: &[&str]) -> AllowDenyRules {
    AllowDenyRules::new(
        allow.iter().copied().map(resource).collect(),
        deny.iter().copied().map(resource).collect(),
    )
}

fn document(
    read: AllowDenyRules,
    write: AllowDenyRules,
    execute: AllowDenyRules,
    connect: AllowDenyRules,
    listen: AllowDenyRules,
) -> ContractDocument {
    ContractDocument::new(
        ContractVersion::V1,
        FilesystemContract::new(read, write),
        ProcessContract::new(execute),
        NetworkContract::new(connect, listen),
    )
}

fn spec_document() -> ContractDocument {
    document(
        rules(&["./src/**"], &["~/.ssh/**"]),
        rules(&["./src/**"], &[]),
        rules(&["/usr/bin/cargo"], &[]),
        rules(&["tcp://203.0.113.0/24:443"], &[]),
        AllowDenyRules::empty(),
    )
}

fn compile(document: ContractDocument) -> CompiledPolicy {
    AcceptedContract::loaded(document)
        .compile()
        .expect("version 1 document compiles")
}

fn decisions(policy: &CompiledPolicy, probes: &[Capability]) -> Vec<Decision> {
    probes
        .iter()
        .map(|capability| policy.evaluate(capability, Coverage::Complete).decision())
        .collect()
}

#[test]
fn golden_yaml_is_stable_for_the_spec_example() {
    let yaml = serialize_contract(&spec_document());
    assert_eq!(yaml, SPEC_YAML);
    assert_eq!(
        serialize_contract(&parse_contract(&yaml).expect("golden")),
        yaml
    );
    assert!(yaml.starts_with("version: 1\n"));
    assert!(yaml.contains("\n      - ./src/**\n"));
    assert!(yaml.contains("\n      - ~/.ssh/**\n"));
    assert!(!yaml.contains('\t'));
    assert!(!yaml.contains('&'));
    assert!(!yaml.contains('!'));
}

#[test]
fn parse_serialize_parse_retains_semantics() {
    let parsed = parse_contract(SPEC_YAML).expect("spec yaml");
    assert_eq!(parsed.version(), ContractVersion::V1);
    assert_eq!(parsed.filesystem().read().deny()[0].as_str(), "~/.ssh/**");
    assert_eq!(
        parsed.network().listen().allow(),
        &[] as &[AuthoringResource]
    );
    assert_eq!(
        parsed.network().listen().deny(),
        &[] as &[AuthoringResource]
    );

    let yaml = serialize_contract(&parsed);
    let again = parse_contract(&yaml).expect("second parse");
    assert_eq!(again, parsed);
    assert_eq!(serialize_contract(&again), yaml);
    assert_eq!(compile(again), compile(parsed));

    let with_listen = document(
        rules(&["./src/**"], &["~/.ssh/**"]),
        rules(&["./src/**"], &[]),
        rules(&["/usr/bin/cargo"], &[]),
        rules(&["tcp://203.0.113.0/24:443"], &[]),
        rules(&[], &["tcp://127.0.0.1:80"]),
    );
    let listen_yaml = serialize_contract(&with_listen);
    let listen_again = parse_contract(&listen_yaml).expect("listen round trip");
    assert_eq!(listen_again, with_listen);
    assert_eq!(
        listen_again.network().listen().deny()[0].as_str(),
        "tcp://127.0.0.1:80"
    );
    assert_eq!(serialize_contract(&listen_again), listen_yaml);
    assert_eq!(compile(listen_again).rules().len(), 6);
}

#[test]
fn unsupported_version_is_a_specific_error() {
    let yaml = "\
version: 2

filesystem:
  read:
    allow:
      - ./src/**
";
    let error = parse_contract(yaml).expect_err("version 2");
    match error {
        ContractParseError::UnsupportedVersion {
            path,
            version,
            expected,
            ..
        } => {
            assert_eq!(path, "version");
            assert_eq!(version, 2);
            assert_ne!(version, 1);
            assert_eq!(expected, "version 1");
        }
        other => panic!("expected unsupported version, got {other:?}"),
    }
    let message = parse_contract("version: 2\n")
        .expect_err("version 2")
        .to_string();
    assert!(message.contains("unsupported"));
    assert!(message.contains("version 2"));
    assert!(message.contains("expected version 1"));
}

#[test]
fn invalid_action_resource_combinations_fail() {
    let file_as_network = document(
        rules(&["tcp://203.0.113.0:443"], &[]),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
    );
    match AcceptedContract::loaded(file_as_network)
        .compile()
        .expect_err("network resource is not a file")
    {
        ContractCompileError::InvalidResource {
            field_path,
            value,
            expected,
        } => {
            assert_eq!(field_path, "filesystem.read.allow[0]");
            assert_eq!(value, "tcp://203.0.113.0:443");
            assert!(expected.contains("repo path") || expected.contains("path"));
        }
        other => panic!("expected an invalid resource, got {other:?}"),
    }

    let path_as_executable = document(
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        rules(&["./src/**"], &[]),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
    );
    match AcceptedContract::loaded(path_as_executable)
        .compile()
        .expect_err("path is not an executable")
    {
        ContractCompileError::InvalidResource {
            field_path, value, ..
        } => {
            assert_eq!(field_path, "process.execute.allow[0]");
            assert_eq!(value, "./src/**");
        }
        other => panic!("expected an invalid resource, got {other:?}"),
    }
}

#[test]
fn identical_inputs_serialize_in_one_order() {
    let forward = document(
        rules(&["./b", "./a"], &["./d", "./c"]),
        rules(&["./z", "./m"], &[]),
        rules(&["/usr/bin/cargo", "/bin/sh"], &[]),
        rules(&["tcp://203.0.113.9:443", "tcp://203.0.113.1:443"], &[]),
        rules(&[], &["udp://127.0.0.1:53", "tcp://127.0.0.1:80"]),
    );
    let reversed = document(
        rules(&["./a", "./b"], &["./c", "./d"]),
        rules(&["./m", "./z"], &[]),
        rules(&["/bin/sh", "/usr/bin/cargo"], &[]),
        rules(&["tcp://203.0.113.1:443", "tcp://203.0.113.9:443"], &[]),
        rules(&[], &["tcp://127.0.0.1:80", "udp://127.0.0.1:53"]),
    );

    let yaml = serialize_contract(&forward);
    assert_eq!(yaml, serialize_contract(&reversed));
    assert!(yaml.find("./a").unwrap() < yaml.find("./b").unwrap());
    assert!(yaml.find("./c").unwrap() < yaml.find("./d").unwrap());
    assert!(yaml.find("/bin/sh").unwrap() < yaml.find("/usr/bin/cargo").unwrap());

    let canonical = parse_contract(&yaml).expect("canonical yaml");
    assert_eq!(serialize_contract(&canonical), yaml);
    let canonical_policy = compile(canonical);
    let forward_policy = compile(forward);
    let reversed_policy = compile(reversed);
    let probes: Vec<Capability> = canonical_policy
        .rules()
        .iter()
        .map(|rule| rule.capability().clone())
        .collect();
    let outside = Capability::filesystem_read(
        FileResource::new(FilesystemAnchor::Repo, "other").expect("outside path"),
    );
    let mut forward_decisions = decisions(&forward_policy, &probes);
    let mut reversed_decisions = decisions(&reversed_policy, &probes);
    forward_decisions.push(
        forward_policy
            .evaluate(&outside, Coverage::Complete)
            .decision(),
    );
    reversed_decisions.push(
        reversed_policy
            .evaluate(&outside, Coverage::Complete)
            .decision(),
    );
    assert_eq!(forward_decisions, reversed_decisions);
    assert_eq!(
        *forward_decisions.last().expect("outside"),
        Decision::Unknown
    );
}

#[test]
fn resource_order_does_not_change_serialized_output() {
    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    let config = ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
    let text = proptest::collection::vec(
        prop_oneof![Just('a'), Just('m'), Just('z'), Just('.'), Just('/')],
        1..=8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>());
    let list = proptest::collection::vec(text, 0..=4);
    runner
        .run(&list, |texts| {
            let forward: Vec<&str> = texts.iter().map(String::as_str).collect();
            let mut reversed = forward.clone();
            reversed.reverse();
            let left = document(
                rules(&forward, &reversed),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
            );
            let right = document(
                rules(&reversed, &forward),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
                AllowDenyRules::empty(),
            );
            let yaml = serialize_contract(&left);
            prop_assert_eq!(&yaml, &serialize_contract(&right));
            let parsed = parse_contract(&yaml).expect("ordered yaml");
            prop_assert_eq!(&serialize_contract(&parsed), &yaml);
            Ok(())
        })
        .expect("one serialized order");
}
