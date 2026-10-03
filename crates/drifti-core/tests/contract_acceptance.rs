// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A generated contract stays a proposal until it is explicitly accepted.

use drifti_core::contract::{
    parse_contract, serialize_contract, AcceptedContract, AllowDenyRules, AuthoringResource,
    ContractCompileError, ContractDocument, ContractProposal, ContractVersion,
    ContractWriteRequest, FilesystemContract, NetworkContract, ProcessContract,
};
use drifti_core::policy::CompiledPolicy;

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

fn authority_policy(contract: &AcceptedContract) -> CompiledPolicy {
    contract.compile().expect("accepted contract compiles")
}

#[test]
fn generated_proposal_is_not_a_loaded_contract() {
    let source = spec_document();
    let proposal = ContractProposal::generated(source.clone());
    let loaded = AcceptedContract::loaded(source.clone());

    assert_eq!(proposal.document(), &source);
    assert_eq!(loaded.document(), &source);
    assert_eq!(proposal.document(), loaded.document());
    let _ = authority_policy(&loaded);
}

#[test]
fn preparing_a_write_does_not_accept_the_proposal() {
    let source = spec_document();
    let proposal = ContractProposal::generated(source.clone());
    let request: ContractWriteRequest = proposal.write_request();

    assert_eq!(request.yaml(), proposal.yaml());
    assert_eq!(request.yaml(), serialize_contract(&source));
    assert!(request.yaml().starts_with("version: 1\n"));
    assert!(!request.yaml().contains("proposal"));
    assert!(!request.yaml().contains("accepted"));
    assert_eq!(proposal.document(), &source);

    let parsed = parse_contract(request.yaml()).expect("write payload parses");
    assert_eq!(parsed, source);
    let reread = ContractProposal::generated(parsed);
    assert_eq!(reread.document(), proposal.document());
}

#[test]
fn explicit_accept_keeps_the_document_and_can_compile() {
    let source = spec_document();
    let proposal = ContractProposal::generated(source.clone());
    let accepted = proposal.accept();

    assert_eq!(accepted.document(), &source);
    assert_eq!(
        accepted.document().filesystem().read().deny()[0].as_str(),
        "~/.ssh/**"
    );
    assert_eq!(
        authority_policy(&accepted),
        authority_policy(&AcceptedContract::loaded(source))
    );
}

#[test]
fn confirming_a_write_accepts_that_document_only() {
    let source = spec_document();
    let proposal = ContractProposal::generated(source.clone());
    let request = proposal.write_request();
    let accepted = request.accept_written();

    assert_eq!(accepted.document(), &source);
    assert_eq!(proposal.document(), &source);
    assert_eq!(
        authority_policy(&accepted).rules().len(),
        authority_policy(&AcceptedContract::loaded(source))
            .rules()
            .len()
    );
}

#[test]
fn accepting_a_proposal_does_not_skip_invalid_resources() {
    let source = document(
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        rules(&["./src/**"], &[]),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
    );
    let accepted = ContractProposal::generated(source).accept();
    let error = accepted.compile().expect_err("invalid executable");

    assert!(matches!(
        error,
        ContractCompileError::InvalidResource { .. }
    ));
}

#[test]
fn an_empty_loaded_contract_compiles_to_no_rules() {
    let source = document(
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
        AllowDenyRules::empty(),
    );
    let loaded = AcceptedContract::loaded(source);
    assert!(authority_policy(&loaded).rules().is_empty());
}

#[test]
fn accept_preserves_authoring_resources() {
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
        prop_oneof![Just('a'), Just('z'), Just('.'), Just('/')],
        1..=8,
    )
    .prop_map(|chars| chars.into_iter().collect::<String>());
    let list = proptest::collection::vec(text, 0..=3);
    runner
        .run(
            &(list.clone(), list),
            |(allow, deny): (Vec<String>, Vec<String>)| {
                let source = document(
                    rules_owned(&allow, &deny),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                );
                let accepted = ContractProposal::generated(source.clone()).accept();
                prop_assert_eq!(accepted.document(), &source);
                let written = ContractProposal::generated(source.clone()).write_request();
                prop_assert_eq!(written.yaml(), serialize_contract(&source));
                let accepted = written.accept_written();
                prop_assert_eq!(accepted.document(), &source);
                Ok(())
            },
        )
        .expect("acceptance preserves resources");
}

fn rules_owned(allow: &[String], deny: &[String]) -> AllowDenyRules {
    AllowDenyRules::new(
        allow
            .iter()
            .map(|text| AuthoringResource::new(text.clone()).expect("allow"))
            .collect(),
        deny.iter()
            .map(|text| AuthoringResource::new(text.clone()).expect("deny"))
            .collect(),
    )
}

#[test]
fn acceptance_source_does_not_write_files_or_render_a_terminal() {
    let source = include_str!("../src/contract/acceptance.rs");
    for token in [
        "std::fs",
        "File::create",
        "OpenOptions",
        "println!",
        "eprintln!",
        "stdout",
        "stderr",
        "clap",
        "dialoguer",
    ] {
        assert!(
            !source.contains(token),
            "acceptance source contains {token}"
        );
    }
}
