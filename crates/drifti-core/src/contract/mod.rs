// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Version-1 Capability Contract document.
//!
//! This is the public shape of `drifti.yaml`. Keys are lowercase and follow
//! the Design System: `version`, then `filesystem`, `process`, and `network`.
//! Each action has `allow` and `deny` lists of authoring resources. Version 1
//! is mandatory. [`parse_contract`] reads one document into this model and
//! rejects every other version. It does not sort resources, resolve patterns
//! into typed resources, or build a policy. [`compile_contract`] does that
//! resolution and returns a typed policy value without accepting authority.
//! [`serialize_contract`] writes the same document as stable YAML. It sorts
//! resource lines for output and does not accept the document as authority.

mod compile;
mod parse;
mod serialize;

pub use compile::{compile_contract, ContractCompileError};
pub use parse::{parse_contract, ContractParseError, SourceLocation};
pub use serialize::serialize_contract;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroU32;

/// Document key for the schema version.
pub const VERSION_KEY: &str = "version";
/// Document key for filesystem rules.
pub const FILESYSTEM_KEY: &str = "filesystem";
/// Document key for process rules.
pub const PROCESS_KEY: &str = "process";
/// Document key for network rules.
pub const NETWORK_KEY: &str = "network";
/// Filesystem action key for read rules.
pub const READ_KEY: &str = "read";
/// Filesystem action key for write rules.
pub const WRITE_KEY: &str = "write";
/// Process action key for execute rules.
pub const EXECUTE_KEY: &str = "execute";
/// Network action key for connect rules.
pub const CONNECT_KEY: &str = "connect";
/// Network action key for listen rules.
pub const LISTEN_KEY: &str = "listen";
/// Effect key for granted resources.
pub const ALLOW_KEY: &str = "allow";
/// Effect key for refused resources.
pub const DENY_KEY: &str = "deny";

/// Top-level section order for a version-1 document.
pub const SECTION_ORDER: [&str; 4] = [VERSION_KEY, FILESYSTEM_KEY, PROCESS_KEY, NETWORK_KEY];
/// Effect order inside one action.
pub const EFFECT_ORDER: [&str; 2] = [ALLOW_KEY, DENY_KEY];

/// Schema version stored in a contract document.
///
/// Only version 1 can be constructed. A missing version is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContractVersion {
    value: NonZeroU32,
}

impl ContractVersion {
    /// `version: 1`
    pub const V1: Self = Self {
        value: NonZeroU32::new(1).unwrap(),
    };

    /// Numeric schema version.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.value.get()
    }
}

/// One authoring resource, still unresolved.
///
/// The text is the contract pattern, such as `./src/**` or
/// `tcp://203.0.113.0/24:443`. It is not a compiled resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthoringResource(String);

impl AuthoringResource {
    /// Stores authoring text. Empty text and an embedded NUL are rejected.
    pub fn new(text: impl Into<String>) -> Result<Self, ContractDocumentError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ContractDocumentError::EmptyResource);
        }
        if text.contains('\0') {
            return Err(ContractDocumentError::EmbeddedNul);
        }
        Ok(Self(text))
    }

    /// Authoring text, in the order the caller supplied.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `allow` and `deny` lists for one action.
///
/// List order is the order supplied here. Sorting belongs to serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowDenyRules {
    allow: Vec<AuthoringResource>,
    deny: Vec<AuthoringResource>,
}

impl AllowDenyRules {
    /// Builds both effect lists. Either list may be empty.
    #[must_use]
    pub fn new(allow: Vec<AuthoringResource>, deny: Vec<AuthoringResource>) -> Self {
        Self { allow, deny }
    }

    /// Empty allow and deny lists.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new())
    }

    /// Resources granted by this action.
    #[must_use]
    pub fn allow(&self) -> &[AuthoringResource] {
        &self.allow
    }

    /// Resources refused by this action.
    #[must_use]
    pub fn deny(&self) -> &[AuthoringResource] {
        &self.deny
    }
}

/// Filesystem `read` and `write` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemContract {
    read: AllowDenyRules,
    write: AllowDenyRules,
}

impl FilesystemContract {
    /// Filesystem section. Both actions are present even when their lists are empty.
    #[must_use]
    pub fn new(read: AllowDenyRules, write: AllowDenyRules) -> Self {
        Self { read, write }
    }

    /// Read rules.
    #[must_use]
    pub fn read(&self) -> &AllowDenyRules {
        &self.read
    }

    /// Write rules.
    #[must_use]
    pub fn write(&self) -> &AllowDenyRules {
        &self.write
    }
}

/// Process `execute` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessContract {
    execute: AllowDenyRules,
}

impl ProcessContract {
    /// Process section.
    #[must_use]
    pub fn new(execute: AllowDenyRules) -> Self {
        Self { execute }
    }

    /// Execute rules.
    #[must_use]
    pub fn execute(&self) -> &AllowDenyRules {
        &self.execute
    }
}

/// Network `connect` and `listen` rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkContract {
    connect: AllowDenyRules,
    listen: AllowDenyRules,
}

impl NetworkContract {
    /// Network section. Connect and listen are both supported actions.
    #[must_use]
    pub fn new(connect: AllowDenyRules, listen: AllowDenyRules) -> Self {
        Self { connect, listen }
    }

    /// Connect rules.
    #[must_use]
    pub fn connect(&self) -> &AllowDenyRules {
        &self.connect
    }

    /// Listen rules.
    #[must_use]
    pub fn listen(&self) -> &AllowDenyRules {
        &self.listen
    }
}

/// Public version-1 contract document.
///
/// The version argument is required. This value is not an accepted contract
/// by itself: acceptance is a later boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDocument {
    version: ContractVersion,
    filesystem: FilesystemContract,
    process: ProcessContract,
    network: NetworkContract,
}

impl ContractDocument {
    /// Builds a document. `version` cannot be omitted.
    #[must_use]
    pub fn new(
        version: ContractVersion,
        filesystem: FilesystemContract,
        process: ProcessContract,
        network: NetworkContract,
    ) -> Self {
        Self {
            version,
            filesystem,
            process,
            network,
        }
    }

    /// Mandatory schema version.
    #[must_use]
    pub fn version(&self) -> ContractVersion {
        self.version
    }

    /// Filesystem section.
    #[must_use]
    pub fn filesystem(&self) -> &FilesystemContract {
        &self.filesystem
    }

    /// Process section.
    #[must_use]
    pub fn process(&self) -> &ProcessContract {
        &self.process
    }

    /// Network section.
    #[must_use]
    pub fn network(&self) -> &NetworkContract {
        &self.network
    }
}

/// Rejected contract-document value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractDocumentError {
    /// Authoring resource text was empty.
    EmptyResource,
    /// Authoring resource text contained a NUL byte.
    EmbeddedNul,
}

impl Display for ContractDocumentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyResource => formatter.write_str("authoring resource text is empty"),
            Self::EmbeddedNul => formatter.write_str("authoring resource text contains a NUL byte"),
        }
    }
}

impl Error for ContractDocumentError {}

#[cfg(test)]
mod tests {
    use super::{
        AllowDenyRules, AuthoringResource, ContractDocument, ContractDocumentError,
        ContractVersion, FilesystemContract, NetworkContract, ProcessContract, ALLOW_KEY,
        CONNECT_KEY, DENY_KEY, EFFECT_ORDER, EXECUTE_KEY, FILESYSTEM_KEY, LISTEN_KEY, NETWORK_KEY,
        PROCESS_KEY, READ_KEY, SECTION_ORDER, VERSION_KEY, WRITE_KEY,
    };

    fn resource(text: &str) -> AuthoringResource {
        AuthoringResource::new(text).expect("resource")
    }

    fn rules(allow: &[&str], deny: &[&str]) -> AllowDenyRules {
        AllowDenyRules::new(
            allow.iter().copied().map(resource).collect(),
            deny.iter().copied().map(resource).collect(),
        )
    }

    fn spec_example() -> ContractDocument {
        let filesystem = FilesystemContract::new(
            rules(&["./src/**"], &["~/.ssh/**"]),
            rules(&["./src/**"], &[]),
        );
        let process = ProcessContract::new(rules(&["/usr/bin/cargo"], &[]));
        let network = NetworkContract::new(
            rules(&["tcp://203.0.113.0/24:443"], &[]),
            AllowDenyRules::empty(),
        );
        ContractDocument::new(ContractVersion::V1, filesystem, process, network)
    }

    #[test]
    fn version_is_mandatory_and_is_one() {
        let document = spec_example();
        assert_eq!(document.version(), ContractVersion::V1);
        assert_eq!(document.version().get(), 1);
        assert_eq!(VERSION_KEY, "version");
    }

    #[test]
    fn keys_follow_the_design_system() {
        assert_eq!(
            SECTION_ORDER,
            ["version", "filesystem", "process", "network"]
        );
        assert_eq!(EFFECT_ORDER, ["allow", "deny"]);
        assert_eq!(FILESYSTEM_KEY, "filesystem");
        assert_eq!(PROCESS_KEY, "process");
        assert_eq!(NETWORK_KEY, "network");
        assert_eq!(READ_KEY, "read");
        assert_eq!(WRITE_KEY, "write");
        assert_eq!(EXECUTE_KEY, "execute");
        assert_eq!(CONNECT_KEY, "connect");
        assert_eq!(LISTEN_KEY, "listen");
        assert_eq!(ALLOW_KEY, "allow");
        assert_eq!(DENY_KEY, "deny");
        assert_ne!(ALLOW_KEY, DENY_KEY);
    }

    #[test]
    fn spec_example_covers_every_version_1_action() {
        let document = spec_example();
        let texts = |rules: &AllowDenyRules| {
            (
                rules
                    .allow()
                    .iter()
                    .map(|item| item.as_str().to_owned())
                    .collect::<Vec<_>>(),
                rules
                    .deny()
                    .iter()
                    .map(|item| item.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            texts(document.filesystem().read()),
            (vec!["./src/**".to_owned()], vec!["~/.ssh/**".to_owned()])
        );
        assert_eq!(
            texts(document.filesystem().write()),
            (vec!["./src/**".to_owned()], Vec::<String>::new())
        );
        assert_eq!(
            texts(document.process().execute()),
            (vec!["/usr/bin/cargo".to_owned()], Vec::<String>::new())
        );
        assert_eq!(
            texts(document.network().connect()),
            (
                vec!["tcp://203.0.113.0/24:443".to_owned()],
                Vec::<String>::new()
            )
        );
        assert_eq!(
            texts(document.network().listen()),
            (Vec::<String>::new(), Vec::<String>::new())
        );
    }

    #[test]
    fn allow_and_deny_keep_author_order_and_stay_distinct() {
        let listed = rules(&["./b", "./a"], &["./d", "./c"]);
        let allow: Vec<_> = listed
            .allow()
            .iter()
            .map(AuthoringResource::as_str)
            .collect();
        let deny: Vec<_> = listed
            .deny()
            .iter()
            .map(AuthoringResource::as_str)
            .collect();
        assert_eq!(allow, ["./b", "./a"]);
        assert_eq!(deny, ["./d", "./c"]);
        assert_ne!(listed.allow(), listed.deny());

        let document = ContractDocument::new(
            ContractVersion::V1,
            FilesystemContract::new(listed.clone(), AllowDenyRules::empty()),
            ProcessContract::new(AllowDenyRules::new(
                Vec::new(),
                vec![resource("/usr/bin/curl")],
            )),
            NetworkContract::new(
                AllowDenyRules::empty(),
                AllowDenyRules::new(vec![resource("tcp://127.0.0.1:80")], Vec::new()),
            ),
        );
        assert_eq!(document.filesystem().read(), &listed);
        assert!(document.filesystem().write().allow().is_empty());
        assert_eq!(
            document.process().execute().deny()[0].as_str(),
            "/usr/bin/curl"
        );
        assert_eq!(
            document.network().listen().allow()[0].as_str(),
            "tcp://127.0.0.1:80"
        );
        assert!(document.network().connect().deny().is_empty());
    }

    #[test]
    fn authoring_resources_reject_empty_text_and_nul() {
        assert_eq!(
            AuthoringResource::new(""),
            Err(ContractDocumentError::EmptyResource)
        );
        assert_eq!(
            AuthoringResource::new("a\0b"),
            Err(ContractDocumentError::EmbeddedNul)
        );
        assert_eq!(resource("./src/**").as_str(), "./src/**");
    }

    #[test]
    fn authoring_resources_keep_non_empty_text_without_nul() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let text = proptest::collection::vec(
            proptest::char::any().prop_filter("nul", |character| *character != '\0'),
            1..=12,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>());
        runner
            .run(&text, |text| {
                let parsed = AuthoringResource::new(text.clone()).expect("resource");
                prop_assert_eq!(parsed.as_str(), text.as_str());
                let mut with_nul = text.clone();
                with_nul.push('\0');
                prop_assert_eq!(
                    AuthoringResource::new(with_nul),
                    Err(ContractDocumentError::EmbeddedNul)
                );
                Ok(())
            })
            .expect("authoring resource");
    }
}
