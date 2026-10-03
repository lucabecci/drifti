// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability values.
//!
//! A capability pairs one MVP action with one resource of the matching family.
//! Public constructors reject every other pairing.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::foundation::{Deserialize, Serialize};
use crate::resource::{ExecutableResource, FileResource, NetworkResource, Resource, ResourceKind};

/// MVP capability action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    /// `filesystem.read`
    #[serde(rename = "filesystem.read")]
    FilesystemRead,
    /// `filesystem.write`
    #[serde(rename = "filesystem.write")]
    FilesystemWrite,
    /// `filesystem.metadata`
    #[serde(rename = "filesystem.metadata")]
    FilesystemMetadata,
    /// `process.execute`
    #[serde(rename = "process.execute")]
    ProcessExecute,
    /// `network.connect`
    #[serde(rename = "network.connect")]
    NetworkConnect,
    /// `network.listen`
    #[serde(rename = "network.listen")]
    NetworkListen,
}

impl Action {
    /// Every MVP action.
    pub const ALL: [Self; 6] = [
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::FilesystemMetadata,
        Self::ProcessExecute,
        Self::NetworkConnect,
        Self::NetworkListen,
    ];

    /// Stable action name from SPEC-001.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::FilesystemMetadata => "filesystem.metadata",
            Self::ProcessExecute => "process.execute",
            Self::NetworkConnect => "network.connect",
            Self::NetworkListen => "network.listen",
        }
    }

    /// Whether this action can name that resource.
    #[must_use]
    pub fn accepts(self, resource: &Resource) -> bool {
        matches!(
            (self, resource),
            (
                Self::FilesystemRead | Self::FilesystemWrite | Self::FilesystemMetadata,
                Resource::File(_),
            ) | (Self::ProcessExecute, Resource::Executable(_))
                | (
                    Self::NetworkConnect | Self::NetworkListen,
                    Resource::Network(_),
                )
        )
    }
}

/// One action paired with one compatible resource.
///
/// Deserialization is a public constructor and uses [`Capability::try_new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    action: Action,
    resource: Resource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFields {
    action: Action,
    resource: Resource,
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = CapabilityFields::deserialize(deserializer)?;
        Self::try_new(fields.action, fields.resource).map_err(serde::de::Error::custom)
    }
}

impl Capability {
    /// Pairs an action with a resource when the families match.
    pub fn try_new(action: Action, resource: Resource) -> Result<Self, CapabilityMismatch> {
        if action.accepts(&resource) {
            Ok(Self { action, resource })
        } else {
            Err(CapabilityMismatch {
                action,
                resource: resource.kind(),
            })
        }
    }

    /// `filesystem.read` of a file.
    #[must_use]
    pub fn filesystem_read(resource: FileResource) -> Self {
        Self {
            action: Action::FilesystemRead,
            resource: Resource::File(resource),
        }
    }

    /// `filesystem.write` of a file.
    #[must_use]
    pub fn filesystem_write(resource: FileResource) -> Self {
        Self {
            action: Action::FilesystemWrite,
            resource: Resource::File(resource),
        }
    }

    /// `filesystem.metadata` of a file.
    #[must_use]
    pub fn filesystem_metadata(resource: FileResource) -> Self {
        Self {
            action: Action::FilesystemMetadata,
            resource: Resource::File(resource),
        }
    }

    /// `process.execute` of an executable.
    #[must_use]
    pub fn process_execute(resource: ExecutableResource) -> Self {
        Self {
            action: Action::ProcessExecute,
            resource: Resource::Executable(resource),
        }
    }

    /// `network.connect` to an endpoint.
    #[must_use]
    pub fn network_connect(resource: NetworkResource) -> Self {
        Self {
            action: Action::NetworkConnect,
            resource: Resource::Network(resource),
        }
    }

    /// `network.listen` on an endpoint.
    #[must_use]
    pub fn network_listen(resource: NetworkResource) -> Self {
        Self {
            action: Action::NetworkListen,
            resource: Resource::Network(resource),
        }
    }

    /// Action half of the capability.
    #[must_use]
    pub fn action(&self) -> Action {
        self.action
    }

    /// Resource half of the capability.
    #[must_use]
    pub fn resource(&self) -> &Resource {
        &self.resource
    }
}

/// Action and resource families that cannot form a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityMismatch {
    /// Action that was requested.
    pub action: Action,
    /// Resource family that was supplied.
    pub resource: ResourceKind,
}

impl Display for CapabilityMismatch {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} cannot name a {} resource",
            self.action.as_str(),
            self.resource.as_str()
        )
    }
}

impl Error for CapabilityMismatch {}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use proptest::prelude::*;
    use proptest::test_runner::{TestRng, TestRunner};

    use super::{Action, Capability, CapabilityMismatch};
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource, Resource, ResourceKind,
    };

    fn file() -> FileResource {
        FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file")
    }

    fn executable() -> ExecutableResource {
        ExecutableResource::new("git").expect("executable")
    }

    fn network() -> NetworkResource {
        NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
        )
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
                let file_path: String = chars.into_iter().collect();
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

    fn arb_resource() -> impl Strategy<Value = Resource> {
        prop_oneof![
            arb_file().prop_map(Resource::File),
            arb_executable().prop_map(Resource::Executable),
            arb_network().prop_map(Resource::Network),
        ]
    }

    fn arb_action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::FilesystemRead),
            Just(Action::FilesystemWrite),
            Just(Action::FilesystemMetadata),
            Just(Action::ProcessExecute),
            Just(Action::NetworkConnect),
            Just(Action::NetworkListen),
        ]
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

    #[test]
    fn action_serializes_to_its_spec_name() {
        for action in Action::ALL {
            let json = serde_json::to_value(action).expect("action json");
            assert_eq!(json.as_str(), Some(action.as_str()));
        }
    }

    #[test]
    fn every_mvp_action_has_a_distinct_name() {
        let mut names = Action::ALL.map(Action::as_str);
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "filesystem.metadata",
                "filesystem.read",
                "filesystem.write",
                "network.connect",
                "network.listen",
                "process.execute",
            ]
        );
    }

    #[test]
    fn typed_constructors_represent_every_action() {
        let cases = [
            Capability::filesystem_read(file()),
            Capability::filesystem_write(file()),
            Capability::filesystem_metadata(file()),
            Capability::process_execute(executable()),
            Capability::network_connect(network()),
            Capability::network_listen(network()),
        ];
        let actions: Vec<_> = cases.iter().map(Capability::action).collect();
        assert_eq!(actions, Action::ALL);
    }

    #[test]
    fn typed_constructor_matches_try_new() {
        let resource = file();
        let typed = Capability::filesystem_read(resource.clone());
        let generic =
            Capability::try_new(Action::FilesystemRead, Resource::File(resource)).expect("pair");
        assert_eq!(typed, generic);
    }

    #[test]
    fn mismatched_pairs_cannot_be_constructed() {
        let samples = [
            (Resource::File(file()), ResourceKind::File),
            (Resource::Executable(executable()), ResourceKind::Executable),
            (Resource::Network(network()), ResourceKind::Network),
        ];
        for action in Action::ALL {
            for (resource, kind) in &samples {
                let result = Capability::try_new(action, resource.clone());
                if action.accepts(resource) {
                    assert!(result.is_ok(), "{}", action.as_str());
                } else {
                    assert_eq!(
                        result,
                        Err(CapabilityMismatch {
                            action,
                            resource: *kind,
                        })
                    );
                }
            }
        }
    }

    #[test]
    fn deserialization_rejects_a_mismatched_pair() {
        let json = r#"{"action":"filesystem.read","resource":{"network":{"protocol":"tcp","address":{"ip":"127.0.0.1"},"port":443}}}"#;
        let error = serde_json::from_str::<Capability>(json).expect_err("mismatched pair");
        assert!(error.to_string().contains("filesystem.read"));
    }

    #[test]
    fn equality_uses_action_and_resource_only() {
        let same = Capability::filesystem_read(file());
        assert_eq!(same, same.clone());
        assert_ne!(
            same,
            Capability::filesystem_write(
                FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file")
            )
        );
        assert_ne!(
            Capability::filesystem_read(file()),
            Capability::filesystem_read(
                FileResource::new(FilesystemAnchor::Repo, "src/main.rs").expect("other file")
            )
        );
    }

    #[test]
    fn try_new_follows_the_family_rule() {
        let mut runner = deterministic_runner();
        let strategy = (arb_action(), arb_resource());
        runner
            .run(&strategy, |(action, resource)| {
                let accepted = action.accepts(&resource);
                let result = Capability::try_new(action, resource);
                prop_assert_eq!(result.is_ok(), accepted);
                Ok(())
            })
            .expect("family rule");
    }

    #[test]
    fn equality_is_reflexive_and_symmetric() {
        let mut runner = deterministic_runner();
        let strategy = (arb_capability(), arb_capability());
        runner
            .run(&strategy, |(left, right)| {
                prop_assert!(left == left.clone());
                prop_assert_eq!(left == right, right == left);
                Ok(())
            })
            .expect("equality");
    }
}
