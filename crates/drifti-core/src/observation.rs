// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observation vocabulary for drift adapters.
//!
//! These types mirror the observer event shape without pulling in platform
//! crates. Execution id, timestamps, and evidence are not part of capability
//! identity and are omitted from the minimal event used for run comparison.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

use crate::capability::Capability;
use crate::resource::{
    ExecutableResource, FileResource, FilesystemRoots, NetworkAddress, NetworkProtocol,
    NetworkResource, ResourceError,
};

/// Operation aligned with SPEC-001 action names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// `filesystem.read`
    FilesystemRead,
    /// `filesystem.write`
    FilesystemWrite,
    /// `filesystem.metadata`
    FilesystemMetadata,
    /// `process.execute`
    ProcessExecute,
    /// `network.connect`
    NetworkConnect,
    /// `network.listen`
    NetworkListen,
}

/// Resource identity from observation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservedResource {
    /// Filesystem path text.
    File {
        /// Path as observed. Not file contents.
        path: String,
    },
    /// Executable identity.
    Executable {
        /// Executable name or path.
        identity: String,
    },
    /// Network endpoint.
    Network {
        /// Host or address text.
        host: String,
        /// Port.
        port: u16,
    },
}

impl ObservedResource {
    /// File resource. Empty text and embedded NUL are rejected.
    pub fn file(path: impl Into<String>) -> Result<Self, ObservationError> {
        let stored = path.into();
        validate_text(&stored)?;
        Ok(Self::File { path: stored })
    }

    /// Executable resource.
    pub fn executable(identity: impl Into<String>) -> Result<Self, ObservationError> {
        let stored = identity.into();
        validate_text(&stored)?;
        Ok(Self::Executable { identity: stored })
    }

    /// Network endpoint.
    pub fn network(host: impl Into<String>, port: u16) -> Result<Self, ObservationError> {
        let stored = host.into();
        validate_text(&stored)?;
        Ok(Self::Network { host: stored, port })
    }
}

/// Whether an observed operation succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Attempted and exercised.
    Success,
    /// Attempted and not exercised.
    Failure,
}

/// Minimal observation used to derive exercised capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEvent {
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
}

impl ObservedEvent {
    /// Builds one observation. Metadata stays outside structural identity.
    #[must_use]
    pub const fn new(operation: Operation, resource: ObservedResource, outcome: Outcome) -> Self {
        Self {
            operation,
            resource,
            outcome,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    #[must_use]
    pub const fn resource(&self) -> &ObservedResource {
        &self.resource
    }

    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// Whether the operation succeeded and counts as exercised authority.
    #[must_use]
    pub const fn was_exercised(&self) -> bool {
        matches!(self.outcome, Outcome::Success)
    }
}

/// Maps one exercised observation to a capability.
#[must_use = "mapping errors must be handled"]
pub fn capability_from_observation(
    operation: Operation,
    resource: &ObservedResource,
    roots: &FilesystemRoots,
) -> Result<Capability, ObservationError> {
    match (operation, resource) {
        (Operation::FilesystemRead, ObservedResource::File { path }) => Ok(
            Capability::filesystem_read(FileResource::from_host_path(roots, path)?),
        ),
        (Operation::FilesystemWrite, ObservedResource::File { path }) => Ok(
            Capability::filesystem_write(FileResource::from_host_path(roots, path)?),
        ),
        (Operation::FilesystemMetadata, ObservedResource::File { path }) => Ok(
            Capability::filesystem_metadata(FileResource::from_host_path(roots, path)?),
        ),
        (Operation::ProcessExecute, ObservedResource::Executable { identity }) => Ok(
            Capability::process_execute(ExecutableResource::new(identity.clone())?),
        ),
        (Operation::NetworkConnect, ObservedResource::Network { host, port }) => {
            let address = parse_observed_address(host)?;
            Ok(Capability::network_connect(NetworkResource::new(
                NetworkProtocol::Tcp,
                address,
                *port,
            )))
        }
        (Operation::NetworkListen, ObservedResource::Network { host, port }) => {
            let address = parse_observed_address(host)?;
            Ok(Capability::network_listen(NetworkResource::new(
                NetworkProtocol::Tcp,
                address,
                *port,
            )))
        }
        _ => Err(ObservationError::MismatchedOperationResource),
    }
}

fn parse_observed_address(host: &str) -> Result<NetworkAddress, ObservationError> {
    let address: IpAddr = host
        .parse()
        .map_err(|_| ObservationError::UnmappedNetworkHost)?;
    Ok(NetworkAddress::ip(address))
}

fn validate_text(text: &str) -> Result<(), ObservationError> {
    if text.is_empty() {
        return Err(ObservationError::EmptyText);
    }
    if text.contains('\0') {
        return Err(ObservationError::EmbeddedNul);
    }
    Ok(())
}

/// Observation could not become a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationError {
    /// Empty path or identity text.
    EmptyText,
    /// Embedded NUL in text.
    EmbeddedNul,
    /// Operation and resource family do not match.
    MismatchedOperationResource,
    /// Network host is not a literal IP address.
    UnmappedNetworkHost,
    /// Resource normalization failed.
    Resource(ResourceError),
}

impl From<ResourceError> for ObservationError {
    fn from(error: ResourceError) -> Self {
        Self::Resource(error)
    }
}

impl Display for ObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyText => formatter.write_str("observation text is empty"),
            Self::EmbeddedNul => formatter.write_str("observation text contains a NUL byte"),
            Self::MismatchedOperationResource => {
                formatter.write_str("operation and resource family do not match")
            }
            Self::UnmappedNetworkHost => {
                formatter.write_str("network host is not a literal IP address")
            }
            Self::Resource(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ObservationError {}
