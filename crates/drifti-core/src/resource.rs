// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed resources named by a capability.
//!
//! A file resource records an anchor and the file path text as supplied.
//! Anchor normalization is a later task. An executable resource records its
//! identity text as supplied. A network resource records a transport, an IP
//! address or CIDR, and a port.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

use crate::foundation::{Deserialize, Serialize};

/// Filesystem root that keeps a file resource portable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAnchor {
    /// `repo://`
    Repo,
    /// `home://`
    Home,
    /// `temp://`
    Temp,
    /// `abs://`
    #[serde(rename = "abs")]
    Absolute,
}

/// File named relative to a [`FilesystemAnchor`].
///
/// Deserialization is a public constructor and uses [`FileResource::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileResource {
    anchor: FilesystemAnchor,
    file_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileResourceFields {
    anchor: FilesystemAnchor,
    file_path: String,
}

impl<'de> Deserialize<'de> for FileResource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = FileResourceFields::deserialize(deserializer)?;
        Self::new(fields.anchor, fields.file_path).map_err(serde::de::Error::custom)
    }
}

impl FileResource {
    /// Builds a file resource from an anchor and the supplied file path text.
    ///
    /// The text is not normalized. An empty value or an embedded NUL is rejected.
    pub fn new(
        anchor: FilesystemAnchor,
        file_path: impl Into<String>,
    ) -> Result<Self, ResourceError> {
        let file_path = file_path.into();
        validate_text(&file_path, ResourceError::EmptyFilePath)?;
        Ok(Self { anchor, file_path })
    }

    /// Anchor that owns this file.
    #[must_use]
    pub fn anchor(&self) -> FilesystemAnchor {
        self.anchor
    }

    /// File path text as supplied to [`Self::new`].
    #[must_use]
    pub fn file_path(&self) -> &str {
        &self.file_path
    }
}

/// Executable named by its identity text.
///
/// Deserialization is a public constructor and uses [`ExecutableResource::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableResource {
    identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutableResourceFields {
    identity: String,
}

impl<'de> Deserialize<'de> for ExecutableResource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = ExecutableResourceFields::deserialize(deserializer)?;
        Self::new(fields.identity).map_err(serde::de::Error::custom)
    }
}

impl ExecutableResource {
    /// Builds an executable resource from the supplied identity text.
    ///
    /// The text is not canonicalized. An empty value or an embedded NUL is rejected.
    pub fn new(identity: impl Into<String>) -> Result<Self, ResourceError> {
        let identity = identity.into();
        validate_text(&identity, ResourceError::EmptyExecutableIdentity)?;
        Ok(Self { identity })
    }

    /// Identity text as supplied to [`Self::new`].
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Transport used by a network capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// CIDR prefix whose length fits the address family.
///
/// Deserialization is a public constructor and uses [`Cidr::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cidr {
    address: IpAddr,
    prefix_length: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CidrFields {
    address: IpAddr,
    prefix_length: u8,
}

impl Cidr {
    /// CIDR prefix. The prefix length must fit the address family.
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, ResourceError> {
        let maximum = prefix_maximum(address);
        if prefix_length > maximum {
            return Err(ResourceError::PrefixOutOfRange {
                prefix_length,
                maximum,
            });
        }
        Ok(Self {
            address,
            prefix_length,
        })
    }

    /// Network address.
    #[must_use]
    pub fn address(self) -> IpAddr {
        self.address
    }

    /// Prefix length in bits.
    #[must_use]
    pub fn prefix_length(self) -> u8 {
        self.prefix_length
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let fields = CidrFields::deserialize(deserializer)?;
        Self::new(fields.address, fields.prefix_length).map_err(serde::de::Error::custom)
    }
}

/// IP address or CIDR named by a network capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAddress {
    /// One host address.
    Ip(IpAddr),
    /// Address prefix.
    Cidr(Cidr),
}

impl NetworkAddress {
    /// One host address.
    #[must_use]
    pub fn ip(address: IpAddr) -> Self {
        Self::Ip(address)
    }

    /// CIDR prefix. The prefix length must fit the address family.
    pub fn cidr(address: IpAddr, prefix_length: u8) -> Result<Self, ResourceError> {
        Ok(Self::Cidr(Cidr::new(address, prefix_length)?))
    }
}

/// Network endpoint: transport, address, and port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkResource {
    protocol: NetworkProtocol,
    address: NetworkAddress,
    port: u16,
}

impl NetworkResource {
    /// Builds a network resource from already typed fields.
    #[must_use]
    pub fn new(protocol: NetworkProtocol, address: NetworkAddress, port: u16) -> Self {
        Self {
            protocol,
            address,
            port,
        }
    }

    /// Transport.
    #[must_use]
    pub fn protocol(&self) -> NetworkProtocol {
        self.protocol
    }

    /// Address or CIDR.
    #[must_use]
    pub fn address(&self) -> NetworkAddress {
        self.address
    }

    /// Port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Resource named by a capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// File resource.
    File(FileResource),
    /// Executable resource.
    Executable(ExecutableResource),
    /// Network resource.
    Network(NetworkResource),
}

impl Resource {
    /// Coarse kind used when a pairing is rejected.
    #[must_use]
    pub fn kind(&self) -> ResourceKind {
        match self {
            Self::File(_) => ResourceKind::File,
            Self::Executable(_) => ResourceKind::Executable,
            Self::Network(_) => ResourceKind::Network,
        }
    }
}

/// Which resource family a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// [`FileResource`].
    File,
    /// [`ExecutableResource`].
    Executable,
    /// [`NetworkResource`].
    Network,
}

impl ResourceKind {
    /// Stable kind name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Executable => "executable",
            Self::Network => "network",
        }
    }
}

/// Rejected resource text or CIDR prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// File path text was empty.
    EmptyFilePath,
    /// Executable identity text was empty.
    EmptyExecutableIdentity,
    /// Text contained a NUL byte.
    EmbeddedNul,
    /// CIDR prefix does not fit the address family.
    PrefixOutOfRange {
        /// Rejected prefix length.
        prefix_length: u8,
        /// Largest prefix length for that address.
        maximum: u8,
    },
}

impl Display for ResourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFilePath => formatter.write_str("file path text is empty"),
            Self::EmptyExecutableIdentity => {
                formatter.write_str("executable identity text is empty")
            }
            Self::EmbeddedNul => formatter.write_str("resource text contains a NUL byte"),
            Self::PrefixOutOfRange {
                prefix_length,
                maximum,
            } => write!(
                formatter,
                "CIDR prefix length {prefix_length} exceeds {maximum}"
            ),
        }
    }
}

impl Error for ResourceError {}

fn validate_text(text: &str, empty: ResourceError) -> Result<(), ResourceError> {
    if text.is_empty() {
        return Err(empty);
    }
    if text.contains('\0') {
        return Err(ResourceError::EmbeddedNul);
    }
    Ok(())
}

fn prefix_maximum(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        Cidr, ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource, Resource, ResourceError, ResourceKind,
    };

    #[test]
    fn file_resource_keeps_the_supplied_text() {
        let resource = FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file");
        assert_eq!(resource.anchor(), FilesystemAnchor::Repo);
        assert_eq!(resource.file_path(), "src/lib.rs");
        assert_eq!(resource, resource.clone());
    }

    #[test]
    fn file_resource_rejects_empty_text_and_nul() {
        assert_eq!(
            FileResource::new(FilesystemAnchor::Home, ""),
            Err(ResourceError::EmptyFilePath)
        );
        assert_eq!(
            FileResource::new(FilesystemAnchor::Temp, "a\0b"),
            Err(ResourceError::EmbeddedNul)
        );
    }

    #[test]
    fn executable_resource_keeps_the_supplied_identity() {
        let resource = ExecutableResource::new("git").expect("executable");
        assert_eq!(resource.identity(), "git");
        assert_eq!(
            ExecutableResource::new(""),
            Err(ResourceError::EmptyExecutableIdentity)
        );
        assert_eq!(
            ExecutableResource::new("git\0"),
            Err(ResourceError::EmbeddedNul)
        );
    }

    #[test]
    fn cidr_prefix_must_fit_the_address_family() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let cidr = Cidr::new(v4, 32).expect("cidr");
        assert_eq!(cidr.address(), v4);
        assert_eq!(cidr.prefix_length(), 32);
        assert_eq!(NetworkAddress::cidr(v4, 32), Ok(NetworkAddress::Cidr(cidr)));
        assert_eq!(
            NetworkAddress::cidr(v4, 33),
            Err(ResourceError::PrefixOutOfRange {
                prefix_length: 33,
                maximum: 32,
            })
        );
        assert_eq!(
            NetworkAddress::cidr(v6, 129),
            Err(ResourceError::PrefixOutOfRange {
                prefix_length: 129,
                maximum: 128,
            })
        );
    }

    #[test]
    fn network_resource_equality_uses_every_field() {
        let address = NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let connect = NetworkResource::new(NetworkProtocol::Tcp, address, 443);
        let other_port = NetworkResource::new(NetworkProtocol::Tcp, address, 80);
        assert_eq!(connect, connect);
        assert_ne!(connect, other_port);
        assert_eq!(Resource::Network(connect).kind(), ResourceKind::Network);
    }

    #[test]
    fn deserialization_uses_the_checked_constructors() {
        let file =
            serde_json::from_str::<FileResource>(r#"{"anchor":"repo","file_path":"src/lib.rs"}"#)
                .expect("file");
        assert_eq!(file.file_path(), "src/lib.rs");
        assert!(
            serde_json::from_str::<FileResource>(r#"{"anchor":"repo","file_path":""}"#).is_err()
        );
        assert!(serde_json::from_str::<ExecutableResource>(r#"{"identity":""}"#).is_err());
        assert!(
            serde_json::from_str::<Cidr>(r#"{"address":"10.0.0.0","prefix_length":99}"#).is_err()
        );
        let cidr = serde_json::from_str::<Cidr>(r#"{"address":"10.0.0.0","prefix_length":8}"#)
            .expect("cidr");
        assert_eq!(cidr.prefix_length(), 8);
    }
}
