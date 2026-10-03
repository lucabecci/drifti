// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed resources named by a capability.
//!
//! A file resource records an anchor and a normalized path. Equivalent paths
//! share one form, and a path that leaves its anchor is not stored there.
//! An executable resource records a canonical identity. A network resource
//! records a transport, an IP address or a CIDR network address, and a port.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Checkout, home, and temp roots used to choose a stable anchor.
///
/// Roots are lexical absolute paths. The longest matching root wins, so a
/// checkout inside the home directory stays `repo://`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemRoots {
    repo: String,
    home: String,
    temp: String,
}

impl FilesystemRoots {
    /// Normalizes the three roots. Each one must be an absolute path.
    pub fn new(
        repo: impl Into<String>,
        home: impl Into<String>,
        temp: impl Into<String>,
    ) -> Result<Self, ResourceError> {
        Ok(Self {
            repo: absolute_root(repo.into())?,
            home: absolute_root(home.into())?,
            temp: absolute_root(temp.into())?,
        })
    }

    /// Checkout root.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Home root.
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// Temp root.
    #[must_use]
    pub fn temp(&self) -> &str {
        &self.temp
    }
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
    /// Builds a file resource and normalizes the path inside that anchor.
    ///
    /// `.` and `..` that stay inside the anchor collapse. A relative path that
    /// would leave `repo://`, `home://`, or `temp://` is rejected. `abs://`
    /// requires an absolute path. An empty value or an embedded NUL is rejected.
    pub fn new(
        anchor: FilesystemAnchor,
        file_path: impl Into<String>,
    ) -> Result<Self, ResourceError> {
        let supplied = file_path.into();
        validate_text(&supplied, ResourceError::EmptyFilePath)?;
        let file_path = match anchor {
            FilesystemAnchor::Absolute => normalize_absolute(&supplied)?,
            FilesystemAnchor::Repo | FilesystemAnchor::Home | FilesystemAnchor::Temp => {
                normalize_relative(&supplied)?
            }
        };
        Ok(Self { anchor, file_path })
    }

    /// Classifies a host path under the longest matching root.
    ///
    /// A relative host path is resolved from the checkout root. The stored
    /// resource does not keep that checkout's absolute location.
    pub fn from_host_path(
        roots: &FilesystemRoots,
        host_path: impl Into<String>,
    ) -> Result<Self, ResourceError> {
        let supplied = host_path.into();
        validate_text(&supplied, ResourceError::EmptyFilePath)?;
        let absolute = resolve_host(roots, &supplied)?;
        Ok(classify(roots, &absolute))
    }

    /// Absolute host path of this resource under the given roots.
    #[must_use]
    pub fn host_path(&self, roots: &FilesystemRoots) -> String {
        let root = match self.anchor {
            FilesystemAnchor::Repo => roots.repo(),
            FilesystemAnchor::Home => roots.home(),
            FilesystemAnchor::Temp => roots.temp(),
            FilesystemAnchor::Absolute => return self.file_path.clone(),
        };
        join_root(root, &self.file_path)
    }

    /// Anchor that owns this file.
    #[must_use]
    pub fn anchor(&self) -> FilesystemAnchor {
        self.anchor
    }

    /// Normalized path text.
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
    /// Builds an executable resource from its canonical identity.
    ///
    /// A bare name is kept as supplied. A path is normalized lexically: `.` and
    /// `..` that stay inside collapse, and a relative `..` that leaves the
    /// relative root is rejected. An empty value or an embedded NUL is rejected.
    /// The text is not resolved through `PATH` or the filesystem.
    pub fn new(identity: impl Into<String>) -> Result<Self, ResourceError> {
        let supplied = identity.into();
        let identity = canonical_executable(&supplied)?;
        Ok(Self { identity })
    }

    /// Canonical identity text.
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
    ///
    /// Host bits are cleared, so `10.1.2.3/8` and `10.0.0.0/8` are one network.
    pub fn new(address: IpAddr, prefix_length: u8) -> Result<Self, ResourceError> {
        let maximum = prefix_maximum(address);
        if prefix_length > maximum {
            return Err(ResourceError::PrefixOutOfRange {
                prefix_length,
                maximum,
            });
        }
        Ok(Self {
            address: canonical_network(address, prefix_length),
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
    /// A relative path left `repo://`, `home://`, or `temp://`.
    EscapesAnchor,
    /// A relative executable path left its relative root.
    ExecutableEscape,
    /// `repo://`, `home://`, or `temp://` was given an absolute path.
    NotRelative,
    /// `abs://` or a filesystem root was given a relative path.
    NotAbsolute,
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
            Self::EscapesAnchor => formatter.write_str("path leaves its filesystem anchor"),
            Self::ExecutableEscape => {
                formatter.write_str("executable path leaves its relative root")
            }
            Self::NotRelative => formatter.write_str("anchored file path must stay relative"),
            Self::NotAbsolute => formatter.write_str("absolute file path must start with /"),
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

fn absolute_root(text: String) -> Result<String, ResourceError> {
    validate_text(&text, ResourceError::NotAbsolute)?;
    normalize_absolute(&text)
}

fn normalize_relative(text: &str) -> Result<String, ResourceError> {
    if text.starts_with('/') || text.starts_with('\\') {
        return Err(ResourceError::NotRelative);
    }
    let mut stack = Vec::new();
    for component in text.split(['/', '\\']) {
        match component {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return Err(ResourceError::EscapesAnchor);
                }
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        Ok(".".to_owned())
    } else {
        Ok(stack.join("/"))
    }
}

fn normalize_absolute(text: &str) -> Result<String, ResourceError> {
    let unified = text.replace('\\', "/");
    if !unified.starts_with('/') {
        return Err(ResourceError::NotAbsolute);
    }
    let mut stack = Vec::new();
    for component in unified.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", stack.join("/")))
    }
}

fn resolve_host(roots: &FilesystemRoots, text: &str) -> Result<String, ResourceError> {
    let unified = text.replace('\\', "/");
    if unified.starts_with('/') {
        return normalize_absolute(&unified);
    }
    let joined = join_root(&roots.repo, &unified);
    normalize_absolute(&joined)
}

fn join_root(root: &str, relative: &str) -> String {
    if relative.is_empty() || relative == "." {
        return root.to_owned();
    }
    if root == "/" {
        format!("/{relative}")
    } else {
        format!("{root}/{relative}")
    }
}

fn classify(roots: &FilesystemRoots, absolute: &str) -> FileResource {
    let candidates = [
        (FilesystemAnchor::Repo, roots.repo()),
        (FilesystemAnchor::Temp, roots.temp()),
        (FilesystemAnchor::Home, roots.home()),
    ];
    let mut best: Option<(FilesystemAnchor, String)> = None;
    let mut best_specificity = 0;
    for (anchor, root) in candidates {
        if let Some(relative) = strip_root(absolute, root) {
            let specificity = root_specificity(root);
            if best.is_none() || specificity > best_specificity {
                best = Some((anchor, relative));
                best_specificity = specificity;
            }
        }
    }
    match best {
        Some((anchor, file_path)) => FileResource { anchor, file_path },
        None => FileResource {
            anchor: FilesystemAnchor::Absolute,
            file_path: absolute.to_owned(),
        },
    }
}

fn strip_root(absolute: &str, root: &str) -> Option<String> {
    if root == "/" {
        return Some(if absolute == "/" {
            ".".to_owned()
        } else {
            absolute[1..].to_owned()
        });
    }
    if absolute == root {
        return Some(".".to_owned());
    }
    let prefix = format!("{root}/");
    absolute.strip_prefix(&prefix).map(str::to_owned)
}

fn root_specificity(root: &str) -> usize {
    if root == "/" {
        0
    } else {
        root.split('/')
            .filter(|component| !component.is_empty())
            .count()
    }
}

fn canonical_executable(text: &str) -> Result<String, ResourceError> {
    validate_text(text, ResourceError::EmptyExecutableIdentity)?;
    let path_like = text.contains('/') || text.contains('\\') || text == "." || text == "..";
    if !path_like {
        return Ok(text.to_owned());
    }
    if text.starts_with('/') || text.starts_with('\\') {
        return normalize_absolute(text);
    }
    normalize_relative(text).map_err(|error| match error {
        ResourceError::EscapesAnchor => ResourceError::ExecutableEscape,
        other => other,
    })
}

fn canonical_network(address: IpAddr, prefix_length: u8) -> IpAddr {
    match address {
        IpAddr::V4(ipv4) => IpAddr::V4(mask_v4(ipv4, prefix_length)),
        IpAddr::V6(ipv6) => IpAddr::V6(mask_v6(ipv6, prefix_length)),
    }
}

fn mask_v4(address: Ipv4Addr, prefix_length: u8) -> Ipv4Addr {
    if prefix_length == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - u32::from(prefix_length));
    Ipv4Addr::from(u32::from(address) & mask)
}

fn mask_v6(address: Ipv6Addr, prefix_length: u8) -> Ipv6Addr {
    if prefix_length == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = u128::MAX << (128 - u32::from(prefix_length));
    Ipv6Addr::from(u128::from(address) & mask)
}

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
        Cidr, ExecutableResource, FileResource, FilesystemAnchor, FilesystemRoots, NetworkAddress,
        NetworkProtocol, NetworkResource, Resource, ResourceError, ResourceKind,
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

    fn sample_roots(repo: &str) -> FilesystemRoots {
        FilesystemRoots::new(repo, "/home/dev", "/home/dev/tmp").expect("roots")
    }

    #[test]
    fn equivalent_paths_normalize_identically() {
        let expected = FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file");
        for supplied in [
            "src/lib.rs",
            "src/./lib.rs",
            "src/foo/../lib.rs",
            "src//lib.rs",
        ] {
            assert_eq!(
                FileResource::new(FilesystemAnchor::Repo, supplied).expect("file"),
                expected
            );
        }
        assert_eq!(
            FileResource::new(FilesystemAnchor::Absolute, "/etc/./passwd").expect("abs"),
            FileResource::new(FilesystemAnchor::Absolute, "/etc/passwd").expect("abs")
        );
    }

    #[test]
    fn normalization_is_idempotent() {
        let roots = sample_roots("/checkouts/one");
        let resource = FileResource::new(FilesystemAnchor::Repo, "src/./lib.rs").expect("file");
        let again = FileResource::new(resource.anchor(), resource.file_path()).expect("again");
        assert_eq!(resource, again);
        let hosted =
            FileResource::from_host_path(&roots, "/checkouts/one/src/./lib.rs").expect("hosted");
        let repeated =
            FileResource::from_host_path(&roots, hosted.host_path(&roots)).expect("repeated");
        assert_eq!(hosted, repeated);
        assert_eq!(hosted.file_path(), "src/lib.rs");
    }

    #[test]
    fn repo_resources_stay_portable_across_checkouts() {
        let first = sample_roots("/checkouts/one");
        let second = sample_roots("/checkouts/two");
        let from_first =
            FileResource::from_host_path(&first, "/checkouts/one/src/lib.rs").expect("first");
        let from_second =
            FileResource::from_host_path(&second, "/checkouts/two/src/lib.rs").expect("second");
        assert_eq!(from_first, from_second);
        assert_eq!(from_first.anchor(), FilesystemAnchor::Repo);
        assert_eq!(from_first.file_path(), "src/lib.rs");
    }

    #[test]
    fn anchor_boundaries_are_not_crossed() {
        assert_eq!(
            FileResource::new(FilesystemAnchor::Repo, "../secret"),
            Err(ResourceError::EscapesAnchor)
        );
        assert_eq!(
            FileResource::new(FilesystemAnchor::Repo, "/etc/passwd"),
            Err(ResourceError::NotRelative)
        );
        assert_eq!(
            FileResource::new(FilesystemAnchor::Absolute, "src/lib.rs"),
            Err(ResourceError::NotAbsolute)
        );
        let roots = FilesystemRoots::new("/work/repo", "/work", "/work/repo/tmp").expect("roots");
        let escaped =
            FileResource::from_host_path(&roots, "/work/repo/../outside").expect("escaped");
        assert_eq!(escaped.anchor(), FilesystemAnchor::Home);
        assert_eq!(escaped.file_path(), "outside");
        let neighbor =
            FileResource::from_host_path(&roots, "/work/repo-extra/file").expect("neighbor");
        assert_eq!(neighbor.anchor(), FilesystemAnchor::Home);
        assert_eq!(neighbor.file_path(), "repo-extra/file");
        let inside = FileResource::from_host_path(&roots, "/work/repo/src/lib.rs").expect("inside");
        assert_eq!(inside.anchor(), FilesystemAnchor::Repo);
        let temporary = FileResource::from_host_path(&roots, "/work/repo/tmp/out").expect("temp");
        assert_eq!(temporary.anchor(), FilesystemAnchor::Temp);
        assert_eq!(temporary.file_path(), "out");
    }

    #[test]
    fn normalization_idempotence_holds_for_generated_paths() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let strategy = proptest::collection::vec(
            prop_oneof![Just("src"), Just("lib.rs"), Just("."), Just(".."), Just("")],
            0..=8,
        );
        runner
            .run(&strategy, |parts| {
                let supplied = parts.join("/");
                if supplied.is_empty() {
                    return Ok(());
                }
                match FileResource::new(FilesystemAnchor::Repo, supplied) {
                    Ok(resource) => {
                        let again = FileResource::new(resource.anchor(), resource.file_path())
                            .expect("again");
                        prop_assert_eq!(resource.clone(), again);
                        prop_assert!(!resource.file_path().contains("//"));
                        prop_assert!(!resource
                            .file_path()
                            .split('/')
                            .any(|component| component == ".."));
                        Ok(())
                    }
                    Err(ResourceError::EscapesAnchor | ResourceError::NotRelative) => Ok(()),
                    Err(error) => panic!("unexpected resource error: {error}"),
                }
            })
            .expect("property");
    }

    #[test]
    fn executable_identity_equality_is_canonical() {
        let expected = ExecutableResource::new("git").expect("name");
        assert_eq!(
            ExecutableResource::new("./git").expect("relative"),
            expected
        );
        assert_eq!(
            ExecutableResource::new("bin/../git").expect("collapsed"),
            expected
        );
        let absolute = ExecutableResource::new("/usr/bin/./git").expect("absolute");
        assert_eq!(absolute.identity(), "/usr/bin/git");
        assert_eq!(
            ExecutableResource::new(absolute.identity()).expect("again"),
            absolute
        );
        assert_ne!(absolute, expected);
        assert_eq!(
            ExecutableResource::new("../git"),
            Err(ResourceError::ExecutableEscape)
        );
    }

    #[test]
    fn cidr_identity_clears_host_bits() {
        let supplied = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let network = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let cidr = Cidr::new(supplied, 8).expect("cidr");
        assert_eq!(cidr.address(), network);
        assert_eq!(Cidr::new(network, 8).expect("again"), cidr);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let masked = Cidr::new(v6, 32).expect("v6");
        assert_eq!(
            masked.address(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
        );
    }

    #[test]
    fn executable_and_network_serialization_is_lossless() {
        let executable = ExecutableResource::new("/usr/bin/./git").expect("executable");
        let executable_json = serde_json::to_string(&executable).expect("json");
        assert_eq!(
            serde_json::from_str::<ExecutableResource>(&executable_json).expect("back"),
            executable
        );
        let cidr = Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 8).expect("cidr");
        let network = NetworkResource::new(NetworkProtocol::Tcp, NetworkAddress::Cidr(cidr), 443);
        let network_json = serde_json::to_string(&network).expect("json");
        let restored = serde_json::from_str::<NetworkResource>(&network_json).expect("back");
        assert_eq!(restored, network);
        assert_eq!(restored.protocol(), NetworkProtocol::Tcp);
        assert_eq!(restored.port(), 443);
        assert_eq!(restored.address(), NetworkAddress::Cidr(cidr));
    }

    #[test]
    fn cidr_canonical_form_is_idempotent() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let strategy = (any::<u32>(), 0u8..=32);
        runner
            .run(&strategy, |(bits, prefix_length)| {
                let address = IpAddr::V4(Ipv4Addr::from(bits));
                let cidr = Cidr::new(address, prefix_length).expect("cidr");
                let again = Cidr::new(cidr.address(), cidr.prefix_length()).expect("again");
                prop_assert_eq!(cidr, again);
                Ok(())
            })
            .expect("property");
    }
}
