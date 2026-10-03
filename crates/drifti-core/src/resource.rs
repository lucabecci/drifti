// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed resources named by a capability.
//!
//! A file resource records an anchor and a normalized path. Equivalent paths
//! share one form, and a path that leaves its anchor is not stored there.
//! A final `**` component is a recursive prefix, not a glob. An executable
//! resource records its identity text as supplied. A network resource records
//! a transport, an IP address or CIDR, and a port.

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
        let pattern = path_pattern(&absolute);
        Ok(classify(roots, pattern.base, pattern.recursive))
    }

    /// Host path of this resource under the given roots.
    ///
    /// A recursive prefix returns its directory, without the `**` marker.
    #[must_use]
    pub fn host_path(&self, roots: &FilesystemRoots) -> String {
        let base = path_pattern(&self.file_path).base;
        let root = match self.anchor {
            FilesystemAnchor::Repo => roots.repo(),
            FilesystemAnchor::Home => roots.home(),
            FilesystemAnchor::Temp => roots.temp(),
            FilesystemAnchor::Absolute => return base.to_owned(),
        };
        join_root(root, base)
    }

    /// Anchor that owns this file.
    #[must_use]
    pub fn anchor(&self) -> FilesystemAnchor {
        self.anchor
    }

    /// Normalized path text.
    ///
    /// A recursive prefix keeps a final `**` component, as in `src/**`.
    #[must_use]
    pub fn file_path(&self) -> &str {
        &self.file_path
    }

    /// Whether the path is a recursive prefix.
    #[must_use]
    pub fn is_recursive(&self) -> bool {
        path_pattern(&self.file_path).recursive
    }

    /// Whether this file covers `other`.
    ///
    /// An exact path covers only itself. A recursive prefix covers that path
    /// and every path under it, including a narrower recursive prefix. A
    /// different anchor is never covered. A literal `*` component is not a glob.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        if self.anchor != other.anchor {
            return false;
        }
        let parent = path_pattern(&self.file_path);
        let child = path_pattern(&other.file_path);
        let parent_parts = path_components(parent.base);
        let child_parts = path_components(child.base);
        if parent.recursive {
            child_parts.starts_with(&parent_parts)
        } else {
            !child.recursive && parent_parts == child_parts
        }
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

    /// Whether this resource covers `other`.
    ///
    /// Different resource families never cover each other. Executable and
    /// network coverage is exact equality. File coverage follows
    /// [`FileResource::contains`].
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(parent), Self::File(child)) => parent.contains(child),
            (Self::Executable(parent), Self::Executable(child)) => parent == child,
            (Self::Network(parent), Self::Network(child)) => parent == child,
            _ => false,
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
    /// `repo://`, `home://`, or `temp://` was given an absolute path.
    NotRelative,
    /// `abs://` or a filesystem root was given a relative path.
    NotAbsolute,
    /// `**` appeared before another path component.
    MisplacedRecursiveMarker,
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
            Self::NotRelative => formatter.write_str("anchored file path must stay relative"),
            Self::NotAbsolute => formatter.write_str("absolute file path must start with /"),
            Self::MisplacedRecursiveMarker => {
                formatter.write_str("recursive marker ** is only valid as the final path component")
            }
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
    let normalized = normalize_absolute(&text)?;
    if path_pattern(&normalized).recursive {
        return Err(ResourceError::MisplacedRecursiveMarker);
    }
    Ok(normalized)
}

fn normalize_relative(text: &str) -> Result<String, ResourceError> {
    if text.starts_with('/') || text.starts_with('\\') {
        return Err(ResourceError::NotRelative);
    }
    normalize_components(text, false)
}

fn normalize_absolute(text: &str) -> Result<String, ResourceError> {
    let unified = text.replace('\\', "/");
    if !unified.starts_with('/') {
        return Err(ResourceError::NotAbsolute);
    }
    normalize_components(&unified, true)
}

fn normalize_components(text: &str, absolute: bool) -> Result<String, ResourceError> {
    let mut stack = Vec::new();
    let mut recursive = false;
    let parts: Vec<&str> = text.split(['/', '\\']).collect();
    for (index, component) in parts.iter().copied().enumerate() {
        match component {
            "" | "." => {}
            ".." => {
                if absolute {
                    stack.pop();
                } else if stack.pop().is_none() {
                    return Err(ResourceError::EscapesAnchor);
                }
            }
            "**" => {
                let rest_is_empty = parts[index + 1..]
                    .iter()
                    .all(|part| part.is_empty() || *part == ".");
                if !rest_is_empty {
                    return Err(ResourceError::MisplacedRecursiveMarker);
                }
                recursive = true;
                break;
            }
            other => stack.push(other),
        }
    }
    Ok(canonical_path(&stack, absolute, recursive))
}

fn canonical_path(stack: &[&str], absolute: bool, recursive: bool) -> String {
    let base = if stack.is_empty() {
        if absolute {
            "/".to_owned()
        } else {
            ".".to_owned()
        }
    } else if absolute {
        format!("/{}", stack.join("/"))
    } else {
        stack.join("/")
    };
    marked(base, recursive)
}

fn marked(base: String, recursive: bool) -> String {
    if !recursive {
        return base;
    }
    match base.as_str() {
        "." => "**".to_owned(),
        "/" => "/**".to_owned(),
        _ => format!("{base}/**"),
    }
}

struct PathPattern<'a> {
    base: &'a str,
    recursive: bool,
}

fn path_pattern(file_path: &str) -> PathPattern<'_> {
    if file_path == "**" {
        return PathPattern {
            base: ".",
            recursive: true,
        };
    }
    if file_path == "/**" {
        return PathPattern {
            base: "/",
            recursive: true,
        };
    }
    match file_path.rsplit_once('/') {
        Some((dir, "**")) if !dir.is_empty() => PathPattern {
            base: dir,
            recursive: true,
        },
        _ => PathPattern {
            base: file_path,
            recursive: false,
        },
    }
}

fn path_components(base: &str) -> Vec<&str> {
    if base == "." || base == "/" {
        Vec::new()
    } else {
        base.trim_start_matches('/')
            .split('/')
            .filter(|component| !component.is_empty())
            .collect()
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

fn classify(roots: &FilesystemRoots, absolute: &str, recursive: bool) -> FileResource {
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
        Some((anchor, file_path)) => FileResource {
            anchor,
            file_path: marked(file_path, recursive),
        },
        None => FileResource {
            anchor: FilesystemAnchor::Absolute,
            file_path: marked(absolute.to_owned(), recursive),
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

    fn file(anchor: FilesystemAnchor, path: &str) -> FileResource {
        FileResource::new(anchor, path).expect("file")
    }

    #[test]
    fn recursive_prefix_is_normalized_once() {
        let prefix = file(FilesystemAnchor::Repo, "src/./domain/../**");
        assert_eq!(prefix.file_path(), "src/**");
        assert!(prefix.is_recursive());
        let again = FileResource::new(prefix.anchor(), prefix.file_path()).expect("again");
        assert_eq!(prefix, again);
        assert_eq!(file(FilesystemAnchor::Repo, "**").file_path(), "**");
        assert_eq!(
            file(FilesystemAnchor::Absolute, "/etc/**").file_path(),
            "/etc/**"
        );
        assert_eq!(file(FilesystemAnchor::Absolute, "/**").file_path(), "/**");
        assert!(!file(FilesystemAnchor::Repo, "src/*").is_recursive());
    }

    #[test]
    fn misplaced_recursive_marker_is_rejected() {
        assert_eq!(
            FileResource::new(FilesystemAnchor::Repo, "src/**/lib.rs"),
            Err(ResourceError::MisplacedRecursiveMarker)
        );
        assert_eq!(
            FileResource::new(FilesystemAnchor::Repo, "src/**/**"),
            Err(ResourceError::MisplacedRecursiveMarker)
        );
        assert_eq!(
            FileResource::new(FilesystemAnchor::Absolute, "/etc/**/passwd"),
            Err(ResourceError::MisplacedRecursiveMarker)
        );
        assert_eq!(
            FilesystemRoots::new("/work/**", "/home", "/tmp"),
            Err(ResourceError::MisplacedRecursiveMarker)
        );
    }

    #[test]
    fn recursive_prefix_containment_follows_the_spec_examples() {
        let root = file(FilesystemAnchor::Repo, "**");
        let src = file(FilesystemAnchor::Repo, "src/**");
        let domain = file(FilesystemAnchor::Repo, "src/domain/**");
        let nested = file(FilesystemAnchor::Repo, "src/domain/mod.rs");
        assert!(src.contains(&domain));
        assert!(domain.contains(&nested));
        assert!(root.contains(&src));
        assert!(root.contains(&domain));
        assert!(!domain.contains(&src));
        assert!(!nested.contains(&domain));
        assert!(src.contains(&file(FilesystemAnchor::Repo, "src")));
        assert!(!file(FilesystemAnchor::Repo, "src").contains(&nested));
        assert!(!src.contains(&file(FilesystemAnchor::Repo, "srcdir/lib.rs")));
        assert!(!file(FilesystemAnchor::Repo, "src/*").contains(&nested));
    }

    #[test]
    fn containment_does_not_cross_anchors_or_resource_families() {
        let repo = file(FilesystemAnchor::Repo, "src/**");
        let home = file(FilesystemAnchor::Home, "src/lib.rs");
        assert!(!repo.contains(&home));
        assert!(!home.contains(&repo));

        let executable = ExecutableResource::new("git").expect("executable");
        let other_executable = ExecutableResource::new("git-lfs").expect("executable");
        let network = NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            443,
        );
        let other_network = NetworkResource::new(network.protocol(), network.address(), 80);
        let file_resource = Resource::File(repo);
        let executable_resource = Resource::Executable(executable.clone());
        let network_resource = Resource::Network(network);

        assert!(file_resource.contains(&file_resource));
        assert!(executable_resource.contains(&Resource::Executable(executable)));
        assert!(!executable_resource.contains(&Resource::Executable(other_executable)));
        assert!(network_resource.contains(&network_resource));
        assert!(!network_resource.contains(&Resource::Network(other_network)));
        for left in [&file_resource, &executable_resource, &network_resource] {
            for right in [&file_resource, &executable_resource, &network_resource] {
                if left.kind() != right.kind() {
                    assert!(!left.contains(right));
                }
            }
        }
    }

    #[test]
    fn host_paths_keep_a_recursive_prefix() {
        let roots = sample_roots("/checkouts/one");
        let hosted =
            FileResource::from_host_path(&roots, "/checkouts/one/src/domain/**").expect("hosted");
        assert_eq!(hosted, file(FilesystemAnchor::Repo, "src/domain/**"));
        assert_eq!(hosted.host_path(&roots), "/checkouts/one/src/domain");
        let reloaded =
            FileResource::from_host_path(&roots, hosted.host_path(&roots)).expect("reloaded");
        assert_eq!(reloaded, file(FilesystemAnchor::Repo, "src/domain"));
        assert!(!reloaded.is_recursive());
        assert_eq!(
            FileResource::from_host_path(&roots, "/checkouts/one/src/**/lib.rs"),
            Err(ResourceError::MisplacedRecursiveMarker)
        );
    }

    #[test]
    fn containment_is_reflexive_antisymmetric_and_transitive() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let anchor = prop_oneof![
            Just(FilesystemAnchor::Repo),
            Just(FilesystemAnchor::Home),
            Just(FilesystemAnchor::Temp),
            Just(FilesystemAnchor::Absolute),
        ];
        let parts = proptest::collection::vec(
            prop_oneof![
                Just("src"),
                Just("domain"),
                Just("lib.rs"),
                Just("a"),
                Just("b")
            ],
            0..=4,
        );
        let pattern = (anchor, parts.clone(), any::<bool>());
        runner
            .run(
                &(pattern.clone(), pattern.clone(), pattern),
                |(
                    (anchor_a, parts_a, recursive_a),
                    (anchor_b, parts_b, recursive_b),
                    (anchor_c, parts_c, recursive_c),
                )| {
                    let parent = generated_file(anchor_a, &parts_a, recursive_a);
                    let child = generated_file(anchor_b, &parts_b, recursive_b);
                    let grandchild = generated_file(anchor_c, &parts_c, recursive_c);
                    prop_assert!(parent.contains(&parent));
                    let rebuilt =
                        FileResource::new(parent.anchor(), parent.file_path()).expect("rebuilt");
                    prop_assert_eq!(&parent, &rebuilt);
                    if parent.anchor() != child.anchor() {
                        prop_assert!(!parent.contains(&child));
                        prop_assert!(!child.contains(&parent));
                        return Ok(());
                    }
                    prop_assert_eq!(
                        parent.contains(&child) && child.contains(&parent),
                        parent == child
                    );
                    if parent.contains(&child) && parent != child {
                        prop_assert!(!child.contains(&parent));
                    }
                    if parent.contains(&child) && child.contains(&grandchild) {
                        prop_assert!(parent.contains(&grandchild));
                    }
                    let expected = if recursive_a && anchor_a == anchor_b {
                        parts_b.starts_with(&parts_a[..])
                    } else {
                        anchor_a == anchor_b && !recursive_b && parts_a == parts_b
                    };
                    prop_assert_eq!(parent.contains(&child), expected);
                    Ok(())
                },
            )
            .expect("containment");
    }

    fn generated_file(anchor: FilesystemAnchor, parts: &[&str], recursive: bool) -> FileResource {
        let supplied = if parts.is_empty() {
            match (anchor, recursive) {
                (FilesystemAnchor::Absolute, true) => "/**".to_owned(),
                (FilesystemAnchor::Absolute, false) => "/".to_owned(),
                (_, true) => "**".to_owned(),
                (_, false) => ".".to_owned(),
            }
        } else {
            let joined = parts.join("/");
            let base = if anchor == FilesystemAnchor::Absolute {
                format!("/{joined}")
            } else {
                joined
            };
            if recursive {
                format!("{base}/**")
            } else {
                base
            }
        };
        FileResource::new(anchor, supplied).expect("generated file")
    }
}
