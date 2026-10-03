// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compile a parsed contract into a typed policy.
//!
//! Parsing has already accepted a version-1 document. Compilation resolves
//! each authoring resource into a SPEC-001 resource and emits SPEC-002 allow
//! and deny rules. `./` and other relative paths become `repo://`. A leading
//! `~` or `~/` becomes `home://`. A leading `/` becomes `abs://`. Network
//! resources become a transport, an IP or CIDR, and a port. The returned
//! [`CompiledPolicy`](crate::policy::CompiledPolicy) is a value the caller can
//! hold. Compilation does not accept that value as authority, sort resources,
//! widen a pattern, or render a terminal.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

use crate::capability::{Action, Capability};
use crate::policy::{CompiledPolicy, Rule, RuleEffect, RuleId};
use crate::resource::{
    ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
    NetworkResource, Resource, ResourceError,
};

use super::{
    AllowDenyRules, ContractDocument, ContractVersion, ALLOW_KEY, CONNECT_KEY, DENY_KEY,
    EXECUTE_KEY, FILESYSTEM_KEY, LISTEN_KEY, NETWORK_KEY, PROCESS_KEY, READ_KEY, WRITE_KEY,
};

const VALUE_LIMIT: usize = 80;

/// Expected filesystem authoring form.
const FILE_FORM: &str =
    "a repo path such as ./src/**, a home path such as ~/.ssh/**, or an absolute path such as /etc/hosts";
/// Expected executable authoring form.
const EXECUTABLE_FORM: &str = "an executable identity such as /usr/bin/cargo";
/// Expected network authoring form.
const NETWORK_FORM: &str = "tcp://<ip-or-cidr>:<port> or udp://<ip-or-cidr>:<port>";
/// A pattern the version-1 filesystem language does not represent.
const PATTERN_FORM: &str = "an exact path or a final ** prefix";
/// A path that would leave the anchor it was classified under.
const INSIDE_FORM: &str = "a path that stays inside its root";
/// A CIDR prefix that does not fit the address family.
const PREFIX_FORM: &str = "a CIDR prefix that fits the address family";

/// Failure while compiling a parsed contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractCompileError {
    /// The document version is not version 1.
    UnsupportedVersion {
        /// Numeric version from the document.
        version: u32,
    },
    /// One authoring resource cannot become the action's typed resource.
    InvalidResource {
        /// Field path, such as `filesystem.read.allow[0]`.
        field_path: String,
        /// The rejected text, bounded for display.
        value: String,
        /// What that action can name.
        expected: &'static str,
    },
}

impl Display for ContractCompileError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "unsupported contract version {version}; supported version is 1"
            ),
            Self::InvalidResource {
                field_path,
                value,
                expected,
            } => write!(
                formatter,
                "invalid resource `{value}` at {field_path}; expected {expected}"
            ),
        }
    }
}

impl Error for ContractCompileError {}

#[derive(Clone, Copy)]
enum Family {
    File,
    Executable,
    Network,
}

enum CompileFailure {
    Form(&'static str),
    Resource(ResourceError),
}

/// Compiles a version-1 document into typed policy rules.
///
/// Rule order follows the document: filesystem read, filesystem write,
/// process execute, network connect, then network listen. Inside each action,
/// allow rules stay before deny rules, and each list keeps author order.
/// Empty lists add no rules. An authoring resource that is not the action's
/// resource family fails the whole compilation.
#[must_use = "compilation errors must be handled"]
pub fn compile_contract(
    document: &ContractDocument,
) -> Result<CompiledPolicy, ContractCompileError> {
    if document.version() != ContractVersion::V1 {
        return Err(ContractCompileError::UnsupportedVersion {
            version: document.version().get(),
        });
    }
    let mut rules = Vec::new();
    let filesystem = document.filesystem();
    append_action(
        &mut rules,
        FILESYSTEM_KEY,
        READ_KEY,
        Action::FilesystemRead,
        Family::File,
        filesystem.read(),
    )?;
    append_action(
        &mut rules,
        FILESYSTEM_KEY,
        WRITE_KEY,
        Action::FilesystemWrite,
        Family::File,
        filesystem.write(),
    )?;
    append_action(
        &mut rules,
        PROCESS_KEY,
        EXECUTE_KEY,
        Action::ProcessExecute,
        Family::Executable,
        document.process().execute(),
    )?;
    let network = document.network();
    append_action(
        &mut rules,
        NETWORK_KEY,
        CONNECT_KEY,
        Action::NetworkConnect,
        Family::Network,
        network.connect(),
    )?;
    append_action(
        &mut rules,
        NETWORK_KEY,
        LISTEN_KEY,
        Action::NetworkListen,
        Family::Network,
        network.listen(),
    )?;
    Ok(CompiledPolicy::new(rules))
}

fn append_action(
    rules: &mut Vec<Rule>,
    domain: &str,
    action_name: &str,
    action: Action,
    family: Family,
    listed: &AllowDenyRules,
) -> Result<(), ContractCompileError> {
    append_effect(
        rules,
        domain,
        action_name,
        action,
        family,
        RuleEffect::Allow,
        listed.allow(),
    )?;
    append_effect(
        rules,
        domain,
        action_name,
        action,
        family,
        RuleEffect::Deny,
        listed.deny(),
    )
}

fn append_effect(
    rules: &mut Vec<Rule>,
    domain: &str,
    action_name: &str,
    action: Action,
    family: Family,
    effect: RuleEffect,
    resources: &[super::AuthoringResource],
) -> Result<(), ContractCompileError> {
    let effect_key = match effect {
        RuleEffect::Allow => ALLOW_KEY,
        RuleEffect::Deny => DENY_KEY,
    };
    for (index, resource) in resources.iter().enumerate() {
        let field_path = format!("{domain}.{action_name}.{effect_key}[{index}]");
        let capability = match compile_resource(family, action, resource.as_str()) {
            Ok(capability) => capability,
            Err(failure) => {
                return Err(invalid_resource(field_path, resource.as_str(), failure));
            }
        };
        let id = RuleId::new(field_path.clone()).expect("field path is a non-empty rule id");
        let rule = match effect {
            RuleEffect::Allow => Rule::allow(id, capability),
            RuleEffect::Deny => Rule::deny(id, capability),
        };
        rules.push(rule);
    }
    Ok(())
}

fn compile_resource(
    family: Family,
    action: Action,
    text: &str,
) -> Result<Capability, CompileFailure> {
    let resource = match family {
        Family::File => Resource::File(compile_file(text)?),
        Family::Executable => Resource::Executable(compile_executable(text)?),
        Family::Network => Resource::Network(compile_network(text)?),
    };
    Capability::try_new(action, resource).map_err(|_| CompileFailure::Form(expected_family(family)))
}

fn expected_family(family: Family) -> &'static str {
    match family {
        Family::File => FILE_FORM,
        Family::Executable => EXECUTABLE_FORM,
        Family::Network => NETWORK_FORM,
    }
}

fn compile_file(text: &str) -> Result<FileResource, CompileFailure> {
    if text.contains("://") {
        return Err(CompileFailure::Form(FILE_FORM));
    }
    let unified = text.replace('\\', "/");
    if has_unsupported_star(&unified) {
        return Err(CompileFailure::Form(PATTERN_FORM));
    }
    let (anchor, relative) = classify_file(&unified)?;
    FileResource::new(anchor, relative).map_err(CompileFailure::Resource)
}

fn classify_file(text: &str) -> Result<(FilesystemAnchor, String), CompileFailure> {
    if let Some(rest) = text.strip_prefix('~') {
        if rest.is_empty() {
            return Ok((FilesystemAnchor::Home, ".".to_owned()));
        }
        if let Some(rest) = rest.strip_prefix('/') {
            let relative = if rest.is_empty() {
                ".".to_owned()
            } else {
                rest.to_owned()
            };
            return Ok((FilesystemAnchor::Home, relative));
        }
        return Err(CompileFailure::Form(FILE_FORM));
    }
    if text.starts_with('/') {
        return Ok((FilesystemAnchor::Absolute, text.to_owned()));
    }
    Ok((FilesystemAnchor::Repo, text.to_owned()))
}

fn has_unsupported_star(text: &str) -> bool {
    text.split(['/', '\\'])
        .any(|component| component != "**" && component.contains('*'))
}

fn compile_executable(text: &str) -> Result<ExecutableResource, CompileFailure> {
    if text.contains("://") || text.contains('~') || text.contains('*') {
        return Err(CompileFailure::Form(EXECUTABLE_FORM));
    }
    let unified = text.replace('\\', "/");
    ExecutableResource::new(unified).map_err(CompileFailure::Resource)
}

fn compile_network(text: &str) -> Result<NetworkResource, CompileFailure> {
    let (scheme, rest) = text
        .split_once("://")
        .ok_or(CompileFailure::Form(NETWORK_FORM))?;
    if scheme.is_empty() || rest.is_empty() {
        return Err(CompileFailure::Form(NETWORK_FORM));
    }
    let protocol = match scheme {
        "tcp" => NetworkProtocol::Tcp,
        "udp" => NetworkProtocol::Udp,
        _ => return Err(CompileFailure::Form(NETWORK_FORM)),
    };
    let (address, port) = parse_endpoint(rest)?;
    Ok(NetworkResource::new(protocol, address, port))
}

fn parse_endpoint(rest: &str) -> Result<(NetworkAddress, u16), CompileFailure> {
    if let Some(rest) = rest.strip_prefix('[') {
        let (address_text, after) = rest
            .split_once(']')
            .ok_or(CompileFailure::Form(NETWORK_FORM))?;
        let address: IpAddr = address_text
            .parse()
            .map_err(|_| CompileFailure::Form(NETWORK_FORM))?;
        return address_from_suffix(address, after);
    }
    if rest.chars().filter(|character| *character == ':').count() != 1 {
        return Err(CompileFailure::Form(NETWORK_FORM));
    }
    let (host, port_text) = rest
        .split_once(':')
        .ok_or(CompileFailure::Form(NETWORK_FORM))?;
    let port = parse_port(port_text)?;
    let address = parse_host(host)?;
    Ok((address, port))
}

fn address_from_suffix(
    address: IpAddr,
    after: &str,
) -> Result<(NetworkAddress, u16), CompileFailure> {
    if let Some(port_text) = after.strip_prefix(':') {
        if port_text.contains('/') || port_text.contains(':') || port_text.contains(']') {
            return Err(CompileFailure::Form(NETWORK_FORM));
        }
        return Ok((NetworkAddress::ip(address), parse_port(port_text)?));
    }
    if let Some(prefix_and_port) = after.strip_prefix('/') {
        let (prefix_text, port_text) = prefix_and_port
            .split_once(':')
            .ok_or(CompileFailure::Form(NETWORK_FORM))?;
        if prefix_text.is_empty() || port_text.contains(':') || port_text.contains('/') {
            return Err(CompileFailure::Form(NETWORK_FORM));
        }
        let prefix_length = parse_decimal_u8(prefix_text)?;
        let port = parse_port(port_text)?;
        let address =
            NetworkAddress::cidr(address, prefix_length).map_err(CompileFailure::Resource)?;
        return Ok((address, port));
    }
    Err(CompileFailure::Form(NETWORK_FORM))
}

fn parse_host(host: &str) -> Result<NetworkAddress, CompileFailure> {
    if host.is_empty() || host.contains(':') || host.contains('[') || host.contains(']') {
        return Err(CompileFailure::Form(NETWORK_FORM));
    }
    if let Some((address_text, prefix_text)) = host.split_once('/') {
        if address_text.is_empty() || prefix_text.contains('/') {
            return Err(CompileFailure::Form(NETWORK_FORM));
        }
        let address: IpAddr = address_text
            .parse()
            .map_err(|_| CompileFailure::Form(NETWORK_FORM))?;
        let prefix_length = parse_decimal_u8(prefix_text)?;
        return NetworkAddress::cidr(address, prefix_length).map_err(CompileFailure::Resource);
    }
    let address: IpAddr = host
        .parse()
        .map_err(|_| CompileFailure::Form(NETWORK_FORM))?;
    Ok(NetworkAddress::ip(address))
}

fn parse_port(text: &str) -> Result<u16, CompileFailure> {
    if !is_decimal(text) {
        return Err(CompileFailure::Form(NETWORK_FORM));
    }
    text.parse::<u16>()
        .map_err(|_| CompileFailure::Form(NETWORK_FORM))
}

fn parse_decimal_u8(text: &str) -> Result<u8, CompileFailure> {
    if !is_decimal(text) {
        return Err(CompileFailure::Form(NETWORK_FORM));
    }
    text.parse::<u8>()
        .map_err(|_| CompileFailure::Form(NETWORK_FORM))
}

fn is_decimal(text: &str) -> bool {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    text.len() == 1 || !text.starts_with('0')
}

fn invalid_resource(
    field_path: String,
    value: &str,
    failure: CompileFailure,
) -> ContractCompileError {
    let expected = match failure {
        CompileFailure::Form(expected) => expected,
        CompileFailure::Resource(error) => expected_resource(error),
    };
    ContractCompileError::InvalidResource {
        field_path,
        value: show_value(value),
        expected,
    }
}

fn expected_resource(error: ResourceError) -> &'static str {
    match error {
        ResourceError::EscapesAnchor | ResourceError::ExecutableEscape => INSIDE_FORM,
        ResourceError::MisplacedRecursiveMarker => PATTERN_FORM,
        ResourceError::PrefixOutOfRange { .. } => PREFIX_FORM,
        ResourceError::EmptyFilePath
        | ResourceError::EmptyExecutableIdentity
        | ResourceError::EmbeddedNul
        | ResourceError::NotRelative
        | ResourceError::NotAbsolute => FILE_FORM,
    }
}

fn show_value(text: &str) -> String {
    let mut shown = String::new();
    for character in text.chars() {
        if shown.chars().count() == VALUE_LIMIT {
            shown.push_str("...");
            break;
        }
        if character.is_control() {
            shown.push('\u{FFFD}');
        } else {
            shown.push(character);
        }
    }
    shown
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        compile_contract, ContractCompileError, EXECUTABLE_FORM, FILE_FORM, INSIDE_FORM,
        NETWORK_FORM, PATTERN_FORM, PREFIX_FORM,
    };
    use crate::capability::{Action, Capability};
    use crate::contract::{
        parse_contract, AllowDenyRules, AuthoringResource, ContractDocument, ContractVersion,
        FilesystemContract, NetworkContract, ProcessContract,
    };
    use crate::policy::{Coverage, Decision, RuleEffect};
    use crate::resource::{
        ExecutableResource, FileResource, FilesystemAnchor, NetworkAddress, NetworkProtocol,
        NetworkResource, Resource,
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

    fn compile_yaml(yaml: &str) -> crate::policy::CompiledPolicy {
        let parsed = parse_contract(yaml).expect("parse");
        compile_contract(&parsed).expect("compile")
    }

    fn file_resource(rule: &crate::policy::Rule) -> &FileResource {
        match rule.capability().resource() {
            Resource::File(file) => file,
            other => panic!("expected a file resource, got {other:?}"),
        }
    }

    fn spec_yaml() -> &'static str {
        "\
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
"
    }

    #[test]
    fn anchors_compile_to_canonical_typed_resources() {
        let policy = compile_yaml(spec_yaml());
        let compiled = policy.rules();
        assert_eq!(compiled.len(), 5);

        assert_eq!(compiled[0].id().as_str(), "filesystem.read.allow[0]");
        assert_eq!(compiled[0].effect(), RuleEffect::Allow);
        assert_eq!(compiled[0].capability().action(), Action::FilesystemRead);
        let read_allow = file_resource(&compiled[0]);
        assert_eq!(read_allow.anchor(), FilesystemAnchor::Repo);
        assert_eq!(read_allow.file_path(), "src/**");
        assert!(read_allow.is_recursive());

        assert_eq!(compiled[1].id().as_str(), "filesystem.read.deny[0]");
        assert_eq!(compiled[1].effect(), RuleEffect::Deny);
        let read_deny = file_resource(&compiled[1]);
        assert_eq!(read_deny.anchor(), FilesystemAnchor::Home);
        assert_eq!(read_deny.file_path(), ".ssh/**");
        assert_ne!(read_deny.anchor(), FilesystemAnchor::Repo);

        assert_eq!(compiled[2].capability().action(), Action::FilesystemWrite);
        assert_eq!(file_resource(&compiled[2]).file_path(), "src/**");
        assert_eq!(file_resource(&compiled[2]).anchor(), FilesystemAnchor::Repo);

        assert_eq!(compiled[3].id().as_str(), "process.execute.allow[0]");
        assert_eq!(compiled[3].effect(), RuleEffect::Allow);
        match compiled[3].capability().resource() {
            Resource::Executable(executable) => {
                assert_eq!(executable.identity(), "/usr/bin/cargo");
            }
            other => panic!("expected an executable, got {other:?}"),
        }

        let endpoint = NetworkResource::new(
            NetworkProtocol::Tcp,
            NetworkAddress::cidr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24).expect("cidr"),
            443,
        );
        let connect = Capability::network_connect(endpoint);
        assert_eq!(compiled[4].id().as_str(), "network.connect.allow[0]");
        assert_eq!(compiled[4].effect(), RuleEffect::Allow);
        assert_eq!(compiled[4].capability(), &connect);
        let network_only = document(
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            rules(&["tcp://203.0.113.10/24:443"], &[]),
            AllowDenyRules::empty(),
        );
        let compiled = compile_contract(&network_only).expect("network");
        assert_eq!(compiled.rules().len(), 1);
        assert_eq!(compiled.rules()[0].capability(), &connect);
        match compiled.rules()[0].capability().resource() {
            Resource::Network(network) => {
                assert_eq!(network.protocol(), NetworkProtocol::Tcp);
                assert_eq!(network.port(), 443);
                match network.address() {
                    NetworkAddress::Cidr(cidr) => {
                        assert_eq!(cidr.prefix_length(), 24);
                        assert_eq!(cidr.address(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)));
                    }
                    other => panic!("expected a CIDR, got {other:?}"),
                }
            }
            other => panic!("expected a network resource, got {other:?}"),
        }
    }

    #[test]
    fn equivalent_authoring_paths_share_one_canonical_resource() {
        let compiled = compile_contract(&document(
            rules(
                &[
                    "./src/../src/main.rs",
                    "./src/./lib.rs",
                    "src//lib.rs",
                    "~/.ssh/./config",
                    "/etc/./ssl/certs/**",
                    ".\\src\\main.rs",
                ],
                &[],
            ),
            AllowDenyRules::empty(),
            rules(&["/usr/bin/./cargo", "bin/../cargo"], &[]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ))
        .expect("compile");
        let rules = compiled.rules();
        assert_eq!(file_resource(&rules[0]).file_path(), "src/main.rs");
        assert_eq!(file_resource(&rules[0]).anchor(), FilesystemAnchor::Repo);
        assert_eq!(
            file_resource(&rules[1]),
            &FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file")
        );
        assert_eq!(file_resource(&rules[2]).file_path(), "src/lib.rs");
        assert_eq!(file_resource(&rules[3]).anchor(), FilesystemAnchor::Home);
        assert_eq!(file_resource(&rules[3]).file_path(), ".ssh/config");
        assert_eq!(
            file_resource(&rules[4]).anchor(),
            FilesystemAnchor::Absolute
        );
        assert_eq!(file_resource(&rules[4]).file_path(), "/etc/ssl/certs/**");
        assert_eq!(file_resource(&rules[5]).file_path(), "src/main.rs");
        match rules[6].capability().resource() {
            Resource::Executable(executable) => assert_eq!(executable.identity(), "/usr/bin/cargo"),
            other => panic!("expected an executable, got {other:?}"),
        }
        match rules[7].capability().resource() {
            Resource::Executable(executable) => assert_eq!(executable.identity(), "cargo"),
            other => panic!("expected an executable, got {other:?}"),
        }
    }

    #[test]
    fn compilation_does_not_widen_patterns_or_cross_anchors() {
        let compiled = compile_contract(&document(
            rules(
                &["./src/**", "./src", "~", "~/", "/etc/hosts"],
                &["~/.ssh/**"],
            ),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            rules(&["tcp://10.1.2.3/8:443", "tcp://10.1.2.3:443"], &[]),
            AllowDenyRules::empty(),
        ))
        .expect("compile");
        let rules = compiled.rules();
        assert_eq!(file_resource(&rules[0]).file_path(), "src/**");
        assert_ne!(file_resource(&rules[0]).file_path(), "**");
        assert_eq!(file_resource(&rules[1]).file_path(), "src");
        assert!(!file_resource(&rules[1]).is_recursive());
        assert_eq!(file_resource(&rules[2]).anchor(), FilesystemAnchor::Home);
        assert_eq!(file_resource(&rules[2]).file_path(), ".");
        assert_eq!(file_resource(&rules[3]).file_path(), ".");
        assert_eq!(
            file_resource(&rules[4]).anchor(),
            FilesystemAnchor::Absolute
        );
        assert_eq!(file_resource(&rules[4]).file_path(), "/etc/hosts");
        assert_eq!(file_resource(&rules[5]).file_path(), ".ssh/**");
        assert_ne!(file_resource(&rules[5]).file_path(), "**");
        assert!(!file_resource(&rules[0]).contains(file_resource(&rules[5])));

        match rules[6].capability().resource() {
            Resource::Network(network) => match network.address() {
                NetworkAddress::Cidr(cidr) => {
                    assert_eq!(cidr.prefix_length(), 8);
                    assert_eq!(cidr.address(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
                }
                other => panic!("expected a CIDR, got {other:?}"),
            },
            other => panic!("expected a network resource, got {other:?}"),
        }
        match rules[7].capability().resource() {
            Resource::Network(network) => {
                assert_eq!(
                    network.address(),
                    NetworkAddress::ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)))
                );
            }
            other => panic!("expected a network resource, got {other:?}"),
        }
        assert_ne!(
            rules[6].capability().resource(),
            rules[7].capability().resource()
        );
    }

    #[test]
    fn invalid_action_resource_combinations_fail_compilation() {
        let cases = [
            (
                document(
                    rules(&["tcp://203.0.113.0:443"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[0]",
                "tcp://203.0.113.0:443",
                FILE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    rules(&[], &["udp://127.0.0.1:53"]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.write.deny[0]",
                "udp://127.0.0.1:53",
                FILE_FORM,
            ),
            (
                document(
                    rules(&["./src/**", "tcp://127.0.0.1:80"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[1]",
                "tcp://127.0.0.1:80",
                FILE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["./src/**"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "process.execute.allow[0]",
                "./src/**",
                EXECUTABLE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["tcp://127.0.0.1:80"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "process.execute.allow[0]",
                "tcp://127.0.0.1:80",
                EXECUTABLE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["~/.local/bin/tool"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "process.execute.allow[0]",
                "~/.local/bin/tool",
                EXECUTABLE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["./src/**"], &[]),
                    AllowDenyRules::empty(),
                ),
                "network.connect.allow[0]",
                "./src/**",
                NETWORK_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["github.com"], &[]),
                    AllowDenyRules::empty(),
                ),
                "network.connect.allow[0]",
                "github.com",
                NETWORK_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["tcp://github.com:443"], &[]),
                    AllowDenyRules::empty(),
                ),
                "network.connect.allow[0]",
                "tcp://github.com:443",
                NETWORK_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["/usr/bin/cargo"], &[]),
                ),
                "network.listen.allow[0]",
                "/usr/bin/cargo",
                NETWORK_FORM,
            ),
            (
                document(
                    rules(&["./src/*"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[0]",
                "./src/*",
                PATTERN_FORM,
            ),
            (
                document(
                    rules(&["../secret"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[0]",
                "../secret",
                INSIDE_FORM,
            ),
            (
                document(
                    rules(&["~luca/.ssh/**"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[0]",
                "~luca/.ssh/**",
                FILE_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["tcp://10.0.0.0/33:80"], &[]),
                    AllowDenyRules::empty(),
                ),
                "network.connect.allow[0]",
                "tcp://10.0.0.0/33:80",
                PREFIX_FORM,
            ),
            (
                document(
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    rules(&["TCP://127.0.0.1:80"], &[]),
                    AllowDenyRules::empty(),
                ),
                "network.connect.allow[0]",
                "TCP://127.0.0.1:80",
                NETWORK_FORM,
            ),
            (
                document(
                    rules(&["temp://cache/out"], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ),
                "filesystem.read.allow[0]",
                "temp://cache/out",
                FILE_FORM,
            ),
        ];

        for (document, field_path, value, expected) in cases {
            let error = compile_contract(&document).expect_err(field_path);
            match &error {
                ContractCompileError::InvalidResource {
                    field_path: got_path,
                    value: got_value,
                    expected: got_expected,
                } => {
                    assert_eq!(got_path, field_path);
                    assert_eq!(got_value, value);
                    assert_eq!(*got_expected, expected);
                }
                other => panic!("expected an invalid resource, got {other:?}"),
            }
            let shown = error.to_string();
            assert!(shown.contains(field_path));
            assert!(shown.contains(value));
            assert!(shown.contains(expected));
            assert!(!shown.contains('\u{1b}'));
        }
    }

    #[test]
    fn a_filesystem_path_stays_a_file_capability() {
        let compiled = compile_contract(&document(
            rules(&["/usr/bin/cargo"], &[]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ))
        .expect("compile");
        assert_eq!(
            compiled.rules()[0].capability().action(),
            Action::FilesystemRead
        );
        assert_eq!(
            file_resource(&compiled.rules()[0]).anchor(),
            FilesystemAnchor::Absolute
        );
        assert_eq!(
            file_resource(&compiled.rules()[0]).file_path(),
            "/usr/bin/cargo"
        );
    }

    #[test]
    fn deny_and_allow_stay_distinct_and_keep_semantics() {
        let yaml = "\
version: 1
filesystem:
  read:
    allow:
      - ./src/**
    deny:
      - ./src/secret.env
      - ~/.ssh/**
";
        let policy = compile_yaml(yaml);
        assert_eq!(policy.rules()[0].effect(), RuleEffect::Allow);
        assert_eq!(policy.rules()[1].effect(), RuleEffect::Deny);
        assert_eq!(policy.rules()[2].effect(), RuleEffect::Deny);
        assert_ne!(policy.rules()[0].effect(), policy.rules()[1].effect());

        let secret = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/secret.env").expect("file"),
        );
        let source = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file"),
        );
        let ssh = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Home, ".ssh/config").expect("file"),
        );
        let missing = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "docs/readme.md").expect("file"),
        );

        let denied = policy.evaluate(&secret, Coverage::Complete);
        assert_eq!(denied.decision(), Decision::Denied);
        assert_eq!(denied.matched_rules().len(), 1);
        assert_eq!(
            denied.matched_rules()[0].id().as_str(),
            "filesystem.read.deny[0]"
        );
        assert_eq!(denied.matched_rules()[0].effect(), RuleEffect::Deny);
        assert_ne!(denied.decision(), Decision::Allowed);
        assert_ne!(denied.decision(), Decision::Unknown);

        let allowed = policy.evaluate(&source, Coverage::Complete);
        assert_eq!(allowed.decision(), Decision::Allowed);
        assert_eq!(
            allowed.matched_rules()[0].id().as_str(),
            "filesystem.read.allow[0]"
        );
        assert_eq!(allowed.matched_rules()[0].effect(), RuleEffect::Allow);

        let ssh_denied = policy.evaluate(&ssh, Coverage::Complete);
        assert_eq!(ssh_denied.decision(), Decision::Denied);
        assert_eq!(
            ssh_denied.matched_rules()[0].id().as_str(),
            "filesystem.read.deny[1]"
        );

        let unknown = policy.evaluate(&missing, Coverage::Complete);
        assert_eq!(unknown.decision(), Decision::Unknown);
        assert_ne!(unknown.decision(), Decision::Denied);

        let same_text = compile_contract(&document(
            rules(&["./src/**"], &["./src/**"]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ))
        .expect("both effects");
        assert_eq!(same_text.rules()[0].effect(), RuleEffect::Allow);
        assert_eq!(same_text.rules()[1].effect(), RuleEffect::Deny);
        assert_eq!(
            same_text.evaluate(&source, Coverage::Complete).decision(),
            Decision::Denied
        );
    }

    #[test]
    fn empty_lists_stay_empty_and_author_order_is_kept() {
        let empty = compile_yaml("version: 1\n");
        assert!(empty.rules().is_empty());
        let read = Capability::filesystem_read(
            FileResource::new(FilesystemAnchor::Repo, "src/lib.rs").expect("file"),
        );
        assert_eq!(
            empty.evaluate(&read, Coverage::Complete).decision(),
            Decision::Unknown
        );

        let ordered = compile_contract(&document(
            rules(&["./b", "./a"], &["./d", "./c"]),
            AllowDenyRules::empty(),
            rules(&[], &["/usr/bin/curl"]),
            AllowDenyRules::empty(),
            rules(&["udp://[2001:db8::1]/32:53"], &[]),
        ))
        .expect("ordered");
        let ids: Vec<_> = ordered
            .rules()
            .iter()
            .map(|rule| rule.id().as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "filesystem.read.allow[0]",
                "filesystem.read.allow[1]",
                "filesystem.read.deny[0]",
                "filesystem.read.deny[1]",
                "process.execute.deny[0]",
                "network.listen.allow[0]",
            ]
        );
        assert_eq!(file_resource(&ordered.rules()[0]).file_path(), "b");
        assert_eq!(file_resource(&ordered.rules()[1]).file_path(), "a");
        assert_eq!(ordered.rules()[4].effect(), RuleEffect::Deny);
        match ordered.rules()[4].capability().resource() {
            Resource::Executable(executable) => assert_eq!(executable.identity(), "/usr/bin/curl"),
            other => panic!("expected an executable, got {other:?}"),
        }
        match ordered.rules()[5].capability().resource() {
            Resource::Network(network) => {
                assert_eq!(
                    ordered.rules()[5].capability().action(),
                    Action::NetworkListen
                );
                assert_eq!(network.protocol(), NetworkProtocol::Udp);
                assert_eq!(network.port(), 53);
                match network.address() {
                    NetworkAddress::Cidr(cidr) => {
                        assert_eq!(cidr.prefix_length(), 32);
                        assert_eq!(
                            cidr.address(),
                            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))
                        );
                    }
                    other => panic!("expected a CIDR, got {other:?}"),
                }
            }
            other => panic!("expected a network resource, got {other:?}"),
        }

        let again = compile_contract(&document(
            rules(&["./b", "./a"], &["./d", "./c"]),
            AllowDenyRules::empty(),
            rules(&[], &["/usr/bin/curl"]),
            AllowDenyRules::empty(),
            rules(&["udp://[2001:db8::1]/32:53"], &[]),
        ))
        .expect("again");
        assert_eq!(ordered, again);
    }

    #[test]
    fn ipv6_host_and_misplaced_marker_fail_closed() {
        let host = compile_contract(&document(
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            rules(&["tcp://[::1]:443"], &[]),
            AllowDenyRules::empty(),
        ))
        .expect("ipv6");
        match host.rules()[0].capability().resource() {
            Resource::Network(network) => {
                assert_eq!(
                    network.address(),
                    NetworkAddress::ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                );
                assert_eq!(network.port(), 443);
            }
            other => panic!("expected a network resource, got {other:?}"),
        }

        let marker = compile_contract(&document(
            rules(&["./src/**/lib.rs"], &[]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ))
        .expect_err("marker");
        match marker {
            ContractCompileError::InvalidResource { expected, .. } => {
                assert_eq!(expected, PATTERN_FORM);
            }
            other => panic!("expected an invalid resource, got {other:?}"),
        }

        let unbracketed = compile_contract(&document(
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            rules(&["tcp://::1:443"], &[]),
            AllowDenyRules::empty(),
        ))
        .expect_err("unbracketed ipv6");
        match unbracketed {
            ContractCompileError::InvalidResource { expected, .. } => {
                assert_eq!(expected, NETWORK_FORM);
            }
            other => panic!("expected an invalid resource, got {other:?}"),
        }
    }

    #[test]
    fn canonical_file_anchors_are_idempotent() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let segment = prop_oneof![Just("src"), Just("domain"), Just("lib.rs"), Just("a")];
        let parts = proptest::collection::vec(segment, 0..=3);
        runner
            .run(&(parts, any::<bool>()), |(parts, recursive)| {
                let body = if parts.is_empty() {
                    if recursive {
                        "**".to_owned()
                    } else {
                        ".".to_owned()
                    }
                } else {
                    let joined = parts.join("/");
                    if recursive {
                        format!("{joined}/**")
                    } else {
                        joined
                    }
                };
                for (anchor, authoring) in [
                    (FilesystemAnchor::Repo, format!("./{body}")),
                    (FilesystemAnchor::Home, format!("~/{body}")),
                    (FilesystemAnchor::Absolute, format!("/{body}")),
                ] {
                    let compiled = compile_contract(&document(
                        rules(&[&authoring], &[]),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                    ))
                    .expect("compile");
                    let file = file_resource(&compiled.rules()[0]);
                    let direct = FileResource::new(anchor, file.file_path()).expect("direct");
                    prop_assert_eq!(file, &direct);
                    prop_assert_eq!(file.anchor(), anchor);
                    let again = compile_contract(&document(
                        rules(&[&authoring], &[]),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                        AllowDenyRules::empty(),
                    ))
                    .expect("again");
                    prop_assert_eq!(compiled.rules(), again.rules());
                    if !recursive {
                        prop_assert!(!file.is_recursive());
                    }
                }
                let starred = format!("./{body}/*");
                let rejected = compile_contract(&document(
                    rules(&[&starred], &[]),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                    AllowDenyRules::empty(),
                ));
                prop_assert!(rejected.is_err());
                Ok(())
            })
            .expect("anchors");
    }

    #[test]
    fn executable_identity_matches_the_typed_constructor() {
        let compiled = compile_contract(&document(
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            rules(&["cargo", "./cargo"], &[]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ))
        .expect("compile");
        let expected = ExecutableResource::new("cargo").expect("executable");
        for rule in compiled.rules() {
            match rule.capability().resource() {
                Resource::Executable(executable) => assert_eq!(executable, &expected),
                other => panic!("expected an executable, got {other:?}"),
            }
        }
    }
}
