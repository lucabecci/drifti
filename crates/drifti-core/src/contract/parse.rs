// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parse one contract document from YAML text.
//!
//! Version 1 is the only version that becomes a [`ContractDocument`]. Any
//! other version fails before the rest of the document is treated as version
//! 1. Aliases, anchors, and tags are rejected rather than expanded.

use std::borrow::Cow;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use saphyr_parser::{Event, Parser, ScanError, Span, StrInput, Tag};

use super::{
    AllowDenyRules, AuthoringResource, ContractDocument, ContractDocumentError, ContractVersion,
    FilesystemContract, NetworkContract, ProcessContract, ALLOW_KEY, CONNECT_KEY, DENY_KEY,
    EXECUTE_KEY, FILESYSTEM_KEY, LISTEN_KEY, NETWORK_KEY, PROCESS_KEY, READ_KEY, VERSION_KEY,
    WRITE_KEY,
};

const VALUE_LIMIT: usize = 80;

/// Where a parse failure was found. Lines and columns are 1-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLocation {
    line: usize,
    column: usize,
}

impl SourceLocation {
    fn new(span: Span) -> Self {
        Self {
            line: span.start.line(),
            column: span.start.col() + 1,
        }
    }

    /// 1-based line.
    #[must_use]
    pub fn line(self) -> usize {
        self.line
    }

    /// 1-based column.
    #[must_use]
    pub fn column(self) -> usize {
        self.column
    }
}

/// Failure while reading a contract document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractParseError {
    /// The text is not a single YAML document.
    Syntax {
        /// Parser message.
        message: String,
        /// Where parsing stopped.
        location: SourceLocation,
    },
    /// `version` was absent.
    MissingVersion {
        /// Where the document mapping starts.
        location: SourceLocation,
    },
    /// The version is a whole number other than 1.
    UnsupportedVersion {
        /// The version that was written.
        version: u64,
        /// Where the version scalar starts.
        location: SourceLocation,
    },
    /// The version is not a whole number.
    InvalidVersion {
        /// The version text, bounded for display.
        value: String,
        /// Where the version scalar starts.
        location: SourceLocation,
    },
    /// A top-level key is not a version-1 capability domain.
    UnknownDomain {
        /// The rejected key.
        name: String,
        /// Where the key starts.
        location: SourceLocation,
    },
    /// A key inside a known section is not part of version 1.
    UnknownField {
        /// Section path, such as `filesystem`.
        path: String,
        /// The rejected key.
        field: String,
        /// Where the key starts.
        location: SourceLocation,
    },
    /// The same key was written twice.
    DuplicateField {
        /// Section path.
        path: String,
        /// The repeated key.
        field: String,
        /// Where the second key starts.
        location: SourceLocation,
    },
    /// A resource entry cannot be stored.
    InvalidResource {
        /// Field path, such as `filesystem.read.allow[0]`.
        path: String,
        /// The rejected text, bounded for display.
        value: String,
        /// What the field should contain.
        expected: &'static str,
        /// Where the entry starts.
        location: SourceLocation,
    },
    /// The document uses an alias, an anchor, or a tag.
    YamlFeature {
        /// `alias`, `anchor`, or `tag`.
        feature: &'static str,
        /// Where the feature starts.
        location: SourceLocation,
    },
    /// More than one YAML document was present.
    MultipleDocuments {
        /// Where the extra document starts.
        location: SourceLocation,
    },
    /// A field had a YAML shape this schema does not use.
    UnexpectedStructure {
        /// Field path.
        path: String,
        /// What the field should contain.
        expected: &'static str,
        /// Where the value starts.
        location: SourceLocation,
    },
}

impl Display for ContractParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { message, location } => write!(
                formatter,
                "invalid contract document at {}:{}: {message}",
                location.line(),
                location.column()
            ),
            Self::MissingVersion { location } => write!(
                formatter,
                "missing contract version at {}:{}; expected version 1",
                location.line(),
                location.column()
            ),
            Self::UnsupportedVersion { version, location } => write!(
                formatter,
                "unsupported contract version {version} at {}:{}; supported version is 1",
                location.line(),
                location.column()
            ),
            Self::InvalidVersion { value, location } => write!(
                formatter,
                "invalid contract version `{value}` at {}:{}; expected version 1",
                location.line(),
                location.column()
            ),
            Self::UnknownDomain { name, location } => write!(
                formatter,
                "unknown capability domain `{name}` at {}:{}; expected filesystem, process, or network",
                location.line(),
                location.column()
            ),
            Self::UnknownField {
                path,
                field,
                location,
            } => write!(
                formatter,
                "unknown field `{field}` at {path} at {}:{}; that field is not part of version 1",
                location.line(),
                location.column()
            ),
            Self::DuplicateField {
                path,
                field,
                location,
            } => write!(
                formatter,
                "duplicate field `{field}` at {path} at {}:{}",
                location.line(),
                location.column()
            ),
            Self::InvalidResource {
                path,
                value,
                expected,
                location,
            } => write!(
                formatter,
                "invalid resource `{value}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::YamlFeature { feature, location } => write!(
                formatter,
                "contract documents reject YAML {feature}s at {}:{}",
                location.line(),
                location.column()
            ),
            Self::MultipleDocuments { location } => write!(
                formatter,
                "contract document contains more than one YAML document at {}:{}",
                location.line(),
                location.column()
            ),
            Self::UnexpectedStructure {
                path,
                expected,
                location,
            } => write!(
                formatter,
                "unexpected value at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
        }
    }
}

impl Error for ContractParseError {}

/// Reads one version-1 contract document.
///
/// A version other than 1 does not produce a document. Missing sections become
/// empty allow and deny lists. Unknown domains and unknown fields fail.
pub fn parse_contract(yaml: &str) -> Result<ContractDocument, ContractParseError> {
    let node = load_document(yaml)?;
    document_from_node(node)
}

enum Node {
    Scalar {
        text: String,
        span: Span,
    },
    Sequence {
        items: Vec<Node>,
        span: Span,
    },
    Mapping {
        entries: Vec<(String, Node, Span)>,
        span: Span,
    },
}

struct Stream<'input> {
    parser: Parser<'input, StrInput<'input>>,
}

impl<'input> Stream<'input> {
    fn new(yaml: &'input str) -> Self {
        Self {
            parser: Parser::new_from_str(yaml),
        }
    }

    fn next_event(&mut self) -> Result<(Event<'input>, Span), ContractParseError> {
        loop {
            match self.parser.next_event() {
                Some(Ok((Event::Nothing, _))) => continue,
                Some(Ok(event)) => return Ok(event),
                Some(Err(error)) => return Err(syntax(error)),
                None => {
                    return Err(ContractParseError::Syntax {
                        message: "the document ended early".to_owned(),
                        location: SourceLocation { line: 1, column: 1 },
                    });
                }
            }
        }
    }
}

fn load_document(yaml: &str) -> Result<Node, ContractParseError> {
    let mut stream = Stream::new(yaml);
    expect_event(&mut stream, "stream start", |event| {
        matches!(event, Event::StreamStart)
    })?;
    let (start, start_span) = stream.next_event()?;
    if !matches!(start, Event::DocumentStart(_)) {
        return Err(unexpected("a YAML document", start_span));
    }
    let (event, span) = stream.next_event()?;
    if matches!(event, Event::DocumentEnd | Event::StreamEnd) {
        return Err(ContractParseError::MissingVersion {
            location: SourceLocation::new(start_span),
        });
    }
    let node = parse_node(&mut stream, event, span, "document")?;
    expect_event(&mut stream, "document end", |event| {
        matches!(event, Event::DocumentEnd)
    })?;
    let (after, after_span) = stream.next_event()?;
    if matches!(after, Event::DocumentStart(_)) {
        return Err(ContractParseError::MultipleDocuments {
            location: SourceLocation::new(after_span),
        });
    }
    if !matches!(after, Event::StreamEnd) {
        return Err(unexpected("the end of the document", after_span));
    }
    Ok(node)
}

fn expect_event<'input>(
    stream: &mut Stream<'input>,
    expected: &'static str,
    matches_event: impl FnOnce(&Event<'input>) -> bool,
) -> Result<Span, ContractParseError> {
    let (event, span) = stream.next_event()?;
    if matches_event(&event) {
        Ok(span)
    } else {
        Err(unexpected(expected, span))
    }
}

fn parse_node(
    stream: &mut Stream<'_>,
    event: Event<'_>,
    span: Span,
    path: &str,
) -> Result<Node, ContractParseError> {
    match event {
        Event::Alias(_) => Err(ContractParseError::YamlFeature {
            feature: "alias",
            location: SourceLocation::new(span),
        }),
        Event::Scalar(text, _, anchor, tag) => {
            reject_decoration(anchor, tag.as_ref(), span)?;
            Ok(Node::Scalar {
                text: text.into_owned(),
                span,
            })
        }
        Event::SequenceStart(anchor, tag) => {
            reject_decoration(anchor, tag.as_ref(), span)?;
            let mut items = Vec::new();
            loop {
                let (event, item_span) = stream.next_event()?;
                if matches!(event, Event::SequenceEnd) {
                    break;
                }
                items.push(parse_node(stream, event, item_span, path)?);
            }
            Ok(Node::Sequence { items, span })
        }
        Event::MappingStart(anchor, tag) => {
            reject_decoration(anchor, tag.as_ref(), span)?;
            let mut entries = Vec::new();
            loop {
                let (event, key_span) = stream.next_event()?;
                if matches!(event, Event::MappingEnd) {
                    break;
                }
                let key = match parse_node(stream, event, key_span, path)? {
                    Node::Scalar { text, span } => (text, span),
                    Node::Sequence { span, .. } | Node::Mapping { span, .. } => {
                        return Err(unexpected("a field name", span));
                    }
                };
                if entries.iter().any(|(existing, _, _)| existing == &key.0) {
                    return Err(ContractParseError::DuplicateField {
                        path: path.to_owned(),
                        field: show_value(&key.0),
                        location: SourceLocation::new(key.1),
                    });
                }
                let (value_event, value_span) = stream.next_event()?;
                let value = parse_node(stream, value_event, value_span, &child_path(path, &key.0))?;
                entries.push((key.0, value, key.1));
            }
            Ok(Node::Mapping { entries, span })
        }
        Event::Nothing
        | Event::StreamStart
        | Event::StreamEnd
        | Event::DocumentStart(_)
        | Event::DocumentEnd
        | Event::SequenceEnd
        | Event::MappingEnd => Err(unexpected("a value", span)),
    }
}

fn reject_decoration(
    anchor: usize,
    tag: Option<&Cow<'_, Tag>>,
    span: Span,
) -> Result<(), ContractParseError> {
    if anchor > 0 {
        return Err(ContractParseError::YamlFeature {
            feature: "anchor",
            location: SourceLocation::new(span),
        });
    }
    if tag.is_some() {
        return Err(ContractParseError::YamlFeature {
            feature: "tag",
            location: SourceLocation::new(span),
        });
    }
    Ok(())
}

fn document_from_node(node: Node) -> Result<ContractDocument, ContractParseError> {
    let Node::Mapping { entries, span } = node else {
        return Err(ContractParseError::UnexpectedStructure {
            path: VERSION_KEY.to_owned(),
            expected: "a mapping",
            location: node_location(&node),
        });
    };
    let version = require_version(&entries, span)?;
    let mut filesystem = None;
    let mut process = None;
    let mut network = None;
    for (key, value, key_span) in &entries {
        match key.as_str() {
            VERSION_KEY => {}
            FILESYSTEM_KEY => filesystem = Some(filesystem_section(value)?),
            PROCESS_KEY => process = Some(process_section(value)?),
            NETWORK_KEY => network = Some(network_section(value)?),
            _ => {
                return Err(ContractParseError::UnknownDomain {
                    name: show_value(key),
                    location: SourceLocation::new(*key_span),
                });
            }
        }
    }
    Ok(ContractDocument::new(
        version,
        filesystem.unwrap_or_else(|| {
            FilesystemContract::new(AllowDenyRules::empty(), AllowDenyRules::empty())
        }),
        process.unwrap_or_else(|| ProcessContract::new(AllowDenyRules::empty())),
        network.unwrap_or_else(|| {
            NetworkContract::new(AllowDenyRules::empty(), AllowDenyRules::empty())
        }),
    ))
}

fn require_version(
    entries: &[(String, Node, Span)],
    document: Span,
) -> Result<ContractVersion, ContractParseError> {
    let Some((_, value, _)) = entries.iter().find(|(key, _, _)| key == VERSION_KEY) else {
        return Err(ContractParseError::MissingVersion {
            location: SourceLocation::new(document),
        });
    };
    let Node::Scalar { text, span } = value else {
        return Err(ContractParseError::InvalidVersion {
            value: show_value(&node_summary(value)),
            location: node_location(value),
        });
    };
    if text == "1" {
        return Ok(ContractVersion::V1);
    }
    if !text.is_empty() && text.chars().all(|character| character.is_ascii_digit()) {
        if let Ok(version) = text.parse::<u64>() {
            if version != 1 {
                return Err(ContractParseError::UnsupportedVersion {
                    version,
                    location: SourceLocation::new(*span),
                });
            }
        }
    }
    Err(ContractParseError::InvalidVersion {
        value: show_value(text),
        location: SourceLocation::new(*span),
    })
}

fn filesystem_section(node: &Node) -> Result<FilesystemContract, ContractParseError> {
    let entries = mapping_entries(node, FILESYSTEM_KEY)?;
    let mut read = None;
    let mut write = None;
    for (key, value, key_span) in entries {
        match key.as_str() {
            READ_KEY => read = Some(action_rules(value, FILESYSTEM_KEY, READ_KEY)?),
            WRITE_KEY => write = Some(action_rules(value, FILESYSTEM_KEY, WRITE_KEY)?),
            _ => {
                return Err(unknown_field(FILESYSTEM_KEY, key, *key_span));
            }
        }
    }
    Ok(FilesystemContract::new(
        read.unwrap_or_else(AllowDenyRules::empty),
        write.unwrap_or_else(AllowDenyRules::empty),
    ))
}

fn process_section(node: &Node) -> Result<ProcessContract, ContractParseError> {
    let entries = mapping_entries(node, PROCESS_KEY)?;
    let mut execute = None;
    for (key, value, key_span) in entries {
        match key.as_str() {
            EXECUTE_KEY => execute = Some(action_rules(value, PROCESS_KEY, EXECUTE_KEY)?),
            _ => return Err(unknown_field(PROCESS_KEY, key, *key_span)),
        }
    }
    Ok(ProcessContract::new(
        execute.unwrap_or_else(AllowDenyRules::empty),
    ))
}

fn network_section(node: &Node) -> Result<NetworkContract, ContractParseError> {
    let entries = mapping_entries(node, NETWORK_KEY)?;
    let mut connect = None;
    let mut listen = None;
    for (key, value, key_span) in entries {
        match key.as_str() {
            CONNECT_KEY => connect = Some(action_rules(value, NETWORK_KEY, CONNECT_KEY)?),
            LISTEN_KEY => listen = Some(action_rules(value, NETWORK_KEY, LISTEN_KEY)?),
            _ => return Err(unknown_field(NETWORK_KEY, key, *key_span)),
        }
    }
    Ok(NetworkContract::new(
        connect.unwrap_or_else(AllowDenyRules::empty),
        listen.unwrap_or_else(AllowDenyRules::empty),
    ))
}

fn action_rules(
    node: &Node,
    domain: &str,
    action: &str,
) -> Result<AllowDenyRules, ContractParseError> {
    let action_path = format!("{domain}.{action}");
    let entries = mapping_entries(node, &action_path)?;
    let mut allow = None;
    let mut deny = None;
    for (key, value, key_span) in entries {
        match key.as_str() {
            ALLOW_KEY => {
                allow = Some(resource_list(value, &format!("{action_path}.{ALLOW_KEY}"))?);
            }
            DENY_KEY => {
                deny = Some(resource_list(value, &format!("{action_path}.{DENY_KEY}"))?);
            }
            _ => return Err(unknown_field(&action_path, key, *key_span)),
        }
    }
    Ok(AllowDenyRules::new(
        allow.unwrap_or_default(),
        deny.unwrap_or_default(),
    ))
}

fn resource_list(node: &Node, path: &str) -> Result<Vec<AuthoringResource>, ContractParseError> {
    let Node::Sequence { items, .. } = node else {
        return Err(ContractParseError::UnexpectedStructure {
            path: path.to_owned(),
            expected: "an explicit list of resource strings",
            location: node_location(node),
        });
    };
    let mut resources = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        let Node::Scalar { text, span } = item else {
            return Err(ContractParseError::InvalidResource {
                path: item_path,
                value: show_value(&node_summary(item)),
                expected: "a resource string",
                location: node_location(item),
            });
        };
        match AuthoringResource::new(text.clone()) {
            Ok(resource) => resources.push(resource),
            Err(error) => {
                return Err(ContractParseError::InvalidResource {
                    path: item_path,
                    value: show_value(text),
                    expected: expected_resource(error),
                    location: SourceLocation::new(*span),
                });
            }
        }
    }
    Ok(resources)
}

fn mapping_entries<'node>(
    node: &'node Node,
    path: &str,
) -> Result<&'node [(String, Node, Span)], ContractParseError> {
    match node {
        Node::Mapping { entries, .. } => Ok(entries),
        _ => Err(ContractParseError::UnexpectedStructure {
            path: path.to_owned(),
            expected: "a mapping",
            location: node_location(node),
        }),
    }
}

fn child_path(parent: &str, key: &str) -> String {
    if parent == "document" {
        key.to_owned()
    } else {
        format!("{parent}.{key}")
    }
}

fn unknown_field(path: &str, field: &str, span: Span) -> ContractParseError {
    ContractParseError::UnknownField {
        path: path.to_owned(),
        field: show_value(field),
        location: SourceLocation::new(span),
    }
}

fn expected_resource(error: ContractDocumentError) -> &'static str {
    match error {
        ContractDocumentError::EmptyResource => "a non-empty resource pattern",
        ContractDocumentError::EmbeddedNul => "a resource pattern without a NUL byte",
    }
}

fn node_location(node: &Node) -> SourceLocation {
    let span = match node {
        Node::Scalar { span, .. } | Node::Sequence { span, .. } | Node::Mapping { span, .. } => {
            *span
        }
    };
    SourceLocation::new(span)
}

fn node_summary(node: &Node) -> String {
    match node {
        Node::Scalar { text, .. } => text.clone(),
        Node::Sequence { .. } => "a list".to_owned(),
        Node::Mapping { .. } => "a mapping".to_owned(),
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

fn syntax(error: ScanError) -> ContractParseError {
    let location = SourceLocation {
        line: error.marker().line(),
        column: error.marker().col() + 1,
    };
    if error.info().contains("unknown anchor") {
        return ContractParseError::YamlFeature {
            feature: "alias",
            location,
        };
    }
    ContractParseError::Syntax {
        message: error.to_string(),
        location,
    }
}

fn unexpected(expected: &'static str, span: Span) -> ContractParseError {
    ContractParseError::UnexpectedStructure {
        path: String::new(),
        expected,
        location: SourceLocation::new(span),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_contract, ContractParseError};
    use crate::contract::{
        AllowDenyRules, AuthoringResource, ContractDocument, ContractVersion, FilesystemContract,
        NetworkContract, ProcessContract,
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

    #[test]
    fn valid_version_1_parses_the_spec_example() {
        let yaml = "\
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
        let document = parse_contract(yaml).expect("version 1");
        let expected = ContractDocument::new(
            ContractVersion::V1,
            FilesystemContract::new(
                rules(&["./src/**"], &["~/.ssh/**"]),
                rules(&["./src/**"], &[]),
            ),
            ProcessContract::new(rules(&["/usr/bin/cargo"], &[])),
            NetworkContract::new(
                rules(&["tcp://203.0.113.0/24:443"], &[]),
                AllowDenyRules::empty(),
            ),
        );
        assert_eq!(document, expected);
        assert_eq!(document.version().get(), 1);
    }

    #[test]
    fn omitted_sections_are_empty_and_listen_and_deny_parse() {
        let yaml = "\
version: 1
process:
  execute:
    deny:
      - /usr/bin/curl
network:
  listen:
    allow:
      - tcp://127.0.0.1:80
    deny:
      - tcp://0.0.0.0:22
";
        let document = parse_contract(yaml).expect("partial document");
        assert!(document.filesystem().read().allow().is_empty());
        assert!(document.filesystem().write().deny().is_empty());
        assert!(document.process().execute().allow().is_empty());
        assert_eq!(
            document.process().execute().deny()[0].as_str(),
            "/usr/bin/curl"
        );
        assert!(document.network().connect().allow().is_empty());
        assert_eq!(
            document.network().listen().allow()[0].as_str(),
            "tcp://127.0.0.1:80"
        );
        assert_eq!(
            document.network().listen().deny()[0].as_str(),
            "tcp://0.0.0.0:22"
        );
    }

    #[test]
    fn unsupported_versions_fail_and_are_not_read_as_version_1() {
        for yaml in [
            "version: 2\n",
            "version: 0\n",
            "version: 99\nfilesystem:\n  read:\n    allow:\n      - ./src/**\n",
        ] {
            let error = parse_contract(yaml).expect_err("unsupported version");
            match &error {
                ContractParseError::UnsupportedVersion { version, .. } => {
                    assert_ne!(*version, 1);
                }
                other => panic!("expected unsupported version, got {other:?}"),
            }
            let message = error.to_string();
            assert!(message.contains("supported version is 1"));
            assert!(!message.contains("interpreted"));
        }
        match parse_contract("version: 2\n").expect_err("version 2") {
            ContractParseError::UnsupportedVersion { version: 2, .. } => {}
            other => panic!("expected version 2, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_or_non_numeric_version_fails() {
        assert!(matches!(
            parse_contract("filesystem:\n  read:\n    allow: []\n"),
            Err(ContractParseError::MissingVersion { .. })
        ));
        match parse_contract("version: latest\n").expect_err("word") {
            ContractParseError::InvalidVersion { value, .. } => assert_eq!(value, "latest"),
            other => panic!("expected invalid version, got {other:?}"),
        }
        match parse_contract("version: 1.0\n").expect_err("decimal") {
            ContractParseError::InvalidVersion { value, .. } => assert_eq!(value, "1.0"),
            other => panic!("expected invalid version, got {other:?}"),
        }
        match parse_contract("version: 01\n").expect_err("leading zero") {
            ContractParseError::InvalidVersion { value, .. } => assert_eq!(value, "01"),
            other => panic!("expected invalid version, got {other:?}"),
        }
    }

    #[test]
    fn unknown_domains_and_fields_fail() {
        match parse_contract("version: 1\nbrowser:\n  open: []\n").expect_err("domain") {
            ContractParseError::UnknownDomain { name, .. } => assert_eq!(name, "browser"),
            other => panic!("expected unknown domain, got {other:?}"),
        }
        match parse_contract("version: 1\nfilesystem:\n  metadata:\n    allow: []\n")
            .expect_err("metadata")
        {
            ContractParseError::UnknownField { path, field, .. } => {
                assert_eq!(path, "filesystem");
                assert_eq!(field, "metadata");
            }
            other => panic!("expected unknown field, got {other:?}"),
        }
    }

    #[test]
    fn malformed_resources_name_the_field_and_the_value() {
        let scalar = parse_contract("version: 1\nfilesystem:\n  read:\n    allow: ./src/**\n")
            .expect_err("scalar allow");
        match &scalar {
            ContractParseError::UnexpectedStructure { path, expected, .. } => {
                assert_eq!(path, "filesystem.read.allow");
                assert_eq!(*expected, "an explicit list of resource strings");
            }
            other => panic!("expected a list, got {other:?}"),
        }
        let message = scalar.to_string();
        assert!(message.contains("filesystem.read.allow"));
        assert!(message.contains("explicit list"));

        let empty = parse_contract("version: 1\nfilesystem:\n  read:\n    allow:\n      - \"\"\n")
            .expect_err("empty resource");
        match &empty {
            ContractParseError::InvalidResource {
                path,
                value,
                expected,
                ..
            } => {
                assert_eq!(path, "filesystem.read.allow[0]");
                assert_eq!(value, "");
                assert_eq!(*expected, "a non-empty resource pattern");
            }
            other => panic!("expected an invalid resource, got {other:?}"),
        }
        let shown = empty.to_string();
        assert!(shown.contains("filesystem.read.allow[0]"));
        assert!(shown.contains("non-empty resource pattern"));

        let nul = parse_contract(
            "version: 1\nfilesystem:\n  read:\n    allow:\n      - \"./src/a\\0b\"\n",
        )
        .expect_err("nul resource");
        match nul {
            ContractParseError::InvalidResource {
                path,
                expected,
                value,
                ..
            } => {
                assert_eq!(path, "filesystem.read.allow[0]");
                assert_eq!(expected, "a resource pattern without a NUL byte");
                assert!(!value.contains('\0'));
            }
            other => panic!("expected an invalid resource, got {other:?}"),
        }
    }

    #[test]
    fn aliases_anchors_and_tags_are_rejected() {
        assert!(matches!(
            parse_contract("version: 1\nfilesystem: &saved\n  read:\n    allow: []\n"),
            Err(ContractParseError::YamlFeature {
                feature: "anchor",
                ..
            })
        ));
        assert!(matches!(
            parse_contract("version: *saved\n"),
            Err(ContractParseError::YamlFeature {
                feature: "alias",
                ..
            })
        ));
        assert!(matches!(
            parse_contract(
                "version: 1\nfilesystem:\n  read: &saved\n    allow: []\n  write:\n    allow: *saved\n"
            ),
            Err(ContractParseError::YamlFeature {
                feature: "anchor",
                ..
            })
        ));
        assert!(matches!(
            parse_contract("version: !!int 1\n"),
            Err(ContractParseError::YamlFeature { feature: "tag", .. })
        ));
    }

    #[test]
    fn duplicate_fields_and_extra_documents_fail() {
        assert!(matches!(
            parse_contract("version: 1\nversion: 1\n"),
            Err(ContractParseError::DuplicateField { .. })
        ));
        assert!(matches!(
            parse_contract("version: 1\n---\nversion: 1\n"),
            Err(ContractParseError::MultipleDocuments { .. })
        ));
    }
}
