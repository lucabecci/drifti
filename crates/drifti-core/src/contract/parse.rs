// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parse one contract document from YAML text.
//!
//! Version 1 is the only version that becomes a [`ContractDocument`]. Any
//! other version fails before the rest of the document is treated as version
//! 1. Aliases, anchors, and tags are rejected rather than expanded.
//!
//! Errors name a field path, the invalid value, and the expected form when
//! those are known. Parsing reads text, so line and column are the file
//! location. Displayed values are capped and do not keep control characters.

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
const VERSION_FORM: &str = "version 1";
const DOCUMENT_PATH: &str = "document";
const PLAIN_YAML: &str = "a plain YAML value without aliases, anchors, or tags";
const ONE_DOCUMENT: &str = "a single YAML document";
const ONE_FIELD: &str = "each field once";
const VERSION_1_FIELD: &str = "a version-1 field";
const DOMAIN_FORM: &str = "filesystem, process, or network";

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
///
/// Each variant carries the field path and the expected form when parsing
/// knows them. [`Self::UnsupportedVersion`] is only a whole number other than
/// 1, so it cannot be read as version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractParseError {
    /// The text is not a single YAML document.
    Syntax {
        /// Field path being read, or `document` before a field is known.
        path: String,
        /// Parser message, bounded and free of control characters.
        message: String,
        /// What the document should be.
        expected: &'static str,
        /// Where parsing stopped.
        location: SourceLocation,
    },
    /// `version` was absent.
    MissingVersion {
        /// Field path. This is `version`.
        path: &'static str,
        /// What the field should contain.
        expected: &'static str,
        /// Where the document mapping starts.
        location: SourceLocation,
    },
    /// The version is a whole number other than 1.
    UnsupportedVersion {
        /// Field path. This is `version`.
        path: &'static str,
        /// The version that was written. This is never 1.
        version: u64,
        /// What the field should contain.
        expected: &'static str,
        /// Where the version scalar starts.
        location: SourceLocation,
    },
    /// The version is not a whole number.
    InvalidVersion {
        /// Field path. This is `version`.
        path: &'static str,
        /// The version text, bounded for display.
        value: String,
        /// What the field should contain.
        expected: &'static str,
        /// Where the version scalar starts.
        location: SourceLocation,
    },
    /// A top-level key is not a version-1 capability domain.
    UnknownDomain {
        /// Field path of the document mapping.
        path: &'static str,
        /// The rejected key, bounded for display.
        name: String,
        /// The domains version 1 accepts.
        expected: &'static str,
        /// Where the key starts.
        location: SourceLocation,
    },
    /// A key inside a known section is not part of version 1.
    UnknownField {
        /// Section path, such as `filesystem`.
        path: String,
        /// The rejected key, bounded for display.
        field: String,
        /// What that section should contain.
        expected: &'static str,
        /// Where the key starts.
        location: SourceLocation,
    },
    /// The same key was written twice.
    DuplicateField {
        /// Section path.
        path: String,
        /// The repeated key, bounded for display.
        field: String,
        /// What the mapping should contain.
        expected: &'static str,
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
        /// Field path being read.
        path: String,
        /// `alias`, `anchor`, or `tag`.
        feature: &'static str,
        /// The rejected feature, bounded for display.
        value: String,
        /// What the field should contain.
        expected: &'static str,
        /// Where the feature starts.
        location: SourceLocation,
    },
    /// More than one YAML document was present.
    MultipleDocuments {
        /// Field path of the document.
        path: &'static str,
        /// A bounded description of the extra document, not its contents.
        value: &'static str,
        /// What the input should contain.
        expected: &'static str,
        /// Where the extra document starts.
        location: SourceLocation,
    },
    /// A field had a YAML shape this schema does not use.
    UnexpectedStructure {
        /// Field path.
        path: String,
        /// The rejected value, bounded for display.
        value: String,
        /// What the field should contain.
        expected: &'static str,
        /// Where the value starts.
        location: SourceLocation,
    },
}

impl Display for ContractParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax {
                path,
                message,
                expected,
                location,
            } => write!(
                formatter,
                "invalid contract document at {path} at {}:{}; {message}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::MissingVersion {
                path,
                expected,
                location,
            } => write!(
                formatter,
                "missing contract field `{path}` at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::UnsupportedVersion {
                path,
                version,
                expected,
                location,
            } => write!(
                formatter,
                "unsupported contract version {version} at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::InvalidVersion {
                path,
                value,
                expected,
                location,
            } => write!(
                formatter,
                "invalid contract version `{value}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::UnknownDomain {
                path,
                name,
                expected,
                location,
            } => write!(
                formatter,
                "unknown capability domain `{name}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::UnknownField {
                path,
                field,
                expected,
                location,
            } => write!(
                formatter,
                "unknown field `{field}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::DuplicateField {
                path,
                field,
                expected,
                location,
            } => write!(
                formatter,
                "duplicate field `{field}` at {path} at {}:{}; expected {expected}",
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
            Self::YamlFeature {
                path,
                feature,
                value,
                expected,
                location,
            } => write!(
                formatter,
                "invalid YAML {feature} `{value}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::MultipleDocuments {
                path,
                value,
                expected,
                location,
            } => write!(
                formatter,
                "extra YAML document `{value}` at {path} at {}:{}; expected {expected}",
                location.line(),
                location.column()
            ),
            Self::UnexpectedStructure {
                path,
                value,
                expected,
                location,
            } => write!(
                formatter,
                "unexpected value `{value}` at {path} at {}:{}; expected {expected}",
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
    field_path: String,
}

impl<'input> Stream<'input> {
    fn new(yaml: &'input str) -> Self {
        Self {
            parser: Parser::new_from_str(yaml),
            field_path: DOCUMENT_PATH.to_owned(),
        }
    }

    fn set_field_path(&mut self, next: &str) {
        self.field_path.clear();
        self.field_path.push_str(next);
    }

    fn next_event(&mut self) -> Result<(Event<'input>, Span), ContractParseError> {
        loop {
            match self.parser.next_event() {
                Some(Ok((Event::Nothing, _))) => continue,
                Some(Ok(event)) => return Ok(event),
                Some(Err(error)) => return Err(syntax(&self.field_path, error)),
                None => {
                    return Err(ContractParseError::Syntax {
                        path: self.field_path.clone(),
                        message: "the document ended early".to_owned(),
                        expected: ONE_DOCUMENT,
                        location: SourceLocation { line: 1, column: 1 },
                    });
                }
            }
        }
    }
}

fn load_document(yaml: &str) -> Result<Node, ContractParseError> {
    let mut stream = Stream::new(yaml);
    expect_event(&mut stream, DOCUMENT_PATH, ONE_DOCUMENT, |event| {
        matches!(event, Event::StreamStart)
    })?;
    let (start, start_span) = stream.next_event()?;
    if !matches!(start, Event::DocumentStart(_)) {
        return Err(structure(
            DOCUMENT_PATH,
            event_label(&start),
            ONE_DOCUMENT,
            SourceLocation::new(start_span),
        ));
    }
    let (event, span) = stream.next_event()?;
    if matches!(event, Event::DocumentEnd | Event::StreamEnd) {
        return Err(ContractParseError::MissingVersion {
            path: VERSION_KEY,
            expected: VERSION_FORM,
            location: SourceLocation::new(start_span),
        });
    }
    let node = parse_node(&mut stream, event, span, DOCUMENT_PATH)?;
    expect_event(&mut stream, DOCUMENT_PATH, ONE_DOCUMENT, |event| {
        matches!(event, Event::DocumentEnd)
    })?;
    let (after, after_span) = stream.next_event()?;
    if matches!(after, Event::DocumentStart(_)) {
        return Err(ContractParseError::MultipleDocuments {
            path: DOCUMENT_PATH,
            value: "an extra YAML document",
            expected: ONE_DOCUMENT,
            location: SourceLocation::new(after_span),
        });
    }
    if !matches!(after, Event::StreamEnd) {
        return Err(structure(
            DOCUMENT_PATH,
            event_label(&after),
            ONE_DOCUMENT,
            SourceLocation::new(after_span),
        ));
    }
    Ok(node)
}

fn expect_event<'input>(
    stream: &mut Stream<'input>,
    field_path: &str,
    expected: &'static str,
    matches_event: impl FnOnce(&Event<'input>) -> bool,
) -> Result<Span, ContractParseError> {
    stream.set_field_path(field_path);
    let (event, span) = stream.next_event()?;
    if matches_event(&event) {
        Ok(span)
    } else {
        Err(structure(
            field_path,
            event_label(&event),
            expected,
            SourceLocation::new(span),
        ))
    }
}

fn parse_node(
    stream: &mut Stream<'_>,
    event: Event<'_>,
    span: Span,
    path: &str,
) -> Result<Node, ContractParseError> {
    stream.set_field_path(path);
    let label = event_label(&event);
    match event {
        Event::Alias(_) => Err(yaml_feature(
            path,
            "alias",
            "alias",
            SourceLocation::new(span),
        )),
        Event::Scalar(text, _, anchor, tag) => {
            reject_decoration(path, anchor, tag.as_ref(), span)?;
            Ok(Node::Scalar {
                text: text.into_owned(),
                span,
            })
        }
        Event::SequenceStart(anchor, tag) => {
            reject_decoration(path, anchor, tag.as_ref(), span)?;
            let mut items = Vec::new();
            let mut index = 0usize;
            loop {
                let item_path = format!("{path}[{index}]");
                stream.set_field_path(&item_path);
                let (event, item_span) = stream.next_event()?;
                if matches!(event, Event::SequenceEnd) {
                    break;
                }
                items.push(parse_node(stream, event, item_span, &item_path)?);
                index += 1;
            }
            Ok(Node::Sequence { items, span })
        }
        Event::MappingStart(anchor, tag) => {
            reject_decoration(path, anchor, tag.as_ref(), span)?;
            let mut entries = Vec::new();
            loop {
                stream.set_field_path(path);
                let (event, key_span) = stream.next_event()?;
                if matches!(event, Event::MappingEnd) {
                    break;
                }
                let key = match parse_node(stream, event, key_span, path)? {
                    Node::Scalar { text, span } => (text, span),
                    Node::Sequence { span, .. } => {
                        return Err(structure(
                            path,
                            "a list",
                            "a field name",
                            SourceLocation::new(span),
                        ));
                    }
                    Node::Mapping { span, .. } => {
                        return Err(structure(
                            path,
                            "a mapping",
                            "a field name",
                            SourceLocation::new(span),
                        ));
                    }
                };
                if entries.iter().any(|(existing, _, _)| existing == &key.0) {
                    return Err(ContractParseError::DuplicateField {
                        path: path.to_owned(),
                        field: show_value(&key.0),
                        expected: ONE_FIELD,
                        location: SourceLocation::new(key.1),
                    });
                }
                let child = child_path(path, &key.0);
                stream.set_field_path(&child);
                let (value_event, value_span) = stream.next_event()?;
                let value = parse_node(stream, value_event, value_span, &child)?;
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
        | Event::MappingEnd => Err(structure(path, label, "a value", SourceLocation::new(span))),
    }
}

fn reject_decoration(
    field_path: &str,
    anchor: usize,
    tag: Option<&Cow<'_, Tag>>,
    span: Span,
) -> Result<(), ContractParseError> {
    if anchor > 0 {
        return Err(yaml_feature(
            field_path,
            "anchor",
            "anchor",
            SourceLocation::new(span),
        ));
    }
    if let Some(tag) = tag {
        return Err(yaml_feature(
            field_path,
            "tag",
            &tag.to_string(),
            SourceLocation::new(span),
        ));
    }
    Ok(())
}

fn document_from_node(node: Node) -> Result<ContractDocument, ContractParseError> {
    let Node::Mapping { entries, span } = node else {
        return Err(structure(
            DOCUMENT_PATH,
            &node_summary(&node),
            "a mapping",
            node_location(&node),
        ));
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
                    path: DOCUMENT_PATH,
                    name: show_value(key),
                    expected: DOMAIN_FORM,
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
            path: VERSION_KEY,
            expected: VERSION_FORM,
            location: SourceLocation::new(document),
        });
    };
    let Node::Scalar { text, span } = value else {
        return Err(ContractParseError::InvalidVersion {
            path: VERSION_KEY,
            value: show_value(&node_summary(value)),
            expected: VERSION_FORM,
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
                    path: VERSION_KEY,
                    version,
                    expected: VERSION_FORM,
                    location: SourceLocation::new(*span),
                });
            }
        }
    }
    Err(ContractParseError::InvalidVersion {
        path: VERSION_KEY,
        value: show_value(text),
        expected: VERSION_FORM,
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
        return Err(structure(
            path,
            &node_summary(node),
            "an explicit list of resource strings",
            node_location(node),
        ));
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
        _ => Err(structure(
            path,
            &node_summary(node),
            "a mapping",
            node_location(node),
        )),
    }
}

fn child_path(parent: &str, key: &str) -> String {
    if parent == "document" {
        key.to_owned()
    } else {
        format!("{parent}.{key}")
    }
}

fn unknown_field(field_path: &str, field: &str, span: Span) -> ContractParseError {
    ContractParseError::UnknownField {
        path: field_path.to_owned(),
        field: show_value(field),
        expected: VERSION_1_FIELD,
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

fn syntax(field_path: &str, error: ScanError) -> ContractParseError {
    let location = SourceLocation {
        line: error.marker().line(),
        column: error.marker().col() + 1,
    };
    if error.info().contains("unknown anchor") {
        return yaml_feature(field_path, "alias", "alias", location);
    }
    ContractParseError::Syntax {
        path: field_path.to_owned(),
        message: show_value(error.info()),
        expected: ONE_DOCUMENT,
        location,
    }
}

fn structure(
    field_path: &str,
    value: &str,
    expected: &'static str,
    location: SourceLocation,
) -> ContractParseError {
    ContractParseError::UnexpectedStructure {
        path: field_path.to_owned(),
        value: show_value(value),
        expected,
        location,
    }
}

fn yaml_feature(
    field_path: &str,
    feature: &'static str,
    value: &str,
    location: SourceLocation,
) -> ContractParseError {
    ContractParseError::YamlFeature {
        path: field_path.to_owned(),
        feature,
        value: show_value(value),
        expected: PLAIN_YAML,
        location,
    }
}

fn event_label(event: &Event<'_>) -> &'static str {
    match event {
        Event::Nothing => "nothing",
        Event::StreamStart => "a stream start",
        Event::StreamEnd => "a stream end",
        Event::DocumentStart(_) => "a document start",
        Event::DocumentEnd => "a document end",
        Event::Alias(_) => "an alias",
        Event::Scalar(_, _, _, _) => "a scalar",
        Event::SequenceStart(_, _) => "a list",
        Event::SequenceEnd => "a list end",
        Event::MappingStart(_, _) => "a mapping",
        Event::MappingEnd => "a mapping end",
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

    fn assert_no_filename(message: &str) {
        assert!(!message.contains("drifti.yaml"));
        assert!(!message.contains(".yml"));
    }

    fn assert_control_free(text: &str) {
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains('\0'));
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
                ContractParseError::UnsupportedVersion {
                    path,
                    version,
                    expected,
                    location,
                } => {
                    assert_eq!(*path, "version");
                    assert_ne!(*version, 1);
                    assert_eq!(*expected, "version 1");
                    assert_eq!(location.line(), 1);
                    assert!(location.column() >= 1);
                }
                other => panic!("expected unsupported version, got {other:?}"),
            }
            let message = error.to_string();
            assert!(message.contains("version"));
            assert!(message.contains("expected version 1"));
            assert!(message.contains("unsupported"));
            assert!(!message.contains("interpreted"));
            assert_no_filename(&message);
            assert_control_free(&message);
        }
        match parse_contract("version: 2\n").expect_err("version 2") {
            ContractParseError::UnsupportedVersion {
                version: 2,
                path,
                expected,
                location,
            } => {
                assert_eq!(path, "version");
                assert_eq!(expected, "version 1");
                assert_eq!(location.line(), 1);
                assert_eq!(location.column(), 10);
            }
            other => panic!("expected version 2, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_or_non_numeric_version_fails() {
        let missing = parse_contract("filesystem:\n  read:\n    allow: []\n").expect_err("missing");
        match &missing {
            ContractParseError::MissingVersion {
                path,
                expected,
                location,
            } => {
                assert_eq!(*path, "version");
                assert_eq!(*expected, "version 1");
                assert!(location.line() >= 1);
                assert!(location.column() >= 1);
            }
            other => panic!("expected a missing version, got {other:?}"),
        }
        let missing_message = missing.to_string();
        assert!(missing_message.contains("version"));
        assert!(missing_message.contains("expected version 1"));
        assert_no_filename(&missing_message);

        match parse_contract("version: latest\n").expect_err("word") {
            ContractParseError::InvalidVersion {
                path,
                value,
                expected,
                location,
            } => {
                assert_eq!(path, "version");
                assert_eq!(value, "latest");
                assert_eq!(expected, "version 1");
                assert_eq!(location.line(), 1);
            }
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
            ContractParseError::UnknownDomain {
                path,
                name,
                expected,
                location,
            } => {
                assert_eq!(path, "document");
                assert_eq!(name, "browser");
                assert_eq!(expected, "filesystem, process, or network");
                assert_eq!(location.line(), 2);
            }
            other => panic!("expected unknown domain, got {other:?}"),
        }
        match parse_contract("version: 1\nfilesystem:\n  metadata:\n    allow: []\n")
            .expect_err("metadata")
        {
            ContractParseError::UnknownField {
                path,
                field,
                expected,
                ..
            } => {
                assert_eq!(path, "filesystem");
                assert_eq!(field, "metadata");
                assert_eq!(expected, "a version-1 field");
            }
            other => panic!("expected unknown field, got {other:?}"),
        }
    }

    #[test]
    fn malformed_resources_name_the_field_and_the_value() {
        let scalar = parse_contract("version: 1\nfilesystem:\n  read:\n    allow: ./src/**\n")
            .expect_err("scalar allow");
        match &scalar {
            ContractParseError::UnexpectedStructure {
                path,
                value,
                expected,
                location,
            } => {
                assert_eq!(path, "filesystem.read.allow");
                assert_eq!(value, "./src/**");
                assert_eq!(*expected, "an explicit list of resource strings");
                assert!(location.line() >= 1);
                assert!(location.column() >= 1);
            }
            other => panic!("expected a list, got {other:?}"),
        }
        let message = scalar.to_string();
        assert!(message.contains("filesystem.read.allow"));
        assert!(message.contains("./src/**"));
        assert!(message.contains("explicit list"));
        assert_no_filename(&message);

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
        match &nul {
            ContractParseError::InvalidResource {
                path,
                expected,
                value,
                location,
            } => {
                assert_eq!(path, "filesystem.read.allow[0]");
                assert_eq!(*expected, "a resource pattern without a NUL byte");
                assert_eq!(value, "./src/a\u{FFFD}b");
                assert_control_free(value);
                assert!(location.line() >= 1);
            }
            other => panic!("expected an invalid resource, got {other:?}"),
        }
        assert_control_free(&nul.to_string());
    }

    #[test]
    fn parse_errors_cap_values_and_replace_controls() {
        let letters = "n".repeat(90);
        let yaml = format!("version: \"\\a{letters}\"\n");
        let error = parse_contract(&yaml).expect_err("long version");
        match &error {
            ContractParseError::InvalidVersion {
                path,
                value,
                expected,
                ..
            } => {
                assert_eq!(*path, "version");
                assert_eq!(*expected, "version 1");
                assert!(value.starts_with('\u{FFFD}'));
                assert!(value.ends_with("..."));
                assert_eq!(value.chars().count(), 83);
                assert_control_free(value);
            }
            other => panic!("expected an invalid version, got {other:?}"),
        }
        assert_control_free(&error.to_string());

        let nul_version = parse_contract("version: \"\\0secret\"\n").expect_err("nul version");
        match nul_version {
            ContractParseError::InvalidVersion { value, .. } => {
                assert_eq!(value, "\u{FFFD}secret");
                assert_control_free(&value);
            }
            other => panic!("expected an invalid version, got {other:?}"),
        }
    }

    #[test]
    fn aliases_anchors_and_tags_are_rejected() {
        match parse_contract("version: 1\nfilesystem: &saved\n  read:\n    allow: []\n")
            .expect_err("anchor")
        {
            ContractParseError::YamlFeature {
                path,
                feature,
                value,
                expected,
                location,
            } => {
                assert_eq!(path, "filesystem");
                assert_eq!(feature, "anchor");
                assert_eq!(value, "anchor");
                assert_eq!(
                    expected,
                    "a plain YAML value without aliases, anchors, or tags"
                );
                assert_eq!(location.line(), 3);
                assert!(location.column() >= 1);
                assert_control_free(&value);
            }
            other => panic!("expected an anchor, got {other:?}"),
        }
        match parse_contract("version: *saved\n").expect_err("alias") {
            ContractParseError::YamlFeature {
                path,
                feature,
                value,
                expected,
                ..
            } => {
                assert_eq!(path, "version");
                assert_eq!(feature, "alias");
                assert_eq!(value, "alias");
                assert_eq!(
                    expected,
                    "a plain YAML value without aliases, anchors, or tags"
                );
            }
            other => panic!("expected an alias, got {other:?}"),
        }
        assert!(matches!(
            parse_contract(
                "version: 1\nfilesystem:\n  read: &saved\n    allow: []\n  write:\n    allow: *saved\n"
            ),
            Err(ContractParseError::YamlFeature {
                feature: "anchor",
                ..
            })
        ));
        match parse_contract("version: !!int 1\n").expect_err("tag") {
            ContractParseError::YamlFeature {
                path,
                feature,
                value,
                expected,
                ..
            } => {
                assert_eq!(path, "version");
                assert_eq!(feature, "tag");
                assert!(value.contains("int"));
                assert_control_free(&value);
                assert_eq!(
                    expected,
                    "a plain YAML value without aliases, anchors, or tags"
                );
            }
            other => panic!("expected a tag, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_fields_and_extra_documents_fail() {
        match parse_contract("version: 1\nversion: 1\n").expect_err("duplicate") {
            ContractParseError::DuplicateField {
                path,
                field,
                expected,
                location,
            } => {
                assert_eq!(path, "document");
                assert_eq!(field, "version");
                assert_eq!(expected, "each field once");
                assert_eq!(location.line(), 2);
            }
            other => panic!("expected a duplicate field, got {other:?}"),
        }
        match parse_contract("version: 1\n---\nversion: 1\n").expect_err("documents") {
            ContractParseError::MultipleDocuments {
                path,
                value,
                expected,
                location,
            } => {
                assert_eq!(path, "document");
                assert_eq!(value, "an extra YAML document");
                assert_eq!(expected, "a single YAML document");
                assert!(location.line() >= 1);
                assert_control_free(value);
            }
            other => panic!("expected multiple documents, got {other:?}"),
        }
    }

    #[test]
    fn syntax_errors_name_a_path_and_hide_controls() {
        let error = parse_contract("version: 1\n@\n").expect_err("syntax");
        match &error {
            ContractParseError::Syntax {
                path,
                message,
                expected,
                location,
            } => {
                assert_eq!(path, "document");
                assert_eq!(*expected, "a single YAML document");
                assert!(location.line() >= 1);
                assert!(location.column() >= 1);
                assert_control_free(message);
                assert!(!message.is_empty());
            }
            other => panic!("expected a syntax error, got {other:?}"),
        }
        let shown = error.to_string();
        assert!(shown.contains("document"));
        assert!(shown.contains("expected a single YAML document"));
        assert_no_filename(&shown);
        assert_control_free(&shown);
    }
}
