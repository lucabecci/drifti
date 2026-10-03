// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema version 1 for `.drifti/state.db`.
//!
//! The statements below are the whole schema. A later migration task owns
//! every change to them. This module does not delete an existing database.
//!
//! Column mapping for one SPEC-004 event, none of which is a payload:
//!
//! | `events` column | SPEC-004 field |
//! | --- | --- |
//! | `execution_id` | execution id as text supplied by the caller |
//! | `sequence` | ordering authority inside one execution |
//! | `monotonic_nanos` | informational monotonic timestamp, not an order key |
//! | `pid`, `tid` | acting process, absent when the backend did not know them |
//! | `parent_pid` | parent process, absent when unknown |
//! | `action` | operation name such as `filesystem.read` |
//! | `resource_kind` | `file`, `executable`, or `network` |
//! | `canonical_resource` | observed resource name, not file bytes |
//! | `outcome_status` | `success` or `failure` |
//! | `errno`, `failure_reason` | failure detail, only when the outcome failed |
//! | `evidence_byte_length` | a count, never the bytes |
//!
//! `executions` holds lifecycle, minimized command metadata, coverage, and
//! version text. `processes` is keyed by `(execution_id, pid)`, so a pid in
//! one execution cannot alias a pid in another. `command_program` and
//! `arg_count` are the minimized command record. Argument values are not a
//! column.

use crate::error::StoreError;

/// Schema this crate creates and opens. Any other version is refused.
pub const SCHEMA_VERSION: i64 = 1;

/// Directory under the workspace root.
pub const STATE_DIR: &str = ".drifti";

/// Database file inside [`STATE_DIR`].
pub const DATABASE_FILE: &str = "state.db";

/// Largest accepted canonical-resource field, in bytes.
pub const MAX_IDENTITY_BYTES: usize = 4096;

const UNIT: char = '\u{1f}';

/// DDL for a new database, in application order.
///
/// `sqlite_master.sql` for two fresh databases matches because this list
/// never depends on the clock or on the workspace path.
pub(crate) const DDL: &[&str] = &[
    "\
    CREATE TABLE schema_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL CHECK (version >= 1)
    )",
    "\
    CREATE TABLE executions (
        execution_id TEXT PRIMARY KEY CHECK (length(execution_id) > 0),
        lifecycle TEXT NOT NULL CHECK (lifecycle IN ('started', 'finished')),
        coverage_status TEXT CHECK (
            coverage_status IS NULL
            OR coverage_status IN ('COMPLETE', 'INCOMPLETE', 'UNSUPPORTED')
        ),
        exit_code INTEGER,
        command_program TEXT CHECK (
            command_program IS NULL
            OR length(command_program) BETWEEN 1 AND 4096
        ),
        arg_count INTEGER CHECK (arg_count IS NULL OR arg_count BETWEEN 0 AND 256),
        contract_version TEXT CHECK (
            contract_version IS NULL OR length(contract_version) > 0
        ),
        tool_version TEXT CHECK (tool_version IS NULL OR length(tool_version) > 0)
    )",
    "\
    CREATE TABLE execution_unsupported_domains (
        execution_id TEXT NOT NULL REFERENCES executions (execution_id),
        domain TEXT NOT NULL CHECK (domain IN ('filesystem', 'process', 'network')),
        PRIMARY KEY (execution_id, domain)
    )",
    "\
    CREATE TABLE processes (
        execution_id TEXT NOT NULL REFERENCES executions (execution_id),
        pid INTEGER NOT NULL CHECK (pid >= 0),
        tid INTEGER CHECK (tid IS NULL OR tid >= 0),
        parent_pid INTEGER CHECK (parent_pid IS NULL OR parent_pid >= 0),
        PRIMARY KEY (execution_id, pid)
    )",
    "\
    CREATE TABLE events (
        execution_id TEXT NOT NULL REFERENCES executions (execution_id),
        sequence INTEGER NOT NULL CHECK (sequence >= 0),
        monotonic_nanos INTEGER NOT NULL CHECK (monotonic_nanos >= 0),
        pid INTEGER CHECK (pid IS NULL OR pid >= 0),
        tid INTEGER CHECK (tid IS NULL OR tid >= 0),
        parent_pid INTEGER CHECK (parent_pid IS NULL OR parent_pid >= 0),
        action TEXT NOT NULL CHECK (
            action IN (
                'filesystem.read',
                'filesystem.write',
                'filesystem.metadata',
                'process.execute',
                'network.connect',
                'network.listen'
            )
        ),
        resource_kind TEXT NOT NULL CHECK (
            resource_kind IN ('file', 'executable', 'network')
        ),
        canonical_resource TEXT NOT NULL CHECK (length(canonical_resource) > 0),
        outcome_status TEXT NOT NULL CHECK (outcome_status IN ('success', 'failure')),
        errno INTEGER,
        failure_reason TEXT CHECK (
            failure_reason IS NULL OR length(failure_reason) BETWEEN 1 AND 128
        ),
        evidence_byte_length INTEGER CHECK (
            evidence_byte_length IS NULL OR evidence_byte_length >= 0
        ),
        PRIMARY KEY (execution_id, sequence),
        CHECK (
            (
                outcome_status = 'success'
                AND errno IS NULL
                AND failure_reason IS NULL
            )
            OR outcome_status = 'failure'
        )
    )",
    "CREATE INDEX idx_events_execution_id ON events (execution_id)",
    "CREATE INDEX idx_events_execution_id_sequence ON events (execution_id, sequence)",
    "CREATE INDEX idx_events_action ON events (action)",
    "CREATE INDEX idx_events_canonical_resource ON events (canonical_resource)",
];

/// Names that must not be columns. They would persist prohibited data.
pub const PROHIBITED_COLUMN_NAMES: &[&str] = &[
    "argv",
    "args",
    "arguments",
    "payload",
    "file_contents",
    "contents",
    "body",
    "secret",
    "secrets",
    "prompt",
    "prompts",
    "response",
    "responses",
    "model_response",
    "password",
    "token",
    "cookie",
    "authorization",
    "file_bytes",
    "network_payload",
];

/// Observed resource name stored in `events.canonical_resource`.
///
/// Recording this name does not authorize the resource. The text is not file
/// bytes, a network payload, a secret, or an argument vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalResource<'a> {
    /// Filesystem path text.
    File(&'a str),
    /// Executable name or path text.
    Executable(&'a str),
    /// Host or address text and a port.
    Network {
        /// Host or address text.
        host: &'a str,
        /// Port.
        port: u16,
    },
}

/// Owned form of [`CanonicalResource`], produced by [`parse_canonical_resource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedCanonicalResource {
    /// Filesystem path text.
    File(String),
    /// Executable name or path text.
    Executable(String),
    /// Host or address text and a port.
    Network {
        /// Host or address text.
        host: String,
        /// Port.
        port: u16,
    },
}

/// Encodes `resource` so two equivalent names share one index key.
///
/// The encoding is `kind`, then one record per field: a unit separator, the
/// byte length in decimal, `:`, and the field bytes. A colon or newline
/// inside a path stays inside that field.
pub fn canonical_resource(resource: CanonicalResource<'_>) -> Result<String, StoreError> {
    match resource {
        CanonicalResource::File(path) => encode("file", &[path]),
        CanonicalResource::Executable(identity) => encode("executable", &[identity]),
        CanonicalResource::Network { host, port } => {
            let port = port.to_string();
            encode("network", &[host, port.as_str()])
        }
    }
}

/// Inverse of [`canonical_resource`].
pub fn parse_canonical_resource(text: &str) -> Result<OwnedCanonicalResource, StoreError> {
    let (kind, rest) = text
        .split_once(UNIT)
        .ok_or(StoreError::InvalidCanonicalResource)?;
    let fields = parse_fields(rest)?;
    match (kind, fields.as_slice()) {
        ("file", [path]) => Ok(OwnedCanonicalResource::File(path.clone())),
        ("executable", [identity]) => Ok(OwnedCanonicalResource::Executable(identity.clone())),
        ("network", [host, port]) => Ok(OwnedCanonicalResource::Network {
            host: host.clone(),
            port: parse_port(port)?,
        }),
        _ => Err(StoreError::InvalidCanonicalResource),
    }
}

/// Fits `value` in a SQLite INTEGER without truncating it.
pub fn sqlite_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::IntegerOutOfRange)
}

fn encode(kind: &str, fields: &[&str]) -> Result<String, StoreError> {
    let mut out = String::from(kind);
    for field in fields {
        validate_field(field)?;
        out.push(UNIT);
        out.push_str(&field.len().to_string());
        out.push(':');
        out.push_str(field);
    }
    Ok(out)
}

fn validate_field(field: &str) -> Result<(), StoreError> {
    if field.is_empty() {
        return Err(StoreError::EmptyIdentity);
    }
    if field.len() > MAX_IDENTITY_BYTES {
        return Err(StoreError::IdentityTooLong);
    }
    if field.as_bytes().contains(&0) {
        return Err(StoreError::EmbeddedNul);
    }
    Ok(())
}

fn parse_fields(mut rest: &str) -> Result<Vec<String>, StoreError> {
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (length, after_len) = rest
            .split_once(':')
            .ok_or(StoreError::InvalidCanonicalResource)?;
        let length: usize = length
            .parse()
            .map_err(|_| StoreError::InvalidCanonicalResource)?;
        if length == 0 || length > MAX_IDENTITY_BYTES || after_len.len() < length {
            return Err(StoreError::InvalidCanonicalResource);
        }
        let (field, tail) = after_len.split_at(length);
        validate_field(field)?;
        fields.push(field.to_owned());
        if tail.is_empty() {
            break;
        }
        rest = tail
            .strip_prefix(UNIT)
            .ok_or(StoreError::InvalidCanonicalResource)?;
    }
    if fields.is_empty() {
        return Err(StoreError::InvalidCanonicalResource);
    }
    Ok(fields)
}

fn parse_port(text: &str) -> Result<u16, StoreError> {
    if text.len() > 1 && text.starts_with('0') {
        return Err(StoreError::InvalidCanonicalResource);
    }
    let port: u16 = text
        .parse()
        .map_err(|_| StoreError::InvalidCanonicalResource)?;
    if port.to_string() != text {
        return Err(StoreError::InvalidCanonicalResource);
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_resource, parse_canonical_resource, sqlite_i64, CanonicalResource,
        OwnedCanonicalResource, DDL, PROHIBITED_COLUMN_NAMES, SCHEMA_VERSION,
    };

    #[test]
    fn schema_version_is_one() {
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn ddl_has_no_blob_and_no_prohibited_column() {
        let sql = DDL.join("\n").to_ascii_lowercase();
        assert!(!sql.contains("blob"));
        for name in PROHIBITED_COLUMN_NAMES {
            let declaration = format!(" {name} ");
            assert!(
                !sql.contains(&declaration),
                "schema declares prohibited column {name}"
            );
        }
    }

    #[test]
    fn canonical_file_keeps_colons_and_newlines() {
        let path = "C:/repo/a\nb:c";
        let encoded = canonical_resource(CanonicalResource::File(path)).expect("encode file");
        assert_eq!(
            parse_canonical_resource(&encoded).expect("parse file"),
            OwnedCanonicalResource::File(path.to_owned())
        );
    }

    #[test]
    fn canonical_network_keeps_an_ipv6_host() {
        let encoded = canonical_resource(CanonicalResource::Network {
            host: "::1",
            port: 443,
        })
        .expect("encode network");
        assert_eq!(
            parse_canonical_resource(&encoded).expect("parse network"),
            OwnedCanonicalResource::Network {
                host: "::1".to_owned(),
                port: 443,
            }
        );
    }

    #[test]
    fn canonical_resource_rejects_empty_and_nul_and_overlong_text() {
        assert!(canonical_resource(CanonicalResource::File("")).is_err());
        assert!(canonical_resource(CanonicalResource::Executable("a\0b")).is_err());
        let overlong = "x".repeat(4097);
        assert!(canonical_resource(CanonicalResource::File(&overlong)).is_err());
    }

    #[test]
    fn parser_rejects_a_truncated_or_padded_port() {
        assert!(parse_canonical_resource("file").is_err());
        assert!(parse_canonical_resource("network\u{1f}3:::1\u{1f}2:01").is_err());
    }

    #[test]
    fn sqlite_i64_does_not_truncate() {
        assert_eq!(sqlite_i64(0).expect("zero"), 0);
        assert_eq!(sqlite_i64(i64::MAX as u64).expect("max"), i64::MAX);
        assert!(sqlite_i64(u64::MAX).is_err());
    }
}
