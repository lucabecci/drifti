// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic events emitted by an observer.
//!
//! An event names an operation and a resource identity. It does not carry
//! file bytes, network payloads, secret values, prompts, responses, or the
//! command argument vector. `sequence` orders events inside one execution.
//! [`MonotonicTimestamp`] is not an ordering key.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::text::{self, TextError};

const MAX_IDENTITY: usize = 4096;
const MAX_HOST: usize = 255;
const MAX_REASON: usize = 128;

/// Opaque id of one observed execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionId(u128);

impl ExecutionId {
    /// Builds an id from a caller-supplied value. This crate does not draw randomness.
    #[must_use]
    pub const fn from_raw(raw: u128) -> Self {
        Self(raw)
    }

    /// Raw id bits.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// Nanoseconds from an observer-defined monotonic origin.
///
/// This is not wall-clock time and it does not order events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonotonicTimestamp {
    nanos: u64,
}

impl MonotonicTimestamp {
    /// Builds a timestamp from a monotonic duration in nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Nanoseconds since the observer's monotonic origin.
    #[must_use]
    pub const fn nanos(self) -> u64 {
        self.nanos
    }
}

/// Acting process, when the backend knows those ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pid: Option<u32>,
    tid: Option<u32>,
}

impl ProcessIdentity {
    /// `None` means the backend did not know that id.
    #[must_use]
    pub const fn new(pid: Option<u32>, tid: Option<u32>) -> Self {
        Self { pid, tid }
    }

    #[must_use]
    pub const fn pid(self) -> Option<u32> {
        self.pid
    }

    #[must_use]
    pub const fn tid(self) -> Option<u32> {
        self.tid
    }
}

/// Parent process id, present only when the backend knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ParentIdentity(u32);

impl ParentIdentity {
    #[must_use]
    pub const fn new(pid: u32) -> Self {
        Self(pid)
    }

    #[must_use]
    pub const fn pid(self) -> u32 {
        self.0
    }
}

/// Operation vocabulary aligned with SPEC-001 action names.
///
/// Recording an operation does not authorize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
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

impl Operation {
    /// Every operation this crate can name.
    pub const ALL: [Self; 6] = [
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::FilesystemMetadata,
        Self::ProcessExecute,
        Self::NetworkConnect,
        Self::NetworkListen,
    ];

    /// Stable operation name.
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
}

/// Resource identity. Paths and endpoints are names, not contents or payloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedResource {
    /// Filesystem path identity.
    File {
        /// Path text as observed. Not file bytes.
        path: String,
    },
    /// Executable identity.
    Executable {
        /// Executable name or path. Not the binary image.
        identity: String,
    },
    /// Network endpoint identity.
    Network {
        /// Host or address text. Not a payload.
        host: String,
        /// Port.
        port: u16,
    },
}

impl ObservedResource {
    /// File resource. Rejects empty text, embedded NUL, and paths over 4096 bytes.
    pub fn file(path: impl Into<String>) -> Result<Self, EventError> {
        Ok(Self::File {
            path: map_text(text::bounded(path, MAX_IDENTITY))?,
        })
    }

    /// Executable resource. Same bounds as [`Self::file`].
    pub fn executable(identity: impl Into<String>) -> Result<Self, EventError> {
        Ok(Self::Executable {
            identity: map_text(text::bounded(identity, MAX_IDENTITY))?,
        })
    }

    /// Network endpoint. The host is at most 255 bytes. The port is stored as given.
    pub fn network(host: impl Into<String>, port: u16) -> Result<Self, EventError> {
        Ok(Self::Network {
            host: map_text(text::bounded(host, MAX_HOST))?,
            port,
        })
    }
}

/// Short failure name. This is not a payload, a secret, or command output.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FailureReason(String);

impl FailureReason {
    /// Accepts 1..=128 bytes and rejects an embedded NUL.
    pub fn new(text: impl Into<String>) -> Result<Self, EventError> {
        Ok(Self(map_text(text::bounded(text, MAX_REASON))?))
    }

    /// Borrowed reason text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether the operation succeeded.
///
/// [`Outcome::Success`] is an exercised operation.
/// [`Outcome::Failure`] is an attempted operation that was not exercised.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    /// The operation succeeded.
    Success,
    /// The operation failed. `errno` and `reason` are present only when known.
    Failure {
        /// Errno when the backend knows it. This is a plain integer, not an FFI type.
        errno: Option<i32>,
        /// Short failure name, when the backend knows it.
        reason: Option<FailureReason>,
    },
}

impl Outcome {
    /// Exercised operation.
    #[must_use]
    pub const fn success() -> Self {
        Self::Success
    }

    /// Attempted operation that did not succeed.
    #[must_use]
    pub const fn failure(errno: Option<i32>, reason: Option<FailureReason>) -> Self {
        Self::Failure { errno, reason }
    }
}

/// Evidence that is safe to keep. Length is a count, never the bytes themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceMeta {
    byte_length: Option<u64>,
}

impl EvidenceMeta {
    /// Evidence with no length.
    #[must_use]
    pub const fn empty() -> Self {
        Self { byte_length: None }
    }

    /// Records a byte count without the bytes.
    #[must_use]
    pub const fn with_byte_length(byte_length: u64) -> Self {
        Self {
            byte_length: Some(byte_length),
        }
    }

    #[must_use]
    pub const fn byte_length(self) -> Option<u64> {
        self.byte_length
    }
}

/// One semantic observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedEvent {
    execution_id: ExecutionId,
    sequence: u64,
    timestamp: MonotonicTimestamp,
    process: ProcessIdentity,
    parent: Option<ParentIdentity>,
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
    evidence: EvidenceMeta,
}

impl ObservedEvent {
    /// Builds an event from already validated resource and outcome values.
    ///
    /// The argument count matches the SPEC-004 field list on purpose.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        execution_id: ExecutionId,
        sequence: u64,
        timestamp: MonotonicTimestamp,
        process: ProcessIdentity,
        parent: Option<ParentIdentity>,
        operation: Operation,
        resource: ObservedResource,
        outcome: Outcome,
        evidence: EvidenceMeta,
    ) -> Self {
        Self {
            execution_id,
            sequence,
            timestamp,
            process,
            parent,
            operation,
            resource,
            outcome,
            evidence,
        }
    }

    #[must_use]
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp(&self) -> MonotonicTimestamp {
        self.timestamp
    }

    #[must_use]
    pub const fn process(&self) -> ProcessIdentity {
        self.process
    }

    #[must_use]
    pub const fn parent(&self) -> Option<ParentIdentity> {
        self.parent
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
    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    #[must_use]
    pub const fn evidence(&self) -> EvidenceMeta {
        self.evidence
    }

    /// Orders two events by `sequence` inside one execution.
    ///
    /// Returns `None` when `execution_id` differs. Does not read `timestamp`.
    #[must_use]
    pub fn sequence_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.execution_id != other.execution_id {
            return None;
        }
        Some(self.sequence.cmp(&other.sequence))
    }

    /// Whether the operation succeeded.
    ///
    /// True only for [`Outcome::Success`]. A failure is not exercised.
    #[must_use]
    pub const fn was_exercised(&self) -> bool {
        match self.outcome() {
            Outcome::Success => true,
            Outcome::Failure { .. } => false,
        }
    }

    /// Whether the operation failed.
    ///
    /// True only for [`Outcome::Failure`]. Success is exercised, not attempted.
    #[must_use]
    pub const fn was_attempted(&self) -> bool {
        match self.outcome() {
            Outcome::Success => false,
            Outcome::Failure { .. } => true,
        }
    }
}

/// Rejected event text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// Text was empty.
    EmptyText,
    /// Text exceeded the bound for that field.
    TextTooLong,
    /// Text contained a NUL byte.
    EmbeddedNul,
}

impl Display for EventError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyText => formatter.write_str("event text is empty"),
            Self::TextTooLong => formatter.write_str("event text exceeds its bound"),
            Self::EmbeddedNul => formatter.write_str("event text contains a NUL byte"),
        }
    }
}

impl Error for EventError {}

fn map_text(result: Result<String, TextError>) -> Result<String, EventError> {
    result.map_err(|error| match error {
        TextError::Empty => EventError::EmptyText,
        TextError::TooLong => EventError::TextTooLong,
        TextError::EmbeddedNul => EventError::EmbeddedNul,
    })
}
