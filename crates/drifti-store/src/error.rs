// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Failures while opening or describing the execution store.
//!
//! An incompatible database is left on disk. This type has no variant that
//! deletes history.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::PathBuf;

/// A store operation failed. The database file is not deleted.
#[derive(Debug)]
pub enum StoreError {
    /// `.drifti/` could not be created.
    CreateStateDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Filesystem error.
        source: io::Error,
    },
    /// The database path could not be read.
    ReadMetadata {
        /// Path that could not be read.
        path: PathBuf,
        /// Filesystem error.
        source: io::Error,
    },
    /// `state.db` exists and is a directory.
    DatabasePathIsDirectory {
        /// Path that was a directory.
        path: PathBuf,
    },
    /// The path exists and is not a SQLite database.
    NotADatabase {
        /// Path that was refused.
        path: PathBuf,
        /// SQLite error.
        source: rusqlite::Error,
    },
    /// SQLite rejected an open or a read of schema metadata.
    Sqlite {
        /// Database path.
        path: PathBuf,
        /// SQLite error.
        source: rusqlite::Error,
    },
    /// The file's schema version is not the version this process can open.
    ///
    /// `found` is `None` when the file has tables but no `schema_meta` row.
    IncompatibleSchema {
        /// Database path. The file is unchanged.
        path: PathBuf,
        /// Version stored in the file, when one was readable.
        found: Option<i64>,
        /// Version this process knows how to open.
        expected: i64,
    },
    /// A canonical resource field was empty.
    EmptyIdentity,
    /// A canonical resource field exceeded 4096 bytes.
    IdentityTooLong,
    /// A canonical resource field contained a NUL byte.
    EmbeddedNul,
    /// Text was not a canonical resource produced by this crate.
    InvalidCanonicalResource,
    /// An unsigned integer does not fit in a SQLite INTEGER.
    IntegerOutOfRange,
    /// No execution row uses this id.
    ExecutionNotFound {
        /// Canonical execution id.
        id: String,
    },
    /// `finish_execution` was called for an execution that is already finished.
    ExecutionAlreadyFinished {
        /// Canonical execution id.
        id: String,
    },
    /// `COMPLETE` was paired with at least one unsupported domain.
    ///
    /// The store does not rewrite that pair into another coverage status.
    CompleteWhileUnsupported,
    /// The command program was empty, contained NUL, or exceeded 4096 bytes.
    InvalidCommandProgram,
    /// The argument count was above 256. Argument values are not stored.
    ArgCountOutOfRange,
    /// Version text was empty, contained NUL, or exceeded 128 bytes.
    InvalidVersionText,
    /// The text was not a canonical execution id.
    InvalidExecutionId,
    /// The clock could not supply a millisecond timestamp inside 48 bits.
    ClockOutOfRange,
    /// Every id for the current millisecond prefix was already issued.
    ExecutionIdExhausted,
    /// A stored execution row broke an invariant this repository can read.
    CorruptExecution,
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateStateDir { path, source } => {
                write!(formatter, "create {}: {source}", path.display())
            }
            Self::ReadMetadata { path, source } => {
                write!(formatter, "read {}: {source}", path.display())
            }
            Self::DatabasePathIsDirectory { path } => {
                write!(formatter, "{} is a directory", path.display())
            }
            Self::NotADatabase { path, source } => {
                write!(formatter, "{} is not a database: {source}", path.display())
            }
            Self::Sqlite { path, source } => {
                write!(formatter, "{}: {source}", path.display())
            }
            Self::IncompatibleSchema {
                path,
                found,
                expected,
            } => match found {
                Some(found) => write!(
                    formatter,
                    "{} has schema version {found}; this store opens version {expected}",
                    path.display()
                ),
                None => write!(
                    formatter,
                    "{} has no schema version; this store opens version {expected}",
                    path.display()
                ),
            },
            Self::EmptyIdentity => formatter.write_str("canonical resource field is empty"),
            Self::IdentityTooLong => {
                formatter.write_str("canonical resource field exceeds 4096 bytes")
            }
            Self::EmbeddedNul => {
                formatter.write_str("canonical resource field contains a NUL byte")
            }
            Self::InvalidCanonicalResource => {
                formatter.write_str("canonical resource text is not valid")
            }
            Self::IntegerOutOfRange => {
                formatter.write_str("value does not fit in a SQLite INTEGER")
            }
            Self::ExecutionNotFound { id } => {
                write!(formatter, "execution {id} is unknown")
            }
            Self::ExecutionAlreadyFinished { id } => {
                write!(formatter, "execution {id} is already finished")
            }
            Self::CompleteWhileUnsupported => {
                formatter.write_str("COMPLETE coverage cannot include an unsupported domain")
            }
            Self::InvalidCommandProgram => {
                formatter.write_str("command program is empty, contains NUL, or exceeds 4096 bytes")
            }
            Self::ArgCountOutOfRange => formatter.write_str("argument count exceeds 256"),
            Self::InvalidVersionText => {
                formatter.write_str("version text is empty, contains NUL, or exceeds 128 bytes")
            }
            Self::InvalidExecutionId => {
                formatter.write_str("execution id must be 32 lowercase hex characters")
            }
            Self::ClockOutOfRange => formatter.write_str("clock is outside the execution id range"),
            Self::ExecutionIdExhausted => formatter.write_str("execution id space is exhausted"),
            Self::CorruptExecution => formatter.write_str("execution row cannot be read honestly"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CreateStateDir { source, .. } | Self::ReadMetadata { source, .. } => Some(source),
            Self::NotADatabase { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::DatabasePathIsDirectory { .. }
            | Self::IncompatibleSchema { .. }
            | Self::EmptyIdentity
            | Self::IdentityTooLong
            | Self::EmbeddedNul
            | Self::InvalidCanonicalResource
            | Self::IntegerOutOfRange
            | Self::ExecutionNotFound { .. }
            | Self::ExecutionAlreadyFinished { .. }
            | Self::CompleteWhileUnsupported
            | Self::InvalidCommandProgram
            | Self::ArgCountOutOfRange
            | Self::InvalidVersionText
            | Self::InvalidExecutionId
            | Self::ClockOutOfRange
            | Self::ExecutionIdExhausted
            | Self::CorruptExecution => None,
        }
    }
}
