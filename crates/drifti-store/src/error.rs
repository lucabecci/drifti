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
            | Self::IntegerOutOfRange => None,
        }
    }
}
