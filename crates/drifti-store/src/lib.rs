// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local execution store.
//!
//! The database is `.drifti/state.db` under a workspace root. This crate owns
//! SQLite. `drifti-core` does not open a database and does not issue SQL.
//!
//! [`Store::open`] creates schema version 1 when the file is missing or has
//! no tables. A file that already has that version is left in place. Any
//! other version, or a file that is not a database, is returned as an error
//! and is not deleted.
//!
//! Observation written here is not authorization. `COMPLETE` coverage is a
//! stored declaration, not a policy decision, and this crate does not turn a
//! storage failure into that declaration.
//!
//! [`Store::create_execution`] records a started execution. It does not grant
//! a capability. Command metadata is the program and an argument count;
//! argument values, prompts, and responses are not columns.

#![forbid(unsafe_code)]

mod error;
mod execution;
mod schema;

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

pub use error::StoreError;
pub use execution::{
    CapabilityDomain, CommandMetadata, CoverageStatus, ExecutionId, ExecutionRecord,
    ExecutionRepository, FinishExecution, Lifecycle,
};
pub use schema::{
    canonical_resource, parse_canonical_resource, sqlite_i64, CanonicalResource,
    OwnedCanonicalResource, DATABASE_FILE, MAX_IDENTITY_BYTES, PROHIBITED_COLUMN_NAMES,
    SCHEMA_VERSION, STATE_DIR,
};

use execution::IdGenerator;
use schema::DDL;

/// Open SQLite file under `{workspace}/.drifti/state.db`.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    connection: Connection,
    ids: IdGenerator,
}

impl Store {
    /// Opens or creates the workspace database.
    ///
    /// A second open of a version-1 file does not rewrite its rows. An
    /// incompatible file is not modified.
    pub fn open(workspace: &Path) -> Result<Self, StoreError> {
        let directory = workspace.join(STATE_DIR);
        fs::create_dir_all(&directory).map_err(|source| StoreError::CreateStateDir {
            path: directory.clone(),
            source,
        })?;
        let path = directory.join(DATABASE_FILE);
        if path.is_dir() {
            return Err(StoreError::DatabasePathIsDirectory { path });
        }
        match inspect(&path)? {
            Inspect::Missing | Inspect::Empty => {
                let mut connection = open_read_write(&path)?;
                initialize(&mut connection).map_err(|source| map_sqlite(&path, source))?;
                Ok(Self {
                    path,
                    connection,
                    ids: IdGenerator::new(),
                })
            }
            Inspect::Compatible => {
                let connection = open_read_write(&path)?;
                Ok(Self {
                    path,
                    connection,
                    ids: IdGenerator::new(),
                })
            }
            Inspect::Incompatible { found } => Err(StoreError::IncompatibleSchema {
                path,
                found,
                expected: SCHEMA_VERSION,
            }),
        }
    }

    /// Path of `state.db`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Version stored in `schema_meta`.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        read_schema_version(&self.connection).map_err(|source| map_sqlite(&self.path, source))
    }
}

enum Inspect {
    Missing,
    Empty,
    Compatible,
    Incompatible { found: Option<i64> },
}

fn inspect(path: &Path) -> Result<Inspect, StoreError> {
    if !path.exists() {
        return Ok(Inspect::Missing);
    }
    if path.is_dir() {
        return Err(StoreError::DatabasePathIsDirectory {
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::metadata(path).map_err(|source| StoreError::ReadMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() == 0 {
        return Ok(Inspect::Empty);
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|source| map_sqlite(path, source))?;
    let tables = user_tables(&connection).map_err(|source| map_sqlite(path, source))?;
    if tables.is_empty() {
        return Ok(Inspect::Empty);
    }
    let stored = stored_version(&connection).map_err(|source| map_sqlite(path, source))?;
    let user_version = read_user_version(&connection).map_err(|source| map_sqlite(path, source))?;
    if stored == Some(SCHEMA_VERSION) && user_version == SCHEMA_VERSION {
        Ok(Inspect::Compatible)
    } else {
        Ok(Inspect::Incompatible { found: stored })
    }
}

fn open_read_write(path: &Path) -> Result<Connection, StoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
    let connection =
        Connection::open_with_flags(path, flags).map_err(|source| map_sqlite(path, source))?;
    connection
        .busy_timeout(std::time::Duration::from_millis(2_000))
        .map_err(|source| map_sqlite(path, source))?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|source| map_sqlite(path, source))?;
    Ok(connection)
}

fn initialize(connection: &mut Connection) -> Result<(), rusqlite::Error> {
    let transaction = connection.transaction()?;
    for statement in DDL {
        transaction.execute(statement, [])?;
    }
    transaction.execute(
        "INSERT INTO schema_meta (singleton, version) VALUES (1, ?1)",
        [SCHEMA_VERSION],
    )?;
    // `SCHEMA_VERSION` is a crate constant, not caller input.
    transaction.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    transaction.commit()?;
    Ok(())
}

fn user_tables(connection: &Connection) -> Result<Vec<String>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let rows = statement.query_map([], |row| row.get(0))?;
    rows.collect()
}

fn stored_version(connection: &Connection) -> Result<Option<i64>, rusqlite::Error> {
    let present: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'",
        [],
        |row| row.get(0),
    )?;
    if present == 0 {
        return Ok(None);
    }
    match read_schema_version(connection) {
        Ok(version) => Ok(Some(version)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_schema_version(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.query_row(
        "SELECT version FROM schema_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )
}

fn read_user_version(connection: &Connection) -> Result<i64, rusqlite::Error> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}

fn map_sqlite(path: &Path, source: rusqlite::Error) -> StoreError {
    if is_not_a_database(&source) {
        StoreError::NotADatabase {
            path: path.to_path_buf(),
            source,
        }
    } else {
        StoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        }
    }
}

fn is_not_a_database(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(ffi, _)
            if ffi.code == rusqlite::ErrorCode::NotADatabase
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::Store;

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "drifti-store-{name}-{}-{nanos}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create workspace");
        path
    }

    #[test]
    fn open_enables_foreign_keys() {
        let workspace = workspace("foreign-keys");
        let store = Store::open(&workspace).expect("open");
        let enabled: i64 = store
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("pragma");
        assert_eq!(enabled, 1);
        drop(store);
        let _ = fs::remove_dir_all(workspace);
    }
}
