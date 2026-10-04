// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema v1 acceptance checks for the execution store.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use drifti_store::{Store, StoreError, DATABASE_FILE, PROHIBITED_COLUMN_NAMES, STATE_DIR};

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "drifti-store-schema-{name}-{}-{nanos}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create workspace");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn database_path(workspace: &Path) -> PathBuf {
    workspace.join(STATE_DIR).join(DATABASE_FILE)
}

fn open_inspect(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("inspect database");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable foreign keys");
    connection
}

fn user_version(path: &Path) -> i64 {
    open_inspect(path)
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user_version")
}

fn schema_objects(path: &Path) -> Vec<(String, String, String, Option<String>)> {
    let connection = open_inspect(path);
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
        .expect("prepare sqlite_master");
    let rows = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query sqlite_master");
    rows.collect::<Result<Vec<_>, _>>().expect("schema rows")
}

fn column_names(path: &Path, table: &str) -> Vec<String> {
    let connection = open_inspect(path);
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("prepare table_info");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .expect("query columns");
    rows.collect::<Result<Vec<_>, _>>().expect("column names")
}

fn column_types(path: &Path, table: &str) -> Vec<String> {
    let connection = open_inspect(path);
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("prepare table_info");
    let rows = statement
        .query_map([], |row| row.get::<_, String>(2))
        .expect("query types");
    rows.collect::<Result<Vec<_>, _>>().expect("column types")
}

fn index_columns(path: &Path, table: &str) -> Vec<(String, bool, Vec<String>)> {
    let connection = open_inspect(path);
    let mut list = connection
        .prepare(&format!("PRAGMA index_list({table})"))
        .expect("prepare index_list");
    let indexes = list
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)? == 1))
        })
        .expect("query indexes")
        .collect::<Result<Vec<_>, _>>()
        .expect("indexes");
    indexes
        .into_iter()
        .map(|(name, unique)| {
            let mut info = connection
                .prepare(&format!("PRAGMA index_info({name})"))
                .expect("prepare index_info");
            let columns = info
                .query_map([], |row| row.get::<_, String>(2))
                .expect("query index columns")
                .collect::<Result<Vec<_>, _>>()
                .expect("index columns");
            (name, unique, columns)
        })
        .collect()
}

fn has_index(indexes: &[(String, bool, Vec<String>)], columns: &[&str], unique: bool) -> bool {
    indexes.iter().any(|(_, is_unique, found)| {
        *is_unique == unique
            && found.len() == columns.len()
            && found
                .iter()
                .zip(columns.iter())
                .all(|(left, right)| left == right)
    })
}

#[test]
fn fresh_database_is_created_under_dot_drifti_with_version_one() {
    let workspace = TempWorkspace::new("fresh");
    let store = Store::open(workspace.path()).expect("open");
    let path = database_path(workspace.path());
    assert_eq!(store.path(), path.as_path());
    assert!(path.is_file());
    assert_eq!(store.schema_version().expect("version"), 1);
    drop(store);
    assert_eq!(user_version(&path), 1);
}

#[test]
fn two_fresh_databases_have_the_same_schema() {
    let first = TempWorkspace::new("schema-a");
    let second = TempWorkspace::new("schema-b");
    drop(Store::open(first.path()).expect("open first"));
    drop(Store::open(second.path()).expect("open second"));
    assert_eq!(
        schema_objects(&database_path(first.path())),
        schema_objects(&database_path(second.path()))
    );
}

#[test]
fn schema_lists_execution_process_and_event_columns() {
    let workspace = TempWorkspace::new("columns");
    drop(Store::open(workspace.path()).expect("open"));
    let path = database_path(workspace.path());
    assert_eq!(column_names(&path, "schema_meta"), ["singleton", "version"]);
    assert_eq!(
        column_names(&path, "executions"),
        [
            "execution_id",
            "lifecycle",
            "coverage_status",
            "exit_code",
            "command_program",
            "arg_count",
            "contract_version",
            "tool_version",
        ]
    );
    assert_eq!(
        column_names(&path, "execution_unsupported_domains"),
        ["execution_id", "domain"]
    );
    assert_eq!(
        column_names(&path, "processes"),
        ["execution_id", "pid", "tid", "parent_pid"]
    );
    assert_eq!(
        column_names(&path, "events"),
        [
            "execution_id",
            "sequence",
            "monotonic_nanos",
            "pid",
            "tid",
            "parent_pid",
            "action",
            "resource_kind",
            "canonical_resource",
            "outcome_status",
            "errno",
            "failure_reason",
            "evidence_byte_length",
        ]
    );
    for table in [
        "schema_meta",
        "executions",
        "execution_unsupported_domains",
        "processes",
        "events",
    ] {
        for declared in column_types(&path, table) {
            assert_ne!(
                declared.to_ascii_lowercase(),
                "blob",
                "{table} has a BLOB column"
            );
        }
    }
}

#[test]
fn required_indexes_cover_execution_sequence_action_and_resource() {
    let workspace = TempWorkspace::new("indexes");
    drop(Store::open(workspace.path()).expect("open"));
    let indexes = index_columns(&database_path(workspace.path()), "events");
    assert!(
        has_index(&indexes, &["execution_id"], false),
        "missing execution_id index: {indexes:?}"
    );
    assert!(
        has_index(&indexes, &["execution_id", "sequence"], true),
        "missing execution_id+sequence index: {indexes:?}"
    );
    assert!(
        has_index(&indexes, &["action"], false),
        "missing action index: {indexes:?}"
    );
    assert!(
        has_index(&indexes, &["canonical_resource"], false),
        "missing canonical resource index: {indexes:?}"
    );
}

#[test]
fn schema_has_no_prohibited_payload_columns() {
    let workspace = TempWorkspace::new("privacy");
    drop(Store::open(workspace.path()).expect("open"));
    let path = database_path(workspace.path());
    let mut names = Vec::new();
    for table in [
        "schema_meta",
        "executions",
        "execution_unsupported_domains",
        "processes",
        "events",
    ] {
        names.extend(column_names(&path, table));
    }
    for prohibited in PROHIBITED_COLUMN_NAMES {
        assert!(
            !names.iter().any(|name| name == prohibited),
            "column {prohibited} would persist prohibited data"
        );
    }
}

#[test]
fn reopening_keeps_rows_and_does_not_reset_the_version() {
    let workspace = TempWorkspace::new("reopen");
    let store = Store::open(workspace.path()).expect("create");
    let path = store.path().to_path_buf();
    drop(store);
    open_inspect(&path)
        .execute(
            "INSERT INTO executions (execution_id, lifecycle, coverage_status, command_program, arg_count)
             VALUES ('exec-1', 'finished', 'INCOMPLETE', 'tool', 0)",
            [],
        )
        .expect("insert execution");
    let store = Store::open(workspace.path()).expect("reopen");
    assert_eq!(store.schema_version().expect("version"), 1);
    drop(store);
    let count: i64 = open_inspect(&path)
        .query_row("SELECT COUNT(*) FROM executions", [], |row| row.get(0))
        .expect("count");
    assert_eq!(count, 1);
    let versions: i64 = open_inspect(&path)
        .query_row("SELECT COUNT(*) FROM schema_meta", [], |row| row.get(0))
        .expect("schema rows");
    assert_eq!(versions, 1);
}

#[test]
fn the_same_pid_in_two_executions_does_not_alias() {
    let workspace = TempWorkspace::new("pid");
    drop(Store::open(workspace.path()).expect("open"));
    let connection = open_inspect(&database_path(workspace.path()));
    connection
        .execute_batch(
            "INSERT INTO executions (execution_id, lifecycle) VALUES ('exec-a', 'started');
             INSERT INTO executions (execution_id, lifecycle) VALUES ('exec-b', 'started');
             INSERT INTO processes (execution_id, pid, parent_pid) VALUES ('exec-a', 7, NULL);
             INSERT INTO processes (execution_id, pid, parent_pid) VALUES ('exec-b', 7, NULL);",
        )
        .expect("same pid in two executions");
    let duplicate = connection.execute(
        "INSERT INTO processes (execution_id, pid) VALUES ('exec-a', 7)",
        [],
    );
    assert!(
        duplicate.is_err(),
        "one execution accepted the same pid twice"
    );
}

#[test]
fn a_process_row_requires_its_execution() {
    let workspace = TempWorkspace::new("fk");
    drop(Store::open(workspace.path()).expect("open"));
    let error = open_inspect(&database_path(workspace.path())).execute(
        "INSERT INTO processes (execution_id, pid) VALUES ('missing', 1)",
        [],
    );
    assert!(error.is_err(), "process row survived without an execution");
}

#[test]
fn an_incompatible_version_is_preserved_and_rejected() {
    let workspace = TempWorkspace::new("incompatible");
    let path = database_path(workspace.path());
    fs::create_dir_all(path.parent().expect("parent")).expect("create .drifti");
    let connection = Connection::open(&path).expect("seed");
    connection
        .execute_batch(
            "CREATE TABLE schema_meta (singleton INTEGER PRIMARY KEY, version INTEGER NOT NULL);
             INSERT INTO schema_meta (singleton, version) VALUES (1, 99);
             CREATE TABLE sentinel (note TEXT NOT NULL);
             INSERT INTO sentinel (note) VALUES ('keep-me');
             PRAGMA user_version = 99;",
        )
        .expect("seed incompatible database");
    drop(connection);
    let before = fs::read(&path).expect("read before");
    let error = Store::open(workspace.path()).expect_err("incompatible database opened");
    match error {
        StoreError::IncompatibleSchema {
            found: Some(99),
            expected: 1,
            ..
        } => {}
        other => panic!("expected incompatible schema, got {other}"),
    }
    let after = fs::read(&path).expect("read after");
    assert_eq!(before, after, "incompatible history was modified");
    let note: String = Connection::open(&path)
        .expect("reopen sentinel")
        .query_row("SELECT note FROM sentinel", [], |row| row.get(0))
        .expect("sentinel");
    assert_eq!(note, "keep-me");
}

#[test]
fn a_database_without_schema_meta_is_preserved_and_rejected() {
    let workspace = TempWorkspace::new("foreign");
    let path = database_path(workspace.path());
    fs::create_dir_all(path.parent().expect("parent")).expect("create .drifti");
    let connection = Connection::open(&path).expect("seed");
    connection
        .execute("CREATE TABLE sentinel (note TEXT NOT NULL)", [])
        .expect("create sentinel");
    connection
        .execute("INSERT INTO sentinel (note) VALUES ('keep-me')", [])
        .expect("insert sentinel");
    drop(connection);
    let before = fs::read(&path).expect("read before");
    let error = Store::open(workspace.path()).expect_err("foreign database opened");
    assert!(matches!(
        error,
        StoreError::IncompatibleSchema { found: None, .. }
    ));
    assert_eq!(fs::read(&path).expect("read after"), before);
}

#[test]
fn a_version_header_mismatch_is_rejected() {
    let workspace = TempWorkspace::new("mismatch");
    drop(Store::open(workspace.path()).expect("create"));
    let path = database_path(workspace.path());
    Connection::open(&path)
        .expect("open")
        .execute_batch("PRAGMA user_version = 2;")
        .expect("bump header");
    let before = fs::read(&path).expect("read before");
    let error = Store::open(workspace.path()).expect_err("mismatched header opened");
    assert!(matches!(
        error,
        StoreError::IncompatibleSchema {
            found: Some(1),
            expected: 1,
            ..
        }
    ));
    assert_eq!(fs::read(&path).expect("read after"), before);
}

#[test]
fn a_non_database_file_is_preserved_and_rejected() {
    let workspace = TempWorkspace::new("garbage");
    let path = database_path(workspace.path());
    fs::create_dir_all(path.parent().expect("parent")).expect("create .drifti");
    fs::write(&path, b"not a database\n").expect("write garbage");
    let error = Store::open(workspace.path()).expect_err("garbage file opened");
    assert!(
        matches!(error, StoreError::NotADatabase { .. }),
        "expected NotADatabase, got {error:?}"
    );
    assert_eq!(fs::read(&path).expect("read after"), b"not a database\n");
}

#[test]
fn an_empty_file_is_initialized() {
    let workspace = TempWorkspace::new("empty");
    let path = database_path(workspace.path());
    fs::create_dir_all(path.parent().expect("parent")).expect("create .drifti");
    fs::write(&path, b"").expect("write empty");
    let store = Store::open(workspace.path()).expect("initialize empty file");
    assert_eq!(store.schema_version().expect("version"), 1);
}

#[test]
fn success_events_cannot_store_a_failure_reason() {
    let workspace = TempWorkspace::new("outcome");
    drop(Store::open(workspace.path()).expect("open"));
    let connection = open_inspect(&database_path(workspace.path()));
    connection
        .execute(
            "INSERT INTO executions (execution_id, lifecycle) VALUES ('exec-1', 'started')",
            [],
        )
        .expect("execution");
    let rejected = connection.execute(
        "INSERT INTO events (
            execution_id, sequence, monotonic_nanos, action, resource_kind,
            canonical_resource, outcome_status, failure_reason
         ) VALUES ('exec-1', 0, 1, 'filesystem.read', 'file', 'file-id', 'success', 'hidden')",
        [],
    );
    assert!(rejected.is_err(), "success row stored a failure reason");
    connection
        .execute(
            "INSERT INTO events (
                execution_id, sequence, monotonic_nanos, action, resource_kind,
                canonical_resource, outcome_status
             ) VALUES ('exec-1', 1, 2, 'filesystem.read', 'file', 'file-id', 'success')",
            [],
        )
        .expect("success event");
    let stored: Option<String> = connection
        .query_row(
            "SELECT failure_reason FROM events WHERE sequence = 1",
            [],
            |row| row.get(0),
        )
        .expect("read event");
    assert_eq!(stored, None);
}
