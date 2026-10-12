// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema migration and restart recovery for the execution store.
//!
//! Fixtures are SQL run by the test. Nothing here is an opaque database file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use drifti_observer::{
    EvidenceMeta, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation, Outcome,
    ParentIdentity, ProcessIdentity,
};
use drifti_store::{
    canonical_resource, CanonicalResource, CapabilityDomain, CommandMetadata, CoverageStatus,
    EventBatchWriter, ExecutionId, FinishExecution, Lifecycle, ProcessRecord, Store, StoreError,
    DATABASE_FILE, STATE_DIR,
};
use rusqlite::{params, Connection};

const EXECUTION_ID: &str = "0123456789abcdef0123456789abcdef";

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
            "drifti-store-migrate-{name}-{}-{nanos}-{id}",
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

fn open_sql(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open database");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("foreign keys");
    connection
}

fn seed_history(path: &Path) {
    let resource =
        canonical_resource(CanonicalResource::File("/tmp/kept")).expect("canonical resource");
    let connection = open_sql(path);
    connection
        .execute(
            "INSERT INTO executions (
                execution_id, lifecycle, coverage_status, exit_code,
                command_program, arg_count, contract_version, tool_version
             ) VALUES (?1, 'finished', 'INCOMPLETE', 3, 'tool', 2, 'contract-a', 'tool-a')",
            [EXECUTION_ID],
        )
        .expect("execution");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, tid, parent_pid)
             VALUES (?1, 1, NULL, NULL)",
            [EXECUTION_ID],
        )
        .expect("parent");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, tid, parent_pid)
             VALUES (?1, 7, 8, 1)",
            [EXECUTION_ID],
        )
        .expect("child");
    connection
        .execute(
            "INSERT INTO events (
                execution_id, sequence, monotonic_nanos, pid, tid, parent_pid,
                action, resource_kind, canonical_resource, outcome_status
             ) VALUES (?1, 0, 5, 7, 8, 1, 'filesystem.read', 'file', ?2, 'success')",
            params![EXECUTION_ID, resource],
        )
        .expect("event");
}

fn legacy_version_one(workspace: &Path) -> PathBuf {
    let store = Store::open(workspace).expect("create current schema");
    let path = store.path().to_path_buf();
    drop(store);
    seed_history(&path);
    open_sql(&path)
        .execute_batch("DROP TABLE execution_event_failures;")
        .expect("drop failure table");
    path
}

fn execution_id() -> ExecutionId {
    ExecutionId::parse(EXECUTION_ID).expect("execution id")
}

fn schema_objects(path: &Path) -> Vec<(String, String, String, Option<String>)> {
    let connection = open_sql(path);
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

fn schema_cookie(path: &Path) -> i64 {
    open_sql(path)
        .pragma_query_value(None, "schema_version", |row| row.get(0))
        .expect("schema cookie")
}

fn user_version(path: &Path) -> i64 {
    open_sql(path)
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user_version")
}

fn count_sql(path: &Path, sql: &str) -> i64 {
    open_sql(path)
        .query_row(sql, [], |row| row.get(0))
        .expect("count")
}

fn journal_paths(path: &Path) -> [PathBuf; 2] {
    let name = path.file_name().expect("file name");
    let mut journal = name.to_os_string();
    journal.push("-journal");
    let mut wal = name.to_os_string();
    wal.push("-wal");
    [path.with_file_name(journal), path.with_file_name(wal)]
}

#[test]
fn restart_reopens_execution_history() {
    let workspace = TempWorkspace::new("restart");
    let mut store = Store::open(workspace.path()).expect("open");
    let created = store
        .create_execution(Some(CommandMetadata::try_new("tool", 2).expect("command")))
        .expect("create");
    let id = created.id().clone();
    store
        .record_process(&id, ProcessRecord::try_new(1, None, None).expect("parent"))
        .expect("record parent");
    store
        .record_process(
            &id,
            ProcessRecord::try_new(7, Some(8), Some(1)).expect("child"),
        )
        .expect("record child");
    let event = ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        4,
        MonotonicTimestamp::from_nanos(9),
        ProcessIdentity::new(Some(7), Some(8)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file("/tmp/kept").expect("path"),
        Outcome::success(),
        EvidenceMeta::empty(),
    );
    EventBatchWriter::with_default_limit()
        .write_batch(&mut store, &id, vec![event])
        .expect("write event");
    let finish = FinishExecution::try_new(
        CoverageStatus::Incomplete,
        [CapabilityDomain::Network],
        Some(0),
        Some("contract-a"),
        Some("tool-a"),
    )
    .expect("finish value");
    store.finish_execution(&id, finish).expect("finish");
    let history = store.execution_history(&id).expect("history");
    let lineage = store.process_lineage(&id, 7).expect("lineage");
    assert_eq!(store.schema_version().expect("version"), 1);
    drop(store);

    let store = Store::open(workspace.path()).expect("reopen");
    assert_eq!(store.schema_version().expect("version"), 1);
    assert_eq!(store.execution_history(&id).expect("history"), history);
    assert_eq!(store.process_lineage(&id, 7).expect("lineage"), lineage);
    assert_eq!(store.list_executions().expect("list").len(), 1);
    let record = store.get_execution(&id).expect("execution");
    assert_eq!(record.lifecycle(), Lifecycle::Finished);
    assert_eq!(record.coverage(), Some(CoverageStatus::Incomplete));
    assert_eq!(record.unsupported_domains().len(), 1);
    assert!(record
        .unsupported_domains()
        .contains(&CapabilityDomain::Network));
}

#[test]
fn a_legacy_version_one_database_migrates_without_a_version_bump() {
    let workspace = TempWorkspace::new("legacy");
    let path = legacy_version_one(workspace.path());
    let store = Store::open(workspace.path()).expect("migrate");
    assert_eq!(store.schema_version().expect("version"), 1);
    let id = execution_id();
    let history = store.execution_history(&id).expect("history");
    assert_eq!(history.execution().lifecycle(), Lifecycle::Finished);
    assert_eq!(history.execution().exit_code(), Some(3));
    assert_eq!(
        history.execution().command().expect("command").program(),
        "tool"
    );
    assert_eq!(
        history.execution().command().expect("command").arg_count(),
        2
    );
    assert_eq!(history.execution().contract_version(), Some("contract-a"));
    assert_eq!(history.execution().tool_version(), Some("tool-a"));
    assert_eq!(history.events().len(), 1);
    assert_eq!(history.events()[0].sequence(), 0);
    assert_eq!(history.events()[0].operation(), Operation::FilesystemRead);
    assert_eq!(history.processes().len(), 2);
    assert_eq!(history.processes()[0].pid(), 1);
    assert_eq!(history.processes()[1].pid(), 7);
    assert_eq!(history.processes()[1].parent_pid(), Some(1));
    drop(store);

    open_sql(&path)
        .execute(
            "INSERT INTO execution_event_failures (execution_id) VALUES (?1)",
            [EXECUTION_ID],
        )
        .expect("marker");
    let bytes = fs::read(&path).expect("bytes after marker");
    let cookie = schema_cookie(&path);
    assert_eq!(user_version(&path), 1);
    assert_eq!(count_sql(&path, "SELECT COUNT(*) FROM schema_meta"), 1);

    let store = Store::open(workspace.path()).expect("second open");
    assert_eq!(store.execution_history(&id).expect("history"), history);
    assert_eq!(store.schema_version().expect("version"), 1);
    drop(store);

    assert_eq!(fs::read(&path).expect("bytes after second open"), bytes);
    assert_eq!(schema_cookie(&path), cookie);
    assert_eq!(user_version(&path), 1);
    let marker: i64 = open_sql(&path)
        .query_row(
            "SELECT COUNT(*) FROM execution_event_failures WHERE execution_id = ?1",
            [EXECUTION_ID],
            |row| row.get(0),
        )
        .expect("marker count");
    assert_eq!(marker, 1);
    assert_eq!(
        count_sql(
            &path,
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'execution_event_failures'"
        ),
        1
    );
    for extra in journal_paths(&path) {
        assert!(!extra.exists(), "partial file at {}", extra.display());
    }

    let fresh = TempWorkspace::new("fresh-schema");
    drop(Store::open(fresh.path()).expect("fresh"));
    assert_eq!(
        schema_objects(&path),
        schema_objects(&database_path(fresh.path()))
    );
}

#[test]
fn two_legacy_databases_migrate_to_the_same_schema() {
    let first = TempWorkspace::new("legacy-a");
    let second = TempWorkspace::new("legacy-b");
    legacy_version_one(first.path());
    legacy_version_one(second.path());
    drop(Store::open(first.path()).expect("migrate first"));
    drop(Store::open(second.path()).expect("migrate second"));
    assert_eq!(
        schema_objects(&database_path(first.path())),
        schema_objects(&database_path(second.path()))
    );
    assert_eq!(user_version(&database_path(first.path())), 1);
    assert_eq!(user_version(&database_path(second.path())), 1);
    for workspace in [first.path(), second.path()] {
        let store = Store::open(workspace).expect("reopen");
        let history = store.execution_history(&execution_id()).expect("history");
        assert_eq!(history.events().len(), 1);
        assert_eq!(history.processes().len(), 2);
        assert_eq!(store.schema_version().expect("version"), 1);
    }
}

#[test]
fn a_future_schema_version_is_preserved_and_rejected() {
    let workspace = TempWorkspace::new("future");
    let store = Store::open(workspace.path()).expect("create");
    let path = store.path().to_path_buf();
    drop(store);
    seed_history(&path);
    let connection = open_sql(&path);
    connection
        .execute("UPDATE schema_meta SET version = 2", [])
        .expect("bump schema_meta");
    connection
        .pragma_update(None, "user_version", 2i64)
        .expect("bump header");
    drop(connection);

    let before = fs::read(&path).expect("bytes before");
    let error = Store::open(workspace.path()).expect_err("version 2 opened");
    assert!(matches!(
        error,
        StoreError::IncompatibleSchema {
            found: Some(2),
            expected: 1,
            ..
        }
    ));
    assert_eq!(fs::read(&path).expect("bytes after"), before);
    assert!(path.is_file());
    for extra in journal_paths(&path) {
        assert!(!extra.exists(), "partial file at {}", extra.display());
    }
    assert_eq!(count_sql(&path, "SELECT COUNT(*) FROM executions"), 1);
    assert_eq!(count_sql(&path, "SELECT COUNT(*) FROM processes"), 2);
    assert_eq!(count_sql(&path, "SELECT COUNT(*) FROM events"), 1);
    let program: String = open_sql(&path)
        .query_row(
            "SELECT command_program FROM executions WHERE execution_id = ?1",
            [EXECUTION_ID],
            |row| row.get(0),
        )
        .expect("program");
    assert_eq!(program, "tool");
}
