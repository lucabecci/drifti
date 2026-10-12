// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-006 acceptance, privacy, and failure matrix for `drifti-store`.
//!
//! Criteria 1–6 from SPEC-006 are locked here with deterministic tests.
//! `INCOMPLETE` and `UNSUPPORTED` must not become success, and a storage
//! failure must not be recorded as `COMPLETE` coverage.

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use drifti_observer::{
    EvidenceMeta, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation, Outcome,
    ParentIdentity, ProcessIdentity,
};
use drifti_store::{
    canonical_resource, CanonicalResource, CapabilityDomain, CommandMetadata, CoverageStatus,
    EventBatchWriter, ExecutionHistory, ExecutionId, FinishExecution, Lifecycle, ProcessRecord,
    Store, StoreError, DATABASE_FILE, SCHEMA_VERSION, STATE_DIR,
};
use rusqlite::{params, Connection};

const EXECUTION_ID: &str = "0123456789abcdef0123456789abcdef";

const ARGV_SENTINEL: &str = "matrix-argv-must-not-persist";
const SECRET_SENTINEL: &str = "matrix-secret-must-not-persist";
const PROMPT_SENTINEL: &str = "matrix-prompt-must-not-persist";
const RESPONSE_SENTINEL: &str = "matrix-model-response-must-not-persist";
const FILE_BYTES_SENTINEL: &str = "matrix-file-bytes-must-not-persist";
const PAYLOAD_SENTINEL: &str = "matrix-network-payload-must-not-persist";

const SENSITIVE: &[&str] = &[
    ARGV_SENTINEL,
    SECRET_SENTINEL,
    PROMPT_SENTINEL,
    RESPONSE_SENTINEL,
    FILE_BYTES_SENTINEL,
    PAYLOAD_SENTINEL,
];

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
            "drifti-store-matrix-{name}-{}-{nanos}-{id}",
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

fn assert_absent(bytes: &[u8], sentinel: &str) {
    assert!(
        !bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes()),
        "{sentinel} was persisted in state.db"
    );
}

fn assert_no_sensitive(bytes: &[u8]) {
    for sentinel in SENSITIVE {
        assert_absent(bytes, sentinel);
    }
}

fn open_sql(path: &Path) -> Connection {
    let connection = Connection::open(path).expect("open database");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("foreign keys");
    connection
}

fn event(
    id: &ExecutionId,
    sequence: u64,
    nanos: u64,
    path: &str,
    evidence: EvidenceMeta,
) -> ObservedEvent {
    ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        sequence,
        MonotonicTimestamp::from_nanos(nanos),
        ProcessIdentity::new(Some(10), Some(11)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file(path).expect("path"),
        Outcome::success(),
        evidence,
    )
}

fn seed_legacy_history(path: &Path) {
    let resource =
        canonical_resource(CanonicalResource::File("/tmp/matrix-kept")).expect("canonical");
    let connection = open_sql(path);
    connection
        .execute(
            "INSERT INTO executions (
                execution_id, lifecycle, coverage_status, exit_code,
                command_program, arg_count, contract_version, tool_version
             ) VALUES (?1, 'finished', 'INCOMPLETE', 9, 'matrix-tool', 3, 'c-1', 't-1')",
            [EXECUTION_ID],
        )
        .expect("execution");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, tid, parent_pid)
             VALUES (?1, 1, NULL, NULL)",
            [EXECUTION_ID],
        )
        .expect("root");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, tid, parent_pid)
             VALUES (?1, 9, 10, 1)",
            [EXECUTION_ID],
        )
        .expect("child");
    connection
        .execute(
            "INSERT INTO events (
                execution_id, sequence, monotonic_nanos, pid, tid, parent_pid,
                action, resource_kind, canonical_resource, outcome_status
             ) VALUES (?1, 0, 3, 9, 10, 1, 'filesystem.read', 'file', ?2, 'success')",
            params![EXECUTION_ID, resource],
        )
        .expect("event");
}

fn legacy_without_failure_table(workspace: &Path) -> PathBuf {
    let store = Store::open(workspace).expect("create schema");
    let path = store.path().to_path_buf();
    drop(store);
    seed_legacy_history(&path);
    open_sql(&path)
        .execute_batch("DROP TABLE execution_event_failures;")
        .expect("drop failure table");
    path
}

#[test]
fn matrix_execution_create_read_and_finish_survives_restart() {
    let workspace = TempWorkspace::new("execution");
    let mut store = Store::open(workspace.path()).expect("open");
    let command = CommandMetadata::try_new("matrix-tool", 4).expect("command");
    let created = store.create_execution(Some(command)).expect("create");
    assert_eq!(created.lifecycle(), Lifecycle::Started);
    assert!(created.coverage().is_none());
    assert!(!created.is_complete());

    let read = store.get_execution(created.id()).expect("read");
    assert_eq!(read, created);

    let finish = FinishExecution::try_new(
        CoverageStatus::Incomplete,
        [CapabilityDomain::Network],
        Some(2),
        Some("matrix-contract"),
        Some("matrix-tool"),
    )
    .expect("finish");
    let finished = store
        .finish_execution(created.id(), finish)
        .expect("finish");
    assert_eq!(finished.lifecycle(), Lifecycle::Finished);
    assert_eq!(finished.coverage(), Some(CoverageStatus::Incomplete));
    assert!(!finished.is_complete());
    assert_eq!(finished.exit_code(), Some(2));

    drop(store);
    let store = Store::open(workspace.path()).expect("restart");
    let loaded = store.get_execution(created.id()).expect("after restart");
    assert_eq!(loaded, finished);
    assert_eq!(loaded.command().expect("command").program(), "matrix-tool");
    assert_eq!(loaded.command().expect("command").arg_count(), 4);
}

#[test]
fn matrix_process_lineage_survives_reopen() {
    let workspace = TempWorkspace::new("lineage");
    let mut store = Store::open(workspace.path()).expect("open");
    let execution = store
        .create_execution(None)
        .expect("execution")
        .id()
        .clone();
    store
        .record_process(
            &execution,
            ProcessRecord::try_new(1, Some(1), None).expect("root"),
        )
        .expect("root");
    store
        .record_process(
            &execution,
            ProcessRecord::try_new(2, Some(20), Some(1)).expect("child"),
        )
        .expect("child");
    let before = store.process_lineage(&execution, 2).expect("lineage");
    assert_eq!(
        before
            .ancestors()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1]
    );
    drop(store);

    let store = Store::open(workspace.path()).expect("reopen");
    let after = store
        .process_lineage(&execution, 2)
        .expect("lineage after reopen");
    assert_eq!(after, before);
    assert_eq!(
        store
            .processes(&execution)
            .expect("list")
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn matrix_ordered_event_batch_rolls_back_and_blocks_complete_coverage() {
    let workspace = TempWorkspace::new("events");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = store.create_execution(None).expect("create").id().clone();
    let writer = EventBatchWriter::new(NonZeroUsize::new(4).expect("limit"));
    let ordered = vec![
        event(&id, 2, 1, "/tmp/second", EvidenceMeta::empty()),
        event(&id, 0, 99, "/tmp/first", EvidenceMeta::empty()),
        event(&id, 1, 5, "/tmp/middle", EvidenceMeta::empty()),
    ];
    writer
        .write_batch(&mut store, &id, ordered)
        .expect("transactional batch");
    let sequences: Vec<i64> = open_sql(store.path())
        .prepare("SELECT sequence FROM events WHERE execution_id = ?1 ORDER BY sequence")
        .expect("prepare")
        .query_map(params![id.as_str()], |row| row.get(0))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows");
    assert_eq!(sequences, vec![0, 1, 2]);

    let duplicate = vec![
        event(&id, 3, 7, "/tmp/kept", EvidenceMeta::empty()),
        event(&id, 3, 8, "/tmp/lost", EvidenceMeta::empty()),
    ];
    let error = writer
        .write_batch(&mut store, &id, duplicate)
        .expect_err("duplicate sequence rolls back");
    assert!(matches!(
        error.store_error(),
        StoreError::DuplicateEventSequence
    ));
    assert!(!error.allows_complete_coverage());
    assert_eq!(sequences.len(), 3);

    let complete = FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
        .expect("complete finish");
    assert!(matches!(
        store.finish_execution(&id, complete),
        Err(StoreError::StorageFailureBlocksComplete)
    ));
    let record = store.get_execution(&id).expect("execution");
    assert!(record.coverage().is_none());
    assert!(!record.is_complete());
}

#[test]
fn matrix_migration_and_reopen_preserve_execution_history() {
    let workspace = TempWorkspace::new("history");
    let path = legacy_without_failure_table(workspace.path());
    let before_events: i64 = open_sql(&path)
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("events");
    let before_processes: i64 = open_sql(&path)
        .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
        .expect("processes");
    assert_eq!(before_events, 1);
    assert_eq!(before_processes, 2);

    let store = Store::open(workspace.path()).expect("migrate");
    assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
    let id = ExecutionId::parse(EXECUTION_ID).expect("id");
    let history = store.execution_history(&id).expect("history");
    assert_eq!(history.events().len(), 1);
    assert_eq!(history.processes().len(), 2);
    assert_eq!(history.execution().exit_code(), Some(9));
    drop(store);

    let store = Store::open(workspace.path()).expect("reopen");
    let again = store.execution_history(&id).expect("history after reopen");
    assert_eq!(again.events().len(), 1);
    assert_eq!(again.processes().len(), 2);
    let events_after: i64 = open_sql(&path)
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .expect("events");
    assert_eq!(events_after, before_events);
    let processes_after: i64 = open_sql(&path)
        .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
        .expect("processes");
    assert_eq!(processes_after, before_processes);
}

#[test]
fn matrix_state_db_omits_sensitive_argv_payloads_secrets_prompts_and_file_bytes() {
    let workspace = TempWorkspace::new("privacy");
    let mut store = Store::open(workspace.path()).expect("open");
    let _argv = ARGV_SENTINEL;
    let _secret = SECRET_SENTINEL;
    let _prompt = PROMPT_SENTINEL;
    let _response = RESPONSE_SENTINEL;
    let _file_bytes = FILE_BYTES_SENTINEL;
    let _payload = PAYLOAD_SENTINEL;

    let command = CommandMetadata::try_new("matrix-tool", 6).expect("command");
    let id = store
        .create_execution(Some(command))
        .expect("create")
        .id()
        .clone();
    let network = ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        1,
        MonotonicTimestamp::from_nanos(2),
        ProcessIdentity::new(Some(4), None),
        None,
        Operation::NetworkConnect,
        ObservedResource::network("matrix.example", 443).expect("host"),
        Outcome::success(),
        EvidenceMeta::with_byte_length(PAYLOAD_SENTINEL.len() as u64),
    );
    let file_event = event(
        &id,
        0,
        1,
        "/tmp/matrix-read",
        EvidenceMeta::with_byte_length(FILE_BYTES_SENTINEL.len() as u64),
    );
    EventBatchWriter::new(NonZeroUsize::new(2).expect("limit"))
        .write_batch(&mut store, &id, vec![file_event, network])
        .expect("write");
    store
        .finish_execution(
            &id,
            FinishExecution::try_new(CoverageStatus::Incomplete, [], Some(0), None, None)
                .expect("finish"),
        )
        .expect("finish");

    let path = database_path(workspace.path());
    drop(store);
    let bytes = fs::read(&path).expect("state.db bytes");
    assert_no_sensitive(&bytes);

    let connection = Connection::open(&path).expect("inspect");
    let (program, arg_count): (String, i64) = connection
        .query_row(
            "SELECT command_program, arg_count FROM executions WHERE execution_id = ?1",
            params![id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("command metadata");
    assert_eq!(program, "matrix-tool");
    assert_eq!(arg_count, 6);
    let evidence: Option<i64> = connection
        .query_row(
            "SELECT evidence_byte_length FROM events WHERE sequence = 0",
            [],
            |row| row.get(0),
        )
        .expect("evidence length");
    assert_eq!(
        evidence,
        Some(i64::try_from(FILE_BYTES_SENTINEL.len()).expect("length"))
    );
}

#[test]
fn matrix_injected_storage_failure_blocks_complete_and_incomplete_is_not_success() {
    let workspace = TempWorkspace::new("failure");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = store.create_execution(None).expect("create").id().clone();
    let writer = EventBatchWriter::new(NonZeroUsize::new(2).expect("limit"));
    let failed = vec![
        event(&id, 1, 1, "/tmp/a", EvidenceMeta::empty()),
        event(&id, 1, 2, "/tmp/b", EvidenceMeta::empty()),
    ];
    let error = writer
        .write_batch(&mut store, &id, failed)
        .expect_err("injected storage failure");
    assert_eq!(error.coverage(), CoverageStatus::Incomplete);
    assert!(!error.allows_complete_coverage());
    assert!(!error.downgrade(CoverageStatus::Complete).is_complete());

    let complete = FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
        .expect("complete");
    assert!(matches!(
        store.finish_execution(&id, complete),
        Err(StoreError::StorageFailureBlocksComplete)
    ));

    let incomplete = FinishExecution::try_new(
        error.downgrade(CoverageStatus::Complete),
        [],
        Some(17),
        None,
        None,
    )
    .expect("incomplete finish");
    let finished = store
        .finish_execution(&id, incomplete)
        .expect("finish incomplete");
    assert_eq!(finished.coverage(), Some(CoverageStatus::Incomplete));
    assert!(!finished.is_complete());
    assert_ne!(finished.coverage(), Some(CoverageStatus::Complete));
    let history: ExecutionHistory = store.execution_history(&id).expect("history");
    assert!(history.events().is_empty());
    assert!(!history.execution().is_complete());
}
