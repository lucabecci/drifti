// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KAN-55 acceptance checks for the execution lifecycle repository.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use drifti_store::{
    CapabilityDomain, CommandMetadata, CoverageStatus, ExecutionId, ExecutionRecord,
    ExecutionRepository, FinishExecution, Lifecycle, Store, StoreError, DATABASE_FILE, STATE_DIR,
};

const ARGV_SENTINEL: &str = "argv-value-must-not-be-stored";
const SECRET_SENTINEL: &str = "secret-value-must-not-be-stored";
const PROMPT_SENTINEL: &str = "prompt-must-not-be-stored";
const RESPONSE_SENTINEL: &str = "model-response-must-not-be-stored";

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
            "drifti-store-exec-{name}-{}-{nanos}-{id}",
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

fn finish(
    coverage: CoverageStatus,
    domains: impl IntoIterator<Item = CapabilityDomain>,
    exit_code: Option<i32>,
) -> FinishExecution {
    FinishExecution::try_new(coverage, domains, exit_code, Some("1"), Some("0.1.0"))
        .expect("finish metadata")
}

fn assert_absent(bytes: &[u8], sentinel: &str) {
    assert!(
        !bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes()),
        "{sentinel} was persisted"
    );
}

fn round_trip(repo: &mut dyn ExecutionRepository) -> ExecutionRecord {
    let started_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("millis");
    let command = CommandMetadata::try_new("tool'; DROP TABLE executions; --", 0).expect("command");
    let created = repo
        .create_execution(Some(command))
        .expect("create through the repository");
    assert_eq!(created.lifecycle(), Lifecycle::Started);
    assert!(created.coverage().is_none());
    assert!(!created.is_complete());
    assert!(created.id().timestamp_millis() + 5_000 >= started_ms);
    assert_ne!(created.id().as_str(), std::process::id().to_string());
    assert!(ExecutionId::parse(created.id().as_str()).is_ok());
    let read = repo.get_execution(created.id()).expect("read created");
    assert_eq!(read, created);
    let finished = repo
        .finish_execution(
            created.id(),
            finish(
                CoverageStatus::Incomplete,
                [CapabilityDomain::Filesystem, CapabilityDomain::Process],
                Some(0),
            ),
        )
        .expect("finish");
    assert_eq!(finished.lifecycle(), Lifecycle::Finished);
    assert_eq!(finished.coverage(), Some(CoverageStatus::Incomplete));
    assert!(!finished.is_complete());
    assert_eq!(finished.exit_code(), Some(0));
    assert_eq!(finished.contract_version(), Some("1"));
    assert_eq!(finished.tool_version(), Some("0.1.0"));
    let expected_domains: BTreeSet<_> = [CapabilityDomain::Filesystem, CapabilityDomain::Process]
        .into_iter()
        .collect();
    assert_eq!(finished.unsupported_domains(), &expected_domains);
    assert_eq!(
        finished.command().expect("command").program(),
        "tool'; DROP TABLE executions; --"
    );
    assert_eq!(finished.command().expect("command").arg_count(), 0);
    finished
}

#[test]
fn repository_creates_reads_and_finishes_without_sql() {
    let workspace = TempWorkspace::new("repo");
    let mut store = Store::open(workspace.path()).expect("open");
    let finished = round_trip(&mut store);
    let again = store.get_execution(finished.id()).expect("read finished");
    assert_eq!(again, finished);
    drop(store);
    let store = Store::open(workspace.path()).expect("reopen");
    assert_eq!(
        store
            .get_execution(finished.id())
            .expect("read after restart"),
        finished
    );
}

#[test]
fn ids_are_unique_time_sortable_and_not_pids() {
    let workspace = TempWorkspace::new("ids");
    let mut store = Store::open(workspace.path()).expect("open");
    let mut ids = Vec::new();
    for _ in 0..24 {
        let record = store.create_execution(None).expect("create");
        assert!(ExecutionId::parse(&record.id().timestamp_millis().to_string()).is_err());
        ids.push(record.id().clone());
    }
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());
    assert!(ExecutionId::parse("7").is_err());
}

#[test]
fn final_coverage_and_versions_survive_restart() {
    let workspace = TempWorkspace::new("restart");
    let mut store = Store::open(workspace.path()).expect("open");
    let started = store.create_execution(None).expect("started");
    let complete = store
        .finish_execution(
            started.id(),
            FinishExecution::try_new(
                CoverageStatus::Complete,
                [],
                None,
                Some("contract-v1"),
                Some("tool-v1"),
            )
            .expect("complete finish"),
        )
        .expect("finish complete");
    assert!(complete.is_complete());
    assert_eq!(complete.exit_code(), None);
    drop(store);
    let store = Store::open(workspace.path()).expect("reopen");
    let loaded = store.get_execution(complete.id()).expect("reload");
    assert_eq!(loaded, complete);
    assert_eq!(loaded.contract_version(), Some("contract-v1"));
    assert_eq!(loaded.tool_version(), Some("tool-v1"));
    assert!(loaded.unsupported_domains().is_empty());
}

#[test]
fn complete_with_an_unsupported_domain_is_rejected_and_not_rewritten() {
    let workspace = TempWorkspace::new("complete");
    let mut store = Store::open(workspace.path()).expect("open");
    let created = store.create_execution(None).expect("create");
    let rejected = FinishExecution::try_new(
        CoverageStatus::Complete,
        [CapabilityDomain::Network],
        Some(1),
        None,
        None,
    );
    assert!(matches!(
        rejected,
        Err(StoreError::CompleteWhileUnsupported)
    ));
    let still = store.get_execution(created.id()).expect("unchanged");
    assert_eq!(still.lifecycle(), Lifecycle::Started);
    assert!(still.coverage().is_none());
    assert!(!still.is_complete());
}

#[test]
fn a_stored_complete_row_with_an_unsupported_domain_is_not_success() {
    let workspace = TempWorkspace::new("illegal");
    let mut store = Store::open(workspace.path()).expect("open");
    let created = store.create_execution(None).expect("create");
    let id = created.id().as_str().to_owned();
    drop(store);
    let connection = Connection::open(database_path(workspace.path())).expect("inspect");
    connection
        .execute(
            "UPDATE executions SET lifecycle = 'finished', coverage_status = 'COMPLETE' WHERE execution_id = ?1",
            [&id],
        )
        .expect("mark complete");
    connection
        .execute(
            "INSERT INTO execution_unsupported_domains (execution_id, domain) VALUES (?1, 'network')",
            [&id],
        )
        .expect("insert domain");
    drop(connection);
    let store = Store::open(workspace.path()).expect("reopen");
    let error = store
        .get_execution(&ExecutionId::parse(&id).expect("id"))
        .expect_err("illegal complete row was returned");
    assert!(matches!(error, StoreError::CompleteWhileUnsupported));
}

#[test]
fn command_metadata_omits_argv_secrets_prompts_and_responses() {
    let workspace = TempWorkspace::new("privacy");
    let mut store = Store::open(workspace.path()).expect("open");
    let command = CommandMetadata::try_new("git", 256).expect("count at the cap");
    let created = store.create_execution(Some(command)).expect("create");
    let path = database_path(workspace.path());
    drop(store);
    let connection = Connection::open(&path).expect("inspect");
    let (program, arg_count): (String, i64) = connection
        .query_row(
            "SELECT command_program, arg_count FROM executions WHERE execution_id = ?1",
            [created.id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("command columns");
    assert_eq!(program, "git");
    assert_eq!(arg_count, 256);
    let bytes = fs::read(&path).expect("database bytes");
    for sentinel in [
        ARGV_SENTINEL,
        SECRET_SENTINEL,
        PROMPT_SENTINEL,
        RESPONSE_SENTINEL,
    ] {
        assert_absent(&bytes, sentinel);
    }
}

#[test]
fn minimized_command_rejects_empty_nul_overlong_text_and_a_large_count() {
    assert!(matches!(
        CommandMetadata::try_new("", 0),
        Err(StoreError::InvalidCommandProgram)
    ));
    assert!(matches!(
        CommandMetadata::try_new("a\0b", 0),
        Err(StoreError::InvalidCommandProgram)
    ));
    let overlong = "x".repeat(4097);
    assert!(matches!(
        CommandMetadata::try_new(&overlong, 1),
        Err(StoreError::InvalidCommandProgram)
    ));
    assert!(matches!(
        CommandMetadata::try_new("tool", 257),
        Err(StoreError::ArgCountOutOfRange)
    ));
    let program = "y".repeat(4096);
    let command = CommandMetadata::try_new(&program, 256).expect("bounds");
    assert_eq!(command.program(), program);
    assert_eq!(command.arg_count(), 256);
}

#[test]
fn version_text_is_bounded_and_a_second_finish_keeps_the_first_record() {
    let workspace = TempWorkspace::new("finish");
    let mut store = Store::open(workspace.path()).expect("open");
    let created = store
        .create_execution(Some(CommandMetadata::try_new("tool", 2).expect("command")))
        .expect("create");
    assert!(matches!(
        FinishExecution::try_new(CoverageStatus::Unsupported, [], Some(3), Some(""), None),
        Err(StoreError::InvalidVersionText)
    ));
    let long = "v".repeat(129);
    assert!(matches!(
        FinishExecution::try_new(CoverageStatus::Unsupported, [], None, None, Some(&long)),
        Err(StoreError::InvalidVersionText)
    ));
    let version = "v".repeat(128);
    let finished = store
        .finish_execution(
            created.id(),
            FinishExecution::try_new(
                CoverageStatus::Unsupported,
                [CapabilityDomain::Network],
                Some(-1),
                Some(&version),
                None,
            )
            .expect("version at the cap"),
        )
        .expect("finish");
    assert_eq!(finished.coverage(), Some(CoverageStatus::Unsupported));
    assert_eq!(finished.contract_version(), Some(version.as_str()));
    assert_eq!(finished.tool_version(), None);
    assert_eq!(finished.exit_code(), Some(-1));
    let second =
        store.finish_execution(created.id(), finish(CoverageStatus::Complete, [], Some(0)));
    assert!(matches!(
        second,
        Err(StoreError::ExecutionAlreadyFinished { .. })
    ));
    assert_eq!(store.get_execution(created.id()).expect("kept"), finished);
}

#[test]
fn missing_ids_fail_and_a_started_execution_survives_restart() {
    let workspace = TempWorkspace::new("missing");
    let mut store = Store::open(workspace.path()).expect("open");
    let missing = ExecutionId::parse(&"ab".repeat(16)).expect("canonical unused id");
    assert!(matches!(
        store.get_execution(&missing),
        Err(StoreError::ExecutionNotFound { .. })
    ));
    assert!(matches!(
        store.finish_execution(&missing, finish(CoverageStatus::Incomplete, [], None)),
        Err(StoreError::ExecutionNotFound { .. })
    ));
    let started = store.create_execution(None).expect("create");
    let id = started.id().clone();
    drop(store);
    let store = Store::open(workspace.path()).expect("reopen");
    assert_eq!(store.get_execution(&id).expect("started survives"), started);
}
