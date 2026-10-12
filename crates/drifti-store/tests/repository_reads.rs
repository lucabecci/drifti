// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KAN-58 reads: history after restart, sequence order, and repository boundaries.

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use drifti_observer::{
    EvidenceMeta, FailureReason, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation,
    Outcome, ParentIdentity, ProcessIdentity,
};
use drifti_store::{
    CapabilityDomain, CommandMetadata, CoverageStatus, EventBatchWriter, ExecutionHistory,
    ExecutionId, ExecutionRepository, FinishExecution, Lifecycle, ProcessRecord, ProcessRepository,
    ReadRepository, Store, StoreError, DATABASE_FILE, STATE_DIR,
};

const ARGV_SENTINEL: &str = "argv-value-must-not-be-read";
const SECRET_SENTINEL: &str = "secret-value-must-not-be-read";
const PROMPT_SENTINEL: &str = "prompt-must-not-be-read";
const RESPONSE_SENTINEL: &str = "model-response-must-not-be-read";
const FILE_SENTINEL: &str = "file-bytes-must-not-be-read";
const PAYLOAD_SENTINEL: &str = "network-payload-must-not-be-read";

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
            "drifti-store-reads-{name}-{}-{nanos}-{id}",
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

fn database_bytes(workspace: &Path) -> Vec<u8> {
    fs::read(workspace.join(STATE_DIR).join(DATABASE_FILE)).expect("read database")
}

fn assert_absent(bytes: &[u8], sentinel: &str) {
    assert!(
        !bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes()),
        "{sentinel} was persisted"
    );
}

fn event(
    id: &ExecutionId,
    sequence: u64,
    nanos: u64,
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
    evidence: EvidenceMeta,
) -> ObservedEvent {
    ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        sequence,
        MonotonicTimestamp::from_nanos(nanos),
        ProcessIdentity::new(Some(10), Some(11)),
        Some(ParentIdentity::new(1)),
        operation,
        resource,
        outcome,
        evidence,
    )
}

fn write_events(store: &mut Store, id: &ExecutionId, events: Vec<ObservedEvent>) {
    let limit = NonZeroUsize::new(events.len()).expect("batch is non-empty");
    let count = EventBatchWriter::new(limit)
        .write_batch(store, id, events)
        .expect("write events");
    assert_eq!(count, limit.get());
}

fn by_sequence(events: &[ObservedEvent]) -> Vec<ObservedEvent> {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(ObservedEvent::sequence);
    ordered
}

fn reopen(workspace: &Path) -> Store {
    Store::open(workspace).expect("reopen")
}

#[test]
fn history_survives_restart_and_keeps_sequence_coverage_outcome_and_evidence() {
    let workspace = TempWorkspace::new("restart");
    let mut store = Store::open(workspace.path()).expect("open");
    assert!(ExecutionRepository::list_executions(&store)
        .expect("empty history")
        .is_empty());

    let command = CommandMetadata::try_new("tool", 2).expect("command");
    let finished_id = {
        let executions: &mut dyn ExecutionRepository = &mut store;
        executions
            .create_execution(Some(command))
            .expect("create")
            .id()
            .clone()
    };
    let started_id = store.create_execution(None).expect("started").id().clone();
    assert!(finished_id < started_id);

    let failure = Outcome::failure(
        Some(13),
        Some(FailureReason::new("eacces").expect("reason")),
    );
    let written = vec![
        event(
            &finished_id,
            2,
            1,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/second").expect("path"),
            Outcome::success(),
            EvidenceMeta::with_byte_length(64),
        ),
        event(
            &finished_id,
            0,
            99,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/first").expect("path"),
            failure,
            EvidenceMeta::empty(),
        ),
        event(
            &finished_id,
            1,
            5,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/middle").expect("path"),
            Outcome::success(),
            EvidenceMeta::with_byte_length(0),
        ),
    ];
    let expected = by_sequence(&written);
    write_events(&mut store, &finished_id, written);

    let processes: &mut dyn ProcessRepository = &mut store;
    processes
        .record_process(
            &finished_id,
            ProcessRecord::try_new(1, Some(1), None).expect("root"),
        )
        .expect("root");
    processes
        .record_process(
            &finished_id,
            ProcessRecord::try_new(10, Some(11), Some(1)).expect("actor"),
        )
        .expect("actor");
    processes
        .record_process(
            &finished_id,
            ProcessRecord::try_new(12, None, Some(10)).expect("child"),
        )
        .expect("child");

    let finish = FinishExecution::try_new(
        CoverageStatus::Incomplete,
        [CapabilityDomain::Filesystem],
        Some(7),
        Some("contracts-1"),
        Some("0.1.0"),
    )
    .expect("finish metadata");
    store
        .finish_execution(&finished_id, finish)
        .expect("finish");

    drop(store);
    let store = reopen(workspace.path());
    let executions: &dyn ExecutionRepository = &store;
    let reads: &dyn ReadRepository = &store;

    let listed = executions.list_executions().expect("list");
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id(), &finished_id);
    assert_eq!(listed[1].id(), &started_id);
    assert_eq!(listed[0].lifecycle(), Lifecycle::Finished);
    assert_eq!(listed[0].coverage(), Some(CoverageStatus::Incomplete));
    assert!(!listed[0].is_complete());
    assert_eq!(
        listed[0]
            .unsupported_domains()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![CapabilityDomain::Filesystem]
    );
    assert_eq!(listed[0].exit_code(), Some(7));
    assert_eq!(listed[0].contract_version(), Some("contracts-1"));
    assert_eq!(listed[0].tool_version(), Some("0.1.0"));
    assert_eq!(listed[0].command().expect("command").program(), "tool");
    assert_eq!(listed[0].command().expect("command").arg_count(), 2);
    assert_eq!(listed[1].lifecycle(), Lifecycle::Started);
    assert!(listed[1].coverage().is_none());
    assert!(!listed[1].is_complete());

    let history: ExecutionHistory = reads.execution_history(&finished_id).expect("history");
    assert_eq!(history.execution(), &listed[0]);
    assert_eq!(history.events(), expected.as_slice());
    let nanos: Vec<_> = history
        .events()
        .iter()
        .map(|event| event.timestamp().nanos())
        .collect();
    let sequences: Vec<_> = history
        .events()
        .iter()
        .map(ObservedEvent::sequence)
        .collect();
    assert_eq!(sequences, vec![0, 1, 2]);
    assert_eq!(nanos, vec![99, 5, 1]);
    assert_eq!(history.events()[0].outcome(), expected[0].outcome());
    assert!(!history.events()[0].was_exercised());
    assert!(history.events()[0].was_attempted());
    assert_eq!(history.events()[0].evidence(), EvidenceMeta::empty());
    assert_eq!(
        history.events()[1].evidence(),
        EvidenceMeta::with_byte_length(0)
    );
    assert_eq!(
        history.events()[2].evidence(),
        EvidenceMeta::with_byte_length(64)
    );
    assert!(history.events()[2].was_exercised());
    assert_eq!(
        history
            .processes()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1, 10, 12]
    );

    let lineage = reads.process_lineage(&finished_id, 10).expect("lineage");
    assert_eq!(
        lineage
            .ancestors()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(
        lineage
            .children()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![12]
    );
    assert_eq!(
        Some(lineage.process().pid()),
        history.events()[0].process().pid()
    );

    let started = reads
        .execution_history(&started_id)
        .expect("started history");
    assert!(started.events().is_empty());
    assert!(started.processes().is_empty());
    assert!(started.execution().coverage().is_none());

    let same_action = reads
        .events_by_action(Operation::FilesystemRead)
        .expect("action");
    assert_eq!(same_action, expected);
    let one_resource = reads
        .events_by_resource(&ObservedResource::file("/tmp/first").expect("path"))
        .expect("resource");
    assert_eq!(one_resource, vec![expected[0].clone()]);
    assert!(reads
        .events_by_action(Operation::NetworkListen)
        .expect("unused action")
        .is_empty());

    let rendered = format!("{history:?}{listed:?}");
    let bytes = database_bytes(workspace.path());
    for sentinel in [
        ARGV_SENTINEL,
        SECRET_SENTINEL,
        PROMPT_SENTINEL,
        RESPONSE_SENTINEL,
        FILE_SENTINEL,
        PAYLOAD_SENTINEL,
    ] {
        assert_absent(&bytes, sentinel);
        assert!(!rendered.contains(sentinel), "{sentinel} was reconstructed");
    }
}

#[test]
fn action_and_resource_queries_preserve_sequence_across_executions() {
    let workspace = TempWorkspace::new("query");
    let mut store = Store::open(workspace.path()).expect("open");
    let first = store.create_execution(None).expect("first").id().clone();
    let second = store.create_execution(None).expect("second").id().clone();
    assert!(first < second);

    let quoted = ObservedResource::file("C:/repo/a' OR '1'='1").expect("quoted path");
    let other = ObservedResource::file("/tmp/other").expect("other path");
    let executable = ObservedResource::executable("bin/tool").expect("executable");
    let first_events = vec![
        event(
            &first,
            2,
            1,
            Operation::FilesystemRead,
            quoted.clone(),
            Outcome::success(),
            EvidenceMeta::with_byte_length(64),
        ),
        event(
            &first,
            0,
            90,
            Operation::FilesystemRead,
            quoted.clone(),
            Outcome::success(),
            EvidenceMeta::empty(),
        ),
        event(
            &first,
            1,
            40,
            Operation::FilesystemWrite,
            other.clone(),
            Outcome::success(),
            EvidenceMeta::with_byte_length(0),
        ),
    ];
    let second_events = vec![
        event(
            &second,
            1,
            3,
            Operation::ProcessExecute,
            executable.clone(),
            Outcome::success(),
            EvidenceMeta::empty(),
        ),
        event(
            &second,
            0,
            8,
            Operation::FilesystemRead,
            quoted.clone(),
            Outcome::success(),
            EvidenceMeta::with_byte_length(7),
        ),
    ];
    write_events(&mut store, &first, first_events.clone());
    write_events(&mut store, &second, second_events.clone());
    drop(store);

    let store = reopen(workspace.path());
    let reads: &dyn ReadRepository = &store;
    let first_ordered = by_sequence(&first_events);
    let second_ordered = by_sequence(&second_events);

    assert_eq!(
        reads.events_for_execution(&first).expect("first events"),
        first_ordered
    );
    assert_eq!(
        reads
            .events_for_execution(&second)
            .expect("second events")
            .iter()
            .map(ObservedEvent::sequence)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    let by_action = reads
        .events_by_action(Operation::FilesystemRead)
        .expect("reads");
    assert_eq!(
        by_action
            .iter()
            .map(|event| (
                event.execution_id().raw(),
                event.sequence(),
                event.timestamp().nanos()
            ))
            .collect::<Vec<_>>(),
        vec![
            (first.to_raw(), 0, 90),
            (first.to_raw(), 2, 1),
            (second.to_raw(), 0, 8),
        ]
    );
    let by_resource = reads.events_by_resource(&quoted).expect("quoted resource");
    assert_eq!(by_resource, by_action);
    assert_eq!(
        reads.events_by_resource(&other).expect("other file"),
        vec![first_ordered[1].clone()]
    );
    assert_eq!(
        reads
            .events_by_action(Operation::ProcessExecute)
            .expect("execute"),
        vec![second_ordered[1].clone()]
    );
    assert_eq!(
        reads.events_by_resource(&executable).expect("executable"),
        vec![second_ordered[1].clone()]
    );
    assert!(reads
        .events_by_action(Operation::NetworkListen)
        .expect("absent action")
        .is_empty());
    assert!(reads
        .events_by_resource(&ObservedResource::network("absent.example", 9).expect("host"))
        .expect("absent resource")
        .is_empty());
}

#[test]
fn missing_execution_is_not_an_empty_history() {
    let workspace = TempWorkspace::new("missing");
    let mut store = Store::open(workspace.path()).expect("open");
    let present = store.create_execution(None).expect("present").id().clone();
    drop(store);
    let store = reopen(workspace.path());
    let missing = ExecutionId::parse(&"0".repeat(32)).expect("canonical id");
    assert_ne!(missing, present);

    let reads: &dyn ReadRepository = &store;
    let executions: &dyn ExecutionRepository = &store;
    for lookup in [
        reads.events_for_execution(&missing).err(),
        reads.execution_history(&missing).err(),
        reads.process_lineage(&missing, 1).err(),
        executions.get_execution(&missing).err(),
    ] {
        match lookup {
            Some(StoreError::ExecutionNotFound { id }) => assert_eq!(id, missing.as_str()),
            other => panic!("expected ExecutionNotFound, got {other:?}"),
        }
    }
    let listed = executions.list_executions().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id(), &present);
    assert!(reads
        .events_by_action(Operation::FilesystemRead)
        .expect("no events")
        .is_empty());
}
