// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transactional event writer: order, bounds, failure, and privacy.

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use drifti_observer::{
    EvidenceMeta, FailureReason, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation,
    Outcome, ParentIdentity, ProcessIdentity,
};
use drifti_store::{
    bounded_event_channel, parse_canonical_resource, CommandMetadata, CoverageStatus,
    EventBatchWriter, ExecutionId, FinishExecution, OwnedCanonicalResource, Store, StoreError,
    MAX_NETWORK_HOST_BYTES,
};
use proptest::prelude::*;
use rusqlite::{params, Connection};

const SECRET_ARGV: &str = "super-secret-argv-value";
const SECRET_PAYLOAD: &str = "raw-network-payload-bytes";

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
            "drifti-store-events-{name}-{}-{nanos}-{id}",
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

#[test]
fn zero_channel_capacity_cannot_be_opened() {
    assert!(NonZeroUsize::new(0).is_none());
    let (sink, _cursor) = bounded_event_channel(NonZeroUsize::new(1).expect("capacity"));
    assert_eq!(sink.capacity(), 1);
}

#[test]
fn events_persist_in_sequence_order_not_timestamp_order() {
    let workspace = TempWorkspace::new("order");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let events = vec![
        sample(&id, 2, 1, "/tmp/second", Outcome::success()),
        sample(&id, 0, 99, "/tmp/first", Outcome::success()),
        sample(&id, 1, 5, "/tmp/middle", Outcome::success()),
    ];
    let writer = EventBatchWriter::new(NonZeroUsize::new(8).expect("limit"));
    assert_eq!(
        writer.write_batch(&mut store, &id, events).expect("write"),
        3
    );
    let stored = read_events(store.path());
    assert_eq!(
        stored
            .iter()
            .map(|event| (event.sequence, event.monotonic_nanos))
            .collect::<Vec<_>>(),
        vec![(0, 99), (1, 5), (2, 1)]
    );
    assert!(stored.iter().all(|event| event.action == "filesystem.read"));
}

#[test]
fn duplicate_sequence_in_one_batch_rolls_back_and_returns_every_event() {
    let workspace = TempWorkspace::new("rollback");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let events = vec![
        sample(&id, 1, 1, "/tmp/a", Outcome::success()),
        sample(&id, 1, 2, "/tmp/b", Outcome::success()),
    ];
    let writer = EventBatchWriter::new(NonZeroUsize::new(2).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, events.clone())
        .expect_err("duplicate sequence");
    assert!(matches!(
        error.store_error(),
        StoreError::DuplicateEventSequence
    ));
    assert_eq!(error.unpersisted().len(), 2);
    assert_eq!(error.persisted(), 0);
    assert!(!error.allows_complete_coverage());
    assert_eq!(error.coverage(), CoverageStatus::Incomplete);
    assert!(!format!("{error}").contains("/tmp/a"));
    assert_eq!(read_events(store.path()).len(), 0);
    assert_eq!(
        sequences_of(&error.into_unpersisted()),
        sequences_of(&events)
    );
}

#[test]
fn sequence_regression_keeps_the_committed_prefix() {
    let workspace = TempWorkspace::new("regression");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let writer = EventBatchWriter::new(NonZeroUsize::new(4).expect("limit"));
    writer
        .write_batch(
            &mut store,
            &id,
            vec![sample(&id, 2, 1, "/tmp/kept", Outcome::success())],
        )
        .expect("first");
    let late = sample(&id, 1, 2, "/tmp/late", Outcome::success());
    let error = writer
        .write_batch(&mut store, &id, vec![late.clone()])
        .expect_err("regression");
    assert!(matches!(
        error.store_error(),
        StoreError::SequenceRegression
    ));
    assert_eq!(error.into_unpersisted(), vec![late]);
    assert_eq!(
        read_events(store.path())
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

#[test]
fn storage_failure_is_visible_and_cannot_finish_complete() {
    let workspace = TempWorkspace::new("coverage");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let events = vec![
        sample(&id, 1, 1, "/tmp/a", Outcome::success()),
        sample(&id, 1, 2, "/tmp/b", Outcome::success()),
    ];
    let writer = EventBatchWriter::new(NonZeroUsize::new(4).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, events)
        .expect_err("failure");
    assert_eq!(
        error.downgrade(CoverageStatus::Complete),
        CoverageStatus::Incomplete
    );
    assert_eq!(
        error.downgrade(CoverageStatus::Unsupported),
        CoverageStatus::Unsupported
    );
    assert_eq!(
        error.downgrade(CoverageStatus::Incomplete),
        CoverageStatus::Incomplete
    );
    assert!(!error.downgrade(CoverageStatus::Complete).is_complete());

    let complete = FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
        .expect("finish value");
    let refused = store
        .finish_execution(&id, complete)
        .expect_err("complete is refused");
    assert!(matches!(refused, StoreError::StorageFailureBlocksComplete));
    let record = store.get_execution(&id).expect("still started");
    assert!(record.coverage().is_none());
    assert!(!record.is_complete());

    let downgraded = FinishExecution::try_new(
        error.downgrade(CoverageStatus::Complete),
        [],
        Some(1),
        None,
        None,
    )
    .expect("downgraded finish");
    let finished = store
        .finish_execution(&id, downgraded)
        .expect("incomplete finish");
    assert_eq!(finished.coverage(), Some(CoverageStatus::Incomplete));
    assert!(!finished.is_complete());
    assert_eq!(finished.exit_code(), Some(1));
}

#[test]
fn successful_retry_after_rollback_can_record_complete() {
    let workspace = TempWorkspace::new("retry");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let writer = EventBatchWriter::new(NonZeroUsize::new(4).expect("limit"));
    let failed = vec![
        sample(&id, 1, 1, "/tmp/a", Outcome::success()),
        sample(&id, 1, 2, "/tmp/b", Outcome::success()),
    ];
    let error = writer
        .write_batch(&mut store, &id, failed)
        .expect_err("rolled back");
    let recovered = error.into_unpersisted();
    let mut unique = Vec::new();
    for event in recovered {
        if unique
            .iter()
            .any(|kept: &ObservedEvent| kept.sequence() == event.sequence())
        {
            continue;
        }
        unique.push(event);
    }
    writer
        .write_batch(&mut store, &id, unique)
        .expect("retry commits the surviving event");
    let complete = FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
        .expect("finish value");
    let finished = store.finish_execution(&id, complete).expect("complete");
    assert!(finished.is_complete());
    assert_eq!(read_events(store.path()).len(), 1);
}

#[test]
fn reopened_store_still_refuses_complete_after_a_failed_batch() {
    let workspace = TempWorkspace::new("reopen-failure");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let writer = EventBatchWriter::new(NonZeroUsize::new(4).expect("limit"));
    let events = vec![
        sample(&id, 1, 1, "/tmp/a", Outcome::success()),
        sample(&id, 1, 2, "/tmp/b", Outcome::success()),
    ];
    let error = writer
        .write_batch(&mut store, &id, events)
        .expect_err("duplicate sequence");
    assert!(!error.allows_complete_coverage());
    drop(store);

    let mut store = Store::open(workspace.path()).expect("reopen");
    let record = store.get_execution(&id).expect("still started");
    assert!(record.coverage().is_none());
    assert!(!record.is_complete());
    let complete = FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
        .expect("finish value");
    let refused = store
        .finish_execution(&id, complete)
        .expect_err("reopen keeps the failure");
    assert!(matches!(refused, StoreError::StorageFailureBlocksComplete));

    let recovered = sample(&id, 1, 3, "/tmp/kept", Outcome::success());
    writer
        .write_batch(&mut store, &id, vec![recovered])
        .expect("later batch clears the marker");
    let finished = store
        .finish_execution(
            &id,
            FinishExecution::try_new(CoverageStatus::Complete, [], Some(0), None, None)
                .expect("finish value"),
        )
        .expect("complete after a committed batch");
    assert!(finished.is_complete());
}

#[test]
fn missing_execution_returns_the_batch_and_writes_nothing() {
    let workspace = TempWorkspace::new("missing");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let events = vec![sample(&id, 0, 1, "/tmp/orphan", Outcome::success())];
    drop(store);
    let mut store = Store::open(workspace.path()).expect("reopen");
    // Reopen clears the in-process failure set. Delete the row so the write
    // fails even though the id text is still canonical.
    {
        let connection = Connection::open(store.path()).expect("open db");
        connection
            .execute(
                "DELETE FROM executions WHERE execution_id = ?1",
                params![id.as_str()],
            )
            .expect("delete execution");
    }
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, events.clone())
        .expect_err("missing execution");
    assert!(matches!(
        error.store_error(),
        StoreError::ExecutionNotFound { .. }
    ));
    assert_eq!(error.into_unpersisted(), events);
    assert!(read_events(store.path()).is_empty());
}

#[test]
fn mismatched_execution_id_is_not_written() {
    let workspace = TempWorkspace::new("mismatch");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let other = started(&mut store);
    let event = sample(&other, 0, 1, "/tmp/other", Outcome::success());
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, vec![event.clone()])
        .expect_err("mismatch");
    assert!(matches!(
        error.store_error(),
        StoreError::EventExecutionMismatch
    ));
    assert_eq!(error.into_unpersisted(), vec![event]);
    assert!(read_events(store.path()).is_empty());
}

#[test]
fn oversized_batch_returns_every_event_without_writing() {
    let workspace = TempWorkspace::new("oversize");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let events = vec![
        sample(&id, 0, 1, "/tmp/a", Outcome::success()),
        sample(&id, 1, 2, "/tmp/b", Outcome::success()),
    ];
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, events.clone())
        .expect_err("too large");
    assert!(matches!(
        error.store_error(),
        StoreError::EventBatchTooLarge
    ));
    assert_eq!(error.unpersisted().len(), events.len());
    assert!(read_events(store.path()).is_empty());
}

#[test]
fn integer_that_does_not_fit_sqlite_returns_the_event() {
    let workspace = TempWorkspace::new("integer");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let event = sample(&id, u64::MAX, 1, "/tmp/wide", Outcome::success());
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, vec![event])
        .expect_err("integer");
    assert!(matches!(error.store_error(), StoreError::IntegerOutOfRange));
    assert_eq!(error.unpersisted().len(), 1);
    assert!(read_events(store.path()).is_empty());
}

#[test]
fn writer_rejects_a_network_host_above_the_observer_cap() {
    let workspace = TempWorkspace::new("host-cap");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let host = "h".repeat(MAX_NETWORK_HOST_BYTES + 1);
    let event = forged_network_host(&id, &host);
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .write_batch(&mut store, &id, vec![event])
        .expect_err("host cap");
    assert!(matches!(
        error.store_error(),
        StoreError::NetworkHostTooLong
    ));
    assert_eq!(error.unpersisted().len(), 1);
    assert!(!error.allows_complete_coverage());
    assert!(read_events(store.path()).is_empty());
    let bytes = fs::read(store.path()).expect("read database");
    assert!(!bytes
        .windows(host.len())
        .any(|window| window == host.as_bytes()));
}

#[test]
fn network_host_of_255_bytes_round_trips_without_a_payload() {
    let workspace = TempWorkspace::new("host-ok");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let host = "h".repeat(MAX_NETWORK_HOST_BYTES);
    let event = ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        0,
        MonotonicTimestamp::from_nanos(7),
        ProcessIdentity::new(Some(4), None),
        None,
        Operation::NetworkConnect,
        ObservedResource::network(&host, 443).expect("255-byte host"),
        Outcome::failure(
            Some(111),
            Some(FailureReason::new("ECONNREFUSED").expect("reason")),
        ),
        EvidenceMeta::with_byte_length(SECRET_PAYLOAD.len() as u64),
    );
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    writer
        .write_batch(&mut store, &id, vec![event])
        .expect("write network");
    let stored = read_events(store.path());
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].resource_kind, "network");
    assert_eq!(stored[0].outcome_status, "failure");
    assert_eq!(stored[0].errno, Some(111));
    assert_eq!(stored[0].failure_reason.as_deref(), Some("ECONNREFUSED"));
    assert_eq!(
        stored[0].evidence_byte_length,
        Some(i64::try_from(SECRET_PAYLOAD.len()).expect("length"))
    );
    assert_eq!(
        parse_canonical_resource(&stored[0].canonical_resource).expect("parse"),
        OwnedCanonicalResource::Network { host, port: 443 }
    );
    let bytes = fs::read(store.path()).expect("read database");
    assert!(!contains_bytes(&bytes, SECRET_PAYLOAD.as_bytes()));
}

#[test]
fn persisted_rows_omit_argv_secrets_and_payloads() {
    let workspace = TempWorkspace::new("privacy");
    let mut store = Store::open(workspace.path()).expect("open");
    let command = CommandMetadata::try_new("tool", 2).expect("command");
    let id = store
        .create_execution(Some(command))
        .expect("create")
        .id()
        .clone();
    let event = sample(&id, 0, 1, "/workspace/src/main.rs", Outcome::success());
    let _secret_argv = SECRET_ARGV;
    let _payload = SECRET_PAYLOAD;
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    writer
        .write_batch(&mut store, &id, vec![event])
        .expect("write");
    let path = store.path().to_path_buf();
    drop(store);
    let bytes = fs::read(&path).expect("read database");
    assert!(!contains_bytes(&bytes, SECRET_ARGV.as_bytes()));
    assert!(!contains_bytes(&bytes, SECRET_PAYLOAD.as_bytes()));
    let connection = Connection::open(&path).expect("open db");
    let mut columns = connection
        .prepare("SELECT name FROM pragma_table_info('events')")
        .expect("prepare");
    let names: Vec<String> = columns
        .query_map([], |row| row.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("columns");
    for forbidden in [
        "argv",
        "args",
        "payload",
        "secret",
        "prompt",
        "file_contents",
    ] {
        assert!(!names.iter().any(|name| name == forbidden));
    }
}

#[test]
fn dropped_cursor_events_can_still_be_written() {
    let workspace = TempWorkspace::new("unconsumed");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let event = sample(&id, 4, 1, "/tmp/queued", Outcome::success());
    let (sink, cursor) = bounded_event_channel(NonZeroUsize::new(1).expect("capacity"));
    sink.emit(event.clone()).expect("queue");
    drop(cursor);
    let pending = sink.take_unconsumed();
    assert_eq!(pending, vec![event]);
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    writer
        .write_batch(&mut store, &id, pending)
        .expect("persist recovered event");
    assert_eq!(read_events(store.path())[0].sequence, 4);
}

#[test]
fn full_channel_blocks_and_drain_persists_every_event() {
    let workspace = TempWorkspace::new("drain");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let first = sample(&id, 1, 10, "/tmp/one", Outcome::success());
    let second = sample(&id, 2, 11, "/tmp/two", Outcome::success());
    let (sink, cursor) = bounded_event_channel(NonZeroUsize::new(1).expect("capacity"));
    let phase = Arc::new(AtomicU8::new(0));
    let worker_phase = Arc::clone(&phase);
    let worker_first = first.clone();
    let worker_second = second.clone();
    let worker = thread::spawn(move || {
        sink.emit(worker_first).expect("sequence 1 queued");
        worker_phase.store(1, Ordering::Release);
        sink.emit(worker_second).expect("sequence 2 queued");
        worker_phase.store(2, Ordering::Release);
    });

    wait_phase(&phase, |value| value >= 1);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        phase.load(Ordering::Acquire),
        1,
        "second emit must stay blocked"
    );

    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let persisted = writer.drain(&mut store, &id, &cursor).expect("drain");
    assert_eq!(persisted, 2);
    worker.join().expect("worker");
    assert_eq!(
        read_events(store.path())
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn drain_failure_returns_the_failed_batch_and_the_events_still_queued() {
    let workspace = TempWorkspace::new("drain-fail");
    let mut store = Store::open(workspace.path()).expect("open");
    let id = started(&mut store);
    let (sink, cursor) = bounded_event_channel(NonZeroUsize::new(4).expect("capacity"));
    let first = sample(&id, 1, 1, "/tmp/kept", Outcome::success());
    let duplicate = sample(&id, 1, 2, "/tmp/dup", Outcome::success());
    let third = sample(&id, 3, 3, "/tmp/queued", Outcome::success());
    sink.emit(first).expect("first");
    sink.emit(duplicate.clone()).expect("duplicate");
    sink.emit(third.clone()).expect("third");
    drop(sink);
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    let error = writer
        .drain(&mut store, &id, &cursor)
        .expect_err("second batch fails");
    assert_eq!(error.persisted(), 1);
    assert!(!error.allows_complete_coverage());
    let returned = error.into_unpersisted();
    assert_eq!(returned.len(), 2);
    assert!(returned.contains(&duplicate));
    assert!(returned.contains(&third));
    assert_eq!(
        read_events(store.path())
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1]
    );
}

#[test]
fn the_same_sequence_in_two_executions_is_not_a_conflict() {
    let workspace = TempWorkspace::new("two-executions");
    let mut store = Store::open(workspace.path()).expect("open");
    let first = started(&mut store);
    let second = started(&mut store);
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    writer
        .write_batch(
            &mut store,
            &first,
            vec![sample(&first, 1, 1, "/tmp/a", Outcome::success())],
        )
        .expect("first execution");
    writer
        .write_batch(
            &mut store,
            &second,
            vec![sample(&second, 1, 1, "/tmp/b", Outcome::success())],
        )
        .expect("second execution");
    assert_eq!(read_events(store.path()).len(), 2);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn any_arrival_order_persists_by_sequence(
        sequences in prop::collection::hash_set(0u64..40, 1..5).prop_flat_map(|set| {
            let mut values: Vec<u64> = set.into_iter().collect();
            values.sort_unstable();
            Just(values).prop_shuffle()
        })
    ) {
        let workspace = TempWorkspace::new("property");
        let mut store = Store::open(workspace.path()).expect("open");
        let id = started(&mut store);
        let events: Vec<_> = sequences
            .iter()
            .enumerate()
            .map(|(index, sequence)| {
                sample(
                    &id,
                    *sequence,
                    u64::try_from(index).expect("index"),
                    "/tmp/property",
                    Outcome::success(),
                )
            })
            .collect();
        let limit = NonZeroUsize::new(events.len()).expect("limit");
        EventBatchWriter::new(limit)
            .write_batch(&mut store, &id, events)
            .expect("write permutation");
        let stored = read_events(store.path());
        let mut expected = sequences.clone();
        expected.sort_unstable();
        assert_eq!(
            stored.iter().map(|event| event.sequence as u64).collect::<Vec<_>>(),
            expected
        );
    }
}

fn started(store: &mut Store) -> ExecutionId {
    store.create_execution(None).expect("create").id().clone()
}

fn sample(
    id: &ExecutionId,
    sequence: u64,
    nanos: u64,
    path: &str,
    outcome: Outcome,
) -> ObservedEvent {
    ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        sequence,
        MonotonicTimestamp::from_nanos(nanos),
        ProcessIdentity::new(Some(10), Some(11)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file(path).expect("path"),
        outcome,
        EvidenceMeta::empty(),
    )
}

fn forged_network_host(id: &ExecutionId, host: &str) -> ObservedEvent {
    let event = ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        0,
        MonotonicTimestamp::from_nanos(1),
        ProcessIdentity::new(None, None),
        None,
        Operation::NetworkListen,
        ObservedResource::network("localhost", 1).expect("host"),
        Outcome::success(),
        EvidenceMeta::empty(),
    );
    let json = serde_json::to_string(&event).expect("serialize");
    let forged = json.replacen("\"localhost\"", &format!("\"{host}\""), 1);
    serde_json::from_str(&forged).expect("forged host bypasses the observer constructor")
}

fn sequences_of(events: &[ObservedEvent]) -> Vec<u64> {
    let mut sequences: Vec<u64> = events.iter().map(ObservedEvent::sequence).collect();
    sequences.sort_unstable();
    sequences
}

struct StoredEvent {
    sequence: i64,
    monotonic_nanos: i64,
    action: String,
    resource_kind: String,
    canonical_resource: String,
    outcome_status: String,
    errno: Option<i64>,
    failure_reason: Option<String>,
    evidence_byte_length: Option<i64>,
}

fn read_events(path: &Path) -> Vec<StoredEvent> {
    let connection = Connection::open(path).expect("open database");
    let mut statement = connection
        .prepare(
            "SELECT sequence, monotonic_nanos, action, resource_kind, canonical_resource,
                    outcome_status, errno, failure_reason, evidence_byte_length
             FROM events ORDER BY execution_id, sequence",
        )
        .expect("prepare");
    let rows = statement
        .query_map([], |row| {
            Ok(StoredEvent {
                sequence: row.get(0)?,
                monotonic_nanos: row.get(1)?,
                action: row.get(2)?,
                resource_kind: row.get(3)?,
                canonical_resource: row.get(4)?,
                outcome_status: row.get(5)?,
                errno: row.get(6)?,
                failure_reason: row.get(7)?,
                evidence_byte_length: row.get(8)?,
            })
        })
        .expect("query");
    rows.collect::<Result<Vec<_>, _>>().expect("rows")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn wait_phase(phase: &AtomicU8, is_ready: impl Fn(u8) -> bool) {
    let started = Instant::now();
    loop {
        let current = phase.load(Ordering::Acquire);
        if is_ready(current) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "phase stayed at {current}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
