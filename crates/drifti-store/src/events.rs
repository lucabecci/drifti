// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transactional persistence of SPEC-004 events.
//!
//! Observers push into a bounded [`EventSink`]. This module drains that
//! channel and inserts each batch inside one SQLite transaction, ordered by
//! `sequence`. A monotonic timestamp is stored and is not the order key.
//!
//! A failed batch is not committed. The same events are returned on
//! [`EventWriteError`], and any events still queued on the cursor are
//! returned with them. Nothing in that failure is discarded.
//!
//! The failure signals [`CoverageStatus::Incomplete`]. It does not signal
//! `COMPLETE`, and it is not authorization. Until a later batch for that
//! execution commits, this process refuses to finish the execution as
//! `COMPLETE`.
//!
//! Network hosts use the SPEC-004 cap of 255 bytes. File and executable
//! identity keep the 4096-byte field cap. Argument vectors, file bytes,
//! network payloads, secrets, prompts, and model responses are not columns.
//!
//! Reads of these rows live on [`crate::ReadRepository`]. That path orders
//! by `sequence` and does not treat the monotonic timestamp as an order key.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use drifti_observer::{
    CursorError, EventCursor, EventSink, EvidenceMeta, ObservedEvent, ObservedResource, Outcome,
};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::StoreError;
use crate::execution::{CoverageStatus, ExecutionId};
use crate::map_sqlite;
use crate::schema::{canonical_resource, sqlite_i64, CanonicalResource, MAX_NETWORK_HOST_BYTES};
use crate::Store;

/// Events written by one transaction when the caller does not choose a limit.
pub const DEFAULT_EVENT_BATCH_LIMIT: usize = 64;

/// Opens the bounded channel that feeds the store.
///
/// `capacity` is the most events that may wait to be persisted. There is no
/// unbounded constructor. [`EventSink::emit`] waits while the channel is full
/// and returns the event if the cursor is gone. It does not drop the event.
#[must_use]
pub fn bounded_event_channel(capacity: NonZeroUsize) -> (EventSink, EventCursor) {
    EventSink::bounded(capacity)
}

/// Writes SPEC-004 events in bounded transactions.
#[derive(Debug, Clone, Copy)]
pub struct EventBatchWriter {
    batch_limit: usize,
}

impl EventBatchWriter {
    /// `batch_limit` is the most events one transaction will hold.
    #[must_use]
    pub fn new(batch_limit: NonZeroUsize) -> Self {
        Self {
            batch_limit: batch_limit.get(),
        }
    }

    /// Uses [`DEFAULT_EVENT_BATCH_LIMIT`].
    #[must_use]
    pub fn with_default_limit() -> Self {
        Self::new(
            NonZeroUsize::new(DEFAULT_EVENT_BATCH_LIMIT).expect("default batch limit is non-zero"),
        )
    }

    /// Bound given to [`Self::new`].
    #[must_use]
    pub const fn batch_limit(&self) -> usize {
        self.batch_limit
    }

    /// Persists `events` for `execution_id` in one transaction.
    ///
    /// Rows are inserted in ascending `sequence`. On failure the transaction
    /// is rolled back and every event is returned. An empty batch writes
    /// nothing and does not clear an earlier failure.
    pub fn write_batch(
        &self,
        store: &mut Store,
        execution_id: &ExecutionId,
        mut events: Vec<ObservedEvent>,
    ) -> Result<usize, EventWriteError> {
        if events.is_empty() {
            return Ok(0);
        }
        if events.len() > self.batch_limit {
            return Err(note_failure(
                store,
                execution_id,
                events,
                StoreError::EventBatchTooLarge,
            ));
        }
        events.sort_by_key(ObservedEvent::sequence);
        let encoded = match events
            .iter()
            .map(|event| encode_event(execution_id, event))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(encoded) => encoded,
            Err(source) => return Err(note_failure(store, execution_id, events, source)),
        };
        match commit_batch(store, execution_id, &encoded) {
            Ok(()) => {
                if let Err(source) = clear_event_write_failure(store, execution_id) {
                    return Err(note_failure(store, execution_id, events, source));
                }
                Ok(events.len())
            }
            Err(source) => Err(note_failure(store, execution_id, events, source)),
        }
    }

    /// Drains `cursor` until every sender is gone, writing batches.
    ///
    /// This call waits while the channel is empty and a sender is still
    /// alive. A storage failure returns the failed batch plus every event
    /// still queued. Events already committed stay committed and are counted
    /// on the error. They are not written again by this call.
    pub fn drain(
        &self,
        store: &mut Store,
        execution_id: &ExecutionId,
        cursor: &EventCursor,
    ) -> Result<u64, EventWriteError> {
        let mut persisted = 0u64;
        loop {
            let mut batch = Vec::with_capacity(self.batch_limit);
            let mut disconnected = false;
            while batch.len() < self.batch_limit {
                match cursor.recv() {
                    Ok(event) => batch.push(event),
                    Err(CursorError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                    Err(CursorError::Empty | CursorError::TimedOut) => {
                        let error =
                            note_failure(store, execution_id, batch, StoreError::EventCursorFailed);
                        return Err(take_queued(cursor, persisted, error));
                    }
                }
            }
            if batch.is_empty() {
                return Ok(persisted);
            }
            match self.write_batch(store, execution_id, batch) {
                Ok(count) => {
                    persisted += u64::try_from(count).expect("batch count fits in u64");
                    if disconnected {
                        return Ok(persisted);
                    }
                }
                Err(error) => return Err(take_queued(cursor, persisted, error)),
            }
        }
    }
}

/// A batch that was not committed.
///
/// `unpersisted` is every event this call did not commit, including events
/// pulled from the cursor after the failing batch. Display does not print
/// resource names or evidence.
#[derive(Debug)]
pub struct EventWriteError {
    persisted: u64,
    unpersisted: Vec<ObservedEvent>,
    signaled: CoverageStatus,
    source: Box<StoreError>,
}

impl EventWriteError {
    /// Events committed by earlier batches in the same drain.
    #[must_use]
    pub const fn persisted(&self) -> u64 {
        self.persisted
    }

    /// Events the caller still holds. This slice is not a successful write.
    #[must_use]
    pub fn unpersisted(&self) -> &[ObservedEvent] {
        &self.unpersisted
    }

    /// Returns the events that were not committed.
    #[must_use]
    pub fn into_unpersisted(self) -> Vec<ObservedEvent> {
        self.unpersisted
    }

    /// Coverage this failure is allowed to signal.
    ///
    /// The value is [`CoverageStatus::Incomplete`]. It is not `COMPLETE`.
    #[must_use]
    pub const fn coverage(&self) -> CoverageStatus {
        self.signaled
    }

    /// Whether this failure may be recorded as `COMPLETE`.
    ///
    /// This is true only when the signaled coverage is complete. The
    /// constructor sets that coverage to `INCOMPLETE`, so a storage failure
    /// does not allow `COMPLETE`.
    #[must_use]
    pub const fn allows_complete_coverage(&self) -> bool {
        self.signaled.is_complete()
    }

    /// Downgrades a declared status after this failure.
    ///
    /// `COMPLETE` becomes the failure's coverage, which is `INCOMPLETE`.
    /// `INCOMPLETE` and `UNSUPPORTED` stay as declared. The result is never
    /// `COMPLETE`.
    #[must_use]
    pub fn downgrade(&self, declared: CoverageStatus) -> CoverageStatus {
        if declared.is_complete() {
            self.coverage()
        } else {
            declared
        }
    }

    /// Storage error that stopped the batch.
    #[must_use]
    pub fn store_error(&self) -> &StoreError {
        &self.source
    }
}

impl Display for EventWriteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "event batch was not persisted ({} events remain with the caller): {}",
            self.unpersisted.len(),
            self.source
        )
    }
}

impl Error for EventWriteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

struct EncodedEvent {
    sequence: i64,
    monotonic_nanos: i64,
    pid: Option<i64>,
    tid: Option<i64>,
    parent_pid: Option<i64>,
    action: &'static str,
    resource_kind: &'static str,
    canonical_resource: String,
    outcome_status: &'static str,
    errno: Option<i64>,
    failure_reason: Option<String>,
    evidence_byte_length: Option<i64>,
}

fn note_failure(
    store: &mut Store,
    execution_id: &ExecutionId,
    events: Vec<ObservedEvent>,
    source: StoreError,
) -> EventWriteError {
    remember_event_write_failure(store, execution_id);
    EventWriteError {
        persisted: 0,
        unpersisted: events,
        signaled: CoverageStatus::Incomplete,
        source: Box::new(source),
    }
}

fn take_queued(
    cursor: &EventCursor,
    persisted_before: u64,
    mut error: EventWriteError,
) -> EventWriteError {
    while let Ok(event) = cursor.try_recv() {
        error.unpersisted.push(event);
    }
    error.persisted = persisted_before.saturating_add(error.persisted);
    error
}

fn remember_event_write_failure(store: &mut Store, execution_id: &ExecutionId) {
    store.event_write_failures.insert(execution_id.clone());
    // A missing execution cannot hold the marker. The caller still receives
    // the original error and the unpersisted events.
    let _ = store.connection.execute(
        "INSERT OR IGNORE INTO execution_event_failures (execution_id) VALUES (?1)",
        params![execution_id.as_str()],
    );
}

fn clear_event_write_failure(
    store: &mut Store,
    execution_id: &ExecutionId,
) -> Result<(), StoreError> {
    let path = store.path.clone();
    store
        .connection
        .execute(
            "DELETE FROM execution_event_failures WHERE execution_id = ?1",
            params![execution_id.as_str()],
        )
        .map_err(|source| map_sqlite(&path, source))?;
    store.event_write_failures.remove(execution_id);
    Ok(())
}

fn encode_event(
    execution_id: &ExecutionId,
    event: &ObservedEvent,
) -> Result<EncodedEvent, StoreError> {
    if event.execution_id().raw() != execution_id.to_raw() {
        return Err(StoreError::EventExecutionMismatch);
    }
    let (resource_kind, canonical_resource) = encode_resource(event.resource())?;
    let (outcome_status, errno, failure_reason) = encode_outcome(event.outcome());
    let parent_pid = event.parent().map(|parent| i64::from(parent.pid()));
    Ok(EncodedEvent {
        sequence: sqlite_i64(event.sequence())?,
        monotonic_nanos: sqlite_i64(event.timestamp().nanos())?,
        pid: event.process().pid().map(i64::from),
        tid: event.process().tid().map(i64::from),
        parent_pid,
        action: event.operation().as_str(),
        resource_kind,
        canonical_resource,
        outcome_status,
        errno,
        failure_reason,
        evidence_byte_length: encode_evidence(event.evidence())?,
    })
}

pub(crate) fn encode_resource(
    resource: &ObservedResource,
) -> Result<(&'static str, String), StoreError> {
    match resource {
        ObservedResource::File { path } => {
            Ok(("file", canonical_resource(CanonicalResource::File(path))?))
        }
        ObservedResource::Executable { identity } => Ok((
            "executable",
            canonical_resource(CanonicalResource::Executable(identity))?,
        )),
        ObservedResource::Network { host, port } => {
            // SPEC-004 limits the host to 255 bytes. The shared encoder used
            // to accept 256..=4096 for every field. The write path applies
            // the observer cap before that encoder runs.
            if host.len() > MAX_NETWORK_HOST_BYTES {
                return Err(StoreError::NetworkHostTooLong);
            }
            Ok((
                "network",
                canonical_resource(CanonicalResource::Network { host, port: *port })?,
            ))
        }
    }
}

fn encode_outcome(outcome: &Outcome) -> (&'static str, Option<i64>, Option<String>) {
    match outcome {
        Outcome::Success {} => ("success", None, None),
        Outcome::Failure { errno, reason } => (
            "failure",
            errno.map(i64::from),
            reason.as_ref().map(|reason| reason.as_str().to_owned()),
        ),
    }
}

fn encode_evidence(evidence: EvidenceMeta) -> Result<Option<i64>, StoreError> {
    evidence.byte_length().map(sqlite_i64).transpose()
}

fn commit_batch(
    store: &mut Store,
    execution_id: &ExecutionId,
    encoded: &[EncodedEvent],
) -> Result<(), StoreError> {
    let path = store.path.clone();
    let transaction = store
        .connection
        .transaction()
        .map_err(|source| map_sqlite(&path, source))?;
    if let Err(source) = insert_all(&transaction, &path, execution_id, encoded) {
        if let Err(rollback) = transaction.rollback() {
            return Err(map_sqlite(&path, rollback));
        }
        return Err(source);
    }
    transaction
        .commit()
        .map_err(|source| map_sqlite(&path, source))
}

fn insert_all(
    transaction: &Transaction<'_>,
    path: &std::path::Path,
    execution_id: &ExecutionId,
    encoded: &[EncodedEvent],
) -> Result<(), StoreError> {
    let exists: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM executions WHERE execution_id = ?1",
            params![execution_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| map_sqlite(path, source))?;
    if exists.is_none() {
        return Err(StoreError::ExecutionNotFound {
            id: execution_id.as_str().to_owned(),
        });
    }
    let mut last = transaction
        .query_row(
            "SELECT MAX(sequence) FROM events WHERE execution_id = ?1",
            params![execution_id.as_str()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|source| map_sqlite(path, source))?;
    for event in encoded {
        if let Some(previous) = last {
            if event.sequence <= previous {
                return Err(if event.sequence == previous {
                    StoreError::DuplicateEventSequence
                } else {
                    StoreError::SequenceRegression
                });
            }
        }
        transaction
            .execute(
                "INSERT INTO events (
                    execution_id, sequence, monotonic_nanos, pid, tid, parent_pid,
                    action, resource_kind, canonical_resource, outcome_status,
                    errno, failure_reason, evidence_byte_length
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    execution_id.as_str(),
                    event.sequence,
                    event.monotonic_nanos,
                    event.pid,
                    event.tid,
                    event.parent_pid,
                    event.action,
                    event.resource_kind,
                    event.canonical_resource,
                    event.outcome_status,
                    event.errno,
                    event.failure_reason,
                    event.evidence_byte_length,
                ],
            )
            .map_err(|source| map_sqlite(path, source))?;
        last = Some(event.sequence);
    }
    Ok(())
}
