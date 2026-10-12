// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository reads for executions and semantic events.
//!
//! Callers use [`ReadRepository`]. They do not send SQL. Order inside one
//! execution is `sequence`. The monotonic timestamp is returned on each event
//! and is not an order key.
//!
//! The action query is an equality lookup on `action`, the column of schema
//! v1 `idx_events_action`. The resource query is an equality lookup on
//! `canonical_resource`, the column of `idx_events_canonical_resource`.
//! Neither query adds an index. The per-execution query filters by execution
//! id and orders by sequence. The primary key of `events` is
//! `(execution_id, sequence)`, and schema v1 also has
//! `idx_events_execution_id_sequence` on that same key.
//!
//! A missing execution is an error. An execution with no events is an empty
//! list. A row that cannot be decoded fails the read. The row is not skipped.
//! Coverage stays on [`ExecutionRecord`]. Outcome and evidence length stay on
//! each [`ObservedEvent`]. Argument vectors, file bytes, network payloads,
//! secrets, prompts, and model responses are not columns and are not
//! reconstructed.
//!
//! Process lineage is [`crate::ProcessRepository::process_lineage`]. This
//! module does not issue a second lineage query. [`ReadRepository::process_lineage`]
//! calls that lookup.

use drifti_observer::{
    EvidenceMeta, FailureReason, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation,
    Outcome, ParentIdentity, ProcessIdentity,
};
use rusqlite::{params, Connection, Row};

use crate::error::StoreError;
use crate::events::encode_resource;
use crate::execution::{ExecutionId, ExecutionRecord};
use crate::map_sqlite;
use crate::process::{ProcessLineage, ProcessRecord};
use crate::schema::{parse_canonical_resource, OwnedCanonicalResource};
use crate::Store;

/// One execution as a learning or verification consumer reads it.
///
/// `execution` holds coverage. `events` are ordered by sequence. `processes`
/// are the rows [`crate::ProcessRepository::process_lineage`] walks. Reading
/// this value does not authorize a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHistory {
    execution: ExecutionRecord,
    events: Vec<ObservedEvent>,
    processes: Vec<ProcessRecord>,
}

impl ExecutionHistory {
    #[must_use]
    pub fn execution(&self) -> &ExecutionRecord {
        &self.execution
    }

    /// Events for this execution, ordered by sequence.
    #[must_use]
    pub fn events(&self) -> &[ObservedEvent] {
        &self.events
    }

    /// Process rows recorded for this execution, ordered by pid.
    #[must_use]
    pub fn processes(&self) -> &[ProcessRecord] {
        &self.processes
    }
}

/// Reads required by learning, verification, and evidence.
///
/// The methods do not take SQL. [`Self::process_lineage`] is the existing
/// execution-scoped lineage lookup.
pub trait ReadRepository {
    /// Events for one execution, ordered by sequence.
    ///
    /// A missing execution is [`StoreError::ExecutionNotFound`]. An execution
    /// with no events is an empty list.
    fn events_for_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Vec<ObservedEvent>, StoreError>;

    /// Events whose action is `action`, ordered by execution id, then sequence.
    ///
    /// An action with no rows is an empty list. The lookup is equality on
    /// `events.action`.
    fn events_by_action(&self, action: Operation) -> Result<Vec<ObservedEvent>, StoreError>;

    /// Events whose canonical resource equals `resource`.
    ///
    /// The resource is encoded with the same form the writer stores, then
    /// matched by equality on `events.canonical_resource`. Results are ordered
    /// by execution id, then sequence. No match is an empty list.
    fn events_by_resource(
        &self,
        resource: &ObservedResource,
    ) -> Result<Vec<ObservedEvent>, StoreError>;

    /// The execution record, its events in sequence order, and its process rows.
    ///
    /// Coverage, outcome, and evidence length are the stored values. Process
    /// lineage for one pid is [`Self::process_lineage`].
    fn execution_history(&self, execution_id: &ExecutionId)
        -> Result<ExecutionHistory, StoreError>;

    /// Ancestors and direct children of `pid` inside one execution.
    ///
    /// This is [`crate::ProcessRepository::process_lineage`]. A pid from
    /// another execution is not a match.
    fn process_lineage(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<ProcessLineage, StoreError>;
}

/// Equality on the primary key, then sequence order.
const EVENTS_FOR_EXECUTION_SQL: &str = "\
SELECT execution_id, sequence, monotonic_nanos, pid, tid, parent_pid, \
action, resource_kind, canonical_resource, outcome_status, errno, \
failure_reason, evidence_byte_length \
FROM events \
WHERE execution_id = ?1 \
ORDER BY sequence";

/// Equality on `action` for `idx_events_action`.
const EVENTS_BY_ACTION_SQL: &str = "\
SELECT execution_id, sequence, monotonic_nanos, pid, tid, parent_pid, \
action, resource_kind, canonical_resource, outcome_status, errno, \
failure_reason, evidence_byte_length \
FROM events \
WHERE action = ?1 \
ORDER BY execution_id, sequence";

/// Equality on `canonical_resource` for `idx_events_canonical_resource`.
const EVENTS_BY_RESOURCE_SQL: &str = "\
SELECT execution_id, sequence, monotonic_nanos, pid, tid, parent_pid, \
action, resource_kind, canonical_resource, outcome_status, errno, \
failure_reason, evidence_byte_length \
FROM events \
WHERE canonical_resource = ?1 \
ORDER BY execution_id, sequence";

impl Store {
    /// Events for one execution, ordered by sequence.
    pub fn events_for_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Vec<ObservedEvent>, StoreError> {
        let _execution = self.get_execution(execution_id)?;
        let events = collect_events(
            &self.connection,
            &self.path,
            EVENTS_FOR_EXECUTION_SQL,
            params![execution_id.as_str()],
        )?;
        if events
            .iter()
            .any(|event| event.execution_id().raw() != execution_id.to_raw())
        {
            return Err(StoreError::CorruptEvent);
        }
        Ok(events)
    }

    /// Events for one action, ordered by execution id, then sequence.
    pub fn events_by_action(&self, action: Operation) -> Result<Vec<ObservedEvent>, StoreError> {
        let events = collect_events(
            &self.connection,
            &self.path,
            EVENTS_BY_ACTION_SQL,
            params![action.as_str()],
        )?;
        if events.iter().any(|event| event.operation() != action) {
            return Err(StoreError::CorruptEvent);
        }
        Ok(events)
    }

    /// Events for one canonical resource, ordered by execution id, then sequence.
    pub fn events_by_resource(
        &self,
        resource: &ObservedResource,
    ) -> Result<Vec<ObservedEvent>, StoreError> {
        let (_kind, canonical) = encode_resource(resource)?;
        let events = collect_events(
            &self.connection,
            &self.path,
            EVENTS_BY_RESOURCE_SQL,
            params![canonical],
        )?;
        if events.iter().any(|event| event.resource() != resource) {
            return Err(StoreError::CorruptEvent);
        }
        Ok(events)
    }

    /// Execution record, sequence-ordered events, and process rows.
    pub fn execution_history(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<ExecutionHistory, StoreError> {
        let execution = self.get_execution(execution_id)?;
        let events = self.events_for_execution(execution_id)?;
        let processes = self.processes(execution_id)?;
        Ok(ExecutionHistory {
            execution,
            events,
            processes,
        })
    }
}

impl ReadRepository for Store {
    fn events_for_execution(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<Vec<ObservedEvent>, StoreError> {
        Store::events_for_execution(self, execution_id)
    }

    fn events_by_action(&self, action: Operation) -> Result<Vec<ObservedEvent>, StoreError> {
        Store::events_by_action(self, action)
    }

    fn events_by_resource(
        &self,
        resource: &ObservedResource,
    ) -> Result<Vec<ObservedEvent>, StoreError> {
        Store::events_by_resource(self, resource)
    }

    fn execution_history(
        &self,
        execution_id: &ExecutionId,
    ) -> Result<ExecutionHistory, StoreError> {
        Store::execution_history(self, execution_id)
    }

    fn process_lineage(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<ProcessLineage, StoreError> {
        Store::process_lineage(self, execution_id, pid)
    }
}

struct RawEvent {
    execution_id: String,
    sequence: i64,
    monotonic_nanos: i64,
    pid: Option<i64>,
    tid: Option<i64>,
    parent_pid: Option<i64>,
    action: String,
    resource_kind: String,
    canonical_resource: String,
    outcome_status: String,
    errno: Option<i64>,
    failure_reason: Option<String>,
    evidence_byte_length: Option<i64>,
}

fn collect_events(
    connection: &Connection,
    path: &std::path::Path,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<ObservedEvent>, StoreError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|source| map_sqlite(path, source))?;
    let rows = statement
        .query_map(params, map_raw_event)
        .map_err(|source| map_sqlite(path, source))?;
    let mut events = Vec::new();
    for row in rows {
        let raw = row.map_err(|source| map_sqlite(path, source))?;
        events.push(decode_event(raw)?);
    }
    Ok(events)
}

fn map_raw_event(row: &Row<'_>) -> rusqlite::Result<RawEvent> {
    Ok(RawEvent {
        execution_id: row.get(0)?,
        sequence: row.get(1)?,
        monotonic_nanos: row.get(2)?,
        pid: row.get(3)?,
        tid: row.get(4)?,
        parent_pid: row.get(5)?,
        action: row.get(6)?,
        resource_kind: row.get(7)?,
        canonical_resource: row.get(8)?,
        outcome_status: row.get(9)?,
        errno: row.get(10)?,
        failure_reason: row.get(11)?,
        evidence_byte_length: row.get(12)?,
    })
}

fn decode_event(raw: RawEvent) -> Result<ObservedEvent, StoreError> {
    let execution_id =
        ExecutionId::parse(&raw.execution_id).map_err(|_| StoreError::CorruptEvent)?;
    let operation = parse_operation(&raw.action)?;
    let resource = decode_resource(&raw.resource_kind, &raw.canonical_resource)?;
    let outcome = decode_outcome(&raw.outcome_status, raw.errno, raw.failure_reason)?;
    let parent = optional_u32(raw.parent_pid)?.map(ParentIdentity::new);
    Ok(ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(execution_id.to_raw()),
        u64_from_stored(raw.sequence)?,
        MonotonicTimestamp::from_nanos(u64_from_stored(raw.monotonic_nanos)?),
        ProcessIdentity::new(optional_u32(raw.pid)?, optional_u32(raw.tid)?),
        parent,
        operation,
        resource,
        outcome,
        decode_evidence(raw.evidence_byte_length)?,
    ))
}

fn parse_operation(action: &str) -> Result<Operation, StoreError> {
    Operation::ALL
        .into_iter()
        .find(|operation| operation.as_str() == action)
        .ok_or(StoreError::CorruptEvent)
}

fn decode_resource(kind: &str, canonical: &str) -> Result<ObservedResource, StoreError> {
    let parsed = parse_canonical_resource(canonical).map_err(|_| StoreError::CorruptEvent)?;
    match (kind, parsed) {
        ("file", OwnedCanonicalResource::File(path)) => {
            ObservedResource::file(path).map_err(|_| StoreError::CorruptEvent)
        }
        ("executable", OwnedCanonicalResource::Executable(identity)) => {
            ObservedResource::executable(identity).map_err(|_| StoreError::CorruptEvent)
        }
        ("network", OwnedCanonicalResource::Network { host, port }) => {
            ObservedResource::network(host, port).map_err(|_| StoreError::CorruptEvent)
        }
        _ => Err(StoreError::CorruptEvent),
    }
}

fn decode_outcome(
    status: &str,
    errno: Option<i64>,
    reason: Option<String>,
) -> Result<Outcome, StoreError> {
    match status {
        "success" => {
            if errno.is_some() || reason.is_some() {
                return Err(StoreError::CorruptEvent);
            }
            Ok(Outcome::success())
        }
        "failure" => {
            let errno = match errno {
                None => None,
                Some(value) => Some(i32::try_from(value).map_err(|_| StoreError::CorruptEvent)?),
            };
            let reason = match reason {
                None => None,
                Some(text) => Some(FailureReason::new(text).map_err(|_| StoreError::CorruptEvent)?),
            };
            Ok(Outcome::failure(errno, reason))
        }
        _ => Err(StoreError::CorruptEvent),
    }
}

fn decode_evidence(value: Option<i64>) -> Result<EvidenceMeta, StoreError> {
    match value {
        None => Ok(EvidenceMeta::empty()),
        Some(length) => {
            let length = u64::try_from(length).map_err(|_| StoreError::CorruptEvent)?;
            Ok(EvidenceMeta::with_byte_length(length))
        }
    }
}

fn optional_u32(value: Option<i64>) -> Result<Option<u32>, StoreError> {
    value
        .map(|value| u32::try_from(value).map_err(|_| StoreError::CorruptEvent))
        .transpose()
}

fn u64_from_stored(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptEvent)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::types::ValueRef;
    use rusqlite::Params;

    use super::{EVENTS_BY_ACTION_SQL, EVENTS_BY_RESOURCE_SQL, EVENTS_FOR_EXECUTION_SQL};
    use crate::Store;

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "drifti-store-read-{name}-{}-{nanos}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create workspace");
        path
    }

    fn order_by(sql: &str) -> &str {
        sql.rsplit("ORDER BY").next().expect("order clause").trim()
    }

    #[test]
    fn read_sql_orders_by_sequence_and_matches_indexed_columns() {
        assert_eq!(order_by(EVENTS_FOR_EXECUTION_SQL), "sequence");
        assert_eq!(order_by(EVENTS_BY_ACTION_SQL), "execution_id, sequence");
        assert_eq!(order_by(EVENTS_BY_RESOURCE_SQL), "execution_id, sequence");
        assert!(EVENTS_FOR_EXECUTION_SQL.contains("WHERE execution_id = ?1"));
        assert!(EVENTS_BY_ACTION_SQL.contains("WHERE action = ?1"));
        assert!(EVENTS_BY_RESOURCE_SQL.contains("WHERE canonical_resource = ?1"));
        for sql in [
            EVENTS_FOR_EXECUTION_SQL,
            EVENTS_BY_ACTION_SQL,
            EVENTS_BY_RESOURCE_SQL,
        ] {
            assert!(!order_by(sql).contains("monotonic"));
            assert!(!sql.contains("SELECT *"));
            assert!(!sql.contains("argv"));
            assert!(!sql.contains("payload"));
            assert!(!sql.contains("secret"));
            assert!(!sql.contains("prompt"));
        }
    }

    #[test]
    fn explain_uses_the_schema_v1_action_and_resource_indexes() {
        // Schema v1 already defines idx_events_action and
        // idx_events_canonical_resource. These reads do not create another
        // index. Equality on the indexed column is the access path. EXPLAIN
        // QUERY PLAN names that index when the bundled planner selects it.
        // A one-page table can SCAN because a scan is cheaper than an index
        // lookup; the rows below plus ANALYZE give the planner a selective
        // resource key and a repeated action key. The asserted plan is the
        // plan of the read SQL, not a handwritten INDEXED BY clause.
        let workspace = workspace("plan");
        let mut store = Store::open(&workspace).expect("open");
        let custom_indexes = index_names(&store.connection)
            .into_iter()
            .filter(|name| name.starts_with("idx_events_"))
            .collect::<Vec<_>>();
        assert_eq!(
            custom_indexes,
            vec![
                "idx_events_action".to_owned(),
                "idx_events_canonical_resource".to_owned(),
                "idx_events_execution_id".to_owned(),
                "idx_events_execution_id_sequence".to_owned(),
            ]
        );

        let execution_id = "ab".repeat(16);
        let transaction = store.connection.transaction().expect("begin");
        transaction
            .execute(
                "INSERT INTO executions (execution_id, lifecycle) VALUES (?1, 'started')",
                rusqlite::params![execution_id],
            )
            .expect("execution");
        let actions = [
            "filesystem.read",
            "filesystem.write",
            "filesystem.metadata",
            "process.execute",
            "network.connect",
            "network.listen",
        ];
        for sequence in 0..400_i64 {
            let action = actions[usize::try_from(sequence).expect("sequence") % actions.len()];
            transaction
                .execute(
                    "INSERT INTO events (
                        execution_id, sequence, monotonic_nanos, action, resource_kind,
                        canonical_resource, outcome_status
                     ) VALUES (?1, ?2, ?3, ?4, 'file', ?5, 'success')",
                    rusqlite::params![
                        execution_id,
                        sequence,
                        400 - sequence,
                        action,
                        format!("r{sequence}")
                    ],
                )
                .expect("event");
        }
        transaction.execute_batch("ANALYZE").expect("analyze");
        transaction.commit().expect("commit");

        let action_plan = explain(
            &store.connection,
            EVENTS_BY_ACTION_SQL,
            rusqlite::params!["filesystem.read"],
        );
        let resource_plan = explain(
            &store.connection,
            EVENTS_BY_RESOURCE_SQL,
            rusqlite::params!["r0"],
        );
        let execution_plan = explain(
            &store.connection,
            EVENTS_FOR_EXECUTION_SQL,
            rusqlite::params![execution_id],
        );
        assert!(
            action_plan.contains("idx_events_action"),
            "action query plan: {action_plan}"
        );
        assert!(
            resource_plan.contains("idx_events_canonical_resource"),
            "resource query plan: {resource_plan}"
        );
        assert!(
            execution_plan.contains("idx_events_execution_id_sequence")
                || execution_plan.contains("sqlite_autoindex_events_1"),
            "execution query plan: {execution_plan}"
        );
        assert!(!execution_plan.contains("monotonic_nanos"));
        drop(store);
        let _ = fs::remove_dir_all(workspace);
    }

    fn index_names(connection: &rusqlite::Connection) -> Vec<String> {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("indexes");
        statement
            .query_map([], |row| row.get(0))
            .expect("query indexes")
            .collect::<Result<Vec<_>, _>>()
            .expect("index names")
    }

    fn explain<P: Params>(connection: &rusqlite::Connection, sql: &str, params: P) -> String {
        let mut statement = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("explain");
        let column_count = statement.column_count();
        let mut rows = statement.query(params).expect("plan rows");
        let mut lines = Vec::new();
        while let Some(row) = rows.next().expect("plan row") {
            let mut parts = Vec::new();
            for index in 0..column_count {
                parts.push(match row.get_ref(index).expect("plan column") {
                    ValueRef::Null => "null".to_owned(),
                    ValueRef::Integer(value) => value.to_string(),
                    ValueRef::Real(value) => value.to_string(),
                    ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
                    ValueRef::Blob(_) => "blob".to_owned(),
                });
            }
            lines.push(parts.join(" "));
        }
        lines.join("\n")
    }
}
