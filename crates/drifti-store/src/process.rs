// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution-scoped process lineage.
//!
//! A pid names a process only inside one execution. The same pid in another
//! execution is a different row. Recording lineage does not authorize the
//! process, and this module does not store argument vectors or secrets.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StoreError;
use crate::execution::ExecutionId;
use crate::map_sqlite;
use crate::Store;

/// One process observed inside a single execution.
///
/// `pid` is not an execution id. `parent_pid` is the parent inside that same
/// execution, when the backend knew it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pid: u32,
    tid: Option<u32>,
    parent_pid: Option<u32>,
}

impl ProcessRecord {
    /// Builds a process record.
    ///
    /// A process cannot name itself as its parent. That link would make every
    /// lineage walk a cycle.
    pub fn try_new(
        pid: u32,
        tid: Option<u32>,
        parent_pid: Option<u32>,
    ) -> Result<Self, StoreError> {
        if parent_pid == Some(pid) {
            return Err(StoreError::InvalidProcessParent);
        }
        Ok(Self {
            pid,
            tid,
            parent_pid,
        })
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    #[must_use]
    pub fn tid(&self) -> Option<u32> {
        self.tid
    }

    #[must_use]
    pub fn parent_pid(&self) -> Option<u32> {
        self.parent_pid
    }
}

/// Ancestors and direct children of one process, all inside one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLineage {
    execution_id: ExecutionId,
    process: ProcessRecord,
    ancestors: Vec<ProcessRecord>,
    children: Vec<ProcessRecord>,
}

impl ProcessLineage {
    #[must_use]
    pub fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }

    #[must_use]
    pub fn process(&self) -> &ProcessRecord {
        &self.process
    }

    /// Parent chain, root first. A parent that was not recorded is absent.
    /// The chain does not include the process itself.
    #[must_use]
    pub fn ancestors(&self) -> &[ProcessRecord] {
        &self.ancestors
    }

    /// Direct children in this execution, ordered by pid.
    #[must_use]
    pub fn children(&self) -> &[ProcessRecord] {
        &self.children
    }
}

/// Process lineage queries. The methods do not take SQL.
///
/// Every read and write is limited to one execution id. A pid from another
/// execution is not a match.
pub trait ProcessRepository {
    /// Inserts lineage for `execution_id`.
    ///
    /// The same pid and the same parent/tid pair is idempotent. A different
    /// pair for that pid fails and leaves the first row in place.
    fn record_process(
        &mut self,
        execution_id: &ExecutionId,
        process: ProcessRecord,
    ) -> Result<ProcessRecord, StoreError>;

    /// Every process in the execution, ordered by pid.
    ///
    /// An unknown execution is an error. An execution with no processes is
    /// an empty list, which is not a missing execution.
    fn processes(&self, execution_id: &ExecutionId) -> Result<Vec<ProcessRecord>, StoreError>;

    /// Ancestors and direct children of `pid` inside `execution_id`.
    fn process_lineage(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<ProcessLineage, StoreError>;
}

impl Store {
    /// Inserts lineage for `execution_id`.
    pub fn record_process(
        &mut self,
        execution_id: &ExecutionId,
        process: ProcessRecord,
    ) -> Result<ProcessRecord, StoreError> {
        self.ensure_execution(execution_id)?;
        if let Some(existing) = self.load_process(execution_id, process.pid())? {
            if existing == process {
                return Ok(existing);
            }
            return Err(StoreError::ProcessConflict {
                execution_id: execution_id.as_str().to_owned(),
                pid: process.pid(),
            });
        }
        let path = self.path.clone();
        self.connection
            .execute(
                "INSERT INTO processes (execution_id, pid, tid, parent_pid)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    execution_id.as_str(),
                    i64::from(process.pid()),
                    process.tid().map(i64::from),
                    process.parent_pid().map(i64::from),
                ],
            )
            .map_err(|source| map_sqlite(&path, source))?;
        Ok(process)
    }

    /// Every process in the execution, ordered by pid.
    pub fn processes(&self, execution_id: &ExecutionId) -> Result<Vec<ProcessRecord>, StoreError> {
        self.ensure_execution(execution_id)?;
        let rows = load_processes(&self.connection, &self.path, execution_id)?;
        Ok(rows.into_values().collect())
    }

    /// Ancestors and direct children of `pid` inside `execution_id`.
    pub fn process_lineage(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<ProcessLineage, StoreError> {
        self.ensure_execution(execution_id)?;
        let rows = load_processes(&self.connection, &self.path, execution_id)?;
        let process = rows.get(&pid).cloned().ok_or(StoreError::ProcessNotFound {
            execution_id: execution_id.as_str().to_owned(),
            pid,
        })?;
        let ancestors = ancestor_chain(execution_id, &rows, &process)?;
        let children = rows
            .values()
            .filter(|row| row.parent_pid() == Some(pid))
            .cloned()
            .collect();
        Ok(ProcessLineage {
            execution_id: execution_id.clone(),
            process,
            ancestors,
            children,
        })
    }

    fn ensure_execution(&self, execution_id: &ExecutionId) -> Result<(), StoreError> {
        let present: Option<i64> = self
            .connection
            .query_row(
                "SELECT 1 FROM executions WHERE execution_id = ?1",
                params![execution_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| map_sqlite(&self.path, source))?;
        if present.is_none() {
            return Err(StoreError::ExecutionNotFound {
                id: execution_id.as_str().to_owned(),
            });
        }
        Ok(())
    }

    fn load_process(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<Option<ProcessRecord>, StoreError> {
        let raw = self
            .connection
            .query_row(
                "SELECT pid, tid, parent_pid FROM processes
                 WHERE execution_id = ?1 AND pid = ?2",
                params![execution_id.as_str(), i64::from(pid)],
                |row| {
                    Ok(RawProcess {
                        pid: row.get(0)?,
                        tid: row.get(1)?,
                        parent_pid: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|source| map_sqlite(&self.path, source))?;
        raw.map(ProcessRecord::from_stored).transpose()
    }
}

impl ProcessRepository for Store {
    fn record_process(
        &mut self,
        execution_id: &ExecutionId,
        process: ProcessRecord,
    ) -> Result<ProcessRecord, StoreError> {
        Store::record_process(self, execution_id, process)
    }

    fn processes(&self, execution_id: &ExecutionId) -> Result<Vec<ProcessRecord>, StoreError> {
        Store::processes(self, execution_id)
    }

    fn process_lineage(
        &self,
        execution_id: &ExecutionId,
        pid: u32,
    ) -> Result<ProcessLineage, StoreError> {
        Store::process_lineage(self, execution_id, pid)
    }
}

struct RawProcess {
    pid: i64,
    tid: Option<i64>,
    parent_pid: Option<i64>,
}

fn load_processes(
    connection: &Connection,
    path: &std::path::Path,
    execution_id: &ExecutionId,
) -> Result<BTreeMap<u32, ProcessRecord>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT pid, tid, parent_pid FROM processes
             WHERE execution_id = ?1 ORDER BY pid",
        )
        .map_err(|source| map_sqlite(path, source))?;
    let rows = statement
        .query_map(params![execution_id.as_str()], |row| {
            Ok(RawProcess {
                pid: row.get(0)?,
                tid: row.get(1)?,
                parent_pid: row.get(2)?,
            })
        })
        .map_err(|source| map_sqlite(path, source))?;
    let mut processes = BTreeMap::new();
    for row in rows {
        let raw = row.map_err(|source| map_sqlite(path, source))?;
        let record = ProcessRecord::from_stored(raw)?;
        processes.insert(record.pid(), record);
    }
    Ok(processes)
}

fn ancestor_chain(
    execution_id: &ExecutionId,
    rows: &BTreeMap<u32, ProcessRecord>,
    process: &ProcessRecord,
) -> Result<Vec<ProcessRecord>, StoreError> {
    let mut chain = Vec::new();
    let mut seen = BTreeSet::from([process.pid()]);
    let mut cursor = process.parent_pid();
    while let Some(parent_pid) = cursor {
        if !seen.insert(parent_pid) {
            return Err(StoreError::ProcessCycle {
                execution_id: execution_id.as_str().to_owned(),
                pid: process.pid(),
            });
        }
        let Some(parent) = rows.get(&parent_pid) else {
            break;
        };
        chain.push(parent.clone());
        cursor = parent.parent_pid();
    }
    chain.reverse();
    Ok(chain)
}

impl ProcessRecord {
    fn from_stored(raw: RawProcess) -> Result<Self, StoreError> {
        let pid = pid_from_stored(raw.pid)?;
        let tid = raw.tid.map(pid_from_stored).transpose()?;
        let parent_pid = raw.parent_pid.map(pid_from_stored).transpose()?;
        if parent_pid == Some(pid) {
            return Err(StoreError::CorruptProcess);
        }
        Ok(Self {
            pid,
            tid,
            parent_pid,
        })
    }
}

fn pid_from_stored(value: i64) -> Result<u32, StoreError> {
    u32::try_from(value).map_err(|_| StoreError::CorruptProcess)
}
