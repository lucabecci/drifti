// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared event metadata and ordering for every decoder in one execution.

use std::time::Instant;

use drifti_observer::{
    EventSink, EvidenceMeta, ExecutionId, MonotonicTimestamp, ObservedEvent, ObservedResource,
    Operation, Outcome, ParentIdentity, ProcessIdentity,
};

use crate::error::TraceError;
use crate::lineage::ThreadLineage;

pub(crate) struct EventEmitter<'a> {
    sink: &'a EventSink,
    execution_id: ExecutionId,
    started: Instant,
    sequence: u64,
}

impl<'a> EventEmitter<'a> {
    pub(crate) fn new(sink: &'a EventSink, execution_id: ExecutionId) -> Self {
        Self {
            sink,
            execution_id,
            started: Instant::now(),
            sequence: 0,
        }
    }

    pub(crate) fn emit(
        &mut self,
        lineage: &ThreadLineage,
        tid: u32,
        operation: Operation,
        resource: ObservedResource,
        outcome: Outcome,
    ) -> Result<(), TraceError> {
        let record = lineage
            .record(tid)
            .ok_or(TraceError::UnknownTracee { tid })?;
        let parent = record
            .parent_tid()
            .and_then(|parent_tid| lineage.record(parent_tid))
            .and_then(|parent| parent.tgid())
            .filter(|parent_pid| Some(*parent_pid) != record.tgid())
            .map(ParentIdentity::new);
        let nanos = self.started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let event = ObservedEvent::new(
            self.execution_id,
            self.sequence,
            MonotonicTimestamp::from_nanos(nanos),
            ProcessIdentity::new(record.tgid(), Some(tid)),
            parent,
            operation,
            resource,
            outcome,
            EvidenceMeta::empty(),
        );
        self.sink.emit(event).map_err(TraceError::Sink)?;
        self.sequence = self.sequence.checked_add(1).ok_or(TraceError::Visitor)?;
        Ok(())
    }
}
