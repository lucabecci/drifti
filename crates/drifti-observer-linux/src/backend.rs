// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Observer`](drifti_observer::Observer) adapter for the ptrace lifecycle.
//!
//! The adapter decodes supported IP network events and does not advertise
//! complete capability domains. [`ExecutionResult`](drifti_observer::ExecutionResult)
//! coverage is `INCOMPLETE`. A launch or trace failure is
//! [`ObserverError::ObservationFailed`](drifti_observer::ObserverError::ObservationFailed),
//! not a successful result.

use drifti_observer::{
    CommandSpec, EventSink, EvidenceMeta, ExecutionId, ExecutionResult, MonotonicTimestamp,
    ObservationFailureReason, ObservedEvent, Observer, ObserverCapabilities, ObserverError,
    ParentIdentity, ProcessIdentity,
};
use std::time::Instant;

use crate::lifecycle::TraceVisitor;
use crate::network::NetworkDecoder;
use crate::session::TraceSession;
use crate::{ThreadLineage, TraceError, TraceStop};

struct NetworkOnlyVisitor<'a> {
    decoder: NetworkDecoder,
    sink: &'a EventSink,
    execution_id: ExecutionId,
    origin: Instant,
    sequence: u64,
}

impl TraceVisitor for NetworkOnlyVisitor<'_> {
    fn on_stop(&mut self, stop: &TraceStop, lineage: &ThreadLineage) -> Result<(), TraceError> {
        if let Some(fact) = self.decoder.on_stop(stop, lineage)? {
            let record = lineage.record(fact.tid).ok_or(TraceError::Visitor)?;
            let nanos = self.origin.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            let event = ObservedEvent::new(
                self.execution_id,
                self.sequence,
                MonotonicTimestamp::from_nanos(nanos),
                ProcessIdentity::new(record.tgid(), Some(fact.tid)),
                record.parent_tid().map(ParentIdentity::new),
                fact.operation,
                fact.resource,
                fact.outcome,
                EvidenceMeta::empty(),
            );
            self.sink.emit(event).map_err(TraceError::Sink)?;
            self.sequence = self.sequence.checked_add(1).ok_or(TraceError::Visitor)?;
        }
        Ok(())
    }
}

/// Linux ptrace observer.
///
/// One value is one execution id. The launch input is a [`CommandSpec`].
/// Arbitrary PID attach is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxObserver {
    execution_id: ExecutionId,
}

impl LinuxObserver {
    /// Observes one execution under `execution_id`.
    #[must_use]
    pub const fn new(execution_id: ExecutionId) -> Self {
        Self { execution_id }
    }

    /// Execution id used for the lineage.
    #[must_use]
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }
}

impl Observer for LinuxObserver {
    fn capabilities(&self) -> ObserverCapabilities {
        ObserverCapabilities::new([])
    }

    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        let mut visitor = NetworkOnlyVisitor {
            decoder: NetworkDecoder::default(),
            sink: &sink,
            execution_id: self.execution_id,
            origin: Instant::now(),
            sequence: 0,
        };
        let result = TraceSession::launch(self.execution_id, command)
            .and_then(|session| session.drive(&mut visitor));
        let mapped = match result {
            Ok(report) => Ok(ExecutionResult::new(
                report.execution_id(),
                report.bootstrap_coverage(),
                report.exit_code(),
            )),
            Err(error) => Err(map_error(error)),
        };
        (sink, mapped)
    }
}

fn map_error(error: crate::error::TraceError) -> ObserverError {
    let mapped = error.into_observer_error();
    debug_assert!(matches!(
        mapped,
        ObserverError::Sink(_)
            | ObserverError::ObservationFailed {
                reason: ObservationFailureReason::Launch
                    | ObservationFailureReason::TraceInterrupted,
            }
    ));
    mapped
}
