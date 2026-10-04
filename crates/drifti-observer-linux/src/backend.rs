// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Observer`](drifti_observer::Observer) adapter for the ptrace lifecycle.
//!
//! The adapter does not decode semantic events and does not advertise
//! capability domains. [`ExecutionResult`](drifti_observer::ExecutionResult)
//! coverage is `INCOMPLETE`. A launch or trace failure is
//! [`ObserverError::ObservationFailed`](drifti_observer::ObserverError::ObservationFailed),
//! not a successful result.

use drifti_observer::{
    CommandSpec, EventSink, ExecutionId, ExecutionResult, ObservationFailureReason, Observer,
    ObserverCapabilities, ObserverError,
};

use crate::lifecycle::AcknowledgeStops;
use crate::session::TraceSession;

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
        let result = TraceSession::launch(self.execution_id, command)
            .and_then(|session| session.drive(&mut AcknowledgeStops));
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
