// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic [`Observer`](crate::Observer) that replays a script.
//!
//! [`MockObserver`] emits each scripted event once, in script order, into the
//! caller's bounded [`EventSink`](crate::EventSink). It does not launch a
//! process, read Linux APIs, or depend on `drifti-core`. A failure outcome is
//! delivered. Coverage is the coverage the script declared. This type does
//! not invent `COMPLETE` and it does not drop an event that the sink rejected.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::coverage::{ExecutionCoverage, ObserverCapabilities};
use crate::event::{ExecutionId, ObservedEvent};
use crate::observer::{CommandSpec, ExecutionResult, Observer, ObserverError};
use crate::sink::EventSink;

/// One synthetic execution. Events are emitted in the order stored here.
///
/// `sequence` on each event remains the ordering authority for a consumer.
/// This script does not sort by timestamp and it does not remove failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationScript {
    execution_id: ExecutionId,
    events: Vec<ObservedEvent>,
    coverage: ExecutionCoverage,
    exit_code: Option<i32>,
}

impl ObservationScript {
    /// Builds a script. Every event must use `execution_id`.
    ///
    /// An empty event list is valid. The returned coverage is `coverage`
    /// unchanged, including when that coverage is `INCOMPLETE` or
    /// `UNSUPPORTED`.
    pub fn try_new(
        execution_id: ExecutionId,
        events: Vec<ObservedEvent>,
        coverage: ExecutionCoverage,
        exit_code: Option<i32>,
    ) -> Result<Self, MockError> {
        for event in &events {
            if event.execution_id() != execution_id {
                return Err(MockError::ForeignExecution {
                    sequence: event.sequence(),
                });
            }
        }
        Ok(Self {
            execution_id,
            events,
            coverage,
            exit_code,
        })
    }

    #[must_use]
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Events in emission order.
    #[must_use]
    pub fn events(&self) -> &[ObservedEvent] {
        &self.events
    }

    #[must_use]
    pub const fn coverage(&self) -> &ExecutionCoverage {
        &self.coverage
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

/// Replays an [`ObservationScript`] through the public observer contract.
///
/// [`Self::accepted`] counts events the current [`Observer::run`] has queued.
/// It resets to zero at the start of each run. A caller can watch it from
/// another thread while [`EventSink::emit`](crate::EventSink::emit) waits on
/// a full buffer. One run at a time: overlapping runs share this counter.
pub struct MockObserver {
    capabilities: ObserverCapabilities,
    script: ObservationScript,
    accepted: Arc<AtomicUsize>,
}

impl MockObserver {
    #[must_use]
    pub fn new(capabilities: ObserverCapabilities, script: ObservationScript) -> Self {
        Self {
            capabilities,
            script,
            accepted: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[must_use]
    pub const fn script(&self) -> &ObservationScript {
        &self.script
    }

    /// Counter incremented after each event is accepted into the sink.
    #[must_use]
    pub fn accepted(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.accepted)
    }
}

impl fmt::Debug for MockObserver {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MockObserver")
            .field("capabilities", &self.capabilities)
            .field("execution_id", &self.script.execution_id())
            .field("event_count", &self.script.events().len())
            .field("coverage", self.script.coverage())
            .field("exit_code", &self.script.exit_code())
            .finish()
    }
}

impl Observer for MockObserver {
    fn capabilities(&self) -> ObserverCapabilities {
        self.capabilities.clone()
    }

    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        // The launch input is not copied into events. Argument values stay
        // on `command` and are omitted from its `Debug` impl.
        let _ = command.program();
        self.accepted.store(0, Ordering::Release);
        for event in self.script.events() {
            if let Err(error) = sink.emit(event.clone()) {
                return (sink, Err(ObserverError::from(error)));
            }
            self.accepted.fetch_add(1, Ordering::Release);
        }
        (
            sink,
            Ok(ExecutionResult::new(
                self.script.execution_id(),
                self.script.coverage().clone(),
                self.script.exit_code(),
            )),
        )
    }
}

/// A script mixed events from more than one execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockError {
    /// `sequence` belongs to an event whose execution id differs from the script.
    ForeignExecution {
        /// Sequence of the rejected event.
        sequence: u64,
    },
}

impl Display for MockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignExecution { sequence } => {
                write!(
                    formatter,
                    "event {sequence} belongs to a different execution"
                )
            }
        }
    }
}

impl Error for MockError {}
