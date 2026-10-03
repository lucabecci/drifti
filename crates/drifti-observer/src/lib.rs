// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Platform-neutral observation boundary.
//!
//! An [`Observer`] launches a [`CommandSpec`], emits [`ObservedEvent`] values
//! into a bounded [`EventSink`], and returns an [`ExecutionResult`] with an
//! explicit [`ExecutionCoverage`]. This crate does not grant capabilities,
//! persist traces, or link a platform backend.
//!
//! `sequence` is the ordering authority inside one execution. A monotonic
//! timestamp is informational. [`EventSink::emit`] waits while the bounded
//! buffer is full and returns the event if the consumer is gone. An event
//! that was already accepted stays available after the cursor drops, and
//! [`Observer::run`] returns the sink so that event is still in the caller's
//! hands. There is no API that discards an event and reports success.
//!
//! Observation coverage (`COMPLETE`, `INCOMPLETE`, `UNSUPPORTED`) is local
//! to this crate. It is not the policy coverage type in `drifti-core`.
//! [`mock::MockObserver`] replays a script on any host. It does not depend
//! on `drifti-core` and it does not launch a process.

#![forbid(unsafe_code)]

mod text;

pub mod coverage;
pub mod event;
pub mod mock;
pub mod observer;
pub mod sink;

pub use coverage::{
    CapabilityDomain, CoverageError, ExecutionCoverage, ObservationCoverage, ObserverCapabilities,
};
pub use event::{
    EventError, EvidenceMeta, ExecutionId, FailureReason, MonotonicTimestamp, ObservedEvent,
    ObservedResource, Operation, Outcome, ParentIdentity, ProcessIdentity,
};
pub use mock::{MockError, MockObserver, ObservationScript};
pub use observer::{CommandSpec, ExecutionResult, Observer, ObserverError};
pub use sink::{CursorError, EventCursor, EventSink, SinkError};
