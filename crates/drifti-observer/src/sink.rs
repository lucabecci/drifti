// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded delivery of semantic events.
//!
//! [`EventSink::emit`] waits while `capacity` events are already buffered.
//! If the consumer drops [`EventCursor`], `emit` returns the same event.
//! Neither path discards an event and reports success.

use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::time::Duration;

use crate::event::ObservedEvent;

/// Sending side of a bounded event channel.
#[derive(Clone)]
pub struct EventSink {
    tx: SyncSender<ObservedEvent>,
    capacity: usize,
}

impl fmt::Debug for EventSink {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSink")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl EventSink {
    /// Opens a channel that holds at most `capacity` events.
    #[must_use]
    pub fn bounded(capacity: NonZeroUsize) -> (Self, EventCursor) {
        let capacity = capacity.get();
        let (tx, rx) = mpsc::sync_channel(capacity);
        (Self { tx, capacity }, EventCursor { rx })
    }

    /// Bound given to [`Self::bounded`].
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Delivers `event` or returns it when the cursor is gone.
    ///
    /// This call waits while the buffer is full. It does not drop `event`.
    pub fn emit(&self, event: ObservedEvent) -> Result<(), SinkError> {
        self.tx
            .send(event)
            .map_err(|error| SinkError::Closed(Box::new(error.0)))
    }
}

/// Receiving side of a bounded event channel. One consumer owns it.
pub struct EventCursor {
    rx: Receiver<ObservedEvent>,
}

impl fmt::Debug for EventCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventCursor")
    }
}

impl EventCursor {
    /// Waits until an event is available or the sink side is gone.
    pub fn recv(&self) -> Result<ObservedEvent, CursorError> {
        self.rx.recv().map_err(|_| CursorError::Disconnected)
    }

    /// Waits up to `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<ObservedEvent, CursorError> {
        self.rx.recv_timeout(timeout).map_err(|error| match error {
            RecvTimeoutError::Timeout => CursorError::TimedOut,
            RecvTimeoutError::Disconnected => CursorError::Disconnected,
        })
    }

    /// Returns [`CursorError::Empty`] when the buffer has no event.
    pub fn try_recv(&self) -> Result<ObservedEvent, CursorError> {
        self.rx.try_recv().map_err(|error| match error {
            TryRecvError::Empty => CursorError::Empty,
            TryRecvError::Disconnected => CursorError::Disconnected,
        })
    }
}

/// The event was not accepted. The value is still in the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError {
    /// The cursor was dropped before the event was queued.
    Closed(Box<ObservedEvent>),
}

impl SinkError {
    /// The event that was not accepted.
    #[must_use]
    pub fn event(&self) -> &ObservedEvent {
        match self {
            Self::Closed(event) => event,
        }
    }

    /// Returns the event that was not accepted.
    #[must_use]
    pub fn into_event(self) -> ObservedEvent {
        match self {
            Self::Closed(event) => *event,
        }
    }
}

impl Display for SinkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(_) => {
                formatter.write_str("event sink closed before the event was accepted")
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// Failure to pull an event. This is not an observed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    /// The buffer is empty and the sender is still alive.
    Empty,
    /// The wait ended before an event arrived.
    TimedOut,
    /// Every sender was dropped.
    Disconnected,
}

impl Display for CursorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("event cursor is empty"),
            Self::TimedOut => formatter.write_str("event cursor timed out"),
            Self::Disconnected => formatter.write_str("event sink disconnected"),
        }
    }
}

impl std::error::Error for CursorError {}
