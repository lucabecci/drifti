// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded delivery of semantic events.
//!
//! [`EventSink::emit`] waits while `capacity` events are already buffered.
//! Dropping [`EventCursor`] keeps events that were already queued; retrieve
//! them with [`EventSink::take_unconsumed`]. A later `emit` returns that new
//! event and does not append it. Neither path discards an event and reports
//! success.

use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::mem;
use std::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::event::ObservedEvent;

/// Sending side of a bounded event channel.
pub struct EventSink {
    inner: Arc<Inner>,
    capacity: usize,
}

/// Receiving side of a bounded event channel. One consumer owns it.
///
/// On drop, events still queued move to [`EventSink::take_unconsumed`].
pub struct EventCursor {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<Shared>,
    /// Signaled when an event is queued or the last sender is gone.
    data: Condvar,
    /// Signaled when a slot frees or the cursor is gone.
    space: Condvar,
}

struct Shared {
    queue: VecDeque<ObservedEvent>,
    senders: usize,
    receiver_alive: bool,
    unconsumed: Vec<ObservedEvent>,
}

impl fmt::Debug for EventSink {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventSink")
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Clone for EventSink {
    fn clone(&self) -> Self {
        let mut guard = lock(&self.inner.state);
        guard.senders += 1;
        drop(guard);
        Self {
            inner: Arc::clone(&self.inner),
            capacity: self.capacity,
        }
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        let mut guard = lock(&self.inner.state);
        guard.senders = guard
            .senders
            .checked_sub(1)
            .expect("event sink sender count");
        let disconnected = guard.senders == 0;
        drop(guard);
        if disconnected {
            self.inner.data.notify_all();
        }
    }
}

impl EventSink {
    /// Opens a channel that holds at most `capacity` events.
    #[must_use]
    pub fn bounded(capacity: NonZeroUsize) -> (Self, EventCursor) {
        let capacity = capacity.get();
        let inner = Arc::new(Inner {
            state: Mutex::new(Shared {
                queue: VecDeque::with_capacity(capacity),
                senders: 1,
                receiver_alive: true,
                unconsumed: Vec::new(),
            }),
            data: Condvar::new(),
            space: Condvar::new(),
        });
        (
            Self {
                inner: Arc::clone(&inner),
                capacity,
            },
            EventCursor { inner },
        )
    }

    /// Bound given to [`Self::bounded`].
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Delivers `event` or returns it when the cursor is gone.
    ///
    /// This call waits while the live cursor already has `capacity` events
    /// queued. It does not drop `event`, and it does not report success after
    /// the cursor is gone.
    pub fn emit(&self, event: ObservedEvent) -> Result<(), SinkError> {
        let mut guard = lock(&self.inner.state);
        loop {
            // Check the cursor before accepting another event. Once it is
            // gone, queued events already live in `unconsumed`.
            if !guard.receiver_alive {
                return Err(SinkError::Closed(Box::new(event)));
            }
            if guard.queue.len() < self.capacity {
                guard.queue.push_back(event);
                self.inner.data.notify_one();
                return Ok(());
            }
            guard = wait(&self.inner.space, guard);
        }
    }

    /// Removes events that were queued when the cursor was dropped.
    ///
    /// The first call returns those events in queue order. A later call is
    /// empty. An event returned from [`Self::emit`] as [`SinkError::Closed`]
    /// is not included; the caller already holds it.
    #[must_use]
    pub fn take_unconsumed(&self) -> Vec<ObservedEvent> {
        mem::take(&mut lock(&self.inner.state).unconsumed)
    }
}

impl fmt::Debug for EventCursor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventCursor")
    }
}

impl Drop for EventCursor {
    fn drop(&mut self) {
        let mut guard = lock(&self.inner.state);
        guard.receiver_alive = false;
        let queued = mem::take(&mut guard.queue);
        guard.unconsumed.extend(queued);
        drop(guard);
        self.inner.space.notify_all();
    }
}

impl EventCursor {
    /// Waits until an event is available or the sink side is gone.
    pub fn recv(&self) -> Result<ObservedEvent, CursorError> {
        let mut guard = lock(&self.inner.state);
        loop {
            if let Some(event) = pop(&self.inner, &mut guard) {
                return Ok(event);
            }
            if guard.senders == 0 {
                return Err(CursorError::Disconnected);
            }
            guard = wait(&self.inner.data, guard);
        }
    }

    /// Waits up to `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<ObservedEvent, CursorError> {
        let mut guard = lock(&self.inner.state);
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(event) = pop(&self.inner, &mut guard) {
                return Ok(event);
            }
            if guard.senders == 0 {
                return Err(CursorError::Disconnected);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CursorError::TimedOut);
            }
            guard = wait_for(&self.inner.data, guard, deadline - now);
        }
    }

    /// Returns [`CursorError::Empty`] when the buffer has no event.
    pub fn try_recv(&self) -> Result<ObservedEvent, CursorError> {
        let mut guard = lock(&self.inner.state);
        if let Some(event) = pop(&self.inner, &mut guard) {
            return Ok(event);
        }
        if guard.senders == 0 {
            Err(CursorError::Disconnected)
        } else {
            Err(CursorError::Empty)
        }
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

fn pop(inner: &Inner, guard: &mut MutexGuard<'_, Shared>) -> Option<ObservedEvent> {
    let event = guard.queue.pop_front()?;
    inner.space.notify_one();
    Some(event)
}

/// A panicked holder must not make the queued events unreachable.
fn lock(state: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait<'a>(condvar: &Condvar, guard: MutexGuard<'a, Shared>) -> MutexGuard<'a, Shared> {
    condvar.wait(guard).unwrap_or_else(PoisonError::into_inner)
}

fn wait_for<'a>(
    condvar: &Condvar,
    guard: MutexGuard<'a, Shared>,
    timeout: Duration,
) -> MutexGuard<'a, Shared> {
    condvar
        .wait_timeout(guard, timeout)
        .unwrap_or_else(PoisonError::into_inner)
        .0
}
