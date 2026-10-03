// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Backpressure and cursor-drop behavior of the bounded event sink.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::{
    CapabilityDomain, CommandSpec, CursorError, EventSink, EvidenceMeta, ExecutionCoverage,
    ExecutionId, ExecutionResult, FailureReason, MonotonicTimestamp, ObservationCoverage,
    ObservedEvent, ObservedResource, Observer, ObserverCapabilities, ObserverError, Operation,
    Outcome, ParentIdentity, ProcessIdentity,
};

#[test]
fn capacity_matches_the_bound_and_zero_is_rejected() {
    let (sink, _cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    assert_eq!(sink.capacity(), 1);
    assert!(NonZeroUsize::new(0).is_none());
}

#[test]
fn full_buffer_blocks_without_dropping_events() {
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let first = sample_event(1);
    let second = sample_event(2);
    let phase = Arc::new(AtomicU8::new(0));
    let worker_phase = Arc::clone(&phase);
    let worker_first = first.clone();
    let worker_second = second.clone();
    let worker = thread::spawn(move || {
        sink.emit(worker_first).expect("sequence 1 queued");
        worker_phase.store(1, Ordering::Release);
        sink.emit(worker_second).expect("sequence 2 queued");
        worker_phase.store(2, Ordering::Release);
    });

    wait_phase(&phase, |value| value >= 1);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        phase.load(Ordering::Acquire),
        1,
        "second emit must stay blocked"
    );

    let received = cursor
        .recv_timeout(Duration::from_secs(2))
        .expect("sequence 1");
    assert_eq!(received, first);

    wait_phase(&phase, |value| value == 2);
    let received = cursor
        .recv_timeout(Duration::from_secs(2))
        .expect("sequence 2");
    assert_eq!(received, second);

    worker.join().expect("worker");
    assert_eq!(
        cursor.try_recv().expect_err("no third event"),
        CursorError::Disconnected
    );
}

#[test]
fn dropped_cursor_keeps_the_queued_event() {
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let queued = sample_event(1);
    sink.emit(queued.clone()).expect("queued");
    let rendered = format!("{sink:?} {cursor:?}");
    assert!(!rendered.contains("backpressure-kept"));
    drop(cursor);

    assert_eq!(sink.take_unconsumed(), vec![queued]);

    let rejected = sample_event(2);
    let error = sink.emit(rejected.clone()).expect_err("closed");
    assert_eq!(error.event(), &rejected);
    assert_eq!(error.into_event(), rejected);
    assert!(sink.take_unconsumed().is_empty());
}

#[test]
fn observer_run_returns_sink_error_when_the_cursor_is_gone() {
    let first = sample_event(1);
    let second = sample_event(2);
    let phase = Arc::new(AtomicU8::new(0));
    let observer = SinkFailureObserver {
        first: first.clone(),
        second: second.clone(),
        phase: Arc::clone(&phase),
    };
    let command = CommandSpec::try_new("demo", [], None).expect("command");
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let handle = thread::spawn(move || observer.run(command, sink));

    wait_phase(&phase, |value| value >= 1);
    drop(cursor);

    let (returned, result) = handle.join().expect("observer thread");
    let error = result.expect_err("sink failure must not be Ok");
    let ObserverError::Sink(sink_error) = error else {
        panic!("expected ObserverError::Sink, got {error}");
    };
    assert_eq!(sink_error.into_event(), second);
    assert_eq!(returned.take_unconsumed(), vec![first]);
    assert!(returned.take_unconsumed().is_empty());
}

struct SinkFailureObserver {
    first: ObservedEvent,
    second: ObservedEvent,
    phase: Arc<AtomicU8>,
}

impl Observer for SinkFailureObserver {
    fn capabilities(&self) -> ObserverCapabilities {
        ObserverCapabilities::new([CapabilityDomain::Filesystem])
    }

    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        let _ = command.program();
        if let Err(error) = sink.emit(self.first.clone()) {
            return (sink, Err(error.into()));
        }
        self.phase.store(1, Ordering::Release);
        if let Err(error) = sink.emit(self.second.clone()) {
            return (sink, Err(error.into()));
        }
        let coverage =
            ExecutionCoverage::declared(ObservationCoverage::Incomplete, []).expect("coverage");
        (
            sink,
            Ok(ExecutionResult::new(
                self.first.execution_id(),
                coverage,
                Some(0),
            )),
        )
    }
}

fn wait_phase(phase: &AtomicU8, is_ready: impl Fn(u8) -> bool) {
    let started = Instant::now();
    loop {
        let current = phase.load(Ordering::Acquire);
        if is_ready(current) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "phase stayed at {current}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn sample_event(sequence: u64) -> ObservedEvent {
    ObservedEvent::new(
        ExecutionId::from_raw(44),
        sequence,
        MonotonicTimestamp::from_nanos(sequence),
        ProcessIdentity::new(Some(44), Some(1)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file(format!("/tmp/backpressure-kept-{sequence}")).expect("path"),
        Outcome::failure(
            Some(13),
            Some(FailureReason::new("eacces").expect("reason")),
        ),
        EvidenceMeta::with_byte_length(0),
    )
}
