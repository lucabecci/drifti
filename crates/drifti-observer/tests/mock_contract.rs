// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mock observer composed with ordering, outcomes, coverage, and backpressure.
//!
//! These tests link only `drifti-observer`. They do not use a Linux target
//! cfg and they do not call `drifti-core`.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::coverage::DomainObservation;
use drifti_observer::{
    CapabilityDomain, CommandSpec, CursorError, EventSink, EvidenceMeta, ExecutionCoverage,
    ExecutionId, FailureReason, MockError, MockObserver, MonotonicTimestamp, ObservationCoverage,
    ObservationScript, ObservedEvent, ObservedResource, Observer, Operation, Outcome,
    ParentIdentity, ProcessIdentity,
};

const SECRET_ARG: &str = "aws-secret-access-key-value";
const EXECUTION: ExecutionId = ExecutionId::from_raw(45);

#[test]
fn mock_observer_delivers_each_scripted_event_once() {
    let events = vec![
        event(
            1,
            300,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/mock-read").expect("path"),
            Outcome::success(),
        ),
        event(
            2,
            100,
            Operation::NetworkConnect,
            ObservedResource::network("example.test", 443).expect("endpoint"),
            Outcome::failure(
                Some(111),
                Some(FailureReason::new("econnrefused").expect("reason")),
            ),
        ),
        event(
            3,
            200,
            Operation::ProcessExecute,
            ObservedResource::executable("/usr/bin/true").expect("executable"),
            Outcome::success(),
        ),
    ];
    let coverage =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, [CapabilityDomain::Network])
            .expect("coverage");
    let observer = observer(events.clone(), coverage.clone());
    let command = CommandSpec::try_new(
        "/usr/bin/demo",
        [SECRET_ARG.to_string()],
        Some("/tmp/work".to_string()),
    )
    .expect("command");
    let rendered = format!("{command:?} {observer:?}");
    assert!(!rendered.contains(SECRET_ARG));
    assert_eq!(command.args(), [SECRET_ARG]);

    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(4).expect("capacity"));
    let (returned, result) = observer.run(command, sink);
    let result = result.expect("run");

    assert_eq!(result.execution_id(), EXECUTION);
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.coverage(), &coverage);
    assert!(!result.coverage().is_complete());
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);

    let mut received = Vec::new();
    for _ in 0..events.len() {
        received.push(
            cursor
                .recv_timeout(Duration::from_secs(1))
                .expect("scripted event"),
        );
    }
    assert_eq!(received, events);
    assert_eq!(
        received
            .iter()
            .map(ObservedEvent::sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(received[0].timestamp().nanos() > received[1].timestamp().nanos());
    assert!(received[0].was_attempted() && received[0].was_exercised());
    assert!(received[1].was_attempted() && !received[1].was_exercised());
    assert!(received[2].was_attempted() && received[2].was_exercised());
    assert_eq!(cursor.try_recv(), Err(CursorError::Empty));
    drop(returned);
    assert_eq!(cursor.try_recv(), Err(CursorError::Disconnected));

    for observed in &received {
        let encoded = serde_json::to_value(observed).expect("serialize event");
        assert_no_forbidden_keys(&encoded);
        assert!(!encoded.to_string().contains(SECRET_ARG));
    }
}

#[test]
fn incomplete_and_unsupported_coverage_survive_run() {
    let capabilities = drifti_observer::ObserverCapabilities::new([
        CapabilityDomain::Filesystem,
        CapabilityDomain::Process,
        CapabilityDomain::Network,
    ]);
    let incomplete =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, [CapabilityDomain::Network])
            .expect("incomplete");
    let unsupported =
        ExecutionCoverage::declared(ObservationCoverage::Unsupported, []).expect("unsupported");

    for coverage in [incomplete, unsupported] {
        let script = ObservationScript::try_new(EXECUTION, Vec::new(), coverage.clone(), Some(0))
            .expect("script");
        let observer = MockObserver::new(capabilities.clone(), script);
        let command = CommandSpec::try_new("demo", [], None).expect("command");
        let (sink, _cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
        let (_sink, result) = observer.run(command, sink);
        let result = result.expect("run");

        assert_eq!(result.exit_code(), Some(0));
        assert_eq!(result.coverage(), &coverage);
        assert!(!result.coverage().is_complete());
        assert_ne!(result.coverage().status(), ObservationCoverage::Complete);

        let encoded = serde_json::to_value(result.coverage()).expect("serialize coverage");
        assert_ne!(encoded["status"], "COMPLETE");
        assert_eq!(encoded["status"], coverage.status().as_str());
        let decoded: ExecutionCoverage =
            serde_json::from_value(encoded).expect("deserialize coverage");
        assert_eq!(decoded, coverage);
        assert!(!decoded.is_complete());

        match coverage.status() {
            ObservationCoverage::Incomplete => {
                assert_eq!(
                    decoded.domain(&capabilities, CapabilityDomain::Filesystem),
                    DomainObservation::NotObserved
                );
                assert_eq!(
                    decoded.domain(&capabilities, CapabilityDomain::Network),
                    DomainObservation::Unsupported
                );
            }
            ObservationCoverage::Unsupported => {
                for domain in CapabilityDomain::ALL {
                    assert_eq!(
                        decoded.domain(&capabilities, domain),
                        DomainObservation::Unsupported
                    );
                }
            }
            ObservationCoverage::Complete => panic!("script must not declare COMPLETE"),
        }
    }
}

#[test]
fn backpressure_keeps_the_blocked_failure() {
    let events = vec![
        event(
            1,
            1,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/mock-1").expect("path"),
            Outcome::success(),
        ),
        event(
            2,
            2,
            Operation::FilesystemWrite,
            ObservedResource::file("/tmp/mock-2").expect("path"),
            Outcome::failure(
                Some(13),
                Some(FailureReason::new("eacces").expect("reason")),
            ),
        ),
        event(
            3,
            3,
            Operation::FilesystemMetadata,
            ObservedResource::file("/tmp/mock-3").expect("path"),
            Outcome::success(),
        ),
    ];
    let coverage =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, []).expect("coverage");
    let observer = observer(events.clone(), coverage.clone());
    let accepted = observer.accepted();
    let command = CommandSpec::try_new("demo", [SECRET_ARG.to_string()], None).expect("command");
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let handle = thread::spawn(move || observer.run(command, sink));

    wait_accepted(&accepted, 1);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        accepted.load(Ordering::Acquire),
        1,
        "the failure event must stay blocked on a full sink"
    );

    let mut received = Vec::new();
    received.push(cursor.recv_timeout(Duration::from_secs(2)).expect("first"));
    wait_accepted(&accepted, 2);
    received.push(cursor.recv_timeout(Duration::from_secs(2)).expect("second"));
    wait_accepted(&accepted, 3);
    received.push(cursor.recv_timeout(Duration::from_secs(2)).expect("third"));

    let (returned, result) = handle.join().expect("observer thread");
    let result = result.expect("run");
    drop(returned);

    assert_eq!(received, events);
    assert!(received[1].was_attempted() && !received[1].was_exercised());
    assert!(!received
        .iter()
        .any(|event| format!("{event:?}").contains(SECRET_ARG)));
    assert_eq!(result.coverage(), &coverage);
    assert!(!result.coverage().is_complete());
    assert_eq!(
        cursor.try_recv().expect_err("no extra event"),
        CursorError::Disconnected
    );
}

#[test]
fn closed_sink_returns_the_unaccepted_event_and_keeps_the_queued_one() {
    let events = vec![
        event(
            1,
            10,
            Operation::FilesystemRead,
            ObservedResource::file("/tmp/mock-kept").expect("path"),
            Outcome::success(),
        ),
        event(
            2,
            20,
            Operation::NetworkConnect,
            ObservedResource::network("blocked.test", 9).expect("endpoint"),
            Outcome::failure(None, None),
        ),
        event(
            3,
            30,
            Operation::ProcessExecute,
            ObservedResource::executable("/usr/bin/false").expect("executable"),
            Outcome::success(),
        ),
    ];
    let coverage =
        ExecutionCoverage::declared(ObservationCoverage::Unsupported, []).expect("coverage");
    let observer = observer(events.clone(), coverage);
    let accepted = observer.accepted();
    let command = CommandSpec::try_new("demo", [], None).expect("command");
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let handle = thread::spawn(move || {
        let (sink, result) = observer.run(command, sink);
        (observer, sink, result)
    });

    wait_accepted(&accepted, 1);
    drop(cursor);

    let (observer, returned, result) = handle.join().expect("observer thread");
    let error = result.expect_err("a closed sink is not a successful run");
    let drifti_observer::ObserverError::Sink(sink_error) = error else {
        panic!("expected ObserverError::Sink, got {error}");
    };
    assert_eq!(sink_error.into_event(), events[1]);
    assert_eq!(returned.take_unconsumed(), vec![events[0].clone()]);
    assert!(returned.take_unconsumed().is_empty());
    assert_eq!(observer.script().events(), events.as_slice());
    assert_eq!(observer.script().events()[2], events[2]);
    assert!(!observer.script().coverage().is_complete());
    assert_eq!(
        observer.script().coverage().status(),
        ObservationCoverage::Unsupported
    );
}

#[test]
fn script_rejects_an_event_from_another_execution() {
    let foreign = ObservedEvent::new(
        ExecutionId::from_raw(99),
        4,
        MonotonicTimestamp::from_nanos(1),
        ProcessIdentity::new(None, None),
        None,
        Operation::FilesystemRead,
        ObservedResource::file("/tmp/other").expect("path"),
        Outcome::success(),
        EvidenceMeta::empty(),
    );
    let error = ObservationScript::try_new(
        EXECUTION,
        vec![foreign],
        ExecutionCoverage::no_events_seen(),
        None,
    )
    .expect_err("foreign execution");
    assert_eq!(error, MockError::ForeignExecution { sequence: 4 });
    assert!(!error.to_string().is_empty());
}

fn observer(events: Vec<ObservedEvent>, coverage: ExecutionCoverage) -> MockObserver {
    let script = ObservationScript::try_new(EXECUTION, events, coverage, Some(0)).expect("script");
    MockObserver::new(
        drifti_observer::ObserverCapabilities::new([
            CapabilityDomain::Filesystem,
            CapabilityDomain::Process,
            CapabilityDomain::Network,
        ]),
        script,
    )
}

fn event(
    sequence: u64,
    timestamp_nanos: u64,
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
) -> ObservedEvent {
    ObservedEvent::new(
        EXECUTION,
        sequence,
        MonotonicTimestamp::from_nanos(timestamp_nanos),
        ProcessIdentity::new(Some(45), Some(1)),
        Some(ParentIdentity::new(7)),
        operation,
        resource,
        outcome,
        EvidenceMeta::with_byte_length(sequence),
    )
}

fn wait_accepted(accepted: &AtomicUsize, target: usize) {
    let started = Instant::now();
    loop {
        let current = accepted.load(Ordering::Acquire);
        if current >= target {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "accepted stayed at {current}, wanted {target}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn assert_no_forbidden_keys(value: &serde_json::Value) {
    const FORBIDDEN: &[&str] = &[
        "content", "payload", "argv", "secret", "prompt", "response", "stdout", "stderr",
    ];
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                assert!(
                    !FORBIDDEN.contains(&key.as_str()),
                    "forbidden event field {key}"
                );
                assert_no_forbidden_keys(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                assert_no_forbidden_keys(item);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}
