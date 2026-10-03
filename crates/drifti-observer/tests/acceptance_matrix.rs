// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-004 acceptance, negative, and security matrix for `drifti-observer`.
//!
//! Criterion 1 (a mock observer drives `drifti-core` without Linux) stays
//! open. RFC-001 §73 does not allow this crate to depend on `drifti-core`,
//! so these tests do not import it and do not mark that criterion passed.
//!
//! Criteria 2–5 and the data-minimization rule are locked here:
//! event order, attempted versus exercised, explicit coverage degradation,
//! and backpressure that cannot drop an event. `INCOMPLETE` and
//! `UNSUPPORTED` must not become success, and neither may be rewritten into
//! the other answer ("not observed" versus "not observable").

use std::cmp::Ordering;
use std::fs;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::coverage::DomainObservation;
use drifti_observer::{
    CapabilityDomain, CommandSpec, CoverageError, CursorError, EventError, EventSink, EvidenceMeta,
    ExecutionCoverage, ExecutionId, FailureReason, MockError, MockObserver, MonotonicTimestamp,
    ObservationCoverage, ObservationScript, ObservedEvent, ObservedResource, Observer,
    ObserverCapabilities, ObserverError, Operation, Outcome, ParentIdentity, ProcessIdentity,
};

const EXECUTION: ExecutionId = ExecutionId::from_raw(46);

const SECRET: &str = "super-secret-value-9f3a";
const PROMPT: &str = "prompt-text-do-not-store";
const PAYLOAD: &str = "payload-body-do-not-store";
const CONTENT: &str = "file-bytes-do-not-store";
const RESPONSE: &str = "model-response-do-not-store";

const SENSITIVE: &[&str] = &[SECRET, PROMPT, PAYLOAD, CONTENT, RESPONSE];

const FORBIDDEN_KEYS: &[&str] = &[
    "argv", "content", "payload", "prompt", "response", "secret", "stderr", "stdout",
];

const EVENT_KEYS: &[&str] = &[
    "evidence",
    "execution_id",
    "operation",
    "outcome",
    "parent",
    "process",
    "resource",
    "sequence",
    "timestamp",
];

#[test]
fn matrix_criterion_1_stays_open_without_a_core_dependency() {
    let manifest = non_comment_text(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    for token in [
        "drifti-core",
        "drifti-observer-linux",
        "libc",
        "nix",
        "rusqlite",
        "sqlx",
        "clap",
        "ptrace",
        "libsqlite3-sys",
    ] {
        assert!(
            !manifest.contains(token),
            "{token} is in the observer manifest; criterion 1 stays open"
        );
    }

    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    for entry in fs::read_dir(src).expect("src dir") {
        let entry = entry.expect("src entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".rs") {
            continue;
        }
        let source = fs::read_to_string(entry.path()).expect("source");
        for token in [
            "drifti_core",
            "ptrace",
            "rusqlite",
            "libsqlite",
            "std::os::unix",
            "std::os::linux",
            "std::fs",
            "nix::",
        ] {
            assert!(
                !source.contains(token),
                "{name} contains {token}; criterion 1 stays open"
            );
        }
    }

    let core = non_comment_text(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../drifti-core/Cargo.toml"
    ));
    assert!(
        !core.contains("drifti-observer"),
        "drifti-core must not depend on drifti-observer"
    );
}

#[test]
fn matrix_events_preserve_script_order_not_timestamp_order() {
    let scripted = vec![
        event(
            1,
            300,
            Operation::FilesystemRead,
            file("/tmp/matrix-read"),
            Outcome::success(),
        ),
        event(
            2,
            100,
            Operation::NetworkConnect,
            endpoint("connect.test", 443),
            Outcome::failure(Some(111), Some(reason("econnrefused"))),
        ),
        event(
            3,
            200,
            Operation::ProcessExecute,
            executable("/usr/bin/true"),
            Outcome::success(),
        ),
    ];
    let by_timestamp = sequences_sorted_by_timestamp(&scripted);
    assert_eq!(by_timestamp, [2, 3, 1]);

    let coverage = declared(ObservationCoverage::Incomplete, &[]);
    let (result, received) = run_collected(scripted.clone(), coverage.clone(), benign_command());
    assert_eq!(received, scripted);
    assert_eq!(sequences(&received), [1, 2, 3]);
    assert_ne!(sequences(&received), by_timestamp);
    assert!(received[0].timestamp().nanos() > received[1].timestamp().nanos());
    assert_eq!(received[0].sequence_cmp(&received[2]), Some(Ordering::Less));
    assert_eq!(result.coverage(), &coverage);
    assert!(!result.coverage().is_complete());

    let other = event_in(
        ExecutionId::from_raw(99),
        1,
        300,
        Operation::FilesystemRead,
        file("/tmp/matrix-other"),
        Outcome::success(),
    );
    assert_eq!(received[0].sequence_cmp(&other), None);
}

#[test]
fn matrix_equal_sequence_is_not_a_reason_to_drop_an_event() {
    let scripted = vec![
        event(
            1,
            10,
            Operation::FilesystemRead,
            file("/tmp/matrix-same-a"),
            Outcome::success(),
        ),
        event(
            1,
            90,
            Operation::FilesystemWrite,
            file("/tmp/matrix-same-b"),
            Outcome::failure(Some(13), Some(reason("eacces"))),
        ),
    ];
    let (_, received) = run_collected(
        scripted.clone(),
        declared(ObservationCoverage::Incomplete, &[]),
        benign_command(),
    );
    assert_eq!(received, scripted);
    assert_eq!(received.len(), 2);
    assert_eq!(
        received[0].sequence_cmp(&received[1]),
        Some(Ordering::Equal)
    );
    assert_ne!(received[0].resource(), received[1].resource());
    assert!(received[1].was_attempted());
    assert!(!received[1].was_exercised());
}

#[test]
fn matrix_foreign_execution_cannot_join_the_script() {
    let foreign = event_in(
        ExecutionId::from_raw(99),
        4,
        1,
        Operation::FilesystemRead,
        file("/tmp/matrix-foreign"),
        Outcome::success(),
    );
    let error = ObservationScript::try_new(
        EXECUTION,
        vec![foreign],
        ExecutionCoverage::no_events_seen(),
        None,
    )
    .expect_err("foreign execution");
    assert_eq!(error, MockError::ForeignExecution { sequence: 4 });
}

#[test]
fn matrix_success_is_exercised_and_failure_is_only_attempted() {
    let exercised = event(
        1,
        20,
        Operation::FilesystemRead,
        file("/tmp/matrix-ok"),
        Outcome::success(),
    );
    let attempted = event(
        2,
        10,
        Operation::FilesystemWrite,
        file("/tmp/matrix-denied"),
        Outcome::failure(Some(13), Some(reason("eacces"))),
    );
    let bare_failure = event(
        3,
        5,
        Operation::NetworkListen,
        endpoint("listen.test", 9),
        Outcome::failure(None, None),
    );
    let scripted = vec![exercised, attempted, bare_failure];
    let (_, received) = run_collected(
        scripted.clone(),
        declared(ObservationCoverage::Incomplete, &[]),
        benign_command(),
    );
    assert_eq!(received, scripted);

    assert!(received[0].was_attempted());
    assert!(received[0].was_exercised());
    assert!(matches!(received[0].outcome(), Outcome::Success {}));

    assert!(received[1].was_attempted());
    assert!(!received[1].was_exercised());
    match received[1].outcome() {
        Outcome::Failure {
            errno: Some(13),
            reason: Some(text),
        } => assert_eq!(text.as_str(), "eacces"),
        other => panic!("expected a named failure, got {other:?}"),
    }

    assert!(received[2].was_attempted());
    assert!(!received[2].was_exercised());
    assert_eq!(received[2].outcome(), &Outcome::failure(None, None));

    for observed in &received {
        assert!(observed.was_attempted());
        assert_eq!(
            observed.was_exercised(),
            matches!(observed.outcome(), Outcome::Success {})
        );
    }
}

#[test]
fn matrix_incomplete_and_unsupported_stay_explicit() {
    let rows = [
        Row {
            name: "incomplete advertised domain is not observed",
            fixture: Fixture::Declared(ObservationCoverage::Incomplete, &[]),
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Filesystem,
            complete: false,
            status: ObservationCoverage::Incomplete,
            observation: DomainObservation::NotObserved,
        },
        Row {
            name: "incomplete marked domain is unsupported",
            fixture: Fixture::Declared(
                ObservationCoverage::Incomplete,
                &[CapabilityDomain::Network],
            ),
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Network,
            complete: false,
            status: ObservationCoverage::Incomplete,
            observation: DomainObservation::Unsupported,
        },
        Row {
            name: "incomplete sibling domain stays not observed",
            fixture: Fixture::Declared(
                ObservationCoverage::Incomplete,
                &[CapabilityDomain::Network],
            ),
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Filesystem,
            complete: false,
            status: ObservationCoverage::Incomplete,
            observation: DomainObservation::NotObserved,
        },
        Row {
            name: "unsupported execution is not not-observed",
            fixture: Fixture::Declared(ObservationCoverage::Unsupported, &[]),
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Process,
            complete: false,
            status: ObservationCoverage::Unsupported,
            observation: DomainObservation::Unsupported,
        },
        Row {
            name: "explicit complete covers an advertised domain",
            fixture: Fixture::Declared(ObservationCoverage::Complete, &[]),
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Network,
            complete: true,
            status: ObservationCoverage::Complete,
            observation: DomainObservation::Covered,
        },
        Row {
            name: "complete does not cover a domain that was not advertised",
            fixture: Fixture::Declared(ObservationCoverage::Complete, &[]),
            advertised: &[CapabilityDomain::Filesystem],
            domain: CapabilityDomain::Network,
            complete: true,
            status: ObservationCoverage::Complete,
            observation: DomainObservation::Unsupported,
        },
        Row {
            name: "complete still covers the advertised domain",
            fixture: Fixture::Declared(ObservationCoverage::Complete, &[]),
            advertised: &[CapabilityDomain::Filesystem],
            domain: CapabilityDomain::Filesystem,
            complete: true,
            status: ObservationCoverage::Complete,
            observation: DomainObservation::Covered,
        },
        Row {
            name: "no events on an advertised domain is not observed",
            fixture: Fixture::NoEvents,
            advertised: &CapabilityDomain::ALL,
            domain: CapabilityDomain::Filesystem,
            complete: false,
            status: ObservationCoverage::Incomplete,
            observation: DomainObservation::NotObserved,
        },
        Row {
            name: "no events on an unadvertised domain is unsupported",
            fixture: Fixture::NoEvents,
            advertised: &[CapabilityDomain::Filesystem],
            domain: CapabilityDomain::Network,
            complete: false,
            status: ObservationCoverage::Incomplete,
            observation: DomainObservation::Unsupported,
        },
    ];

    for row in &rows {
        let coverage = match row.fixture {
            Fixture::Declared(status, unsupported) => {
                ExecutionCoverage::declared(status, unsupported.iter().copied()).expect(row.name)
            }
            Fixture::NoEvents => ExecutionCoverage::no_events_seen(),
        };
        let capabilities = ObserverCapabilities::new(row.advertised.iter().copied());
        let got = coverage.domain(&capabilities, row.domain);
        assert_eq!(got, row.observation, "{}", row.name);
        assert_eq!(coverage.status(), row.status, "{}", row.name);
        assert_eq!(coverage.is_complete(), row.complete, "{}", row.name);
        assert_ne!(coverage.status().as_str(), "success", "{}", row.name);
        match row.observation {
            DomainObservation::NotObserved => {
                assert_ne!(got, DomainObservation::Unsupported, "{}", row.name);
                assert_ne!(got, DomainObservation::Covered, "{}", row.name);
            }
            DomainObservation::Unsupported => {
                assert_ne!(got, DomainObservation::NotObserved, "{}", row.name);
                assert_ne!(got, DomainObservation::Covered, "{}", row.name);
            }
            DomainObservation::Covered => {
                assert!(row.complete, "{}", row.name);
            }
        }
        if !row.complete {
            assert_ne!(
                coverage.status(),
                ObservationCoverage::Complete,
                "{}",
                row.name
            );
        }
    }

    let advertised = ObserverCapabilities::new(CapabilityDomain::ALL);
    let unsupported = declared(ObservationCoverage::Unsupported, &[]);
    for domain in CapabilityDomain::ALL {
        let got = unsupported.domain(&advertised, domain);
        assert_eq!(got, DomainObservation::Unsupported);
        assert_ne!(got, DomainObservation::NotObserved);
        assert_ne!(got, DomainObservation::Covered);
    }
    assert!(!unsupported.is_complete());

    let incomplete = declared(ObservationCoverage::Incomplete, &[]);
    let stayed = incomplete.degrade_status(ObservationCoverage::Complete);
    assert_eq!(stayed.status(), ObservationCoverage::Incomplete);
    assert!(!stayed.is_complete());
    assert_eq!(
        stayed.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );
    assert_ne!(
        stayed.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::Unsupported
    );

    let folded = unsupported.degrade_status(ObservationCoverage::Complete);
    assert_eq!(folded.status(), ObservationCoverage::Unsupported);
    assert!(!folded.is_complete());
    assert_eq!(
        folded.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_ne!(
        folded.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::NotObserved
    );

    let marked = declared(
        ObservationCoverage::Incomplete,
        &[CapabilityDomain::Network],
    );
    let partial = marked.degrade_status(ObservationCoverage::Complete);
    assert!(!partial.is_complete());
    assert_eq!(
        partial.domain(&advertised, CapabilityDomain::Network),
        DomainObservation::Unsupported
    );
    assert_eq!(
        partial.domain(&advertised, CapabilityDomain::Filesystem),
        DomainObservation::NotObserved
    );

    for left in ObservationCoverage::ALL {
        for right in ObservationCoverage::ALL {
            let degraded = left.degrade(right);
            if left.is_complete() && right.is_complete() {
                assert!(degraded.is_complete());
            } else {
                assert!(!degraded.is_complete());
                assert_ne!(degraded, ObservationCoverage::Complete);
            }
        }
    }
}

#[test]
fn matrix_false_complete_coverage_is_rejected() {
    let rejected =
        ExecutionCoverage::declared(ObservationCoverage::Complete, [CapabilityDomain::Network]);
    assert_eq!(rejected, Err(CoverageError::CompleteWhileUnsupported));

    let decoded = serde_json::from_str::<ExecutionCoverage>(
        r#"{"status":"COMPLETE","unsupported_domains":["network"]}"#,
    );
    assert!(decoded.is_err(), "COMPLETE plus an unsupported domain");

    for name in [
        "success",
        "SUCCESS",
        "ALLOWED",
        "ok",
        "not_observed",
        "not_observable",
    ] {
        let parsed = serde_json::from_str::<ObservationCoverage>(&format!("\"{name}\""));
        assert!(parsed.is_err(), "{name} is not a coverage status");
    }

    let absent = ExecutionCoverage::no_events_seen();
    assert_eq!(absent.status(), ObservationCoverage::Incomplete);
    assert!(!absent.is_complete());
    assert_ne!(absent.status(), ObservationCoverage::Unsupported);
    assert_ne!(absent.status(), ObservationCoverage::Complete);

    let incomplete = declared(ObservationCoverage::Incomplete, &[]);
    let with_events = vec![event(
        1,
        1,
        Operation::FilesystemRead,
        file("/tmp/matrix-seen"),
        Outcome::success(),
    )];
    let (seen, _) = run_collected(with_events, incomplete.clone(), benign_command());
    assert_eq!(seen.exit_code(), Some(0));
    assert_eq!(seen.coverage(), &incomplete);
    assert!(!seen.coverage().is_complete());
    assert_ne!(seen.coverage().status(), ObservationCoverage::Complete);

    let unsupported = declared(ObservationCoverage::Unsupported, &[]);
    let (empty, received) = run_collected(Vec::new(), unsupported.clone(), benign_command());
    assert!(received.is_empty());
    assert_eq!(empty.exit_code(), Some(0));
    assert_eq!(empty.coverage(), &unsupported);
    assert_ne!(empty.coverage(), &absent);
    assert_eq!(empty.coverage().status(), ObservationCoverage::Unsupported);
    assert!(!empty.coverage().is_complete());

    let explicit = declared(ObservationCoverage::Complete, &[]);
    let (complete, _) = run_collected(Vec::new(), explicit.clone(), benign_command());
    assert!(complete.coverage().is_complete());
    assert_eq!(complete.coverage(), &explicit);
    assert_eq!(complete.coverage().status(), ObservationCoverage::Complete);

    let encoded = serde_json::to_value(empty.coverage()).expect("coverage json");
    assert_eq!(encoded["status"], "UNSUPPORTED");
    assert_ne!(encoded["status"], "COMPLETE");
    assert_ne!(encoded["status"], "success");
    assert_exact_keys(
        encoded.as_object().expect("coverage object"),
        &["status", "unsupported_domains"],
    );
}

#[test]
fn matrix_backpressure_delivers_every_event_once() {
    let scripted = vec![
        event(
            1,
            40,
            Operation::FilesystemRead,
            file("/tmp/matrix-bp-1"),
            Outcome::success(),
        ),
        event(
            2,
            30,
            Operation::FilesystemWrite,
            file("/tmp/matrix-bp-2"),
            Outcome::failure(Some(13), Some(reason("eacces"))),
        ),
        event(
            3,
            20,
            Operation::FilesystemMetadata,
            file("/tmp/matrix-bp-3"),
            Outcome::success(),
        ),
        event(
            4,
            10,
            Operation::NetworkConnect,
            endpoint("backpressure.test", 443),
            Outcome::failure(None, None),
        ),
    ];
    let coverage = declared(ObservationCoverage::Incomplete, &[]);
    let observer = mock(scripted.clone(), coverage.clone());
    let accepted = observer.accepted();
    let command = sensitive_command();
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let handle = thread::spawn(move || observer.run(command, sink));

    wait_accepted(&accepted, 1);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(
        accepted.load(AtomicOrdering::Acquire),
        1,
        "a full sink must block instead of dropping the next event"
    );

    let mut received = Vec::new();
    for index in 1..=scripted.len() {
        if index > 1 {
            wait_accepted(&accepted, index);
        }
        received.push(
            cursor
                .recv_timeout(Duration::from_secs(2))
                .expect("queued event"),
        );
    }
    let (returned, result) = handle.join().expect("observer thread");
    let result = result.expect("run");
    drop(returned);

    assert_eq!(received, scripted);
    assert_eq!(sequences(&received), [1, 2, 3, 4]);
    assert_eq!(received.len(), scripted.len());
    assert!(received[1].was_attempted());
    assert!(!received[1].was_exercised());
    assert_eq!(result.coverage(), &coverage);
    assert!(!result.coverage().is_complete());
    assert_eq!(
        cursor.try_recv().expect_err("no hidden event"),
        CursorError::Disconnected
    );
    for observed in &received {
        assert_text_has_no_sensitive(&format!("{observed:?}"));
        let encoded = serde_json::to_value(observed).expect("event json");
        assert_event_contract(&encoded);
    }
}

#[test]
fn matrix_closed_sink_is_not_success_and_keeps_every_event() {
    let scripted = vec![
        event(
            1,
            10,
            Operation::FilesystemRead,
            file("/tmp/matrix-keep"),
            Outcome::success(),
        ),
        event(
            2,
            20,
            Operation::NetworkConnect,
            endpoint("closed.test", 9),
            Outcome::failure(Some(111), Some(reason("econnrefused"))),
        ),
        event(
            3,
            30,
            Operation::ProcessExecute,
            executable("/usr/bin/false"),
            Outcome::success(),
        ),
    ];
    let coverage = declared(ObservationCoverage::Unsupported, &[]);
    let observer = mock(scripted.clone(), coverage);
    let accepted = observer.accepted();
    let command = sensitive_command();
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let handle = thread::spawn(move || {
        let (sink, result) = observer.run(command, sink);
        (observer, sink, result)
    });

    wait_accepted(&accepted, 1);
    drop(cursor);

    let (observer, returned, result) = handle.join().expect("observer thread");
    let error = result.expect_err("a closed sink is not a successful run");
    let ObserverError::Sink(sink_error) = error else {
        panic!("expected ObserverError::Sink, got {error}");
    };
    let rejected = sink_error.into_event();
    let queued = returned.take_unconsumed();
    assert!(returned.take_unconsumed().is_empty());

    assert_eq!(queued, vec![scripted[0].clone()]);
    assert_eq!(rejected, scripted[1]);
    let mut accounted = queued;
    accounted.push(rejected);
    assert_eq!(accounted, scripted[..2]);
    assert!(!accounted.contains(&scripted[2]));
    assert_eq!(observer.script().events(), scripted.as_slice());
    assert_eq!(observer.script().events()[2], scripted[2]);
    assert!(!observer.script().coverage().is_complete());
    assert_eq!(
        observer.script().coverage().status(),
        ObservationCoverage::Unsupported
    );
    assert_ne!(
        observer.script().coverage().status(),
        ObservationCoverage::Complete
    );

    for observed in &accounted {
        let encoded = serde_json::to_value(observed).expect("event json");
        assert_event_contract(&encoded);
        assert_text_has_no_sensitive(&encoded.to_string());
    }
}

#[test]
fn matrix_events_do_not_store_secrets_content_payload_argv_or_prompts() {
    let command = sensitive_command();
    let rendered = format!("{command:?}");
    assert_text_has_no_sensitive(&rendered);
    assert!(!rendered.contains("argv"));
    assert_eq!(command.args(), [SECRET, PROMPT, PAYLOAD, CONTENT, RESPONSE]);

    let scripted = vec![
        event(
            1,
            60,
            Operation::FilesystemRead,
            file("/tmp/matrix-file"),
            Outcome::success(),
        ),
        event(
            2,
            50,
            Operation::FilesystemWrite,
            file("/tmp/matrix-write"),
            Outcome::failure(Some(13), Some(reason("eacces"))),
        ),
        event(
            3,
            40,
            Operation::FilesystemMetadata,
            file("/tmp/matrix-meta"),
            Outcome::success(),
        ),
        event(
            4,
            30,
            Operation::ProcessExecute,
            executable("/usr/bin/demo"),
            Outcome::success(),
        ),
        event(
            5,
            20,
            Operation::NetworkConnect,
            endpoint("example.test", 443),
            Outcome::failure(None, Some(reason("econnrefused"))),
        ),
        event(
            6,
            10,
            Operation::NetworkListen,
            endpoint("listen.test", 9),
            Outcome::failure(None, None),
        ),
    ];
    let (result, received) = run_collected(
        scripted.clone(),
        declared(
            ObservationCoverage::Incomplete,
            &[CapabilityDomain::Network],
        ),
        command,
    );
    assert_eq!(received, scripted);
    assert_text_has_no_sensitive(&format!("{result:?}"));

    for observed in &received {
        let encoded = serde_json::to_value(observed).expect("event json");
        assert_event_contract(&encoded);
        assert_text_has_no_sensitive(&encoded.to_string());
        assert_text_has_no_sensitive(&format!("{observed:?}"));
        reject_extra_event_fields(&encoded);
    }

    let evidence = serde_json::to_value(EvidenceMeta::with_byte_length(4)).expect("evidence");
    assert_exact_keys(
        evidence.as_object().expect("evidence object"),
        &["byte_length"],
    );
    reject_extra::<EvidenceMeta>(&evidence);

    let coverage = serde_json::to_value(result.coverage()).expect("coverage");
    reject_extra::<ExecutionCoverage>(&coverage);
    assert_ne!(coverage["status"], "COMPLETE");

    assert_eq!(
        FailureReason::new(SECRET.repeat(8)).expect_err("oversized reason"),
        EventError::TextTooLong
    );
    assert_eq!(
        ObservedResource::file(CONTENT.repeat(300)).expect_err("oversized path"),
        EventError::TextTooLong
    );
    assert_eq!(
        ObservedResource::network(PAYLOAD.repeat(20), 80).expect_err("oversized host"),
        EventError::TextTooLong
    );
    assert_eq!(
        ObservedResource::file(format!("a\0{SECRET}")).expect_err("nul path"),
        EventError::EmbeddedNul
    );
}

struct Row {
    name: &'static str,
    fixture: Fixture,
    advertised: &'static [CapabilityDomain],
    domain: CapabilityDomain,
    complete: bool,
    status: ObservationCoverage,
    observation: DomainObservation,
}

enum Fixture {
    Declared(ObservationCoverage, &'static [CapabilityDomain]),
    NoEvents,
}

fn declared(status: ObservationCoverage, unsupported: &[CapabilityDomain]) -> ExecutionCoverage {
    ExecutionCoverage::declared(status, unsupported.iter().copied()).expect("coverage")
}

fn mock(events: Vec<ObservedEvent>, coverage: ExecutionCoverage) -> MockObserver {
    let script = ObservationScript::try_new(EXECUTION, events, coverage, Some(0)).expect("script");
    MockObserver::new(
        ObserverCapabilities::new([
            CapabilityDomain::Filesystem,
            CapabilityDomain::Process,
            CapabilityDomain::Network,
        ]),
        script,
    )
}

fn run_collected(
    events: Vec<ObservedEvent>,
    coverage: ExecutionCoverage,
    command: CommandSpec,
) -> (drifti_observer::ExecutionResult, Vec<ObservedEvent>) {
    let capacity = NonZeroUsize::new(events.len().max(1)).expect("capacity");
    let observer = mock(events, coverage);
    let (sink, cursor) = EventSink::bounded(capacity);
    let (returned, result) = observer.run(command, sink);
    let result = result.expect("run");
    let mut received = Vec::new();
    loop {
        match cursor.try_recv() {
            Ok(event) => received.push(event),
            Err(CursorError::Empty) => break,
            Err(error) => panic!("unexpected cursor error {error}"),
        }
    }
    drop(returned);
    (result, received)
}

fn event(
    sequence: u64,
    timestamp_nanos: u64,
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
) -> ObservedEvent {
    event_in(
        EXECUTION,
        sequence,
        timestamp_nanos,
        operation,
        resource,
        outcome,
    )
}

fn event_in(
    execution_id: ExecutionId,
    sequence: u64,
    timestamp_nanos: u64,
    operation: Operation,
    resource: ObservedResource,
    outcome: Outcome,
) -> ObservedEvent {
    ObservedEvent::new(
        execution_id,
        sequence,
        MonotonicTimestamp::from_nanos(timestamp_nanos),
        ProcessIdentity::new(Some(46), Some(1)),
        Some(ParentIdentity::new(7)),
        operation,
        resource,
        outcome,
        EvidenceMeta::with_byte_length(sequence),
    )
}

fn file(path: &str) -> ObservedResource {
    ObservedResource::file(path).expect("path")
}

fn executable(identity: &str) -> ObservedResource {
    ObservedResource::executable(identity).expect("executable")
}

fn endpoint(host: &str, port: u16) -> ObservedResource {
    ObservedResource::network(host, port).expect("endpoint")
}

fn reason(text: &str) -> FailureReason {
    FailureReason::new(text).expect("reason")
}

fn benign_command() -> CommandSpec {
    CommandSpec::try_new("demo", [], None).expect("command")
}

fn sensitive_command() -> CommandSpec {
    CommandSpec::try_new(
        "/usr/bin/demo",
        [
            SECRET.to_string(),
            PROMPT.to_string(),
            PAYLOAD.to_string(),
            CONTENT.to_string(),
            RESPONSE.to_string(),
        ],
        Some("/tmp/matrix-work".to_string()),
    )
    .expect("command")
}

fn sequences(events: &[ObservedEvent]) -> Vec<u64> {
    events.iter().map(ObservedEvent::sequence).collect()
}

fn sequences_sorted_by_timestamp(events: &[ObservedEvent]) -> Vec<u64> {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|event| event.timestamp().nanos());
    sequences(&ordered)
}

fn wait_accepted(accepted: &AtomicUsize, target: usize) {
    let started = Instant::now();
    loop {
        let current = accepted.load(AtomicOrdering::Acquire);
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

fn non_comment_text(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_text_has_no_sensitive(text: &str) {
    for marker in SENSITIVE {
        assert!(
            !text.contains(marker),
            "sensitive text leaked into observer output"
        );
    }
}

fn assert_event_contract(value: &serde_json::Value) {
    let object = value.as_object().expect("event object");
    assert_exact_keys(object, EVENT_KEYS);
    assert_no_forbidden_keys(value);
    assert_exact_keys(
        object["timestamp"].as_object().expect("timestamp"),
        &["nanos"],
    );
    assert_exact_keys(
        object["process"].as_object().expect("process"),
        &["pid", "tid"],
    );
    assert_exact_keys(
        object["evidence"].as_object().expect("evidence"),
        &["byte_length"],
    );
    let resource = object["resource"].as_object().expect("resource");
    match resource["kind"].as_str().expect("resource kind") {
        "file" => assert_exact_keys(resource, &["kind", "path"]),
        "executable" => assert_exact_keys(resource, &["kind", "identity"]),
        "network" => assert_exact_keys(resource, &["host", "kind", "port"]),
        other => panic!("unknown resource kind {other}"),
    }
    let outcome = object["outcome"].as_object().expect("outcome");
    match outcome["status"].as_str().expect("outcome status") {
        "success" => assert_exact_keys(outcome, &["status"]),
        "failure" => assert_exact_keys(outcome, &["errno", "reason", "status"]),
        other => panic!("unknown outcome status {other}"),
    }
}

fn assert_exact_keys(object: &serde_json::Map<String, serde_json::Value>, allowed: &[&str]) {
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected = allowed.to_vec();
    expected.sort_unstable();
    assert_eq!(keys, expected);
}

fn assert_no_forbidden_keys(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                assert!(
                    !FORBIDDEN_KEYS.contains(&key.as_str()),
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

fn reject_extra_event_fields(baseline: &serde_json::Value) {
    for key in FORBIDDEN_KEYS {
        let mut event = baseline.clone();
        event
            .as_object_mut()
            .expect("event object")
            .insert((*key).to_string(), serde_json::json!("do-not-store"));
        assert!(
            serde_json::from_value::<ObservedEvent>(event).is_err(),
            "event accepted {key}"
        );

        let mut evidence = baseline.clone();
        evidence["evidence"]
            .as_object_mut()
            .expect("evidence")
            .insert((*key).to_string(), serde_json::json!("do-not-store"));
        assert!(
            serde_json::from_value::<ObservedEvent>(evidence).is_err(),
            "evidence accepted {key}"
        );

        let mut resource = baseline.clone();
        resource["resource"]
            .as_object_mut()
            .expect("resource")
            .insert((*key).to_string(), serde_json::json!("do-not-store"));
        assert!(
            serde_json::from_value::<ObservedEvent>(resource).is_err(),
            "resource accepted {key}"
        );

        let mut outcome = baseline.clone();
        outcome["outcome"]
            .as_object_mut()
            .expect("outcome")
            .insert((*key).to_string(), serde_json::json!("do-not-store"));
        assert!(
            serde_json::from_value::<ObservedEvent>(outcome).is_err(),
            "outcome accepted {key}"
        );
    }
}

fn reject_extra<T>(baseline: &serde_json::Value)
where
    T: serde::de::DeserializeOwned,
{
    for key in FORBIDDEN_KEYS {
        let mut value = baseline.clone();
        value
            .as_object_mut()
            .expect("object")
            .insert((*key).to_string(), serde_json::json!("do-not-store"));
        assert!(
            serde_json::from_value::<T>(value).is_err(),
            "accepted forbidden field {key}"
        );
    }
}
