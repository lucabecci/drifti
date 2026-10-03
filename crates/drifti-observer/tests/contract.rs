// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mock observer against the public contract. No platform backend is linked.

use std::fs;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::{
    CapabilityDomain, CommandSpec, CoverageError, EventError, EventSink, EvidenceMeta,
    ExecutionCoverage, ExecutionId, ExecutionResult, FailureReason, MonotonicTimestamp,
    ObservationCoverage, ObservedEvent, ObservedResource, Observer, ObserverCapabilities,
    ObserverError, Operation, Outcome, ParentIdentity, ProcessIdentity,
};

const SECRET_ARG: &str = "super-secret-argv-token";

struct MockObserver {
    events: Vec<ObservedEvent>,
    coverage: ExecutionCoverage,
}

impl Observer for MockObserver {
    fn capabilities(&self) -> ObserverCapabilities {
        ObserverCapabilities::new([CapabilityDomain::Filesystem])
    }

    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        let _ = command.program();
        for event in &self.events {
            if let Err(error) = sink.emit(event.clone()) {
                return (sink, Err(error.into()));
            }
        }
        let execution_id = self
            .events
            .first()
            .map(ObservedEvent::execution_id)
            .unwrap_or_else(|| ExecutionId::from_raw(1));
        (
            sink,
            Ok(ExecutionResult::new(
                execution_id,
                self.coverage.clone(),
                Some(0),
            )),
        )
    }
}

#[test]
fn mock_observer_emits_then_returns_explicit_coverage() {
    let event = sample_event(1, 50);
    let later = sample_event(2, 10);
    let coverage =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, []).expect("declaration");
    let observer = MockObserver {
        events: vec![event.clone(), later.clone()],
        coverage: coverage.clone(),
    };
    let command = CommandSpec::try_new(
        "/usr/bin/demo",
        [SECRET_ARG.to_string()],
        Some("/tmp/work".to_string()),
    )
    .expect("command");
    let rendered = format!("{command:?}");
    assert!(!rendered.contains(SECRET_ARG));
    assert_eq!(command.args(), [SECRET_ARG]);

    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(4).expect("capacity"));
    let (_sink, result) = observer.run(command, sink);
    let result = result.expect("run");

    assert_eq!(result.execution_id(), ExecutionId::from_raw(7));
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.coverage(), &coverage);
    assert!(!result.coverage().is_complete());
    assert!(result.coverage().unsupported_domains().is_empty());
    assert!(observer
        .capabilities()
        .observes(CapabilityDomain::Filesystem));
    assert!(!observer.capabilities().observes(CapabilityDomain::Network));

    let first = cursor
        .recv_timeout(Duration::from_secs(1))
        .expect("first event");
    let second = cursor
        .recv_timeout(Duration::from_secs(1))
        .expect("second event");
    assert_eq!(first.sequence(), 1);
    assert_eq!(second.sequence(), 2);
    assert!(first.timestamp().nanos() > second.timestamp().nanos());

    let encoded = serde_json::to_value(&first).expect("serialize event");
    assert_no_forbidden_keys(&encoded);
    let encoded_text = encoded.to_string();
    assert!(!encoded_text.contains(SECRET_ARG));
    let decoded: ObservedEvent = serde_json::from_value(encoded).expect("deserialize event");
    assert_eq!(decoded, first);
}

#[test]
fn exit_code_zero_does_not_declare_complete_coverage() {
    let coverage =
        ExecutionCoverage::declared(ObservationCoverage::Incomplete, []).expect("declaration");
    let observer = MockObserver {
        events: Vec::new(),
        coverage: coverage.clone(),
    };
    let command = CommandSpec::try_new("demo", [], None).expect("command");
    let (sink, _cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    let (_sink, result) = observer.run(command, sink);
    let result = result.expect("run");
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert!(!result.coverage().is_complete());
}

#[test]
fn complete_coverage_with_an_unsupported_domain_is_rejected() {
    let error =
        ExecutionCoverage::declared(ObservationCoverage::Complete, [CapabilityDomain::Network])
            .expect_err("contradiction");
    assert_eq!(error, CoverageError::CompleteWhileUnsupported);
    let explicit =
        ExecutionCoverage::declared(ObservationCoverage::Complete, []).expect("explicit complete");
    assert!(explicit.is_complete());
}

#[test]
fn closed_sink_returns_the_event() {
    let event = sample_event(1, 1);
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    drop(cursor);
    let error = sink.emit(event.clone()).expect_err("closed");
    assert_eq!(error.event(), &event);
    assert_eq!(error.into_event(), event);
}

#[test]
fn dropped_cursor_keeps_the_accepted_event() {
    let accepted = sample_event(1, 1);
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(1).expect("capacity"));
    sink.emit(accepted.clone()).expect("accepted");
    drop(cursor);

    assert_eq!(sink.take_unconsumed(), vec![accepted]);

    let rejected = sample_event(2, 2);
    let error = sink.emit(rejected.clone()).expect_err("closed");
    assert_eq!(error.into_event(), rejected);
    assert!(sink.take_unconsumed().is_empty());
}

#[test]
fn run_returns_an_accepted_event_without_cloning_the_sink() {
    let first = sample_event(1, 1);
    let second = sample_event(2, 2);
    let phase = Arc::new(AtomicU8::new(0));
    let observer = BlockingObserver {
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

#[test]
fn deserialize_rejects_complete_with_an_unsupported_domain() {
    let rejected = serde_json::from_str::<ExecutionCoverage>(
        r#"{"status":"COMPLETE","unsupported_domains":["network"]}"#,
    )
    .expect_err("COMPLETE plus an unsupported domain");
    assert!(!rejected.to_string().is_empty());

    let coverage: ExecutionCoverage =
        serde_json::from_str(r#"{"status":"COMPLETE","unsupported_domains":[]}"#)
            .expect("explicit complete");
    assert!(coverage.is_complete());
    assert_eq!(coverage.status(), ObservationCoverage::Complete);

    let partial: ExecutionCoverage =
        serde_json::from_str(r#"{"status":"INCOMPLETE","unsupported_domains":["network"]}"#)
            .expect("partial declaration");
    assert!(!partial.is_complete());
    assert_eq!(partial.status(), ObservationCoverage::Incomplete);
    assert_ne!(partial.status(), ObservationCoverage::Complete);
}

#[test]
fn evidence_rejects_a_content_field() {
    let error = serde_json::from_str::<EvidenceMeta>(r#"{"byte_length":null,"content":"secret"}"#)
        .expect_err("unknown content field");
    assert!(!error.to_string().is_empty());
}

#[test]
fn resource_text_rejects_empty_and_nul() {
    assert_eq!(
        ObservedResource::file("").expect_err("empty"),
        EventError::EmptyText
    );
    assert_eq!(
        ObservedResource::file("a\0b").expect_err("nul"),
        EventError::EmbeddedNul
    );
    assert_eq!(
        FailureReason::new("x".repeat(129)).expect_err("long reason"),
        EventError::TextTooLong
    );
}

#[test]
fn crate_boundary_has_no_platform_or_core_dependency() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("observer manifest");
    let dependencies = manifest
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["drifti-core", "libc", "nix", "rusqlite", "clap", "ptrace"] {
        assert!(
            !dependencies.contains(forbidden),
            "{forbidden} leaked into the observer manifest"
        );
    }
    let core_manifest = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../drifti-core/Cargo.toml"
    ))
    .expect("core manifest");
    assert!(!core_manifest.contains("drifti-observer"));

    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    for entry in fs::read_dir(src).expect("src dir") {
        let entry = entry.expect("src entry");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".rs") {
            continue;
        }
        let source = fs::read_to_string(entry.path()).expect("source");
        for forbidden in [
            "std::os::unix",
            "std::os::linux",
            "libc",
            "ptrace",
            "rusqlite",
            "std::fs",
        ] {
            assert!(!source.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}

struct BlockingObserver {
    first: ObservedEvent,
    second: ObservedEvent,
    phase: Arc<AtomicU8>,
}

impl Observer for BlockingObserver {
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

fn sample_event(sequence: u64, timestamp_nanos: u64) -> ObservedEvent {
    ObservedEvent::new(
        ExecutionId::from_raw(7),
        sequence,
        MonotonicTimestamp::from_nanos(timestamp_nanos),
        ProcessIdentity::new(Some(42), Some(7)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file("/tmp/demo").expect("path"),
        Outcome::failure(
            Some(13),
            Some(FailureReason::new("eacces").expect("reason")),
        ),
        EvidenceMeta::with_byte_length(0),
    )
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
