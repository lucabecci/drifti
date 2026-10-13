// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sequence ordering and outcome semantics for [`ObservedEvent`].

use std::cmp::Ordering;

use drifti_observer::{
    EventError, EvidenceMeta, ExecutionId, FailureReason, MonotonicTimestamp, NetworkProtocol,
    ObservedEvent, ObservedResource, Operation, Outcome, ParentIdentity, ProcessIdentity,
};

#[test]
fn network_resource_keeps_authoritative_protocol_and_address() {
    let endpoint = ObservedResource::network_with_protocol(NetworkProtocol::Tcp, "127.0.0.1", 8080)
        .expect("endpoint");
    let json = serde_json::to_value(&endpoint).expect("serialize");
    assert_eq!(json["protocol"], "tcp");
    assert_eq!(json["host"], "127.0.0.1");
    assert_eq!(json["port"], 8080);
    assert_eq!(
        serde_json::from_value::<ObservedResource>(json).unwrap(),
        endpoint
    );
    let old = ObservedResource::network("example.test", 443).unwrap();
    assert!(serde_json::to_value(old).unwrap().get("protocol").is_none());
}

/// Looks like an argument or secret. It is never stored on the event.
const SECRET_LOOKING_ARGUMENT: &str = "aws-secret-access-key=not-part-of-the-event";

const FORBIDDEN_KEYS: &[&str] = &[
    "content", "payload", "argv", "secret", "prompt", "response", "stdout", "stderr",
];

#[test]
fn sequence_cmp_orders_by_sequence_when_timestamps_are_inverted() {
    let earlier = event(ExecutionId::from_raw(7), 1, 900);
    let later = event(ExecutionId::from_raw(7), 2, 10);
    assert!(earlier.timestamp().nanos() > later.timestamp().nanos());

    assert_eq!(earlier.sequence_cmp(&later), Some(Ordering::Less));
    assert_eq!(later.sequence_cmp(&earlier), Some(Ordering::Greater));

    let same_sequence_other_time = event(ExecutionId::from_raw(7), 1, 1);
    assert_ne!(
        earlier.timestamp().nanos(),
        same_sequence_other_time.timestamp().nanos()
    );
    assert_eq!(
        earlier.sequence_cmp(&same_sequence_other_time),
        Some(Ordering::Equal)
    );
}

#[test]
fn sequence_cmp_returns_none_for_a_different_execution() {
    let left = event(ExecutionId::from_raw(7), 1, 900);
    let right = event(ExecutionId::from_raw(8), 1, 900);
    assert_eq!(left.sequence_cmp(&right), None);
    assert_eq!(right.sequence_cmp(&left), None);
}

#[test]
fn sorting_with_sequence_cmp_is_not_a_timestamp_sort() {
    let execution = ExecutionId::from_raw(7);
    let mut events = vec![
        event(execution, 2, 10),
        event(execution, 3, 200),
        event(execution, 1, 900),
    ];
    let by_timestamp: Vec<u64> = {
        let mut ordered = events.clone();
        ordered.sort_by_key(|event| event.timestamp().nanos());
        ordered.into_iter().map(|event| event.sequence()).collect()
    };
    assert_eq!(by_timestamp, [2, 3, 1]);

    events.sort_by(|left, right| {
        left.sequence_cmp(right)
            .expect("fixture uses one execution id")
    });
    let by_sequence: Vec<u64> = events.iter().map(ObservedEvent::sequence).collect();
    assert_eq!(by_sequence, [1, 2, 3]);
    assert_ne!(by_sequence, by_timestamp);
}

#[test]
fn success_is_attempted_and_exercised_and_failure_is_only_attempted() {
    let reason = FailureReason::new("eacces").expect("reason");
    let exercised = event_with_outcome(Outcome::success());
    assert!(exercised.was_attempted());
    assert!(exercised.was_exercised());

    let attempted = event_with_outcome(Outcome::failure(Some(13), Some(reason)));
    assert!(attempted.was_attempted());
    assert!(!attempted.was_exercised());
}

#[test]
fn event_json_has_no_payload_secret_or_argv_fields() {
    let _not_stored = SECRET_LOOKING_ARGUMENT;
    let observed = event(ExecutionId::from_raw(7), 1, 900);
    let encoded = serde_json::to_value(&observed).expect("serialize event");
    assert_no_forbidden_keys(&encoded);
    let encoded_text = encoded.to_string();
    assert!(
        !encoded_text.contains(SECRET_LOOKING_ARGUMENT),
        "a string that is not part of the event leaked into JSON"
    );

    let timestamp = encoded
        .get("timestamp")
        .and_then(serde_json::Value::as_object)
        .expect("monotonic timestamp object");
    assert_eq!(timestamp.len(), 1);
    assert!(timestamp.contains_key("nanos"));
    assert!(!timestamp.contains_key("wall_clock"));
}

#[test]
fn failure_reason_and_file_identity_reject_invalid_text() {
    assert_eq!(
        FailureReason::new("").expect_err("empty"),
        EventError::EmptyText
    );
    assert_eq!(
        FailureReason::new("a\0b").expect_err("nul"),
        EventError::EmbeddedNul
    );
    assert_eq!(
        FailureReason::new("x".repeat(129)).expect_err("129 bytes"),
        EventError::TextTooLong
    );
    assert_eq!(
        ObservedResource::file("").expect_err("empty path"),
        EventError::EmptyText
    );
}

#[test]
fn evidence_meta_rejects_an_extra_content_field() {
    let error = serde_json::from_str::<EvidenceMeta>(r#"{"byte_length":null,"content":"secret"}"#)
        .expect_err("unknown content field");
    assert!(!error.to_string().is_empty());
}

fn event(execution_id: ExecutionId, sequence: u64, timestamp_nanos: u64) -> ObservedEvent {
    event_with(execution_id, sequence, timestamp_nanos, Outcome::success())
}

fn event_with_outcome(outcome: Outcome) -> ObservedEvent {
    event_with(
        ExecutionId::from_raw(7),
        1,
        MonotonicTimestamp::from_nanos(1).nanos(),
        outcome,
    )
}

fn event_with(
    execution_id: ExecutionId,
    sequence: u64,
    timestamp_nanos: u64,
    outcome: Outcome,
) -> ObservedEvent {
    ObservedEvent::new(
        execution_id,
        sequence,
        MonotonicTimestamp::from_nanos(timestamp_nanos),
        ProcessIdentity::new(Some(42), Some(7)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file("/tmp/demo").expect("path"),
        outcome,
        EvidenceMeta::with_byte_length(0),
    )
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
