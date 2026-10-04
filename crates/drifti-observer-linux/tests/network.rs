// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Controlled local TCP fixture. No public network dependency.

#![cfg(target_os = "linux")]

use std::num::NonZeroUsize;

use drifti_observer::{
    CommandSpec, CursorError, EventSink, ExecutionId, NetworkProtocol, ObservationCoverage,
    ObservedResource, Observer, Operation, Outcome,
};
use drifti_observer_linux::LinuxObserver;

#[test]
fn loopback_listen_connect_and_failed_attempt_keep_authoritative_identity() {
    let observer = LinuxObserver::new(ExecutionId::from_raw(50));
    let command = CommandSpec::try_new(env!("CARGO_BIN_EXE_network-tracee"), [], None)
        .expect("fixture command");
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(32).unwrap());
    let (_sink, result) = observer.run(command, sink);
    let result = result.expect("trace completed");
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    let mut events = Vec::new();
    while let Ok(event) = cursor.try_recv() {
        events.push(event);
    }
    assert!(matches!(cursor.try_recv(), Err(CursorError::Empty)));
    assert_eq!(events.len(), 3, "expected listen, connect, failed connect");
    assert!(events
        .windows(2)
        .all(|pair| pair[0].sequence() < pair[1].sequence()));
    let listen = events
        .iter()
        .find(|event| event.operation() == Operation::NetworkListen)
        .expect("listen");
    let successful = events
        .iter()
        .find(|event| event.operation() == Operation::NetworkConnect && event.was_exercised())
        .expect("successful connect");
    let failed = events
        .iter()
        .find(|event| event.operation() == Operation::NetworkConnect && !event.was_exercised())
        .expect("failed connect");
    assert_eq!(listen.resource(), successful.resource());
    assert!(
        matches!(listen.resource(), ObservedResource::Network { protocol: Some(NetworkProtocol::Tcp), host, port } if host == "127.0.0.1" && *port != 0)
    );
    assert!(
        matches!(failed.resource(), ObservedResource::Network { protocol: Some(NetworkProtocol::Tcp), host, port: 0 } if host == "127.0.0.1")
    );
    assert!(matches!(
        failed.outcome(),
        Outcome::Failure { errno: Some(_), .. }
    ));
}
