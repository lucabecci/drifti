// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Controlled local TCP fixture. No public network dependency.
//!
//! `waitpid(-1)` reaps any child of this process, so these tests share one lock.

#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::MutexGuard;
use std::thread;

use drifti_observer::{
    CapabilityDomain, CommandSpec, CursorError, EventSink, ExecutionId, NetworkProtocol,
    ObservationCoverage, ObservedEvent, ObservedResource, Observer, Operation, Outcome,
};
use drifti_observer_linux::LinuxObserver;

fn exclusive_tracer() -> MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn observe() -> (drifti_observer::ExecutionResult, Vec<ObservedEvent>) {
    let _exclusive = exclusive_tracer();
    let observer = LinuxObserver::new(ExecutionId::from_raw(50));
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(256).unwrap());
    let collector = thread::spawn(move || {
        let mut events = Vec::new();
        loop {
            match cursor.recv() {
                Ok(event) => events.push(event),
                Err(CursorError::Disconnected) => break,
                Err(CursorError::Empty | CursorError::TimedOut) => {}
            }
        }
        events
    });
    let command = CommandSpec::try_new(env!("CARGO_BIN_EXE_network-tracee"), [], None)
        .expect("fixture command");
    let (sink, result) = observer.run(command, sink);
    drop(sink);
    let events = collector.join().expect("event collector");
    let result = result.expect("trace completed");
    (result, events)
}

#[cfg(target_arch = "x86_64")]
#[test]
fn loopback_listen_connect_and_failed_attempt_keep_authoritative_identity() {
    let observer = LinuxObserver::new(ExecutionId::from_raw(50));
    assert!(observer.capabilities().observes(CapabilityDomain::Network));
    let (result, events) = observe();
    assert_eq!(result.exit_code(), Some(0));
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert!(!result.coverage().is_complete());
    assert!(result.coverage().unsupported_domains().is_empty());
    assert!(events
        .windows(2)
        .all(|pair| pair[0].sequence() < pair[1].sequence()));
    for event in &events {
        assert_eq!(event.evidence().byte_length(), None);
    }
    let network: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event.operation(),
                Operation::NetworkConnect | Operation::NetworkListen
            )
        })
        .collect();
    assert_eq!(network.len(), 3, "expected listen, connect, failed connect");
    let listen = network
        .iter()
        .find(|event| event.operation() == Operation::NetworkListen)
        .expect("listen");
    let successful = network
        .iter()
        .find(|event| event.operation() == Operation::NetworkConnect && event.was_exercised())
        .expect("successful connect");
    let failed = network
        .iter()
        .find(|event| event.operation() == Operation::NetworkConnect && !event.was_exercised())
        .expect("failed connect");
    assert_eq!(listen.resource(), successful.resource());
    assert!(listen.was_attempted());
    assert!(listen.was_exercised());
    assert!(successful.was_attempted());
    match listen.resource() {
        ObservedResource::Network {
            protocol: Some(NetworkProtocol::Tcp),
            host,
            port,
        } => {
            assert_eq!(host, "127.0.0.1");
            assert_ne!(host, "localhost");
            assert!(host.parse::<IpAddr>().is_ok());
            assert_ne!(*port, 0);
        }
        other => panic!("listen identity {other:?}"),
    }
    match failed.resource() {
        ObservedResource::Network {
            protocol: Some(NetworkProtocol::Tcp),
            host,
            port: 0,
        } => {
            assert_eq!(host, "127.0.0.1");
            assert_ne!(host, "localhost");
        }
        other => panic!("failed connect identity {other:?}"),
    }
    assert!(failed.was_attempted());
    assert!(!failed.was_exercised());
    assert!(matches!(
        failed.outcome(),
        Outcome::Failure { errno: Some(_), .. }
    ));
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
fn non_x86_64_run_marks_network_unsupported() {
    let observer = LinuxObserver::new(ExecutionId::from_raw(50));
    assert!(!observer.capabilities().observes(CapabilityDomain::Network));
    let (result, events) = observe();
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert!(!result.coverage().is_complete());
    assert!(result
        .coverage()
        .unsupported_domains()
        .contains(&CapabilityDomain::Network));
    assert!(events.iter().all(|event| {
        !matches!(
            event.operation(),
            Operation::NetworkConnect | Operation::NetworkListen
        )
    }));
}
