// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-005 end-to-end acceptance matrix (KAN-52).
//!
//! Fixture binaries are deterministic and avoid the public internet. Each test
//! asserts canonical semantics and `INCOMPLETE` coverage on a successful trace.

#![cfg(target_os = "linux")]

use std::fs;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
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

fn observe(
    binary: &str,
    args: &[&str],
    cwd: Option<&Path>,
    execution: u64,
) -> (drifti_observer::ExecutionResult, Vec<ObservedEvent>) {
    let _exclusive = exclusive_tracer();
    let observer = LinuxObserver::new(ExecutionId::from_raw(u128::from(execution)));
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(128).unwrap());
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
    let command = CommandSpec::try_new(
        binary,
        args.iter().copied().map(str::to_string),
        cwd.map(|dir| dir.to_str().expect("utf-8 cwd").to_string()),
    )
    .expect("fixture command");
    let (sink, result) = observer.run(command, sink);
    drop(sink);
    let events = collector.join().expect("event collector");
    let result = result.expect("trace completed");
    assert_incomplete(&result);
    (result, events)
}

fn assert_incomplete(result: &drifti_observer::ExecutionResult) {
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert!(!result.coverage().is_complete());
}

struct Temp(PathBuf);

impl Temp {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("drifti-kan52-{label}-{}", std::process::id()));
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

fn file_path(event: &ObservedEvent) -> Option<&str> {
    match event.resource() {
        ObservedResource::File { path } => Some(path),
        _ => None,
    }
}

/// Parent is canonical. The final component is not followed, so a symlink
/// stays the link and a missing file keeps its name.
fn expected_path(path: &Path) -> String {
    let parent = path.parent().expect("parent");
    let parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    parent
        .join(path.file_name().expect("file name"))
        .to_str()
        .expect("utf-8 path")
        .to_string()
}

fn require<'a>(
    events: &'a [ObservedEvent],
    operation: Operation,
    expected: &str,
) -> &'a ObservedEvent {
    let matched: Vec<_> = events
        .iter()
        .filter(|event| event.operation() == operation && file_path(event) == Some(expected))
        .collect();
    if matched.len() != 1 {
        let seen: Vec<_> = events
            .iter()
            .filter(|event| event.operation() == operation)
            .filter_map(file_path)
            .collect();
        panic!(
            "expected one {} for {expected}, saw {seen:?}",
            operation.as_str()
        );
    }
    matched[0]
}

#[test]
fn fixture_process_tree_emits_three_exercised_exec_events() {
    let binary = env!("CARGO_BIN_EXE_fixture-process-tree");
    let (_result, events) = observe(binary, &["exec-tree"], None, 5201);
    let execs: Vec<_> = events
        .iter()
        .filter(|event| event.operation() == Operation::ProcessExecute)
        .collect();
    assert_eq!(execs.len(), 3);
    assert!(execs.iter().all(|event| event.was_exercised()));
    assert_eq!(execs[0].parent(), None);
    assert_eq!(
        execs[1].parent().map(|parent| parent.pid()),
        execs[0].process().pid()
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fixture_fs_read_and_write_use_canonical_paths() {
    let read_bin = env!("CARGO_BIN_EXE_fixture-fs-read");
    let write_bin = env!("CARGO_BIN_EXE_fixture-fs-write");
    let dir = Temp::new("fs");
    let file = dir.0.join("payload");
    fs::write(&file, b"SECRET").unwrap();
    let (_result, read_events) = observe(read_bin, &["read", path_text(&file)], None, 5202);
    let read = require(
        &read_events,
        Operation::FilesystemRead,
        &expected_path(&file),
    );
    assert!(read.was_exercised());

    let created = dir.0.join("created");
    let (_result, write_events) = observe(write_bin, &["write", path_text(&created)], None, 5203);
    let write = require(
        &write_events,
        Operation::FilesystemWrite,
        &expected_path(&created),
    );
    assert!(write.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fixture_symlink_follow_and_nofollow_differ() {
    let binary = env!("CARGO_BIN_EXE_fixture-symlink");
    let dir = Temp::new("symlink");
    let target = dir.0.join("target");
    fs::write(&target, b"x").unwrap();
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (_result, follow) = observe(binary, &["symlink-follow", path_text(&link)], None, 5204);
    let expected_target = fs::canonicalize(&target).expect("target path");
    let follow_event = require(
        &follow,
        Operation::FilesystemRead,
        expected_target.to_str().expect("utf-8 path"),
    );
    assert!(follow_event.was_exercised());

    let (_result, nofollow) = observe(binary, &["symlink-nofollow", path_text(&link)], None, 5205);
    let nofollow_event = require(&nofollow, Operation::FilesystemRead, &expected_path(&link));
    assert!(nofollow_event.was_attempted());
    assert!(!nofollow_event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fixture_network_connect_stays_on_loopback() {
    let binary = env!("CARGO_BIN_EXE_fixture-network-connect");
    let (_result, events) = observe(binary, &[], None, 5206);
    let network: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event.operation(),
                Operation::NetworkConnect | Operation::NetworkListen
            )
        })
        .collect();
    assert_eq!(network.len(), 3);
    for event in &network {
        match event.resource() {
            ObservedResource::Network {
                protocol: Some(NetworkProtocol::Tcp),
                host,
                port: _,
            } => {
                assert_eq!(host, "127.0.0.1");
                assert!(host.parse::<IpAddr>().is_ok());
            }
            other => panic!("network identity {other:?}"),
        }
    }
}

#[test]
fn fixture_failed_access_is_attempted_not_exercised() {
    let process_bin = env!("CARGO_BIN_EXE_fixture-failed-access");
    let (_result, process_events) = observe(process_bin, &["failed-exec"], None, 5207);
    let failure = process_events
        .iter()
        .find(|event| event.operation() == Operation::ProcessExecute && !event.was_exercised())
        .expect("failed exec");
    assert!(failure.was_attempted());
    assert!(matches!(
        failure.outcome(),
        Outcome::Failure { errno: Some(2), .. }
    ));

    #[cfg(target_arch = "x86_64")]
    {
        let fs_bin = env!("CARGO_BIN_EXE_fixture-fs-read");
        let missing = PathBuf::from("/drifti-kan52-missing");
        let (_result, fs_events) = observe(fs_bin, &["fail", path_text(&missing)], None, 5208);
        let open = require(
            &fs_events,
            Operation::FilesystemRead,
            &expected_path(&missing),
        );
        assert!(open.was_attempted());
        assert!(!open.was_exercised());
    }
}

#[test]
fn fixture_io_uring_degrades_filesystem_and_network_coverage() {
    let binary = env!("CARGO_BIN_EXE_fixture-io-uring");
    let (result, _events) = observe(binary, &["io-uring"], None, 5209);
    let unsupported = result.coverage().unsupported_domains();
    assert!(unsupported.contains(&CapabilityDomain::Filesystem));
    assert!(unsupported.contains(&CapabilityDomain::Network));
}
