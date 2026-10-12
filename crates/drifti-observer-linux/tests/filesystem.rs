// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filesystem observation tests. They launch `filesystem-tracee` and read
//! semantic events from [`LinuxObserver`]. They do not attach to an arbitrary pid.
//!
//! `waitpid(-1)` reaps any child of this process, so these tests share one lock.

#![cfg(target_os = "linux")]

use std::fs;
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::MutexGuard;
use std::thread;

use drifti_observer::{
    CapabilityDomain, CommandSpec, CursorError, EventSink, ExecutionId, ExecutionResult,
    ObservationCoverage, ObservedEvent, ObservedResource, Observer, Operation,
};
use drifti_observer_linux::LinuxObserver;

fn exclusive_tracer() -> MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn tracee() -> &'static str {
    env!("CARGO_BIN_EXE_filesystem-tracee")
}

fn observe(args: &[&str], cwd: Option<&Path>) -> (ExecutionResult, Vec<ObservedEvent>) {
    let _exclusive = exclusive_tracer();
    let observer = LinuxObserver::new(ExecutionId::from_raw(49));
    let (sink, cursor) = EventSink::bounded(NonZeroUsize::new(64).unwrap());
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
        tracee(),
        args.iter().copied().map(str::to_string),
        cwd.map(|dir| dir.to_str().expect("utf-8 cwd").to_string()),
    )
    .expect("fixture command is within CommandSpec bounds");
    let (sink, result) = observer.run(command, sink);
    drop(sink);
    let events = collector.join().expect("event collector");
    let result = result.unwrap_or_else(|error| panic!("observer run failed: {error}"));
    assert_eq!(result.exit_code(), Some(0), "tracee did not exit 0");
    assert!(!result.coverage().is_complete());
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert_no_file_bytes(&events);
    (result, events)
}

fn assert_no_file_bytes(events: &[ObservedEvent]) {
    for event in events {
        assert!(
            !format!("{event:?}").contains("SUPER_SECRET_BYTES"),
            "event stored file bytes"
        );
        assert_eq!(event.evidence().byte_length(), None);
    }
}

fn file_path(event: &ObservedEvent) -> Option<&str> {
    match event.resource() {
        ObservedResource::File { path } => Some(path),
        _ => None,
    }
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

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "drifti-obs-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("temp dir");
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn text(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

#[cfg(target_arch = "x86_64")]
#[test]
fn read_emits_filesystem_read_without_file_bytes() {
    let dir = Temp::new("read");
    let file = dir.path.join("payload");
    fs::write(&file, b"SUPER_SECRET_BYTES").unwrap();
    let observer = LinuxObserver::new(ExecutionId::from_raw(49));
    assert!(observer
        .capabilities()
        .observes(CapabilityDomain::Filesystem));
    let (_result, events) = observe(&["read", text(&file)], None);
    let event = require(&events, Operation::FilesystemRead, &expected_path(&file));
    assert!(event.was_attempted());
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn write_emits_filesystem_write() {
    let dir = Temp::new("write");
    let file = dir.path.join("created");
    let (_result, events) = observe(&["write", text(&file)], None);
    let event = require(&events, Operation::FilesystemWrite, &expected_path(&file));
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn utimensat_emits_metadata_mutation() {
    let dir = Temp::new("meta");
    let file = dir.path.join("stamp");
    fs::write(&file, b"x").unwrap();
    let (_result, events) = observe(&["metadata", text(&file)], None);
    let event = require(
        &events,
        Operation::FilesystemMetadata,
        &expected_path(&file),
    );
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn statx_emits_metadata() {
    let dir = Temp::new("statx");
    let file = dir.path.join("info");
    fs::write(&file, b"x").unwrap();
    let (_result, events) = observe(&["statx", text(&file)], None);
    let event = require(
        &events,
        Operation::FilesystemMetadata,
        &expected_path(&file),
    );
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn faccessat2_failure_is_attempted_not_exercised() {
    let dir = Temp::new("access");
    let file = dir.path.join("missing-access");
    let (_result, events) = observe(&["faccessat2", text(&file)], None);
    let event = require(
        &events,
        Operation::FilesystemMetadata,
        &expected_path(&file),
    );
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn mknod_emits_write() {
    let dir = Temp::new("mknod");
    let file = dir.path.join("fifo");
    let (_result, events) = observe(&["mknod", text(&file)], None);
    let event = require(&events, Operation::FilesystemWrite, &expected_path(&file));
    assert!(event.was_attempted());
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn mknodat_resolves_dirfd_without_a_returned_descriptor() {
    let dir = Temp::new("mknodat");
    let name = "fifo-at";
    let (_result, events) = observe(&["mknodat", text(&dir.path), name], None);
    let event = require(
        &events,
        Operation::FilesystemWrite,
        &expected_path(&dir.path.join(name)),
    );
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn relative_path_uses_the_tracee_cwd() {
    let dir = Temp::new("rel");
    let file = dir.path.join("payload");
    fs::write(&file, b"x").unwrap();
    let (_result, events) = observe(&["relative", "payload"], Some(&dir.path));
    let event = require(&events, Operation::FilesystemRead, &expected_path(&file));
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn dirfd_failure_resolves_the_entry_path() {
    let dir = Temp::new("dirfd");
    let missing = dir.path.join("missing-entry");
    let (_result, events) = observe(&["dirfd", text(&dir.path), "missing-entry"], None);
    // The open fails, so the tracee never receives a descriptor to read back.
    let event = require(&events, Operation::FilesystemRead, &expected_path(&missing));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn symlink_follow_names_the_target() {
    let dir = Temp::new("follow");
    let target = dir.path.join("target");
    let link = dir.path.join("link");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (_result, events) = observe(&["symlink-follow", text(&link)], None);
    let expected = fs::canonicalize(&target).unwrap();
    let event = require(
        &events,
        Operation::FilesystemRead,
        expected.to_str().expect("utf-8 path"),
    );
    assert!(event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn symlink_nofollow_names_the_link_and_is_not_exercised() {
    let dir = Temp::new("nofollow");
    let target = dir.path.join("target");
    let link = dir.path.join("link");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (_result, events) = observe(&["symlink-nofollow", text(&link)], None);
    let event = require(&events, Operation::FilesystemRead, &expected_path(&link));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
    assert_ne!(file_path(event), Some(expected_path(&target).as_str()));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn failed_open_is_attempted_not_exercised() {
    let dir = Temp::new("fail");
    let missing = dir.path.join("no-such-file");
    let (_result, events) = observe(&["fail", text(&missing)], None);
    let event = require(&events, Operation::FilesystemRead, &expected_path(&missing));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn proc_self_is_the_tracee_not_the_tracer() {
    let (_result, events) = observe(&["proc-self"], None);
    let event = events
        .iter()
        .find(|event| {
            event.operation() == Operation::FilesystemRead
                && file_path(event).is_some_and(|path| path.contains("drifti-kan49-missing"))
        })
        .expect("proc self event");
    let pid = event.process().pid().expect("tracee pid");
    assert_ne!(pid, std::process::id());
    let expected = format!("/proc/{pid}/drifti-kan49-missing");
    assert_eq!(file_path(event), Some(expected.as_str()));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn proc_thread_self_uses_the_tracee_tid() {
    let (_result, events) = observe(&["thread-self"], None);
    let event = events
        .iter()
        .find(|event| {
            event.operation() == Operation::FilesystemRead
                && file_path(event).is_some_and(|path| path.contains("drifti-kan49-missing"))
        })
        .expect("thread self event");
    let pid = event.process().pid().expect("tracee pid");
    let tid = event.process().tid().expect("tracee tid");
    assert_ne!(tid, std::process::id());
    assert_ne!(tid, pid);
    let expected = format!("/proc/{tid}/drifti-kan49-missing");
    assert_eq!(file_path(event), Some(expected.as_str()));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn lchown_keeps_the_symlink() {
    let dir = Temp::new("lchown");
    let target = dir.path.join("target");
    let link = dir.path.join("link");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (_result, events) = observe(&["lchown", text(&link)], None);
    let event = require(
        &events,
        Operation::FilesystemMetadata,
        &expected_path(&link),
    );
    assert!(event.was_exercised());
    assert_ne!(file_path(event), Some(expected_path(&target).as_str()));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn openat2_no_symlinks_keeps_the_link_on_failure() {
    let dir = Temp::new("nosym");
    let target = dir.path.join("target");
    let link = dir.path.join("link");
    fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let (_result, events) = observe(&["openat2-nosym", text(&link)], None);
    let event = require(&events, Operation::FilesystemRead, &expected_path(&link));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
    assert_ne!(file_path(event), Some(expected_path(&target).as_str()));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn openat2_in_root_scopes_a_failed_absolute_path() {
    let dir = Temp::new("inroot");
    let jail = dir.path.join("jail");
    fs::create_dir(&jail).unwrap();
    let (_result, events) = observe(
        &["openat2-in-root", text(&jail), "/drifti-openat2-missing"],
        None,
    );
    let expected = expected_path(&jail.join("drifti-openat2-missing"));
    let event = require(&events, Operation::FilesystemRead, &expected);
    assert!(!expected.starts_with("/drifti-openat2-missing"));
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn openat2_beneath_does_not_follow_an_escaping_symlink() {
    let dir = Temp::new("beneath");
    let outside = dir.path.join("outside");
    let jail = dir.path.join("jail");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(&jail).unwrap();
    std::os::unix::fs::symlink(&outside, jail.join("escape")).unwrap();
    let (_result, events) = observe(&["openat2-beneath", text(&jail), "escape"], None);
    let event = require(
        &events,
        Operation::FilesystemRead,
        &expected_path(&jail.join("escape")),
    );
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
    assert_ne!(file_path(event), Some(expected_path(&outside).as_str()));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn openat2_no_magiclinks_does_not_follow_proc_exe() {
    let (_result, events) = observe(&["openat2-magic"], None);
    let event = events
        .iter()
        .find(|event| file_path(event).is_some_and(|path| path.ends_with("/exe")))
        .expect("magic link event");
    let pid = event.process().pid().expect("tracee pid");
    assert_ne!(pid, std::process::id());
    let expected = format!("/proc/{pid}/exe");
    assert_eq!(file_path(event), Some(expected.as_str()));
    let binary = events.iter().find(|candidate| {
        candidate.operation() == Operation::ProcessExecute && candidate.was_exercised()
    });
    let binary = binary.expect("process execute");
    assert_ne!(
        file_path(event),
        match binary.resource() {
            ObservedResource::Executable { identity } => Some(identity.as_str()),
            _ => None,
        }
    );
    assert!(event.was_attempted());
    assert!(!event.was_exercised());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn openat2_no_xdev_does_not_follow_onto_another_device() {
    let dir = Temp::new("xdev");
    let link = dir.path.join("to-proc");
    std::os::unix::fs::symlink("/proc/self/stat", &link).unwrap();
    let (_result, events) = observe(&["openat2-noxdev", text(&link)], None);
    let event = events
        .iter()
        .find(|event| file_path(event).is_some_and(|path| path.ends_with("/to-proc")))
        .expect("noxdev event");
    let tmp_dev = fs::metadata(&dir.path).unwrap().dev();
    let proc_dev = fs::metadata("/proc").unwrap().dev();
    if tmp_dev != proc_dev {
        let path = file_path(event).unwrap();
        assert!(!path.contains("/proc/"), "{path}");
        assert!(event.was_attempted());
        assert!(!event.was_exercised());
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
fn non_x86_64_run_marks_filesystem_unsupported() {
    let (_result, _events) = observe(&["fail", "/drifti-kan49-missing"], None);
    let observer = LinuxObserver::new(ExecutionId::from_raw(49));
    assert!(!observer
        .capabilities()
        .observes(CapabilityDomain::Filesystem));
    let (result, _) = observe(&["fail", "/drifti-kan49-missing"], None);
    assert!(result
        .coverage()
        .unsupported_domains()
        .contains(&CapabilityDomain::Filesystem));
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
}
