// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux lifecycle tests. They use the `lifecycle-tracee` and
//! `lifecycle-tracer` fixtures and do not attach to an arbitrary pid.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use drifti_observer::{
    CommandSpec, CursorError, EventSink, ExecutionId, ObservationCoverage, Observer,
};
use drifti_observer_linux::{
    LinuxObserver, ObservationGap, ObservedSyscall, SessionLimits, ThreadLineage, TraceError,
    TraceSession, TraceStop, TraceVisitor,
};

fn limits() -> SessionLimits {
    SessionLimits {
        max_tracees: 64,
        max_gaps: 64,
        max_stops: 10_000,
        max_wait: Some(Duration::from_secs(5)),
    }
}

fn command(args: &[&str], current_dir: Option<&str>) -> CommandSpec {
    CommandSpec::try_new(
        env_tracee(),
        args.iter().copied().map(str::to_string),
        current_dir.map(str::to_string),
    )
    .expect("fixture command is within CommandSpec bounds")
}

fn env_tracee() -> &'static str {
    // `cargo test` sets this to the fixture binary. Cross-check builds that
    // do not link bins leave it unset; those builds do not run the test.
    option_env!("CARGO_BIN_EXE_lifecycle_tracee").unwrap_or("lifecycle-tracee")
}

fn drive(args: &[&str]) -> drifti_observer_linux::TraceReport {
    let session =
        TraceSession::launch_with_limits(ExecutionId::from_raw(47), command(args, None), limits())
            .expect("launch");
    session
        .drive(&mut drifti_observer_linux::AcknowledgeStops)
        .expect("drive")
}

#[test]
fn exit_code_is_observed_and_coverage_is_incomplete() {
    let report = drive(&["exit", "7"]);
    assert_eq!(report.exit_code(), Some(7));
    assert!(report.stops_delivered() > 0);
    let coverage = report.bootstrap_coverage();
    assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
    assert!(!coverage.is_complete());
    assert!(report
        .lineage()
        .record(report.lineage().root().unwrap())
        .is_some());
    assert!(report
        .lineage()
        .threads()
        .all(|thread| thread.options_applied()));
}

#[test]
fn child_and_grandchild_remain_attached() {
    let report = drive(&["tree"]);
    let root = report.lineage().root().expect("root");
    let child = report
        .lineage()
        .threads()
        .find(|thread| thread.parent_tid() == Some(root))
        .expect("child");
    let grandchild = report
        .lineage()
        .threads()
        .find(|thread| thread.parent_tid() == Some(child.tid()))
        .expect("grandchild");
    assert!(child.options_applied());
    assert!(grandchild.options_applied());
    assert!(!child.is_live());
    assert!(!grandchild.is_live());
}

#[test]
fn syscall_entry_and_exit_alternate_per_thread() {
    let mut phases = Phases::default();
    let session = TraceSession::launch_with_limits(
        ExecutionId::from_raw(47),
        command(&["threads"], None),
        limits(),
    )
    .expect("launch");
    let report = session.drive(&mut phases).expect("drive");
    assert!(report.lineage().threads().count() >= 2);
    assert!(phases
        .0
        .values()
        .any(|seen| { seen.iter().any(|mark| matches!(mark, Mark::Phase(_))) }));
    for seen in phases.0.values() {
        assert!(
            phases_are_deterministic(seen),
            "syscall phases were not deterministic: {seen:?}"
        );
    }
}

#[test]
fn launch_failure_does_not_echo_argument_values() {
    let command = command(
        &["SUPER_SECRET_ARG", "exit", "0"],
        Some("/no/such/drifti-cwd"),
    );
    let error = match TraceSession::launch_with_limits(ExecutionId::from_raw(47), command, limits())
    {
        Err(error) => error,
        Ok(_session) => panic!("chdir must fail before attach"),
    };
    let text = error.to_string();
    assert!(!text.contains("SUPER_SECRET_ARG"));
    assert!(matches!(
        error,
        TraceError::TraceeExitedBeforeAttach { code: 126 }
    ));
    let observer = error.into_observer_error();
    let rendered = observer.to_string();
    assert!(!rendered.contains("SUPER_SECRET_ARG"));
    assert!(!rendered.contains("COMPLETE"));
}

#[test]
fn successful_report_does_not_contain_argument_values() {
    let session = TraceSession::launch_with_limits(
        ExecutionId::from_raw(47),
        command(&["SUPER_SECRET_ARG", "exit", "0"], None),
        limits(),
    )
    .expect("launch");
    let report = session
        .drive(&mut drifti_observer_linux::AcknowledgeStops)
        .expect("drive");
    assert!(!format!("{report:?}").contains("SUPER_SECRET_ARG"));
}

#[test]
fn stop_limit_is_not_success() {
    let mut tight = limits();
    tight.max_stops = 1;
    let session = TraceSession::launch_with_limits(
        ExecutionId::from_raw(47),
        command(&["exit", "0"], None),
        tight,
    )
    .expect("launch");
    let error = session
        .drive(&mut drifti_observer_linux::AcknowledgeStops)
        .expect_err("limit");
    assert!(matches!(error, TraceError::StopLimit { .. }));
    assert!(!format!("{error}").contains("COMPLETE"));
}

#[test]
fn visitor_rejection_kills_the_tracee() {
    let session = TraceSession::launch_with_limits(
        ExecutionId::from_raw(47),
        command(&["sleep"], None),
        limits(),
    )
    .expect("launch");
    let pid = session.root_pid().expect("pid");
    let error = session.drive(&mut Boom).expect_err("visitor");
    assert!(matches!(error, TraceError::Visitor));
    assert!(
        becomes_absent(pid),
        "rejected run left tracee {pid} running"
    );
}

#[test]
fn tracer_exit_kills_the_tracee() {
    let output =
        Command::new(option_env!("CARGO_BIN_EXE_lifecycle_tracer").unwrap_or("lifecycle-tracer"))
            .arg(env_tracee())
            .output()
            .expect("tracer");
    assert!(
        output.status.success(),
        "tracer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("pid text");
    let pid: u32 = text.trim().parse().expect("pid");
    assert!(becomes_absent(pid), "tracee {pid} survived tracer exit");
}

#[test]
fn observer_run_emits_no_semantic_events_and_is_incomplete() {
    let observer = LinuxObserver::new(ExecutionId::from_raw(47));
    assert!(observer.capabilities().domains().is_empty());
    let (sink, cursor) = EventSink::bounded(std::num::NonZeroUsize::new(4).unwrap());
    let (_sink, result) = observer.run(command(&["exit", "0"], None), sink);
    let result = result.expect("run");
    assert_eq!(result.exit_code(), Some(0));
    assert!(!result.coverage().is_complete());
    assert_eq!(result.coverage().status(), ObservationCoverage::Incomplete);
    assert!(matches!(cursor.try_recv(), Err(CursorError::Empty)));
}

#[derive(Debug)]
enum Mark {
    Phase(ObservedSyscall),
    Gap(ObservationGap),
}

#[derive(Default)]
struct Phases(BTreeMap<u32, Vec<Mark>>);

impl TraceVisitor for Phases {
    fn on_stop(&mut self, stop: &TraceStop, _lineage: &ThreadLineage) -> Result<(), TraceError> {
        match stop {
            TraceStop::Syscall(syscall) => {
                self.0
                    .entry(syscall.tid())
                    .or_default()
                    .push(Mark::Phase(syscall.observed()));
            }
            TraceStop::Gap(gap) => {
                let tid = gap_tid(*gap);
                self.0.entry(tid).or_default().push(Mark::Gap(*gap));
            }
            _ => {}
        }
        Ok(())
    }
}

fn gap_tid(gap: ObservationGap) -> u32 {
    match gap {
        ObservationGap::SyscallPhaseMismatch { tid, .. }
        | ObservationGap::UnaffiliatedTracee { tid }
        | ObservationGap::SeccompStop { tid }
        | ObservationGap::ProcStatusUnreadable { tid }
        | ObservationGap::PidfdUnavailable { tid }
        | ObservationGap::Continued { tid }
        | ObservationGap::InvalidEventMessage { tid }
        | ObservationGap::ExecWithUnknownTgid { tid }
        | ObservationGap::ExecRetiredThread { tid }
        | ObservationGap::UntrackedWait { tid }
        | ObservationGap::UnknownPtraceEvent { tid, .. }
        | ObservationGap::ParentConflict { tid, .. }
        | ObservationGap::TgidConflict { tid, .. } => tid,
    }
}

struct Boom;

impl TraceVisitor for Boom {
    fn on_stop(&mut self, _stop: &TraceStop, _lineage: &ThreadLineage) -> Result<(), TraceError> {
        Err(TraceError::Visitor)
    }
}

fn phases_are_deterministic(marks: &[Mark]) -> bool {
    let mut expect = ObservedSyscall::Entry;
    for mark in marks {
        match mark {
            Mark::Gap(ObservationGap::SyscallPhaseMismatch { observed, .. }) => {
                expect = *observed;
            }
            Mark::Phase(phase) => {
                if *phase != expect {
                    return false;
                }
                expect = match phase {
                    ObservedSyscall::Entry => ObservedSyscall::Exit,
                    ObservedSyscall::Exit => ObservedSyscall::Entry,
                };
            }
            Mark::Gap(_) => {}
        }
    }
    true
}

fn becomes_absent(pid: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if !process_exists(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn process_exists(pid: u32) -> bool {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            // A zombie is not a running tracee.
            return !rest.trim().starts_with('Z');
        }
    }
    true
}
