// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure tracee-lifecycle transitions.
//!
//! [`apply_stop`] always returns a [`TraceStop`] or an error that still
//! carries the rejected fact. It does not drop a stop and return success.

use crate::abi::{
    PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT, PTRACE_EVENT_FORK,
    PTRACE_EVENT_SECCOMP, PTRACE_EVENT_STOP, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE,
};
use crate::error::{ObservationGap, TraceError, TraceStop};
use crate::lineage::{SpawnKind, SpawnStop, SyscallDelivery, ThreadLineage};
use crate::syscall::ParsedSyscall;

/// What the session should do with the thread that just stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAction {
    /// Apply lifecycle options, then `PTRACE_SYSCALL` with no signal.
    AttachThenSyscall,
    /// `PTRACE_SYSCALL`, reinjecting `signal` when it is non-zero.
    Syscall {
        /// Linux signal number, or `0` to inject nothing.
        signal: i32,
    },
    /// The task has been reaped. Do not call `ptrace`.
    Reaped,
    /// The kernel already continued the task.
    AlreadyRunning,
}

/// One accepted transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedStop {
    /// Stop to deliver, unless it is a [`TraceStop::Gap`] already stored
    /// on the lineage. The session delivers stored gaps from the lineage
    /// so a gap is handed to the visitor once.
    pub stop: TraceStop,
    /// How to resume the thread that stopped.
    pub action: ResumeAction,
}

/// Kernel event number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceEventKind {
    /// `PTRACE_EVENT_FORK`.
    Fork,
    /// `PTRACE_EVENT_VFORK`.
    Vfork,
    /// `PTRACE_EVENT_CLONE`.
    Clone,
    /// `PTRACE_EVENT_EXEC`.
    Exec,
    /// `PTRACE_EVENT_VFORK_DONE`.
    VforkDone,
    /// `PTRACE_EVENT_EXIT`.
    Exit,
    /// `PTRACE_EVENT_SECCOMP`.
    Seccomp,
    /// `PTRACE_EVENT_STOP`.
    Stop,
    /// An event number this layer does not name.
    Other(u32),
}

impl PtraceEventKind {
    /// Maps a raw event field.
    #[must_use]
    pub const fn from_raw(event: u32) -> Self {
        match event {
            PTRACE_EVENT_FORK => Self::Fork,
            PTRACE_EVENT_VFORK => Self::Vfork,
            PTRACE_EVENT_CLONE => Self::Clone,
            PTRACE_EVENT_EXEC => Self::Exec,
            PTRACE_EVENT_VFORK_DONE => Self::VforkDone,
            PTRACE_EVENT_EXIT => Self::Exit,
            PTRACE_EVENT_SECCOMP => Self::Seccomp,
            PTRACE_EVENT_STOP => Self::Stop,
            other => Self::Other(other),
        }
    }
}

/// A decoded stop plus any data read while the tracee was stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawStop {
    /// Syscall entry, exit, seccomp, or an unavailable op.
    Syscall(ParsedSyscall),
    /// Ptrace event. `message` is `PTRACE_GETEVENTMSG`.
    Event {
        /// Event kind.
        event: PtraceEventKind,
        /// Event message.
        message: u64,
    },
    /// Signal-delivery stop.
    Stopped {
        /// Linux signal number.
        signal: i32,
    },
    /// Normal exit.
    Exited {
        /// Exit code.
        code: i32,
    },
    /// Death by signal.
    Signaled {
        /// Linux signal number.
        signal: i32,
    },
    /// Continued.
    Continued,
}

/// Visitor invoked for every delivered stop before the tracee is resumed.
///
/// `on_stop` runs while the tracee is stopped. A remote memory read for a
/// syscall argument has to happen here. Returning an error aborts the
/// lifecycle; the session does not resume and then report success.
pub trait TraceVisitor {
    /// Handles one stop.
    fn on_stop(&mut self, stop: &TraceStop, lineage: &ThreadLineage) -> Result<(), TraceError>;
}

/// Visitor that accepts every stop and does not decode it.
#[derive(Debug, Default)]
pub struct AcknowledgeStops;

impl TraceVisitor for AcknowledgeStops {
    fn on_stop(&mut self, _stop: &TraceStop, _lineage: &ThreadLineage) -> Result<(), TraceError> {
        Ok(())
    }
}

/// Applies `stop` for `tid` to `lineage`.
pub fn apply_stop(
    lineage: &mut ThreadLineage,
    tid: u32,
    stop: RawStop,
) -> Result<AppliedStop, TraceError> {
    match stop {
        RawStop::Syscall(parsed) => apply_syscall(lineage, tid, parsed),
        RawStop::Event { event, message } => apply_event(lineage, tid, event, message),
        RawStop::Stopped { signal } => apply_signal(lineage, tid, signal),
        RawStop::Exited { code } => {
            lineage.ensure_unaffiliated(tid)?;
            lineage.mark_reaped(tid)?;
            lineage.note_root_exit(tid, code);
            Ok(AppliedStop {
                stop: TraceStop::ProcessExited {
                    tid,
                    exit_code: code,
                },
                action: ResumeAction::Reaped,
            })
        }
        RawStop::Signaled { signal } => {
            lineage.ensure_unaffiliated(tid)?;
            lineage.mark_reaped(tid)?;
            lineage.note_root_signal(tid, signal);
            Ok(AppliedStop {
                stop: TraceStop::ProcessSignaled { tid, signal },
                action: ResumeAction::Reaped,
            })
        }
        RawStop::Continued => {
            let gap = ObservationGap::Continued { tid };
            lineage.push_gap(gap)?;
            Ok(AppliedStop {
                stop: TraceStop::Gap(gap),
                action: ResumeAction::AlreadyRunning,
            })
        }
    }
}

fn apply_syscall(
    lineage: &mut ThreadLineage,
    tid: u32,
    parsed: ParsedSyscall,
) -> Result<AppliedStop, TraceError> {
    match lineage.observe_syscall(tid, parsed)? {
        SyscallDelivery::Observed { stop, .. } => Ok(AppliedStop {
            stop: TraceStop::Syscall(stop),
            action: ResumeAction::Syscall { signal: 0 },
        }),
        SyscallDelivery::Gap(gap) => Ok(AppliedStop {
            stop: TraceStop::Gap(gap),
            action: ResumeAction::Syscall { signal: 0 },
        }),
    }
}

fn apply_event(
    lineage: &mut ThreadLineage,
    tid: u32,
    event: PtraceEventKind,
    message: u64,
) -> Result<AppliedStop, TraceError> {
    lineage.ensure_unaffiliated(tid)?;
    match event {
        PtraceEventKind::Fork => spawn(lineage, tid, message, SpawnKind::Fork),
        PtraceEventKind::Vfork => spawn(lineage, tid, message, SpawnKind::Vfork),
        PtraceEventKind::Clone => spawn(lineage, tid, message, SpawnKind::Clone),
        PtraceEventKind::Exec => {
            lineage.retire_siblings_on_exec(tid)?;
            Ok(AppliedStop {
                stop: TraceStop::Exec { tid },
                action: ResumeAction::Syscall { signal: 0 },
            })
        }
        PtraceEventKind::VforkDone => Ok(AppliedStop {
            stop: TraceStop::VforkDone { tid },
            action: ResumeAction::Syscall { signal: 0 },
        }),
        PtraceEventKind::Exit => Ok(AppliedStop {
            stop: TraceStop::ExitEvent {
                tid,
                wait_status: message,
            },
            action: ResumeAction::Syscall { signal: 0 },
        }),
        PtraceEventKind::Seccomp => gap_and_resume(lineage, ObservationGap::SeccompStop { tid }),
        PtraceEventKind::Other(event) => {
            gap_and_resume(lineage, ObservationGap::UnknownPtraceEvent { tid, event })
        }
        PtraceEventKind::Stop => {
            if lineage.options_applied(tid)? {
                Ok(AppliedStop {
                    stop: TraceStop::GroupStop { tid },
                    action: ResumeAction::Syscall { signal: 0 },
                })
            } else {
                Ok(AppliedStop {
                    stop: TraceStop::Attach { tid },
                    action: ResumeAction::AttachThenSyscall,
                })
            }
        }
    }
}

fn spawn(
    lineage: &mut ThreadLineage,
    parent: u32,
    message: u64,
    kind: SpawnKind,
) -> Result<AppliedStop, TraceError> {
    let child = u32::try_from(message).unwrap_or(0);
    if child == 0 {
        let gap = ObservationGap::InvalidEventMessage { tid: parent };
        lineage.push_gap(gap)?;
        return Ok(AppliedStop {
            stop: TraceStop::Gap(gap),
            action: ResumeAction::Syscall { signal: 0 },
        });
    }
    lineage.ensure_descendant(parent, child, kind)?;
    Ok(AppliedStop {
        stop: TraceStop::Spawn(SpawnStop {
            parent,
            child,
            kind,
        }),
        action: ResumeAction::Syscall { signal: 0 },
    })
}

fn gap_and_resume(
    lineage: &mut ThreadLineage,
    gap: ObservationGap,
) -> Result<AppliedStop, TraceError> {
    lineage.push_gap(gap)?;
    Ok(AppliedStop {
        stop: TraceStop::Gap(gap),
        action: ResumeAction::Syscall { signal: 0 },
    })
}

fn apply_signal(
    lineage: &mut ThreadLineage,
    tid: u32,
    signal: i32,
) -> Result<AppliedStop, TraceError> {
    lineage.ensure_unaffiliated(tid)?;
    if lineage.options_applied(tid)? {
        Ok(AppliedStop {
            stop: TraceStop::Signal { tid, signal },
            action: ResumeAction::Syscall { signal },
        })
    } else {
        Ok(AppliedStop {
            stop: TraceStop::Attach { tid },
            action: ResumeAction::AttachThenSyscall,
        })
    }
}

#[cfg(test)]
mod tests {
    use drifti_observer::ExecutionId;

    use super::{apply_stop, PtraceEventKind, RawStop, ResumeAction};
    use crate::abi::SIGSTOP;
    use crate::error::TraceStop;
    use crate::lineage::{SpawnKind, ThreadLineage};
    use crate::syscall::{ParsedSyscall, SyscallPhase};

    fn rooted() -> ThreadLineage {
        let mut lineage = ThreadLineage::new(ExecutionId::from_raw(3), 8, 8);
        lineage.attach_root(10).unwrap();
        lineage.mark_options_applied(10).unwrap();
        lineage
    }

    #[test]
    fn fork_then_grandchild_stay_attached_in_the_lineage() {
        let mut lineage = rooted();
        apply_stop(
            &mut lineage,
            10,
            RawStop::Event {
                event: PtraceEventKind::Fork,
                message: 11,
            },
        )
        .unwrap();
        let child_stop =
            apply_stop(&mut lineage, 11, RawStop::Stopped { signal: SIGSTOP }).unwrap();
        assert!(matches!(child_stop.stop, TraceStop::Attach { tid: 11 }));
        assert_eq!(child_stop.action, ResumeAction::AttachThenSyscall);
        lineage.mark_options_applied(11).unwrap();
        apply_stop(
            &mut lineage,
            11,
            RawStop::Event {
                event: PtraceEventKind::Fork,
                message: 12,
            },
        )
        .unwrap();
        apply_stop(&mut lineage, 12, RawStop::Stopped { signal: SIGSTOP }).unwrap();
        lineage.mark_options_applied(12).unwrap();
        assert!(lineage.record(11).unwrap().options_applied());
        assert!(lineage.record(12).unwrap().options_applied());
        assert_eq!(lineage.record(12).unwrap().parent_tid(), Some(11));
        assert_eq!(lineage.record(12).unwrap().spawn(), Some(SpawnKind::Fork));
        assert!(lineage.record(11).unwrap().is_live());
        assert!(lineage.record(12).unwrap().is_live());
    }

    #[test]
    fn syscall_entry_and_exit_are_delivered_per_thread() {
        let mut lineage = rooted();
        lineage.ensure_unaffiliated(20).unwrap();
        lineage.mark_options_applied(20).unwrap();
        let first = apply_stop(
            &mut lineage,
            10,
            RawStop::Syscall(ParsedSyscall::Entry {
                number: 1,
                args: [9, 0, 0, 0, 0, 0],
            }),
        )
        .unwrap();
        let second = apply_stop(
            &mut lineage,
            20,
            RawStop::Syscall(ParsedSyscall::Entry {
                number: 2,
                args: [8, 0, 0, 0, 0, 0],
            }),
        )
        .unwrap();
        let first_exit = apply_stop(
            &mut lineage,
            10,
            RawStop::Syscall(ParsedSyscall::Exit {
                return_value: 3,
                is_error: false,
            }),
        )
        .unwrap();
        match first.stop {
            TraceStop::Syscall(stop) => {
                assert_eq!(stop.tid(), 10);
                assert_eq!(stop.args()[0], 9);
            }
            other => panic!("entry dropped: {other:?}"),
        }
        match second.stop {
            TraceStop::Syscall(stop) => assert_eq!(stop.number(), Some(2)),
            other => panic!("second entry dropped: {other:?}"),
        }
        match first_exit.stop {
            TraceStop::Syscall(stop) => {
                assert_eq!(stop.tid(), 10);
                assert_eq!(stop.number(), Some(1));
            }
            other => panic!("exit dropped: {other:?}"),
        }
        assert_eq!(
            lineage.record(20).unwrap().syscall_phase(),
            SyscallPhase::ExpectingExit
        );
    }

    #[test]
    fn signal_after_attach_is_reinjected() {
        let mut lineage = rooted();
        let applied = apply_stop(&mut lineage, 10, RawStop::Stopped { signal: 15 }).unwrap();
        assert_eq!(applied.action, ResumeAction::Syscall { signal: 15 });
        assert!(matches!(
            applied.stop,
            TraceStop::Signal {
                tid: 10,
                signal: 15
            }
        ));
    }

    #[test]
    fn zero_event_message_is_a_gap_and_not_a_child() {
        let mut lineage = rooted();
        let applied = apply_stop(
            &mut lineage,
            10,
            RawStop::Event {
                event: PtraceEventKind::Clone,
                message: 0,
            },
        )
        .unwrap();
        assert!(matches!(applied.stop, TraceStop::Gap(_)));
        assert!(lineage.record(0).is_none());
        assert_eq!(applied.action, ResumeAction::Syscall { signal: 0 });
    }
}
