// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lifecycle failures and visible observation gaps.
//!
//! Display text uses reason codes, tids, and errnos. It does not include
//! command arguments or remote memory.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use drifti_observer::{ObservationFailureReason, ObserverError, SinkError};

use crate::syscall::ObservedSyscall;

/// A stop or fact the tracer could not treat as ordinary progress.
///
/// Recording a gap is the opposite of dropping it. Callers surface the gap
/// to the visitor and keep it on the lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationGap {
    /// Kernel entry/exit order disagreed with this thread's slot.
    SyscallPhaseMismatch {
        /// Thread that stopped.
        tid: u32,
        /// Phase the slot expected.
        expected: ObservedSyscall,
        /// Phase the kernel reported.
        observed: ObservedSyscall,
    },
    /// A stop arrived for a thread before its spawn event.
    UnaffiliatedTracee {
        /// Thread id from `wait`.
        tid: u32,
    },
    /// A second spawn named a different parent. The first parent is kept.
    ParentConflict {
        /// Child thread.
        tid: u32,
        /// Parent already recorded.
        existing: u32,
        /// Parent on the new event.
        observed: u32,
    },
    /// `PTRACE_GETEVENTMSG` was not a usable id.
    InvalidEventMessage {
        /// Thread that reported the event.
        tid: u32,
    },
    /// Ptrace event number this lifecycle does not interpret.
    UnknownPtraceEvent {
        /// Thread that stopped.
        tid: u32,
        /// Raw event number.
        event: u32,
    },
    /// `wait` reported the task as continued.
    Continued {
        /// Thread id.
        tid: u32,
    },
    /// A seccomp stop arrived. Seccomp tracing is not enabled by this layer.
    SeccompStop {
        /// Thread that stopped.
        tid: u32,
    },
    /// `/proc/<tid>/status` did not yield a Tgid.
    ProcStatusUnreadable {
        /// Thread id.
        tid: u32,
    },
    /// `/proc` reported a different Tgid than the one already recorded.
    TgidConflict {
        /// Thread id.
        tid: u32,
        /// Tgid already recorded.
        existing: u32,
        /// Tgid read from `/proc`.
        observed: u32,
    },
    /// `exec` happened on a thread whose thread-group id is unknown.
    ExecWithUnknownTgid {
        /// Thread that exec'd.
        tid: u32,
    },
    /// A sibling thread was retired because its thread group exec'd.
    ExecRetiredThread {
        /// Retired thread.
        tid: u32,
    },
    /// `pidfd_open` failed. Exit cleanup falls back to the pid number.
    PidfdUnavailable {
        /// Thread id.
        tid: u32,
    },
    /// `wait` returned a pid that is not part of this execution.
    UntrackedWait {
        /// Pid from `wait`.
        tid: u32,
    },
}

impl Display for ObservationGap {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyscallPhaseMismatch {
                tid,
                expected,
                observed,
            } => write!(
                formatter,
                "syscall phase mismatch on tid {tid}: expected {expected}, observed {observed}"
            ),
            Self::UnaffiliatedTracee { tid } => {
                write!(
                    formatter,
                    "tracee tid {tid} attached before its spawn event"
                )
            }
            Self::ParentConflict {
                tid,
                existing,
                observed,
            } => write!(
                formatter,
                "tid {tid} parent conflict: kept {existing}, ignored {observed}"
            ),
            Self::InvalidEventMessage { tid } => {
                write!(formatter, "invalid ptrace event message on tid {tid}")
            }
            Self::UnknownPtraceEvent { tid, event } => {
                write!(formatter, "unknown ptrace event {event} on tid {tid}")
            }
            Self::Continued { tid } => write!(formatter, "continued stop on tid {tid}"),
            Self::SeccompStop { tid } => write!(formatter, "seccomp stop on tid {tid}"),
            Self::ProcStatusUnreadable { tid } => {
                write!(formatter, "tgid unavailable for tid {tid}")
            }
            Self::TgidConflict {
                tid,
                existing,
                observed,
            } => write!(
                formatter,
                "tid {tid} tgid conflict: kept {existing}, ignored {observed}"
            ),
            Self::ExecWithUnknownTgid { tid } => {
                write!(formatter, "exec on tid {tid} with unknown tgid")
            }
            Self::ExecRetiredThread { tid } => {
                write!(formatter, "tid {tid} retired after thread-group exec")
            }
            Self::PidfdUnavailable { tid } => {
                write!(formatter, "pidfd unavailable for tid {tid}")
            }
            Self::UntrackedWait { tid } => {
                write!(formatter, "wait status for untracked tid {tid}")
            }
        }
    }
}

/// Failure of the ptrace lifecycle.
///
/// `Ok` is not implied. A gap that cannot be stored is an error that still
/// carries the gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    /// `fork` or another launch syscall failed.
    Launch {
        /// `errno` from the failing call.
        errno: i32,
    },
    /// The child exited before `SIGSTOP` attach.
    TraceeExitedBeforeAttach {
        /// Exit code from `wait`.
        code: i32,
    },
    /// The first stop was not the expected attach stop.
    UnexpectedFirstStop,
    /// `wait` failed or timed out.
    Wait {
        /// `errno`, or `0` when the deadline expired.
        errno: i32,
    },
    /// A ptrace request failed.
    Ptrace {
        /// `errno` from `ptrace`.
        errno: i32,
    },
    /// `PTRACE_GET_SYSCALL_INFO` failed.
    SyscallInfo {
        /// `errno` from `ptrace`.
        errno: i32,
    },
    /// The kernel wrote fewer bytes than `ptrace_syscall_info`.
    SyscallInfoTruncated {
        /// Bytes reported by the kernel.
        wrote: i64,
    },
    /// The syscall stop had no entry/exit op, so the per-thread slot cannot advance.
    SyscallOpUnavailable {
        /// Thread that stopped.
        tid: u32,
    },
    /// The gap list is full. `gap` was not discarded.
    GapCapacity {
        /// Gap that could not be stored.
        gap: ObservationGap,
    },
    /// The tracee table is full.
    TraceeCapacity {
        /// Thread that was not inserted.
        tid: u32,
    },
    /// The same tid was inserted twice.
    DuplicateTracee {
        /// Thread id.
        tid: u32,
    },
    /// The tid is not in this execution.
    UnknownTracee {
        /// Thread id.
        tid: u32,
    },
    /// A tid of `0` or a pid that does not fit the platform pid type.
    InvalidTid,
    /// Another stop would pass the configured limit. `stop` was not discarded.
    StopLimit {
        /// Stop that was not delivered.
        stop: Box<TraceStop>,
    },
    /// The visitor rejected the stop.
    Visitor,
    /// The sink rejected a semantic event.
    Sink(SinkError),
    /// The lifecycle ended while a tracee was still live.
    LiveTraceesRemain,
}

impl TraceError {
    /// Maps a lifecycle failure onto the platform-neutral observer error.
    ///
    /// Launch failures stay launch failures. Every other variant is an
    /// interrupted trace. A sink rejection stays a sink rejection. None of
    /// these are `COMPLETE` coverage.
    #[must_use]
    pub fn into_observer_error(self) -> ObserverError {
        match self {
            Self::Sink(error) => ObserverError::Sink(error),
            Self::Launch { .. }
            | Self::TraceeExitedBeforeAttach { .. }
            | Self::UnexpectedFirstStop => ObserverError::ObservationFailed {
                reason: ObservationFailureReason::Launch,
            },
            Self::Wait { .. }
            | Self::Ptrace { .. }
            | Self::SyscallInfo { .. }
            | Self::SyscallInfoTruncated { .. }
            | Self::SyscallOpUnavailable { .. }
            | Self::GapCapacity { .. }
            | Self::TraceeCapacity { .. }
            | Self::DuplicateTracee { .. }
            | Self::UnknownTracee { .. }
            | Self::InvalidTid
            | Self::StopLimit { .. }
            | Self::Visitor
            | Self::LiveTraceesRemain => ObserverError::ObservationFailed {
                reason: ObservationFailureReason::TraceInterrupted,
            },
        }
    }
}

impl Display for TraceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launch { errno } => write!(formatter, "tracee launch failed: errno {errno}"),
            Self::TraceeExitedBeforeAttach { code } => {
                write!(formatter, "tracee exited before attach: code {code}")
            }
            Self::UnexpectedFirstStop => formatter.write_str("tracee did not stop for attach"),
            Self::Wait { errno } => write!(formatter, "wait for tracee failed: errno {errno}"),
            Self::Ptrace { errno } => write!(formatter, "ptrace request failed: errno {errno}"),
            Self::SyscallInfo { errno } => {
                write!(formatter, "syscall info request failed: errno {errno}")
            }
            Self::SyscallInfoTruncated { wrote } => {
                write!(formatter, "syscall info truncated after {wrote} bytes")
            }
            Self::SyscallOpUnavailable { tid } => {
                write!(formatter, "syscall op unavailable on tid {tid}")
            }
            Self::GapCapacity { gap } => write!(formatter, "gap capacity exceeded: {gap}"),
            Self::TraceeCapacity { tid } => {
                write!(formatter, "tracee capacity exceeded at tid {tid}")
            }
            Self::DuplicateTracee { tid } => write!(formatter, "duplicate tracee tid {tid}"),
            Self::UnknownTracee { tid } => write!(formatter, "unknown tracee tid {tid}"),
            Self::InvalidTid => formatter.write_str("invalid tracee tid"),
            Self::StopLimit { .. } => formatter.write_str("trace stop limit exceeded"),
            Self::Visitor => formatter.write_str("trace visitor rejected a stop"),
            Self::Sink(error) => write!(formatter, "{error}"),
            Self::LiveTraceesRemain => formatter.write_str("trace ended with live tracees"),
        }
    }
}

impl Error for TraceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sink(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TraceError> for ObserverError {
    fn from(error: TraceError) -> Self {
        error.into_observer_error()
    }
}

/// One delivered lifecycle stop.
///
/// This is not an [`drifti_observer::ObservedEvent`]. Semantic decoding is a
/// later layer. Every variant is handed to [`crate::TraceVisitor`] while the
/// tracee is still stopped, except [`Self::Gap`] for a fact that is not
/// itself a ptrace stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceStop {
    /// Syscall entry or exit.
    Syscall(crate::syscall::SyscallStop),
    /// `fork`, `vfork`, or `clone`.
    Spawn(crate::lineage::SpawnStop),
    /// Ptrace exec event. This is not `process.execute`.
    Exec {
        /// Thread that exec'd.
        tid: u32,
    },
    /// `vfork` completed.
    VforkDone {
        /// Parent thread.
        tid: u32,
    },
    /// Ptrace exit event. The task is still alive until it is reaped.
    ExitEvent {
        /// Thread that is exiting.
        tid: u32,
        /// Raw event message. This is the wait status the kernel reported.
        wait_status: u64,
    },
    /// Signal-delivery stop. The signal is reinjected.
    Signal {
        /// Thread that stopped.
        tid: u32,
        /// Linux signal number.
        signal: i32,
    },
    /// Group-stop.
    GroupStop {
        /// Thread that stopped.
        tid: u32,
    },
    /// Initial attach stop. Options are applied before resume.
    Attach {
        /// Thread that stopped.
        tid: u32,
    },
    /// Task exited with a code.
    ProcessExited {
        /// Thread id.
        tid: u32,
        /// Exit code.
        exit_code: i32,
    },
    /// Task died on a signal.
    ProcessSignaled {
        /// Thread id.
        tid: u32,
        /// Linux signal number.
        signal: i32,
    },
    /// A gap. This was not dropped.
    Gap(ObservationGap),
}

#[cfg(test)]
mod tests {
    use super::{ObservationGap, TraceError};

    #[test]
    fn launch_display_has_no_argument_text() {
        let error = TraceError::Launch { errno: 2 };
        let text = error.to_string();
        assert_eq!(text, "tracee launch failed: errno 2");
        assert!(!text.contains("SUPER_SECRET_ARG"));
    }

    #[test]
    fn gap_capacity_keeps_the_gap() {
        let gap = ObservationGap::UnaffiliatedTracee { tid: 44 };
        let error = TraceError::GapCapacity { gap };
        match error.clone() {
            TraceError::GapCapacity { gap } => {
                assert_eq!(gap, ObservationGap::UnaffiliatedTracee { tid: 44 });
            }
            other => panic!("gap was dropped: {other}"),
        }
        let observer = error.into_observer_error();
        assert!(matches!(
            observer,
            drifti_observer::ObserverError::ObservationFailed {
                reason: drifti_observer::ObservationFailureReason::TraceInterrupted,
            }
        ));
    }
}
