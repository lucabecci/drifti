// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Observer`](drifti_observer::Observer) adapter for the ptrace lifecycle.
//!
//! The adapter decodes process execution and filesystem activity through one
//! [`EventEmitter`](crate::emitter::EventEmitter). Network decoding is a later
//! task, so coverage remains `INCOMPLETE`. A launch or trace failure is
//! [`ObserverError::ObservationFailed`](drifti_observer::ObserverError::ObservationFailed),
//! not a successful result.

use drifti_observer::{
    CapabilityDomain, CommandSpec, EventSink, ExecutionCoverage, ExecutionId, ExecutionResult,
    ObservationCoverage, ObservationFailureReason, Observer, ObserverCapabilities, ObserverError,
};

use crate::emitter::EventEmitter;
use crate::error::{ObservationGap, TraceError, TraceStop};
use crate::filesystem::{FilesystemDecodeError, FilesystemDecoder};
use crate::lifecycle::TraceVisitor;
use crate::lineage::ThreadLineage;
use crate::process::ProcessDecoder;
use crate::session::{SessionLimits, TraceSession};

/// Linux ptrace observer.
///
/// One value is one execution id. The launch input is a [`CommandSpec`].
/// Arbitrary PID attach is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxObserver {
    execution_id: ExecutionId,
}

impl LinuxObserver {
    /// Observes one execution under `execution_id`.
    #[must_use]
    pub const fn new(execution_id: ExecutionId) -> Self {
        Self { execution_id }
    }

    /// Execution id used for the lineage.
    #[must_use]
    pub const fn execution_id(self) -> ExecutionId {
        self.execution_id
    }
}

impl Observer for LinuxObserver {
    fn capabilities(&self) -> ObserverCapabilities {
        let mut domains = vec![CapabilityDomain::Process];
        if cfg!(target_arch = "x86_64") {
            domains.push(CapabilityDomain::Filesystem);
        }
        ObserverCapabilities::new(domains)
    }

    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>) {
        let mut decoder = ExecutionVisitor {
            process: ProcessDecoder::new(),
            filesystem: FilesystemDecoder::new(SessionLimits::production().max_tracees),
            emitter: EventEmitter::new(&sink, self.execution_id),
            filesystem_unsupported: !cfg!(target_arch = "x86_64"),
        };
        let result = TraceSession::launch(self.execution_id, command)
            .and_then(|session| session.drive(&mut decoder));
        let filesystem_unsupported = decoder.filesystem_unsupported;
        let mapped = match result {
            Ok(report) => Ok(ExecutionResult::new(
                report.execution_id(),
                execution_coverage(filesystem_unsupported),
                report.exit_code(),
            )),
            Err(error) => Err(map_error(error)),
        };
        (sink, mapped)
    }
}

fn execution_coverage(filesystem_unsupported: bool) -> ExecutionCoverage {
    if filesystem_unsupported {
        ExecutionCoverage::declared(
            ObservationCoverage::Incomplete,
            [CapabilityDomain::Filesystem],
        )
        .expect("incomplete coverage may name an unsupported domain")
    } else {
        ExecutionCoverage::no_events_seen()
    }
}

struct ExecutionVisitor<'a> {
    process: ProcessDecoder,
    filesystem: FilesystemDecoder,
    emitter: EventEmitter<'a>,
    filesystem_unsupported: bool,
}

impl TraceVisitor for ExecutionVisitor<'_> {
    fn on_stop(&mut self, stop: &TraceStop, lineage: &ThreadLineage) -> Result<(), TraceError> {
        if let TraceStop::Gap(gap) = stop {
            let tid = gap_tid(*gap);
            if self.filesystem.has_pending(tid) {
                return Err(TraceError::FilesystemDecode);
            }
            self.filesystem.on_gap(tid);
        }
        if let TraceStop::ProcessExited { tid, .. } | TraceStop::ProcessSignaled { tid, .. } = stop
        {
            if self.filesystem.has_pending(*tid) {
                return Err(TraceError::FilesystemDecode);
            }
        }
        self.process.on_stop(stop, lineage, &mut self.emitter)?;
        if let TraceStop::Syscall(syscall) = stop {
            match self.filesystem.on_syscall(syscall) {
                Ok(facts) => {
                    for fact in facts {
                        self.emitter.emit(
                            lineage,
                            fact.tid,
                            fact.operation,
                            fact.resource,
                            fact.outcome,
                        )?;
                    }
                }
                Err(FilesystemDecodeError::UnsupportedAbi) => {
                    self.filesystem_unsupported = true;
                }
                Err(_) => return Err(TraceError::FilesystemDecode),
            }
        }
        Ok(())
    }
}

fn gap_tid(gap: ObservationGap) -> u32 {
    match gap {
        ObservationGap::SyscallPhaseMismatch { tid, .. }
        | ObservationGap::UnaffiliatedTracee { tid }
        | ObservationGap::ParentConflict { tid, .. }
        | ObservationGap::InvalidEventMessage { tid }
        | ObservationGap::UnknownPtraceEvent { tid, .. }
        | ObservationGap::Continued { tid }
        | ObservationGap::SeccompStop { tid }
        | ObservationGap::ProcStatusUnreadable { tid }
        | ObservationGap::TgidConflict { tid, .. }
        | ObservationGap::ExecWithUnknownTgid { tid }
        | ObservationGap::ExecRetiredThread { tid }
        | ObservationGap::PidfdUnavailable { tid }
        | ObservationGap::UntrackedWait { tid } => tid,
    }
}

fn map_error(error: crate::error::TraceError) -> ObserverError {
    let mapped = error.into_observer_error();
    debug_assert!(matches!(
        mapped,
        ObserverError::Sink(_)
            | ObserverError::ObservationFailed {
                reason: ObservationFailureReason::Launch
                    | ObservationFailureReason::TraceInterrupted,
            }
    ));
    mapped
}

#[cfg(test)]
mod tests {
    use super::{execution_coverage, LinuxObserver};
    use drifti_observer::{CapabilityDomain, ExecutionId, ObservationCoverage, Observer};

    #[test]
    fn unsupported_filesystem_abi_degrades_coverage() {
        let coverage = execution_coverage(true);
        assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
        assert!(coverage
            .unsupported_domains()
            .contains(&CapabilityDomain::Filesystem));
        assert!(!coverage.is_complete());
    }

    #[test]
    fn supported_filesystem_abi_stays_incomplete() {
        let coverage = execution_coverage(false);
        assert_eq!(coverage.status(), ObservationCoverage::Incomplete);
        assert!(coverage.unsupported_domains().is_empty());
        assert!(!coverage.is_complete());
    }

    #[test]
    fn capabilities_advertise_filesystem_only_on_x86_64() {
        let observer = LinuxObserver::new(ExecutionId::from_raw(1));
        assert!(observer.capabilities().observes(CapabilityDomain::Process));
        assert_eq!(
            observer
                .capabilities()
                .observes(CapabilityDomain::Filesystem),
            cfg!(target_arch = "x86_64")
        );
    }
}
