// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution-scoped decoding of successful and failed executable replacement.
//!
//! `PTRACE_EVENT_EXEC` is the success signal. An exec syscall entry alone is
//! only an attempt; a failing syscall exit emits `Outcome::Failure`. The
//! executable name on success comes from `/proc/<tid>/exe` while stopped.

use std::collections::BTreeMap;
use std::fs;

use drifti_observer::{ObservedResource, Operation, Outcome};

use crate::emitter::EventEmitter;
use crate::error::{TraceError, TraceStop};
use crate::lineage::ThreadLineage;
use crate::memory::read_remote_memory;
use crate::syscall::ObservedSyscall;

/// Decodes process events for exactly one execution.
pub(crate) struct ProcessDecoder {
    pending: BTreeMap<u32, String>,
}

impl ProcessDecoder {
    pub(crate) fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
        }
    }

    fn emit(
        &mut self,
        tid: u32,
        lineage: &ThreadLineage,
        identity: String,
        outcome: Outcome,
        emitter: &mut EventEmitter<'_>,
    ) -> Result<(), TraceError> {
        let resource = ObservedResource::executable(identity).map_err(|_| TraceError::Visitor)?;
        emitter.emit(lineage, tid, Operation::ProcessExecute, resource, outcome)
    }

    pub(crate) fn on_stop(
        &mut self,
        stop: &TraceStop,
        lineage: &ThreadLineage,
        emitter: &mut EventEmitter<'_>,
    ) -> Result<(), TraceError> {
        match stop {
            TraceStop::Syscall(syscall)
                if syscall.observed() == ObservedSyscall::Entry
                    && syscall.number().is_some_and(is_exec_syscall) =>
            {
                let is_execveat = syscall.number() == Some(libc::SYS_execveat as u64);
                let path_arg = if is_execveat {
                    syscall.args()[1]
                } else {
                    syscall.args()[0]
                };
                let pid = lineage
                    .record(syscall.tid())
                    .and_then(|record| record.tgid())
                    .ok_or(TraceError::Visitor)?;
                let mut path = read_exec_path(pid, path_arg)?;
                if is_execveat && path.is_empty() {
                    let dirfd = syscall.args()[0] as i32;
                    let target = fs::read_link(format!("/proc/{pid}/fd/{dirfd}"))
                        .map_err(|_| TraceError::Visitor)?;
                    path = target
                        .into_os_string()
                        .into_string()
                        .map_err(|_| TraceError::Visitor)?;
                }
                self.pending.insert(syscall.tid(), path);
            }
            TraceStop::Syscall(syscall)
                if syscall.observed() == ObservedSyscall::Exit
                    && syscall.number().is_some_and(is_exec_syscall) =>
            {
                // A successful exec is reported by PTRACE_EVENT_EXEC, not by
                // this syscall exit. Only a failed exit is an attempted event.
                let pending = self.pending.remove(&syscall.tid());
                if syscall.is_error() {
                    let path = pending.ok_or(TraceError::Visitor)?;
                    let errno = syscall
                        .return_value()
                        .and_then(|value| i32::try_from(-value).ok());
                    self.emit(
                        syscall.tid(),
                        lineage,
                        path,
                        Outcome::failure(errno, None),
                        emitter,
                    )?;
                }
            }
            TraceStop::Exec { tid } => {
                // The old image and its pending path may differ from the
                // resolved executable. Use the kernel's executable link.
                self.pending.remove(tid);
                let path =
                    fs::read_link(format!("/proc/{tid}/exe")).map_err(|_| TraceError::Visitor)?;
                let identity = path
                    .into_os_string()
                    .into_string()
                    .map_err(|_| TraceError::Visitor)?;
                self.emit(*tid, lineage, identity, Outcome::success(), emitter)?;
            }
            TraceStop::ProcessExited { tid, .. } | TraceStop::ProcessSignaled { tid, .. } => {
                self.pending.remove(tid);
            }
            _ => {}
        }
        Ok(())
    }
}

fn is_exec_syscall(number: u64) -> bool {
    number == libc::SYS_execve as u64 || number == libc::SYS_execveat as u64
}

/// Read only the path argument, one byte at a time. This avoids crossing an
/// unmapped page after the NUL terminator and caps the remote read at 4096.
fn read_exec_path(pid: u32, address: u64) -> Result<String, TraceError> {
    let mut bytes = Vec::with_capacity(256);
    for offset in 0..4096_u64 {
        let pointer = address.checked_add(offset).ok_or(TraceError::Visitor)?;
        let next = read_remote_memory(pid, pointer, 1).map_err(|_| TraceError::Visitor)?[0];
        if next == 0 {
            return String::from_utf8(bytes).map_err(|_| TraceError::Visitor);
        }
        bytes.push(next);
    }
    Err(TraceError::Visitor)
}
