// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution-scoped pid/tid lineage.
//!
//! A lineage belongs to one [`ExecutionId`]. Inserting a tid into one
//! execution does not make it visible to another. The table is bounded.

use std::collections::BTreeMap;

use drifti_observer::ExecutionId;

use crate::error::{ObservationGap, TraceError};
use crate::syscall::{
    ObservedSyscall, ParsedSyscall, SyscallOrderError, SyscallPhase, SyscallSlot, SyscallStop,
};

/// How a descendant was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnKind {
    /// `fork`.
    Fork,
    /// `vfork`.
    Vfork,
    /// `clone`, including threads.
    Clone,
}

/// A spawn stop. This is not yet a semantic event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnStop {
    /// Spawning thread.
    pub parent: u32,
    /// New thread or process.
    pub child: u32,
    /// Kernel event that created `child`.
    pub kind: SpawnKind,
}

/// One thread inside an execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRecord {
    tid: u32,
    tgid: Option<u32>,
    parent_tid: Option<u32>,
    spawn: Option<SpawnKind>,
    live: bool,
    options_applied: bool,
    syscall: SyscallSlot,
    entries: u64,
    exits: u64,
    closed_inside_syscall: bool,
}

impl ThreadRecord {
    fn leader(tid: u32) -> Self {
        Self {
            tid,
            tgid: Some(tid),
            parent_tid: None,
            spawn: None,
            live: true,
            options_applied: false,
            syscall: SyscallSlot::new(),
            entries: 0,
            exits: 0,
            closed_inside_syscall: false,
        }
    }

    fn descendant(tid: u32, parent: Option<u32>, spawn: Option<SpawnKind>) -> Self {
        Self {
            tid,
            tgid: None,
            parent_tid: parent,
            spawn,
            live: true,
            options_applied: false,
            syscall: SyscallSlot::new(),
            entries: 0,
            exits: 0,
            closed_inside_syscall: false,
        }
    }

    /// Thread id.
    #[must_use]
    pub const fn tid(&self) -> u32 {
        self.tid
    }

    /// Thread-group id, when known.
    #[must_use]
    pub const fn tgid(&self) -> Option<u32> {
        self.tgid
    }

    /// Spawning thread, when known.
    #[must_use]
    pub const fn parent_tid(&self) -> Option<u32> {
        self.parent_tid
    }

    /// Spawn kind, when this thread was not the root.
    #[must_use]
    pub const fn spawn(&self) -> Option<SpawnKind> {
        self.spawn
    }

    /// Whether the tracer still expects stops from this thread.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.live
    }

    /// Whether `PTRACE_SETOPTIONS` was applied.
    #[must_use]
    pub const fn options_applied(&self) -> bool {
        self.options_applied
    }

    /// Current syscall phase.
    #[must_use]
    pub const fn syscall_phase(&self) -> SyscallPhase {
        self.syscall.phase()
    }

    /// Accepted syscall entries, including entries accepted after a gap.
    #[must_use]
    pub const fn syscall_entries(&self) -> u64 {
        self.entries
    }

    /// Accepted syscall exits.
    #[must_use]
    pub const fn syscall_exits(&self) -> u64 {
        self.exits
    }

    /// The thread was reaped while a syscall entry had no exit stop.
    #[must_use]
    pub const fn closed_inside_syscall(&self) -> bool {
        self.closed_inside_syscall
    }
}

/// Result of applying one parsed syscall to a thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallDelivery {
    /// Entry or exit. `gap` is also stored on the lineage when present.
    Observed {
        /// Captured stop.
        stop: SyscallStop,
        /// Phase mismatch recorded before the stop was forced.
        gap: Option<ObservationGap>,
    },
    /// The stop is only a gap. The syscall slot was not advanced.
    Gap(ObservationGap),
}

/// Threads observed for one execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLineage {
    execution_id: ExecutionId,
    max_tracees: usize,
    max_gaps: usize,
    root: Option<u32>,
    root_exit: Option<i32>,
    root_signal: Option<i32>,
    threads: BTreeMap<u32, ThreadRecord>,
    gaps: Vec<ObservationGap>,
}

impl ThreadLineage {
    /// Empty lineage for `execution_id`.
    ///
    /// `max_tracees` and `max_gaps` bound the tables. Zero is a valid limit
    /// and rejects the first insert or gap.
    #[must_use]
    pub fn new(execution_id: ExecutionId, max_tracees: usize, max_gaps: usize) -> Self {
        Self {
            execution_id,
            max_tracees,
            max_gaps,
            root: None,
            root_exit: None,
            root_signal: None,
            threads: BTreeMap::new(),
            gaps: Vec::new(),
        }
    }

    /// Execution this map belongs to.
    #[must_use]
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Root tid, once attached.
    #[must_use]
    pub const fn root(&self) -> Option<u32> {
        self.root
    }

    /// Root exit code, if the root has exited.
    #[must_use]
    pub const fn root_exit(&self) -> Option<i32> {
        self.root_exit
    }

    /// Root fatal signal, if the root died by signal.
    #[must_use]
    pub const fn root_signal(&self) -> Option<i32> {
        self.root_signal
    }

    /// Recorded gaps, in the order they were accepted.
    #[must_use]
    pub fn gaps(&self) -> &[ObservationGap] {
        &self.gaps
    }

    /// Thread record, if this execution has seen `tid`.
    #[must_use]
    pub fn record(&self, tid: u32) -> Option<&ThreadRecord> {
        self.threads.get(&tid)
    }

    /// Every thread, in tid order.
    pub fn threads(&self) -> impl Iterator<Item = &ThreadRecord> {
        self.threads.values()
    }

    /// Live thread ids, in tid order.
    pub fn live_tids(&self) -> impl Iterator<Item = u32> + '_ {
        self.threads
            .iter()
            .filter(|(_, record)| record.live)
            .map(|(tid, _)| *tid)
    }

    /// How many threads are still live.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.threads.values().filter(|record| record.live).count()
    }

    /// Inserts the launched root. Its tgid is its own tid.
    pub fn attach_root(&mut self, tid: u32) -> Result<(), TraceError> {
        self.reserve(tid)?;
        if self.root.is_some() {
            return Err(TraceError::DuplicateTracee { tid });
        }
        self.root = Some(tid);
        self.threads.insert(tid, ThreadRecord::leader(tid));
        Ok(())
    }

    /// Records a descendant. An existing record keeps a conflicting parent.
    pub fn ensure_descendant(
        &mut self,
        parent: u32,
        child: u32,
        kind: SpawnKind,
    ) -> Result<bool, TraceError> {
        if child == 0 || parent == 0 {
            return Err(TraceError::InvalidTid);
        }
        if !self.threads.contains_key(&parent) {
            return Err(TraceError::UnknownTracee { tid: parent });
        }
        if let Some(existing) = self
            .threads
            .get(&child)
            .and_then(|record| record.parent_tid)
        {
            if existing != parent {
                self.push_gap(ObservationGap::ParentConflict {
                    tid: child,
                    existing,
                    observed: parent,
                })?;
            }
            return Ok(false);
        }
        if self.threads.contains_key(&child) {
            let record = self
                .threads
                .get_mut(&child)
                .ok_or(TraceError::UnknownTracee { tid: child })?;
            record.parent_tid = Some(parent);
            record.spawn = Some(kind);
            return Ok(false);
        }
        self.reserve(child)?;
        self.threads.insert(
            child,
            ThreadRecord::descendant(child, Some(parent), Some(kind)),
        );
        Ok(true)
    }

    /// Records a thread that stopped before its spawn event.
    pub fn ensure_unaffiliated(&mut self, tid: u32) -> Result<bool, TraceError> {
        if tid == 0 {
            return Err(TraceError::InvalidTid);
        }
        if self.threads.contains_key(&tid) {
            return Ok(false);
        }
        self.reserve(tid)?;
        self.push_gap(ObservationGap::UnaffiliatedTracee { tid })?;
        self.threads
            .insert(tid, ThreadRecord::descendant(tid, None, None));
        Ok(true)
    }

    /// Stores a gap or returns it in [`TraceError::GapCapacity`].
    pub fn push_gap(&mut self, gap: ObservationGap) -> Result<(), TraceError> {
        if self.gaps.len() >= self.max_gaps {
            return Err(TraceError::GapCapacity { gap });
        }
        self.gaps.push(gap);
        Ok(())
    }

    /// Sets the thread-group id. A conflicting value is kept and reported.
    pub fn set_tgid(&mut self, tid: u32, tgid: u32) -> Result<(), TraceError> {
        let current = self
            .threads
            .get(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?
            .tgid;
        match current {
            Some(existing) if existing != tgid => self.push_gap(ObservationGap::TgidConflict {
                tid,
                existing,
                observed: tgid,
            }),
            Some(_) => Ok(()),
            None => {
                let record = self
                    .threads
                    .get_mut(&tid)
                    .ok_or(TraceError::UnknownTracee { tid })?;
                record.tgid = Some(tgid);
                Ok(())
            }
        }
    }

    /// Marks lifecycle options as applied. Repeating the call is success.
    pub fn mark_options_applied(&mut self, tid: u32) -> Result<(), TraceError> {
        let record = self
            .threads
            .get_mut(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?;
        record.options_applied = true;
        Ok(())
    }

    /// Whether lifecycle options were applied to `tid`.
    pub fn options_applied(&self, tid: u32) -> Result<bool, TraceError> {
        self.threads
            .get(&tid)
            .map(|record| record.options_applied)
            .ok_or(TraceError::UnknownTracee { tid })
    }

    /// Applies one syscall observation to `tid`.
    pub fn observe_syscall(
        &mut self,
        tid: u32,
        parsed: ParsedSyscall,
    ) -> Result<SyscallDelivery, TraceError> {
        self.ensure_unaffiliated(tid)?;
        match parsed {
            ParsedSyscall::Unavailable => Err(TraceError::SyscallOpUnavailable { tid }),
            ParsedSyscall::Seccomp => {
                let gap = ObservationGap::SeccompStop { tid };
                self.push_gap(gap)?;
                Ok(SyscallDelivery::Gap(gap))
            }
            ParsedSyscall::Entry { number, args } => self.observe_entry(tid, number, args),
            ParsedSyscall::Exit {
                return_value,
                is_error,
            } => self.observe_exit(tid, return_value, is_error),
        }
    }

    /// Marks `tid` reaped and closes its syscall slot.
    pub fn mark_reaped(&mut self, tid: u32) -> Result<(), TraceError> {
        let record = self
            .threads
            .get_mut(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?;
        if record.syscall.close_on_reap() {
            record.closed_inside_syscall = true;
        }
        record.live = false;
        Ok(())
    }

    /// Records the root's exit code. A child exit does not change it.
    pub fn note_root_exit(&mut self, tid: u32, code: i32) {
        if self.root == Some(tid) && self.root_exit.is_none() && self.root_signal.is_none() {
            self.root_exit = Some(code);
        }
    }

    /// Records the root's fatal signal. A child signal does not change it.
    pub fn note_root_signal(&mut self, tid: u32, signal: i32) {
        if self.root == Some(tid) && self.root_exit.is_none() && self.root_signal.is_none() {
            self.root_signal = Some(signal);
        }
    }

    /// Retires other live threads in the same thread group after exec.
    pub fn retire_siblings_on_exec(&mut self, tid: u32) -> Result<(), TraceError> {
        let tgid = match self.threads.get(&tid).and_then(|record| record.tgid) {
            Some(tgid) => tgid,
            None => {
                self.push_gap(ObservationGap::ExecWithUnknownTgid { tid })?;
                return Ok(());
            }
        };
        let siblings: Vec<u32> = self
            .threads
            .iter()
            .filter(|(id, record)| **id != tid && record.tgid == Some(tgid) && record.live)
            .map(|(id, _)| *id)
            .collect();
        for sibling in siblings {
            self.push_gap(ObservationGap::ExecRetiredThread { tid: sibling })?;
            self.mark_reaped(sibling)?;
        }
        Ok(())
    }

    fn observe_entry(
        &mut self,
        tid: u32,
        number: u64,
        args: [u64; 6],
    ) -> Result<SyscallDelivery, TraceError> {
        let phase = self
            .threads
            .get(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?
            .syscall
            .phase();
        let gap = if phase == SyscallPhase::ExpectingEntry {
            None
        } else {
            Some(ObservationGap::SyscallPhaseMismatch {
                tid,
                expected: ObservedSyscall::Exit,
                observed: ObservedSyscall::Entry,
            })
        };
        if let Some(gap) = gap {
            self.push_gap(gap)?;
            let record = self
                .threads
                .get_mut(&tid)
                .ok_or(TraceError::UnknownTracee { tid })?;
            record.syscall.force_entry(number);
            record.entries = record.entries.saturating_add(1);
            return Ok(SyscallDelivery::Observed {
                stop: SyscallStop::entry(tid, number, args),
                gap: Some(gap),
            });
        }
        let record = self
            .threads
            .get_mut(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?;
        record
            .syscall
            .observe_entry(number)
            .map_err(|_| TraceError::SyscallOpUnavailable { tid })?;
        record.entries = record.entries.saturating_add(1);
        Ok(SyscallDelivery::Observed {
            stop: SyscallStop::entry(tid, number, args),
            gap: None,
        })
    }

    fn observe_exit(
        &mut self,
        tid: u32,
        return_value: i64,
        is_error: bool,
    ) -> Result<SyscallDelivery, TraceError> {
        let phase = self
            .threads
            .get(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?
            .syscall
            .phase();
        if phase != SyscallPhase::ExpectingExit {
            let gap = ObservationGap::SyscallPhaseMismatch {
                tid,
                expected: ObservedSyscall::Entry,
                observed: ObservedSyscall::Exit,
            };
            self.push_gap(gap)?;
            let record = self
                .threads
                .get_mut(&tid)
                .ok_or(TraceError::UnknownTracee { tid })?;
            let number = record.syscall.force_exit();
            record.exits = record.exits.saturating_add(1);
            return Ok(SyscallDelivery::Observed {
                stop: SyscallStop::exit(tid, number, return_value, is_error),
                gap: Some(gap),
            });
        }
        let record = self
            .threads
            .get_mut(&tid)
            .ok_or(TraceError::UnknownTracee { tid })?;
        let number = record.syscall.observe_exit().map_err(|error| match error {
            SyscallOrderError::UnexpectedExit | SyscallOrderError::UnexpectedEntry => {
                TraceError::SyscallOpUnavailable { tid }
            }
        })?;
        record.exits = record.exits.saturating_add(1);
        Ok(SyscallDelivery::Observed {
            stop: SyscallStop::exit(tid, Some(number), return_value, is_error),
            gap: None,
        })
    }

    fn reserve(&self, tid: u32) -> Result<(), TraceError> {
        if tid == 0 {
            return Err(TraceError::InvalidTid);
        }
        if self.threads.contains_key(&tid) {
            return Err(TraceError::DuplicateTracee { tid });
        }
        if self.threads.len() >= self.max_tracees {
            return Err(TraceError::TraceeCapacity { tid });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use drifti_observer::ExecutionId;

    use super::{SpawnKind, SyscallDelivery, ThreadLineage};
    use crate::error::{ObservationGap, TraceError};
    use crate::syscall::{ParsedSyscall, SyscallPhase};

    fn lineage() -> ThreadLineage {
        ThreadLineage::new(ExecutionId::from_raw(1), 8, 8)
    }

    #[test]
    fn lineage_does_not_alias_across_executions() {
        let mut first = ThreadLineage::new(ExecutionId::from_raw(1), 4, 4);
        let second = ThreadLineage::new(ExecutionId::from_raw(2), 4, 4);
        first.attach_root(10).unwrap();
        assert!(second.record(10).is_none());
        assert_ne!(first.execution_id(), second.execution_id());
    }

    #[test]
    fn descendants_keep_parent_links_and_reject_a_conflicting_parent() {
        let mut lineage = lineage();
        lineage.attach_root(10).unwrap();
        assert!(lineage.ensure_descendant(10, 11, SpawnKind::Fork).unwrap());
        assert!(lineage.ensure_descendant(11, 12, SpawnKind::Fork).unwrap());
        assert_eq!(lineage.record(12).unwrap().parent_tid(), Some(11));
        assert_eq!(lineage.record(11).unwrap().parent_tid(), Some(10));
        lineage.ensure_descendant(10, 12, SpawnKind::Clone).unwrap();
        assert_eq!(lineage.record(12).unwrap().parent_tid(), Some(11));
        assert_eq!(
            lineage.gaps(),
            &[ObservationGap::ParentConflict {
                tid: 12,
                existing: 11,
                observed: 10,
            }]
        );
    }

    #[test]
    fn tracee_and_gap_limits_return_the_rejected_fact() {
        let mut lineage = ThreadLineage::new(ExecutionId::from_raw(1), 1, 0);
        lineage.attach_root(10).unwrap();
        let error = lineage
            .ensure_descendant(10, 11, SpawnKind::Fork)
            .unwrap_err();
        assert_eq!(error, TraceError::TraceeCapacity { tid: 11 });
        assert!(lineage.record(11).is_none());
        let error = lineage
            .push_gap(ObservationGap::Continued { tid: 10 })
            .unwrap_err();
        assert_eq!(
            error,
            TraceError::GapCapacity {
                gap: ObservationGap::Continued { tid: 10 },
            }
        );
        assert!(lineage.gaps().is_empty());
    }

    #[test]
    fn syscall_phases_stay_per_thread_and_a_mismatch_is_a_gap() {
        let mut lineage = lineage();
        lineage.attach_root(1).unwrap();
        lineage.ensure_unaffiliated(2).unwrap();
        lineage
            .observe_syscall(
                1,
                ParsedSyscall::Entry {
                    number: 10,
                    args: [1, 0, 0, 0, 0, 0],
                },
            )
            .unwrap();
        lineage
            .observe_syscall(
                2,
                ParsedSyscall::Entry {
                    number: 11,
                    args: [2, 0, 0, 0, 0, 0],
                },
            )
            .unwrap();
        assert_eq!(
            lineage.record(1).unwrap().syscall_phase(),
            SyscallPhase::ExpectingExit
        );
        let delivery = lineage
            .observe_syscall(
                1,
                ParsedSyscall::Entry {
                    number: 99,
                    args: [0; 6],
                },
            )
            .unwrap();
        match delivery {
            SyscallDelivery::Observed { stop, gap } => {
                assert_eq!(stop.number(), Some(99));
                assert_eq!(
                    gap,
                    Some(ObservationGap::SyscallPhaseMismatch {
                        tid: 1,
                        expected: crate::syscall::ObservedSyscall::Exit,
                        observed: crate::syscall::ObservedSyscall::Entry,
                    })
                );
            }
            SyscallDelivery::Gap(gap) => panic!("syscall stop dropped: {gap}"),
        }
        assert_eq!(lineage.record(2).unwrap().syscall_entries(), 1);
        assert_eq!(
            lineage.record(2).unwrap().syscall_phase(),
            SyscallPhase::ExpectingExit
        );
        let exit = lineage
            .observe_syscall(
                2,
                ParsedSyscall::Exit {
                    return_value: 0,
                    is_error: false,
                },
            )
            .unwrap();
        match exit {
            SyscallDelivery::Observed { stop, gap: None } => {
                assert_eq!(stop.number(), Some(11));
                assert_eq!(stop.return_value(), Some(0));
            }
            other => panic!("exit was not delivered: {other:?}"),
        }
    }

    #[test]
    fn unavailable_syscall_op_does_not_advance_the_slot() {
        let mut lineage = lineage();
        lineage.attach_root(5).unwrap();
        let error = lineage
            .observe_syscall(5, ParsedSyscall::Unavailable)
            .unwrap_err();
        assert_eq!(error, TraceError::SyscallOpUnavailable { tid: 5 });
        assert_eq!(
            lineage.record(5).unwrap().syscall_phase(),
            SyscallPhase::ExpectingEntry
        );
        assert_eq!(lineage.record(5).unwrap().syscall_entries(), 0);
    }

    #[test]
    fn seccomp_stop_does_not_advance_the_slot() {
        let mut lineage = lineage();
        lineage.attach_root(5).unwrap();
        let delivery = lineage.observe_syscall(5, ParsedSyscall::Seccomp).unwrap();
        assert_eq!(
            delivery,
            SyscallDelivery::Gap(ObservationGap::SeccompStop { tid: 5 })
        );
        assert_eq!(lineage.gaps(), &[ObservationGap::SeccompStop { tid: 5 }]);
        assert_eq!(
            lineage.record(5).unwrap().syscall_phase(),
            SyscallPhase::ExpectingEntry
        );
    }

    #[test]
    fn root_death_ignores_children_and_does_not_overwrite() {
        let mut lineage = lineage();
        lineage.attach_root(10).unwrap();
        lineage.ensure_descendant(10, 11, SpawnKind::Fork).unwrap();
        lineage.note_root_exit(11, 9);
        assert_eq!(lineage.root_exit(), None);
        lineage.note_root_exit(10, 4);
        lineage.note_root_signal(10, 9);
        assert_eq!(lineage.root_exit(), Some(4));
        assert_eq!(lineage.root_signal(), None);
    }

    #[test]
    fn exec_retires_live_siblings_in_the_same_tgid() {
        let mut lineage = lineage();
        lineage.attach_root(10).unwrap();
        lineage.ensure_descendant(10, 11, SpawnKind::Clone).unwrap();
        lineage.set_tgid(11, 10).unwrap();
        lineage.retire_siblings_on_exec(10).unwrap();
        assert!(!lineage.record(11).unwrap().is_live());
        assert!(lineage.record(10).unwrap().is_live());
        assert!(lineage
            .gaps()
            .contains(&ObservationGap::ExecRetiredThread { tid: 11 }));
    }

    #[test]
    fn conflicting_tgid_is_not_overwritten() {
        let mut lineage = lineage();
        lineage.attach_root(10).unwrap();
        lineage.set_tgid(10, 99).unwrap();
        assert_eq!(lineage.record(10).unwrap().tgid(), Some(10));
        assert_eq!(
            lineage.gaps(),
            &[ObservationGap::TgidConflict {
                tid: 10,
                existing: 10,
                observed: 99,
            }]
        );
    }
}
