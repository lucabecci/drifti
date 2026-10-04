// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-thread syscall entry/exit slot.
//!
//! The slot never accepts an unexpected phase by itself. A mismatch returns
//! an error and leaves the slot unchanged. The caller records a gap and may
//! then call [`SyscallSlot::force_entry`] or [`SyscallSlot::force_exit`].

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Whether the next syscall stop should be an entry or an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallPhase {
    /// The next syscall stop is an entry.
    ExpectingEntry,
    /// The thread is inside a syscall. The next syscall stop is an exit.
    ExpectingExit,
}

/// What the kernel reported for one syscall stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedSyscall {
    /// Syscall entry.
    Entry,
    /// Syscall exit.
    Exit,
}

impl Display for ObservedSyscall {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry => formatter.write_str("entry"),
            Self::Exit => formatter.write_str("exit"),
        }
    }
}

impl ObservedSyscall {
    /// Phase that expects this observation next.
    #[must_use]
    pub const fn expected_phase(self) -> SyscallPhase {
        match self {
            Self::Entry => SyscallPhase::ExpectingEntry,
            Self::Exit => SyscallPhase::ExpectingExit,
        }
    }
}

/// Syscall number and arguments captured at a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallStop {
    tid: u32,
    observed: ObservedSyscall,
    number: Option<u64>,
    args: [u64; 6],
    return_value: Option<i64>,
    is_error: bool,
}

impl SyscallStop {
    pub(crate) fn entry(tid: u32, number: u64, args: [u64; 6]) -> Self {
        Self {
            tid,
            observed: ObservedSyscall::Entry,
            number: Some(number),
            args,
            return_value: None,
            is_error: false,
        }
    }

    pub(crate) fn exit(tid: u32, number: Option<u64>, return_value: i64, is_error: bool) -> Self {
        Self {
            tid,
            observed: ObservedSyscall::Exit,
            number,
            args: [0; 6],
            return_value: Some(return_value),
            is_error,
        }
    }

    /// Thread that stopped.
    #[must_use]
    pub const fn tid(&self) -> u32 {
        self.tid
    }

    /// Entry or exit.
    #[must_use]
    pub const fn observed(&self) -> ObservedSyscall {
        self.observed
    }

    /// Syscall number when the entry was seen.
    #[must_use]
    pub const fn number(&self) -> Option<u64> {
        self.number
    }

    /// Argument registers. Meaningful on entry. Zeros on exit.
    #[must_use]
    pub const fn args(&self) -> [u64; 6] {
        self.args
    }

    /// Return value. `None` on entry.
    #[must_use]
    pub const fn return_value(&self) -> Option<i64> {
        self.return_value
    }

    /// Kernel `is_error` flag from an exit stop.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.is_error
    }
}

/// Kernel syscall-stop classification before it is applied to a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedSyscall {
    /// Entry, with the syscall number and six argument registers.
    Entry {
        /// Syscall number.
        number: u64,
        /// Argument registers.
        args: [u64; 6],
    },
    /// Exit. The syscall number comes from the matching entry.
    Exit {
        /// Raw return value.
        return_value: i64,
        /// Whether the kernel marked the return as an error.
        is_error: bool,
    },
    /// Seccomp notification. The slot must not advance.
    Seccomp,
    /// The kernel did not name entry or exit.
    Unavailable,
}

/// Rejected syscall transition. The slot is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOrderError {
    /// An entry arrived while the thread was inside a syscall.
    UnexpectedEntry,
    /// An exit arrived while the thread was between syscalls.
    UnexpectedExit,
}

impl Display for SyscallOrderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEntry => formatter.write_str("syscall entry while a syscall is open"),
            Self::UnexpectedExit => formatter.write_str("syscall exit while no syscall is open"),
        }
    }
}

impl Error for SyscallOrderError {}

/// Entry/exit memory for one thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallSlot {
    phase: SyscallPhase,
    entered: Option<u64>,
}

impl SyscallSlot {
    /// A new thread is between syscalls.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: SyscallPhase::ExpectingEntry,
            entered: None,
        }
    }

    /// Next expected phase.
    #[must_use]
    pub const fn phase(&self) -> SyscallPhase {
        self.phase
    }

    /// Syscall number of the open entry, if any.
    #[must_use]
    pub const fn entered(&self) -> Option<u64> {
        self.entered
    }

    /// Records an entry. On error the slot is unchanged.
    pub const fn observe_entry(&mut self, number: u64) -> Result<(), SyscallOrderError> {
        if !matches!(self.phase, SyscallPhase::ExpectingEntry) {
            return Err(SyscallOrderError::UnexpectedEntry);
        }
        self.phase = SyscallPhase::ExpectingExit;
        self.entered = Some(number);
        Ok(())
    }

    /// Records an exit and returns the number from the matching entry.
    ///
    /// On error the slot is unchanged.
    pub const fn observe_exit(&mut self) -> Result<u64, SyscallOrderError> {
        if !matches!(self.phase, SyscallPhase::ExpectingExit) {
            return Err(SyscallOrderError::UnexpectedExit);
        }
        let number = match self.entered {
            Some(number) => number,
            None => return Err(SyscallOrderError::UnexpectedExit),
        };
        self.phase = SyscallPhase::ExpectingEntry;
        self.entered = None;
        Ok(number)
    }

    /// Accepts an entry after the caller has recorded a phase gap.
    pub const fn force_entry(&mut self, number: u64) {
        self.phase = SyscallPhase::ExpectingExit;
        self.entered = Some(number);
    }

    /// Accepts an exit after the caller has recorded a phase gap.
    ///
    /// Returns the open syscall number when one was recorded.
    pub const fn force_exit(&mut self) -> Option<u64> {
        let number = self.entered;
        self.phase = SyscallPhase::ExpectingEntry;
        self.entered = None;
        number
    }

    /// Closes the slot because the thread was reaped.
    ///
    /// Returns `true` when the thread was inside a syscall. That is normal
    /// for `exit_group`, which often has no syscall-exit stop. It is recorded
    /// on the thread; it is not dropped.
    pub const fn close_on_reap(&mut self) -> bool {
        let inside = matches!(self.phase, SyscallPhase::ExpectingExit);
        self.phase = SyscallPhase::ExpectingEntry;
        self.entered = None;
        inside
    }
}

impl Default for SyscallSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ObservedSyscall, SyscallOrderError, SyscallPhase, SyscallSlot};

    #[test]
    fn entry_then_exit_is_deterministic_for_one_thread() {
        let mut slot = SyscallSlot::new();
        slot.observe_entry(39).unwrap();
        assert_eq!(slot.phase(), SyscallPhase::ExpectingExit);
        assert_eq!(slot.observe_exit().unwrap(), 39);
        assert_eq!(slot.phase(), SyscallPhase::ExpectingEntry);
        assert_eq!(slot.entered(), None);
    }

    #[test]
    fn second_entry_does_not_overwrite_an_open_syscall() {
        let mut slot = SyscallSlot::new();
        slot.observe_entry(0).unwrap();
        let error = slot.observe_entry(1).unwrap_err();
        assert_eq!(error, SyscallOrderError::UnexpectedEntry);
        assert_eq!(slot.phase(), SyscallPhase::ExpectingExit);
        assert_eq!(slot.entered(), Some(0));
        slot.force_entry(1);
        assert_eq!(slot.entered(), Some(1));
        assert_eq!(slot.phase(), SyscallPhase::ExpectingExit);
    }

    #[test]
    fn exit_between_syscalls_does_not_invent_an_entry() {
        let mut slot = SyscallSlot::new();
        assert_eq!(
            slot.observe_exit().unwrap_err(),
            SyscallOrderError::UnexpectedExit
        );
        assert_eq!(slot.phase(), SyscallPhase::ExpectingEntry);
        assert_eq!(slot.force_exit(), None);
    }

    #[test]
    fn interleaved_threads_do_not_share_a_phase() {
        let mut first = SyscallSlot::new();
        let mut second = SyscallSlot::new();
        first.observe_entry(10).unwrap();
        second.observe_entry(11).unwrap();
        assert_eq!(first.observe_exit().unwrap(), 10);
        assert_eq!(second.phase(), SyscallPhase::ExpectingExit);
        assert_eq!(second.observe_exit().unwrap(), 11);
        assert_eq!(first.phase(), SyscallPhase::ExpectingEntry);
    }

    #[test]
    fn close_on_reap_records_an_open_syscall() {
        let mut slot = SyscallSlot::new();
        assert!(!slot.close_on_reap());
        slot.observe_entry(231).unwrap();
        assert!(slot.close_on_reap());
        assert_eq!(slot.phase(), SyscallPhase::ExpectingEntry);
        assert_eq!(slot.entered(), None);
    }

    #[test]
    fn observed_syscall_names_are_stable() {
        assert_eq!(ObservedSyscall::Entry.to_string(), "entry");
        assert_eq!(
            ObservedSyscall::Exit.expected_phase(),
            SyscallPhase::ExpectingExit
        );
    }
}
