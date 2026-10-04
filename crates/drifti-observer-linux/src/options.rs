// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ptrace options for the tracee lifecycle.
//!
//! The session applies [`TraceOptions::lifecycle`] to the root and to every
//! descendant. A mask that omits tracer-exit kill, descendant tracing, exec
//! tracing, or marked syscall stops is rejected.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::abi::{
    PTRACE_O_EXITKILL, PTRACE_O_TRACECLONE, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT,
    PTRACE_O_TRACEFORK, PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORK, PTRACE_O_TRACEVFORKDONE,
};

/// Bitmask passed to `PTRACE_SETOPTIONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceOptions {
    bits: u32,
}

impl TraceOptions {
    /// Options required to track exec, descendants, syscall stops, and tracer exit.
    #[must_use]
    pub const fn lifecycle() -> Self {
        Self {
            bits: PTRACE_O_TRACESYSGOOD
                | PTRACE_O_TRACEFORK
                | PTRACE_O_TRACEVFORK
                | PTRACE_O_TRACECLONE
                | PTRACE_O_TRACEEXEC
                | PTRACE_O_TRACEVFORKDONE
                | PTRACE_O_TRACEEXIT
                | PTRACE_O_EXITKILL,
        }
    }

    /// Builds a mask. [`crate::TraceSession`] still rejects a mask that does
    /// not include [`Self::lifecycle`].
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Raw `PTRACE_SETOPTIONS` value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.bits
    }

    /// `PTRACE_O_EXITKILL` is set.
    #[must_use]
    pub const fn kills_on_tracer_exit(self) -> bool {
        self.bits & PTRACE_O_EXITKILL != 0
    }

    /// Fork, vfork, and clone are all traced.
    #[must_use]
    pub const fn traces_descendants(self) -> bool {
        let required = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
        self.bits & required == required
    }

    /// Exec is traced.
    #[must_use]
    pub const fn traces_exec(self) -> bool {
        self.bits & PTRACE_O_TRACEEXEC != 0
    }

    /// Syscall stops are marked with the `0x80` bit.
    #[must_use]
    pub const fn marks_syscall_stops(self) -> bool {
        self.bits & PTRACE_O_TRACESYSGOOD != 0
    }

    /// Accepts `options` only when every lifecycle bit is present.
    pub const fn require_lifecycle(self) -> Result<Self, OptionsError> {
        let required = Self::lifecycle().bits;
        if self.bits & required != required {
            return Err(OptionsError::LifecycleOptionsMissing);
        }
        Ok(self)
    }
}

/// The option mask cannot host a trace session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionsError {
    /// At least one lifecycle bit is missing.
    LifecycleOptionsMissing,
}

impl Display for OptionsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::LifecycleOptionsMissing => {
                formatter.write_str("ptrace lifecycle options are incomplete")
            }
        }
    }
}

impl Error for OptionsError {}

#[cfg(test)]
mod tests {
    use super::TraceOptions;
    use crate::abi::PTRACE_O_EXITKILL;

    #[test]
    fn lifecycle_options_cover_descendants_exec_syscalls_and_exitkill() {
        let options = TraceOptions::lifecycle();
        assert!(options.kills_on_tracer_exit());
        assert!(options.traces_descendants());
        assert!(options.traces_exec());
        assert!(options.marks_syscall_stops());
        assert!(options.require_lifecycle().is_ok());
        assert_ne!(options.bits() & PTRACE_O_EXITKILL, 0);
    }

    #[test]
    fn options_without_exitkill_are_rejected() {
        let weakened =
            TraceOptions::from_bits(TraceOptions::lifecycle().bits() & !PTRACE_O_EXITKILL);
        assert!(!weakened.kills_on_tracer_exit());
        assert!(weakened.require_lifecycle().is_err());
    }

    #[test]
    fn fork_without_clone_is_rejected() {
        let only_fork = TraceOptions::from_bits(crate::abi::PTRACE_O_TRACEFORK | PTRACE_O_EXITKILL);
        assert!(!only_fork.traces_descendants());
        assert!(only_fork.require_lifecycle().is_err());
    }
}
