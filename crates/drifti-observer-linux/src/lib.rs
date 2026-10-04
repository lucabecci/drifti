// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux ptrace backend for Drifti.
//!
//! This crate launches a command as a tracee. Arbitrary PID attach is not
//! representable: the only launch input is [`drifti_observer::CommandSpec`].
//! The lifecycle traces exec, fork, vfork, and clone, keeps per-thread
//! syscall entry/exit state, and sets `PTRACE_O_EXITKILL` so a tracer that
//! dies does not leave tracees running where the kernel supports that option.
//!
//! Process execution is decoded into semantic events. Filesystem and network
//! decoding follow in separate tasks. Decoders consume [`TraceStop`] values
//! from [`TraceVisitor`] while the tracee is stopped. Coverage remains
//! `INCOMPLETE`. Remote reads go through [`read_remote_memory`] and are capped
//! by [`MAX_REMOTE_READ`].
//!
//! The ptrace session is compiled only for Linux. On any other target this
//! crate still builds the lifecycle state machine and rejects oversize
//! remote reads, and [`PTRACE_BACKEND_COMPILED`] is `false`.

#![deny(unsafe_code)]

mod abi;
mod cleanup;
#[cfg(target_os = "linux")]
mod emitter;
mod error;
mod lifecycle;
mod lineage;
mod memory;
mod options;
mod proc_status;
#[cfg(target_os = "linux")]
mod process;
mod report;
mod syscall;
mod syscall_info;
mod wait_status;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod session;

#[cfg(target_os = "linux")]
mod backend;

pub use error::{ObservationGap, TraceError, TraceStop};
pub use lifecycle::{
    apply_stop, AcknowledgeStops, AppliedStop, PtraceEventKind, RawStop, ResumeAction, TraceVisitor,
};
pub use lineage::{SpawnKind, SpawnStop, SyscallDelivery, ThreadLineage, ThreadRecord};
pub use memory::{accept_remote_transfer, check_remote_read_len, RemoteReadError, MAX_REMOTE_READ};
pub use options::{OptionsError, TraceOptions};
pub use proc_status::{bounded_prefix, parse_tgid, MAX_PROC_STATUS};
pub use report::TraceReport;
pub use syscall::{
    ObservedSyscall, ParsedSyscall, SyscallOrderError, SyscallPhase, SyscallSlot, SyscallStop,
};
pub use wait_status::{decode_wait_status, DecodedWait};

#[cfg(target_os = "linux")]
pub use backend::LinuxObserver;
#[cfg(target_os = "linux")]
pub use memory::read_remote_memory;
#[cfg(target_os = "linux")]
pub use session::{SessionLimits, TraceSession};

/// `true` when the ptrace session is part of this build.
pub const PTRACE_BACKEND_COMPILED: bool = cfg!(target_os = "linux");

#[cfg(test)]
mod tests {
    use super::PTRACE_BACKEND_COMPILED;

    #[test]
    fn ptrace_backend_is_compiled_only_on_linux() {
        assert_eq!(PTRACE_BACKEND_COMPILED, cfg!(target_os = "linux"));
    }
}
