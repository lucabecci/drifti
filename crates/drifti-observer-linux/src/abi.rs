// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux ABI numbers used by the lifecycle.
//!
//! These match the Linux UAPI. They are not the host libc constants, so the
//! state machine can be tested on another OS. A Linux test compares them
//! with `libc`.

/// `SIGTRAP`.
pub const SIGTRAP: i32 = 5;

/// `SIGKILL`. Used by the Linux session; kept on other targets so the ABI
/// table stays complete.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const SIGKILL: i32 = 9;

/// `SIGSTOP`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const SIGSTOP: i32 = 19;

/// `PTRACE_O_TRACESYSGOOD`.
pub const PTRACE_O_TRACESYSGOOD: u32 = 0x0000_0001;

/// `PTRACE_O_TRACEFORK`.
pub const PTRACE_O_TRACEFORK: u32 = 0x0000_0002;

/// `PTRACE_O_TRACEVFORK`.
pub const PTRACE_O_TRACEVFORK: u32 = 0x0000_0004;

/// `PTRACE_O_TRACECLONE`.
pub const PTRACE_O_TRACECLONE: u32 = 0x0000_0008;

/// `PTRACE_O_TRACEEXEC`.
pub const PTRACE_O_TRACEEXEC: u32 = 0x0000_0010;

/// `PTRACE_O_TRACEVFORKDONE`.
pub const PTRACE_O_TRACEVFORKDONE: u32 = 0x0000_0020;

/// `PTRACE_O_TRACEEXIT`.
pub const PTRACE_O_TRACEEXIT: u32 = 0x0000_0040;

/// `PTRACE_O_EXITKILL`.
pub const PTRACE_O_EXITKILL: u32 = 0x0010_0000;

/// `PTRACE_EVENT_FORK`.
pub const PTRACE_EVENT_FORK: u32 = 1;

/// `PTRACE_EVENT_VFORK`.
pub const PTRACE_EVENT_VFORK: u32 = 2;

/// `PTRACE_EVENT_CLONE`.
pub const PTRACE_EVENT_CLONE: u32 = 3;

/// `PTRACE_EVENT_EXEC`.
pub const PTRACE_EVENT_EXEC: u32 = 4;

/// `PTRACE_EVENT_VFORK_DONE`.
pub const PTRACE_EVENT_VFORK_DONE: u32 = 5;

/// `PTRACE_EVENT_EXIT`.
pub const PTRACE_EVENT_EXIT: u32 = 6;

/// `PTRACE_EVENT_SECCOMP`.
pub const PTRACE_EVENT_SECCOMP: u32 = 7;

/// `PTRACE_EVENT_STOP`.
pub const PTRACE_EVENT_STOP: u32 = 128;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::{
        PTRACE_EVENT_CLONE, PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT, PTRACE_EVENT_FORK,
        PTRACE_EVENT_SECCOMP, PTRACE_EVENT_STOP, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE,
        PTRACE_O_EXITKILL, PTRACE_O_TRACECLONE, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT,
        PTRACE_O_TRACEFORK, PTRACE_O_TRACESYSGOOD, PTRACE_O_TRACEVFORK, PTRACE_O_TRACEVFORKDONE,
        SIGKILL, SIGSTOP, SIGTRAP,
    };

    #[test]
    fn abi_numbers_match_linux_libc() {
        assert_eq!(SIGTRAP, libc::SIGTRAP);
        assert_eq!(SIGKILL, libc::SIGKILL);
        assert_eq!(SIGSTOP, libc::SIGSTOP);
        assert_eq!(PTRACE_O_TRACESYSGOOD, libc::PTRACE_O_TRACESYSGOOD as u32);
        assert_eq!(PTRACE_O_TRACEFORK, libc::PTRACE_O_TRACEFORK as u32);
        assert_eq!(PTRACE_O_TRACEVFORK, libc::PTRACE_O_TRACEVFORK as u32);
        assert_eq!(PTRACE_O_TRACECLONE, libc::PTRACE_O_TRACECLONE as u32);
        assert_eq!(PTRACE_O_TRACEEXEC, libc::PTRACE_O_TRACEEXEC as u32);
        assert_eq!(
            PTRACE_O_TRACEVFORKDONE,
            libc::PTRACE_O_TRACEVFORKDONE as u32
        );
        assert_eq!(PTRACE_O_TRACEEXIT, libc::PTRACE_O_TRACEEXIT as u32);
        assert_eq!(PTRACE_O_EXITKILL, libc::PTRACE_O_EXITKILL as u32);
        assert_eq!(PTRACE_EVENT_FORK, libc::PTRACE_EVENT_FORK as u32);
        assert_eq!(PTRACE_EVENT_VFORK, libc::PTRACE_EVENT_VFORK as u32);
        assert_eq!(PTRACE_EVENT_CLONE, libc::PTRACE_EVENT_CLONE as u32);
        assert_eq!(PTRACE_EVENT_EXEC, libc::PTRACE_EVENT_EXEC as u32);
        assert_eq!(
            PTRACE_EVENT_VFORK_DONE,
            libc::PTRACE_EVENT_VFORK_DONE as u32
        );
        assert_eq!(PTRACE_EVENT_EXIT, libc::PTRACE_EVENT_EXIT as u32);
        assert_eq!(PTRACE_EVENT_SECCOMP, libc::PTRACE_EVENT_SECCOMP as u32);
        assert_eq!(PTRACE_EVENT_STOP, libc::PTRACE_EVENT_STOP as u32);
    }
}
