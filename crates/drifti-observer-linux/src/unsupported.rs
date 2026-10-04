// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Known syscall paths whose effects this observer cannot fully decode.

#[cfg(target_os = "linux")]
use crate::error::{ObservationGap, TraceStop};
#[cfg(target_os = "linux")]
use crate::syscall::ObservedSyscall;

/// Returns a coverage gap for the first io_uring entry in an execution.
///
/// The caller records the returned gap in the lineage and delivers it to the
/// visitor before resuming the tracee. Once recorded, further io_uring stops
/// need no duplicate gap: coverage has already degraded.
#[cfg(target_os = "linux")]
pub(crate) fn io_uring_gap(stop: &TraceStop, already_recorded: bool) -> Option<ObservationGap> {
    if already_recorded {
        return None;
    }
    let TraceStop::Syscall(syscall) = stop else {
        return None;
    };
    if syscall.observed() != ObservedSyscall::Entry {
        return None;
    }
    let number = syscall.number()?;
    let is_io_uring = [
        libc::SYS_io_uring_setup as u64,
        libc::SYS_io_uring_enter as u64,
        libc::SYS_io_uring_register as u64,
    ]
    .contains(&number);
    is_io_uring.then_some(ObservationGap::UnsupportedIoUring {
        tid: syscall.tid(),
        syscall: number,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::io_uring_gap;
    use crate::error::{ObservationGap, TraceStop};
    use crate::syscall::SyscallStop;

    #[test]
    fn io_uring_attempt_is_a_visible_gap_before_resume() {
        let stop = TraceStop::Syscall(SyscallStop::entry(
            17,
            libc::SYS_io_uring_enter as u64,
            [0; 6],
        ));
        assert_eq!(
            io_uring_gap(&stop, false),
            Some(ObservationGap::UnsupportedIoUring {
                tid: 17,
                syscall: libc::SYS_io_uring_enter as u64,
            })
        );
        assert_eq!(io_uring_gap(&stop, true), None);
        assert_eq!(
            io_uring_gap(
                &TraceStop::Syscall(SyscallStop::exit(17, Some(1), 0, false)),
                false
            ),
            None
        );
    }
}
