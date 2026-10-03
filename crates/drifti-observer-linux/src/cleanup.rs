// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decisions for killing a tracee that is still in ptrace-stop.
//!
//! The stop that a visitor rejects has already been collected by `wait`.
//! The tracee stays stopped until the tracer resumes it, so one
//! non-blocking `wait` after `SIGKILL` does not reap it. A failed
//! `pidfd_send_signal` is not a successful kill.

use std::time::Duration;

use crate::wait_status::DecodedWait;

/// How long session cleanup waits for a signaled tracee to die.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const REAP_BUDGET: Duration = Duration::from_secs(2);

/// What a non-blocking reap of one signaled tracee should do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReapStep {
    /// `wait` reported death.
    Reaped,
    /// No death is queued. The tracee can still be in a ptrace-stop whose
    /// status was already consumed. Resume it. Do not treat this as success.
    Resume,
}

/// Classifies one `waitpid` poll while reaping a signaled tracee.
///
/// `None` is `WNOHANG` returning 0. That is not a reap: the stop was already
/// collected, and the tracee stays stopped until the tracer resumes it.
#[must_use]
pub(crate) const fn reap_step(polled: Option<DecodedWait>) -> ReapStep {
    match polled {
        Some(DecodedWait::Exited { .. } | DecodedWait::Signaled { .. }) => ReapStep::Reaped,
        Some(
            DecodedWait::Syscall
            | DecodedWait::Event { .. }
            | DecodedWait::Stopped { .. }
            | DecodedWait::Continued,
        )
        | None => ReapStep::Resume,
    }
}

/// Result of attempting `pidfd_send_signal` before any `kill` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidfdSignal {
    /// The pidfd accepted `SIGKILL`.
    Sent,
    /// The pidfd target is already gone.
    AlreadyGone,
    /// The pidfd call failed for another reason.
    Failed,
    /// This tid has no pidfd.
    Unavailable,
}

/// A failed or missing pidfd signal still needs `kill`.
///
/// `Sent` and `AlreadyGone` do not. Ignoring a failed pidfd call and
/// skipping `kill` leaves the tracee running.
#[must_use]
pub(crate) const fn needs_kill_fallback(signal: PidfdSignal) -> bool {
    match signal {
        PidfdSignal::Failed | PidfdSignal::Unavailable => true,
        PidfdSignal::Sent | PidfdSignal::AlreadyGone => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{needs_kill_fallback, reap_step, PidfdSignal, ReapStep};
    use crate::wait_status::DecodedWait;

    #[test]
    fn consumed_ptrace_stop_is_not_a_reap() {
        assert_eq!(reap_step(None), ReapStep::Resume);
        assert_eq!(
            reap_step(Some(DecodedWait::Stopped { signal: 19 })),
            ReapStep::Resume
        );
        assert_eq!(reap_step(Some(DecodedWait::Syscall)), ReapStep::Resume);
        assert_eq!(
            reap_step(Some(DecodedWait::Signaled { signal: 9 })),
            ReapStep::Reaped
        );
        assert_eq!(
            reap_step(Some(DecodedWait::Exited { code: 0 })),
            ReapStep::Reaped
        );
    }

    #[test]
    fn failed_pidfd_signal_falls_back_to_kill() {
        assert!(needs_kill_fallback(PidfdSignal::Failed));
        assert!(needs_kill_fallback(PidfdSignal::Unavailable));
        assert!(!needs_kill_fallback(PidfdSignal::Sent));
        assert!(!needs_kill_fallback(PidfdSignal::AlreadyGone));
    }
}
