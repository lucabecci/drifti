// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux `wait` status decoder.
//!
//! The bit layout is the Linux ABI (`0x7f` stopped marker, event number in
//! bits 16..23, `SIGTRAP|0x80` for a syscall stop). It does not call `libc`,
//! so the decoder is tested without a tracee.

use crate::abi::SIGTRAP;

/// Classification of one Linux wait status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedWait {
    /// Syscall stop (`PTRACE_O_TRACESYSGOOD`).
    Syscall,
    /// Ptrace event. The number is the raw event field.
    Event {
        /// Event number from bits 16..23.
        event: u32,
    },
    /// Signal-delivery stop.
    Stopped {
        /// Linux signal number.
        signal: i32,
    },
    /// Normal exit.
    Exited {
        /// Exit code.
        code: i32,
    },
    /// Death by signal.
    Signaled {
        /// Linux signal number.
        signal: i32,
    },
    /// `WIFCONTINUED`.
    Continued,
}

/// Decodes a Linux wait status word.
#[must_use]
pub const fn decode_wait_status(status: i32) -> DecodedWait {
    let bits = status as u32;
    if bits == 0xffff {
        return DecodedWait::Continued;
    }
    if bits & 0xff == 0x7f {
        let signal = ((bits >> 8) & 0xff) as i32;
        let event = (bits >> 16) & 0xff;
        if event != 0 {
            return DecodedWait::Event { event };
        }
        if signal == (SIGTRAP | 0x80) {
            return DecodedWait::Syscall;
        }
        return DecodedWait::Stopped { signal };
    }
    if bits & 0x7f == 0 {
        return DecodedWait::Exited {
            code: ((bits >> 8) & 0xff) as i32,
        };
    }
    DecodedWait::Signaled {
        signal: (bits & 0x7f) as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_wait_status;
    use crate::abi::{PTRACE_EVENT_FORK, SIGSTOP, SIGTRAP};
    use crate::wait_status::DecodedWait;

    #[test]
    fn sigstop_attach_stop_is_not_a_syscall() {
        let status = (SIGSTOP << 8) | 0x7f;
        assert_eq!(
            decode_wait_status(status),
            DecodedWait::Stopped { signal: SIGSTOP }
        );
    }

    #[test]
    fn tracesysgood_stop_is_a_syscall() {
        let status = ((SIGTRAP | 0x80) << 8) | 0x7f;
        assert_eq!(decode_wait_status(status), DecodedWait::Syscall);
    }

    #[test]
    fn fork_event_is_not_dropped_as_sigtrap() {
        let status = ((PTRACE_EVENT_FORK << 16) | ((SIGTRAP as u32) << 8) | 0x7f) as i32;
        assert_eq!(
            decode_wait_status(status),
            DecodedWait::Event {
                event: PTRACE_EVENT_FORK
            }
        );
    }

    #[test]
    fn exit_and_signal_death_stay_distinct() {
        assert_eq!(decode_wait_status(7 << 8), DecodedWait::Exited { code: 7 });
        assert_eq!(decode_wait_status(9), DecodedWait::Signaled { signal: 9 });
        assert_eq!(decode_wait_status(0xffff), DecodedWait::Continued);
    }
}
