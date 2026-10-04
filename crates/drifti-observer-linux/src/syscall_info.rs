// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! How many bytes `PTRACE_GET_SYSCALL_INFO` must return.
//!
//! The kernel returns the number of bytes it wrote. That count is
//! `offsetofend` of the last field of the active member. It does not include
//! the tail padding of a `repr(C)` member.
//!
//! The common prefix of `ptrace_syscall_info` is 24 bytes: `op`, three
//! padding bytes, `arch`, `instruction_pointer`, and `stack_pointer`. The
//! exit member is `{ rval: i64, is_error: u8 }`. `repr(C)` rounds that member
//! up to 16 bytes because `i64` is aligned to 8, so prefix plus `sizeof` is
//! 40. The kernel stops at `is_error` and returns 33 on the 64-bit UAPI
//! layout (24 + 8 + 1). Those 33 bytes include `rval` and `is_error`. A
//! shorter write does not: 32 ends at the byte before `is_error`, and reading
//! the flag there would observe the zeroed buffer instead of the kernel.

/// `wrote` covers `need` bytes. A non-positive count does not.
#[must_use]
pub(crate) const fn syscall_info_covers(wrote: i64, need: usize) -> bool {
    wrote >= need as i64
}

/// Bytes required to read `exit.rval` and `exit.is_error`.
///
/// This is the kernel's exit return value, not `sizeof` of the padded member.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) const fn exit_syscall_info_need() -> usize {
    let prefix = std::mem::offset_of!(libc::ptrace_syscall_info, u);
    let is_error = std::mem::offset_of!(libc::__c_anonymous_ptrace_syscall_info_exit, is_error);
    prefix + is_error + std::mem::size_of::<u8>()
}

/// 64-bit UAPI: `offsetofend(exit.is_error)` is 33, not the padded 40.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
const _: () = assert!(exit_syscall_info_need() == 33);

#[cfg(test)]
mod tests {
    use super::syscall_info_covers;

    /// `offsetofend(struct ptrace_syscall_info, exit.is_error)` on 64-bit.
    const EXIT_SYSCALL_INFO_BYTES: usize = 33;
    /// Prefix plus the padded `repr(C)` exit member (`24 + 16`).
    const EXIT_SYSCALL_INFO_PADDED_BYTES: usize = 40;
    /// Bytes up to, but not including, `is_error`.
    const EXIT_SYSCALL_INFO_BEFORE_IS_ERROR: usize = 32;

    #[test]
    fn exit_info_accepts_kernel_size_and_rejects_a_short_prefix() {
        let kernel = EXIT_SYSCALL_INFO_BYTES as i64;
        let padded = EXIT_SYSCALL_INFO_PADDED_BYTES;
        let before_is_error = EXIT_SYSCALL_INFO_BEFORE_IS_ERROR as i64;

        assert!(kernel < padded as i64);
        assert!(
            !syscall_info_covers(kernel, padded),
            "the old padded threshold rejects the kernel's 33-byte exit"
        );
        assert!(syscall_info_covers(kernel, EXIT_SYSCALL_INFO_BYTES));
        assert!(syscall_info_covers(padded as i64, EXIT_SYSCALL_INFO_BYTES));
        assert!(!syscall_info_covers(
            before_is_error,
            EXIT_SYSCALL_INFO_BYTES
        ));
        assert!(!syscall_info_covers(1, EXIT_SYSCALL_INFO_BYTES));
        assert!(!syscall_info_covers(0, EXIT_SYSCALL_INFO_BYTES));
    }

    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[test]
    fn linux_exit_need_matches_the_unpadded_kernel_size() {
        use super::exit_syscall_info_need;

        let need = exit_syscall_info_need();
        let prefix = std::mem::offset_of!(libc::ptrace_syscall_info, u);
        let padded = prefix + std::mem::size_of::<libc::__c_anonymous_ptrace_syscall_info_exit>();
        assert_eq!(need, EXIT_SYSCALL_INFO_BYTES);
        assert_eq!(need, 33);
        assert_eq!(padded, EXIT_SYSCALL_INFO_PADDED_BYTES);
        assert!(padded > need);
        assert!(syscall_info_covers(need as i64, need));
        assert!(!syscall_info_covers((need as i64) - 1, need));
    }
}
