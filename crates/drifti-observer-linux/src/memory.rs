// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded remote memory reads.
//!
//! [`MAX_REMOTE_READ`] is the only accepted length. A longer request is
//! rejected before any kernel call. Short and overlong transfers are errors,
//! so a truncated path or sockaddr is not returned as success.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Largest remote read, in bytes.
///
/// This covers a pathname or a socket address. It is not a memory dump size.
pub const MAX_REMOTE_READ: usize = 4096;

/// Rejected or failed remote read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteReadError {
    /// The requested length was zero.
    Empty,
    /// The requested length is above [`MAX_REMOTE_READ`].
    ExceedsBound {
        /// Requested length.
        requested: usize,
        /// Accepted maximum.
        max: usize,
    },
    /// The kernel copied fewer bytes than requested.
    Short {
        /// Bytes copied.
        read: usize,
        /// Bytes requested.
        requested: usize,
    },
    /// The kernel reported more bytes than the buffer allows.
    Overlong {
        /// Bytes the kernel claimed.
        returned: usize,
        /// Bytes requested.
        requested: usize,
    },
    /// The address does not fit in a local pointer.
    AddressUnaddressable,
    /// The kernel rejected the read.
    Os {
        /// `errno`.
        errno: i32,
    },
}

impl Display for RemoteReadError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("remote read length is empty"),
            Self::ExceedsBound { requested, max } => {
                write!(formatter, "remote read of {requested} bytes exceeds {max}")
            }
            Self::Short { read, requested } => {
                write!(
                    formatter,
                    "remote read returned {read} of {requested} bytes"
                )
            }
            Self::Overlong {
                returned,
                requested,
            } => write!(
                formatter,
                "remote read claimed {returned} bytes for a {requested} byte buffer"
            ),
            Self::AddressUnaddressable => {
                formatter.write_str("remote address does not fit a local pointer")
            }
            Self::Os { errno } => write!(formatter, "remote read failed: errno {errno}"),
        }
    }
}

impl Error for RemoteReadError {}

/// Rejects a length that is empty or above [`MAX_REMOTE_READ`].
pub const fn check_remote_read_len(requested: usize) -> Result<usize, RemoteReadError> {
    if requested == 0 {
        return Err(RemoteReadError::Empty);
    }
    if requested > MAX_REMOTE_READ {
        return Err(RemoteReadError::ExceedsBound {
            requested,
            max: MAX_REMOTE_READ,
        });
    }
    Ok(requested)
}

/// Interprets a `process_vm_readv` result.
///
/// The length is checked first. An oversize request stays
/// [`RemoteReadError::ExceedsBound`] even when `returned` is large.
pub fn accept_remote_transfer(
    requested: usize,
    returned: isize,
    errno: i32,
) -> Result<usize, RemoteReadError> {
    let requested = check_remote_read_len(requested)?;
    if returned < 0 {
        return Err(RemoteReadError::Os { errno });
    }
    let returned = returned as usize;
    if returned > requested {
        return Err(RemoteReadError::Overlong {
            returned,
            requested,
        });
    }
    if returned < requested {
        return Err(RemoteReadError::Short {
            read: returned,
            requested,
        });
    }
    Ok(returned)
}

/// Reads `len` bytes from `address` in thread group `pid`.
///
/// `pid` is a thread-group id. `len` must be in `1..=MAX_REMOTE_READ`.
/// The returned buffer's length is exactly `len`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn read_remote_memory(pid: u32, address: u64, len: usize) -> Result<Vec<u8>, RemoteReadError> {
    let len = check_remote_read_len(len)?;
    let remote = usize::try_from(address).map_err(|_| RemoteReadError::AddressUnaddressable)?;
    let pid = i32::try_from(pid).map_err(|_| RemoteReadError::Os { errno: 0 })?;
    let mut buffer = vec![0_u8; len];
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote_iov = libc::iovec {
        iov_base: remote as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: `buffer` is a writable allocation of `len` bytes and `len` is
    // in `1..=MAX_REMOTE_READ`. Both iovecs describe that many bytes. The
    // kernel copies at most `iov_len` bytes into `buffer` and does not retain
    // the pointer. `pid` is a thread-group id, not an unbounded address range.
    let returned = unsafe { libc::process_vm_readv(pid, &local, 1, &remote_iov, 1, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let accepted = accept_remote_transfer(len, returned, errno)?;
    buffer.truncate(accepted);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::{accept_remote_transfer, check_remote_read_len, RemoteReadError, MAX_REMOTE_READ};

    #[test]
    fn oversize_read_is_rejected_before_a_transfer_is_accepted() {
        let error = check_remote_read_len(MAX_REMOTE_READ + 1).unwrap_err();
        assert_eq!(
            error,
            RemoteReadError::ExceedsBound {
                requested: MAX_REMOTE_READ + 1,
                max: MAX_REMOTE_READ,
            }
        );
        let error = accept_remote_transfer(MAX_REMOTE_READ + 1, 10, 0).unwrap_err();
        assert!(matches!(error, RemoteReadError::ExceedsBound { .. }));
    }

    #[test]
    fn empty_short_and_overlong_reads_are_not_success() {
        assert_eq!(check_remote_read_len(0), Err(RemoteReadError::Empty));
        assert_eq!(
            accept_remote_transfer(8, 3, 0),
            Err(RemoteReadError::Short {
                read: 3,
                requested: 8,
            })
        );
        assert_eq!(
            accept_remote_transfer(8, 9, 0),
            Err(RemoteReadError::Overlong {
                returned: 9,
                requested: 8,
            })
        );
        assert_eq!(
            accept_remote_transfer(4, -1, 14),
            Err(RemoteReadError::Os { errno: 14 })
        );
        assert_eq!(accept_remote_transfer(4, 4, 0), Ok(4));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remote_read_of_this_process_returns_the_requested_bytes_only() {
        let data = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        let got = super::read_remote_memory(std::process::id(), data.as_ptr() as u64, data.len())
            .unwrap();
        assert_eq!(got, data);
        assert_eq!(got.len(), data.len());
        let error = super::read_remote_memory(
            std::process::id(),
            data.as_ptr() as u64,
            MAX_REMOTE_READ + 1,
        )
        .unwrap_err();
        assert!(matches!(error, RemoteReadError::ExceedsBound { .. }));
    }
}
