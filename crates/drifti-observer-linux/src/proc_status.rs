// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded `/proc/<tid>/status` parsing for thread-group ids.
//!
//! Only the `Tgid` line is read. The file prefix is capped so a large
//! status blob cannot be pulled in full.

/// Maximum bytes taken from `/proc/<tid>/status`.
pub const MAX_PROC_STATUS: usize = 8192;

/// Returns the prefix of `bytes` that a status read is allowed to parse.
#[must_use]
pub fn bounded_prefix(bytes: &[u8], max: usize) -> &[u8] {
    let end = bytes.len().min(max);
    &bytes[..end]
}

/// Parses `Tgid` from a `/proc/<tid>/status` blob.
///
/// Returns `None` when the line is missing or not a `u32`. Other lines are
/// ignored. This does not read `environ` or command arguments.
#[must_use]
pub fn parse_tgid(text: &str) -> Option<u32> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{bounded_prefix, parse_tgid, MAX_PROC_STATUS};

    #[test]
    fn tgid_is_read_from_the_status_prefix() {
        let text = "Name:\tfixture\nTgid:\t42\nPid:\t43\n";
        assert_eq!(parse_tgid(text), Some(42));
    }

    #[test]
    fn missing_tgid_is_not_invented() {
        assert_eq!(parse_tgid("Name:\tfixture\nPid:\t7\n"), None);
        assert_eq!(parse_tgid("Tgid:\tnope\n"), None);
    }

    #[test]
    fn status_prefix_is_capped() {
        let bytes = vec![b'a'; MAX_PROC_STATUS + 50];
        let prefix = bounded_prefix(&bytes, MAX_PROC_STATUS);
        assert_eq!(prefix.len(), MAX_PROC_STATUS);
        assert!(prefix.len() < bytes.len());
    }
}
