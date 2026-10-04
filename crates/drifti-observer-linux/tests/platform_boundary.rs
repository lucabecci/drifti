// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ptrace backend is compiled only on Linux.

#[test]
fn backend_flag_matches_the_target() {
    assert_eq!(
        drifti_observer_linux::PTRACE_BACKEND_COMPILED,
        cfg!(target_os = "linux")
    );
}
