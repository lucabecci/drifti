// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe exit semantics (KAN-77).

use drifti_cli::{DefaultApplicationServices, EXIT_USER, run_with_services};

#[test]
#[cfg(not(target_os = "linux"))]
fn observe_requires_linux_before_running_a_child() {
    let code = run_with_services(
        &DefaultApplicationServices,
        ["drifti", "observe", "--", "true"],
    );
    assert_eq!(code, i32::from(EXIT_USER));
}
