// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use drifti_cli::run_with_services;
use drifti_cli::{DefaultApplicationServices, StubApplicationServices};
use drifti_cli::{EXIT_NOT_READY, EXIT_USER};

#[test]
fn verify_requires_linux_before_running_a_child() {
    #[cfg(not(target_os = "linux"))]
    {
        let code = run_with_services(
            &DefaultApplicationServices,
            ["drifti", "verify", "--", "true"],
        );
        assert_eq!(code, i32::from(EXIT_USER));
    }
}

#[test]
fn verify_stub_stays_not_ready() {
    let code = run_with_services(&StubApplicationServices, ["drifti", "verify", "--", "true"]);
    assert_eq!(code, i32::from(EXIT_NOT_READY));
}

#[test]
fn verify_without_contract_is_user_error() {
    static WORKSPACE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = WORKSPACE.lock().expect("workspace");
    let dir = tempfile::tempdir().expect("tempdir");
    std::env::set_current_dir(dir.path()).expect("chdir");
    let code = run_with_services(
        &DefaultApplicationServices,
        ["drifti", "verify", "--", "true"],
    );
    assert_eq!(code, i32::from(EXIT_USER));
    let _ = dir.close();
}
