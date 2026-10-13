// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic CLI parsing tests (no TTY).

use clap::CommandFactory;
use drifti_cli::app::StubApplicationServices;
use drifti_cli::cli::{Commands, DriftiCli};
use drifti_cli::{run_with_services, EXIT_NOT_READY, EXIT_USER};

#[test]
fn root_help_is_well_formed() {
    DriftiCli::command().debug_assert();
}

#[test]
fn parse_init() {
    let cli = DriftiCli::try_parse_from(["drifti", "init"]).expect("parse init");
    assert!(matches!(cli.command, Commands::Init));
}

#[test]
fn parse_learn_diff_doctor() {
    DriftiCli::try_parse_from(["drifti", "learn"]).expect("parse learn");
    DriftiCli::try_parse_from(["drifti", "diff"]).expect("parse diff");
    DriftiCli::try_parse_from(["drifti", "doctor"]).expect("parse doctor");
}

#[test]
fn parse_generate_with_write_flag() {
    let cli = DriftiCli::try_parse_from(["drifti", "generate", "--write"]).expect("parse generate");
    assert!(matches!(cli.command, Commands::Generate { write: true }));
}

#[test]
fn parse_observe_trailing_command() {
    let cli = DriftiCli::try_parse_from(["drifti", "observe", "--", "echo", "hello"])
        .expect("parse observe");
    assert!(matches!(
        cli.command,
        Commands::Observe { ref command } if command == &["echo", "hello"]
    ));
}

#[test]
fn parse_verify_trailing_command() {
    let cli = DriftiCli::try_parse_from(["drifti", "verify", "--", "cargo", "test"])
        .expect("parse verify");
    assert!(matches!(
        cli.command,
        Commands::Verify { ref command } if command == &["cargo", "test"]
    ));
}

#[test]
fn parse_verify_allows_hyphen_values() {
    let cli = DriftiCli::try_parse_from(["drifti", "verify", "--", "cargo", "test", "--", "lib"])
        .expect("parse verify with nested separator");
    assert!(matches!(
        cli.command,
        Commands::Verify { ref command } if command == &["cargo", "test", "--", "lib"]
    ));
}

#[test]
fn invalid_format_is_rejected_by_clap() {
    let error =
        DriftiCli::try_parse_from(["drifti", "--format", "xml", "init"]).expect_err("xml format");
    assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn observe_without_separator_fails_before_stub() {
    let code = run_with_services(
        &StubApplicationServices,
        ["drifti", "observe", "echo", "hello"],
    );
    assert_eq!(code, i32::from(EXIT_USER));
}

#[test]
fn observe_without_command_fails_before_stub() {
    let code = run_with_services(&StubApplicationServices, ["drifti", "observe"]);
    assert_eq!(code, i32::from(EXIT_USER));
}

#[test]
fn observe_empty_after_separator_fails_before_stub() {
    let code = run_with_services(&StubApplicationServices, ["drifti", "observe", "--"]);
    assert_eq!(code, i32::from(EXIT_USER));
}

#[test]
fn verify_without_separator_fails_before_stub() {
    let code = run_with_services(
        &StubApplicationServices,
        ["drifti", "verify", "cargo", "test"],
    );
    assert_eq!(code, i32::from(EXIT_USER));
}

#[test]
fn init_stub_returns_not_implemented_exit() {
    let code = run_with_services(&StubApplicationServices, ["drifti", "init"]);
    assert_eq!(code, i32::from(EXIT_NOT_READY));
}

#[test]
fn subcommand_help_smoke() {
    let root = DriftiCli::command();
    for sub in root.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        sub.clone().debug_assert();
    }
}
