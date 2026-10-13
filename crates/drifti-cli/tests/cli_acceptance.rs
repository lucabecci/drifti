// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-009 CLI acceptance tests (KAN-81).

use std::sync::{Mutex, MutexGuard};

use drifti_cli::app::{ApplicationServices, CommandContext, MvpApplicationServices};
use drifti_cli::exit::{
    map_command_outcome, CommandExitClass, CommandExitInput, EXIT_INCOMPLETE,
    EXIT_INVALID_CONTRACT, EXIT_SUCCESS, EXIT_VIOLATION,
};
use drifti_cli::output::{ColorPolicy, OutputConfig, OutputFormat};
use drifti_cli::render::render_result;
use drifti_cli::result::{CommandResult, InitResult, ResultStatus};
use drifti_cli::{run_with_services, EXIT_USAGE};

static WORKDIR: Mutex<()> = Mutex::new(());

fn isolated_workdir() -> (tempfile::TempDir, MutexGuard<'static, ()>) {
    let guard = WORKDIR
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (tempfile::tempdir().expect("tempdir"), guard)
}

#[test]
fn init_twice_succeeds() {
    let (dir, _guard) = isolated_workdir();
    std::env::set_current_dir(dir.path()).expect("chdir");
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
}

#[test]
fn doctor_returns_structured_result() {
    let (dir, _guard) = isolated_workdir();
    std::env::set_current_dir(dir.path()).expect("chdir");
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
    let code = run_with_services(&MvpApplicationServices, ["drifti", "doctor"]);
    assert_eq!(code, i32::from(EXIT_SUCCESS));
}

#[test]
fn init_text_and_json_share_status() {
    let (dir, _guard) = isolated_workdir();
    let text_output = OutputConfig::new(OutputFormat::Text, false, false, ColorPolicy::Never);
    let json_output = OutputConfig::new(OutputFormat::Json, false, false, ColorPolicy::Never);
    let ctx = |format| CommandContext {
        cwd: dir.path().to_path_buf(),
        output: format,
    };
    let init = MvpApplicationServices
        .init(&ctx(text_output))
        .expect("init service");
    let text = render_to_string(|stdout| {
        render_result(&init, &ctx(text_output).output, stdout).expect("text render");
    });
    let json = render_to_string(|stdout| {
        render_result(&init, &ctx(json_output).output, stdout).expect("json render");
    });
    assert!(text.contains("status: ok"));
    let parsed: serde_json::Value = serde_json::from_str(json.trim()).expect("json init");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["command"], "init");
}

#[test]
fn no_color_render_skips_ansi() {
    let result = CommandResult::Init(InitResult {
        status: ResultStatus::Ok,
        state_dir: ".drifti".to_owned(),
        contract_present: false,
        store_path: None,
    });
    let output = OutputConfig::new(OutputFormat::Text, false, false, ColorPolicy::Never);
    let rendered = render_to_string(|stdout| {
        render_result(&result, &output, stdout).expect("render");
    });
    assert!(!rendered.contains("\x1b["));
}

#[test]
fn exit_mapper_covers_spec_codes() {
    assert_eq!(
        map_command_outcome(CommandExitInput::success()),
        EXIT_SUCCESS
    );
    assert_eq!(
        map_command_outcome(CommandExitInput {
            class: CommandExitClass::Violation,
            process_exit: Some(0),
        }),
        EXIT_VIOLATION
    );
    assert_eq!(
        map_command_outcome(CommandExitInput {
            class: CommandExitClass::Incomplete,
            process_exit: None,
        }),
        EXIT_INCOMPLETE
    );
    assert_eq!(
        map_command_outcome(CommandExitInput {
            class: CommandExitClass::InvalidContract,
            process_exit: None,
        }),
        EXIT_INVALID_CONTRACT
    );
    assert_eq!(
        map_command_outcome(CommandExitInput::success().with_process(300)),
        255
    );
}

#[test]
fn learn_without_history_is_usage_error() {
    let (dir, _guard) = isolated_workdir();
    std::env::set_current_dir(dir.path()).expect("chdir");
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "learn"]),
        i32::from(EXIT_USAGE)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn observe_smoke_true() {
    let (dir, _guard) = isolated_workdir();
    std::env::set_current_dir(dir.path()).expect("chdir");
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
    let code = run_with_services(
        &MvpApplicationServices,
        ["drifti", "observe", "--", "/bin/true"],
    );
    assert!(code == i32::from(EXIT_SUCCESS) || code == i32::from(EXIT_INCOMPLETE));
}

fn render_to_string(render: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut buffer = Vec::new();
    render(&mut buffer);
    String::from_utf8(buffer).expect("utf8")
}
