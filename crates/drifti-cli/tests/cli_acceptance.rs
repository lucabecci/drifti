// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-009 CLI acceptance tests (KAN-81).

use std::fs;
use std::sync::{Mutex, MutexGuard};

use drifti_cli::app::{ApplicationServices, CommandContext, MvpApplicationServices};
use drifti_cli::exit::{
    map_command_outcome, CommandExitClass, CommandExitInput, EXIT_INCOMPLETE,
    EXIT_INVALID_CONTRACT, EXIT_SUCCESS, EXIT_VIOLATION,
};
use drifti_cli::output::{ColorPolicy, OutputConfig, OutputFormat};
use drifti_cli::render::render_result;
use std::num::NonZeroUsize;

use drifti_cli::result::{
    CommandResult, InitResult, ResultStatus, VerifyEvaluationView, VerifyResult,
};
use drifti_cli::{run_with_services, EXIT_USAGE};
use drifti_core::capability::Capability;
use drifti_core::resource::{FileResource, FilesystemAnchor};
use drifti_observer::{
    EvidenceMeta, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation, Outcome,
    ParentIdentity, ProcessIdentity,
};
use drifti_store::{CommandMetadata, CoverageStatus, EventBatchWriter, FinishExecution, Store};

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
fn verify_invalid_contract_exits_123() {
    let (dir, _guard) = isolated_workdir();
    std::env::set_current_dir(dir.path()).expect("chdir");
    assert_eq!(
        run_with_services(&MvpApplicationServices, ["drifti", "init"]),
        i32::from(EXIT_SUCCESS)
    );
    fs::write(
        dir.path().join("drifti.yaml"),
        "version: not-a-valid-contract\n",
    )
    .expect("write contract");
    let code = run_with_services(
        &MvpApplicationServices,
        ["drifti", "verify", "--", "/bin/true"],
    );
    assert_eq!(code, i32::from(EXIT_INVALID_CONTRACT));
}

#[test]
fn verify_text_and_json_share_status() {
    let capability = Capability::filesystem_read(
        FileResource::new(FilesystemAnchor::Repo, "src/main.rs").expect("file"),
    );
    let result = CommandResult::Verify(VerifyResult {
        status: ResultStatus::Incomplete,
        coverage: "incomplete".to_owned(),
        child_exit: Some(0),
        evaluations: vec![VerifyEvaluationView {
            decision: "INDETERMINATE".to_owned(),
            capability: Some(capability),
        }],
    });
    let text_output = OutputConfig::new(OutputFormat::Text, false, false, ColorPolicy::Never);
    let json_output = OutputConfig::new(OutputFormat::Json, false, false, ColorPolicy::Never);
    let text = render_to_string(|stdout| {
        render_result(&result, &text_output, stdout).expect("text render");
    });
    let json = render_to_string(|stdout| {
        render_result(&result, &json_output, stdout).expect("json render");
    });
    assert!(text.contains("status: incomplete"));
    assert!(text.contains("coverage: incomplete"));
    assert_eq!(text.matches("INDETERMINATE").count(), 1);
    let parsed: serde_json::Value = serde_json::from_str(json.trim()).expect("json verify");
    assert_eq!(parsed["command"], "verify");
    assert_eq!(parsed["status"], "incomplete");
    assert_eq!(parsed["coverage"], "incomplete");
    assert_eq!(parsed["evaluations"].as_array().map(|a| a.len()), Some(1));
}

#[test]
fn verify_structured_statuses_map_to_spec_exits() {
    let violation = CommandResult::Verify(VerifyResult {
        status: ResultStatus::Violation,
        coverage: "complete".to_owned(),
        child_exit: Some(0),
        evaluations: Vec::new(),
    });
    assert_eq!(
        map_command_outcome(CommandExitInput {
            class: violation.exit_class(),
            process_exit: Some(0),
        }),
        EXIT_VIOLATION
    );
    let incomplete = CommandResult::Verify(VerifyResult {
        status: ResultStatus::Incomplete,
        coverage: "incomplete".to_owned(),
        child_exit: Some(0),
        evaluations: Vec::new(),
    });
    assert_eq!(
        map_command_outcome(CommandExitInput {
            class: incomplete.exit_class(),
            process_exit: Some(0),
        }),
        EXIT_INCOMPLETE
    );
}

#[test]
fn quiet_hides_successful_init_output() {
    let result = CommandResult::Init(InitResult {
        status: ResultStatus::Ok,
        state_dir: ".drifti".to_owned(),
        contract_present: false,
        store_path: None,
    });
    let quiet = OutputConfig::new(OutputFormat::Text, true, false, ColorPolicy::Never);
    let rendered = render_to_string(|stdout| {
        render_result(&result, &quiet, stdout).expect("render");
    });
    assert!(rendered.is_empty());
}

#[test]
fn learn_render_profile_not_accepted_contract() {
    let (dir, _guard) = isolated_workdir();
    let mut store = Store::open(dir.path()).expect("store");
    seed_finished_read(&mut store, "src/main.rs");
    let text_output = OutputConfig::new(OutputFormat::Text, false, false, ColorPolicy::Never);
    let json_output = OutputConfig::new(OutputFormat::Json, false, false, ColorPolicy::Never);
    let ctx = |format| CommandContext {
        cwd: dir.path().to_path_buf(),
        output: format,
    };
    let learn = MvpApplicationServices
        .learn(&ctx(text_output))
        .expect("learn");
    let text = render_to_string(|stdout| {
        render_result(&learn, &ctx(text_output).output, stdout).expect("text");
    });
    assert!(text.contains("Capability Profile"));
    assert!(!text.to_lowercase().contains("accepted contract"));
    let json = render_to_string(|stdout| {
        render_result(&learn, &ctx(json_output).output, stdout).expect("json");
    });
    let parsed: serde_json::Value = serde_json::from_str(json.trim()).expect("json learn");
    assert_eq!(parsed["command"], "learn");
    assert_eq!(parsed["status"], "ok");
}

fn seed_finished_read(store: &mut Store, path: &str) {
    let metadata = CommandMetadata::try_new("echo", 0).expect("metadata");
    let record = store.create_execution(Some(metadata)).expect("execution");
    let id = record.id().clone();
    let event = ObservedEvent::new(
        drifti_observer::ExecutionId::from_raw(id.to_raw()),
        0,
        MonotonicTimestamp::from_nanos(1),
        ProcessIdentity::new(Some(10), Some(11)),
        Some(ParentIdentity::new(1)),
        Operation::FilesystemRead,
        ObservedResource::file(path).expect("path"),
        Outcome::success(),
        EvidenceMeta::with_byte_length(1),
    );
    let writer = EventBatchWriter::new(NonZeroUsize::new(1).expect("limit"));
    writer
        .write_batch(store, &id, vec![event])
        .expect("write events");
    let finish = FinishExecution::try_new(
        CoverageStatus::Complete,
        std::iter::empty(),
        Some(0),
        None,
        Some("test"),
    )
    .expect("finish");
    store.finish_execution(&id, finish).expect("finish");
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
