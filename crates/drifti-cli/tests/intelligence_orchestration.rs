// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::num::NonZeroUsize;

use drifti_cli::dispatch::map_app_error;
use drifti_cli::exit::{EXIT_COMMAND, EXIT_USER};
use drifti_cli::{run_with_services, DefaultApplicationServices, StubApplicationServices};
use drifti_observer::{
    EvidenceMeta, MonotonicTimestamp, ObservedEvent, ObservedResource, Operation, Outcome,
    ParentIdentity, ProcessIdentity,
};
use drifti_store::{CommandMetadata, CoverageStatus, EventBatchWriter, FinishExecution, Store};
use tempfile::TempDir;

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
fn learn_without_store_fails_actionably() {
    let dir = TempDir::new().expect("tempdir");
    std::env::set_current_dir(dir.path()).expect("chdir");
    let code = run_with_services(&DefaultApplicationServices, ["drifti", "learn"]);
    assert_eq!(code, i32::from(EXIT_USER));
}

#[test]
fn learn_json_artifact_is_not_contract() {
    let dir = TempDir::new().expect("tempdir");
    let mut store = Store::open(dir.path()).expect("store");
    seed_finished_read(&mut store, "src/main.rs");
    std::env::set_current_dir(dir.path()).expect("chdir");
    let code = run_with_services(
        &DefaultApplicationServices,
        ["drifti", "--format", "json", "learn"],
    );
    assert_eq!(code, 0);
}

#[test]
fn generate_write_does_not_use_stub() {
    let dir = TempDir::new().expect("tempdir");
    let mut store = Store::open(dir.path()).expect("store");
    seed_finished_read(&mut store, "src/lib.rs");
    std::env::set_current_dir(dir.path()).expect("chdir");
    let code = run_with_services(
        &DefaultApplicationServices,
        ["drifti", "generate", "--write"],
    );
    assert_eq!(code, 0);
    let yaml = std::fs::read_to_string(dir.path().join("drifti.yaml")).expect("yaml");
    assert!(yaml.contains("version:"));
}

#[test]
fn diff_invalid_contract_maps_to_exit_123() {
    assert_eq!(
        map_app_error(drifti_cli::app::AppError::InvalidContract {
            message: "bad".into()
        }),
        EXIT_COMMAND
    );
}

#[test]
fn stub_still_not_implemented_for_learn() {
    let code = run_with_services(&StubApplicationServices, ["drifti", "learn"]);
    assert_ne!(code, 0);
}
