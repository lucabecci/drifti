// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPEC-010 verify end-to-end acceptance matrix (KAN-95).
//!
//! Linux ptrace runs under a process-wide lock because other observer tests
//! may run in the same CI job.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use drifti_cli::{
    run_with_services, MvpApplicationServices, EXIT_INCOMPLETE, EXIT_INVALID_CONTRACT,
    EXIT_SUCCESS, EXIT_VIOLATION,
};

fn exclusive_tracer() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn filesystem_tracee() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_filesystem-tracee") {
            return PathBuf::from(path);
        }
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        let candidate = target_dir.join(profile).join("filesystem-tracee");
        assert!(
            candidate.is_file(),
            "missing {} (run workspace tests so observer-linux fixtures build)",
            candidate.display()
        );
        candidate
    })
    .clone()
}

struct Workspace {
    dir: tempfile::TempDir,
    _guard: MutexGuard<'static, ()>,
}

impl Workspace {
    fn new() -> Self {
        let guard = exclusive_tracer();
        let dir = tempfile::tempdir().expect("tempdir");
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir.path()).expect("chdir");
        assert_eq!(
            run_with_services(&MvpApplicationServices, ["drifti", "init"]),
            i32::from(EXIT_SUCCESS)
        );
        std::env::set_current_dir(previous).expect("restore cwd");
        Self { dir, _guard: guard }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn run_verify(&self, args: impl IntoIterator<Item = impl AsRef<str>>) -> i32 {
        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(self.path()).expect("chdir");
        let code = run_with_services(&MvpApplicationServices, args);
        std::env::set_current_dir(previous).expect("restore cwd");
        code
    }

    fn write_contract(&self, yaml: &str) {
        fs::write(self.path().join("drifti.yaml"), yaml).expect("contract");
    }
}

const ALLOW_REPO_READS: &str = "\
version: 1

filesystem:
  read:
    allow:
      - ./**
  write:
    allow: []

process:
  execute:
    allow: []

network:
  connect:
    allow: []
";

fn deny_payload_contract() -> String {
    format!(
        "\
version: 1

filesystem:
  read:
    allow:
      - ./**
    deny:
      - ./{payload}/**
  write:
    allow: []

process:
  execute:
    allow: []

network:
  connect:
    allow: []
",
        payload = "payload"
    )
}

fn path_text(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

#[test]
fn verify_denied_read_exits_121() {
    let workspace = Workspace::new();
    workspace.write_contract(&deny_payload_contract());
    let payload = workspace.path().join("payload");
    fs::create_dir_all(&payload).expect("payload dir");
    let file = payload.join("secret.txt");
    fs::write(&file, b"x").expect("payload file");
    let tracee = path_text(&filesystem_tracee());
    let code = workspace.run_verify(["drifti", "verify", "--", &tracee, "read", &path_text(&file)]);
    assert_eq!(code, i32::from(EXIT_VIOLATION));
}

#[test]
fn verify_incomplete_coverage_without_violation_exits_122() {
    let workspace = Workspace::new();
    workspace.write_contract(ALLOW_REPO_READS);
    let file = workspace.path().join("allowed.txt");
    fs::write(&file, b"ok").expect("allowed file");
    let tracee = path_text(&filesystem_tracee());
    let code = workspace.run_verify(["drifti", "verify", "--", &tracee, "read", &path_text(&file)]);
    assert_eq!(code, i32::from(EXIT_INCOMPLETE));
}

#[test]
fn verify_invalid_contract_exits_123_before_launch() {
    let workspace = Workspace::new();
    workspace.write_contract("version: not-valid\n");
    let code = workspace.run_verify(["drifti", "verify", "--", "/bin/true"]);
    assert_eq!(code, i32::from(EXIT_INVALID_CONTRACT));
}

#[test]
fn verify_allowed_fixture_does_not_exit_violation() {
    let workspace = Workspace::new();
    workspace.write_contract(ALLOW_REPO_READS);
    let file = workspace.path().join("allowed.txt");
    fs::write(&file, b"ok").expect("allowed file");
    let tracee = path_text(&filesystem_tracee());
    let code = workspace.run_verify(["drifti", "verify", "--", &tracee, "read", &path_text(&file)]);
    assert_ne!(code, i32::from(EXIT_VIOLATION));
    assert_ne!(code, i32::from(EXIT_INVALID_CONTRACT));
}
