// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! KAN-56 acceptance checks for execution-scoped process lineage.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use drifti_store::{ProcessRecord, ProcessRepository, Store, StoreError, DATABASE_FILE, STATE_DIR};

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "drifti-store-proc-{name}-{}-{nanos}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create workspace");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn process(pid: u32, tid: Option<u32>, parent: Option<u32>) -> ProcessRecord {
    ProcessRecord::try_new(pid, tid, parent).expect("process")
}

#[test]
fn lineage_survives_restart_and_rebuilds_parent_and_children() {
    let workspace = TempWorkspace::new("restart");
    let mut store = Store::open(workspace.path()).expect("open");
    let execution = store
        .create_execution(None)
        .expect("execution")
        .id()
        .clone();
    let repo: &mut dyn ProcessRepository = &mut store;
    repo.record_process(&execution, process(1, Some(1), None))
        .expect("root");
    repo.record_process(&execution, process(2, Some(20), Some(1)))
        .expect("child");
    repo.record_process(&execution, process(3, None, Some(2)))
        .expect("grandchild");
    repo.record_process(&execution, process(4, Some(40), Some(1)))
        .expect("other child");
    let before = repo.process_lineage(&execution, 3).expect("lineage");
    assert_eq!(
        before
            .ancestors()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(before.children().is_empty());
    let root = repo.process_lineage(&execution, 1).expect("root lineage");
    assert!(root.ancestors().is_empty());
    assert_eq!(
        root.children()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
    assert_eq!(root.process().tid(), Some(1));
    drop(store);
    let store = Store::open(workspace.path()).expect("reopen");
    let after = store.process_lineage(&execution, 3).expect("after restart");
    assert_eq!(after, before);
    let listed = store.processes(&execution).expect("list");
    assert_eq!(
        listed.iter().map(ProcessRecord::pid).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn the_same_pid_in_two_executions_does_not_alias() {
    let workspace = TempWorkspace::new("alias");
    let mut store = Store::open(workspace.path()).expect("open");
    let first = store.create_execution(None).expect("first").id().clone();
    let second = store.create_execution(None).expect("second").id().clone();
    store
        .record_process(&first, process(7, Some(70), Some(1)))
        .expect("first pid");
    store
        .record_process(&first, process(1, None, None))
        .expect("first parent");
    store
        .record_process(&second, process(7, Some(71), Some(9)))
        .expect("second pid");
    let left = store.process_lineage(&first, 7).expect("left");
    let right = store.process_lineage(&second, 7).expect("right");
    assert_eq!(left.execution_id(), &first);
    assert_eq!(right.execution_id(), &second);
    assert_eq!(left.process().tid(), Some(70));
    assert_eq!(right.process().tid(), Some(71));
    assert_eq!(left.process().parent_pid(), Some(1));
    assert_eq!(right.process().parent_pid(), Some(9));
    assert_eq!(
        left.ancestors()
            .iter()
            .map(ProcessRecord::pid)
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert!(right.ancestors().is_empty());
    assert!(matches!(
        store.process_lineage(&second, 1),
        Err(StoreError::ProcessNotFound { pid: 1, .. })
    ));
    assert_eq!(store.processes(&first).expect("first list").len(), 2);
    assert_eq!(store.processes(&second).expect("second list").len(), 1);
}

#[test]
fn queries_fail_for_an_unknown_execution_and_do_not_invent_a_parent() {
    let workspace = TempWorkspace::new("scope");
    let mut store = Store::open(workspace.path()).expect("open");
    let execution = store
        .create_execution(None)
        .expect("execution")
        .id()
        .clone();
    let missing = drifti_store::ExecutionId::parse(&"cd".repeat(16)).expect("unused id");
    assert!(matches!(
        store.record_process(&missing, process(1, None, None)),
        Err(StoreError::ExecutionNotFound { .. })
    ));
    assert!(matches!(
        store.processes(&missing),
        Err(StoreError::ExecutionNotFound { .. })
    ));
    store
        .record_process(&execution, process(5, Some(8), Some(4)))
        .expect("orphan");
    let lineage = store.process_lineage(&execution, 5).expect("lineage");
    assert!(lineage.ancestors().is_empty());
    assert_eq!(lineage.process().parent_pid(), Some(4));
    assert!(store.processes(&execution).expect("empty sibling").len() == 1);
    let started = store.get_execution(&execution).expect("execution");
    assert!(started.coverage().is_none());
    assert!(!started.is_complete());
}

#[test]
fn a_conflicting_lineage_is_kept_and_a_repeat_is_idempotent() {
    let workspace = TempWorkspace::new("conflict");
    let mut store = Store::open(workspace.path()).expect("open");
    let execution = store
        .create_execution(None)
        .expect("execution")
        .id()
        .clone();
    let original = process(3, Some(1), Some(2));
    store
        .record_process(&execution, original.clone())
        .expect("record");
    let again = store
        .record_process(&execution, original.clone())
        .expect("idempotent");
    assert_eq!(again, original);
    let conflict = store.record_process(&execution, process(3, Some(9), Some(2)));
    assert!(matches!(
        conflict,
        Err(StoreError::ProcessConflict { pid: 3, .. })
    ));
    assert_eq!(
        store
            .process_lineage(&execution, 3)
            .expect("kept")
            .process(),
        &original
    );
    assert!(matches!(
        ProcessRecord::try_new(4, None, Some(4)),
        Err(StoreError::InvalidProcessParent)
    ));
}

#[test]
fn a_stored_parent_cycle_is_not_walked_forever() {
    let workspace = TempWorkspace::new("cycle");
    let mut store = Store::open(workspace.path()).expect("open");
    let execution = store
        .create_execution(None)
        .expect("execution")
        .id()
        .clone();
    drop(store);
    let path = workspace.path().join(STATE_DIR).join(DATABASE_FILE);
    let connection = Connection::open(path).expect("inspect");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, parent_pid) VALUES (?1, 2, 3)",
            [execution.as_str()],
        )
        .expect("insert 2");
    connection
        .execute(
            "INSERT INTO processes (execution_id, pid, parent_pid) VALUES (?1, 3, 2)",
            [execution.as_str()],
        )
        .expect("insert 3");
    drop(connection);
    let store = Store::open(workspace.path()).expect("reopen");
    let error = store
        .process_lineage(&execution, 2)
        .expect_err("cycle was walked");
    assert!(matches!(error, StoreError::ProcessCycle { pid: 2, .. }));
    let rows = store.processes(&execution).expect("rows remain");
    assert_eq!(rows.len(), 2);
}
