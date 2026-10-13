// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Forward schema migrations for `.drifti/state.db`.
//!
//! The current schema is version 1. A version-1 file that predates
//! `execution_event_failures` gains that empty table inside one transaction.
//! The version number does not change, existing rows are not rewritten, and
//! a second open sees the table and skips the step.
//!
//! A later version would be a step in [`MIGRATIONS`] whose `to` is exactly
//! one greater than `from`. Every pending step of one open runs in a single
//! transaction. The version is written only when that transaction commits.
//! A statement that fails rolls the transaction back, so the file stays at
//! the version it had before the attempt. A newer version this process does
//! not know, or a header that disagrees with `schema_meta`, is refused
//! before any write.

use rusqlite::{params, Connection, Transaction};

use crate::schema::{EVENT_FAILURE_TABLE, SCHEMA_VERSION};
use crate::{read_schema_version, read_user_version};

/// One forward step. Statements are crate constants, not caller input.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Migration {
    /// When the step runs, and whether it changes the stored version.
    pub kind: MigrationKind,
    /// SQL applied in order. Empty text is not a plan this runner accepts.
    pub statements: &'static [&'static str],
}

/// How one [`Migration`] decides that it is already done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationKind {
    /// Additive change that stays on `version`.
    ///
    /// Skipped once `table` exists. `schema_meta` and `user_version` are
    /// left alone, so a current database is not rewritten.
    Repair { version: i64, table: &'static str },
    /// Moves `from` to `to` after every statement succeeds.
    ///
    /// `to` must be `from + 1`. The version columns change in the same
    /// transaction as the statements. The version-1 plan does not construct
    /// this step; tests do, to prove a forward transition can roll back.
    #[allow(dead_code)]
    Advance { from: i64, to: i64 },
}

/// Steps this process knows how to apply.
///
/// Version 1 is still the schema created by [`crate::schema::DDL`]. The
/// repair below is the only gap: databases written before
/// `execution_event_failures` existed.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    kind: MigrationKind::Repair {
        version: 1,
        table: "execution_event_failures",
    },
    statements: &[EVENT_FAILURE_TABLE],
}];

/// How many steps ran. Zero means the file was already current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct MigrationReport {
    /// Steps whose statements ran. A step that was already applied is omitted.
    pub applied: u32,
}

/// [`migrate`] could not finish. A failed step does not leave a new version.
#[derive(Debug)]
pub(crate) enum MigrateError {
    /// The plan skips a version or repeats one.
    InvalidPlan,
    /// `version` is not something this plan can open. Nothing was written.
    Unsupported {
        /// Version stored in `schema_meta`.
        version: i64,
    },
    /// Reading the current version failed. Nothing was written.
    Read(rusqlite::Error),
    /// A statement failed. `version` is the version still stored.
    Failed {
        /// Version still stored after the rollback.
        version: i64,
        /// Statement that failed.
        source: rusqlite::Error,
    },
}

/// `true` when `stored` matches the header and this plan can reach `SCHEMA_VERSION`.
pub(crate) fn version_is_supported(stored: i64, user_version: i64) -> bool {
    stored == user_version && can_reach(stored, SCHEMA_VERSION, MIGRATIONS)
}

/// Applies `plan` until `schema_meta.version` is `target`.
///
/// Pending steps share one transaction. A second call that finds every step
/// already applied returns [`MigrationReport::applied`] `0` and does not
/// start a transaction.
pub(crate) fn migrate(
    connection: &mut Connection,
    plan: &[Migration],
    target: i64,
) -> Result<MigrationReport, MigrateError> {
    if !plan_is_valid(plan) {
        return Err(MigrateError::InvalidPlan);
    }
    let version = read_schema_version(connection).map_err(MigrateError::Read)?;
    let user_version = read_user_version(connection).map_err(MigrateError::Read)?;
    if version != user_version || !can_reach(version, target, plan) {
        return Err(MigrateError::Unsupported { version });
    }
    if !needs_migration(connection, version, target, plan)? {
        return Ok(MigrationReport { applied: 0 });
    }

    let transaction = connection.transaction().map_err(MigrateError::Read)?;
    let applied = match apply_pending(&transaction, version, target, plan) {
        Ok(applied) => applied,
        Err(source) => {
            drop(transaction);
            let version = read_schema_version(connection).unwrap_or(version);
            return Err(MigrateError::Failed { version, source });
        }
    };
    match transaction.commit() {
        Ok(()) => Ok(MigrationReport { applied }),
        Err(source) => {
            let version = read_schema_version(connection).unwrap_or(version);
            Err(MigrateError::Failed { version, source })
        }
    }
}

fn needs_migration(
    connection: &Connection,
    version: i64,
    target: i64,
    plan: &[Migration],
) -> Result<bool, MigrateError> {
    if version < target {
        return Ok(true);
    }
    for step in plan {
        if let MigrationKind::Repair { version: at, table } = step.kind {
            if at == version && !table_exists(connection, table).map_err(MigrateError::Read)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn apply_pending(
    transaction: &Transaction<'_>,
    mut version: i64,
    target: i64,
    plan: &[Migration],
) -> Result<u32, rusqlite::Error> {
    let mut applied = 0;
    loop {
        applied += apply_repairs(transaction, version, plan)?;
        if version == target {
            return Ok(applied);
        }
        let step = advance_from(plan, version).ok_or(rusqlite::Error::InvalidQuery)?;
        for statement in step.statements {
            transaction.execute_batch(statement)?;
        }
        let MigrationKind::Advance { to, .. } = step.kind else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        let updated = transaction.execute(
            "UPDATE schema_meta SET version = ?1 WHERE singleton = 1 AND version = ?2",
            params![to, version],
        )?;
        if updated != 1 {
            return Err(rusqlite::Error::StatementChangedRows(updated));
        }
        transaction.pragma_update(None, "user_version", to)?;
        version = to;
        applied += 1;
    }
}

fn apply_repairs(
    transaction: &Transaction<'_>,
    version: i64,
    plan: &[Migration],
) -> Result<u32, rusqlite::Error> {
    let mut applied = 0;
    for step in plan {
        let MigrationKind::Repair { version: at, table } = step.kind else {
            continue;
        };
        if at != version || table_exists(transaction, table)? {
            continue;
        }
        for statement in step.statements {
            transaction.execute_batch(statement)?;
        }
        applied += 1;
    }
    Ok(applied)
}

fn advance_from(plan: &[Migration], version: i64) -> Option<&Migration> {
    plan.iter().find(|step| {
        matches!(
            step.kind,
            MigrationKind::Advance { from, to } if from == version && to == version.saturating_add(1)
        )
    })
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count != 0)
}

fn can_reach(stored: i64, target: i64, plan: &[Migration]) -> bool {
    if stored < 1 || target < 1 || stored > target {
        return false;
    }
    let mut cursor = stored;
    while cursor < target {
        let Some(next) = cursor.checked_add(1) else {
            return false;
        };
        let advances = plan.iter().any(|step| {
            matches!(
                step.kind,
                MigrationKind::Advance { from, to } if from == cursor && to == next
            )
        });
        if !advances {
            return false;
        }
        cursor = next;
    }
    true
}

fn plan_is_valid(plan: &[Migration]) -> bool {
    let mut previous_from: Option<i64> = None;
    let mut repairs: Vec<(i64, &str)> = Vec::new();
    for step in plan {
        if step.statements.is_empty() || step.statements.iter().any(|sql| sql.is_empty()) {
            return false;
        }
        match step.kind {
            MigrationKind::Repair { version, table } => {
                if version < 1 || table.is_empty() {
                    return false;
                }
                if repairs.iter().any(|(seen_version, seen_table)| {
                    *seen_version == version && *seen_table == table
                }) {
                    return false;
                }
                repairs.push((version, table));
            }
            MigrationKind::Advance { from, to } => {
                let Some(next) = from.checked_add(1) else {
                    return false;
                };
                if to != next || from < 1 {
                    return false;
                }
                if previous_from.is_some_and(|previous| from <= previous) {
                    return false;
                }
                previous_from = Some(from);
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::{params, Connection};

    use super::{
        advance_from, migrate, plan_is_valid, table_exists, MigrateError, Migration, MigrationKind,
        MigrationReport, MIGRATIONS,
    };
    use crate::schema::{
        canonical_resource, CanonicalResource, DDL, EVENT_FAILURE_TABLE, SCHEMA_VERSION,
    };
    use crate::{
        read_schema_version, read_user_version, Store, StoreError, DATABASE_FILE, STATE_DIR,
    };

    const EXECUTION_ID: &str = "0123456789abcdef0123456789abcdef";

    const FAILING_ADVANCE: &[&str] = &[
        "CREATE TABLE migration_probe (id INTEGER PRIMARY KEY)",
        "INSERT INTO migration_probe (id) VALUES (1)",
        "INSERT INTO migration_absent (id) VALUES (1)",
    ];

    struct Fixture {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn legacy(name: &str) -> Self {
            let dir = temp_dir(name);
            let path = dir.join("state.db");
            seed_legacy(&path);
            Self { dir, path }
        }

        fn workspace(name: &str) -> Self {
            let dir = temp_dir(name);
            let path = dir.join(STATE_DIR).join(DATABASE_FILE);
            fs::create_dir_all(path.parent().expect("parent")).expect("state dir");
            seed_legacy(&path);
            Self { dir, path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "drifti-migrate-{name}-{}-{nanos}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create fixture dir");
        path
    }

    fn open_rw(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("open fixture");
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("foreign keys");
        connection
    }

    fn seed_legacy(path: &Path) {
        let mut connection = open_rw(path);
        let transaction = connection.transaction().expect("seed transaction");
        for statement in DDL {
            if *statement == EVENT_FAILURE_TABLE {
                continue;
            }
            transaction.execute_batch(statement).expect("legacy ddl");
        }
        transaction
            .execute(
                "INSERT INTO schema_meta (singleton, version) VALUES (1, 1)",
                [],
            )
            .expect("schema_meta");
        transaction
            .pragma_update(None, "user_version", 1i64)
            .expect("user_version");
        transaction
            .execute(
                "INSERT INTO executions (
                    execution_id, lifecycle, coverage_status, exit_code,
                    command_program, arg_count, contract_version, tool_version
                 ) VALUES (?1, 'finished', 'INCOMPLETE', 3, 'tool', 2, 'contract-a', 'tool-a')",
                [EXECUTION_ID],
            )
            .expect("execution");
        transaction
            .execute(
                "INSERT INTO processes (execution_id, pid, tid, parent_pid)
                 VALUES (?1, 1, NULL, NULL)",
                [EXECUTION_ID],
            )
            .expect("parent process");
        transaction
            .execute(
                "INSERT INTO processes (execution_id, pid, tid, parent_pid)
                 VALUES (?1, 7, 8, 1)",
                [EXECUTION_ID],
            )
            .expect("child process");
        let resource =
            canonical_resource(CanonicalResource::File("/tmp/kept")).expect("canonical resource");
        transaction
            .execute(
                "INSERT INTO events (
                    execution_id, sequence, monotonic_nanos, pid, tid, parent_pid,
                    action, resource_kind, canonical_resource, outcome_status
                 ) VALUES (?1, 0, 5, 7, 8, 1, 'filesystem.read', 'file', ?2, 'success')",
                params![EXECUTION_ID, resource],
            )
            .expect("event");
        transaction.commit().expect("commit seed");
    }

    fn repair_and(advance: &'static [&'static str]) -> Vec<Migration> {
        vec![
            Migration {
                kind: MigrationKind::Repair {
                    version: 1,
                    table: "execution_event_failures",
                },
                statements: &[EVENT_FAILURE_TABLE],
            },
            Migration {
                kind: MigrationKind::Advance { from: 1, to: 2 },
                statements: advance,
            },
        ]
    }

    fn assert_legacy_rows(connection: &Connection) {
        assert_eq!(read_schema_version(connection).expect("version"), 1);
        assert_eq!(read_user_version(connection).expect("header"), 1);
        assert_eq!(count(connection, "SELECT COUNT(*) FROM schema_meta"), 1);
        assert_eq!(count(connection, "SELECT COUNT(*) FROM executions"), 1);
        assert_eq!(count(connection, "SELECT COUNT(*) FROM processes"), 2);
        assert_eq!(count(connection, "SELECT COUNT(*) FROM events"), 1);
        let program: String = connection
            .query_row(
                "SELECT command_program FROM executions WHERE execution_id = ?1",
                [EXECUTION_ID],
                |row| row.get(0),
            )
            .expect("program");
        assert_eq!(program, "tool");
        let sequence: i64 = connection
            .query_row(
                "SELECT sequence FROM events WHERE execution_id = ?1",
                [EXECUTION_ID],
                |row| row.get(0),
            )
            .expect("sequence");
        assert_eq!(sequence, 0);
    }

    fn count(connection: &Connection, sql: &str) -> i64 {
        connection
            .query_row(sql, [], |row| row.get(0))
            .expect("count")
    }

    fn schema_cookie(connection: &Connection) -> i64 {
        connection
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .expect("schema cookie")
    }

    fn schema_sql(connection: &Connection) -> Vec<(String, String, Option<String>)> {
        let mut statement = connection
            .prepare(
                "SELECT type, name, sql FROM sqlite_master
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            )
            .expect("prepare sqlite_master");
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("query sqlite_master");
        rows.collect::<Result<Vec<_>, _>>().expect("schema rows")
    }

    fn journal_paths(path: &Path) -> [PathBuf; 2] {
        let name = path.file_name().expect("file name");
        let mut journal = name.to_os_string();
        journal.push("-journal");
        let mut wal = name.to_os_string();
        wal.push("-wal");
        [path.with_file_name(journal), path.with_file_name(wal)]
    }

    #[test]
    fn production_plan_repairs_version_one_without_bumping_it() {
        assert!(plan_is_valid(MIGRATIONS));
        assert_eq!(SCHEMA_VERSION, 1);
        assert!(MIGRATIONS.iter().all(|step| {
            matches!(
                step.kind,
                MigrationKind::Repair {
                    version: 1,
                    table: "execution_event_failures",
                }
            )
        }));

        let fixture = Fixture::legacy("repair");
        let mut connection = open_rw(&fixture.path);
        let report = migrate(&mut connection, MIGRATIONS, SCHEMA_VERSION).expect("repair");
        assert_eq!(report, MigrationReport { applied: 1 });
        assert_legacy_rows(&connection);
        assert!(table_exists(&connection, "execution_event_failures").expect("table"));
        assert_eq!(
            count(&connection, "SELECT COUNT(*) FROM execution_event_failures"),
            0
        );
        let cookie = schema_cookie(&connection);
        let schema = schema_sql(&connection);

        let again = migrate(&mut connection, MIGRATIONS, SCHEMA_VERSION).expect("second open");
        assert_eq!(again, MigrationReport { applied: 0 });
        assert_legacy_rows(&connection);
        assert_eq!(schema_cookie(&connection), cookie);
        assert_eq!(schema_sql(&connection), schema);
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'execution_event_failures'"
            ),
            1
        );
    }

    #[test]
    fn two_legacy_fixtures_repair_to_the_same_schema() {
        let first = Fixture::legacy("repair-a");
        let second = Fixture::legacy("repair-b");
        let mut left = open_rw(&first.path);
        let mut right = open_rw(&second.path);
        assert_eq!(
            migrate(&mut left, MIGRATIONS, SCHEMA_VERSION)
                .expect("first")
                .applied,
            1
        );
        assert_eq!(
            migrate(&mut right, MIGRATIONS, SCHEMA_VERSION)
                .expect("second")
                .applied,
            1
        );
        assert_eq!(schema_sql(&left), schema_sql(&right));
        assert_legacy_rows(&left);
        assert_legacy_rows(&right);
    }

    #[test]
    fn a_forward_transition_keeps_rows_and_a_future_version_stays_closed() {
        let fixture = Fixture::workspace("advance");
        let plan = repair_and(&["CREATE TABLE migration_probe (id INTEGER PRIMARY KEY)"]);
        {
            let mut connection = open_rw(&fixture.path);
            let report = migrate(&mut connection, &plan, 2).expect("advance");
            assert_eq!(report.applied, 2);
            assert_eq!(read_schema_version(&connection).expect("version"), 2);
            assert_eq!(read_user_version(&connection).expect("header"), 2);
            assert_eq!(count(&connection, "SELECT COUNT(*) FROM executions"), 1);
            assert_eq!(count(&connection, "SELECT COUNT(*) FROM processes"), 2);
            assert_eq!(count(&connection, "SELECT COUNT(*) FROM events"), 1);
            assert!(table_exists(&connection, "execution_event_failures").expect("failures"));
            assert!(table_exists(&connection, "migration_probe").expect("probe"));
            let cookie = schema_cookie(&connection);
            let again = migrate(&mut connection, &plan, 2).expect("second advance");
            assert_eq!(again.applied, 0);
            assert_eq!(schema_cookie(&connection), cookie);
            assert_eq!(
                count(&connection, "SELECT COUNT(*) FROM migration_probe"),
                0
            );
        }

        let before = fs::read(&fixture.path).expect("bytes before reject");
        let error = Store::open(&fixture.dir).expect_err("version 2 opened");
        assert!(matches!(
            error,
            StoreError::IncompatibleSchema {
                found: Some(2),
                expected: 1,
                ..
            }
        ));
        assert_eq!(fs::read(&fixture.path).expect("bytes after reject"), before);
        let connection = open_rw(&fixture.path);
        assert_eq!(read_schema_version(&connection).expect("version"), 2);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM executions"), 1);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM events"), 1);
    }

    #[test]
    fn a_failed_migration_rolls_back_to_the_previous_version() {
        let fixture = Fixture::legacy("rollback");
        let before = fs::read(&fixture.path).expect("bytes before");
        let plan = repair_and(FAILING_ADVANCE);
        {
            let mut connection = open_rw(&fixture.path);
            let error = migrate(&mut connection, &plan, 2).expect_err("partial migration");
            match error {
                MigrateError::Failed { version, source } => {
                    assert_eq!(version, 1);
                    let message = source.to_string();
                    assert!(
                        message.contains("migration_absent"),
                        "failed before the last statement: {message}"
                    );
                }
                other => panic!("expected rollback, got {other:?}"),
            }
            assert_legacy_rows(&connection);
            assert!(!table_exists(&connection, "migration_probe").expect("probe"));
            assert!(!table_exists(&connection, "execution_event_failures").expect("failures"));
        }
        assert_eq!(fs::read(&fixture.path).expect("bytes after"), before);
        for path in journal_paths(&fixture.path) {
            assert!(!path.exists(), "partial journal left at {}", path.display());
        }
        let connection = open_rw(&fixture.path);
        assert_legacy_rows(&connection);
        assert!(!table_exists(&connection, "migration_probe").expect("probe"));
    }

    #[test]
    fn an_unsupported_version_is_not_modified() {
        let fixture = Fixture::legacy("future");
        {
            let connection = open_rw(&fixture.path);
            connection
                .execute("UPDATE schema_meta SET version = 2", [])
                .expect("bump schema_meta");
            connection
                .pragma_update(None, "user_version", 2i64)
                .expect("bump header");
        }
        let before = fs::read(&fixture.path).expect("bytes before");
        let mut connection = open_rw(&fixture.path);
        let error = migrate(&mut connection, MIGRATIONS, SCHEMA_VERSION)
            .expect_err("future version migrated");
        assert!(matches!(error, MigrateError::Unsupported { version: 2 }));
        drop(connection);
        assert_eq!(fs::read(&fixture.path).expect("bytes after"), before);
        let connection = open_rw(&fixture.path);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM executions"), 1);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM processes"), 2);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM events"), 1);
        assert!(advance_from(MIGRATIONS, 1).is_none());
    }

    #[test]
    fn a_header_mismatch_is_not_migrated() {
        let fixture = Fixture::legacy("mismatch");
        {
            let connection = open_rw(&fixture.path);
            connection
                .pragma_update(None, "user_version", 2i64)
                .expect("bump header");
        }
        let before = fs::read(&fixture.path).expect("bytes before");
        let mut connection = open_rw(&fixture.path);
        let error =
            migrate(&mut connection, MIGRATIONS, SCHEMA_VERSION).expect_err("mismatched header");
        assert!(matches!(error, MigrateError::Unsupported { version: 1 }));
        drop(connection);
        assert_eq!(fs::read(&fixture.path).expect("bytes after"), before);
    }

    #[test]
    fn an_invalid_plan_does_not_write() {
        let fixture = Fixture::legacy("invalid");
        let before = fs::read(&fixture.path).expect("bytes before");
        let plan = [Migration {
            kind: MigrationKind::Advance { from: 1, to: 3 },
            statements: &["CREATE TABLE should_not_exist (id INTEGER)"],
        }];
        let mut connection = open_rw(&fixture.path);
        let error = migrate(&mut connection, &plan, 3).expect_err("invalid plan applied");
        assert!(matches!(error, MigrateError::InvalidPlan));
        drop(connection);
        assert_eq!(fs::read(&fixture.path).expect("bytes after"), before);
        let connection = open_rw(&fixture.path);
        assert_legacy_rows(&connection);
        assert!(!table_exists(&connection, "should_not_exist").expect("table"));
    }
}
