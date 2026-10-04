// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Execution lifecycle repository.
//!
//! Callers use [`ExecutionRepository`]. They do not send SQL. Creating or
//! finishing an execution records metadata; it does not authorize a capability.
//!
//! An id is 48 bits of Unix milliseconds and 80 bits of uniqueness, written as
//! 32 lowercase hex characters. That text sorts in time order. A PID is not an
//! id and cannot be parsed as one.
//!
//! Command metadata is the program and an argument count. Argument values,
//! prompts, responses, and secret values are not fields on this repository.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StoreError;
use crate::map_sqlite;
use crate::Store;

const ID_HEX_LEN: usize = 32;
const TS_BITS: u32 = 48;
const TAIL_BITS: u32 = 80;
const MAX_PROGRAM_BYTES: usize = 4096;
const MAX_ARG_COUNT: u16 = 256;
const MAX_VERSION_BYTES: usize = 128;

/// Repository operations for one execution's lifecycle.
///
/// The methods do not take SQL. A storage error is an error. It is not
/// `COMPLETE` coverage and it is not authorization.
pub trait ExecutionRepository {
    /// Inserts a started execution and returns its new id.
    ///
    /// `command` stores a program and an argument count. It has no argument
    /// vector.
    fn create_execution(
        &mut self,
        command: Option<CommandMetadata>,
    ) -> Result<ExecutionRecord, StoreError>;

    /// Reads one execution. The id must already be canonical.
    fn get_execution(&self, id: &ExecutionId) -> Result<ExecutionRecord, StoreError>;

    /// Marks a started execution finished.
    ///
    /// A second finish fails and leaves the first record in place. `COMPLETE`
    /// paired with an unsupported domain fails before any write.
    fn finish_execution(
        &mut self,
        id: &ExecutionId,
        finish: FinishExecution,
    ) -> Result<ExecutionRecord, StoreError>;
}

/// Canonical execution id. The text form is time-sortable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutionId(String);

impl ExecutionId {
    /// Parses the 32-character lowercase hex form produced by this crate.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        if text.len() == ID_HEX_LEN
            && text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(Self(text.to_owned()))
        } else {
            Err(StoreError::InvalidExecutionId)
        }
    }

    /// Hex text. This is the primary key stored in `executions`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unix millisecond prefix. This is not a PID.
    #[must_use]
    pub fn timestamp_millis(&self) -> u64 {
        u64::from_str_radix(&self.0[..12], 16).expect("canonical execution id is hex")
    }

    fn from_parts(timestamp_ms: u64, tail: u128) -> Result<Self, StoreError> {
        if timestamp_ms >= 1u64 << TS_BITS || tail >= 1u128 << TAIL_BITS {
            return Err(StoreError::ExecutionIdExhausted);
        }
        let mut bytes = [0u8; 16];
        bytes[..6].copy_from_slice(&timestamp_ms.to_be_bytes()[2..]);
        bytes[6..].copy_from_slice(&tail.to_be_bytes()[6..]);
        Ok(Self(hex_encode(&bytes)))
    }
}

/// Per-process monotonic id source.
///
/// The first id at a new millisecond uses the supplied random tail. A clock
/// that stalls or moves backward keeps issuing later ids so one process does
/// not reuse a value.
#[derive(Debug)]
pub(crate) struct IdGenerator {
    previous: Option<(u64, u128)>,
}

impl IdGenerator {
    pub(crate) const fn new() -> Self {
        Self { previous: None }
    }

    pub(crate) fn next(
        &mut self,
        now_ms: u64,
        random_tail: u128,
    ) -> Result<ExecutionId, StoreError> {
        if now_ms >= 1u64 << TS_BITS {
            return Err(StoreError::ClockOutOfRange);
        }
        let random_tail = random_tail & ((1u128 << TAIL_BITS) - 1);
        let (timestamp_ms, tail) = match self.previous {
            Some((last_ms, _)) if now_ms > last_ms => (now_ms, random_tail),
            Some((last_ms, last_tail)) => {
                if last_tail == (1u128 << TAIL_BITS) - 1 {
                    if last_ms == (1u64 << TS_BITS) - 1 {
                        return Err(StoreError::ExecutionIdExhausted);
                    }
                    (last_ms + 1, 0)
                } else {
                    (last_ms, last_tail + 1)
                }
            }
            None => (now_ms, random_tail),
        };
        self.previous = Some((timestamp_ms, tail));
        ExecutionId::from_parts(timestamp_ms, tail)
    }
}

/// Minimized command record. Argument values are not part of this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandMetadata {
    program: String,
    arg_count: u16,
}

impl CommandMetadata {
    /// `program` is the executable name or path. `arg_count` is how many
    /// arguments were present. The arguments themselves are discarded.
    pub fn try_new(program: &str, arg_count: u16) -> Result<Self, StoreError> {
        if !valid_bounded_text(program, MAX_PROGRAM_BYTES) {
            return Err(StoreError::InvalidCommandProgram);
        }
        if arg_count > MAX_ARG_COUNT {
            return Err(StoreError::ArgCountOutOfRange);
        }
        Ok(Self {
            program: program.to_owned(),
            arg_count,
        })
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn arg_count(&self) -> u16 {
        self.arg_count
    }

    fn from_stored(program: String, arg_count: i64) -> Result<Self, StoreError> {
        let arg_count = u16::try_from(arg_count).map_err(|_| StoreError::CorruptExecution)?;
        if !valid_bounded_text(&program, MAX_PROGRAM_BYTES) || arg_count > MAX_ARG_COUNT {
            return Err(StoreError::CorruptExecution);
        }
        Ok(Self { program, arg_count })
    }
}

/// Stored lifecycle. Started is not a finished execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// The execution row exists and has not been finished.
    Started,
    /// [`ExecutionRepository::finish_execution`] recorded the final metadata.
    Finished,
}

impl Lifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Finished => "finished",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "started" => Some(Self::Started),
            "finished" => Some(Self::Finished),
            _ => None,
        }
    }
}

/// Coverage declaration stored for a finished execution.
///
/// This is not a policy decision. `COMPLETE` is not success of the execution,
/// and it is not `UNKNOWN` or `DENIED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    /// The caller declared that observation covered the advertised domains.
    Complete,
    /// The caller declared that coverage is partial.
    Incomplete,
    /// The caller declared that observation cannot cover the execution.
    Unsupported,
}

impl CoverageStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Incomplete => "INCOMPLETE",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "COMPLETE" => Some(Self::Complete),
            "INCOMPLETE" => Some(Self::Incomplete),
            "UNSUPPORTED" => Some(Self::Unsupported),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Domain that a finished execution may mark unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityDomain {
    /// Filesystem operations.
    Filesystem,
    /// Network endpoints.
    Network,
    /// Process execution.
    Process,
}

impl CapabilityDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Process => "process",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "filesystem" => Some(Self::Filesystem),
            "network" => Some(Self::Network),
            "process" => Some(Self::Process),
            _ => None,
        }
    }
}

/// Final metadata written by [`ExecutionRepository::finish_execution`].
///
/// An exit code is not coverage. Zero does not declare `COMPLETE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishExecution {
    coverage: CoverageStatus,
    unsupported_domains: BTreeSet<CapabilityDomain>,
    exit_code: Option<i32>,
    contract_version: Option<String>,
    tool_version: Option<String>,
}

impl FinishExecution {
    /// Builds a finish record.
    ///
    /// `COMPLETE` with any unsupported domain is rejected here, before the
    /// store writes. The other statuses may name unsupported domains.
    pub fn try_new(
        coverage: CoverageStatus,
        unsupported_domains: impl IntoIterator<Item = CapabilityDomain>,
        exit_code: Option<i32>,
        contract_version: Option<&str>,
        tool_version: Option<&str>,
    ) -> Result<Self, StoreError> {
        let unsupported_domains: BTreeSet<CapabilityDomain> =
            unsupported_domains.into_iter().collect();
        if coverage.is_complete() && !unsupported_domains.is_empty() {
            return Err(StoreError::CompleteWhileUnsupported);
        }
        Ok(Self {
            coverage,
            unsupported_domains,
            exit_code,
            contract_version: optional_version(contract_version)?,
            tool_version: optional_version(tool_version)?,
        })
    }

    #[must_use]
    pub fn coverage(&self) -> CoverageStatus {
        self.coverage
    }

    #[must_use]
    pub fn unsupported_domains(&self) -> &BTreeSet<CapabilityDomain> {
        &self.unsupported_domains
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    #[must_use]
    pub fn contract_version(&self) -> Option<&str> {
        self.contract_version.as_deref()
    }

    #[must_use]
    pub fn tool_version(&self) -> Option<&str> {
        self.tool_version.as_deref()
    }
}

/// One execution row, read back through the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord {
    id: ExecutionId,
    lifecycle: Lifecycle,
    command: Option<CommandMetadata>,
    exit_code: Option<i32>,
    coverage: Option<CoverageStatus>,
    unsupported_domains: BTreeSet<CapabilityDomain>,
    contract_version: Option<String>,
    tool_version: Option<String>,
}

impl ExecutionRecord {
    #[must_use]
    pub fn id(&self) -> &ExecutionId {
        &self.id
    }

    #[must_use]
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    #[must_use]
    pub fn command(&self) -> Option<&CommandMetadata> {
        self.command.as_ref()
    }

    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Declared coverage. `None` means the execution is still started.
    /// Absence is not `COMPLETE`.
    #[must_use]
    pub fn coverage(&self) -> Option<CoverageStatus> {
        self.coverage
    }

    #[must_use]
    pub fn unsupported_domains(&self) -> &BTreeSet<CapabilityDomain> {
        &self.unsupported_domains
    }

    #[must_use]
    pub fn contract_version(&self) -> Option<&str> {
        self.contract_version.as_deref()
    }

    #[must_use]
    pub fn tool_version(&self) -> Option<&str> {
        self.tool_version.as_deref()
    }

    /// `true` only for a stored `COMPLETE` declaration with no unsupported domain.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.coverage.is_some_and(CoverageStatus::is_complete)
            && self.unsupported_domains.is_empty()
    }
}

impl Store {
    /// Inserts a started execution and returns its new id.
    pub fn create_execution(
        &mut self,
        command: Option<CommandMetadata>,
    ) -> Result<ExecutionRecord, StoreError> {
        let id = self.allocate_id()?;
        self.insert_started(&id, command.as_ref())?;
        self.get_execution(&id)
    }

    /// Reads one execution.
    pub fn get_execution(&self, id: &ExecutionId) -> Result<ExecutionRecord, StoreError> {
        load_execution(&self.connection, &self.path, id)
    }

    /// Marks a started execution finished.
    pub fn finish_execution(
        &mut self,
        id: &ExecutionId,
        finish: FinishExecution,
    ) -> Result<ExecutionRecord, StoreError> {
        self.write_finish(id, &finish)?;
        self.get_execution(id)
    }

    fn allocate_id(&mut self) -> Result<ExecutionId, StoreError> {
        let now = unix_millis()?;
        let tail =
            random_tail(&self.connection).map_err(|source| map_sqlite(&self.path, source))?;
        self.ids.next(now, tail)
    }

    fn insert_started(
        &mut self,
        id: &ExecutionId,
        command: Option<&CommandMetadata>,
    ) -> Result<(), StoreError> {
        let path = self.path.clone();
        let (program, arg_count) = match command {
            Some(command) => (
                Some(command.program()),
                Some(i64::from(command.arg_count())),
            ),
            None => (None, None),
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| map_sqlite(&path, source))?;
        transaction
            .execute(
                "INSERT INTO executions (execution_id, lifecycle, command_program, arg_count)
                 VALUES (?1, ?2, ?3, ?4)",
                params![id.as_str(), Lifecycle::Started.as_str(), program, arg_count],
            )
            .map_err(|source| map_sqlite(&path, source))?;
        transaction
            .commit()
            .map_err(|source| map_sqlite(&path, source))?;
        Ok(())
    }

    fn write_finish(
        &mut self,
        id: &ExecutionId,
        finish: &FinishExecution,
    ) -> Result<(), StoreError> {
        if finish.coverage.is_complete() && !finish.unsupported_domains.is_empty() {
            return Err(StoreError::CompleteWhileUnsupported);
        }
        let path = self.path.clone();
        let transaction = self
            .connection
            .transaction()
            .map_err(|source| map_sqlite(&path, source))?;
        let lifecycle: Option<String> = transaction
            .query_row(
                "SELECT lifecycle FROM executions WHERE execution_id = ?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|source| map_sqlite(&path, source))?;
        match lifecycle.as_deref() {
            None => {
                return Err(StoreError::ExecutionNotFound {
                    id: id.as_str().to_owned(),
                })
            }
            Some("finished") => {
                return Err(StoreError::ExecutionAlreadyFinished {
                    id: id.as_str().to_owned(),
                })
            }
            Some("started") => {}
            Some(_) => return Err(StoreError::CorruptExecution),
        }
        let changed = transaction
            .execute(
                "UPDATE executions
                 SET lifecycle = 'finished',
                     coverage_status = ?2,
                     exit_code = ?3,
                     contract_version = ?4,
                     tool_version = ?5
                 WHERE execution_id = ?1 AND lifecycle = 'started'",
                params![
                    id.as_str(),
                    finish.coverage.as_str(),
                    finish.exit_code,
                    finish.contract_version.as_deref(),
                    finish.tool_version.as_deref(),
                ],
            )
            .map_err(|source| map_sqlite(&path, source))?;
        if changed != 1 {
            return Err(StoreError::ExecutionAlreadyFinished {
                id: id.as_str().to_owned(),
            });
        }
        for domain in &finish.unsupported_domains {
            transaction
                .execute(
                    "INSERT INTO execution_unsupported_domains (execution_id, domain)
                     VALUES (?1, ?2)",
                    params![id.as_str(), domain.as_str()],
                )
                .map_err(|source| map_sqlite(&path, source))?;
        }
        transaction
            .commit()
            .map_err(|source| map_sqlite(&path, source))?;
        Ok(())
    }
}

impl ExecutionRepository for Store {
    fn create_execution(
        &mut self,
        command: Option<CommandMetadata>,
    ) -> Result<ExecutionRecord, StoreError> {
        Store::create_execution(self, command)
    }

    fn get_execution(&self, id: &ExecutionId) -> Result<ExecutionRecord, StoreError> {
        Store::get_execution(self, id)
    }

    fn finish_execution(
        &mut self,
        id: &ExecutionId,
        finish: FinishExecution,
    ) -> Result<ExecutionRecord, StoreError> {
        Store::finish_execution(self, id, finish)
    }
}

struct RawExecution {
    lifecycle: String,
    coverage: Option<String>,
    exit_code: Option<i64>,
    program: Option<String>,
    arg_count: Option<i64>,
    contract_version: Option<String>,
    tool_version: Option<String>,
}

fn load_execution(
    connection: &Connection,
    path: &std::path::Path,
    id: &ExecutionId,
) -> Result<ExecutionRecord, StoreError> {
    let raw = connection
        .query_row(
            "SELECT lifecycle, coverage_status, exit_code, command_program, arg_count,
                    contract_version, tool_version
             FROM executions WHERE execution_id = ?1",
            params![id.as_str()],
            |row| {
                Ok(RawExecution {
                    lifecycle: row.get(0)?,
                    coverage: row.get(1)?,
                    exit_code: row.get(2)?,
                    program: row.get(3)?,
                    arg_count: row.get(4)?,
                    contract_version: row.get(5)?,
                    tool_version: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|source| map_sqlite(path, source))?;
    let Some(raw) = raw else {
        return Err(StoreError::ExecutionNotFound {
            id: id.as_str().to_owned(),
        });
    };
    let lifecycle = Lifecycle::parse(&raw.lifecycle).ok_or(StoreError::CorruptExecution)?;
    let coverage = match raw.coverage.as_deref() {
        None => None,
        Some(text) => Some(CoverageStatus::parse(text).ok_or(StoreError::CorruptExecution)?),
    };
    let unsupported_domains = load_domains(connection, path, id)?;
    if coverage.is_some_and(CoverageStatus::is_complete) && !unsupported_domains.is_empty() {
        return Err(StoreError::CompleteWhileUnsupported);
    }
    let exit_code = match raw.exit_code {
        None => None,
        Some(code) => Some(i32::try_from(code).map_err(|_| StoreError::CorruptExecution)?),
    };
    let command = match (raw.program, raw.arg_count) {
        (None, None) => None,
        (Some(program), Some(arg_count)) => Some(CommandMetadata::from_stored(program, arg_count)?),
        _ => return Err(StoreError::CorruptExecution),
    };
    let contract_version = optional_stored_text(raw.contract_version)?;
    let tool_version = optional_stored_text(raw.tool_version)?;
    match lifecycle {
        Lifecycle::Started => {
            if coverage.is_some()
                || exit_code.is_some()
                || contract_version.is_some()
                || tool_version.is_some()
                || !unsupported_domains.is_empty()
            {
                return Err(StoreError::CorruptExecution);
            }
        }
        Lifecycle::Finished => {
            if coverage.is_none() {
                return Err(StoreError::CorruptExecution);
            }
        }
    }
    Ok(ExecutionRecord {
        id: id.clone(),
        lifecycle,
        command,
        exit_code,
        coverage,
        unsupported_domains,
        contract_version,
        tool_version,
    })
}

fn load_domains(
    connection: &Connection,
    path: &std::path::Path,
    id: &ExecutionId,
) -> Result<BTreeSet<CapabilityDomain>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT domain FROM execution_unsupported_domains
             WHERE execution_id = ?1 ORDER BY domain",
        )
        .map_err(|source| map_sqlite(path, source))?;
    let rows = statement
        .query_map(params![id.as_str()], |row| row.get::<_, String>(0))
        .map_err(|source| map_sqlite(path, source))?;
    let mut domains = BTreeSet::new();
    for row in rows {
        let name = row.map_err(|source| map_sqlite(path, source))?;
        let domain = CapabilityDomain::parse(&name).ok_or(StoreError::CorruptExecution)?;
        domains.insert(domain);
    }
    Ok(domains)
}

fn unix_millis() -> Result<u64, StoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::ClockOutOfRange)?
        .as_millis();
    u64::try_from(millis).map_err(|_| StoreError::ClockOutOfRange)
}

fn random_tail(connection: &Connection) -> Result<u128, rusqlite::Error> {
    let blob: Vec<u8> = connection.query_row("SELECT randomblob(10)", [], |row| row.get(0))?;
    if blob.len() != 10 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut tail = 0u128;
    for byte in blob {
        tail = (tail << 8) | u128::from(byte);
    }
    Ok(tail)
}

fn optional_version(value: Option<&str>) -> Result<Option<String>, StoreError> {
    match value {
        None => Ok(None),
        Some(text) if valid_bounded_text(text, MAX_VERSION_BYTES) => Ok(Some(text.to_owned())),
        Some(_) => Err(StoreError::InvalidVersionText),
    }
}

fn optional_stored_text(value: Option<String>) -> Result<Option<String>, StoreError> {
    match value {
        None => Ok(None),
        Some(text) if valid_bounded_text(&text, MAX_VERSION_BYTES) => Ok(Some(text)),
        Some(_) => Err(StoreError::CorruptExecution),
    }
}

fn valid_bounded_text(text: &str, max_bytes: usize) -> bool {
    !text.is_empty() && text.len() <= max_bytes && !text.as_bytes().contains(&0)
}

fn hex_encode(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(ID_HEX_LEN);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{ExecutionId, IdGenerator, TAIL_BITS, TS_BITS};

    fn tail_max() -> u128 {
        (1u128 << TAIL_BITS) - 1
    }

    #[test]
    fn parse_rejects_a_pid_and_uppercase_hex() {
        assert!(ExecutionId::parse("7").is_err());
        assert!(ExecutionId::parse("0").is_err());
        assert!(ExecutionId::parse(&std::process::id().to_string()).is_err());
        let mut upper = "ab".repeat(16);
        upper.replace_range(0..1, "A");
        assert!(ExecutionId::parse(&upper).is_err());
    }

    #[test]
    fn same_millisecond_ids_increase_when_the_clock_stalls() {
        let mut generator = IdGenerator::new();
        let first = generator.next(1_700_000_000_000, 5).expect("first");
        let second = generator.next(1_700_000_000_000, 5).expect("second");
        assert!(first < second);
        assert_eq!(first.timestamp_millis(), second.timestamp_millis());
        assert_ne!(first.as_str(), second.as_str());
        assert_eq!(first.as_str().len(), 32);
    }

    #[test]
    fn a_backward_clock_does_not_reuse_an_id() {
        let mut generator = IdGenerator::new();
        let first = generator.next(100, 1).expect("first");
        let second = generator.next(50, 1).expect("second");
        assert!(first < second);
        assert!(ExecutionId::parse("100").is_err());
        assert_ne!(second.as_str(), "50");
    }

    #[test]
    fn a_full_tail_advances_the_millisecond() {
        let mut generator = IdGenerator {
            previous: Some((10, tail_max())),
        };
        let id = generator.next(10, 0).expect("bump");
        assert_eq!(id.timestamp_millis(), 11);
    }

    #[test]
    fn the_last_id_does_not_wrap() {
        let mut generator = IdGenerator {
            previous: Some(((1u64 << TS_BITS) - 1, tail_max())),
        };
        assert!(generator.next(0, 0).is_err());
    }

    #[test]
    fn generated_ids_round_trip_through_parse() {
        let mut generator = IdGenerator::new();
        let id = generator.next(42, tail_max()).expect("id");
        assert_eq!(ExecutionId::parse(id.as_str()).expect("parse"), id);
        assert_eq!(id.timestamp_millis(), 42);
    }

    proptest::proptest! {
        #[test]
        fn lexicographic_order_matches_timestamp_then_tail(
            left_ms in 0u64..(1u64 << TS_BITS),
            right_ms in 0u64..(1u64 << TS_BITS),
            left_tail in 0u128..(1u128 << TAIL_BITS),
            right_tail in 0u128..(1u128 << TAIL_BITS),
        ) {
            let left = ExecutionId::from_parts(left_ms, left_tail).expect("left");
            let right = ExecutionId::from_parts(right_ms, right_tail).expect("right");
            let time_order = (left_ms, left_tail).cmp(&(right_ms, right_tail));
            proptest::prop_assert_eq!(left.cmp(&right), time_order);
            proptest::prop_assert_eq!(left.timestamp_millis(), left_ms);
            proptest::prop_assert_eq!(right.as_str().len(), 32);
        }
    }
}
