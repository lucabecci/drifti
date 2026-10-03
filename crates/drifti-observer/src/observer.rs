// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observer contract: launch a command, emit events, return coverage.
//!
//! [`CommandSpec`] holds the launch input, including argument text the
//! backend needs in order to start a process. Those arguments are not part
//! of [`crate::ObservedEvent`]. Debug output for a command shows the program
//! and the argument count, not the argument values.

use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use crate::coverage::ExecutionCoverage;
use crate::event::ExecutionId;
use crate::sink::{EventSink, SinkError};
use crate::text::{self, TextError};

const MAX_PROGRAM: usize = 4096;
const MAX_ARG: usize = 4096;
const MAX_ARGS: usize = 256;

/// Launch input for one observation run.
pub struct CommandSpec {
    program: String,
    args: Vec<String>,
    current_dir: Option<String>,
}

impl CommandSpec {
    /// Builds a command. Argument values stay available to the backend and
    /// are omitted from [`Debug`].
    pub fn try_new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = String>,
        current_dir: Option<String>,
    ) -> Result<Self, ObserverError> {
        let program = map_program(text::bounded(program, MAX_PROGRAM))?;
        let mut stored = Vec::new();
        for (index, arg) in args.into_iter().enumerate() {
            if stored.len() == MAX_ARGS {
                return Err(ObserverError::TooManyArgs { max: MAX_ARGS });
            }
            stored.push(map_arg(arg, index)?);
        }
        let current_dir = match current_dir {
            Some(dir) => Some(map_dir(text::bounded(dir, MAX_PROGRAM))?),
            None => None,
        };
        Ok(Self {
            program,
            args: stored,
            current_dir,
        })
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Argument values for the process launch. Do not copy these into an event.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    #[must_use]
    pub fn current_dir(&self) -> Option<&str> {
        self.current_dir.as_deref()
    }
}

impl Debug for CommandSpec {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("arg_count", &self.args.len())
            .field("current_dir", &self.current_dir)
            .finish()
    }
}

/// Metadata returned after a run. An exit code is not coverage and is not a
/// policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    execution_id: ExecutionId,
    coverage: ExecutionCoverage,
    exit_code: Option<i32>,
}

impl ExecutionResult {
    /// Records the id, the declared coverage, and an optional exit code.
    ///
    /// This constructor does not choose [`crate::ObservationCoverage::Complete`].
    #[must_use]
    pub fn new(
        execution_id: ExecutionId,
        coverage: ExecutionCoverage,
        exit_code: Option<i32>,
    ) -> Self {
        Self {
            execution_id,
            coverage,
            exit_code,
        }
    }

    #[must_use]
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    #[must_use]
    pub const fn coverage(&self) -> &ExecutionCoverage {
        &self.coverage
    }

    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

/// Platform-neutral observer.
///
/// `run` takes the [`EventSink`] by value and returns that same sink with the
/// result. The caller does not need to clone the sink. Events already accepted
/// stay reachable on the returned sink after the cursor is dropped, and on the
/// cursor while it is still alive. A rejected event stays inside
/// [`ObserverError::Sink`]. A sink failure is an [`Err`], not a successful result.
pub trait Observer {
    /// Domains this backend can observe.
    fn capabilities(&self) -> crate::ObserverCapabilities;

    /// Launches `command`, emits semantic events into `sink`, and returns coverage.
    ///
    /// The sink is returned on both `Ok` and `Err`. Dropping it is the caller's
    /// choice after they have taken any accepted events the cursor did not pull.
    fn run(
        &self,
        command: CommandSpec,
        sink: EventSink,
    ) -> (EventSink, Result<ExecutionResult, ObserverError>);
}

/// Failure before or during a run. Success is not implied by any variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverError {
    /// The program text was empty.
    EmptyProgram,
    /// The program text exceeded 4096 bytes.
    ProgramTooLong,
    /// An argument exceeded 4096 bytes.
    ArgTooLong {
        /// Index in the caller-supplied argument list.
        index: usize,
    },
    /// More than 256 arguments were supplied.
    TooManyArgs {
        /// Accepted maximum.
        max: usize,
    },
    /// The working directory text was empty.
    EmptyCurrentDir,
    /// The working directory text exceeded 4096 bytes.
    CurrentDirTooLong,
    /// Program, argument, or directory text contained a NUL byte.
    EmbeddedNul,
    /// The sink rejected an event. The event is inside `SinkError`.
    Sink(SinkError),
}

impl Display for ObserverError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProgram => formatter.write_str("program text is empty"),
            Self::ProgramTooLong => formatter.write_str("program text exceeds 4096 bytes"),
            Self::ArgTooLong { index } => {
                write!(formatter, "argument {index} exceeds 4096 bytes")
            }
            Self::TooManyArgs { max } => {
                write!(formatter, "argument list exceeds {max} entries")
            }
            Self::EmptyCurrentDir => formatter.write_str("working directory text is empty"),
            Self::CurrentDirTooLong => {
                formatter.write_str("working directory text exceeds 4096 bytes")
            }
            Self::EmbeddedNul => formatter.write_str("command text contains a NUL byte"),
            Self::Sink(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ObserverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sink(error) => Some(error),
            _ => None,
        }
    }
}

impl From<SinkError> for ObserverError {
    fn from(error: SinkError) -> Self {
        Self::Sink(error)
    }
}

fn map_program(result: Result<String, TextError>) -> Result<String, ObserverError> {
    result.map_err(|error| match error {
        TextError::Empty => ObserverError::EmptyProgram,
        TextError::TooLong => ObserverError::ProgramTooLong,
        TextError::EmbeddedNul => ObserverError::EmbeddedNul,
    })
}

fn map_dir(result: Result<String, TextError>) -> Result<String, ObserverError> {
    result.map_err(|error| match error {
        TextError::Empty => ObserverError::EmptyCurrentDir,
        TextError::TooLong => ObserverError::CurrentDirTooLong,
        TextError::EmbeddedNul => ObserverError::EmbeddedNul,
    })
}

fn map_arg(arg: String, index: usize) -> Result<String, ObserverError> {
    if arg.len() > MAX_ARG {
        return Err(ObserverError::ArgTooLong { index });
    }
    if arg.contains('\0') {
        return Err(ObserverError::EmbeddedNul);
    }
    Ok(arg)
}
