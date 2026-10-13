// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process exit codes for the `drifti` binary (SPEC-009).
//!
//! Mapping used by [`crate::dispatch`]:
//! - [`EXIT_SUCCESS`]: command completed without error.
//! - Clap usage / invalid flags: `2` (conventional; not a named constant here).
//! - [`EXIT_INTERNAL`]: unexpected failure in [`crate::app::AppError::Internal`].
//! - [`EXIT_USER`] / [`EXIT_VIOLATION`]: actionable user input or capability violation.
//! - [`EXIT_NOT_READY`]: command not wired yet ([`crate::app::AppError::NotImplemented`]).
//! - [`EXIT_INCOMPLETE_OBSERVATION`]: incomplete or indeterminate observation.
//! - [`EXIT_COMMAND`] / [`EXIT_INVALID_CONTRACT`]: invalid capability contract.

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_INTERNAL: u8 = 120;
pub const EXIT_USER: u8 = 121;
pub const EXIT_VIOLATION: u8 = 121;
pub const EXIT_NOT_READY: u8 = 122;
pub const EXIT_INCOMPLETE_OBSERVATION: u8 = 122;
pub const EXIT_COMMAND: u8 = 123;
pub const EXIT_INVALID_CONTRACT: u8 = 123;

/// High-level outcome used by [`map_command_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandExitClass {
    Success,
    Violation,
    Incomplete,
    InvalidContract,
}

/// Inputs for SPEC-009 exit mapping after command orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandExitInput {
    pub class: CommandExitClass,
    /// Child process exit when Drifti did not override the code.
    pub process_exit: Option<u16>,
}

impl CommandExitInput {
    #[must_use]
    pub const fn success() -> Self {
        Self {
            class: CommandExitClass::Success,
            process_exit: None,
        }
    }

    #[must_use]
    pub const fn with_process(mut self, code: u16) -> Self {
        self.process_exit = Some(code);
        self
    }
}

/// Maps a command outcome to a process exit code (SPEC-009).
#[must_use]
pub fn map_command_outcome(input: CommandExitInput) -> u8 {
    match input.class {
        CommandExitClass::Success => input
            .process_exit
            .map(|code| u8::try_from(code.min(255)).unwrap_or(EXIT_SUCCESS))
            .unwrap_or(EXIT_SUCCESS),
        CommandExitClass::Violation => EXIT_VIOLATION,
        CommandExitClass::Incomplete => EXIT_INCOMPLETE_OBSERVATION,
        CommandExitClass::InvalidContract => EXIT_INVALID_CONTRACT,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        map_command_outcome, CommandExitClass, CommandExitInput, EXIT_INCOMPLETE_OBSERVATION,
        EXIT_INVALID_CONTRACT, EXIT_VIOLATION,
    };

    #[test]
    fn success_propagates_child_exit_capped() {
        assert_eq!(
            map_command_outcome(CommandExitInput::success().with_process(7)),
            7
        );
        assert_eq!(
            map_command_outcome(CommandExitInput::success().with_process(300)),
            255
        );
    }

    #[test]
    fn domain_outcomes_override_child_when_required() {
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
                process_exit: Some(0),
            }),
            EXIT_INCOMPLETE_OBSERVATION
        );
        assert_eq!(
            map_command_outcome(CommandExitInput {
                class: CommandExitClass::InvalidContract,
                process_exit: None,
            }),
            EXIT_INVALID_CONTRACT
        );
    }
}
