// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process exit codes for the `drifti` binary (SPEC-009).
//!
//! - [`EXIT_SUCCESS`]: command completed without error.
//! - Clap usage / invalid flags / actionable user input: `2` ([`EXIT_USAGE`]).
//! - [`EXIT_INTERNAL`]: unexpected Drifti failure.
//! - [`EXIT_VIOLATION`]: capability violation during verify.
//! - [`EXIT_INCOMPLETE`]: incomplete or indeterminate observation / coverage.
//! - [`EXIT_INVALID_CONTRACT`]: invalid or unusable capability contract.

pub const EXIT_SUCCESS: u8 = 0;
/// Actionable usage errors (missing `--`, bad cwd message, non-Linux observe).
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_INTERNAL: u8 = 120;
pub const EXIT_VIOLATION: u8 = 121;
pub const EXIT_INCOMPLETE: u8 = 122;
pub const EXIT_INVALID_CONTRACT: u8 = 123;

/// High-level outcome used by [`map_command_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandExitClass {
    Success,
    Violation,
    Incomplete,
    InvalidContract,
}

/// Inputs for SPEC-009 exit mapping after rendering.
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
        CommandExitClass::Incomplete => EXIT_INCOMPLETE,
        CommandExitClass::InvalidContract => EXIT_INVALID_CONTRACT,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        map_command_outcome, CommandExitClass, CommandExitInput, EXIT_INCOMPLETE, EXIT_INTERNAL,
        EXIT_INVALID_CONTRACT, EXIT_SUCCESS, EXIT_VIOLATION,
    };

    #[test]
    fn spec_exit_constants() {
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_INTERNAL, 120);
        assert_eq!(EXIT_VIOLATION, 121);
        assert_eq!(EXIT_INCOMPLETE, 122);
        assert_eq!(EXIT_INVALID_CONTRACT, 123);
    }

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
    fn domain_outcomes_map_to_spec_codes() {
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
    }
}
