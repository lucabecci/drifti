// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify process exit mapping (SPEC-009 / KAN-79).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::app::VerifyExit;
use crate::exit::{map_command_outcome, CommandExitClass, CommandExitInput};

/// Outcome of verify orchestration before exit mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyRun {
    pub denied: bool,
    pub indeterminate: bool,
    pub child_exit: Option<i32>,
    pub observation_complete: bool,
}

/// Maps verification outcome to the process exit code.
///
/// Deny overrides the child. Incomplete observation or indeterminate policy
/// never yields success, even when the child exited zero. When verification
/// succeeds, the child exit is propagated.
#[must_use]
pub fn process_exit_for_verify(run: VerifyRun) -> VerifyExit {
    let class = if run.denied {
        CommandExitClass::Violation
    } else if run.indeterminate || !run.observation_complete {
        CommandExitClass::Incomplete
    } else {
        CommandExitClass::Success
    };
    let process_exit = child_exit_u16(run.child_exit);
    VerifyExit {
        code: map_command_outcome(CommandExitInput {
            class,
            process_exit,
        }),
    }
}

fn child_exit_u16(exit: Option<i32>) -> Option<u16> {
    match exit {
        None | Some(0) => None,
        Some(code) if (1..=255).contains(&code) => Some(code as u16),
        Some(code) => Some((code & 0xff) as u16),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::{EXIT_INCOMPLETE_OBSERVATION, EXIT_SUCCESS, EXIT_VIOLATION};

    #[test]
    fn violation_overrides_successful_child() {
        let exit = process_exit_for_verify(VerifyRun {
            denied: true,
            indeterminate: false,
            child_exit: Some(0),
            observation_complete: true,
        });
        assert_eq!(exit.code, EXIT_VIOLATION);
    }

    #[test]
    fn incomplete_never_success_when_child_is_zero() {
        let exit = process_exit_for_verify(VerifyRun {
            denied: false,
            indeterminate: true,
            child_exit: Some(0),
            observation_complete: true,
        });
        assert_eq!(exit.code, EXIT_INCOMPLETE_OBSERVATION);
    }

    #[test]
    fn incomplete_observation_maps_to_122() {
        let exit = process_exit_for_verify(VerifyRun {
            denied: false,
            indeterminate: false,
            child_exit: Some(0),
            observation_complete: false,
        });
        assert_eq!(exit.code, EXIT_INCOMPLETE_OBSERVATION);
    }

    #[test]
    fn compliant_complete_run_propagates_child() {
        let exit = process_exit_for_verify(VerifyRun {
            denied: false,
            indeterminate: false,
            child_exit: Some(9),
            observation_complete: true,
        });
        assert_eq!(exit.code, 9);
    }

    #[test]
    fn compliant_successful_child_exits_zero() {
        let exit = process_exit_for_verify(VerifyRun {
            denied: false,
            indeterminate: false,
            child_exit: Some(0),
            observation_complete: true,
        });
        assert_eq!(exit.code, EXIT_SUCCESS);
    }
}
