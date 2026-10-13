// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe process exit mapping (SPEC-009 / KAN-77).

use crate::app::ObserveExit;
use crate::exit::{EXIT_INCOMPLETE_OBSERVATION, EXIT_SUCCESS};

/// Result of a completed observe orchestration before exit mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserveRun {
    pub child_exit: Option<i32>,
    pub coverage_complete: bool,
}

impl ObserveRun {
    #[must_use]
    pub const fn success(child_exit: Option<i32>) -> Self {
        Self {
            child_exit,
            coverage_complete: true,
        }
    }

    #[must_use]
    pub const fn incomplete(child_exit: Option<i32>) -> Self {
        Self {
            child_exit,
            coverage_complete: false,
        }
    }
}

/// Maps observation outcome to the process exit code.
///
/// Incomplete or unsupported coverage never becomes success, even when the
/// child exited zero. When coverage is complete, the child exit is propagated.
#[must_use]
pub fn process_exit_for_observe(run: ObserveRun) -> ObserveExit {
    if !run.coverage_complete {
        return ObserveExit {
            code: EXIT_INCOMPLETE_OBSERVATION,
        };
    }
    ObserveExit {
        code: child_exit_code(run.child_exit),
    }
}

fn child_exit_code(exit: Option<i32>) -> u8 {
    match exit {
        None | Some(0) => EXIT_SUCCESS,
        Some(code) if (1..=255).contains(&code) => code as u8,
        Some(code) => (code & 0xff) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_coverage_never_exits_success_even_when_child_is_zero() {
        let exit = process_exit_for_observe(ObserveRun::incomplete(Some(0)));
        assert_eq!(exit.code, EXIT_INCOMPLETE_OBSERVATION);
    }

    #[test]
    fn complete_coverage_propagates_child_non_zero() {
        let exit = process_exit_for_observe(ObserveRun::success(Some(7)));
        assert_eq!(exit.code, 7);
    }

    #[test]
    fn complete_coverage_with_successful_child_exits_zero() {
        let exit = process_exit_for_observe(ObserveRun::success(Some(0)));
        assert_eq!(exit.code, EXIT_SUCCESS);
    }
}
