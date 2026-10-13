// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stub services for bootstrap tests and pre-orchestration CLI wiring.

use super::{AppError, ApplicationServices, CommandContext, ObserveExit, VerifyExit};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StubApplicationServices;

impl ApplicationServices for StubApplicationServices {
    fn init(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "init" })
    }

    fn observe(&self, _ctx: &CommandContext, _command: &[String]) -> Result<ObserveExit, AppError> {
        Err(AppError::NotImplemented { command: "observe" })
    }

    fn learn(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "learn" })
    }

    fn generate(&self, _ctx: &CommandContext, _write: bool) -> Result<(), AppError> {
        Err(AppError::NotImplemented {
            command: "generate",
        })
    }

    fn verify(&self, _ctx: &CommandContext, _command: &[String]) -> Result<VerifyExit, AppError> {
        Err(AppError::NotImplemented { command: "verify" })
    }

    fn diff(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "diff" })
    }

    fn doctor(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "doctor" })
    }
}
