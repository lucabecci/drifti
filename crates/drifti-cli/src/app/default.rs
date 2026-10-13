// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Default application services wired for the `drifti` binary.

use super::observe;
use super::{AppError, ApplicationServices, CommandContext, ObserveExit, VerifyExit};

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultApplicationServices;

impl ApplicationServices for DefaultApplicationServices {
    fn init(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "init" })
    }

    fn observe(&self, ctx: &CommandContext, command: &[String]) -> Result<ObserveExit, AppError> {
        observe::observe(ctx, command)
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
