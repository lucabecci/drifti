// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Default application services wired for the `drifti` binary.

use super::intelligence;
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

    fn learn(&self, ctx: &CommandContext) -> Result<(), AppError> {
        intelligence::learn(ctx)
    }

    fn generate(&self, ctx: &CommandContext, write: bool) -> Result<(), AppError> {
        intelligence::generate(ctx, write)
    }

    fn verify(&self, _ctx: &CommandContext, _command: &[String]) -> Result<VerifyExit, AppError> {
        Err(AppError::NotImplemented { command: "verify" })
    }

    fn diff(&self, ctx: &CommandContext) -> Result<(), AppError> {
        intelligence::diff(ctx)
    }

    fn doctor(&self, _ctx: &CommandContext) -> Result<(), AppError> {
        Err(AppError::NotImplemented { command: "doctor" })
    }
}
