// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application service boundary between CLI parsing and orchestration.

use std::path::PathBuf;

use super::AppError;
use crate::output::OutputConfig;
use crate::result::CommandResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandContext {
    pub cwd: PathBuf,
    pub output: OutputConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    pub result: CommandResult,
    pub process_exit: u8,
}

pub trait ApplicationServices {
    fn init(&self, ctx: &CommandContext) -> Result<CommandResult, AppError>;
    fn observe(&self, ctx: &CommandContext, command: &[String])
        -> Result<ProcessOutcome, AppError>;
    fn learn(&self, ctx: &CommandContext) -> Result<CommandResult, AppError>;
    fn generate(&self, ctx: &CommandContext, write: bool) -> Result<CommandResult, AppError>;
    fn verify(&self, ctx: &CommandContext, command: &[String]) -> Result<ProcessOutcome, AppError>;
    fn diff(&self, ctx: &CommandContext) -> Result<CommandResult, AppError>;
    fn doctor(&self, ctx: &CommandContext) -> Result<CommandResult, AppError>;
}
