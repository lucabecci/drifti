// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application service boundary between CLI parsing and future orchestration.

use std::path::PathBuf;

use super::AppError;
use crate::output::OutputConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandContext {
    pub cwd: PathBuf,
    pub output: OutputConfig,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveExit {
    pub code: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyExit {
    pub code: u8,
}

pub trait ApplicationServices {
    fn init(&self, ctx: &CommandContext) -> Result<(), AppError>;
    fn observe(&self, ctx: &CommandContext, command: &[String]) -> Result<ObserveExit, AppError>;
    fn learn(&self, ctx: &CommandContext) -> Result<(), AppError>;
    fn generate(&self, ctx: &CommandContext, write: bool) -> Result<(), AppError>;
    fn verify(&self, ctx: &CommandContext, command: &[String]) -> Result<VerifyExit, AppError>;
    fn diff(&self, ctx: &CommandContext) -> Result<(), AppError>;
    fn doctor(&self, ctx: &CommandContext) -> Result<(), AppError>;
}
