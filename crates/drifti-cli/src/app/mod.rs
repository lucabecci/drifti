// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

mod error;
mod generate;
mod mvp;
mod service;
mod store_learning;
mod stub;
mod verify;

pub use error::{AppError, CliError};
pub use mvp::MvpApplicationServices;
pub use service::{ApplicationServices, CommandContext, ProcessOutcome};
pub use stub::StubApplicationServices;
