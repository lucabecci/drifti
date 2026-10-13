// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

mod error;
mod service;
mod stub;

pub use error::{AppError, CliError};
pub use service::{ApplicationServices, CommandContext, ObserveExit, VerifyExit};
pub use stub::StubApplicationServices;
