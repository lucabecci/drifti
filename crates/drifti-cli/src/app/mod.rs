// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

mod default;
mod error;
mod events;
mod generate;
mod intelligence;
mod observe;
mod service;
mod store_learning;
mod stub;
mod verify;
mod workspace;

pub use default::DefaultApplicationServices;
pub use error::{AppError, CliError};
pub use service::{ApplicationServices, CommandContext, ObserveExit, VerifyExit};
pub use stub::StubApplicationServices;
