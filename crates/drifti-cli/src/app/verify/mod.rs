// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify command orchestration.

mod evaluate;
mod exit_code;

#[cfg(target_os = "linux")]
mod linux;

use crate::app::{AppError, CommandContext, VerifyExit};

pub fn verify(ctx: &CommandContext, command: &[String]) -> Result<VerifyExit, AppError> {
    #[cfg(target_os = "linux")]
    {
        return linux::verify_on_linux(ctx, command);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ctx, command);
        Err(AppError::User {
            message: "drifti verify requires a Linux host with ptrace observation support".into(),
        })
    }
}
