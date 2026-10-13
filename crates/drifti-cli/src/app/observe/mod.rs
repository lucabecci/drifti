// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe command orchestration.

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod exit_code;

#[cfg(target_os = "linux")]
mod linux;

use crate::app::{AppError, CommandContext, ObserveExit};

pub fn observe(ctx: &CommandContext, command: &[String]) -> Result<ObserveExit, AppError> {
    #[cfg(target_os = "linux")]
    {
        return linux::observe_on_linux(ctx, command);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ctx, command);
        Err(AppError::User {
            message: "drifti observe requires a Linux host with ptrace observation support".into(),
        })
    }
}
