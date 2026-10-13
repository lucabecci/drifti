// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application-layer errors (actionable messages, no stringly domain logic).

use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub enum AppError {
    NotImplemented { command: &'static str },
    User { message: String },
    Internal { message: String },
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { command } => {
                write!(f, "{command} is not implemented yet")
            }
            Self::User { message } | Self::Internal { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for AppError {}

#[derive(Debug, Eq, PartialEq)]
pub enum CliError {
    MissingCommandSeparator { subcommand: &'static str },
    EmptyWrappedCommand { subcommand: &'static str },
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommandSeparator { subcommand } => write!(
                f,
                "{subcommand} requires `--` before the command to run (example: drifti {subcommand} -- echo hello)"
            ),
            Self::EmptyWrappedCommand { subcommand } => write!(
                f,
                "{subcommand} requires a command after `--` (example: drifti {subcommand} -- echo hello)"
            ),
        }
    }
}

impl std::error::Error for CliError {}
