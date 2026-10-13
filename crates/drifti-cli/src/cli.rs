// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Clap command tree for the MVP CLI (SPEC-009).

use clap::{Parser, Subcommand};

use crate::output::{ColorPolicy, OutputFormat};

#[derive(Parser, Debug)]
#[command(
    name = "drifti",
    about = "Capability contracts for AI agents.",
    version,
    after_help = "Examples:\n  drifti init\n  drifti observe -- cargo build\n  drifti verify -- ./scripts/check.sh"
)]
pub struct DriftiCli {
    /// Output format for structured results.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, global = true)]
    pub format: OutputFormat,

    /// Suppress non-essential output.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Show additional detail while running.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Color policy (`NO_COLOR` is respected when set to auto).
    #[arg(long, value_enum, default_value_t = ColorPolicy::Auto, global = true)]
    pub color: ColorPolicy,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize Drifti metadata in the current repository.
    #[command(
        about = "Initialize Drifti metadata in the current repository.",
        after_help = "Example:\n  drifti init"
    )]
    Init,

    /// Run a command under observation and record evidence locally.
    #[command(
        about = "Run a command under observation and record evidence locally.",
        after_help = "Example:\n  drifti observe -- echo hello",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    Observe {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Learn a capability profile from stored observations.
    #[command(
        about = "Learn a capability profile from stored observations.",
        after_help = "Example:\n  drifti learn"
    )]
    Learn,

    /// Propose a capability contract from the learned profile.
    #[command(
        about = "Propose a capability contract from the learned profile.",
        after_help = "Example:\n  drifti generate --write"
    )]
    Generate {
        /// Write the proposed contract to the workspace when implemented.
        #[arg(long)]
        write: bool,
    },

    /// Run a command and verify it against the trusted contract.
    #[command(
        about = "Run a command and verify it against the trusted contract.",
        after_help = "Example:\n  drifti verify -- cargo test",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    Verify {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show capability drift between profile and contract.
    #[command(
        about = "Show capability drift between profile and contract.",
        after_help = "Example:\n  drifti diff"
    )]
    Diff,

    /// Check local prerequisites for observation and verification.
    #[command(
        about = "Check local prerequisites for observation and verification.",
        after_help = "Example:\n  drifti doctor"
    )]
    Doctor,
}

impl DriftiCli {
    pub fn try_parse_from<I, T>(args: I) -> clap::error::Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::try_parse_from(args)
    }
}
