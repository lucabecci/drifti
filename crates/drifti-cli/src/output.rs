// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Global output options (parse and hold only; rendering comes later).

use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutputMode {
    pub quiet: bool,
    pub verbose: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum ColorPolicy {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputConfig {
    pub format: OutputFormat,
    pub mode: OutputMode,
    pub color: ColorPolicy,
}

impl OutputConfig {
    pub fn new(format: OutputFormat, quiet: bool, verbose: bool, color: ColorPolicy) -> Self {
        Self {
            format,
            mode: OutputMode { quiet, verbose },
            color,
        }
    }
}
