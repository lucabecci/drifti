// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

mod json;
mod text;

use std::io::{self, IsTerminal, Write};

use crate::output::{ColorPolicy, OutputConfig, OutputFormat};
use crate::result::CommandResult;

pub fn render_result(
    result: &CommandResult,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> io::Result<()> {
    if should_suppress_success(result, output) {
        return Ok(());
    }
    let use_color = color_enabled(output.color);
    match output.format {
        OutputFormat::Text => text::render(result, output, use_color, stdout),
        OutputFormat::Json => json::render(result, stdout),
    }
}

fn should_suppress_success(result: &CommandResult, output: &OutputConfig) -> bool {
    if !output.mode.quiet {
        return false;
    }
    matches!(
        result,
        CommandResult::Init(_) | CommandResult::Learn(_) if result.exit_class() == crate::exit::CommandExitClass::Success
    )
}

fn color_enabled(policy: ColorPolicy) -> bool {
    match policy {
        ColorPolicy::Never => false,
        ColorPolicy::Always => true,
        ColorPolicy::Auto => std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal(),
    }
}
