// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

mod intelligence;

use std::io::{self, Write};

use crate::output::{OutputConfig, OutputFormat};
use crate::result::IntelligenceResult;

pub fn render_intelligence(
    result: &IntelligenceResult,
    output: &OutputConfig,
    stdout: &mut impl Write,
) -> io::Result<()> {
    if output.mode.quiet {
        return Ok(());
    }
    match output.format {
        OutputFormat::Text => intelligence::render_text(result, stdout),
        OutputFormat::Json => intelligence::render_json(result, stdout),
    }
}
